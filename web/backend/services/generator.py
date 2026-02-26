"""Artifact generator – produces Ansible playbooks (Ubuntu) and PS1 scripts (Windows)."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import List

# Project root (same resolution as rule_loader)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# Temporary artifact storage
ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _ensure_artifact_dir() -> tuple[str, Path]:
    """Create a unique sub-directory for this generation run."""
    artifact_id = uuid.uuid4().hex[:12]
    out_dir = ARTIFACTS_DIR / artifact_id
    out_dir.mkdir(parents=True, exist_ok=True)
    return artifact_id, out_dir


# ── Ubuntu – Ansible Playbook ────────────────────────────────────────────────

def _generate_ubuntu_ansible(rule_ids: List[str]) -> dict:
    """Read remediation.sh scripts and wrap them in an Ansible playbook."""
    index_path = PROJECT_ROOT / "platforms" / "linux" / "ubuntu" / "desktop" / "rules" / "index.json"
    if not index_path.exists():
        return {"success": False, "message": "Ubuntu index.json bulunamadı."}

    with open(index_path, "r", encoding="utf-8") as f:
        entries = json.load(f)

    # Build lookup: rule_id → index entry
    lookup = {e["id"]: e for e in entries}

    # Collect tasks
    tasks = []
    skipped = []
    for rid in rule_ids:
        entry = lookup.get(rid)
        if not entry:
            skipped.append(rid)
            continue

        remediation_rel = entry.get("remediation")
        if not remediation_rel:
            skipped.append(rid)
            continue

        script_path = PROJECT_ROOT / remediation_rel
        if not script_path.exists():
            skipped.append(rid)
            continue

        script_content = script_path.read_text(encoding="utf-8").strip()
        tasks.append({
            "rule_id": rid,
            "title": entry.get("title", rid),
            "section": entry.get("section", "Unknown"),
            "script": script_content,
        })

    if not tasks:
        return {
            "success": False,
            "message": f"Seçilen kurallardan hiçbiri için remediation scripti bulunamadı. "
                       f"Atlanan: {', '.join(skipped) if skipped else 'yok'}",
        }

    # Build YAML playbook
    lines = [
        "---",
        "# CIS Ubuntu Desktop Hardening Playbook",
        f"# Generated for {len(tasks)} rules",
        "# WARNING: Review each task before applying to production systems.",
        "",
        "- name: CIS Ubuntu Desktop Hardening",
        "  hosts: all",
        "  become: true",
        "  tasks:",
    ]

    for t in tasks:
        safe_title = t["title"].replace('"', '\\"')
        lines.append(f"")
        lines.append(f"    # ── {t['rule_id']}: {t['section']} ──")
        lines.append(f'    - name: "CIS {t["rule_id"]} - {safe_title}"')
        lines.append(f"      ansible.builtin.shell: |")
        for script_line in t["script"].splitlines():
            lines.append(f"        {script_line}")
        lines.append(f"      args:")
        lines.append(f"        executable: /bin/bash")
        lines.append(f"      changed_when: true")
        lines.append(f'      tags: ["cis", "{t["rule_id"]}"]')

    playbook_content = "\n".join(lines) + "\n"

    # Write to artifact directory
    artifact_id, out_dir = _ensure_artifact_dir()
    filename = "cis_ubuntu_hardening.yml"
    out_path = out_dir / filename
    out_path.write_text(playbook_content, encoding="utf-8")

    sha256 = _sha256(out_path)

    msg = f"{len(tasks)} kural için Ansible playbook oluşturuldu."
    if skipped:
        msg += f" ({len(skipped)} kural atlandı: remediation scripti bulunamadı)"

    return {
        "success": True,
        "message": msg,
        "artifact_id": artifact_id,
        "filename": filename,
        "sha256": sha256,
    }


# ── Windows – PowerShell Script ──────────────────────────────────────────────

def _load_windows_rule_json(rule_id: str) -> dict | None:
    """Find and load a Windows rule JSON by rule_id."""
    win_base = PROJECT_ROOT / "platforms" / "windows"

    for rules_dir in [win_base / "rules", win_base / "manual_rules"]:
        if not rules_dir.exists():
            continue
        for json_file in rules_dir.rglob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("rule_id") == rule_id:
                    return data
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
    return None


def _generate_windows_ps1(rule_ids: List[str]) -> dict:
    """Build a consolidated PowerShell hardening script from rule JSONs."""

    rules_data = []
    skipped = []

    for rid in rule_ids:
        rule = _load_windows_rule_json(rid)
        if not rule:
            skipped.append(rid)
            continue

        impl = rule.get("implementation_local")
        if not impl:
            skipped.append(rid)
            continue

        ps_script = impl.get("powershell_script") or impl.get("powershell_command")
        if not ps_script:
            skipped.append(rid)
            continue

        rules_data.append({
            "rule_id": rid,
            "title": rule.get("title", rid),
            "category": rule.get("category", "Unknown"),
            "cis_level": rule.get("cis_level", "N/A"),
            "requires_admin": impl.get("requires_admin", True),
            "requires_reboot": impl.get("requires_reboot", False),
            "script": ps_script,
        })

    if not rules_data:
        return {
            "success": False,
            "message": f"Seçilen kurallardan hiçbiri için PowerShell scripti bulunamadı. "
                       f"Atlanan: {', '.join(skipped) if skipped else 'yok'}",
        }

    # Build PS1 script
    lines = [
        "#Requires -RunAsAdministrator",
        "<#",
        ".SYNOPSIS",
        "    CIS Windows Hardening Script",
        ".DESCRIPTION",
        f"    Consolidated hardening script for {len(rules_data)} CIS rules.",
        "    Generated by CIS Hardening Platform.",
        "",
        "    WARNING: Review each rule before applying to production systems.",
        "#>",
        "",
        'param(',
        '    [switch]$WhatIf',
        ')',
        "",
        "$ErrorActionPreference = 'Stop'",
        "$Script:Results = @()",
        "",
        "function Write-RuleResult {",
        "    param([string]$RuleId, [string]$Title, [string]$Status, [string]$Details)",
        '    $Script:Results += [PSCustomObject]@{',
        "        RuleId = $RuleId; Title = $Title; Status = $Status; Details = $Details",
        "    }",
        '    $color = switch ($Status) {',
        "        'PASS' { 'Green' }",
        "        'FAIL' { 'Red' }",
        "        'APPLIED' { 'Cyan' }",
        "        default { 'Yellow' }",
        "    }",
        '    Write-Host "[${Status}] ${RuleId}: ${Title}" -ForegroundColor $color',
        '    if ($Details) { Write-Host "       $Details" -ForegroundColor Gray }',
        "}",
        "",
    ]

    # Per-rule functions
    for r in rules_data:
        func_name = r["rule_id"].replace(".", "_")
        safe_title = r["title"].replace('"', '`"')
        lines.append(f"# ── CIS {r['rule_id']} ──────────────────────────────────────")
        lines.append(f'function Apply-CIS_{func_name} {{')
        lines.append(f"    <#")
        lines.append(f"    .SYNOPSIS")
        lines.append(f"        {r['title']}")
        lines.append(f"    .NOTES")
        lines.append(f"        Category:       {r['category']}")
        lines.append(f"        CIS Level:      {r['cis_level']}")
        lines.append(f"        Requires Admin: {r['requires_admin']}")
        lines.append(f"        Requires Reboot:{r['requires_reboot']}")
        lines.append(f"    #>")
        lines.append(f"    try {{")
        lines.append(f'        if ($WhatIf) {{')
        lines.append(f'            Write-RuleResult -RuleId "{r["rule_id"]}" -Title "{safe_title}" -Status "SKIPPED" -Details "WhatIf mode"')
        lines.append(f'            return')
        lines.append(f'        }}')

        # Indent the PowerShell script
        for ps_line in r["script"].replace("\\n", "\n").splitlines():
            lines.append(f"        {ps_line}")

        lines.append(f'        Write-RuleResult -RuleId "{r["rule_id"]}" -Title "{safe_title}" -Status "APPLIED" -Details "Successfully applied"')
        lines.append(f"    }}")
        lines.append(f"    catch {{")
        lines.append(f'        Write-RuleResult -RuleId "{r["rule_id"]}" -Title "{safe_title}" -Status "FAIL" -Details $_.Exception.Message')
        lines.append(f"    }}")
        lines.append(f"}}")
        lines.append(f"")

    # Main orchestrator
    lines.append("")
    lines.append("# ══════════════════════════════════════════════════════════════")
    lines.append("# Main Execution")
    lines.append("# ══════════════════════════════════════════════════════════════")
    lines.append("")
    lines.append('Write-Host ""')
    lines.append('Write-Host "================================================================" -ForegroundColor Cyan')
    lines.append(f'Write-Host "  CIS Windows Hardening – {len(rules_data)} Rules" -ForegroundColor Cyan')
    lines.append('Write-Host "================================================================" -ForegroundColor Cyan')
    lines.append('Write-Host ""')
    lines.append("")

    for r in rules_data:
        func_name = r["rule_id"].replace(".", "_")
        lines.append(f"Apply-CIS_{func_name}")

    lines.append("")
    lines.append("# Summary")
    lines.append('Write-Host ""')
    lines.append('Write-Host "================================================================" -ForegroundColor Cyan')
    lines.append('$applied = ($Script:Results | Where-Object Status -eq "APPLIED").Count')
    lines.append('$failed  = ($Script:Results | Where-Object Status -eq "FAIL").Count')
    lines.append('$skipped = ($Script:Results | Where-Object Status -eq "SKIPPED").Count')
    lines.append('Write-Host "Applied: $applied  |  Failed: $failed  |  Skipped: $skipped" -ForegroundColor White')
    lines.append('Write-Host "================================================================" -ForegroundColor Cyan')
    lines.append("")

    script_content = "\r\n".join(lines) + "\r\n"

    # Write to artifact directory
    artifact_id, out_dir = _ensure_artifact_dir()
    filename = "CIS_Windows_Hardening.ps1"
    out_path = out_dir / filename
    out_path.write_text(script_content, encoding="utf-8-sig")  # BOM for PowerShell compatibility

    sha256 = _sha256(out_path)

    msg = f"{len(rules_data)} kural için PowerShell scripti oluşturuldu."
    if skipped:
        msg += f" ({len(skipped)} kural atlandı: implementation bulunamadı)"

    return {
        "success": True,
        "message": msg,
        "artifact_id": artifact_id,
        "filename": filename,
        "sha256": sha256,
    }


# ── Public API ───────────────────────────────────────────────────────────────

def generate(os_name: str, rule_ids: List[str], fmt: str) -> dict:
    """Generate configuration artifact for the given OS and format."""
    if os_name == "ubuntu":
        return _generate_ubuntu_ansible(rule_ids)
    elif os_name == "windows":
        return _generate_windows_ps1(rule_ids)
    else:
        return {"success": False, "message": f"Desteklenmeyen OS: {os_name}"}


def get_artifact_path(artifact_id: str) -> Path | None:
    """Return the path to the first file in the artifact directory."""
    art_dir = ARTIFACTS_DIR / artifact_id
    if not art_dir.exists():
        return None
    files = list(art_dir.iterdir())
    return files[0] if files else None
