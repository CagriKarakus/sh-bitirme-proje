"""Artifact generator – multi-format output for Ubuntu and Windows."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import uuid
import zipfile
from datetime import datetime
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


def _mark_permanent(artifact_id: str) -> None:
    """Create .permanent marker so the artifact is indexable/searchable."""
    (ARTIFACTS_DIR / artifact_id / ".permanent").touch()


def is_artifact_permanent(artifact_id: str) -> bool:
    return (ARTIFACTS_DIR / artifact_id / ".permanent").exists()


def delete_artifact(artifact_id: str) -> None:
    """Remove the artifact directory entirely (used as a background task)."""
    art_dir = ARTIFACTS_DIR / artifact_id
    if art_dir.exists():
        shutil.rmtree(art_dir, ignore_errors=True)


def _find_permanent_by_sha256(sha256: str) -> str | None:
    """Return the artifact_id of an existing permanent artifact whose file matches sha256."""
    for art_dir in ARTIFACTS_DIR.iterdir():
        if not art_dir.is_dir() or not (art_dir / ".permanent").exists():
            continue
        for f in art_dir.iterdir():
            if f.is_file() and not f.name.startswith(".") and not f.name.startswith("_"):
                try:
                    if _sha256(f) == sha256:
                        return art_dir.name
                except OSError:
                    continue
    return None


def _ensure_artifact_dir() -> tuple[str, Path]:
    """Create a unique sub-directory for this generation run."""
    artifact_id = uuid.uuid4().hex[:12]
    out_dir = ARTIFACTS_DIR / artifact_id
    out_dir.mkdir(parents=True, exist_ok=True)
    return artifact_id, out_dir


def _load_ubuntu_index() -> list[dict] | None:
    """Load Ubuntu rule index."""
    index_path = PROJECT_ROOT / "platforms" / "linux" / "ubuntu" / "desktop" / "rules" / "index.json"
    if not index_path.exists():
        return None
    with open(index_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _collect_ubuntu_scripts(rule_ids: List[str]) -> tuple[list[dict], list[str]]:
    """Collect remediation scripts for the given Ubuntu rule IDs."""
    entries = _load_ubuntu_index()
    if not entries:
        return [], rule_ids[:]

    lookup = {e["id"]: e for e in entries}
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

    return tasks, skipped


# ── Ubuntu – Ansible Playbook ────────────────────────────────────────────────

def _generate_ubuntu_ansible(rule_ids: List[str]) -> dict:
    """Read remediation.sh scripts and wrap them in an Ansible playbook."""
    tasks, skipped = _collect_ubuntu_scripts(rule_ids)

    if not tasks:
        return {
            "success": False,
            "message": f"Seçilen kurallardan hiçbiri için remediation scripti bulunamadı. "
                       f"Atlanan: {', '.join(skipped) if skipped else 'yok'}",
        }

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

    artifact_id, out_dir = _ensure_artifact_dir()
    filename = "cis_ubuntu_hardening.yml"
    out_path = out_dir / filename
    out_path.write_text(playbook_content, encoding="utf-8")

    sha256 = _sha256(out_path)

    msg = f"{len(tasks)} kural için Ansible playbook oluşturuldu."
    if skipped:
        msg += f" ({len(skipped)} kural atlandı)"

    return {
        "success": True,
        "message": msg,
        "artifact_id": artifact_id,
        "filename": filename,
        "sha256": sha256,
    }


# ── Ubuntu – Bash Script ─────────────────────────────────────────────────────

def _generate_ubuntu_bash(rule_ids: List[str]) -> dict:
    """Concatenate remediation.sh scripts into a single executable bash script."""
    tasks, skipped = _collect_ubuntu_scripts(rule_ids)

    if not tasks:
        return {
            "success": False,
            "message": f"Seçilen kurallardan hiçbiri için remediation scripti bulunamadı. "
                       f"Atlanan: {', '.join(skipped) if skipped else 'yok'}",
        }

    lines = [
        "#!/usr/bin/env bash",
        "# ============================================================================",
        "# CIS Ubuntu Desktop Hardening Script",
        f"# Generated for {len(tasks)} rules",
        f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# WARNING: Review each rule before applying to production systems.",
        "# ============================================================================",
        "",
        "set -euo pipefail",
        "",
        "# Colors",
        'RED="\\033[0;31m"',
        'GREEN="\\033[0;32m"',
        'CYAN="\\033[0;36m"',
        'NC="\\033[0m"',
        "",
        "PASS_COUNT=0",
        "FAIL_COUNT=0",
        "TOTAL=0",
        "",
        "apply_rule() {",
        '    local rule_id="$1"',
        '    local title="$2"',
        "    TOTAL=$((TOTAL + 1))",
        '    echo ""',
        '    echo -e "${CYAN}[APPLY] ${rule_id}: ${title}${NC}"',
        '    if "$3"; then',
        "        PASS_COUNT=$((PASS_COUNT + 1))",
        '        echo -e "${GREEN}[OK] ${rule_id} applied successfully${NC}"',
        "    else",
        "        FAIL_COUNT=$((FAIL_COUNT + 1))",
        '        echo -e "${RED}[FAIL] ${rule_id} failed${NC}"',
        "    fi",
        "}",
        "",
        "# Check root",
        'if [[ "$EUID" -ne 0 ]]; then',
        '    echo -e "${RED}[ERROR] This script must be run as root${NC}"',
        "    exit 1",
        "fi",
        "",
        'echo "================================================================"',
        f'echo "  CIS Ubuntu Desktop Hardening – {len(tasks)} Rules"',
        'echo "================================================================"',
        "",
    ]

    for t in tasks:
        func_name = t["rule_id"].replace(".", "_")
        lines.append(f"# ── CIS {t['rule_id']}: {t['section']} ──")
        lines.append(f"rule_{func_name}() {{")

        for script_line in t["script"].splitlines():
            # Skip shebang lines in individual scripts
            if script_line.strip().startswith("#!/"):
                continue
            lines.append(f"    {script_line}")

        lines.append("}")
        lines.append(f'apply_rule "{t["rule_id"]}" "{t["title"]}" rule_{func_name}')
        lines.append("")

    # Summary
    lines.extend([
        '# ── Summary ──',
        'echo ""',
        'echo "================================================================"',
        'echo -e "Applied: ${GREEN}${PASS_COUNT}${NC}  |  Failed: ${RED}${FAIL_COUNT}${NC}  |  Total: ${TOTAL}"',
        'echo "================================================================"',
        "",
    ])

    script_content = "\n".join(lines) + "\n"

    artifact_id, out_dir = _ensure_artifact_dir()
    filename = "cis_ubuntu_hardening.sh"
    out_path = out_dir / filename
    out_path.write_text(script_content, encoding="utf-8")

    sha256 = _sha256(out_path)

    msg = f"{len(tasks)} kural için Bash scripti oluşturuldu."
    if skipped:
        msg += f" ({len(skipped)} kural atlandı)"

    return {
        "success": True,
        "message": msg,
        "artifact_id": artifact_id,
        "filename": filename,
        "sha256": sha256,
    }


# ── Windows – Helpers ────────────────────────────────────────────────────────

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


def _find_windows_rule_files(rule_ids: List[str]) -> list[Path]:
    """Find the JSON file paths for given Windows rule IDs."""
    win_base = PROJECT_ROOT / "platforms" / "windows"
    files = []
    id_set = set(rule_ids)

    for rules_dir in [win_base / "rules", win_base / "manual_rules"]:
        if not rules_dir.exists():
            continue
        for json_file in rules_dir.rglob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("rule_id") in id_set:
                    files.append(json_file)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
    return files


# ── Windows – PowerShell Script ──────────────────────────────────────────────

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

        for ps_line in r["script"].replace("\\n", "\n").splitlines():
            lines.append(f"        {ps_line}")

        lines.append(f'        Write-RuleResult -RuleId "{r["rule_id"]}" -Title "{safe_title}" -Status "APPLIED" -Details "Successfully applied"')
        lines.append(f"    }}")
        lines.append(f"    catch {{")
        lines.append(f'        Write-RuleResult -RuleId "{r["rule_id"]}" -Title "{safe_title}" -Status "FAIL" -Details $_.Exception.Message')
        lines.append(f"    }}")
        lines.append(f"}}")
        lines.append(f"")

    lines.extend([
        "",
        "# ══════════════════════════════════════════════════════════════",
        "# Main Execution",
        "# ══════════════════════════════════════════════════════════════",
        "",
        'Write-Host ""',
        'Write-Host "================================================================" -ForegroundColor Cyan',
        f'Write-Host "  CIS Windows Hardening – {len(rules_data)} Rules" -ForegroundColor Cyan',
        'Write-Host "================================================================" -ForegroundColor Cyan',
        'Write-Host ""',
        "",
    ])

    for r in rules_data:
        func_name = r["rule_id"].replace(".", "_")
        lines.append(f"Apply-CIS_{func_name}")

    lines.extend([
        "",
        "# Summary",
        'Write-Host ""',
        'Write-Host "================================================================" -ForegroundColor Cyan',
        '$applied = ($Script:Results | Where-Object Status -eq "APPLIED").Count',
        '$failed  = ($Script:Results | Where-Object Status -eq "FAIL").Count',
        '$skipped = ($Script:Results | Where-Object Status -eq "SKIPPED").Count',
        'Write-Host "Applied: $applied  |  Failed: $failed  |  Skipped: $skipped" -ForegroundColor White',
        'Write-Host "================================================================" -ForegroundColor Cyan',
        "",
    ])

    script_content = "\r\n".join(lines) + "\r\n"

    artifact_id, out_dir = _ensure_artifact_dir()
    filename = "CIS_Windows_Hardening.ps1"
    out_path = out_dir / filename
    out_path.write_text(script_content, encoding="utf-8-sig")

    sha256 = _sha256(out_path)

    msg = f"{len(rules_data)} kural için PowerShell scripti oluşturuldu."
    if skipped:
        msg += f" ({len(skipped)} kural atlandı)"

    return {
        "success": True,
        "message": msg,
        "artifact_id": artifact_id,
        "filename": filename,
        "sha256": sha256,
    }


# ── Windows – GPO Backup ────────────────────────────────────────────────────

def _generate_windows_gpo(rule_ids: List[str]) -> dict:
    """Generate GPO backup by calling the existing PowerShell toolkit, then zip."""

    tools_dir = PROJECT_ROOT / "platforms" / "windows" / "tools"
    generator_ps1 = tools_dir / "generator.ps1"

    if not generator_ps1.exists():
        return {"success": False, "message": "Windows generator.ps1 bulunamadı."}

    # Find which rule files match the selected IDs
    rule_files = _find_windows_rule_files(rule_ids)
    if not rule_files:
        return {
            "success": False,
            "message": "Seçilen kurallardan hiçbiri bulunamadı.",
        }

    artifact_id, out_dir = _ensure_artifact_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Create a temporary rules directory with only selected rule files
    temp_rules_dir = out_dir / "_selected_rules"
    temp_rules_dir.mkdir(exist_ok=True)
    for rf in rule_files:
        shutil.copy2(rf, temp_rules_dir / rf.name)

    # Build a custom generator script that uses our selected rules
    custom_script = f"""
$ErrorActionPreference = "Stop"

$scriptDir  = "{tools_dir.as_posix()}"
$rulesPath  = "{temp_rules_dir.as_posix()}"
$outputPath = "{out_dir.as_posix()}"

# Load builder modules
. (Join-Path $scriptDir "ps_script_builder.ps1")
. (Join-Path $scriptDir "gpo_builder.ps1")
. (Join-Path $scriptDir "registry_pol_writer.ps1")

# Process selected rules
$rules = Get-ChildItem -Path $rulesPath -Filter "*.json" -Recurse
$processedRules = @()
foreach ($file in $rules) {{
    $content = Get-Content $file.FullName -Raw | ConvertFrom-Json
    # Skip manual rules (automated only)
    if ($content.automated -eq $false) {{ continue }}
    $processedRules += [PSCustomObject]@{{ Rule = $content }}
}}

if ($processedRules.Count -eq 0) {{
    Write-Error "No processable rules found"
    exit 1
}}

# Generate GPO Backup only
$gpoOutput = Join-Path $outputPath "GPO_Backup_{timestamp}"
if (-not (Test-Path $gpoOutput)) {{
    New-Item -Path $gpoOutput -ItemType Directory -Force | Out-Null
}}
New-GPOBackup -Rules $processedRules -OutputPath $gpoOutput -GPOName "CIS_Hardening_{timestamp}"
Write-Host "GPO_OUTPUT_DIR=$gpoOutput"
"""

    custom_script_path = out_dir / "_run_gpo.ps1"
    custom_script_path.write_text(custom_script, encoding="utf-8-sig")

    try:
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(custom_script_path)],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(tools_dir),
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            return {
                "success": False,
                "message": f"GPO oluşturma hatası: {error_msg[:200]}",
            }

    except subprocess.TimeoutExpired:
        return {"success": False, "message": "GPO oluşturma zaman aşımına uğradı (60s)."}
    except FileNotFoundError:
        return {"success": False, "message": "PowerShell bulunamadı. GPO oluşturma için PowerShell gereklidir."}

    # Find the generated GPO backup directory
    gpo_dir = out_dir / f"GPO_Backup_{timestamp}"
    if not gpo_dir.exists():
        return {"success": False, "message": "GPO backup klasörü oluşturulamadı."}

    # Zip the GPO backup folder
    filename = f"CIS_GPO_Backup_{timestamp}.zip"
    zip_path = out_dir / filename

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in gpo_dir.rglob("*"):
            if file_path.is_file():
                arcname = file_path.relative_to(gpo_dir.parent)
                zf.write(file_path, arcname)

    # Clean up temp files
    shutil.rmtree(temp_rules_dir, ignore_errors=True)
    shutil.rmtree(gpo_dir, ignore_errors=True)
    custom_script_path.unlink(missing_ok=True)

    sha256 = _sha256(zip_path)

    return {
        "success": True,
        "message": f"{len(rule_files)} kural için GPO backup oluşturuldu.",
        "artifact_id": artifact_id,
        "filename": filename,
        "sha256": sha256,
    }


# ── Public API ───────────────────────────────────────────────────────────────

def generate(os_name: str, rule_ids: List[str], fmt: str, permanent: bool = False) -> dict:
    """Generate configuration artifact for the given OS and format."""
    if os_name == "ubuntu":
        if fmt == "bash":
            result = _generate_ubuntu_bash(rule_ids)
        else:  # default: ansible
            result = _generate_ubuntu_ansible(rule_ids)
    elif os_name == "windows":
        if fmt == "gpo":
            result = _generate_windows_gpo(rule_ids)
        else:  # default: powershell
            result = _generate_windows_ps1(rule_ids)
    else:
        return {"success": False, "message": f"Desteklenmeyen OS: {os_name}"}

    if permanent and result.get("success") and result.get("artifact_id"):
        existing_id = _find_permanent_by_sha256(result["sha256"])
        if existing_id:
            # Identical content already stored permanently — discard duplicate, reuse existing
            delete_artifact(result["artifact_id"])
            result["artifact_id"] = existing_id
        else:
            _mark_permanent(result["artifact_id"])

    return result


def get_artifact_path(artifact_id: str) -> Path | None:
    """Return the path to the first file in the artifact directory."""
    art_dir = ARTIFACTS_DIR / artifact_id
    if not art_dir.exists():
        return None
    # Return the first non-hidden, non-marker file
    files = [
        f for f in art_dir.iterdir()
        if f.is_file() and not f.name.startswith((".", "_"))
    ]
    return files[0] if files else None


def get_artifact_info(artifact_id: str) -> dict | None:
    """Return filename and sha256 for an existing permanent artifact, or None if not found."""
    if not is_artifact_permanent(artifact_id):
        return None
    file_path = get_artifact_path(artifact_id)
    if not file_path or not file_path.exists():
        return None
    return {
        "filename": file_path.name,
        "sha256": _sha256(file_path),
    }
