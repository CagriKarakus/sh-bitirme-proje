"""Load rules from the platforms/ directory into a unified format."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List

from models import RuleItem

# Resolve project root (three levels up from web/backend/services/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# ── In-memory cache ───────────────────────────────────────────────────────────
_CACHE_TTL = 60.0  # seconds
_cache: dict[str, tuple[dict, float]] = {}  # os_name → (grouped_result, timestamp)


# ── Ubuntu loader ────────────────────────────────────────────────────────────

def _load_ubuntu_rules() -> List[RuleItem]:
    """Read the Ubuntu desktop index.json and return unified RuleItems."""
    index_path = PROJECT_ROOT / "platforms" / "linux" / "ubuntu" / "desktop" / "rules" / "index.json"
    if not index_path.exists():
        return []

    with open(index_path, "r", encoding="utf-8") as f:
        entries = json.load(f)

    rules: List[RuleItem] = []
    for entry in entries:
        rules.append(
            RuleItem(
                rule_id=entry["id"],
                title=entry.get("title", entry["id"]),
                section=entry.get("section", "Unknown"),
                os="ubuntu",
                cis_level=None,
                category=entry.get("section"),
                subcategory=None,
                description=None,
                automated=entry.get("remediation") is not None,
                severity=None,
                tags=[],
            )
        )
    return rules


# ── Windows loader ───────────────────────────────────────────────────────────

def _load_windows_directory(base_dir: Path, is_manual: bool = False) -> List[RuleItem]:
    """Walk a windows rules directory and load all .json files."""
    rules: List[RuleItem] = []
    if not base_dir.exists():
        return rules

    for json_file in sorted(base_dir.rglob("*.json")):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

        # Skip files without rule_id (not actual rule files)
        if "rule_id" not in data:
            continue

        # Derive section from parent directory name
        section_dir = json_file.parent.name
        section = data.get("category", section_dir)
        impact = data.get("impact", {})

        rules.append(
            RuleItem(
                rule_id=data["rule_id"],
                title=data.get("title", data["rule_id"]),
                section=section,
                os="windows",
                cis_level=data.get("cis_level"),
                category=data.get("category"),
                subcategory=data.get("subcategory"),
                description=data.get("description"),
                automated=data.get("automated", not is_manual),
                severity=impact.get("severity") if isinstance(impact, dict) else None,
                tags=data.get("tags", []),
            )
        )
    return rules


def _load_windows_rules() -> List[RuleItem]:
    """Load both automated and manual Windows rules."""
    win_base = PROJECT_ROOT / "platforms" / "windows"
    automated = _load_windows_directory(win_base / "rules")
    manual = _load_windows_directory(win_base / "manual_rules", is_manual=True)
    return automated + manual


# ── Public API ───────────────────────────────────────────────────────────────

def load_rules(os_name: str) -> List[RuleItem]:
    """Return all rules for the given OS."""
    if os_name == "ubuntu":
        return _load_ubuntu_rules()
    elif os_name == "windows":
        return _load_windows_rules()
    else:
        return []


def load_rules_grouped(os_name: str) -> Dict[str, List[RuleItem]]:
    """Return rules grouped by section. Results are cached for _CACHE_TTL seconds."""
    now = time.monotonic()
    cached = _cache.get(os_name)
    if cached is not None and (now - cached[1]) < _CACHE_TTL:
        return cached[0]

    rules = load_rules(os_name)
    grouped: Dict[str, List[RuleItem]] = {}
    for rule in rules:
        key = rule.section or "Other"
        grouped.setdefault(key, []).append(rule)

    _cache[os_name] = (grouped, now)
    return grouped
