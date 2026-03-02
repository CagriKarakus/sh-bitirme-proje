"""Dependency / conflict resolver for selected rules.

Checks:
1. Missing dependencies  – rule A depends_on B but B is not selected → warning
2. Conflicts             – rule A conflicts_with B and both selected → error

Dependency data sources:
- Ubuntu:  depends_on / conflicts_with fields in platforms/linux/ubuntu/desktop/rules/index.json
- Windows: (future) depends_on / conflicts_with fields in rule JSONs
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Set

from models import Error, ResolveResult, Warning

# Project root (same resolution as other services)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# Firewall mutual-exclusion groups (structural constants, not per-rule metadata).
_UFW_RULES = {"4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7"}
_NFT_RULES = {"4.3.2", "4.3.3", "4.3.4", "4.3.5", "4.3.6", "4.3.7", "4.3.8", "4.3.9"}
_IPT_RULES = {"4.4.2.1", "4.4.2.2", "4.4.2.3", "4.4.2.4"}
_FIREWALL_GROUPS = [_UFW_RULES, _NFT_RULES, _IPT_RULES]


def _load_ubuntu_deps() -> Dict[str, Dict[str, List[str]]]:
    """Load per-rule dependency metadata from index.json."""
    index_path = _PROJECT_ROOT / "platforms" / "linux" / "ubuntu" / "desktop" / "rules" / "index.json"
    try:
        with open(index_path, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        e["id"]: {
            "depends_on": e.get("depends_on", []),
            "conflicts_with": e.get("conflicts_with", []),
        }
        for e in entries
        if e.get("depends_on") or e.get("conflicts_with")
    }


# ── Resolver logic ───────────────────────────────────────────────────────────

def _check_firewall_conflicts(selected: Set[str]) -> List[Error]:
    """Check if rules from mutually exclusive firewall groups are selected."""
    errors: List[Error] = []
    active_groups = []
    for group in _FIREWALL_GROUPS:
        intersection = selected & group
        if intersection:
            active_groups.append(intersection)

    if len(active_groups) > 1:
        # More than one firewall group is active → conflict
        all_conflicting = set()
        for g in active_groups:
            all_conflicting |= g
        first = sorted(all_conflicting)[0]
        last = sorted(all_conflicting)[-1]
        errors.append(
            Error(
                rule_id=first,
                conflicting_rule=last,
                message=(
                    "Birden fazla firewall grubu seçildi (UFW / nftables / iptables). "
                    "Yalnızca bir firewall çözümü seçilmelidir."
                ),
            )
        )
    return errors


def resolve(os_name: str, selected_ids: List[str]) -> ResolveResult:
    """Validate the selected rule set and return warnings / errors."""
    selected: Set[str] = set(selected_ids)
    warnings: List[Warning] = []
    errors: List[Error] = []

    if os_name == "ubuntu":
        deps = _load_ubuntu_deps()

        # Check missing dependencies
        for rule_id in selected_ids:
            rule_deps = deps.get(rule_id, {}).get("depends_on", [])
            for dep in rule_deps:
                if dep not in selected:
                    warnings.append(
                        Warning(
                            rule_id=rule_id,
                            missing_dependency=dep,
                            message=f"Kural {rule_id}, {dep} kuralına bağımlıdır ancak {dep} seçilmemiş.",
                        )
                    )

        # Check firewall mutual exclusion
        errors.extend(_check_firewall_conflicts(selected))

    elif os_name == "windows":
        # Windows rules don't have depends_on/conflicts_with fields yet.
        # For now, pass through as valid.
        pass

    valid = len(errors) == 0
    return ResolveResult(valid=valid, warnings=warnings, errors=errors)
