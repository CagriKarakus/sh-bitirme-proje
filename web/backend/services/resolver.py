"""Dependency / conflict resolver for selected rules.

Checks:
1. Missing dependencies  – rule A depends_on B but B is not selected → warning
2. Conflicts             – rule A conflicts_with B and both selected → error

Dependency data sources:
- Ubuntu:  statically defined dependency map (extracted from docs/kural_bagimliliklari.py)
- Windows: (future) depends_on / conflicts_with fields in rule JSONs
"""

from __future__ import annotations

from typing import Dict, List, Set

from models import Error, ResolveResult, Warning


# ── Static dependency data ───────────────────────────────────────────────────
# Extracted from docs/kural_bagimliliklari.py
# Format: { rule_id: { "depends_on": [rule_ids], "conflicts_with": [rule_ids] } }

UBUNTU_DEPENDENCIES: Dict[str, Dict[str, List[str]]] = {
    # Firewall – UFW chain
    "4.2.1": {"depends_on": ["4.1.1"], "conflicts_with": []},
    "4.2.2": {"depends_on": ["4.2.1"], "conflicts_with": []},
    "4.2.3": {"depends_on": ["4.2.1"], "conflicts_with": []},
    "4.2.4": {"depends_on": ["4.2.3"], "conflicts_with": []},
    "4.2.5": {"depends_on": ["4.2.4"], "conflicts_with": []},
    "4.2.6": {"depends_on": ["4.2.5"], "conflicts_with": []},
    "4.2.7": {"depends_on": ["4.2.6"], "conflicts_with": []},

    # Firewall – nftables chain
    "4.3.2": {"depends_on": ["4.1.1"], "conflicts_with": []},
    "4.3.3": {"depends_on": ["4.3.2"], "conflicts_with": []},
    "4.3.4": {"depends_on": ["4.3.3"], "conflicts_with": []},
    "4.3.5": {"depends_on": ["4.3.4"], "conflicts_with": []},
    "4.3.6": {"depends_on": ["4.3.5"], "conflicts_with": []},
    "4.3.7": {"depends_on": ["4.3.2"], "conflicts_with": []},
    "4.3.8": {"depends_on": ["4.3.7"], "conflicts_with": []},
    "4.3.9": {"depends_on": ["4.3.8"], "conflicts_with": []},

    # Firewall – iptables chain
    "4.4.2.1": {"depends_on": ["4.1.1"], "conflicts_with": []},
    "4.4.2.2": {"depends_on": ["4.4.2.1"], "conflicts_with": []},
    "4.4.2.3": {"depends_on": ["4.4.2.2"], "conflicts_with": []},
    "4.4.2.4": {"depends_on": ["4.4.2.3"], "conflicts_with": []},

    # Mutual exclusion – firewall groups
    # If UFW rules selected, they conflict with nftables and iptables
    "4.2.1_group": {"depends_on": [], "conflicts_with": ["4.3.2", "4.4.2.1"]},
    "4.3.2_group": {"depends_on": [], "conflicts_with": ["4.2.1", "4.4.2.1"]},
    "4.4.2.1_group": {"depends_on": [], "conflicts_with": ["4.2.1", "4.3.2"]},

    # GDM dependencies
    "1.7.2": {"depends_on": [], "conflicts_with": []},
    "1.7.3": {"depends_on": ["1.7.1"], "conflicts_with": []},
    "1.7.4": {"depends_on": ["1.7.1"], "conflicts_with": []},
    "1.7.5": {"depends_on": ["1.7.4"], "conflicts_with": []},
    "1.7.6": {"depends_on": ["1.7.1"], "conflicts_with": []},

    # PAM chain
    "5.3.2.1": {"depends_on": ["5.3.1.1"], "conflicts_with": []},
    "5.3.2.2": {"depends_on": ["5.3.1.1"], "conflicts_with": []},
    "5.3.2.3": {"depends_on": ["5.3.1.1"], "conflicts_with": []},
    "5.3.2.4": {"depends_on": ["5.3.1.1"], "conflicts_with": []},
    "5.3.3.1.1": {"depends_on": ["5.3.2.2"], "conflicts_with": []},
    "5.3.3.1.2": {"depends_on": ["5.3.2.2"], "conflicts_with": []},
    "5.3.3.1.3": {"depends_on": ["5.3.2.2"], "conflicts_with": []},
}

# Firewall mutual-exclusion groups (if any rule from group A and group B are
# both selected, that is a conflict).
_UFW_RULES = {"4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7"}
_NFT_RULES = {"4.3.2", "4.3.3", "4.3.4", "4.3.5", "4.3.6", "4.3.7", "4.3.8", "4.3.9"}
_IPT_RULES = {"4.4.2.1", "4.4.2.2", "4.4.2.3", "4.4.2.4"}
_FIREWALL_GROUPS = [_UFW_RULES, _NFT_RULES, _IPT_RULES]


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
        deps = UBUNTU_DEPENDENCIES

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
