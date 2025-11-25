#!/usr/bin/env python3
"""Generate a registry JSON from the Rules directory.

The registry captures the rule ID, title, section, and the locations of the
corresponding audit and remediation scripts. It derives metadata from the
folder hierarchy beneath ``Rules/`` where each rule directory contains both an
``audit.sh`` file and a remediation script whose filename contains
``remediation``.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterable, List, Tuple


RuleEntry = dict


def parse_rule_directory(rule_dir: Path, section: str) -> RuleEntry | None:
    """Return a registry entry if audit/remediation scripts exist."""
    audit_path = rule_dir / "audit.sh"
    remediation_candidates = sorted(rule_dir.glob("*remediation*.sh"))

    if not audit_path.exists() or not remediation_candidates:
        return None

    remediation_path = remediation_candidates[0]
    rule_name = rule_dir.name

    if " " in rule_name:
        rule_id, title = rule_name.split(" ", 1)
    else:
        rule_id, title = rule_name, rule_name

    return {
        "id": rule_id,
        "title": title,
        "section": section,
        "audit": str(audit_path.as_posix()),
        "remediation": str(remediation_path.as_posix()),
    }


def natural_key(rule_id: str) -> Tuple:
    """Produce a key that keeps numeric rule fragments in order."""
    fragments = re.split(r"(\d+)", rule_id)
    key_parts: List[int | str] = []
    for fragment in fragments:
        if fragment.isdigit():
            key_parts.append(int(fragment))
        elif fragment:
            key_parts.append(fragment)
    return tuple(key_parts)


def discover_rules(base_path: Path) -> List[RuleEntry]:
    registry: List[RuleEntry] = []
    for section_dir in sorted(base_path.iterdir()):
        if not section_dir.is_dir():
            continue
        for rule_dir in section_dir.rglob("*"):
            if not rule_dir.is_dir():
                continue
            entry = parse_rule_directory(rule_dir, section_dir.name)
            if entry:
                registry.append(entry)
    registry.sort(key=lambda entry: natural_key(entry["id"]))
    return registry


def write_registry(registry: Iterable[RuleEntry], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(list(registry), handle, indent=2)
        handle.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate rule registry JSON")
    parser.add_argument(
        "--rules-dir", default="Rules", type=Path, help="Root directory containing rule folders"
    )
    parser.add_argument(
        "--output", default=Path("rules/index.json"), type=Path, help="Output registry path"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    registry = discover_rules(args.rules_dir)
    write_registry(registry, args.output)
    print(f"Discovered {len(registry)} rules under {args.rules_dir} -> {args.output}")


if __name__ == "__main__":
    main()
