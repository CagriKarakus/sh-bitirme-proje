#!/usr/bin/env python3
"""Compose a bundled remediation script from rule IDs.

The tool reads ``rules/index.json`` (or another registry path) and concatenates
audit/remediation snippets for the requested rule IDs into a single bash script
with consistent headers and per-rule labels inspired by OpenSCAP output.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Dict, List

HEADER = """#!/usr/bin/env bash
###############################################################################
#
# Generated remediation bundle
#
# Source registry : {registry}
# Generated on    : {timestamp} UTC
# Rule count      : {rule_count}
#
# This script concatenates audit and remediation content for selected rules.
# Each rule block includes its audit instructions followed by remediation steps.
#
###############################################################################
"""

FOOTER = """
###############################################################################
# End of generated remediation bundle
###############################################################################
(>&2 echo "Completed rendering {rule_count} rule block(s) from {registry}")
"""


class Registry:
    def __init__(self, entries: List[Dict[str, str]]):
        self.entries = {entry["id"]: entry for entry in entries}

    @classmethod
    def from_file(cls, path: Path) -> "Registry":
        with path.open("r", encoding="utf-8") as handle:
            entries = json.load(handle)
        return cls(entries)

    def resolve(self, rule_id: str) -> Dict[str, str]:
        if rule_id not in self.entries:
            raise KeyError(f"Rule ID '{rule_id}' not found in registry")
        return self.entries[rule_id]


def read_file(path: Path) -> str:
    with path.open("r", encoding="utf-8") as handle:
        return handle.read().rstrip() + "\n"


def build_rule_block(entry: Dict[str, str], index: int, total: int) -> str:
    """Render one rule block with an inert audit transcript and runnable remediation."""

    label = f"{entry['id']} {entry['title']}"
    audit_block = "\n".join(
        [
            f": <<'__AUDIT_{index}__'  # Audit transcript (not executed)",
            read_file(Path(entry["audit"])).rstrip("\n"),
            f"__AUDIT_{index}__",
        ]
    )

    lines = [
        "###############################################################################",
        f"# BEGIN fix ({index} / {total}) for '{label}'",
        "###############################################################################",
        f"(>&2 echo \"Remediating rule {index}/{total}: '{label}'\")",
        "",
        "# --- Audit ---",
        audit_block,
        "# --- Remediation ---",
        read_file(Path(entry["remediation"])),
        f"# END fix for '{label}'",
        "",
    ]
    return "\n".join(lines)


def compose_script(registry_path: Path, rule_ids: List[str], output_path: Path) -> str:
    registry = Registry.from_file(registry_path)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    total = len(rule_ids)
    header = HEADER.format(registry=registry_path, timestamp=timestamp, rule_count=total)
    footer = FOOTER.format(rule_count=total, registry=registry_path)

    blocks = [build_rule_block(registry.resolve(rule_id), idx + 1, total) for idx, rule_id in enumerate(rule_ids)]
    script = "\n".join([header, *blocks, footer])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write(script)

    return script


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compose remediation bash script from rule IDs")
    parser.add_argument("rule_ids", nargs="+", help="Rule IDs to include, in desired order")
    parser.add_argument("--registry", default=Path("rules/index.json"), type=Path, help="Path to registry JSON")
    parser.add_argument("--output", default=Path("samples/generated_remediation.sh"), type=Path, help="Where to write the combined script")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    compose_script(args.registry, args.rule_ids, args.output)
    print(f"Wrote remediation bundle with {len(args.rule_ids)} rule(s) to {args.output}")


if __name__ == "__main__":
    main()
