#!/usr/bin/env python3
"""Compare two Android bugreport snapshots without claiming historical causation.

Compares observed build properties, explicit owner/user/lock-task clues,
and diagnostic signal counts. A difference is
an investigation clue, not proof of a behavioural cause.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from triage import analyse, FOCUSES
from report_io import add_scan_arguments, limits_from_args


def compare(before: dict, after: dict) -> dict:
    if before.get('multiple_capture_sources') or after.get('multiple_capture_sources'):
        raise ValueError('Multiple capture sources: analyse one main report member per input before comparison')
    keys = sorted(set(before["profile"]) | set(after["profile"]))
    changed_properties = []
    for key in keys:
        left = before["profile"].get(key, {}).get("value")
        right = after["profile"].get(key, {}).get("value")
        if left != right:
            changed_properties.append({"field": key, "before": left, "after": right,
                                       "before_source": before['profile'].get(key),
                                       "after_source": after['profile'].get(key)})

    def snapshot(report, key):
        value = report["configuration"].get(key)
        return value.get("value") if isinstance(value, dict) else None

    current_state = {}
    for key in ("lock_task_mode_at_capture", "current_user"):
        left, right = snapshot(before, key), snapshot(after, key)
        if left != right:
            current_state[key] = {"before": left, "after": right}

    def owner_pairs(report):
        return sorted({(x["type"], x["value"]) for x in report["configuration"]["owners"]})

    owner_before, owner_after = owner_pairs(before), owner_pairs(after)
    if owner_before != owner_after:
        current_state["owner_mentions"] = {"before": owner_before, "after": owner_after}

    evidence_a = {item["id"]: item["occurrences"] for item in before["findings"]}
    evidence_b = {item["id"]: item["occurrences"] for item in after["findings"]}
    changes = [{"signal": key, "before": evidence_a.get(key, 0), "after": evidence_b.get(key, 0)}
               for key in sorted(set(evidence_a) | set(evidence_b)) if evidence_a.get(key, 0) != evidence_b.get(key, 0)]
    return {"before": before["source"], "after": after["source"], "property_changes": changed_properties,
            "snapshot_changes": current_state, "signal_count_changes": changes,
            "coverage_before": before['coverage'], "coverage_after": after['coverage'],
            "profile_conflicts": {'before': before.get('profile_conflicts', {}), 'after': after.get('profile_conflicts', {})},
            "warning": "Reports may cover different time windows/boots/users. Signal-count changes are not directly comparable without coverage normalization and causal investigation."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--focus", choices=FOCUSES, default="auto")
    add_scan_arguments(parser)
    args = parser.parse_args()
    try:
        options = {'limits': limits_from_args(args), 'member_substring': args.member}
        result = compare(analyse(args.before, args.focus, [], None, 15, **options), analyse(args.after, args.focus, [], None, 15, **options))
        print("# Bugreport comparison\n")
        print(result["warning"])
        for side in ('before', 'after'):
            cov = result['coverage_' + side]
            print(f"{side}: {cov['scanned_lines']} lines, {cov['member_count']} text members; selected text scan complete: {cov['complete']}")
            for item in cov['skipped']:
                print(f"NOT SCANNED {item['source']}: {item['reason']}")
            if cov['truncated_lines']:
                print(f'{side}: long lines were clipped; negative comparisons are unreliable')
            if result['profile_conflicts'][side]:
                print(f'{side}: conflicting properties; compare individual report members before drawing conclusions')
        print("\n## Changed build/device properties")
        for item in result["property_changes"]:
            print(f"- {item['field']}: {item['before'] or '[not observed]'} -> {item['after'] or '[not observed]'}")
            for side in ('before', 'after'):
                point = item[side + '_source']
                if point:
                    print(f"  {side}: {point['source']}:{point['line']}")
        if not result["property_changes"]:
            print("- No differences in observed property subset")
        print("\n## Changed management/user snapshots")
        for field, values in result["snapshot_changes"].items():
            print(f"- {field}: {values['before']} -> {values['after']}")
        if not result["snapshot_changes"]:
            print("- No differences in indexed state subset")
        print("\n## Changed signature counts (non-causal)")
        for item in result["signal_count_changes"]:
            print(f"- {item['signal']}: {item['before']} -> {item['after']}")
        if not result["signal_count_changes"]:
            print("- No differences in indexed signature counts")
        return 0
    except Exception as error:
        print(f"Compare failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
