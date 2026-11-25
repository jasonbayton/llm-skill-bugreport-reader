#!/usr/bin/env python3
"""Search report members with bounded context, or revisit an exact source line."""
from __future__ import annotations

import argparse
from collections import deque
from pathlib import Path
import re
import sys

from evidence_context import ContextTracker

from report_io import iter_lines, redact, new_coverage, add_scan_arguments, limits_from_args


def locate(report: Path, patterns: list[str], context: int, max_hits: int,
           member_substring: str | None = None, *, coverage=None, limits=None,
           line_numbers=None, literal=False, annotate=False):
    if not 0 <= context <= 100 or not 1 <= max_hits <= 1000:
        raise ValueError('Context/hit limits out of range')
    expressions = [re.compile(re.escape(p) if literal else p, re.I) for p in patterns]
    targets = set(line_numbers or [])
    cov = coverage if coverage is not None else new_coverage()
    prev = deque(maxlen=context)
    last_member = None
    after = 0
    matched = 0
    last_emitted = 0
    tracker = ContextTracker()
    def row(kind, member, number, raw, metadata):
        value = (kind, member, number, redact(raw)[:1200])
        return value + (metadata,) if annotate else value
    for member, line_no, raw in iter_lines(report, coverage=cov, limits=limits, member_substring=member_substring):
        metadata = tracker.feed(member, line_no, raw)
        if member != last_member:
            last_member = member
            prev.clear()
            after = 0
            last_emitted = 0
        is_match = matched < max_hits and (line_no in targets or any(exp.search(raw) for exp in expressions))
        if is_match:
            matched += 1
            for old in prev:
                if old[1] > last_emitted:
                    yield row('context', old[0], old[1], old[2], old[3])
                    last_emitted = old[1]
            yield row('match', member, line_no, raw, metadata)
            last_emitted = line_no
            after = context
        elif after > 0:
            yield row('context', member, line_no, raw, metadata)
            last_emitted = line_no
            after -= 1
        prev.append((member, line_no, raw, metadata))
        if matched >= max_hits and after == 0:
            cov['stopped_early'] = True
            cov['complete'] = False
            break


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument('--pattern', action='append', help='Case-insensitive regex (repeatable)')
    selector.add_argument('--line', type=int, action='append', help='One-based physical line (use --member to select its source)')
    parser.add_argument('--literal', action='store_true', help='Interpret --pattern as a fixed string')
    parser.add_argument('--context', type=int, default=8)
    parser.add_argument('--max-hits', type=int, default=40)
    add_scan_arguments(parser)
    args = parser.parse_args()
    if args.line and min(args.line) < 1:
        parser.error('--line must be positive')
    try:
        cov = new_coverage()
        found = False
        for kind, member, number, excerpt, metadata in locate(args.report, args.pattern or [], args.context,
                                                    args.max_hits, args.member, coverage=cov,
                                                    limits=limits_from_args(args), line_numbers=args.line,
                                                    literal=args.literal, annotate=True):
            found = True
            marker = '>' if kind == 'match' else ' '
            print(f"{marker} {member}:{number} [{metadata['kind']} / {metadata['section']} / buffer={metadata['buffer']} / {metadata['timeline_segment']} / boot={metadata['boot_epoch']} / package={metadata['package'] or 'unknown'} / subsection={metadata['package_subsection'] or 'unknown'} / package_state={metadata['package_state_kind']}]: {excerpt}")
        if not found:
            print('No matches in the selected text scope; absence is not proof the event did not occur.')
        if cov['stopped_early']:
            print('Search stopped at the hit limit; this is a sample, not an exhaustive search.', file=sys.stderr)
        for item in cov['skipped']:
            print(f"NOT SCANNED {item['source']}: {item['reason']}", file=sys.stderr)
        if cov['truncated_lines']:
            print('Long lines were clipped; coverage is incomplete.', file=sys.stderr)
        if cov['source_truncation_markers']:
            print('Source contains explicit truncation markers; captured evidence is incomplete.', file=sys.stderr)
        if cov['decode_replacement_lines']:
            print('Some lines contained undecodable bytes; decoded with replacement.', file=sys.stderr)
        if cov['null_byte_lines']:
            print('Null bytes in text candidates rendered as [NUL]; mixed binary sections need separate interpretation.', file=sys.stderr)
        return 0
    except Exception as error:
        print(f'Search failed: {type(error).__name__}: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
