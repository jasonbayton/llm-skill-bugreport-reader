#!/usr/bin/env python3
"""Extract exact Package blocks and their own per-user state; never infer incident history."""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from report_io import iter_lines, new_coverage, redact, add_scan_arguments, limits_from_args
from evidence_context import ContextTracker

USER = re.compile(r'^\s*User (\d+):\s*(.*)')
FIELDS = re.compile(r'\b(installed|enabled|hidden|suspended|stopped|notLaunched|instant|virtual)=([^\s]+)')
META = re.compile(r'\b(versionCode|installerPackageName|initiatingPackageName|originatingPackageName|userId|appId)=([^\s]+)')


def uid_identity(uid):
    if not re.fullmatch(r'\d+', str(uid)):
        raise ValueError('UID must be a nonnegative numeric Android UID, not a package appId or label')
    uid = int(uid)
    return {'uid': uid, 'user_id': uid // 100000, 'app_id': uid % 100000,
            'caveat': 'Arithmetic identity only; shared/isolated UID does not identify one package. A package-level userId/appId is not necessarily a full per-user UID.'}


def extract(report, package, *, member=None, limits=None):
    cov = new_coverage(); tracker = ContextTracker(); records = []; active = None
    for source, number, raw in iter_lines(report, coverage=cov, limits=limits, member_substring=member):
        context = tracker.feed(source, number, raw)
        if active and (source != active['source'] or context['package_line'] != active['line']):
            active = None
        if context['package_line'] == number:
            active = None
            if context['package'] == package:
                active = {'package': package, 'source': source, 'line': number, 'section': context['section'],
                          'package_subsection': context['package_subsection'],
                          'package_state_kind': context['package_state_kind'],
                          'basis': ('factory_system_image_copy_not_current_state'
                                    if context['package_state_kind'] == 'factory_system_image_copy'
                                    else 'capture_snapshot_not_incident_history'),
                          'metadata': {}, 'users': []}
                records.append(active)
            continue
        if not active:
            continue
        user = USER.match(raw)
        if user:
            values = dict(FIELDS.findall(user[2]))
            active['users'].append({'user_id': int(user[1]), 'line': number, 'state': values})
        else:
            version = re.match(r'^\s*versionName=(.*)', raw)
            if version:
                active['metadata']['versionName'] = {'value': redact(re.split(r'\s+\w+=', version[1], maxsplit=1)[0]), 'line': number}
            for key, value in META.findall(raw):
                active['metadata'][key] = {'value': redact(value), 'line': number}
    return {'package': package, 'records': records, 'coverage': cov,
            'notice': 'No matching block is not proof of absence. enabled is retained as a raw enum; default is not disabled. Version/installer metadata is package-level, user states are block-specific. Hidden system packages are factory copies, not current installed state; an absent subsection stays unknown.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('report', type=Path); p.add_argument('package')
    p.add_argument('--uid', help='Also decode a full numeric Android UID')
    add_scan_arguments(p); a = p.parse_args()
    try:
        result = extract(a.report, a.package, member=a.member, limits=limits_from_args(a))
        if a.uid is not None: result['uid_identity'] = uid_identity(a.uid)
        print(json.dumps(result, indent=2)); return 0
    except Exception as e:
        p.exit(2, f'Package extraction failed: {type(e).__name__}: {e}\n')

if __name__ == '__main__':
    raise SystemExit(main())
