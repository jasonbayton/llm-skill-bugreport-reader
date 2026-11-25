#!/usr/bin/env python3
"""Read-only management and health overview, with optional offline HTML."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence_context import ContextTracker
from package_state import PackageCollector
from report_io import iter_lines, new_coverage, redact, add_scan_arguments, limits_from_args, validate_output_paths

BASICS = {
    'ro.product.manufacturer': 'Manufacturer', 'ro.product.model': 'Model',
    'ro.build.version.release': 'Android version', 'ro.build.version.sdk': 'API level',
    'ro.build.id': 'Build ID', 'ro.build.type': 'Build type',
    'ro.build.version.security_patch': 'Security patch', 'ro.vendor.build.security_patch': 'Vendor patch',
    'ro.boot.verifiedbootstate': 'Verified Boot state', 'ro.boot.flash.locked': 'Bootloader locked flag',
    'ro.boot.vbmeta.device_state': 'VBMeta device state', 'ro.crypto.state': 'Encryption state',
    'persist.sys.timezone': 'Timezone', 'ro.fw.mu.headless_system_user': 'Headless system user flag',
}
PROP = re.compile(r'^\s*\[([^\]]+)\]\s*:\s*\[([^\]]*)\]')
OWNER = re.compile(r'^\s*(Device Owner|Profile Owner)(?:\s*\(User\s+(\d+)\))?\s*[:=]\s*(.*)$', re.I)
COMPONENT = re.compile(r'(?:ComponentInfo\{)?([A-Za-z][\w.]*/[\w.$]+)')
POLICY = re.compile(r'^(?:m)?(?:disableCamera|cameraDisabled|disableScreenCapture|screenCaptureDisabled|'
                    r'password\w*|minimumPassword\w*|maximumTimeTo\w*|maximumFailedPasswords\w*|'
                    r'strongAuth\w*|requiredPasswordComplexity|keyguardDisabledFeatures|'
                    r'lockTask\w*|isNetworkLoggingEnabled|networkLoggingEnabled|'
                    r'isSecurityLoggingEnabled|securityLoggingEnabled|encryptionRequested|'
                    r'isOrganizationOwnedDevice\w*|organizationOwned\w*)\b', re.I)
PAIR = re.compile(r'^\s*([\w][\w .()-]*?)\s*[:=]\s*(.*?)\s*$')
SECTIONS = ('basics', 'ownership', 'users', 'policies', 'restrictions', 'health')
HEALTH_NOTE = ('Snapshots and retained aggregates are not a health certification. Battery charge and the Android '
               'health flag do not establish battery wear or remaining full-charge capacity. Missing metrics are unknown.')
BATTERY_HEALTH = {'1': 'Unknown', '2': 'Good', '3': 'Overheat', '4': 'Dead', '5': 'Over voltage',
                  '6': 'Unspecified failure', '7': 'Cold'}
BATTERY_FIELDS = {'level', 'scale', 'status', 'health', 'present', 'voltage', 'temperature', 'technology',
                  'charge counter', 'cycle count', 'ac powered', 'usb powered', 'wireless powered',
                  'max charging current', 'max charging voltage', 'battery full charge', 'battery capacity',
                  'battery capacity level', 'charging state', 'battery health', 'updates stopped'}


def service_name(section):
    match = re.match(r'DUMP OF SERVICE\s+(\S+)', section, re.I)
    return match[1].lower() if match else None


def make_capture(source):
    return {'source': source, **{key: [] for key in SECTIONS}, 'packages': [], 'sections_seen': [],
            'omitted_rows': {}, 'conflicts': [], 'gaps': []}


def analyse_overview(report: Path, *, member=None, limits=None, max_rows=2000, max_packages=5000):
    if max_rows < 1 or max_packages < 1:
        raise ValueError('Overview row limits must be positive')
    coverage = new_coverage()
    tracker = ContextTracker()
    packages = PackageCollector(max_records=max_packages)
    captures = {}
    current_source = None
    owner = None
    user_id = None
    user_indent = None
    stack = []
    unsectioned_service = None
    for source, number, raw in iter_lines(report, coverage=coverage, limits=limits, member_substring=member):
        context = tracker.feed(source, number, raw)
        packages.feed(source, number, raw, context)
        if source != current_source or context['boundary'] in ('section_boundary', 'buffer_boundary_not_reboot'):
            owner, user_id, user_indent, stack, unsectioned_service = None, None, None, [], None
            current_source = source
        capture = captures.setdefault(source, make_capture(source))
        section = context['section']
        if section not in capture['sections_seen'] and len(capture['sections_seen']) < 200:
            capture['sections_seen'].append(section)
        if context['kind'] in ('log', 'retained_history', 'collector'):
            continue
        if raw.strip() == 'Current Device Policy Manager state:':
            unsectioned_service = 'device_policy'
        elif raw.strip() == 'Current Battery Service state:':
            unsectioned_service = 'battery'
        service = service_name(section) or unsectioned_service
        text = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if owner and text and indent <= owner['_indent']:
            owner = None
        if user_indent is not None and text and indent <= user_indent:
            user_id, user_indent = None, None
        while stack and text and indent <= stack[-1][0]:
            stack.pop()
        scope = ' / '.join(label for _, label in stack) or 'scope not established'
        if user_id is not None:
            parent_scope = any('parentAdmin' in label for _, label in stack)
            scope = (f'Admin user {user_id}; parent-profile target not resolved / {scope}' if parent_scope
                     else f'User {user_id} / {scope}')

        def add(group, label, value, basis='capture snapshot', row_scope=None, excerpt=None):
            if len(capture[group]) >= max_rows:
                capture['omitted_rows'][group] = capture['omitted_rows'].get(group, 0) + 1
                return None
            row = {'label': redact(str(label)), 'value': redact(str(value))[:600], 'basis': basis,
                   'scope': redact(row_scope or scope), 'source': source, 'line': number,
                   'section': section, 'excerpt': redact(raw if excerpt is None else excerpt)[:600]}
            if len(redact(str(value))) > 600:
                row['value_truncated'] = True
                capture['omitted_rows']['long_values_clipped'] = capture['omitted_rows'].get('long_values_clipped', 0) + 1
            capture[group].append(row)
            return row

        prop = PROP.match(raw)
        if prop and prop[1] in BASICS:
            add('basics', BASICS[prop[1]], prop[2], 'observed system property', 'device',
                f'[{prop[1]}]: [{prop[2]}]')
        if text.lower().startswith('== dumpstate:'):
            add('basics', 'Capture time', text.split(':', 1)[1].strip(), 'capture header', 'capture')
        pair = PAIR.match(raw)

        if service == 'device_policy':
            match = OWNER.match(raw)
            if match:
                component = COMPONENT.search(match[3])
                value = component[1] if component else ('Explicitly none' if match[3].lower() in ('null', 'none') else 'Admin component not shown')
                owner = add('ownership', match[1].title(), value, 'owner record at capture',
                            'User ' + match[2] if match[2] else 'user not shown')
                if owner:
                    owner.update(_indent=indent, user_id=int(match[2]) if match[2] else None,
                                 component=component[1] if component else None, organization_owned=None)
            elif owner:
                component = COMPONENT.search(raw) if re.match(r'^\s*admin\s*=', raw) else None
                if component:
                    owner['component'] = component[1]
                    owner['value'] = component[1]
                    owner['component_line'] = number
                own_user = re.match(r'^\s*User ID:\s*(\d+)', raw)
                if own_user:
                    owner['user_id'] = int(own_user[1])
                    owner['scope'] = 'User ' + own_user[1]
                    owner['user_line'] = number
                org = re.match(r'^\s*isOrganizationOwnedDevice\s*=\s*(true|false)', raw)
                if org:
                    owner['organization_owned'] = org[1]
                    owner['organization_owned_line'] = number
            if POLICY.match(text) and pair:
                add('policies', pair[1], pair[2], 'recorded policy/flag; enforcement not inferred',
                    row_scope=owner['scope'] if owner else None)
            policy_user = re.search(r'\bUser\s+(\d+)', text) if text.endswith(':') else None
            if policy_user and not OWNER.match(raw):
                user_id, user_indent = int(policy_user[1]), indent
            if text.endswith(':') and len(text) < 200 and not OWNER.match(raw):
                # The hierarchy includes parentAdmin and declared-policy blocks without decoding them.
                label = redact(text[:-1])
                stack.append((indent, label))
        if service == 'user':
            user = re.search(r'UserInfo\{(\d+):[^:}]*:([^}]+)\}', raw)
            if user:
                user_id, user_indent = int(user[1]), indent
                safe = f'UserInfo{{{user[1]}:[name omitted]:{user[2]}}}'
                attrs = re.findall(r'\b(?:parentId|profileGroupId|isPrimary)=[\w-]+', raw)
                add('users', 'User record', safe + (' ' + ' '.join(attrs) if attrs else ''),
                    row_scope=f'User {user_id}', excerpt=safe + ' ' + ' '.join(attrs))
            elif pair and re.fullmatch(r'Type|Flags|State|Has profile owner|profileGroupId|parentId|quietMode|isQuietModeEnabled|Current user', pair[1], re.I):
                add('users', pair[1], pair[2], row_scope=f'User {user_id}' if user_id is not None else 'device / unknown user')
            if text.endswith(':') and re.search(r'restrictions', text, re.I):
                stack.append((indent, text[:-1]))
        restriction_scope = next((label for _, label in reversed(stack) if 'restriction' in label.lower()), None)
        if service in ('user', 'device_policy') and restriction_scope:
            basis = ('effective restriction cache at capture' if service == 'user' and restriction_scope.lower() == 'effective restrictions'
                     else 'recorded restriction; effective state not established')
            for match in re.finditer(r'\b(no_[a-z_]+|ensure_verify_apps|DISALLOW_[A-Z_]+)\s*=\s*(true|false)\b', raw):
                add('restrictions', match[1], match[2], basis)
            if text.lower() in ('null', 'none', '(none)', '{}'):
                add('restrictions', restriction_scope, 'Explicitly empty', basis)
        if service in ('activity', 'activity activities', 'window') and pair and re.match(r'mLockTask(?:ModeState|Packages|Features)', pair[1]):
            add('policies', pair[1], pair[2], 'runtime state at capture; not historical proof')

        if service == 'battery' and pair and pair[1].lower() in BATTERY_FIELDS:
            label, value = pair[1], pair[2]
            if label.lower() == 'health':
                value += ' — ' + BATTERY_HEALTH.get(value, 'unrecognised raw code') + ' (platform flag, not battery wear)'
            elif label.lower() == 'temperature' and re.fullmatch(r'-?\d+', value):
                value = f'{int(value) / 10:g} °C (raw tenths °C: {value})'
            elif label.lower() == 'voltage' and re.fullmatch(r'\d+', value):
                value += ' mV'
            add('health', 'Battery · ' + label, value, 'battery-service snapshot', 'device battery')
        if service == 'battery' and 'UPDATES STOPPED' in text.upper():
            add('health', 'Battery · updates stopped', text,
                'battery values may be frozen or simulated; not live health evidence', 'device battery')
        if service == 'batterystats' and pair and re.match(r'Time on battery|Estimated battery capacity|(?:Min|Max|Last) learned battery capacity|Start clock time', pair[1], re.I):
            add('health', 'Battery history · ' + pair[1], pair[2], 'retained aggregate; collection interval matters', 'batterystats')
        if (service == 'meminfo' or section.upper().startswith('MEMORY INFO')) and pair and re.fullmatch(r'Total RAM|Free RAM|Used RAM|Lost RAM|ZRAM|KSM', pair[1], re.I):
            add('health', 'Memory · ' + pair[1], pair[2], row_scope='memory; definitions follow the dump')
        if 'MEMORY INFO' in section.upper() and pair and pair[1] in ('MemTotal', 'MemFree', 'MemAvailable', 'Buffers', 'Cached', 'SwapTotal', 'SwapFree'):
            add('health', 'Memory · ' + pair[1], pair[2], row_scope='proc meminfo; MemFree differs from MemAvailable')
        if (service == 'diskstats' or 'FILESYSTEM' in section.upper()) and pair and re.match(r'(?:Data|Cache|System)-Free|File-based Encryption|Latency|Data size|App Size|Cache Size', pair[1], re.I):
            add('health', 'Storage · ' + pair[1], pair[2], row_scope='storage')
        if 'FILESYSTEM' in section.upper():
            fields = text.split()
            if len(fields) >= 6 and fields[0].startswith('/') and fields[-1] in ('/data', '/system', '/cache', '/metadata'):
                add('health', 'Filesystem ' + fields[-1], ' '.join(fields[1:-1]),
                    'df snapshot; units follow source header', 'storage')
        if 'UPTIME' in section.upper():
            if re.fullmatch(r'\d+(?:\.\d+)?\s+\d+(?:\.\d+)?', text):
                add('health', 'Uptime', text.split()[0] + ' seconds', 'proc uptime; first field', 'current boot')
            elif re.search(r'\bup\b|uptime|realtime', text, re.I) and not text.startswith('------'):
                add('health', 'Uptime / load', text, row_scope='current boot')
        if service == 'thermalservice' and re.search(r'Thermal Status:|Temperature\{', text):
            add('health', 'Thermal state', text, 'reported thermal snapshot; raw status codes', 'device')
    for record in packages.records:
        captures[record['source']]['packages'].append(record)
    omitted = {'package_records': packages.omitted_records, 'package_user_rows': packages.omitted_users}
    for capture in captures.values():
        for row in capture['ownership']:
            row.pop('_indent', None)
        values = {}
        for group in SECTIONS:
            for row in capture[group]:
                key = (group, row['label'], row['scope'])
                values.setdefault(key, set()).add(row['value'])
            if not capture[group]:
                capture['gaps'].append(group + ': no supported observations found; not proof of absence')
        capture['conflicts'] = [f'{group}: {label} ({scope}) has differing observations; inspect source lines'
                                for (group, label, scope), observed in values.items() if len(observed) > 1]
        if not capture['packages']:
            capture['gaps'].append('packages: no supported package blocks found')
    useful = [c for c in captures.values() if any(c[key] for key in SECTIONS) or c['packages']]
    return {'schema_version': 1, 'mode': 'device_overview', 'coverage': coverage,
            'captures': useful, 'unclassified_sources': [s for s, c in captures.items() if not any(c[key] for key in SECTIONS) and not c['packages']],
            'omitted': omitted, 'health_note': HEALTH_NOTE,
            'notice': 'Under testing. Each text source is separate; no synthetic merged device. A snapshot is not incident history. Recorded policy is not automatically effective enforcement. Redaction is best-effort; review before sharing.'}


def as_text(report):
    parts = ['DEVICE OVERVIEW', report['notice'], report['health_note']]
    for capture in report['captures']:
        parts.append('\nSOURCE: ' + capture['source'])
        for group in SECTIONS:
            parts.append('\n' + group.upper())
            for row in capture[group][:30]:
                parts.append(f"- {row['label']}: {row['value']} [{row['scope']}; {row['basis']}; line {row['line']}]")
            if len(capture[group]) > 30:
                parts.append('Additional rows are available in JSON/HTML.')
        parts.append(f"\nPackage blocks: {len(capture['packages'])} (active, factory or unknown subsection kept separate)")
        parts.extend(capture['gaps'] + capture['conflicts'])
    parts.append('\nCoverage: ' + json.dumps(report['coverage']))
    parts.append('Omitted inventory rows: ' + json.dumps(report['omitted']))
    if not report['captures']:
        parts.append('No supported state observations; this is not a clean bill of health.')
    return '\n'.join(parts) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--html', type=Path, help='New offline HTML overview file')
    parser.add_argument('--json', type=Path, help='New structured overview file')
    parser.add_argument('--max-rows', type=int, default=2000, help='Retained rows per group per source')
    parser.add_argument('--max-packages', type=int, default=5000, help='Retained package blocks across sources')
    add_scan_arguments(parser)
    args = parser.parse_args()
    try:
        outputs = [p for p in (args.html, args.json) if p]
        validate_output_paths([args.report], outputs)
        report = analyse_overview(args.report, member=args.member, limits=limits_from_args(args),
                                  max_rows=args.max_rows, max_packages=args.max_packages)
        if args.html:
            from overview_html import render
            with args.html.open('x', encoding='utf-8') as output:
                output.write(render(report))
        if args.json:
            with args.json.open('x', encoding='utf-8') as output:
                json.dump(report, output, indent=2)
        if not outputs:
            print(as_text(report), end='')
        return 0
    except Exception as error:
        parser.exit(2, f'Overview failed: {type(error).__name__}: {error}\n')


if __name__ == '__main__':
    raise SystemExit(main())
