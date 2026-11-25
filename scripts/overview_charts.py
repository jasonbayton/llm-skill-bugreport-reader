"""Small, evidence-backed snapshot charts. No invented history or health scores."""
from html import escape
import math
import re


def unique(rows, label):
    matches = [r for r in rows if r['label'].lower() == label.lower()]
    if not matches or any(r.get('value_truncated') for r in matches):
        return None
    signatures = {(r['value'], r.get('scope'), r.get('section')) for r in matches}
    return matches[0] if len(signatures) == 1 else None


def number(row):
    if not row:
        return None
    try:
        result = float(row['value'])
        return result if math.isfinite(result) else None
    except ValueError:
        return None


def kib(row):
    # Android's meminfo K/kB fields are KiB. Leave unfamiliar units unplotted.
    match = re.match(r'^([\d,]+)\s*(?:K|kB)\b', row['value']) if row else None
    return int(match[1].replace(',', '')) if match else None


def snapshot_metrics(capture):
    rows = capture['health']
    result = {'battery': None, 'memory': None, 'storage': [], 'apps': [], 'app_conflicts': 0}
    level, scale = unique(rows, 'Battery · level'), unique(rows, 'Battery · scale')
    amount, maximum = number(level), number(scale)
    if amount is not None and maximum is not None and maximum > 0 and 0 <= amount <= maximum and level['section'] == scale['section']:
        result['battery'] = {'percent': 100 * amount / maximum, 'rows': [level, scale],
                             'frozen': any(r['label'].lower() == 'battery · updates stopped' and r['value'].lower() != 'false' for r in rows)}
    # Prefer available RAM from proc. Never substitute MemFree for MemAvailable.
    for total_label, part_label, part_name in [('MemTotal', 'MemAvailable', 'Available'),
                                              ('Total RAM', 'Free RAM', 'Free (includes cache)')]:
        total_row, part_row = (unique(rows, 'Memory · ' + label) for label in (total_label, part_label))
        total, part = kib(total_row), kib(part_row)
        if total is not None and part is not None and total > 0 and 0 <= part <= total and total_row['section'] == part_row['section']:
            result['memory'] = {'total': total, 'part': part, 'label': part_name,
                                'rows': [total_row, part_row]}
            break
    for label in ('Data', 'Cache', 'System'):
        row = unique(rows, f'Storage · {label}-Free')
        match = re.fullmatch(r'([\d,]+)K\s*/\s*([\d,]+)K total(?:\s*=.*)?', row['value']) if row else None
        if match:
            free, total = (int(v.replace(',', '')) for v in match.groups())
            if total > 0 and 0 <= free <= total:
                result['storage'].append({'label': label, 'total': total, 'free': free, 'rows': [row]})
    # Count unique active package/user pairs. Factory copies and conflicting pairs
    # cannot provide a current inventory. Missing booleans remain unknown.
    pairs = {}
    for record in capture['packages']:
        if record['package_state_kind'] != 'active_package_settings':
            continue
        for user in record['users']:
            pairs.setdefault((record['package'], user['user_id']), []).append(user['state'])
    users = {}
    for (package, user), states in pairs.items():
        counts = users.setdefault(user, {'user': user, 'records': 0, 'installed': 0, 'suspended': 0,
                                       'hidden': 0, 'unknown_install': 0, 'unknown_suspension': 0, 'unknown_hidden': 0})
        fields = ('installed', 'suspended', 'hidden')
        if len({tuple(s.get(f) for f in fields) for s in states}) != 1:
            result['app_conflicts'] += 1
            continue
        state = states[0]
        counts['records'] += 1
        if state.get('installed') == 'true':
            counts['installed'] += 1
            for field, unknown in [('suspended', 'unknown_suspension'), ('hidden', 'unknown_hidden')]:
                counts[field] += state.get(field) == 'true'
                counts[unknown] += state.get(field) not in ('true', 'false')
        elif state.get('installed') != 'false':
            counts['unknown_install'] += 1
    result['apps'] = sorted(users.values(), key=lambda u: u['user'])
    return result


def size(kilobytes):
    return f'{kilobytes / 1024 ** 2:.1f} GiB' if kilobytes >= 1024 ** 2 else f'{kilobytes / 1024:.0f} MiB'


def sources(rows):
    return '<details class="chart-source"><summary>Source values</summary><ul>' + ''.join(
        '<li>' + escape(f"{r['label']}: {r['value']} · {r['source']}:{r['line']}") + '</li>' for r in rows) + '</ul></details>'


def bar(percent, label, tone='teal'):
    # Only finite, validated numbers reach attributes. Labels remain text.
    return (f'<div class="meter {tone}" role="img" aria-label="{escape(label, quote=True)}">'
            f'<span style="width:{percent:.3f}%"></span></div>')


def chart_panel(title, content, note, category):
    return f'<section class="chart {category}"><h3>{title}</h3>{content}<p class="chart-note">{note}</p></section>'


def render_charts(capture, prefix):
    metrics = snapshot_metrics(capture)
    out = ['<div class="section-intro"><span class="eyebrow">At a glance</span><h2>Resource use</h2>'
           '<p>Values from this capture. Open the source values for the detail.</p></div><div class="charts">']
    battery = metrics['battery']
    if battery:
        percent = battery['percent']
        svg = (f'<svg class="charge-ring" viewBox="0 0 180 180" role="img" aria-label="Battery charge: {percent:g}%">'
               '<circle class="ring-track" cx="90" cy="90" r="72"/>'
               f'<circle class="ring-value" cx="90" cy="90" r="72" pathLength="100" stroke-dasharray="{percent:g} 100" transform="rotate(-90 90 90)"/>'
               f'<text x="90" y="91" class="ring-number">{percent:g}%</text><text x="90" y="115" class="ring-label">charge</text></svg>')
        details = []
        supporting_rows = []
        for key, label in [('temperature', 'Temperature'), ('voltage', 'Voltage'), ('cycle count', 'Cycles')]:
            row = unique(capture['health'], 'Battery · ' + key)
            if row:
                details.append('<div><span>' + label + '</span><strong>' + escape(row['value'].split(' (raw')[0]) + '</strong></div>')
                supporting_rows.append(row)
        body = '<div class="battery-layout">' + svg + '<div class="mini-stats">' + ''.join(details) + '</div></div>'
        if battery['frozen']:
            body += '<p class="alert">Battery updates are stopped. These values may be frozen or simulated.</p>'
        body += sources(battery['rows'] + supporting_rows)
    else:
        body = '<p class="chart-missing">Charge unavailable</p><p>Both a valid level and scale are needed.</p>'
    out.append(chart_panel('Battery', body, 'Charge tells us how full the battery is. It doesn’t tell us how much capacity it has lost.', 'battery-chart'))
    memory = metrics['memory']
    if memory:
        percent = 100 * memory['part'] / memory['total']
        body = '<div class="chart-number">' + size(memory['total']) + '</div><p class="chart-unit">Total RAM</p>'
        body += bar(percent, f"{memory['label']}: {percent:.1f}% of total RAM", 'violet')
        body += f'<div class="legend"><span><i class="violet-dot"></i>{escape(memory["label"])} <b>{size(memory["part"])}</b></span><span>Other RAM <b>{size(memory["total"] - memory["part"])}</b></span></div>'
        body += sources(memory['rows'])
        note = 'A single reading won’t show a memory leak. ' + ('Available RAM is an estimate of what apps can use.' if memory['label'] == 'Available' else 'The dump’s Free RAM figure includes cache; it isn’t MemAvailable.')
    else:
        body, note = '<p class="chart-missing">No comparable RAM figures</p>', 'The source needs a consistent total and free or available value before we can plot it.'
    out.append(chart_panel('Memory', body, note, 'memory-chart'))
    body = ''
    for storage in metrics['storage']:
        used = storage['total'] - storage['free']
        percent = 100 * used / storage['total']
        body += f'<div class="storage-heading"><span>{escape(storage["label"])}</span><strong>{percent:.1f}% used</strong></div>'
        body += bar(percent, f'{storage["label"]}: {percent:.1f}% used, {100 - percent:.1f}% free', 'amber')
        body += f'<div class="legend"><span><i class="used-dot"></i>Used <b>{size(used)}</b></span><span><i class="free-dot"></i>Free <b>{size(storage["free"])}</b></span></div>'
        body += f'<p class="small muted">{size(storage["total"])} total · {100 - percent:.1f}% free</p>'
        body += sources(storage['rows'])
    if not body:
        body = '<p class="chart-missing">No comparable storage figures</p>'
    out.append(chart_panel('Storage', body, 'Filled bars show used space; the pale remainder is free.', 'storage-chart'))
    body = ''
    for user in metrics['apps'][:12]:
        count, total = user['installed'], user['records']
        body += f'<div class="storage-heading"><span>User {user["user"]}</span><strong>{count} installed</strong></div>'
        body += bar(100 * count / total if total else 0, f'User {user["user"]}: {count} installed in {total} unambiguous package records')
        body += f'<p class="app-counts">{user["suspended"]} suspended · {user["hidden"]} hidden · {total} package records</p>'
        unknown = user['unknown_install'] + user['unknown_suspension'] + user['unknown_hidden']
        if unknown:
            body += f'<p class="small muted">Unknown fields: installed {user["unknown_install"]}, suspended {user["unknown_suspension"]}, hidden {user["unknown_hidden"]}.</p>'
    if not body:
        body = '<p class="chart-missing">No active app inventory</p>'
    if len(metrics['apps']) > 12:
        body += '<p>Showing the first 12 users. See the full app list below.</p>'
    if metrics['app_conflicts']:
        body += f'<p class="alert">{metrics["app_conflicts"]} conflicting package/user pairs left out of the counts.</p>'
    body += f'<a class="detail-link" href="#{prefix}-packages">See apps and source lines →</a>'
    out.append(chart_panel('Apps by user', body, 'Counts use the retained active package records. Suspended and hidden counts refer to installed apps; an app can be both. Factory copies are excluded.', 'apps-chart'))
    out.append('</div>')
    return ''.join(out)
