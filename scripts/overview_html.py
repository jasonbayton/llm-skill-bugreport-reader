"""Self-contained HTML presentation; report strings never become executable content."""
from html import escape
import json
from overview_charts import render_charts

STYLE = '''
:root{color-scheme:light;--ink:#142734;--muted:#526572;--line:#dce5e9;--accent:#087567;--paper:#f4f6f8;--teal:#099b86;--violet:#7560cf;--amber:#d99023}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 system-ui,-apple-system,sans-serif}a{color:var(--accent)}.wrap{max-width:1320px;margin:auto;padding:0 36px}
header{background:radial-gradient(ellipse at 90% 10%,#235b62 0,transparent 55%),#142c38;color:white;padding:54px 0 48px;border-bottom:5px solid #42c9ad}.hero{display:flex;justify-content:space-between;align-items:center;gap:40px}.hero-copy{max-width:780px}.hero-mark{width:104px;height:150px;border:2px solid #66b9b3;border-radius:24px;transform:rotate(9deg);display:flex;flex-direction:column;justify-content:center;gap:9px;padding:18px;flex-shrink:0}.hero-mark span{height:9px;border-radius:9px;background:#63c9b3}.hero-mark span:nth-child(2){width:70%;background:#a99de9}.hero-mark span:nth-child(3){width:40%;background:#f0bd69}
.eyebrow{text-transform:uppercase;letter-spacing:.16em;font-size:11px;font-weight:750;color:var(--accent)}header .eyebrow{color:#9ce7d7}h1{font-size:clamp(32px,4vw,52px);letter-spacing:-1.8px;line-height:1.13;margin:14px 0 18px}h2{font-size:27px;letter-spacing:-.7px;line-height:1.25;margin:0 0 12px}h3{font-size:19px;letter-spacing:-.3px;margin:0 0 12px}p{margin:8px 0 15px}.subtitle{color:#d2e3e8;font-size:17px;max-width:670px}.badge{display:inline-block;padding:4px 10px;border-radius:30px;font-size:12px;background:#e8eff2;color:#354d5c}
nav{display:flex;gap:8px;flex-wrap:wrap;padding:6px 0 22px}nav a{background:white;border:1px solid var(--line);padding:8px 14px;border-radius:25px;text-decoration:none;font-size:13px}nav a:hover{background:#e6f3f0}a:focus-visible,summary:focus-visible{outline:3px solid #7560cf;outline-offset:3px}
.notice,.alert{border-left:3px solid var(--amber);background:#fff6e6;padding:12px 16px;border-radius:3px;color:#75501a}.muted{color:var(--muted)}.small{font-size:12px}.source{overflow-wrap:anywhere}.capture{margin:32px 0 60px}.source-heading{display:flex;justify-content:space-between;gap:24px;align-items:baseline}.source-heading h2{font-size:17px;font-weight:550}.source-heading .eyebrow{white-space:nowrap}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:18px;margin:22px 0}.card{padding:22px;background:white;border:1px solid var(--line);border-radius:12px;min-width:0}.card label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:9px}.card strong{font-size:22px;letter-spacing:-.6px;font-weight:650;overflow-wrap:anywhere}.card small{display:block;margin-top:7px;color:var(--muted)}
.section-intro{margin:22px 0}.section-intro h2{margin:7px 0}.section-intro p{color:var(--muted)}.charts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px;margin:0 0 34px}.chart{padding:26px 28px;background:white;border:1px solid var(--line);border-top:3px solid var(--teal);border-radius:14px;min-width:0;box-shadow:0 6px 18px #1b354405}.chart h3{font-size:20px}.memory-chart{border-top-color:var(--violet)}.storage-chart{border-top-color:var(--amber)}.chart-number{font-size:46px;font-weight:680;letter-spacing:-1.5px;line-height:1.2;margin:20px 0 0}.chart-unit{margin:3px 0 26px;color:var(--muted);font-size:13px}.chart-note{font-size:12px;color:var(--muted);margin:20px 0 0;max-width:550px}.chart-missing{font-size:22px;line-height:1.3;color:var(--muted);margin:30px 0}.chart-source{margin-top:12px}.chart-source ul{font-size:12px;overflow-wrap:anywhere;color:var(--muted)}.battery-layout{display:flex;align-items:center;gap:28px}.charge-ring{width:180px;max-width:50%;flex-shrink:0}.ring-track,.ring-value{fill:none;stroke-width:13}.ring-track{stroke:#e8efef}.ring-value{stroke:var(--teal);stroke-linecap:butt}.ring-number{font:650 35px system-ui;fill:var(--ink);text-anchor:middle;letter-spacing:-1px}.ring-label{font:13px system-ui;fill:var(--muted);text-anchor:middle}.mini-stats{display:grid;gap:15px}.mini-stats span{font-size:11px;color:var(--muted);display:block}.mini-stats strong{font-size:18px;font-weight:620;overflow-wrap:anywhere}.meter{height:18px;background:#e9edf2;border-radius:6px;overflow:hidden;margin:12px 0}.meter span{display:block;height:100%;background:var(--teal)}.meter.violet span{background:var(--violet)}.meter.amber span{background:var(--amber)}.legend{display:flex;justify-content:space-between;gap:16px;font-size:12px;color:var(--muted)}.legend b{display:block;color:var(--ink);font-size:16px;font-weight:600}.legend span:last-child{text-align:right}.legend i{display:inline-block;width:8px;height:8px;background:var(--violet);border-radius:50%;margin-right:6px}.storage-heading{display:flex;justify-content:space-between;gap:12px;align-items:baseline;margin-top:20px;font-size:13px}.storage-heading strong{font-size:21px;letter-spacing:-.4px}.app-counts{font-size:12px;color:var(--muted)}.detail-link{font-size:12px;text-decoration:none}.detail-link:hover{text-decoration:underline}
.panel{background:white;border:1px solid var(--line);border-radius:12px;padding:25px 28px;margin:18px 0;scroll-margin-top:20px}.panel>p{max-width:920px}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:11px 12px;background:#f5f8f9}td{padding:13px 12px;border-top:1px solid var(--line);vertical-align:top;max-width:390px;overflow-wrap:anywhere}td:first-child{font-weight:600}code,pre{font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f5f6;padding:12px;border-radius:6px;max-height:330px;overflow:auto}summary{cursor:pointer;color:var(--accent);font-size:13px}details[open]>summary{margin-bottom:10px}.empty{padding:18px;border:1px dashed #bacbd4;border-radius:7px;color:var(--muted)}.group{margin:18px 0}.footer{border-top:1px solid var(--line);padding:25px 0 45px;font-size:12px;color:var(--muted)}.scope{font-size:12px;color:var(--muted)}ul{padding-left:21px}.gap{color:#795614}.pill{display:inline-block;border-radius:4px;padding:2px 6px;background:#eaf3f0;color:#17574b;font-size:11px}.warn{background:#fff1d8;color:#795614}.reading-note{color:var(--muted);font-size:12px;padding:16px 0 0}
.storage-chart .used-dot{background:var(--amber)}.storage-chart .free-dot{background:#e9edf2;border:1px solid #b8c4cf}
@media(max-width:800px){.wrap{padding:0 20px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.charts{grid-template-columns:1fr}.hero-mark{display:none}.panel,.chart{padding:20px}td,th{padding:9px}.card{padding:16px}.source-heading{display:block}.hero{gap:0}}
@media(max-width:450px){.wrap{padding:0 16px}header{padding:32px 0}h2{font-size:23px}.cards{gap:10px}.card strong{font-size:18px}.card small{font-size:11px}.battery-layout{gap:18px}.mini-stats strong{font-size:16px}.legend{gap:8px}.chart-number{font-size:40px}}
@media print{header{background:white;color:#182b36;padding:20px 0}.subtitle,header .eyebrow{color:#526573}.hero-mark,nav{display:none}.panel,.card,.chart{break-inside:avoid}body{background:white}.wrap{max-width:none;padding:0}.table-wrap{overflow:visible}*{print-color-adjust:exact;-webkit-print-color-adjust:exact}}
'''


def e(value):
    return escape(str(value), quote=True)


def evidence(row):
    points = [f"{row['source']}:{row['line']} · {row.get('section', 'package dump')}", row.get('excerpt', '')]
    for field, label in [('component_line', 'component'), ('user_line', 'user ID'), ('organization_owned_line', 'organization-owned flag')]:
        if row.get(field):
            points.append(f"{label}: source line {row[field]}")
    return '<details><summary>' + e(f"{row['source']}:{row['line']}") + '</summary><pre>' + e('\n'.join(points)) + '</pre></details>'


def table(rows, ownership=False):
    if not rows:
        return '<div class="empty">Not found in the fields this reader supports. Check the source if you need to confirm it.</div>'
    out = ['<div class="table-wrap"><table><thead><tr><th>Setting</th><th>Value</th><th>Applies to</th><th>Source</th></tr></thead><tbody>']
    for row in rows:
        value = e(row['value'])
        if row.get('value_truncated'):
            value += '<br><span class="pill warn">Value clipped — inspect source</span>'
        if ownership:
            if (row.get('component') or '').startswith('com.google.android.apps.work.clouddpc/'):
                value += '<br><span class="pill">Android Device Policy</span>'
            if row.get('organization_owned') is not None:
                value += '<br><span class="scope">Organization-owned device flag: ' + e(row['organization_owned']) + '</span>'
        out.append('<tr><td>' + e(row['label']) + '</td><td>' + value + '</td><td>' +
                   e(row['scope']) + '<br><span class="scope">' + e(row['basis']) + '</span></td><td>' + evidence(row) + '</td></tr>')
    return ''.join(out) + '</tbody></table></div>'


def package_table(records):
    # Bound HTML size independently of the JSON inventory; always disclose the display limit.
    entries = [(record, user) for record in records for user in
               (record['users'] or [{'user_id': 'not shown', 'line': record['line'], 'state': {}}])]
    no_users = sum(not record['users'] for record in records)
    out = [f'<p class="muted small">{len(records)} package blocks · {len(entries)} display rows. '
           f'{no_users} blocks have no recognised User row. Enabled values are raw; 0 means default, not disabled.</p>']
    if not entries:
        return ''.join(out) + '<div class="empty">No per-user package state shown.</div>'
    out.append('<div class="table-wrap"><table><thead><tr><th>Package / user</th><th>Version / installer</th><th>Installed</th><th>Enabled (raw)</th><th>Hidden</th><th>Suspended</th><th>Stopped</th><th>Evidence</th></tr></thead><tbody>')
    for record, user in entries[:1000]:
        meta = record['metadata']
        version = meta.get('versionName', meta.get('versionCode', {})).get('value', 'not shown')
        installer = meta.get('installerPackageName', {}).get('value', 'not shown')
        state = user['state']
        out.append('<tr><td>' + e(record['package']) + '<br><span class="scope">User ' + e(user['user_id']) +
                   '</span></td><td>' + e(version) + '<br><span class="scope">' + e(installer) + '</span></td>')
        for field in ('installed', 'enabled', 'hidden', 'suspended', 'stopped'):
            out.append('<td>' + e(state.get(field, 'not shown')) + '</td>')
        pointers = [f"{record['source']}:{user['line']}", f"Package block: line {record['line']}; {record['package_subsection'] or 'subsection unknown'}"]
        pointers += [f'{key}: {item["value"]} (line {item["line"]})' for key, item in meta.items()]
        out.append('<td><details><summary>' + e(f"line {user['line']}") + '</summary><pre>' + e('\n'.join(pointers)) + '</pre></details></td></tr>')
    out.append('</tbody></table></div>')
    if len(entries) > 1000:
        out.append(f'<p class="gap">Showing the first 1,000 of {len(entries)} retained package/user rows. Use the JSON inventory or package_state.py for the remainder.</p>')
    return ''.join(out)


def single(rows, label):
    values = {row['value'] for row in rows if row['label'] == label}
    return next(iter(values)) if len(values) == 1 else ('Conflicting values' if values else 'Not shown')


def owner_card(rows):
    identified = [row for row in rows if row.get('component')]
    if len(identified) == 1:
        row = identified[0]
        note = row['scope']
        if row.get('organization_owned') is not None:
            note += ' · company-owned device' if row['organization_owned'] == 'true' else ' · company-owned flag is false'
        return row['label'], note
    if identified:
        return f'{len(identified)} owner records', 'Review roles and source scope below'
    return 'Not established', 'No owner component shown; see explicit absence records below'


def battery_card(rows):
    level, scale = single(rows, 'Battery · level'), single(rows, 'Battery · scale')
    try:
        amount, maximum = float(level), float(scale)
        if maximum > 0 and 0 <= amount <= maximum:
            return f'{100 * amount / maximum:g}%', 'Reported charge · not battery wear'
    except ValueError:
        pass
    return level, 'Raw level · scale: ' + scale


def render(report):
    out = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
           '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
           '<title>Android device overview</title><style>', STYLE, '</style></head><body>',
           '<header><div class="wrap hero"><div class="hero-copy"><div class="eyebrow">Android Enterprise / Device report</div><h1>Device overview.</h1>',
           '<p class="subtitle">Management, apps and resource use, from this capture.</p></div><div class="hero-mark" aria-hidden="true"><span></span><span></span><span></span></div></div></header><main class="wrap">']
    scan = report['coverage']
    if not scan['complete']:
        out.append('<p class="notice">Some source text wasn’t read. Check the reading limits below before relying on the totals.</p>')
    if not report['captures']:
        out.append('<section class="panel"><h2>No supported state observations</h2><p>This input cannot establish a management or health overview. Inspect its format and scan coverage.</p></section>')
    for index, capture in enumerate(report['captures'], 1):
        prefix = f'capture-{index}'
        out += [f'<article class="capture" id="{prefix}"><div class="eyebrow muted">Source {index} of {len(report["captures"])}</div>',
                '<h2 class="source">' + e(capture['source']) + '</h2>', '<div class="cards">']
        ownership, owner_note = owner_card(capture['ownership'])
        cards = [('Model', single(capture['basics'], 'Model'), single(capture['basics'], 'Manufacturer')),
                 ('Android', single(capture['basics'], 'Android version'), 'Patch: ' + single(capture['basics'], 'Security patch')),
                 ('Management', ownership, owner_note), ('Captured', single(capture['basics'], 'Capture time'), 'Device clock')]
        for label, value, note in cards:
            out.append('<div class="card"><label>' + e(label) + '</label><strong>' + e(value) + '</strong><small>' + e(note) + '</small></div>')
        out.append('</div><nav aria-label="Overview sections">')
        for key, label in [('ownership', 'Management'), ('users', 'Users & profiles'), ('policies', 'Policy'), ('restrictions', 'Restrictions'), ('packages', 'Apps'), ('health', 'Health'), ('basics', 'Device basics')]:
            out.append(f'<a href="#{prefix}-{key}">{e(label)}</a>')
        out.append('</nav>')
        if any(count for key, count in capture['omitted_rows'].items() if key != 'long_values_clipped') or any(report['omitted'].values()):
            out.append('<p class="notice">Some rows were left out at the reader’s limits. Charts show only the retained values; see reading limits below.</p>')
        elif capture['omitted_rows'].get('long_values_clipped'):
            out.append('<p class="reading-note">' + str(capture['omitted_rows']['long_values_clipped']) + ' long values are shortened in the detail tables. The source has the full text; no rows were dropped.</p>')
        out.append(render_charts(capture, prefix))
        headings = [('ownership', 'Who manages this device?', 'Owner records identify the admin app and its user. An installed management app alone doesn’t establish ownership.'),
                    ('users', 'Users & profiles', 'User IDs and profile types come from the dump. Names and serial numbers are left out.'),
                    ('policies', 'Policy settings', 'These settings belong to the admin, user or parent profile shown. A recorded setting doesn’t, by itself, prove Android enforced it.'),
                    ('restrictions', 'User restrictions', 'Effective restrictions are Android’s cached state at capture. Base and admin restrictions are listed separately.'),
                    ('health', 'Battery, memory & storage detail', report['health_note']),
                    ('basics', 'Build & security', 'The device properties reported at capture.')]
        for key, title, note in headings:
            out.append(f'<section class="panel" id="{prefix}-{key}"><h3>{e(title)}</h3><p class="muted small">{e(note)}</p>')
            folded = key in ('policies', 'restrictions', 'health', 'basics')
            if folded:
                out.append('<details><summary>Show ' + str(len(capture[key])) + ' readings and source lines</summary>')
            out.append(table(capture[key], ownership=key == 'ownership'))
            if folded:
                out.append('</details>')
            out.append('</section>')
        out.append(f'<section class="panel" id="{prefix}-packages"><h3>Apps by user</h3><p class="muted small">App state can differ between users. Factory copies are listed separately from active package settings.</p>')
        for origin, label in [('active_package_settings', 'Active package settings'), ('unknown', 'Subsection not shown — current/factory status unknown'), ('factory_system_image_copy', 'Factory / system-image copies — not current installed state')]:
            records = [r for r in capture['packages'] if r['package_state_kind'] == origin]
            if records:
                out.append('<details class="group"><summary>' + e(label) + '</summary>' + package_table(records) + '</details>')
        if not capture['packages']:
            out.append('<div class="empty">No supported package blocks found. This does not mean no apps are installed.</div>')
        out.append('</section><section class="panel"><h3>What needs a closer look</h3>')
        gaps = capture['gaps'] + capture['conflicts']
        if capture['omitted_rows']:
            gaps.append('Overview row cap omitted observations: ' + json.dumps(capture['omitted_rows']))
        out.append('<ul>' + ''.join('<li>' + e(item) + '</li>' for item in gaps) + '</ul>' if gaps else '<p>No conflicting values or empty sections were found in the supported fields.</p>')
        out.append('</section></article>')
    out.append('<section class="panel"><h3>About this reading</h3><p class="muted">Each source is kept separate. The reader may skip unsupported fields or stop at size limits; the details below show what was read.</p><details><summary>Show files read and limits reached</summary><pre>' + e(json.dumps({'coverage': scan, 'omitted': report['omitted'], 'unclassified_sources': report['unclassified_sources']}, indent=2)) + '</pre></details></section>')
    out.append('<footer class="footer">Generated locally · Works offline · No external requests<br>Review before sharing: filenames, app names and policy details may still be sensitive.</footer></main></body></html>')
    return ''.join(out)
