"""Self-contained HTML presentation; report strings never become executable content."""
from html import escape
import json

STYLE = '''
:root{color-scheme:light;--ink:#182b36;--muted:#526573;--line:#dbe3e7;--accent:#09675c;--paper:#f3f6f7}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,-apple-system,sans-serif}
a{color:var(--accent)}.wrap{max-width:1340px;margin:auto;padding:0 30px}header{background:#142d38;color:white;padding:42px 0 34px}
.eyebrow{text-transform:uppercase;letter-spacing:.16em;font-size:11px;font-weight:700;color:#a7dcd2}h1{font-size:36px;letter-spacing:-1px;margin:7px 0 8px}h2{font-size:24px;letter-spacing:-.5px;margin:0 0 10px}h3{font-size:18px;margin:0 0 12px}p{margin:8px 0 15px}.subtitle{color:#c3d4dc;max-width:820px}.badge{display:inline-block;padding:4px 10px;border-radius:30px;font-size:12px;background:#e8eff2;color:#354d5c}.beta{background:#3f4943;color:#ffe2a7;margin-left:8px}
nav{display:flex;gap:8px;flex-wrap:wrap;padding:18px 0}nav a{background:white;border:1px solid var(--line);padding:7px 13px;border-radius:8px;text-decoration:none;font-size:13px}
.notice{border-left:4px solid #cd9a3f;background:#fff8e9;padding:16px 20px;border-radius:4px;margin:18px 0;color:#5d4923}.muted{color:var(--muted)}.small{font-size:12px}.source{overflow-wrap:anywhere}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0}.card{padding:22px;background:white;border:1px solid var(--line);border-radius:12px}.card label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:8px}.card strong{font-size:20px;font-weight:650;overflow-wrap:anywhere}.card small{display:block;margin-top:7px;color:var(--muted)}.capture{margin:35px 0 60px}.panel{background:white;border:1px solid var(--line);border-radius:12px;padding:24px;margin:18px 0;scroll-margin-top:20px}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:11px 12px;background:#f5f8f9}td{padding:13px 12px;border-top:1px solid var(--line);vertical-align:top;max-width:390px;overflow-wrap:anywhere}td:first-child{font-weight:600}code,pre{font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f5f6;padding:12px;border-radius:6px;max-height:330px;overflow:auto}summary{cursor:pointer;color:var(--accent);font-size:12px}details[open]>summary{margin-bottom:10px}.empty{padding:18px;border:1px dashed #bacbd4;border-radius:7px;color:var(--muted)}.group{margin:18px 0}.footer{border-top:1px solid var(--line);padding:25px 0 45px;font-size:12px;color:var(--muted)}.scope{font-size:12px;color:var(--muted)}ul{padding-left:21px}.gap{color:#795614}.pill{display:inline-block;border-radius:4px;padding:2px 6px;background:#eaf3f0;color:#17574b;font-size:11px}.warn{background:#fff1d8;color:#795614}
@media(max-width:800px){.wrap{padding:0 16px}.cards{grid-template-columns:repeat(2,1fr)}h1{font-size:29px}.panel{padding:17px}td,th{padding:9px}.card{padding:16px}}
@media(max-width:450px){.cards{grid-template-columns:1fr}header{padding:26px 0}h2{font-size:21px}}
@media print{header{background:white;color:#182b36}.subtitle,.eyebrow{color:#526573}nav{display:none}.panel,.card{break-inside:avoid}body{background:white}.wrap{max-width:none;padding:0}details{display:block}.table-wrap{overflow:visible}}
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
        return '<div class="empty">Not shown in recognised fields. This does not establish absence or a healthy state.</div>'
    out = ['<div class="table-wrap"><table><thead><tr><th>Observation</th><th>Value</th><th>Scope &amp; meaning</th><th>Evidence</th></tr></thead><tbody>']
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
            note += ' · organization-owned: ' + row['organization_owned']
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
           '<header><div class="wrap"><div class="eyebrow">Android Enterprise · capture overview</div><h1>Your device, in context <span class="badge beta">Under testing</span></h1>',
           '<p class="subtitle">Management, profiles, policy and health observations in one place. Every finding stays attached to its source; unknowns stay visible.</p></div></header><main class="wrap">',
           '<div class="notice">' + e(report['notice']) + '</div>']
    scan = report['coverage']
    out.append('<p class="muted small">Text scan: <strong>' + ('completed within configured limits' if scan['complete'] else 'incomplete — inspect coverage') +
               '</strong>. Complete reading does not mean the capture contains every relevant event or policy.</p>')
    if not report['captures']:
        out.append('<section class="panel"><h2>No supported state observations</h2><p>This input cannot establish a management or health overview. Inspect its format and scan coverage.</p></section>')
    for index, capture in enumerate(report['captures'], 1):
        prefix = f'capture-{index}'
        out += [f'<article class="capture" id="{prefix}"><div class="eyebrow muted">Source {index} of {len(report["captures"])}</div>',
                '<h2 class="source">' + e(capture['source']) + '</h2>',
                '<p class="muted small">A separate source view. Repeated or conflicting observations are retained, not silently merged.</p>', '<div class="cards">']
        ownership, owner_note = owner_card(capture['ownership'])
        battery, battery_note = battery_card(capture['health'])
        cards = [('Model', single(capture['basics'], 'Model'), 'Observed device property'),
                 ('Android', single(capture['basics'], 'Android version'), 'Patch: ' + single(capture['basics'], 'Security patch')),
                 ('Management', ownership, owner_note), ('Battery charge', battery, battery_note)]
        for label, value, note in cards:
            out.append('<div class="card"><label>' + e(label) + '</label><strong>' + e(value) + '</strong><small>' + e(note) + '</small></div>')
        out.append('</div><nav aria-label="Overview sections">')
        for key, label in [('ownership', 'Management'), ('users', 'Users & profiles'), ('policies', 'Policy'), ('restrictions', 'Restrictions'), ('packages', 'Apps'), ('health', 'Health'), ('basics', 'Device basics')]:
            out.append(f'<a href="#{prefix}-{key}">{e(label)}</a>')
        out.append('</nav>')
        headings = [('ownership', 'Ownership & management', 'Ownership comes from explicit owner records. A company-owned work profile needs an organization-owned profile-owner flag; app presence alone cannot establish it.'),
                    ('users', 'Users & profiles', 'User IDs, named types and parent links are preserved. User 0 is not automatically a personal profile. Display names and serial numbers are omitted.'),
                    ('policies', 'Recorded policy & runtime flags', 'Camera, screen capture, password, lock-task and logging fields retain their admin/user/parent scope. Stored policy and enabled flags do not prove successful enforcement or log collection.'),
                    ('restrictions', 'User restrictions', 'Only rows explicitly labelled effective restriction cache represent that captured effective view. Base/admin restrictions stay separate. Missing rows do not mean false.'),
                    ('health', 'Health observations', report['health_note']),
                    ('basics', 'Device basics & security state', 'Properties are capture-time observations, not certification or a guarantee of security. Conflicts require source review.')]
        for key, title, note in headings:
            out.append(f'<section class="panel" id="{prefix}-{key}"><h3>{e(title)}</h3><p class="muted small">{e(note)}</p>')
            out.append(table(capture[key], ownership=key == 'ownership'))
            out.append('</section>')
        out.append(f'<section class="panel" id="{prefix}-packages"><h3>Apps by user</h3><p class="muted small">Package/version metadata is global to each block; state is per user. Factory copies never stand in for installed app state.</p>')
        for origin, label in [('active_package_settings', 'Active package settings'), ('unknown', 'Subsection not shown — current/factory status unknown'), ('factory_system_image_copy', 'Factory / system-image copies — not current installed state')]:
            records = [r for r in capture['packages'] if r['package_state_kind'] == origin]
            if records:
                out.append('<details class="group"' + (' open' if origin != 'factory_system_image_copy' else '') + '><summary>' + e(label) + '</summary>' + package_table(records) + '</details>')
        if not capture['packages']:
            out.append('<div class="empty">No supported package blocks found. This does not mean no apps are installed.</div>')
        out.append('</section><section class="panel"><h3>Gaps &amp; conflicting observations</h3>')
        gaps = capture['gaps'] + capture['conflicts']
        if capture['omitted_rows']:
            gaps.append('Overview row cap omitted observations: ' + json.dumps(capture['omitted_rows']))
        out.append('<ul>' + ''.join('<li>' + e(item) + '</li>' for item in gaps) + '</ul>' if gaps else '<p>No indexed conflicts or empty groups. This is not proof of complete evidence.</p>')
        out.append('</section></article>')
    out.append('<section class="panel"><h3>Reader coverage &amp; limits</h3><p class="muted">Review omitted, truncated and unclassified sources before making any negative claim.</p><details><summary>Show coverage details</summary><pre>' + e(json.dumps({'coverage': scan, 'omitted': report['omitted'], 'unclassified_sources': report['unclassified_sources']}, indent=2)) + '</pre></details></section>')
    out.append('<footer class="footer">Generated locally by Android Enterprise Bugreport. No external assets, scripts or network requests. Treat this report as sensitive; redaction is best-effort. Battery usage history is not battery wear analysis.</footer></main></body></html>')
    return ''.join(out)
