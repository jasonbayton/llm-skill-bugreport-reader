"""Overview tests cover scope, unknowns, independent captures and inert HTML."""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from overview import analyse_overview
from overview_html import render, battery_card
from report_io import ScanLimits


class HTMLAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attributes = []
    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)


class OverviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
    def file(self, text):
        path = self.directory / 'report.txt'
        path.write_text(text)
        return path
    def demo(self):
        return analyse_overview(ROOT / 'tests/fixtures/overview.txt')

    def test_dumpstate_completion_footer_is_not_a_capture_time(self):
        report = analyse_overview(self.file('== dumpstate: 2026-02-11 12:10:00+0000\n'
                                           '== dumpstate: done (id 5)\n'))
        rows = report['captures'][0]['basics']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['value'], '2026-02-11 12:10:00+0000')
        self.assertEqual(report['captures'][0]['conflicts'], [])

    def test_owners_and_organization_owned_work_profile(self):
        capture = self.demo()['captures'][0]
        do, po = capture['ownership']
        self.assertEqual(do['value'], 'Explicitly none')
        self.assertIsNone(do['component'])
        self.assertEqual(po['user_id'], 10)
        self.assertEqual(po['organization_owned'], 'true')
        self.assertTrue(po['component'].startswith('com.google.android.apps.work.clouddpc/'))
        self.assertGreater(po['component_line'], po['line'])
        self.assertIn('Android Device Policy', render(self.demo()))

    def test_device_owner_indented_user_id_and_missing_owner_not_unmanaged(self):
        text = ('DUMP OF SERVICE device_policy:\n  Device Owner:\n'
                '    admin=ComponentInfo{com.example.admin/.Admin}\n    User ID: 0\n')
        owner = analyse_overview(self.file(text))['captures'][0]['ownership'][0]
        self.assertEqual(owner['component'], 'com.example.admin/.Admin')
        self.assertEqual(owner['user_id'], 0)
        report = analyse_overview(self.file('[ro.product.model]: [Example]\n'))
        self.assertEqual(report['captures'][0]['ownership'], [])
        self.assertIn('ownership: no supported observations', '\n'.join(report['captures'][0]['gaps']))

    def test_user_names_and_device_serial_are_not_exposed(self):
        text = json.dumps(self.demo())
        self.assertNotIn('Personal Example', text)
        self.assertNotIn('Work Example', text)
        self.assertNotIn('synthetic-private-serial', text)
        rows = self.demo()['captures'][0]['users']
        self.assertTrue(any('parentId=0' in row['value'] and row['scope'] == 'User 10' for row in rows))
        self.assertTrue(any(row['value'] == 'android.os.usertype.profile.MANAGED' for row in rows))

    def test_admin_and_parent_policy_are_not_effective_cache(self):
        capture = self.demo()['captures'][0]
        camera = [row for row in capture['policies'] if row['label'] == 'disableCamera']
        self.assertEqual([r['value'] for r in camera], ['false', 'true'])
        self.assertNotIn('parentAdmin', camera[0]['scope'])
        self.assertIn('parentAdmin', camera[1]['scope'])
        self.assertIn('parent-profile target not resolved', camera[1]['scope'])
        self.assertTrue(all('enforcement not inferred' in r['basis'] for r in camera))
        # Timestamped camera=true log at the end is not a third snapshot.
        self.assertEqual(len(camera), 2)

    def test_effective_restrictions_keep_user_and_base_sources_separate(self):
        rows = self.demo()['captures'][0]['restrictions']
        effective = [r for r in rows if r['basis'] == 'effective restriction cache at capture']
        self.assertEqual(len(effective), 3)
        self.assertTrue(any(r['label'] == 'no_camera' and r['value'] == 'false' and 'User 10' in r['scope'] for r in effective))
        global_row = next(r for r in rows if r['label'] == 'no_factory_reset')
        self.assertNotIn('User 10', global_row['scope'])
        self.assertNotIn('effective restriction cache', global_row['basis'])

    def test_package_inventory_uses_shared_scope_and_preserves_factory_copy(self):
        records = self.demo()['captures'][0]['packages']
        self.assertEqual(len(records), 3)
        active = next(r for r in records if r['package'] == 'com.example.browser' and r['package_state_kind'] == 'active_package_settings')
        factory = records[-1]
        self.assertEqual(active['users'][1]['user_id'], 10)
        self.assertEqual(active['users'][1]['state']['suspended'], 'true')
        self.assertEqual(factory['package_state_kind'], 'factory_system_image_copy')
        self.assertEqual(factory['metadata']['versionCode']['value'], '100')
        self.assertEqual(len(factory['users']), 1)

    def test_health_has_units_and_no_battery_wear_inference(self):
        report = self.demo()
        rows = {row['label']: row for row in report['captures'][0]['health']}
        self.assertEqual(rows['Battery · temperature']['value'], '29.5 °C (raw tenths °C: 295)')
        self.assertIn('not battery wear', rows['Battery · health']['value'])
        self.assertIn('retained aggregate', rows['Battery history · Time on battery']['basis'])
        self.assertEqual(rows['Uptime']['value'], '123456.78 seconds')
        self.assertIn('Memory · Free RAM', rows)
        self.assertIn('Storage · Data-Free', rows)
        self.assertNotIn('97%', json.dumps(report))
        self.assertEqual(battery_card(report['captures'][0]['health'])[0], '78%')
        self.assertEqual(battery_card([{'label': 'Battery · level', 'value': '78'}])[0], '78')
        self.assertEqual(battery_card([{'label': 'Battery · level', 'value': '78'},
                                       {'label': 'Battery · scale', 'value': '200'}])[0], '39%')

    def test_memory_proc_fields_and_frozen_battery_are_disclosed(self):
        report = analyse_overview(self.file('------ MEMORY INFO (/proc/meminfo) ------\n'
                                           'MemTotal: 8000000 kB\nMemAvailable: 2500000 kB\n'
                                           'DUMP OF SERVICE battery:\nUPDATES STOPPED -- use reset to restart\n'))
        rows = report['captures'][0]['health']
        self.assertEqual(rows[1]['value'], '2500000 kB')
        self.assertIn('frozen or simulated', rows[2]['basis'])

    def test_captures_and_conflicting_properties_never_silently_merge(self):
        path = self.directory / 'capture.zip'
        with zipfile.ZipFile(path, 'w') as output:
            output.writestr('a.txt', '[ro.product.model]: [First]\n[ro.product.model]: [Second]\n')
            output.writestr('b.txt', '[ro.product.model]: [Third]\n')
        captures = analyse_overview(path)['captures']
        self.assertEqual(len(captures), 2)
        self.assertTrue(captures[0]['conflicts'])
        self.assertFalse(captures[1]['conflicts'])
        self.assertEqual(captures[1]['basics'][0]['value'], 'Third')

    def test_unknown_input_stays_unknown_and_history_is_not_a_snapshot(self):
        report = analyse_overview(self.file('------ SYSTEM LOG ------\n'
                                           '01-01 12:00:00.000 1 2 I DPM: Device Owner: example/.Admin\n'))
        self.assertEqual(report['captures'], [])
        self.assertEqual(report['unclassified_sources'], ['report.txt'])
        self.assertIn('No supported state observations', render(report))

    def test_output_caps_and_source_truncation_are_visible(self):
        report = analyse_overview(ROOT / 'tests/fixtures/overview.txt', max_rows=1, max_packages=1)
        self.assertTrue(report['captures'][0]['omitted_rows'])
        self.assertEqual(report['omitted']['package_records'], 2)
        text = 'DUMP OF SERVICE device_policy:\n  mLockTaskPackages=' + 'x' * 1000 + '\n'
        clipped = analyse_overview(self.file(text))
        self.assertTrue(clipped['captures'][0]['policies'][0]['value_truncated'])
        self.assertIn('Value clipped', render(clipped))
        limited = analyse_overview(self.file('[ro.product.model]: [' + 'a' * 100 + ']\n'), limits=ScanLimits(line_bytes=30))
        self.assertFalse(limited['coverage']['complete'])

    def test_html_escapes_all_report_content_and_has_no_active_resources(self):
        payload = '</style><script>alert(1)</script><img src=x onerror=alert(2)>'
        report = analyse_overview(self.file('[ro.product.model]: [' + payload + ']\n'))
        html = render(report)
        audit = HTMLAudit(); audit.feed(html)
        self.assertNotIn('script', audit.tags)
        self.assertNotIn('img', audit.tags)
        self.assertFalse(any(name.lower().startswith('on') for name, value in audit.attributes))
        self.assertIn('&lt;script&gt;', html)
        self.assertIn("default-src 'none'", html)
        self.assertFalse(any(name in ('src', 'href') and value.startswith(('http:', 'https:', '//')) for name, value in audit.attributes))

    def test_cli_under_isolated_python_preserves_inputs_and_prevents_overwrite(self):
        source = self.file((ROOT / 'tests/fixtures/overview.txt').read_text())
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        html, data = self.directory / 'device.html', self.directory / 'device.json'
        command = [sys.executable, '-I', str(ROOT / 'scripts/overview.py'), str(source), '--html', str(html), '--json', str(data)]
        result = subprocess.run(command, cwd=self.directory, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(data.read_text())['mode'], 'device_overview')
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        existing = html.read_bytes()
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        self.assertEqual(html.read_bytes(), existing)
        self.assertNotEqual(subprocess.run(command[:4] + ['--html', str(source)], capture_output=True).returncode, 0)

    def test_html_keeps_metadata_when_package_user_rows_are_missing(self):
        report = analyse_overview(self.file('DUMP OF SERVICE package:\nPackages:\n'
                                           '  Package [com.example.app] (a):\n    versionCode=7\n'))
        html = render(report)
        self.assertIn('com.example.app', html)
        self.assertIn('User not shown', html)
        self.assertIn('versionCode: 7', html)


if __name__ == '__main__':
    unittest.main()
