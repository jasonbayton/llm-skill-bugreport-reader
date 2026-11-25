"""Synthetic dumpstate-format and evaluator-isolation regressions."""
import json
from datetime import datetime
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from evidence_context import ContextTracker
from package_state import extract
from triage import analyse, as_markdown

PACKAGE_DUMP = '''DUMP OF SERVICE package:
Packages:
  Package [com.example.browser] (abc):
    versionCode=20 minSdk=23 targetSdk=35
    User 0: ceDataInode=123 installed=true hidden=false suspended=true stopped=false enabled=0
    User 10: installed=true hidden=false suspended=true enabled=0
Hidden system packages:
  Package [com.example.browser] (def):
    versionCode=10 minSdk=23 targetSdk=34
    User 0: installed=true hidden=false suspended=false stopped=false enabled=0
Queries:
  User 99: installed=false suspended=true
'''


class OutputRegressions(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def report(self, text):
        path = self.directory / 'bugreport.txt'
        path.write_text(text)
        return path

    def test_utc_markdown_keeps_applied_window_outside_device_profile(self):
        report = analyse(ROOT / 'evals/fixtures/browser.txt', 'auto', [],
                         datetime(2026, 2, 11, 12), 2, utc=True)
        rendered = as_markdown(report, 20)
        self.assertNotIn('Incident: not supplied', rendered)
        self.assertIn(report['incident_utc'], rendered.split('## Coverage')[0])
        timing = rendered.split('## Incident timing and chronology')[1].split('## Device profile')[0]
        self.assertIn(report['incident_utc'], timing)
        self.assertIn('±2 minutes', timing)
        self.assertIn('section/chronology boundaries', timing)
        profile = rendered.split('## Device profile')[1].split('## Structured')[0]
        self.assertNotIn('UTC alignment', profile)
        self.assertTrue(any(e['incident_window'] for f in report['findings'] for e in f['evidence']))

    def test_local_and_missing_incident_markdown(self):
        fixture = ROOT / 'evals/fixtures/browser.txt'
        local = as_markdown(analyse(fixture, 'auto', [], datetime(2026, 2, 11, 12), 2), 10)
        self.assertIn('2026-02-11T12:00:00', local.split('## Coverage')[0])
        self.assertIn('(device-local)', local.split('## Coverage')[0])
        missing = as_markdown(analyse(fixture, 'auto', [], None, 2), 10)
        self.assertIn('no incident window applied', missing)

    def test_state_mentions_preserve_package_identity_and_history(self):
        report = analyse(ROOT / 'evals/fixtures/browser.txt', 'auto', [], None, 15)
        rows = {row['line']: row for row in report['state_snapshots_or_mentions']['package_state']}
        self.assertEqual(rows[11]['package'], 'com.example.other')
        self.assertEqual(rows[15]['package'], 'com.example.browser')
        self.assertEqual(rows[16]['package'], 'com.example.browser')
        self.assertEqual(rows[4]['kind'], 'log')
        self.assertIsNone(rows[4]['package'])
        rendered = as_markdown(report, 20).split('## Relevant state snapshots / mentions')[1]
        other = next(line for line in rendered.splitlines() if 'browser.txt:11`' in line)
        browser = next(line for line in rendered.splitlines() if 'browser.txt:16`' in line)
        history = next(line for line in rendered.splitlines() if 'browser.txt:4`' in line)
        self.assertIn('package=com.example.other', other)
        self.assertIn('package=com.example.browser', browser)
        self.assertIn('kind=log', history)

    def test_factory_copy_cannot_masquerade_as_active_package_state(self):
        path = self.report(PACKAGE_DUMP)
        records = extract(path, 'com.example.browser')['records']
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]['package_subsection'], 'Packages')
        self.assertEqual(records[0]['package_state_kind'], 'active_package_settings')
        self.assertEqual(records[0]['metadata']['versionCode']['value'], '20')
        self.assertEqual(records[1]['package_subsection'], 'Hidden system packages')
        self.assertEqual(records[1]['package_state_kind'], 'factory_system_image_copy')
        self.assertIn('not_current_state', records[1]['basis'])
        self.assertEqual(records[1]['metadata']['versionCode']['value'], '10')
        self.assertEqual([u['user_id'] for u in records[1]['users']], [0])
        report = analyse(path, 'auto', [], None, 15)
        rows = {row['line']: row for row in report['state_snapshots_or_mentions']['package_state']}
        self.assertEqual(rows[10]['package_state_kind'], 'factory_system_image_copy')
        self.assertIsNone(rows[12]['package'])
        self.assertIsNone(rows[12]['package_subsection'])
        rendered = as_markdown(report, 10)
        self.assertIn('subsection=Hidden system packages / package_state=factory_system_image_copy', rendered)

    def test_subsection_does_not_leak_between_sources_or_services(self):
        archive = self.directory / 'reports.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr('a.txt', PACKAGE_DUMP)
            output.writestr('b.txt', '  Package [com.example.browser] (ghi):\n    User 0: installed=true\n')
        records = extract(archive, 'com.example.browser')['records']
        self.assertIsNone(records[-1]['package_subsection'])
        self.assertEqual(records[-1]['package_state_kind'], 'unknown')
        tracker = ContextTracker()
        tracker.feed('a', 1, 'Hidden system packages:')
        tracker.feed('a', 2, 'DUMP OF SERVICE device_policy:')
        self.assertIsNone(tracker.feed('a', 3, '  User 10: installed=true')['package_subsection'])

    def test_duration_footer_preserves_section_and_buffer_without_new_segment(self):
        tracker = ContextTracker()
        tracker.feed('report', 1, '------ SYSTEM LOG ------')
        before = tracker.feed('report', 2, '--------- beginning of system')
        footer = tracker.feed('report', 3, "------ 0.123s was the duration of 'SYSTEM LOG' ------")
        self.assertEqual(footer['section'], 'SYSTEM LOG')
        self.assertEqual(footer['buffer'], 'system')
        self.assertEqual(footer['timeline_segment'], before['timeline_segment'])
        self.assertIsNone(footer['boundary'])
        self.assertEqual(footer['kind'], 'collector')

    def test_context_cli_displays_buffer_on_hits_and_context(self):
        path = self.report('------ SYSTEM LOG ------\n--------- beginning of main\n'
                           '01-01 12:00:00.000 1 2 I Tag: hit\n'
                           '--------- beginning of events\n01-01 12:00:01.000 1 2 I Tag: hit\n')
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/context.py'), str(path),
                                 '--pattern', 'hit', '--context', '1'], capture_output=True, text=True, check=True)
        hits = [line for line in result.stdout.splitlines() if line.startswith('>')]
        self.assertIn('buffer=main', hits[0])
        self.assertIn('buffer=events', hits[1])
        self.assertIn('buffer=main', next(line for line in result.stdout.splitlines() if 'beginning of main' in line))

    def test_prepared_run_has_executable_skill_but_no_tests_or_rubric(self):
        run = self.directory / 'run'
        subprocess.run([sys.executable, str(ROOT / 'evals/prepare.py'), '--skill', str(ROOT),
                        '--out', str(run)], capture_output=True, text=True, check=True)
        copied = run / 'skill'
        self.assertTrue((copied / 'SKILL.md').is_file())
        self.assertFalse((copied / 'evals').exists())
        self.assertFalse((copied / 'tests').exists())
        self.assertFalse((copied / '.git').exists())
        self.assertFalse(list(run.rglob('rubric.json')))
        self.assertFalse(any(path.is_symlink() for path in run.rglob('*')))
        requests = json.loads((run / 'requests.json').read_text())
        self.assertEqual(len(requests), 4)
        for request in requests:
            self.assertIn(str(copied / 'SKILL.md'), request['prompt'])
            self.assertNotIn(str(ROOT), request['prompt'])
        result = subprocess.run([sys.executable, str(copied / 'scripts/package_state.py'),
                                 str(run / 'pending-install/report.txt'), 'com.example.inventory'],
                                cwd=run, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['records'][0]['metadata']['versionCode']['value'], '6')

    def test_preparer_rejects_existing_output_and_output_inside_skill(self):
        for destination in [self.directory, ROOT / 'must-not-create-eval-run']:
            result = subprocess.run([sys.executable, str(ROOT / 'evals/prepare.py'), '--skill', str(ROOT),
                                     '--out', str(destination)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
        self.assertFalse((ROOT / 'must-not-create-eval-run').exists())


if __name__ == '__main__':
    unittest.main()
