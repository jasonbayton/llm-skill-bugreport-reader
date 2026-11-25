"""Run trusted helpers with -I from a report folder containing shadow modules."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class IsolatedPython(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.case = Path(temporary.name)
        self.report = self.case / 'report.txt'
        self.report.write_bytes((ROOT / 'evals/fixtures/browser.txt').read_bytes())
        self.before = hashlib.sha256(self.report.read_bytes()).hexdigest()
        # Neither the case directory nor PYTHONPATH may supply executable modules.
        for module in ['report_io', 'evidence_context', 'incident_time', 'triage', 'json', 'pathlib']:
            (self.case / (module + '.py')).write_text("raise RuntimeError('UNTRUSTED_MODULE_EXECUTED')\n")
        self.environment = dict(os.environ, PYTHONPATH=str(self.case))

    def run_python(self, *args):
        result = subprocess.run([sys.executable, '-I', *map(str, args)], cwd=self.case,
                                env=self.environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('UNTRUSTED_MODULE_EXECUTED', result.stdout + result.stderr)
        self.assertEqual(hashlib.sha256(self.report.read_bytes()).hexdigest(), self.before)
        return result.stdout

    def test_triage_isolated_reads_report_and_aligns_utc(self):
        output = self.case / 'triage.json'
        markdown = self.case / 'triage.md'
        self.run_python(ROOT / 'scripts/triage.py', self.report,
                        '--package', 'com.example.browser', '--utc',
                        '--incident', '2026-02-11T12:00:00Z', '--json', output, '--markdown', markdown)
        report = json.loads(output.read_text())
        self.assertEqual(report['incident_utc'], '2026-02-11T12:00:00+00:00')
        self.assertIn('(UTC)', markdown.read_text())
        self.assertTrue(any(e['incident_window'] for f in report['findings'] for e in f['evidence']))

    def test_context_isolated_returns_exact_package_row(self):
        rendered = self.run_python(ROOT / 'scripts/context.py', self.report, '--line', '16', '--context', '0')
        self.assertIn('package=com.example.browser', rendered)
        self.assertIn('User 10:', rendered)

    def test_package_state_isolated_keeps_user_identity(self):
        report = json.loads(self.run_python(ROOT / 'scripts/package_state.py', self.report, 'com.example.browser'))
        self.assertEqual([u['user_id'] for u in report['records'][0]['users']], [0, 10])
        self.assertEqual(report['records'][0]['metadata']['versionCode']['value'], '14')

    def test_compare_isolated_preserves_snapshot_comparison(self):
        rendered = self.run_python(ROOT / 'scripts/compare.py', self.report, self.report)
        self.assertIn('No differences in indexed signature counts', rendered)

    def test_incident_time_isolated_load_and_clock_inventory(self):
        self.run_python(ROOT / 'scripts/incident_time.py')
        code = ('import runpy,json,sys; from pathlib import Path; '
                'module=runpy.run_path(sys.argv[1]); '
                'print(json.dumps(module["clock_inventory"](Path(sys.argv[2]))))')
        inventory = json.loads(self.run_python('-c', code, ROOT / 'scripts/incident_time.py', self.report))
        self.assertEqual(inventory['members']['report.txt']['zone'], 'UTC')

    def test_other_modules_and_eval_copy_work_under_isolation(self):
        for script in ['report_io.py', 'evidence_context.py']:
            with self.subTest(script=script):
                self.run_python(ROOT / 'scripts' / script)
        run = self.case / 'run'
        self.run_python(ROOT / 'evals/prepare.py', '--skill', ROOT, '--out', run)
        copied = json.loads(self.run_python(run / 'skill/scripts/package_state.py',
                                           run / 'case-002/report.txt', 'com.example.browser'))
        self.assertEqual(copied['records'][0]['package'], 'com.example.browser')
        self.assertFalse((run / 'skill/evals').exists())


if __name__ == '__main__':
    unittest.main()
