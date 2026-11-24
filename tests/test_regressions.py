"""Behavioral regressions using invented, non-identifying evidence only."""
from datetime import datetime
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from report_io import iter_lines, redact, ScanLimits, new_coverage, safe_archive_name
from triage import analyse, timestamp_from_line
from context import locate
from compare import compare


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, text, name='report.txt'):
        p = self.root / name
        p.write_text(text)
        return p

    def test_common_secret_encodings(self):
        for value in [
            'Authorization: Bearer synthetic-value',
            'Authorization: Basic synthetic-value',
            '{"password": "synthetic-value"}',
            "{'access_token': 'synthetic-value'}",
            'registration_token=synthetic-value',
            '[ro.serialno]: [synthetic-value]',
            'https://user:synthetic-value@example.invalid/path?key=synthetic-value#synthetic-value',
        ]:
            with self.subTest(value=value):
                self.assertNotIn('synthetic-value', redact(value))

    def test_nested_zip_text_and_precise_source(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('bugreport.txt', 'first\nFATAL EXCEPTION nested\n')
            z.writestr('bugreport.proto', b'\x00FATAL EXCEPTION binary')
        outer = self.root / 'wrapper.zip'
        with zipfile.ZipFile(outer, 'w') as z:
            z.writestr('reports/inner.zip', inner.getvalue())
        cov = new_coverage()
        rows = list(iter_lines(outer, coverage=cov))
        self.assertEqual(rows[1], ('reports/inner.zip!bugreport.txt', 2, 'FATAL EXCEPTION nested\n'))
        self.assertEqual(len(rows), 2)
        self.assertTrue(cov['complete'])
        self.assertEqual(cov['nested_archives'], ['reports/inner.zip'])
        self.assertEqual(cov['ignored_binary_members'], 1)

    def test_oversize_member_is_disclosed(self):
        p = self.root / 'report.zip'
        with zipfile.ZipFile(p, 'w') as z:
            z.writestr('bugreport.txt', 'FATAL EXCEPTION\n' * 30)
        cov = new_coverage()
        self.assertEqual(list(iter_lines(p, coverage=cov, limits=ScanLimits(member_bytes=10))), [])
        self.assertFalse(cov['complete'])
        self.assertEqual(cov['skipped'][0]['source'], 'bugreport.txt')

    def test_null_bytes_do_not_end_valid_report_scan(self):
        p = self.file('header\nservice value=\x00\nFATAL EXCEPTION later\n')
        cov = new_coverage()
        rows = list(iter_lines(p, coverage=cov))
        self.assertEqual(rows[-1][1:], (3, 'FATAL EXCEPTION later\n'))
        self.assertIn('[NUL]', rows[1][2])
        self.assertEqual(cov['null_byte_lines'], 1)
        self.assertTrue(cov['complete'])

    def test_saved_call_history_not_unrelated_appop_activity(self):
        p = self.file('01-01 10:00:00 I PrivacyLog: App Op for com.android.server.telecom(1000), active=true\n'
                      '    10:00:01.000 - SET_CONNECTING (test)\n'
                      '    10:00:02.000 - SET_DIALING (test)\n'
                      '    10:00:03.000 - SET_ACTIVE (test)\n'
                      '    10:00:04.000 - SET_DISCONNECTED (test)\n')
        result = analyse(p, 'telephony', [], None, 15)
        finding = next(f for f in result['findings'] if f['id'] == 'telephony-lifecycle')
        self.assertEqual(finding['occurrences'], 4)
        self.assertTrue(any('SET_ACTIVE' in e['excerpt'] for e in finding['evidence']))
        self.assertTrue(all(e['timestamp'] is None for e in finding['evidence']))

    def test_named_timezone_requires_manual_alignment(self):
        stamp, within = timestamp_from_line('2026-01-01 10:00:00 EDT event', datetime(2026, 1, 1, 10), 15)
        self.assertIn('EDT', stamp)
        self.assertIsNone(within)

    def test_total_cap_fails_instead_of_silent_partial(self):
        p = self.file('first\nsecond\nthird\n')
        with self.assertRaises(ValueError):
            list(iter_lines(p, limits=ScanLimits(total_bytes=10)))

    def test_long_line_preserves_physical_line_numbers(self):
        p = self.file('x' * 1000 + '\nFATAL EXCEPTION\n')
        cov = new_coverage()
        rows = list(iter_lines(p, coverage=cov, limits=ScanLimits(line_bytes=64)))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][1], 2)
        self.assertIn('FATAL EXCEPTION', rows[1][2])
        self.assertLess(len(rows[0][2]), 100)
        self.assertFalse(cov['complete'])

    def test_hit_limit_on_consecutive_matches(self):
        p = self.file('FATAL EXCEPTION\n' * 100)
        cov = new_coverage()
        rows = list(locate(p, ['FATAL'], 2, 2, coverage=cov))
        self.assertEqual(sum(r[0] == 'match' for r in rows), 2)
        self.assertEqual(len(rows), 4)
        self.assertTrue(cov['stopped_early'])

    def test_zero_context_limit(self):
        p = self.file('FATAL EXCEPTION\n' * 100)
        self.assertEqual(len(list(locate(p, ['FATAL'], 0, 2))), 2)

    def test_member_filter_before_size_check(self):
        p = self.root / 'report.zip'
        with zipfile.ZipFile(p, 'w') as z:
            z.writestr('huge.txt', 'x' * 500)
            z.writestr('chosen.txt', 'a\nFATAL\nb\n')
        cov = new_coverage()
        rows = list(locate(p, ['FATAL'], 1, 5, 'chosen.txt', coverage=cov, limits=ScanLimits(member_bytes=50)))
        self.assertEqual(len(rows), 3)
        self.assertTrue(cov['complete'])
        self.assertEqual(cov['candidate_members'], 1)

    def test_literal_and_exact_line_retrieval(self):
        p = self.file('comXexampleXapp\ncom.example.app\ntrailer\n')
        rows = list(locate(p, ['com.example.app'], 0, 10, literal=True))
        self.assertEqual([r[2] for r in rows], [2])
        rows = list(locate(p, [], 1, 10, line_numbers=[2]))
        self.assertEqual([r[2] for r in rows], [1, 2, 3])

    def test_explicit_year_is_not_rewritten(self):
        self.assertIs(timestamp_from_line('2025-01-01 12:00:00.000 FATAL', datetime(2026, 1, 1, 12))[1], False)

    def test_year_boundary_and_leap_day(self):
        self.assertIs(timestamp_from_line('12-31 23:59:59.000 x', datetime(2026, 1, 1), 1)[1], True)
        self.assertIs(timestamp_from_line('02-29 12:00:00.000 x', datetime(2025, 3, 1, 12), 1)[1], False)

    def test_explicit_timezone_requires_alignment(self):
        self.assertIsNone(timestamp_from_line('2026-01-01T12:00:00Z x', datetime(2026, 1, 1, 12))[1])

    def test_window_is_not_global_mutable_state(self):
        line = '01-01 12:10:00.000 event'
        incident = datetime(2026, 1, 1, 12)
        self.assertTrue(timestamp_from_line(line, incident, 15)[1])
        self.assertFalse(timestamp_from_line(line, incident, 1)[1])
        self.assertTrue(timestamp_from_line(line, incident, 15)[1])

    def test_incident_survives_later_noise(self):
        p = self.file('01-01 01:00:00.000 FATAL EXCEPTION old\n' * 5 +
                      '01-01 12:00:00.000 FATAL EXCEPTION com.example.target incident\n' +
                      '01-01 23:00:00.000 FATAL EXCEPTION com.example.target later\n' * 100)
        result = analyse(p, 'crash', ['com.example.target'], datetime(2026, 1, 1, 12), 1)
        finding = next(x for x in result['findings'] if x['id'] == 'crash-or-anr')
        self.assertEqual(finding['evidence'][0]['line'], 6)
        self.assertEqual(result['package_context'][0]['line'], 6)
        self.assertEqual(finding['occurrences'], 106)

    def test_early_package_signal_survives_unrelated_tail(self):
        p = self.file('01-01 01:00:00.000 FATAL EXCEPTION unrelated\n' * 5 +
                      '01-01 12:00:00.000 FATAL EXCEPTION com.example.target\n' +
                      '01-01 23:00:00.000 FATAL EXCEPTION unrelated\n' * 100)
        result = analyse(p, 'crash', ['com.example.target'], None, 15)
        finding = next(x for x in result['findings'] if x['id'] == 'crash-or-anr')
        self.assertEqual(finding['evidence'][0]['line'], 6)

    def test_collector_errors_are_not_application_failures(self):
        p = self.root / 'report.zip'
        with zipfile.ZipFile(p, 'w') as z:
            z.writestr('bugreport.txt', '[ro.build.version.sdk]: [35]\n')
            z.writestr('dumpstate_log.txt', 'KeyStore error while dumping service\n')
        result = analyse(p, 'certificates', [], None, 15)
        self.assertEqual(result['findings'], [])
        self.assertEqual(len(result['collection_diagnostics']), 1)

    def test_conflicting_profiles_are_not_silently_merged(self):
        p = self.root / 'report.zip'
        with zipfile.ZipFile(p, 'w') as z:
            z.writestr('a.txt', '[ro.product.model]: [SyntheticA]\n')
            z.writestr('b.txt', '[ro.product.model]: [SyntheticB]\n')
        result = analyse(p, 'auto', [], None, 15)
        self.assertEqual(result['profile_conflicts']['model'][0]['value'], 'SyntheticB')
        with self.assertRaises(ValueError):
            compare(result, result)

    def test_lowercase_restriction_and_owner_block(self):
        p = self.file('Device Owner:\n  admin=ComponentInfo{com.example.dpc/.Admin}\n  User ID: 0\n'
                      '01-01 12:00:00.000 Finsky: Installs disallowed by policy\nno_install_apps=true\n')
        result = analyse(p, 'install', [], None, 15)
        self.assertIn('com.example.dpc', result['configuration']['owners'][0]['value'])
        self.assertIn('no_install_apps', result['configuration']['restriction_mentions'])
        self.assertIn('install-policy-denial', [x['id'] for x in result['findings']])

    def test_historical_locktask_is_not_capture_snapshot(self):
        p = self.file('01-01 12:00:00.000 D Log: mLockTaskModeState=LOCKED\n')
        result = analyse(p, 'kiosk', [], None, 15)
        self.assertIsNone(result['configuration']['lock_task_mode_at_capture'])

    def test_cli_refuses_source_or_existing_output(self):
        p = self.file('FATAL EXCEPTION original\n')
        for output in [p, self.file('existing', 'output.json')]:
            original = output.read_bytes()
            run = subprocess.run([sys.executable, str(ROOT/'scripts/triage.py'), str(p), '--json', str(output)], capture_output=True)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(output.read_bytes(), original)

    def test_cli_writes_valid_new_json(self):
        p = self.file('FATAL EXCEPTION synthetic\n')
        out = self.root / 'result.json'
        run = subprocess.run([sys.executable, str(ROOT/'scripts/triage.py'), str(p), '--json', str(out)], capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(out.read_text())['findings'][0]['id'], 'crash-or-anr')

    def test_bad_zip_returns_controlled_failure(self):
        p = self.file('not a zip', 'broken.zip')
        run = subprocess.run([sys.executable, str(ROOT/'scripts/context.py'), str(p), '--pattern', 'x'], capture_output=True)
        self.assertEqual(run.returncode, 2)
        self.assertNotIn(b'Traceback', run.stderr)

    def test_unsafe_path_variants(self):
        for path in ['../report.txt', '/report.txt', r'C:\report.txt', r'a\..\report.txt']:
            self.assertFalse(safe_archive_name(path))


if __name__ == '__main__':
    unittest.main()
