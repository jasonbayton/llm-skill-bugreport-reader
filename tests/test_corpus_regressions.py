"""Synthetic reproductions of corpus-discovered failures; no customer data."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from report_io import iter_lines, new_coverage, redact
from triage import analyse, SIGNATURE_GATES
from compare import compare


class CorpusRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def nested(self, captures):
        path = self.root / 'reports.zip'
        with zipfile.ZipFile(path, 'w') as outer:
            for name, data in captures:
                outer.writestr(name, data)
        return path

    def inner(self, text):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('bugreport.txt', text)
        return buf.getvalue()

    def test_identical_nested_reports_count_once(self):
        data = self.inner('FATAL EXCEPTION repeated capture\n')
        p = self.nested([('one.zip', data), ('copy.zip', data)])
        cov = new_coverage()
        rows = list(iter_lines(p, coverage=cov))
        self.assertEqual(len(rows), 1)
        self.assertTrue(cov['complete'])
        self.assertEqual(cov['duplicate_archives'][0]['same_as'], 'one.zip')

    def test_member_filter_can_select_duplicate_alias(self):
        data = self.inner('FATAL EXCEPTION\n')
        p = self.nested([('one.zip', data), ('copy.zip', data)])
        rows = list(iter_lines(p, member_substring='copy.zip!bugreport.txt'))
        self.assertEqual(rows[0][0], 'copy.zip!bugreport.txt')

    def test_appledouble_metadata_not_opened_as_zip(self):
        p = self.nested([('__MACOSX/._report.zip', b'not an archive'), ('report.zip', self.inner('valid\n'))])
        cov = new_coverage()
        self.assertEqual(len(list(iter_lines(p, coverage=cov))), 1)
        self.assertEqual(cov['ignored_metadata_members'], 1)
        self.assertTrue(cov['complete'])

    def test_enrollment_and_recovery_credentials_masked(self):
        for key in ('recoveryKey', 'registrationKey', 'enrollment_token', 'activationCode', 'clientSecret', 'authToken'):
            self.assertNotIn('invented-sensitive-value', redact(key + '=invented-sensitive-value, next=ok'))

    def test_dry_run_placeholder_preserves_text_and_marks_gap(self):
        p = self.nested([('visible_windows.zip', b'cmd window dump-visible-window-views: skipped on dry run\n'),
                         ('bugreport.txt', b'dry run remaining text\n')])
        cov = new_coverage()
        rows = list(iter_lines(p, coverage=cov))
        self.assertEqual(rows[0][2], 'dry run remaining text\n')
        self.assertFalse(cov['complete'])
        self.assertIn('dry-run placeholder', cov['skipped'][0]['reason'])

    def test_other_invalid_nested_archives_still_fail(self):
        for name, data in [('visible_windows.zip', b'corrupt'),
                           ('report.zip', b'cmd window dump-visible-window-views: skipped on dry run\n')]:
            with self.subTest(name=name):
                p = self.nested([(name, data)])
                with self.assertRaises(zipfile.BadZipFile):
                    list(iter_lines(p))

    def test_denial_survives_surrounding_kiosk_snapshot_noise(self):
        p = self.root / 'report.txt'
        p.write_text('mLockTaskModeState=NONE\n' * 100 +
                     '01-01 10:00:00 ActivityTaskManager: Attempted Lock Task Mode violation u0 example.app/.Screen\n' +
                     'mLockTaskModeState=NONE\n' * 100)
        report = analyse(p, 'kiosk', [], None, 15)
        denial = next(f for f in report['findings'] if f['id'] == 'locktask-denial')
        self.assertEqual(denial['occurrences'], 1)
        self.assertIn('example.app/.Screen', denial['evidence'][0]['excerpt'])

    def test_native_tombstone_and_account_sync_leads(self):
        p = self.root / 'log.txt'
        p.write_text('signal 6 (SIGABRT), code -1\nAbort message: sample abort\n'
                     'SyncPolicyRequestFailureMetric(failureReason=1)\nBAD_AUTHENTICATION\n'
                     'Job INSTALL_UPDATE finished\nFOTA: policy is same\n')
        report = analyse(p, 'auto', [], None, 15)
        counts = {f['id']: f['occurrences'] for f in report['findings']}
        self.assertEqual(counts['native-crash'], 2)
        self.assertEqual(counts['account-sync-failure'], 2)
        self.assertEqual(counts['boot-lifecycle'], 2)

    def test_quoted_json_install_failure_field_is_indexed(self):
        p = self.root / 'report.txt'
        p.write_text('{"installationFailureReason": 12}\n')
        report = analyse(p, 'install', [], None, 15)
        finding = next(f for f in report['findings'] if f['id'] == 'install-result')
        self.assertEqual(finding['occurrences'], 1)
        self.assertEqual(finding['evidence'][0]['line'], 1)

    def test_flutter_dns_error_is_not_lost_without_java_exception(self):
        p = self.root / 'log.txt'
        p.write_text("flutter: SocketException: Failed host lookup: 'example.invalid' (No address associated with hostname)\n")
        report = analyse(p, 'network', [], None, 15)
        self.assertEqual(next(f for f in report['findings'] if f['id'] == 'network-failure')['occurrences'], 1)

    def test_policy_response_timeout_is_a_lead_not_a_root_cause(self):
        p = self.root / 'log.txt'
        p.write_text('clouddpc: PolicyUpdateMetric eventType=POLICY_UPDATE_TIMEOUT_AFTER_FCM_PING\n')
        report = analyse(p, 'provisioning', [], None, 15)
        f = next(f for f in report['findings'] if f['id'] == 'policy-sync-timeout')
        self.assertEqual(f['evidence'][0]['line'], 1)

    def test_dropbox_anr_header_without_logcat_anr_phrase(self):
        p = self.root / 'anr.txt'
        p.write_text('Searching for: system_app_anr\nLow priority tags: {system_app_anr}\n'
                     '2026-01-02 12:00:00 system_app_anr (compressed text, 123 bytes)\n'
                     'Process: example.settings\n')
        report = analyse(p, 'performance', [], None, 15)
        f = next(f for f in report['findings'] if f['id'] == 'crash-or-anr')
        self.assertEqual(f['occurrences'], 1)
        self.assertEqual(f['evidence'][0]['line'], 3)

    def test_dropbox_crash_header_is_an_event_not_tag_inventory(self):
        p = self.root / 'crash.txt'
        p.write_text('Low priority tags: {system_server_crash}\n'
                     '2026-01-02 12:00:00 system_server_crash (text, 123 bytes)\n'
                     'Process: system_server\n')
        report = analyse(p, 'crash', [], None, 15)
        f = next(f for f in report['findings'] if f['id'] == 'crash-or-anr')
        self.assertEqual(f['occurrences'], 1)
        self.assertEqual(f['evidence'][0]['line'], 2)

    def test_source_truncation_is_disclosed_without_losing_later_lines(self):
        p = self.root / 'anr.txt'
        p.write_text('first\n[[TRUNCATED]]\nlast\n')
        cov = new_coverage()
        rows = list(iter_lines(p, coverage=cov))
        self.assertFalse(cov['complete'])
        self.assertEqual(cov['source_truncation_markers'][0]['line'], 2)
        self.assertEqual(rows[-1][1], 3)

    def test_native_allocation_failure_without_java_oom(self):
        p = self.root / 'log.txt'
        p.write_text('android.system.ErrnoException: mmap failed: ENOMEM (Out of memory)\n'
                     'pthread_create failed: Try again\nToo many open files\n')
        report = analyse(p, 'performance', [], None, 15)
        f = next(f for f in report['findings'] if f['id'] == 'native-allocation-failure')
        self.assertEqual(f['occurrences'], 3)

    def test_same_build_distinct_captures_not_one_snapshot(self):
        a = self.inner('[ro.product.model]: [Example]\nmLockTaskModeState=LOCKED\n')
        b = self.inner('[ro.product.model]: [Example]\nmLockTaskModeState=NONE\n')
        p = self.nested([('before.zip', a), ('after.zip', b)])
        report = analyse(p, 'kiosk', [], None, 15)
        self.assertTrue(report['multiple_capture_sources'])
        self.assertEqual(report['profile'], {})
        self.assertIsNone(report['configuration']['lock_task_mode_at_capture'])
        modes = {c['snapshots']['lock_task_mode_at_capture']['value'] for c in report['captures']}
        self.assertEqual(modes, {'LOCKED', 'NONE'})
        with self.assertRaises(ValueError):
            compare(report, report)

    def test_literal_prefilter_keeps_same_evidence(self):
        p = self.root / 'log.txt'
        p.write_text('\n'.join([
            'FATAL EXCEPTION test', 'PackageInstaller failure', 'Network is unreachable',
            'Failed to create data directory', 'Kernel panic', 'User unlocked',
            'ActivityTaskManager START u0 sample', 'securityexception denied',
            'UnknownHostException résumé', 'mLockTaskModeState=LOCKED',
            'SETUP optional unrelated warning',
        ]))
        gated = analyse(p, 'auto', [], None, 15)
        backup = dict(SIGNATURE_GATES)
        try:
            SIGNATURE_GATES.clear()
            plain = analyse(p, 'auto', [], None, 15)
        finally:
            SIGNATURE_GATES.update(backup)
        self.assertEqual(gated, plain)


if __name__ == '__main__':
    unittest.main()
