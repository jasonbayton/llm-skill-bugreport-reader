import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from report_io import iter_lines, redact
from triage import analyse, as_markdown, timestamp_from_line
from context import locate
from compare import compare


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.fixture_dir = ROOT / "tests" / "fixtures"

    def test_profile_and_explicit_provisioning_result(self):
        report = analyse(self.fixture_dir / "provisioning.txt", "provisioning", [], None, 15)
        self.assertEqual(report["profile"]["api_level"]["value"], "34")
        self.assertIn("provisioning-rejected", [x["id"] for x in report["findings"]])
        self.assertIn("STATUS_DEVICE_ADMIN_NOT_SUPPORTED", as_markdown(report, 10))
        self.assertNotIn("example@example.com", as_markdown(report, 10))
        self.assertNotIn("not-real-secret", as_markdown(report, 10))

    def test_kiosk_policy_and_incident_window(self):
        from datetime import datetime
        report = analyse(self.fixture_dir / "kiosk.txt", "kiosk", ["com.example.browser"], datetime(2026, 1, 1, 12, 5, 2), 2)
        ids = [x["id"] for x in report["findings"]]
        self.assertIn("package-policy", ids)
        self.assertIn("activity-rejected", ids)
        self.assertTrue(any(x.get("incident_window") is True for x in report["package_context"]))
        self.assertTrue(report["state_snapshots_or_mentions"]["management"])

    def test_zip_sources_and_traversal_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "report.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("bugreport-synthetic.txt", (self.fixture_dir / "provisioning.txt").read_text())
                archive.writestr("../bugreport-danger.txt", "FATAL EXCEPTION\n")
                archive.writestr("images/screenshot.png", b"\x89PNG")
            records = list(iter_lines(source))
            self.assertTrue(records)
            self.assertEqual({r[0] for r in records}, {"bugreport-synthetic.txt"})
            report = analyse(source, "auto", [], None, 15)
            self.assertIn("provisioning-rejected", [x["id"] for x in report["findings"]])

    def test_context_returns_neighbours(self):
        results = list(locate(self.fixture_dir / "provisioning.txt", ["STATUS_DEVICE_ADMIN_NOT_SUPPORTED"], 1, 5))
        self.assertEqual(len(results), 3)
        self.assertEqual(results[1][0], "match")

    def test_compare_reports_marks_snapshot_not_causation(self):
        a = analyse(self.fixture_dir / "provisioning.txt", "auto", [], None, 15)
        b = analyse(self.fixture_dir / "kiosk.txt", "auto", [], None, 15)
        result = compare(a, b)
        self.assertTrue(any(item["field"] == "api_level" for item in result["property_changes"]))
        self.assertIn("not directly comparable", result["warning"])

    def test_redaction(self):
        redacted = redact("contact=someone@example.org ip=192.168.1.2 Authorization: BEARERTOKEN serial=AA1234567890")
        self.assertNotIn("someone@example.org", redacted)
        self.assertNotIn("192.168.1.2", redacted)
        self.assertNotIn("BEARERTOKEN", redacted)
        self.assertNotIn("AA1234567890", redacted)

    def test_missing_evidence_does_not_create_false_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clean.txt"
            path.write_text("[ro.build.version.sdk]: [35]\nActivity requested and completed.\n")
            result = analyse(path, "auto", [], None, 15)
            self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
