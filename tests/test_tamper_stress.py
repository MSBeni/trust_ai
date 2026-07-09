from __future__ import annotations

import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.tamper_stress import (
    TAMPER_STRESS_REPORT_SCHEMA,
    build_tamper_stress_report,
    load_tamper_stress_report,
    verify_tamper_stress_report,
    write_tamper_stress_report,
)


class TamperStressReportTests(unittest.TestCase):
    def test_tamper_stress_report_verifies_samples_and_tamper_vectors(self):
        report = build_tamper_stress_report(entry_count=64, sample_indexes=[0, 31, 63], tamper_index=31)

        result = verify_tamper_stress_report(report, deep=True)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(TAMPER_STRESS_REPORT_SCHEMA, report["schema"])
        self.assertEqual(64, report["chain"]["entry_count"])
        self.assertEqual(4, report["summary"]["tamper_checks_detected"])
        self.assertTrue(report["summary"]["all_generated_entries_verified"])
        self.assertTrue(report["summary"]["all_tamper_checks_detected"])

    def test_tamper_stress_report_detects_summary_tamper(self):
        report = build_tamper_stress_report(entry_count=16)
        tampered = copy.deepcopy(report)
        tampered["summary"]["tamper_checks_detected"] = 0

        result = verify_tamper_stress_report(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("report_id" in error for error in result.errors))
        self.assertTrue(any("summary detected tamper count" in error for error in result.errors))

    def test_cli_tamper_stress_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_path = Path(tmp_dir) / "tamper-stress.json"
            create = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "tamper-stress-report",
                    "--entries",
                    "32",
                    "--sample-index",
                    "0",
                    "--sample-index",
                    "15",
                    "--sample-index",
                    "31",
                    "--tamper-index",
                    "15",
                    "--out",
                    str(report_path),
                ],
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(create.returncode, 0, create.stderr)
            verify = subprocess.run(
                [sys.executable, "-m", "trustai", "tamper-stress-verify", str(report_path), "--deep"],
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertIn("deep verification: regenerated chain root matched", verify.stdout)
            report = load_tamper_stress_report(report_path)
            self.assertEqual(32, report["chain"]["entry_count"])

    def test_write_tamper_stress_report_creates_parent(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "nested" / "report.json"
            report = build_tamper_stress_report(entry_count=8)

            write_tamper_stress_report(path, report)

            self.assertTrue(path.exists())
            self.assertTrue(verify_tamper_stress_report(load_tamper_stress_report(path)).ok)


if __name__ == "__main__":
    unittest.main()
