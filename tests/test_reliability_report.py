import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.reliability_report import (
    RELIABILITY_REPORT_ENTRY_TYPE,
    RELIABILITY_REPORT_SCHEMA,
    append_reliability_report,
    build_reliability_report,
    verify_reliability_report,
    write_reliability_report,
)


ROOT = Path(__file__).resolve().parents[1]


def _source_product() -> dict:
    return {
        "schema": "trustai.actuarial-product/0.1",
        "product_id": "product:trustai/reliability-benchmark/2026",
        "product": {"name": "TrustAI reliability benchmark", "publisher": "trustai-local"},
        "aggregate": {"record_count": 12, "incident_count": 2},
    }


def _cohorts() -> list[dict]:
    return [
        {
            "segment_ref": "segment:finserv",
            "contributing_org_count": 3,
            "agent_count": 12,
            "proof_pack_count": 48,
            "promotion_pass_count": 42,
            "promotion_fail_count": 6,
            "incident_count": 2,
            "total_action_count": 125000,
            "source_ref": "actuarial-product:finserv",
        },
        {
            "segment_ref": "segment:insurance",
            "contributing_org_count": 4,
            "agent_count": 8,
            "proof_pack_count": 24,
            "promotion_pass_count": 21,
            "promotion_fail_count": 3,
            "incident_count": 1,
            "total_action_count": 80000,
            "source_ref": "actuarial-product:insurance",
        },
    ]


class ReliabilityReportTests(unittest.TestCase):
    def test_draft_report_binds_sources_and_appends(self):
        product = _source_product()
        report = build_reliability_report(
            ROOT,
            report_ref="report:trustai/state-of-agent-reliability/2026",
            producer_ref="oidc:trustai.example/reliability-research",
            period_start="2026-01-01T00:00:00Z",
            period_end="2026-12-31T00:00:00Z",
            cohorts=_cohorts(),
            source_products=[product],
            generated_at="2026-12-31T12:00:00Z",
        )
        result = verify_reliability_report(report, root=ROOT, source_products=[product])
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="reliability-report-test")
            entry = append_reliability_report(chain, report, root=ROOT, source_products=[product])

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertIn("draft mode", result.warnings[0])
        self.assertEqual(RELIABILITY_REPORT_SCHEMA, report["schema"])
        self.assertEqual(3, report["aggregate"]["incident_count"])
        self.assertEqual(1, report["aggregate"]["incident_rate_per_100k_actions"])
        self.assertEqual({"external-required": 1, "passed": 7}, entry["payload"]["control_summary"])
        self.assertEqual(RELIABILITY_REPORT_ENTRY_TYPE, entry["entry_type"])

    def test_published_report_satisfies_all_controls(self):
        product = _source_product()
        report = build_reliability_report(
            ROOT,
            report_ref="report:trustai/state-of-agent-reliability/2026",
            producer_ref="oidc:trustai.example/reliability-research",
            period_start="2026-01-01T00:00:00Z",
            period_end="2026-12-31T00:00:00Z",
            cohorts=_cohorts(),
            source_products=[product],
            mode="published-evidence",
            publication_ref="https://trustai.example/reports/state-of-agent-reliability-2026",
            publication_hash="sha256:" + "c" * 64,
            generated_at="2026-12-31T12:00:00Z",
        )
        result = verify_reliability_report(report, root=ROOT, source_products=[product])
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="reliability-report-published-test")
            entry = append_reliability_report(chain, report, root=ROOT, source_products=[product])

        self.assertTrue(result.ok, result.errors)
        self.assertEqual([], result.warnings)
        self.assertEqual({"passed": 8}, entry["payload"]["control_summary"])
        self.assertEqual(1, entry["payload"]["source_product_count"])

    def test_report_detects_source_artifact_tamper(self):
        product = _source_product()
        report = build_reliability_report(
            ROOT,
            report_ref="report:trustai/state-of-agent-reliability/tamper",
            producer_ref="oidc:trustai.example/reliability-research",
            period_start="2026-01-01T00:00:00Z",
            period_end="2026-12-31T00:00:00Z",
            cohorts=_cohorts(),
            source_products=[product],
        )
        tampered = copy.deepcopy(report)
        tampered["source_artifacts"][0]["sha256"] = "sha256:tampered"

        result = verify_reliability_report(tampered, root=ROOT, source_products=[product])

        self.assertFalse(result.ok)
        self.assertIn("report_id does not match canonical state-of-agent-reliability body", result.errors)
        self.assertTrue(any("source artifact hash mismatch" in error for error in result.errors), result.errors)

    def test_published_report_requires_privacy_threshold(self):
        product = _source_product()
        cohorts = _cohorts()
        cohorts[0]["contributing_org_count"] = 2
        report = build_reliability_report(
            ROOT,
            report_ref="report:trustai/state-of-agent-reliability/privacy",
            producer_ref="oidc:trustai.example/reliability-research",
            period_start="2026-01-01T00:00:00Z",
            period_end="2026-12-31T00:00:00Z",
            cohorts=cohorts,
            source_products=[product],
            mode="published-evidence",
            publication_ref="https://trustai.example/reports/state-of-agent-reliability-2026",
            publication_hash="sha256:" + "c" * 64,
        )

        result = verify_reliability_report(report, root=ROOT, source_products=[product])

        self.assertFalse(result.ok)
        self.assertTrue(any("published-evidence mode requires" in error for error in result.errors), result.errors)

    def test_cli_reliability_report_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            product_path = tmp / "actuarial-product.json"
            report_path = tmp / "state-of-agent-reliability-report.json"
            entry_path = tmp / "state-of-agent-reliability-report-entry.json"
            state_path = tmp / "chain.json"
            write_reliability_report(product_path, _source_product())
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            generated = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "reliability-report",
                    "--root",
                    str(ROOT),
                    "--report-ref",
                    "report:trustai/state-of-agent-reliability/2026",
                    "--producer-ref",
                    "oidc:trustai.example/reliability-research",
                    "--period-start",
                    "2026-01-01T00:00:00Z",
                    "--period-end",
                    "2026-12-31T00:00:00Z",
                    "--cohort",
                    "segment:finserv,3,12,48,42,6,2,125000,actuarial-product:finserv",
                    "--actuarial-product",
                    str(product_path),
                    "--generated-at",
                    "2026-12-31T12:00:00Z",
                    "--out",
                    str(report_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, generated.returncode, generated.stderr)

            verified = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "reliability-report-verify",
                    str(report_path),
                    "--root",
                    str(ROOT),
                    "--actuarial-product",
                    str(product_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)

            appended = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "reliability-report-append",
                    str(report_path),
                    "--root",
                    str(ROOT),
                    "--actuarial-product",
                    str(product_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "reliability-report-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, appended.returncode, appended.stderr)
            self.assertEqual(RELIABILITY_REPORT_SCHEMA, json.loads(report_path.read_text())["schema"])
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()