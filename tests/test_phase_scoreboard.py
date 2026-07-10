import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.phase_scoreboard import (
    PHASE_SCOREBOARD_ENTRY_TYPE,
    PHASE_SCOREBOARD_SCHEMA,
    append_phase_scoreboard,
    build_phase_scoreboard,
    verify_phase_scoreboard,
)


ROOT = Path(__file__).resolve().parents[1]


def _external_milestones() -> list[dict]:
    return [
        {"phase": "P1", "kind": "paying-design-partner", "metric_value": 3, "evidence_ref": "crm:customers/p1-design-partners", "evidence_hash": "sha256:" + "1" * 64, "issuer": "TrustAI Finance", "issued_at": "2026-12-31T00:00:00Z"},
        {"phase": "P1", "kind": "signed-pilot-value", "metric_value": 260000, "evidence_ref": "finance:signed-pilots/2026", "evidence_hash": "sha256:" + "2" * 64, "issuer": "TrustAI Finance", "issued_at": "2026-12-31T00:00:00Z"},
        {"phase": "P1", "kind": "external-scrutiny-survival", "metric_value": 1, "evidence_ref": "review:auditor/proof-pack-survived", "evidence_hash": "sha256:" + "3" * 64, "issuer": "Example Auditor", "issued_at": "2026-12-31T00:00:00Z"},
        {"phase": "P2", "kind": "customer-count", "metric_value": 15, "evidence_ref": "crm:customers/p2", "evidence_hash": "sha256:" + "4" * 64, "issuer": "TrustAI Finance", "issued_at": "2027-06-30T00:00:00Z"},
        {"phase": "P2", "kind": "arr", "metric_value": 1200000, "evidence_ref": "finance:arr/p2", "evidence_hash": "sha256:" + "5" * 64, "issuer": "TrustAI Finance", "issued_at": "2027-06-30T00:00:00Z"},
        {"phase": "P2", "kind": "vertical-beyond-finserv", "metric_value": 2, "evidence_ref": "crm:verticals/p2", "evidence_hash": "sha256:" + "6" * 64, "issuer": "TrustAI GTM", "issued_at": "2027-06-30T00:00:00Z"},
        {"phase": "P2", "kind": "insurer-integration-live", "metric_value": 1, "evidence_ref": "partner:insurer/live-integration", "evidence_hash": "sha256:" + "7" * 64, "issuer": "Example Underwriter", "issued_at": "2027-06-30T00:00:00Z"},
        {"phase": "P2", "kind": "own-soc2-type-ii", "metric_value": 1, "evidence_ref": "audit:soc2-type-ii/trustai", "evidence_hash": "sha256:" + "8" * 64, "issuer": "Example CPA", "issued_at": "2027-06-30T00:00:00Z"},
        {"phase": "P2", "kind": "own-iso-42001", "metric_value": 1, "evidence_ref": "cert:iso-42001/trustai", "evidence_hash": "sha256:" + "9" * 64, "issuer": "Example Certification Body", "issued_at": "2027-06-30T00:00:00Z"},
        {"phase": "P2", "kind": "series-a", "metric_value": 1, "evidence_ref": "finance:series-a/close", "evidence_hash": "sha256:" + "a" * 64, "issuer": "TrustAI Counsel", "issued_at": "2027-06-30T00:00:00Z"},
        {"phase": "P3", "kind": "arr", "metric_value": 9000000, "evidence_ref": "finance:arr/p3", "evidence_hash": "sha256:" + "b" * 64, "issuer": "TrustAI Finance", "issued_at": "2028-06-30T00:00:00Z"},
        {"phase": "P3", "kind": "regulator-acceptance", "metric_value": 1, "evidence_ref": "regulator:exam/accepted-pack", "evidence_hash": "sha256:" + "c" * 64, "issuer": "Example Supervisor", "issued_at": "2028-06-30T00:00:00Z"},
        {"phase": "P3", "kind": "insurer-pricing", "metric_value": 2, "evidence_ref": "insurer:pricing-on-packs", "evidence_hash": "sha256:" + "d" * 64, "issuer": "Insurance Partners", "issued_at": "2028-06-30T00:00:00Z"},
        {"phase": "P3", "kind": "standards-track", "metric_value": 1, "evidence_ref": "standards:trustai/spec-track", "evidence_hash": "sha256:" + "e" * 64, "issuer": "Standards Body", "issued_at": "2028-06-30T00:00:00Z"},
        {"phase": "P4", "kind": "procurement-contract", "metric_value": 1, "evidence_ref": "contract:vendor/proof-pack-clause", "evidence_hash": "sha256:" + "f" * 64, "issuer": "Example Buyer", "issued_at": "2029-06-30T00:00:00Z"},
        {"phase": "P4", "kind": "data-product-revenue", "metric_value": 1, "evidence_ref": "finance:data-products/revenue", "evidence_hash": "sha256:" + "0" * 64, "issuer": "TrustAI Finance", "issued_at": "2029-06-30T00:00:00Z"},
        {"phase": "P4", "kind": "generic-market-usage", "metric_value": 1, "evidence_ref": "market:proof-pack/generic-usage", "evidence_hash": "sha256:" + "a1" * 32, "issuer": "Market Research", "issued_at": "2029-06-30T00:00:00Z"},
    ]


class PhaseScoreboardTests(unittest.TestCase):
    def test_readiness_scoreboard_binds_sources_and_appends(self):
        scoreboard = build_phase_scoreboard(
            ROOT,
            scoreboard_ref="scoreboard:trustai/roadmap/readiness",
            producer_ref="oidc:trustai.example/strategy",
            generated_at="2026-07-20T00:00:00Z",
        )
        result = verify_phase_scoreboard(scoreboard, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="phase-scoreboard-test")
            entry = append_phase_scoreboard(chain, scoreboard, root=ROOT)

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertIn("readiness mode", result.warnings[0])
        self.assertEqual(PHASE_SCOREBOARD_SCHEMA, scoreboard["schema"])
        self.assertEqual("readiness", scoreboard["mode"])
        self.assertEqual(0, scoreboard["metrics"]["milestone_count"])
        self.assertEqual({"external-required": 10, "passed": 2}, entry["payload"]["control_summary"])
        self.assertEqual(PHASE_SCOREBOARD_ENTRY_TYPE, entry["entry_type"])

    def test_external_evidence_scoreboard_satisfies_all_phase_controls(self):
        scoreboard = build_phase_scoreboard(
            ROOT,
            scoreboard_ref="scoreboard:trustai/roadmap/external",
            producer_ref="oidc:trustai.example/strategy",
            mode="external-evidence",
            milestones=_external_milestones(),
            generated_at="2029-06-30T00:00:00Z",
        )
        result = verify_phase_scoreboard(scoreboard, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="phase-scoreboard-external-test")
            entry = append_phase_scoreboard(chain, scoreboard, root=ROOT)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual([], result.warnings)
        self.assertEqual(17, scoreboard["metrics"]["milestone_count"])
        self.assertEqual({"passed": 12}, entry["payload"]["control_summary"])
        self.assertEqual(7, entry["payload"]["phase_counts"]["P2"])

    def test_scoreboard_detects_source_artifact_tamper(self):
        scoreboard = build_phase_scoreboard(
            ROOT,
            scoreboard_ref="scoreboard:trustai/roadmap/tamper",
            producer_ref="oidc:trustai.example/strategy",
        )
        tampered = copy.deepcopy(scoreboard)
        tampered["source_artifacts"][0]["sha256"] = "sha256:tampered"

        result = verify_phase_scoreboard(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("scoreboard_id does not match canonical roadmap phase scoreboard body", result.errors)
        self.assertTrue(any("source artifact hash mismatch" in error for error in result.errors), result.errors)

    def test_external_mode_rejects_missing_milestones(self):
        scoreboard = build_phase_scoreboard(
            ROOT,
            scoreboard_ref="scoreboard:trustai/roadmap/incomplete",
            producer_ref="oidc:trustai.example/strategy",
            mode="external-evidence",
            milestones=_external_milestones()[:3],
        )

        result = verify_phase_scoreboard(scoreboard, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("external-evidence mode requires" in error for error in result.errors), result.errors)

    def test_cli_phase_scoreboard_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            scoreboard_path = tmp / "phase-scoreboard.json"
            entry_path = tmp / "phase-scoreboard-entry.json"
            state_path = tmp / "chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            generated = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "phase-scoreboard",
                    "--root",
                    str(ROOT),
                    "--scoreboard-ref",
                    "scoreboard:trustai/roadmap/readiness",
                    "--producer-ref",
                    "oidc:trustai.example/strategy",
                    "--generated-at",
                    "2026-07-20T00:00:00Z",
                    "--out",
                    str(scoreboard_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, generated.returncode, generated.stderr)

            verified = subprocess.run(
                [sys.executable, "-m", "trustai", "phase-scoreboard-verify", str(scoreboard_path), "--root", str(ROOT)],
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
                    "phase-scoreboard-append",
                    str(scoreboard_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "phase-scoreboard-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, appended.returncode, appended.stderr)
            self.assertEqual(PHASE_SCOREBOARD_SCHEMA, json.loads(scoreboard_path.read_text())["schema"])
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()