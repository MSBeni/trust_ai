import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.own_compliance import (
    OWN_COMPLIANCE_ENTRY_TYPE,
    OWN_COMPLIANCE_SCHEMA,
    append_own_compliance_dossier,
    build_own_compliance_dossier,
    verify_own_compliance_dossier,
)


ROOT = Path(__file__).resolve().parents[1]


class OwnComplianceDossierTests(unittest.TestCase):
    def test_readiness_dossier_binds_sources_and_appends(self):
        dossier = build_own_compliance_dossier(
            ROOT,
            dossier_ref="dossier:trustai/own-compliance-readiness",
            producer_ref="oidc:trustai.example/compliance-ops",
            scope_ref="scope:trustai/company",
            generated_at="2026-07-19T00:00:00Z",
        )
        result = verify_own_compliance_dossier(dossier, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="own-compliance-test")
            entry = append_own_compliance_dossier(chain, dossier, root=ROOT)

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertIn("readiness mode", result.warnings[0])
        self.assertEqual(OWN_COMPLIANCE_SCHEMA, dossier["schema"])
        self.assertEqual("readiness", dossier["mode"])
        self.assertEqual({"external-required": 2, "passed": 6}, entry["payload"]["control_summary"])
        self.assertEqual(OWN_COMPLIANCE_ENTRY_TYPE, entry["entry_type"])

    def test_external_certification_dossier_satisfies_required_controls(self):
        dossier = build_own_compliance_dossier(
            ROOT,
            dossier_ref="dossier:trustai/own-compliance-certified",
            producer_ref="oidc:trustai.example/compliance-ops",
            scope_ref="scope:trustai/company",
            mode="external-certification",
            evidence=[
                {
                    "kind": "soc2-type-ii-report",
                    "evidence_ref": "audit:soc2/type-ii/2026",
                    "evidence_hash": "sha256:" + "a" * 64,
                    "issuer": "auditor:example-cpa",
                    "issued_at": "2026-07-19T01:00:00Z",
                    "expires_at": "2027-07-19T01:00:00Z",
                },
                {
                    "kind": "iso-42001-certificate",
                    "evidence_ref": "cert:iso-42001/2026",
                    "evidence_hash": "sha256:" + "b" * 64,
                    "issuer": "certification-body:example",
                    "issued_at": "2026-07-19T01:05:00Z",
                    "expires_at": "2027-07-19T01:05:00Z",
                },
            ],
            generated_at="2026-07-19T01:10:00Z",
        )
        result = verify_own_compliance_dossier(dossier, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="own-compliance-external-test")
            entry = append_own_compliance_dossier(chain, dossier, root=ROOT)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual([], result.warnings)
        self.assertEqual(2, dossier["metrics"]["required_certification_evidence_count"])
        self.assertEqual({"passed": 8}, entry["payload"]["control_summary"])

    def test_dossier_detects_source_artifact_tamper(self):
        dossier = build_own_compliance_dossier(
            ROOT,
            dossier_ref="dossier:trustai/own-compliance-tamper",
            producer_ref="oidc:trustai.example/compliance-ops",
            scope_ref="scope:trustai/company",
        )
        tampered = copy.deepcopy(dossier)
        tampered["source_artifacts"][0]["sha256"] = "sha256:tampered"

        result = verify_own_compliance_dossier(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("dossier_id does not match canonical own compliance body", result.errors)
        self.assertTrue(any("source artifact hash mismatch" in error for error in result.errors), result.errors)

    def test_external_certification_requires_both_required_evidence_kinds(self):
        dossier = build_own_compliance_dossier(
            ROOT,
            dossier_ref="dossier:trustai/own-compliance-incomplete",
            producer_ref="oidc:trustai.example/compliance-ops",
            scope_ref="scope:trustai/company",
            mode="external-certification",
            evidence=[
                {
                    "kind": "soc2-type-ii-report",
                    "evidence_ref": "audit:soc2/type-ii/2026",
                    "evidence_hash": "sha256:" + "a" * 64,
                    "issuer": "auditor:example-cpa",
                    "issued_at": "2026-07-19T01:00:00Z",
                },
            ],
        )

        result = verify_own_compliance_dossier(dossier, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("external-certification mode requires" in error for error in result.errors), result.errors)

    def test_cli_own_compliance_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            dossier_path = tmp / "own-compliance-dossier.json"
            entry_path = tmp / "own-compliance-dossier-entry.json"
            state_path = tmp / "chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            generated = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "own-compliance-dossier",
                    "--root",
                    str(ROOT),
                    "--dossier-ref",
                    "dossier:trustai/own-compliance-readiness",
                    "--producer-ref",
                    "oidc:trustai.example/compliance-ops",
                    "--scope-ref",
                    "scope:trustai/company",
                    "--generated-at",
                    "2026-07-19T00:00:00Z",
                    "--out",
                    str(dossier_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, generated.returncode, generated.stderr)

            verified = subprocess.run(
                [sys.executable, "-m", "trustai", "own-compliance-dossier-verify", str(dossier_path), "--root", str(ROOT)],
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
                    "own-compliance-dossier-append",
                    str(dossier_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "own-compliance-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, appended.returncode, appended.stderr)
            self.assertEqual(OWN_COMPLIANCE_SCHEMA, json.loads(dossier_path.read_text())["schema"])
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()