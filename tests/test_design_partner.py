import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.design_partner import (
    DESIGN_PARTNER_ENTRY_TYPE,
    DESIGN_PARTNER_SCHEMA,
    append_design_partner_dossier,
    build_design_partner_dossier,
    verify_design_partner_dossier,
)


ROOT = Path(__file__).resolve().parents[1]


class DesignPartnerDossierTests(unittest.TestCase):
    def test_readiness_dossier_binds_sources_and_appends(self):
        dossier = build_design_partner_dossier(
            ROOT,
            dossier_ref="dossier:design-partner/phase1-readiness",
            producer_ref="oidc:trustai.example/gtm-ops",
            partners=[
                {"partner_ref": "partner:bank-a", "industry": "finserv", "agent_ref": "agent:payments-risk", "pilot_value_usd": 60000, "contract_status": "negotiating"},
                {"partner_ref": "partner:insurer-b", "industry": "insurance", "agent_ref": "agent:claims-triage", "pilot_value_usd": 90000, "contract_status": "negotiating"},
                {"partner_ref": "partner:fintech-c", "industry": "fintech", "agent_ref": "agent:treasury-ops", "pilot_value_usd": 100000, "contract_status": "negotiating"},
            ],
            scrutiny_events=[
                {"scrutiny_ref": "scrutiny:model-risk-a", "party_type": "model-risk", "party_ref": "team:model-risk", "partner_ref": "partner:bank-a", "outcome": "submitted"},
            ],
            generated_at="2026-07-18T00:00:00Z",
        )
        result = verify_design_partner_dossier(dossier, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="design-partner-test")
            entry = append_design_partner_dossier(chain, dossier, root=ROOT)

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertIn("readiness mode", result.warnings[0])
        self.assertEqual(DESIGN_PARTNER_SCHEMA, dossier["schema"])
        self.assertEqual("readiness", dossier["mode"])
        self.assertEqual(3, dossier["metrics"]["partner_count"])
        self.assertEqual({"external-required": 2, "passed": 6}, entry["payload"]["control_summary"])
        self.assertEqual(DESIGN_PARTNER_ENTRY_TYPE, entry["entry_type"])

    def test_external_evidence_dossier_satisfies_phase1_controls(self):
        dossier = build_design_partner_dossier(
            ROOT,
            dossier_ref="dossier:design-partner/phase1-external",
            producer_ref="oidc:trustai.example/gtm-ops",
            mode="external-evidence",
            partners=[
                {
                    "partner_ref": "partner:bank-a",
                    "industry": "finserv",
                    "agent_ref": "agent:payments-risk",
                    "pilot_value_usd": 90000,
                    "contract_status": "signed",
                    "contract_evidence_ref": "contract:bank-a/MSA-2026",
                    "contract_evidence_hash": "sha256:" + "1" * 64,
                    "payment_evidence_ref": "payment:bank-a/pilot-invoice-2026",
                    "payment_evidence_hash": "sha256:" + "2" * 64,
                },
                {
                    "partner_ref": "partner:insurer-b",
                    "industry": "insurance",
                    "agent_ref": "agent:claims-triage",
                    "pilot_value_usd": 80000,
                    "contract_status": "active",
                    "contract_evidence_ref": "contract:insurer-b/pilot-2026",
                    "contract_evidence_hash": "sha256:" + "3" * 64,
                    "payment_evidence_ref": "payment:insurer-b/pilot-invoice-2026",
                    "payment_evidence_hash": "sha256:" + "4" * 64,
                },
                {
                    "partner_ref": "partner:fintech-c",
                    "industry": "fintech",
                    "agent_ref": "agent:treasury-ops",
                    "pilot_value_usd": 90000,
                    "contract_status": "signed",
                    "contract_evidence_ref": "contract:fintech-c/SOW-2026",
                    "contract_evidence_hash": "sha256:" + "5" * 64,
                    "payment_evidence_ref": "payment:fintech-c/pilot-invoice-2026",
                    "payment_evidence_hash": "sha256:" + "6" * 64,
                },
            ],
            scrutiny_events=[
                {
                    "scrutiny_ref": "scrutiny:auditor-a",
                    "party_type": "auditor",
                    "party_ref": "auditor:example",
                    "partner_ref": "partner:bank-a",
                    "outcome": "survived",
                    "evidence_ref": "review:auditor-a/proof-pack-accepted",
                    "evidence_hash": "sha256:" + "7" * 64,
                },
            ],
            generated_at="2026-07-18T01:00:00Z",
        )
        result = verify_design_partner_dossier(dossier, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="design-partner-external-test")
            entry = append_design_partner_dossier(chain, dossier, root=ROOT)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual([], result.warnings)
        self.assertEqual(260000, dossier["metrics"]["signed_pilot_value_usd"])
        self.assertEqual(260000, dossier["metrics"]["evidence_bound_pilot_value_usd"])
        self.assertEqual(3, entry["payload"]["paying_evidence_bound_partner_count"])
        self.assertEqual({"passed": 8}, entry["payload"]["control_summary"])
        self.assertEqual(1, entry["payload"]["external_scrutiny_survival_count"])
        self.assertEqual(1, entry["payload"]["evidence_bound_scrutiny_survival_count"])

    def test_external_evidence_dossier_requires_hash_bound_business_evidence(self):
        dossier = build_design_partner_dossier(
            ROOT,
            dossier_ref="dossier:design-partner/phase1-weak-external",
            producer_ref="oidc:trustai.example/gtm-ops",
            mode="external-evidence",
            partners=[
                {"partner_ref": "partner:bank-a", "industry": "finserv", "agent_ref": "agent:payments-risk", "pilot_value_usd": 90000, "contract_status": "signed", "contract_evidence_ref": "contract:bank-a/MSA-2026"},
                {"partner_ref": "partner:insurer-b", "industry": "insurance", "agent_ref": "agent:claims-triage", "pilot_value_usd": 80000, "contract_status": "active", "contract_evidence_ref": "contract:insurer-b/pilot-2026"},
                {"partner_ref": "partner:fintech-c", "industry": "fintech", "agent_ref": "agent:treasury-ops", "pilot_value_usd": 90000, "contract_status": "signed", "contract_evidence_ref": "contract:fintech-c/SOW-2026"},
            ],
            scrutiny_events=[
                {"scrutiny_ref": "scrutiny:auditor-a", "party_type": "auditor", "party_ref": "auditor:example", "partner_ref": "partner:bank-a", "outcome": "survived", "evidence_ref": "review:auditor-a/proof-pack-accepted"},
            ],
            generated_at="2026-07-18T01:00:00Z",
        )

        result = verify_design_partner_dossier(dossier, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("external-evidence mode requires hash-bound partner contract/payment and scrutiny evidence for exit-criteria claims", result.errors)
        self.assertEqual(0, dossier["metrics"]["paying_evidence_bound_partner_count"])
        self.assertEqual(0, dossier["metrics"]["evidence_bound_scrutiny_survival_count"])

    def test_dossier_detects_source_artifact_tamper(self):
        dossier = build_design_partner_dossier(
            ROOT,
            dossier_ref="dossier:design-partner/tamper",
            producer_ref="oidc:trustai.example/gtm-ops",
            partners=[
                {"partner_ref": "partner:bank-a", "industry": "finserv", "agent_ref": "agent:payments-risk", "pilot_value_usd": 60000, "contract_status": "negotiating"},
                {"partner_ref": "partner:insurer-b", "industry": "insurance", "agent_ref": "agent:claims-triage", "pilot_value_usd": 90000, "contract_status": "negotiating"},
                {"partner_ref": "partner:fintech-c", "industry": "fintech", "agent_ref": "agent:treasury-ops", "pilot_value_usd": 100000, "contract_status": "negotiating"},
            ],
        )
        tampered = copy.deepcopy(dossier)
        tampered["source_artifacts"][0]["sha256"] = "sha256:tampered"

        result = verify_design_partner_dossier(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("dossier_id does not match canonical design-partner pilot body", result.errors)
        self.assertTrue(any("source artifact hash mismatch" in error for error in result.errors), result.errors)

    def test_unknown_scrutiny_partner_is_rejected(self):
        dossier = build_design_partner_dossier(
            ROOT,
            dossier_ref="dossier:design-partner/unknown-scrutiny",
            producer_ref="oidc:trustai.example/gtm-ops",
            partners=[
                {"partner_ref": "partner:bank-a", "industry": "finserv", "agent_ref": "agent:payments-risk", "pilot_value_usd": 60000, "contract_status": "negotiating"},
                {"partner_ref": "partner:insurer-b", "industry": "insurance", "agent_ref": "agent:claims-triage", "pilot_value_usd": 90000, "contract_status": "negotiating"},
                {"partner_ref": "partner:fintech-c", "industry": "fintech", "agent_ref": "agent:treasury-ops", "pilot_value_usd": 100000, "contract_status": "negotiating"},
            ],
            scrutiny_events=[
                {"scrutiny_ref": "scrutiny:bad", "party_type": "auditor", "party_ref": "auditor:example", "partner_ref": "partner:missing", "outcome": "submitted"},
            ],
        )

        result = verify_design_partner_dossier(dossier, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("references unknown partner_ref" in error for error in result.errors), result.errors)

    def test_cli_design_partner_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            dossier_path = tmp / "design-partner-dossier.json"
            entry_path = tmp / "design-partner-dossier-entry.json"
            state_path = tmp / "chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            generated = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "design-partner-dossier",
                    "--root",
                    str(ROOT),
                    "--dossier-ref",
                    "dossier:design-partner/phase1-readiness",
                    "--producer-ref",
                    "oidc:trustai.example/gtm-ops",
                    "--partner",
                    "partner:bank-a,finserv,agent:payments-risk,60000,negotiating",
                    "--partner",
                    "partner:insurer-b,insurance,agent:claims-triage,90000,negotiating",
                    "--partner",
                    "partner:fintech-c,fintech,agent:treasury-ops,100000,negotiating",
                    "--scrutiny",
                    "scrutiny:model-risk-a,model-risk,team:model-risk,partner:bank-a,submitted",
                    "--generated-at",
                    "2026-07-18T00:00:00Z",
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
                [sys.executable, "-m", "trustai", "design-partner-dossier-verify", str(dossier_path), "--root", str(ROOT)],
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
                    "design-partner-dossier-append",
                    str(dossier_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "design-partner-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, appended.returncode, appended.stderr)
            self.assertEqual(DESIGN_PARTNER_SCHEMA, json.loads(dossier_path.read_text())["schema"])
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()