import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.crypto import sign_value
from trustai.design_partner import build_design_partner_dossier, write_design_partner_dossier
from trustai.design_partner_authority import (
    DESIGN_PARTNER_AUTHORITY_ENTRY_TYPE,
    DESIGN_PARTNER_AUTHORITY_SCHEMA,
    append_design_partner_authority_dossier,
    build_design_partner_authority_dossier,
    verify_design_partner_authority_dossier,
)


ROOT = Path(__file__).resolve().parents[1]


def _external_pilot_dossier(*, mode: str = "external-evidence", generated_at: str = "2026-07-18T01:00:00Z"):
    return build_design_partner_dossier(
        ROOT,
        dossier_ref=f"dossier:design-partner/{mode}",
        producer_ref="oidc:trustai.example/gtm-ops",
        mode=mode,
        partners=[
            {
                "partner_ref": "partner:bank-a",
                "industry": "finserv",
                "agent_ref": "agent:payments-risk",
                "pilot_value_usd": 90000,
                "contract_status": "signed" if mode == "external-evidence" else "negotiating",
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
                "contract_status": "active" if mode == "external-evidence" else "negotiating",
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
                "contract_status": "signed" if mode == "external-evidence" else "negotiating",
                "contract_evidence_ref": "contract:fintech-c/SOW-2026",
                "contract_evidence_hash": "sha256:" + "5" * 64,
                "payment_evidence_ref": "payment:fintech-c/pilot-invoice-2026",
                "payment_evidence_hash": "sha256:" + "6" * 64,
            },
        ],
        scrutiny_events=[
            {
                "scrutiny_ref": "scrutiny:regulator-a",
                "party_type": "regulator",
                "party_ref": "regulator:example",
                "partner_ref": "partner:bank-a",
                "outcome": "survived" if mode == "external-evidence" else "submitted",
                "evidence_ref": "review:regulator-a/proof-pack-survived",
                "evidence_hash": "sha256:" + "7" * 64,
            },
        ],
        generated_at=generated_at,
    )


def _authority_rows():
    return [
        {
            "requirement_id": "customer-paid-pilot-acceptance",
            "authority_kind": "customer",
            "evidence_ref": "customer:bank-a/paid-pilot-acceptance",
            "evidence_hash": "sha256:" + "a" * 64,
            "description": "Customer acceptance and payment evidence for the Phase 1 paid pilot.",
            "issuer": "Bank A",
            "subject": "TrustAI paid pilot",
            "source_uri": "https://customer.example/bank-a/pilot/acceptance",
            "issued_at": "2026-07-19T00:00:00Z",
            "expires_at": "2026-12-31T00:00:00Z",
        },
        {
            "requirement_id": "regulator-or-supervisor-scrutiny-survival",
            "authority_kind": "regulator",
            "evidence_ref": "regulator:exam-2026/proof-pack-survived",
            "evidence_hash": "sha256:" + "b" * 64,
            "description": "Regulator or supervisor review evidence showing the proof pack survived scrutiny.",
            "issuer": "Example Supervisor",
            "subject": "TrustAI proof pack review",
            "source_uri": "https://regulator.example/exams/trustai-proof-pack",
            "issued_at": "2026-07-20T00:00:00Z",
            "expires_at": "2026-12-31T00:00:00Z",
        },
        {
            "requirement_id": "insurer-underwriting-review",
            "authority_kind": "insurer",
            "evidence_ref": "insurer:underwriting-2026/proof-pack-review",
            "evidence_hash": "sha256:" + "c" * 64,
            "description": "Insurer underwriting review evidence consuming proof-pack telemetry.",
            "issuer": "Example AI Liability Insurer",
            "subject": "TrustAI proof-pack underwriting review",
            "source_uri": "https://insurer.example/underwriting/trustai",
            "issued_at": "2026-07-21T00:00:00Z",
            "expires_at": "2026-12-31T00:00:00Z",
        },
    ]


def _resign(dossier: dict):
    body = without_keys(dossier, "dossier_id", "signatures")
    dossier["dossier_id"] = content_hash(body)
    dossier["signatures"] = [sign_value({"dossier_id": dossier["dossier_id"], "design_partner_authority": body})]


class DesignPartnerAuthorityTests(unittest.TestCase):
    def test_partial_partner_dossier_verifies_and_appends(self):
        pilot = _external_pilot_dossier()
        dossier = build_design_partner_authority_dossier(
            pilot,
            root=ROOT,
            mode="partner-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:design-partner-authority/phase1",
            authority_ref="authority:design-partner/phase1",
            producer_ref="oidc:trustai.example/design-partner-authority-worker",
            authority_evidence=[_authority_rows()[0]],
            generated_at="2026-07-21T01:00:00Z",
        )
        result = verify_design_partner_authority_dossier(dossier, pilot_dossier=pilot, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="design-partner-authority-test")
            entry = append_design_partner_authority_dossier(chain, dossier, pilot_dossier=pilot, root=ROOT)

        self.assertTrue(result.ok, result.errors)
        self.assertIn("design partner authority evidence missing for", "\n".join(result.warnings))
        self.assertEqual(1, result.covered_count)
        self.assertEqual(DESIGN_PARTNER_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual({"deferred": 3, "passed": 4}, entry["payload"]["control_summary"])

    def test_complete_production_dossier_requires_fresh_evidence(self):
        pilot = _external_pilot_dossier()
        dossier = build_design_partner_authority_dossier(
            pilot,
            root=ROOT,
            mode="production-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:design-partner-authority/phase1-production",
            authority_ref="authority:design-partner/phase1",
            producer_ref="oidc:trustai.example/design-partner-authority-worker",
            authority_evidence=_authority_rows(),
            generated_at="2026-07-21T01:00:00Z",
        )

        result = verify_design_partner_authority_dossier(
            dossier,
            pilot_dossier=pilot,
            root=ROOT,
            require_complete=True,
            require_fresh=True,
            now="2026-07-22T00:00:00Z",
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual([], result.warnings)
        self.assertEqual(3, result.covered_count)
        self.assertEqual(3, result.fresh_evidence_count)
        self.assertEqual({"passed": 7}, dossier["controls"] and {c["status"]: sum(1 for item in dossier["controls"] if item["status"] == c["status"]) for c in dossier["controls"]})

    def test_production_dossier_rejects_readiness_source(self):
        pilot = _external_pilot_dossier(mode="readiness")
        dossier = build_design_partner_authority_dossier(
            pilot,
            root=ROOT,
            mode="production-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:design-partner-authority/weak-source",
            authority_ref="authority:design-partner/phase1",
            producer_ref="oidc:trustai.example/design-partner-authority-worker",
            authority_evidence=_authority_rows(),
            generated_at="2026-07-21T01:00:00Z",
        )

        result = verify_design_partner_authority_dossier(
            dossier,
            pilot_dossier=pilot,
            root=ROOT,
            require_complete=True,
            require_fresh=True,
            now="2026-07-22T00:00:00Z",
        )

        self.assertFalse(result.ok)
        self.assertIn("production-dossier requires a source pilot dossier that meets Phase 1 exit metrics", "\n".join(result.errors))

    def test_malformed_hash_after_resign_is_rejected(self):
        pilot = _external_pilot_dossier()
        dossier = build_design_partner_authority_dossier(
            pilot,
            root=ROOT,
            mode="partner-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:design-partner-authority/malformed",
            authority_ref="authority:design-partner/phase1",
            producer_ref="oidc:trustai.example/design-partner-authority-worker",
            authority_evidence=[_authority_rows()[0]],
            generated_at="2026-07-21T01:00:00Z",
        )
        tampered = copy.deepcopy(dossier)
        tampered["authority_evidence"][0]["evidence_hash"] = "sha256:not-a-real-digest"
        tampered["authority_evidence"][0]["evidence_id"] = content_hash(without_keys(tampered["authority_evidence"][0], "evidence_id"))
        _resign(tampered)

        result = verify_design_partner_authority_dossier(tampered, pilot_dossier=pilot, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("evidence_hash" in error for error in result.errors), result.errors)

    def test_source_context_mismatch_after_resign_is_rejected(self):
        pilot = _external_pilot_dossier()
        dossier = build_design_partner_authority_dossier(
            pilot,
            root=ROOT,
            mode="partner-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:design-partner-authority/source-context",
            authority_ref="authority:design-partner/phase1",
            producer_ref="oidc:trustai.example/design-partner-authority-worker",
            authority_evidence=[_authority_rows()[0]],
            generated_at="2026-07-21T01:00:00Z",
        )
        tampered = copy.deepcopy(dossier)
        tampered["authority_evidence"][0]["source_context"]["dossier_id"] = "tampered"
        tampered["authority_evidence"][0]["evidence_id"] = content_hash(without_keys(tampered["authority_evidence"][0], "evidence_id"))
        _resign(tampered)

        result = verify_design_partner_authority_dossier(tampered, pilot_dossier=pilot, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("source_context does not match pilot source", "\n".join(result.errors))

    def test_cli_design_partner_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pilot_path = tmp / "pilot.json"
            dossier_path = tmp / "authority.json"
            entry_path = tmp / "authority-entry.json"
            state_path = tmp / "chain.json"
            pilot = _external_pilot_dossier()
            write_design_partner_dossier(pilot_path, pilot)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            evidence_args: list[str] = []
            for item in _authority_rows():
                metadata = (
                    f"issuer={item['issuer']};subject={item['subject']};source_uri={item['source_uri']};"
                    f"issued_at={item['issued_at']};expires_at={item['expires_at']}"
                )
                evidence_args.extend(
                    [
                        "--authority-evidence",
                        f"{item['requirement_id']},{item['authority_kind']},{item['evidence_ref']},{item['evidence_hash']},{item['description']};{metadata}",
                    ]
                )

            generated = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "design-partner-authority",
                    str(pilot_path),
                    "--root",
                    str(ROOT),
                    "--mode",
                    "production-dossier",
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:design-partner-authority/phase1-production",
                    "--authority-ref",
                    "authority:design-partner/phase1",
                    "--producer-ref",
                    "oidc:trustai.example/design-partner-authority-worker",
                    "--generated-at",
                    "2026-07-21T01:00:00Z",
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-22T00:00:00Z",
                    "--out",
                    str(dossier_path),
                    *evidence_args,
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
                    "design-partner-authority-verify",
                    str(dossier_path),
                    str(pilot_path),
                    "--root",
                    str(ROOT),
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-22T00:00:00Z",
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
                    "design-partner-authority-append",
                    str(dossier_path),
                    str(pilot_path),
                    "--root",
                    str(ROOT),
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-22T00:00:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "design-partner-authority-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, appended.returncode, appended.stderr)
            self.assertEqual(DESIGN_PARTNER_AUTHORITY_SCHEMA, json.loads(dossier_path.read_text())["schema"])
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
