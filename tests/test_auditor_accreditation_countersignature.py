import copy
import tempfile
import unittest
from pathlib import Path

import tests.test_auditor_program_sponsorship as sponsorship_helpers

from trustai.auditor_accreditation import build_auditor_accreditation_receipt
from trustai.auditor_accreditation_countersignature import (
    AUDITOR_ACCREDITATION_COUNTERSIGNATURE_ENTRY_TYPE,
    AUDITOR_ACCREDITATION_COUNTERSIGNATURE_SCHEMA,
    append_auditor_accreditation_countersignature_receipt,
    build_auditor_accreditation_countersignature_receipt,
    verify_auditor_accreditation_countersignature_receipt,
)
from trustai.auditor_program_sponsorship import build_auditor_program_sponsorship_receipt
from trustai.chain import EvidenceChain


ROOT = Path(__file__).resolve().parents[1]


class AuditorAccreditationCountersignatureTests(unittest.TestCase):
    def _sources(self, tmp: Path, *, sponsorship_status: str = "active"):
        sources = sponsorship_helpers.AuditorProgramSponsorshipTests()._sources(tmp)
        pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance = sources
        sponsorship = build_auditor_program_sponsorship_receipt(
            governance,
            ballot,
            certification_kit=kit,
            standards_package=standards,
            proof_pack=pack,
            regulator_disclosure=disclosure,
            submission_receipt=submission,
            status_receipt=status,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            sponsor_body="Linux Foundation TrustAI Working Group",
            sponsor_ref="wg:trustai-proof-packs",
            sponsorship_ref="LF-TRUSTAI-AUDITOR-SPONSOR-2026-001",
            terms_ref="charter:trustai-auditor-program-v0.1",
            charter_ref="charter:trustai-auditor-program-v0.1",
            oversight_refs=["minutes:trustai-wg/2026-07-25"],
            evidence_refs=["minutes:trustai-wg/2026-07-25"],
            issued_at="2026-07-25T04:00:00Z",
            effective_at="2026-07-25T05:00:00Z",
            expires_at="2027-07-25T00:00:00Z",
            status=sponsorship_status,
        )
        accreditation = build_auditor_accreditation_receipt(
            kit,
            standards_package=standards,
            proof_pack=pack,
            regulator_disclosure=disclosure,
            root=ROOT,
            auditor_name="Example Audit LLP",
            auditor_ref="oidc:auditor.example/reviewer-123",
            auditor_organization="Example Audit LLP",
            auditor_role="external-ai-auditor",
            accreditation_body="TrustAI Auditor Program",
            program_ref="TRUSTAI-AUDITOR-0.1",
            credential_id="TA-AUD-2026-001",
            score_percent=92,
            issued_at="2026-07-15T00:00:00Z",
            expires_at="2027-07-15T00:00:00Z",
            renewal_due_at="2027-06-15T00:00:00Z",
            proctor_ref="oidc:trustai.example/proctor-1",
            evidence_refs=["exam:TRUSTAI-AUD-2026-001"],
        )
        return pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation

    def test_auditor_accreditation_countersignature_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation = sources
            receipt = build_auditor_accreditation_countersignature_receipt(
                accreditation,
                sponsorship,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                governance_receipt=governance,
                ballot_receipt=ballot,
                submission_receipt=submission,
                status_receipt=status,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
                operation="issue",
                mode="sponsor-countersigned",
                countersignature_ref="LF-TRUSTAI-AUD-CS-2026-001",
                operation_ref="TA-AUD-2026-001:issue",
                sponsor_actor_ref="oidc:standards.example/accreditation-sponsor-1",
                sponsor_actor_role="working-group-chair",
                authority_ref="minutes:trustai-wg/2026-07-26",
                terms_ref="charter:trustai-auditor-program-v0.1",
                evidence_refs=["minutes:trustai-wg/2026-07-26"],
                signed_at="2026-07-26T00:00:00Z",
                effective_at="2026-07-26T01:00:00Z",
                expires_at="2027-07-15T00:00:00Z",
            )

            result = verify_auditor_accreditation_countersignature_receipt(
                receipt,
                accreditation_receipt=accreditation,
                sponsorship_receipt=sponsorship,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                governance_receipt=governance,
                ballot_receipt=ballot,
                submission_receipt=submission,
                status_receipt=status,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )
            chain = EvidenceChain.load(Path(tmp_dir) / "auditor-accreditation-countersignature-chain.json", tenant_id="auditor-accreditation-countersignature-local")
            entry = append_auditor_accreditation_countersignature_receipt(
                chain,
                receipt,
                accreditation_receipt=accreditation,
                sponsorship_receipt=sponsorship,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                governance_receipt=governance,
                ballot_receipt=ballot,
                submission_receipt=submission,
                status_receipt=status,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

            self.assertEqual(AUDITOR_ACCREDITATION_COUNTERSIGNATURE_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("issue", result.operation)
            self.assertEqual("sponsor-countersigned", result.mode)
            self.assertEqual(AUDITOR_ACCREDITATION_COUNTERSIGNATURE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["countersignature_id"], entry["payload"]["countersignature_id"])

    def test_auditor_accreditation_countersignature_detects_sponsorship_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation = sources
            receipt = build_auditor_accreditation_countersignature_receipt(
                accreditation,
                sponsorship,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                governance_receipt=governance,
                ballot_receipt=ballot,
                submission_receipt=submission,
                status_receipt=status,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
                sponsor_actor_ref="oidc:standards.example/accreditation-sponsor-1",
                signed_at="2026-07-26T00:00:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["source_artifacts"][1]["content_hash"] = "changed"

            result = verify_auditor_accreditation_countersignature_receipt(
                tampered,
                accreditation_receipt=accreditation,
                sponsorship_receipt=sponsorship,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                governance_receipt=governance,
                ballot_receipt=ballot,
                submission_receipt=submission,
                status_receipt=status,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("countersignature_id" in error for error in result.errors))
            self.assertTrue(any("auditor_program_sponsorship_receipt content_hash mismatch" in error for error in result.errors))

    def test_auditor_accreditation_countersignature_requires_active_sponsorship(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir), sponsorship_status="suspended")
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation = sources

            with self.assertRaisesRegex(ValueError, "requires an active sponsorship"):
                build_auditor_accreditation_countersignature_receipt(
                    accreditation,
                    sponsorship,
                    certification_kit=kit,
                    proof_pack=pack,
                    regulator_disclosure=disclosure,
                    standards_package=standards,
                    governance_receipt=governance,
                    ballot_receipt=ballot,
                    submission_receipt=submission,
                    status_receipt=status,
                    verifier_release=release,
                    conformance_report=conformance,
                    root=ROOT,
                    sponsor_actor_ref="oidc:standards.example/accreditation-sponsor-1",
                    signed_at="2026-07-26T00:00:00Z",
                )


if __name__ == "__main__":
    unittest.main()
