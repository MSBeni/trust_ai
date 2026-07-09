import copy
import tempfile
import unittest
from pathlib import Path

import tests.test_certification as certification_helpers

from trustai.auditor_program_governance import build_auditor_program_governance_receipt
from trustai.auditor_program_sponsorship import (
    AUDITOR_PROGRAM_SPONSORSHIP_ENTRY_TYPE,
    AUDITOR_PROGRAM_SPONSORSHIP_SCHEMA,
    append_auditor_program_sponsorship_receipt,
    build_auditor_program_sponsorship_receipt,
    verify_auditor_program_sponsorship_receipt,
)
from trustai.certification import build_auditor_certification_kit
from trustai.chain import EvidenceChain
from trustai.standards_body_ballot import build_standards_body_ballot_receipt
from trustai.standards_body_status import build_standards_body_status_receipt
from trustai.standards_body_submission import build_standards_body_submission_receipt
from trustai.verifier_conformance import build_verifier_conformance_report
from trustai.verifier_release import build_verifier_release_manifest


ROOT = Path(__file__).resolve().parents[1]


class AuditorProgramSponsorshipTests(unittest.TestCase):
    def _sources(self, tmp: Path, *, ballot_outcome: str = "accepted"):
        pack, disclosure, standards = certification_helpers.AuditorCertificationTests()._source_artifacts(tmp)
        conformance = build_verifier_conformance_report(pack)
        release = build_verifier_release_manifest(
            ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )
        submission = build_standards_body_submission_receipt(
            standards,
            release,
            conformance,
            root=ROOT,
            standards_body="Linux Foundation TrustAI Working Group",
            program_ref="LF-TRUSTAI-PROOF-PACKS",
            target_track="draft-specification",
            endpoint="https://standards.example/submissions/trustai",
            contact_ref="wg:trustai-proof-packs",
            submission_ref="STD-TRUSTAI-2026-001",
            status="submitted",
            submitted_at="2026-07-17T00:00:00Z",
        )
        status = build_standards_body_status_receipt(
            submission,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            new_status="ballot_open",
            docket_ref="LF-TRUSTAI-DKT-2026-001",
            status_ref="LF-TRUSTAI-DKT-2026-001:ballot",
            ballot_ref="LF-TRUSTAI-BALLOT-2026-001",
            actor_ref="oidc:standards.example/chair-1",
            actor_role="working-group-chair",
            decided_at="2026-07-19T00:00:00Z",
        )
        ballot = build_standards_body_ballot_receipt(
            submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            ballot_ref="LF-TRUSTAI-BALLOT-2026-001",
            decision_ref="LF-TRUSTAI-DECISION-2026-001",
            motion="Accept TrustAI proof-pack v0.1 as a working-group draft specification.",
            outcome=ballot_outcome,
            eligible_voters=7,
            votes_for=6 if ballot_outcome == "accepted" else 2,
            votes_against=1 if ballot_outcome == "accepted" else 5,
            abstentions=0,
            quorum_required=4,
            approval_threshold_percent=66,
            opened_at="2026-07-19T00:00:00Z",
            closed_at="2026-07-25T00:00:00Z",
            decided_at="2026-07-25T02:00:00Z",
            actor_ref="oidc:standards.example/chair-1",
        )
        kit = build_auditor_certification_kit(
            pack,
            regulator_disclosure=disclosure,
            standards_package=standards,
        )
        governance = build_auditor_program_governance_receipt(
            kit,
            standards_package=standards,
            proof_pack=pack,
            regulator_disclosure=disclosure,
            root=ROOT,
            program_name="TrustAI Auditor Program",
            program_ref="TRUSTAI-AUDITOR-0.1",
            accreditation_body="TrustAI Auditor Program",
            governance_body="Linux Foundation TrustAI Working Group",
            governance_ref="LF-TRUSTAI-AUDITOR-SPONSOR-2026-001",
            governance_mode="standards-body-sponsored",
            operator_ref="oidc:trustai.example/program-operator",
            board_members=["oidc:standards.example/chair-1", "oidc:trustai.example/program-operator"],
            independence_policy_ref="policy:auditor-independence-v0.1",
            proctoring_policy_ref="policy:auditor-proctoring-v0.1",
            revocation_policy_ref="policy:auditor-revocation-v0.1",
            renewal_policy_ref="policy:auditor-renewal-v0.1",
            appeals_policy_ref="policy:auditor-appeals-v0.1",
            registry_ref="registry:trustai-auditors",
            evidence_refs=["minutes:trustai-wg/2026-07-25"],
            issued_at="2026-07-25T03:00:00Z",
            effective_at="2026-07-25T04:00:00Z",
            expires_at="2027-07-25T00:00:00Z",
        )
        return pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance

    def test_auditor_program_sponsorship_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance = sources
            receipt = build_auditor_program_sponsorship_receipt(
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
            )

            result = verify_auditor_program_sponsorship_receipt(
                receipt,
                governance_receipt=governance,
                ballot_receipt=ballot,
                certification_kit=kit,
                standards_package=standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                submission_receipt=submission,
                status_receipt=status,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )
            chain = EvidenceChain.load(Path(tmp_dir) / "auditor-program-sponsorship-chain.json", tenant_id="auditor-program-sponsorship-local")
            entry = append_auditor_program_sponsorship_receipt(
                chain,
                receipt,
                governance_receipt=governance,
                ballot_receipt=ballot,
                certification_kit=kit,
                standards_package=standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                submission_receipt=submission,
                status_receipt=status,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

            self.assertEqual(AUDITOR_PROGRAM_SPONSORSHIP_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("active", result.status)
            self.assertEqual("standards-body-sponsored", result.sponsorship_mode)
            self.assertEqual(AUDITOR_PROGRAM_SPONSORSHIP_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["sponsorship_id"], entry["payload"]["sponsorship_id"])

    def test_auditor_program_sponsorship_detects_ballot_hash_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance = sources
            receipt = build_auditor_program_sponsorship_receipt(
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
                issued_at="2026-07-25T04:00:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["source_artifacts"][1]["content_hash"] = "changed"

            result = verify_auditor_program_sponsorship_receipt(
                tampered,
                governance_receipt=governance,
                ballot_receipt=ballot,
                certification_kit=kit,
                standards_package=standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                submission_receipt=submission,
                status_receipt=status,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("sponsorship_id" in error for error in result.errors))
            self.assertTrue(any("standards_body_ballot_receipt content_hash mismatch" in error for error in result.errors))

    def test_auditor_program_sponsorship_requires_accepted_ballot(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir), ballot_outcome="rejected")
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance = sources

            with self.assertRaisesRegex(ValueError, "requires an accepted"):
                build_auditor_program_sponsorship_receipt(
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
                    issued_at="2026-07-25T04:00:00Z",
                )


if __name__ == "__main__":
    unittest.main()
