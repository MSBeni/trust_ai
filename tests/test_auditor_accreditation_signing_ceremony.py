import copy
import tempfile
import unittest
from pathlib import Path

from tests import test_auditor_accreditation_countersignature
from trustai.auditor_accreditation_countersignature import build_auditor_accreditation_countersignature_receipt
from trustai.auditor_accreditation_signing_ceremony import (
    AUDITOR_ACCREDITATION_SIGNING_CEREMONY_ENTRY_TYPE,
    AUDITOR_ACCREDITATION_SIGNING_CEREMONY_SCHEMA,
    append_auditor_accreditation_signing_ceremony_receipt,
    build_auditor_accreditation_signing_ceremony_receipt,
    verify_auditor_accreditation_signing_ceremony_receipt,
)
from trustai.chain import EvidenceChain


ROOT = Path(__file__).resolve().parents[1]


class AuditorAccreditationSigningCeremonyTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        sources = test_auditor_accreditation_countersignature.AuditorAccreditationCountersignatureTests()._sources(tmp)
        pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation = sources
        countersignature = build_auditor_accreditation_countersignature_receipt(
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
        return pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature

    def test_auditor_accreditation_signing_ceremony_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature = sources
            receipt = build_auditor_accreditation_signing_ceremony_receipt(
                countersignature,
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
                mode="sponsor-controlled",
                ceremony_ref="LF-TRUSTAI-AUD-CS-2026-001:ceremony",
                signing_system="LF TrustAI Sponsor Signing HSM",
                signing_endpoint="https://signing.example/accreditations",
                key_provider="lf-trustai-hsm",
                key_ref="kms:lf-trustai/auditor-accreditation-signing",
                public_key_ref="https://standards.example/keys/auditor-accreditation-signing.pub",
                credential_ref="env:SPONSOR_SIGNING_TOKEN",
                sponsor_operator_ref="oidc:standards.example/accreditation-sponsor-1",
                approver_refs=["oidc:standards.example/chair-1", "oidc:standards.example/secretary-1"],
                witness_refs=["audit-log:lf-trustai/signing/2026-07-26"],
                quorum_required=2,
                authority_ref="minutes:trustai-wg/2026-07-26",
                policy_ref="policy:auditor-accreditation-signing-v0.1",
                rotation_ref="key-rotation:lf-trustai/2026-Q3",
                revocation_ref="crl:lf-trustai/auditor-accreditation-signing",
                evidence_refs=["minutes:trustai-wg/2026-07-26"],
                ceremony_at="2026-07-26T00:30:00Z",
            )

            result = verify_auditor_accreditation_signing_ceremony_receipt(
                receipt,
                countersignature_receipt=countersignature,
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
            chain = EvidenceChain.load(Path(tmp_dir) / "auditor-accreditation-signing-ceremony-chain.json", tenant_id="auditor-accreditation-signing-ceremony-local")
            entry = append_auditor_accreditation_signing_ceremony_receipt(
                chain,
                receipt,
                countersignature_receipt=countersignature,
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

            self.assertEqual(AUDITOR_ACCREDITATION_SIGNING_CEREMONY_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("sponsor-controlled", result.mode)
            self.assertEqual(AUDITOR_ACCREDITATION_SIGNING_CEREMONY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["ceremony_id"], entry["payload"]["ceremony_id"])

    def test_auditor_accreditation_signing_ceremony_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature = sources
            receipt = build_auditor_accreditation_signing_ceremony_receipt(
                countersignature,
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
                mode="sponsor-controlled",
                key_ref="kms:lf-trustai/auditor-accreditation-signing",
                sponsor_operator_ref="oidc:standards.example/accreditation-sponsor-1",
                approver_refs=["oidc:standards.example/chair-1"],
                authority_ref="minutes:trustai-wg/2026-07-26",
                policy_ref="policy:auditor-accreditation-signing-v0.1",
                ceremony_at="2026-07-26T00:30:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["source_artifacts"][0]["content_hash"] = "changed"

            result = verify_auditor_accreditation_signing_ceremony_receipt(
                tampered,
                countersignature_receipt=countersignature,
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
            self.assertTrue(any("ceremony_id" in error for error in result.errors))
            self.assertTrue(any("auditor_accreditation_countersignature_receipt content_hash mismatch" in error for error in result.errors))

    def test_auditor_accreditation_signing_ceremony_requires_quorum(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature = sources

            with self.assertRaisesRegex(ValueError, "quorum_required"):
                build_auditor_accreditation_signing_ceremony_receipt(
                    countersignature,
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
                    mode="sponsor-controlled",
                    key_ref="kms:lf-trustai/auditor-accreditation-signing",
                    sponsor_operator_ref="oidc:standards.example/accreditation-sponsor-1",
                    approver_refs=["oidc:standards.example/chair-1"],
                    quorum_required=2,
                    authority_ref="minutes:trustai-wg/2026-07-26",
                    policy_ref="policy:auditor-accreditation-signing-v0.1",
                    ceremony_at="2026-07-26T00:30:00Z",
                )


if __name__ == "__main__":
    unittest.main()
