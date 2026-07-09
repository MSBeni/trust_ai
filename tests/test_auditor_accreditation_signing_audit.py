import copy
import tempfile
import unittest
from pathlib import Path

from tests import test_auditor_accreditation_signing_ceremony
from trustai.auditor_accreditation_signing_audit import (
    AUDITOR_ACCREDITATION_SIGNING_AUDIT_ENTRY_TYPE,
    AUDITOR_ACCREDITATION_SIGNING_AUDIT_SCHEMA,
    append_auditor_accreditation_signing_audit_receipt,
    build_auditor_accreditation_signing_audit_receipt,
    verify_auditor_accreditation_signing_audit_receipt,
)
from trustai.auditor_accreditation_signing_ceremony import build_auditor_accreditation_signing_ceremony_receipt
from trustai.chain import EvidenceChain


ROOT = Path(__file__).resolve().parents[1]


class AuditorAccreditationSigningAuditTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        sources = test_auditor_accreditation_signing_ceremony.AuditorAccreditationSigningCeremonyTests()._sources(tmp)
        pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature = sources
        ceremony = build_auditor_accreditation_signing_ceremony_receipt(
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
        return pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature, ceremony

    def test_auditor_accreditation_signing_audit_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature, ceremony = sources
            receipt = build_auditor_accreditation_signing_audit_receipt(
                ceremony,
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
                mode="provider-anchored",
                audit_ref="LF-TRUSTAI-AUD-CS-2026-001:audit",
                publisher="LF TrustAI Signing Transparency",
                publication_endpoint="https://standards.example/signing-audit",
                credential_ref="env:SPONSOR_SIGNING_AUDIT_TOKEN",
                actor_ref="oidc:standards.example/accreditation-sponsor-1",
                public_key_ref="https://standards.example/keys/auditor-accreditation-signing.pub",
                public_key_fingerprint="sha256:lf-trustai-auditor-accreditation-signing",
                publication_ref="KEYPUB-2026-TRUSTAI-AUD-001",
                rotation_ref="key-rotation:lf-trustai/2026-Q3",
                revocation_ref="crl:lf-trustai/auditor-accreditation-signing",
                audit_log_ref="audit-log:lf-trustai/signing/2026-07-26",
                audit_log_root="8c93d55abc6b8425ace8b488ab53ff0ef0ac79d6231cdfe6d5b7dc0c5268eaa2",
                audit_log_size=4,
                audit_log_entry_ref="audit-log-entry:LF-TRUSTAI-AUD-CS-2026-001",
                audit_log_export_ref="audit-export:LF-TRUSTAI-AUD-CS-2026-001",
                retention_until="2033-07-26T00:00:00Z",
                witness_refs=["audit-log:lf-trustai/signing/2026-07-26"],
                evidence_refs=["key-publication:KEYPUB-2026-TRUSTAI-AUD-001"],
                response_status=201,
                response_body={"status": "published", "publication_ref": "KEYPUB-2026-TRUSTAI-AUD-001"},
                published_at="2026-07-26T00:45:00Z",
            )

            result = verify_auditor_accreditation_signing_audit_receipt(
                receipt,
                signing_ceremony_receipt=ceremony,
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
            chain = EvidenceChain.load(Path(tmp_dir) / "auditor-accreditation-signing-audit-chain.json", tenant_id="auditor-accreditation-signing-audit-local")
            entry = append_auditor_accreditation_signing_audit_receipt(
                chain,
                receipt,
                signing_ceremony_receipt=ceremony,
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

            self.assertEqual(AUDITOR_ACCREDITATION_SIGNING_AUDIT_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("provider-anchored", result.mode)
            self.assertEqual(AUDITOR_ACCREDITATION_SIGNING_AUDIT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["audit_id"], entry["payload"]["audit_id"])

    def test_auditor_accreditation_signing_audit_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature, ceremony = sources
            receipt = build_auditor_accreditation_signing_audit_receipt(
                ceremony,
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
                public_key_ref="https://standards.example/keys/auditor-accreditation-signing.pub",
                public_key_fingerprint="sha256:lf-trustai-auditor-accreditation-signing",
                audit_log_ref="audit-log:lf-trustai/signing/2026-07-26",
                audit_log_root="8c93d55abc6b8425ace8b488ab53ff0ef0ac79d6231cdfe6d5b7dc0c5268eaa2",
                audit_log_size=4,
                actor_ref="oidc:standards.example/accreditation-sponsor-1",
                response_status=201,
                published_at="2026-07-26T00:45:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["source_artifacts"][0]["content_hash"] = "changed"

            result = verify_auditor_accreditation_signing_audit_receipt(
                tampered,
                signing_ceremony_receipt=ceremony,
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
            self.assertTrue(any("audit_id" in error for error in result.errors))
            self.assertTrue(any("auditor_accreditation_signing_ceremony_receipt content_hash mismatch" in error for error in result.errors))

    def test_auditor_accreditation_signing_audit_requires_audit_log(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature, ceremony = sources

            with self.assertRaisesRegex(ValueError, "audit_log_ref"):
                build_auditor_accreditation_signing_audit_receipt(
                    ceremony,
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
                    mode="provider-anchored",
                    public_key_ref="https://standards.example/keys/auditor-accreditation-signing.pub",
                    public_key_fingerprint="sha256:lf-trustai-auditor-accreditation-signing",
                    actor_ref="oidc:standards.example/accreditation-sponsor-1",
                    response_status=201,
                    published_at="2026-07-26T00:45:00Z",
                )


if __name__ == "__main__":
    unittest.main()
