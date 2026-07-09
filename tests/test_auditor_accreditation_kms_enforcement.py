import copy
import tempfile
import unittest
from pathlib import Path

from tests import test_auditor_accreditation_signing_audit
from trustai.auditor_accreditation_kms_enforcement import (
    AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_ENTRY_TYPE,
    AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_SCHEMA,
    append_auditor_accreditation_kms_enforcement_receipt,
    build_auditor_accreditation_kms_enforcement_receipt,
    verify_auditor_accreditation_kms_enforcement_receipt,
)
from trustai.auditor_accreditation_signing_audit import build_auditor_accreditation_signing_audit_receipt
from trustai.chain import EvidenceChain


ROOT = Path(__file__).resolve().parents[1]


class AuditorAccreditationKmsEnforcementTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        sources = test_auditor_accreditation_signing_audit.AuditorAccreditationSigningAuditTests()._sources(tmp)
        pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature, ceremony = sources
        audit = build_auditor_accreditation_signing_audit_receipt(
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
        return pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature, ceremony, audit

    def test_auditor_accreditation_kms_enforcement_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature, ceremony, audit = sources
            receipt = build_auditor_accreditation_kms_enforcement_receipt(
                audit,
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
                mode="provider-enforced",
                enforcement_ref="LF-TRUSTAI-AUD-CS-2026-001:kms-enforcement",
                provider="LF TrustAI Sponsor KMS",
                provider_endpoint="https://kms.example/signing/auditor-accreditation",
                credential_ref="env:SPONSOR_KMS_TOKEN",
                actor_ref="oidc:standards.example/accreditation-sponsor-1",
                attestation_ref="hsm-attestation:lf-trustai/auditor-accreditation-signing/2026-07-26",
                attestation_hash="sha256:lf-trustai-hsm-attestation-20260726",
                key_policy_ref="key-policy:lf-trustai/auditor-accreditation-signing/v0.1",
                key_policy_hash="sha256:lf-trustai-auditor-accreditation-key-policy",
                allowed_actor_refs=["oidc:standards.example/accreditation-sponsor-1"],
                denied_operation_refs=["kms:decrypt", "kms:export-private-key"],
                quorum_required=2,
                quorum_approver_refs=["oidc:standards.example/chair-1", "oidc:standards.example/secretary-1"],
                evidence_refs=["hsm-attestation:lf-trustai/auditor-accreditation-signing/2026-07-26"],
                response_status=200,
                response_body={"status": "enforced", "key_ref": "kms:lf-trustai/auditor-accreditation-signing"},
                enforced_at="2026-07-26T01:00:00Z",
            )

            result = verify_auditor_accreditation_kms_enforcement_receipt(
                receipt,
                signing_audit_receipt=audit,
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
            chain = EvidenceChain.load(Path(tmp_dir) / "auditor-accreditation-kms-enforcement-chain.json", tenant_id="auditor-accreditation-kms-enforcement-local")
            entry = append_auditor_accreditation_kms_enforcement_receipt(
                chain,
                receipt,
                signing_audit_receipt=audit,
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

            self.assertEqual(AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("provider-enforced", result.mode)
            self.assertEqual(AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["enforcement_id"], entry["payload"]["enforcement_id"])

    def test_auditor_accreditation_kms_enforcement_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature, ceremony, audit = sources
            receipt = build_auditor_accreditation_kms_enforcement_receipt(
                audit,
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
                mode="provider-enforced",
                actor_ref="oidc:standards.example/accreditation-sponsor-1",
                attestation_ref="hsm-attestation:lf-trustai/auditor-accreditation-signing/2026-07-26",
                attestation_hash="sha256:lf-trustai-hsm-attestation-20260726",
                key_policy_ref="key-policy:lf-trustai/auditor-accreditation-signing/v0.1",
                key_policy_hash="sha256:lf-trustai-auditor-accreditation-key-policy",
                allowed_actor_refs=["oidc:standards.example/accreditation-sponsor-1"],
                quorum_required=1,
                quorum_approver_refs=["oidc:standards.example/chair-1"],
                response_status=200,
                enforced_at="2026-07-26T01:00:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["source_artifacts"][0]["content_hash"] = "changed"

            result = verify_auditor_accreditation_kms_enforcement_receipt(
                tampered,
                signing_audit_receipt=audit,
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
            self.assertTrue(any("enforcement_id" in error for error in result.errors))
            self.assertTrue(any("auditor_accreditation_signing_audit_receipt content_hash mismatch" in error for error in result.errors))

    def test_auditor_accreditation_kms_enforcement_requires_quorum(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            pack, disclosure, standards, conformance, release, submission, status, ballot, kit, governance, sponsorship, accreditation, countersignature, ceremony, audit = sources

            with self.assertRaisesRegex(ValueError, "quorum_approver_refs"):
                build_auditor_accreditation_kms_enforcement_receipt(
                    audit,
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
                    mode="provider-enforced",
                    actor_ref="oidc:standards.example/accreditation-sponsor-1",
                    attestation_ref="hsm-attestation:lf-trustai/auditor-accreditation-signing/2026-07-26",
                    attestation_hash="sha256:lf-trustai-hsm-attestation-20260726",
                    key_policy_ref="key-policy:lf-trustai/auditor-accreditation-signing/v0.1",
                    key_policy_hash="sha256:lf-trustai-auditor-accreditation-key-policy",
                    allowed_actor_refs=["oidc:standards.example/accreditation-sponsor-1"],
                    quorum_required=2,
                    quorum_approver_refs=["oidc:standards.example/chair-1"],
                    response_status=200,
                    enforced_at="2026-07-26T01:00:00Z",
                )


if __name__ == "__main__":
    unittest.main()
