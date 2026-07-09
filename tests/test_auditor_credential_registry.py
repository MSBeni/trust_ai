import copy
import tempfile
import unittest
from pathlib import Path

import tests.test_auditor_accreditation as accreditation_helpers

from trustai.auditor_accreditation import build_auditor_accreditation_receipt
from trustai.auditor_credential_registry import (
    AUDITOR_CREDENTIAL_REGISTRY_ENTRY_TYPE,
    AUDITOR_CREDENTIAL_REGISTRY_SCHEMA,
    append_auditor_credential_registry_receipt,
    build_auditor_credential_registry_receipt,
    verify_auditor_credential_registry_receipt,
)
from trustai.chain import EvidenceChain


ROOT = Path(__file__).resolve().parents[1]


class AuditorCredentialRegistryTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        pack, disclosure, standards, kit = accreditation_helpers.AuditorAccreditationTests()._sources(tmp)
        accreditation = build_auditor_accreditation_receipt(
            kit,
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
            proof_pack=pack,
            regulator_disclosure=disclosure,
            standards_package=standards,
            root=ROOT,
        )
        return pack, disclosure, standards, kit, accreditation

    def test_auditor_credential_registry_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack, disclosure, standards, kit, accreditation = self._sources(tmp)
            receipt = build_auditor_credential_registry_receipt(
                accreditation,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
                registry_name="TrustAI Auditor Credential Registry",
                registry_endpoint="https://auditors.example",
                namespace="trustai-auditors",
                publication_ref="AUD-REG-2026-001",
                revocation_endpoint="https://auditors.example/revocations/TA-AUD-2026-001",
                operator_ref="oidc:trustai.example/registry-operator",
                published_at="2026-07-16T00:00:00Z",
            )

            result = verify_auditor_credential_registry_receipt(
                receipt,
                accreditation_receipt=accreditation,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
            )
            chain = EvidenceChain.load(tmp / "auditor-credential-registry-chain.json", tenant_id="auditor-credential-registry-local")
            entry = append_auditor_credential_registry_receipt(
                chain,
                receipt,
                accreditation_receipt=accreditation,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
            )

            self.assertEqual(AUDITOR_CREDENTIAL_REGISTRY_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("active", result.status)
            self.assertEqual(AUDITOR_CREDENTIAL_REGISTRY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["registry_id"], entry["payload"]["registry_id"])
            self.assertEqual("TA-AUD-2026-001", receipt["credential_record"]["credential_id"])

    def test_auditor_credential_registry_detects_accreditation_hash_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, disclosure, standards, kit, accreditation = self._sources(Path(tmp_dir))
            receipt = build_auditor_credential_registry_receipt(
                accreditation,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
                published_at="2026-07-16T00:00:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["source_artifacts"][0]["content_hash"] = "changed"

            result = verify_auditor_credential_registry_receipt(
                tampered,
                accreditation_receipt=accreditation,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("registry_id" in error for error in result.errors))
            self.assertTrue(any("auditor_accreditation_receipt content_hash mismatch" in error for error in result.errors))

    def test_auditor_credential_registry_requires_status_match(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, disclosure, standards, kit, accreditation = self._sources(Path(tmp_dir))

            with self.assertRaisesRegex(ValueError, "status must match"):
                build_auditor_credential_registry_receipt(
                    accreditation,
                    certification_kit=kit,
                    proof_pack=pack,
                    regulator_disclosure=disclosure,
                    standards_package=standards,
                    root=ROOT,
                    status="suspended",
                    published_at="2026-07-16T00:00:00Z",
                )


if __name__ == "__main__":
    unittest.main()
