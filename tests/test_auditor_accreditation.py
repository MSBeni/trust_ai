import copy
import tempfile
import unittest
from pathlib import Path

import tests.test_certification as certification_helpers

from trustai.auditor_accreditation import (
    AUDITOR_ACCREDITATION_ENTRY_TYPE,
    AUDITOR_ACCREDITATION_SCHEMA,
    append_auditor_accreditation_receipt,
    build_auditor_accreditation_receipt,
    verify_auditor_accreditation_receipt,
)
from trustai.certification import build_auditor_certification_kit
from trustai.chain import EvidenceChain


ROOT = Path(__file__).resolve().parents[1]


class AuditorAccreditationTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        pack, disclosure, standards = certification_helpers.AuditorCertificationTests()._source_artifacts(tmp)
        kit = build_auditor_certification_kit(
            pack,
            regulator_disclosure=disclosure,
            standards_package=standards,
        )
        return pack, disclosure, standards, kit

    def test_auditor_accreditation_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack, disclosure, standards, kit = self._sources(tmp)
            receipt = build_auditor_accreditation_receipt(
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

            result = verify_auditor_accreditation_receipt(
                receipt,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
            )
            chain = EvidenceChain.load(tmp / "auditor-accreditation-chain.json", tenant_id="auditor-accreditation-local")
            entry = append_auditor_accreditation_receipt(
                chain,
                receipt,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
            )

            self.assertEqual(AUDITOR_ACCREDITATION_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("active", result.status)
            self.assertEqual(AUDITOR_ACCREDITATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["accreditation_id"], entry["payload"]["accreditation_id"])

    def test_auditor_accreditation_detects_kit_hash_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, disclosure, standards, kit = self._sources(Path(tmp_dir))
            receipt = build_auditor_accreditation_receipt(
                kit,
                auditor_name="Example Audit LLP",
                auditor_ref="oidc:auditor.example/reviewer-123",
                auditor_organization="Example Audit LLP",
                issued_at="2026-07-15T00:00:00Z",
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
            )
            tampered = copy.deepcopy(receipt)
            tampered["source_artifacts"][0]["content_hash"] = "changed"

            result = verify_auditor_accreditation_receipt(
                tampered,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("accreditation_id" in error for error in result.errors))
            self.assertTrue(any("auditor_certification_kit content_hash mismatch" in error for error in result.errors))

    def test_auditor_accreditation_requires_minimum_score(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, disclosure, standards, kit = self._sources(Path(tmp_dir))

            with self.assertRaisesRegex(ValueError, "minimum score"):
                build_auditor_accreditation_receipt(
                    kit,
                    auditor_name="Example Audit LLP",
                    auditor_ref="oidc:auditor.example/reviewer-123",
                    auditor_organization="Example Audit LLP",
                    score_percent=79,
                    proof_pack=pack,
                    regulator_disclosure=disclosure,
                    standards_package=standards,
                    root=ROOT,
                )


if __name__ == "__main__":
    unittest.main()
