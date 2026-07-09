import copy
import tempfile
import unittest
from pathlib import Path

import tests.test_certification as certification_helpers

from trustai.auditor_program_governance import (
    AUDITOR_PROGRAM_GOVERNANCE_ENTRY_TYPE,
    AUDITOR_PROGRAM_GOVERNANCE_SCHEMA,
    append_auditor_program_governance_receipt,
    build_auditor_program_governance_receipt,
    verify_auditor_program_governance_receipt,
)
from trustai.certification import build_auditor_certification_kit
from trustai.chain import EvidenceChain


ROOT = Path(__file__).resolve().parents[1]


class AuditorProgramGovernanceTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        pack, disclosure, standards = certification_helpers.AuditorCertificationTests()._source_artifacts(tmp)
        kit = build_auditor_certification_kit(
            pack,
            regulator_disclosure=disclosure,
            standards_package=standards,
        )
        return pack, disclosure, standards, kit

    def test_auditor_program_governance_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack, disclosure, standards, kit = self._sources(tmp)
            receipt = build_auditor_program_governance_receipt(
                kit,
                standards_package=standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                root=ROOT,
                program_name="TrustAI Auditor Program",
                program_ref="TRUSTAI-AUDITOR-0.1",
                accreditation_body="TrustAI Auditor Program",
                governance_body="TrustAI Auditor Governance Board",
                governance_ref="TRUSTAI-AUD-GOV-2026-001",
                governance_mode="local-reference",
                operator_ref="oidc:trustai.example/program-operator",
                board_members=["oidc:trustai.example/board-1", "oidc:trustai.example/board-2"],
                independence_policy_ref="policy:auditor-independence-v0.1",
                proctoring_policy_ref="policy:auditor-proctoring-v0.1",
                revocation_policy_ref="policy:auditor-revocation-v0.1",
                renewal_policy_ref="policy:auditor-renewal-v0.1",
                appeals_policy_ref="policy:auditor-appeals-v0.1",
                registry_ref="registry:trustai-auditors",
                evidence_refs=["minutes:TRUSTAI-AUD-GOV-2026-001"],
                issued_at="2026-07-14T00:00:00Z",
                effective_at="2026-07-14T01:00:00Z",
                expires_at="2027-07-14T00:00:00Z",
            )

            result = verify_auditor_program_governance_receipt(
                receipt,
                certification_kit=kit,
                standards_package=standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                root=ROOT,
            )
            chain = EvidenceChain.load(tmp / "auditor-program-governance-chain.json", tenant_id="auditor-program-governance-local")
            entry = append_auditor_program_governance_receipt(
                chain,
                receipt,
                certification_kit=kit,
                standards_package=standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                root=ROOT,
            )

            self.assertEqual(AUDITOR_PROGRAM_GOVERNANCE_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("active", result.status)
            self.assertEqual(AUDITOR_PROGRAM_GOVERNANCE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["program_id"], entry["payload"]["program_id"])

    def test_auditor_program_governance_detects_source_hash_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, disclosure, standards, kit = self._sources(Path(tmp_dir))
            receipt = build_auditor_program_governance_receipt(
                kit,
                standards_package=standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                root=ROOT,
                issued_at="2026-07-14T00:00:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["source_artifacts"][0]["content_hash"] = "changed"

            result = verify_auditor_program_governance_receipt(
                tampered,
                certification_kit=kit,
                standards_package=standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("program_id" in error for error in result.errors))
            self.assertTrue(any("auditor_certification_kit content_hash mismatch" in error for error in result.errors))

    def test_auditor_program_governance_version_must_match_kit(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, disclosure, standards, kit = self._sources(Path(tmp_dir))
            receipt = build_auditor_program_governance_receipt(
                kit,
                standards_package=standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                root=ROOT,
                issued_at="2026-07-14T00:00:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["program"]["version"] = "9.9.9"
            tampered["governance_payload_hash"] = "changed"

            result = verify_auditor_program_governance_receipt(
                tampered,
                certification_kit=kit,
                standards_package=standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("version does not match" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
