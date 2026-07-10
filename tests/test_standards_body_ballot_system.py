import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.standards import build_standards_submission
from trustai.standards_body_ballot import build_standards_body_ballot_receipt
from trustai.standards_body_ballot_system import (
    STANDARDS_BODY_BALLOT_SYSTEM_ENTRY_TYPE,
    STANDARDS_BODY_BALLOT_SYSTEM_SCHEMA,
    append_standards_body_ballot_system_receipt,
    build_standards_body_ballot_system_receipt,
    verify_standards_body_ballot_system_receipt,
)
from trustai.standards_body_status import build_standards_body_status_receipt
from trustai.standards_body_submission import build_standards_body_submission_receipt
from trustai.verifier import load_proof_pack
from trustai.verifier_conformance import build_verifier_conformance_report
from trustai.verifier_release import build_verifier_release_manifest

from tests import test_framework_runtime_service_authority_recorded_export_provider_bundle as provider_bundle_fixtures


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "artifacts" / "aitrade-proof-pack.json"


class StandardsBodyBallotSystemTests(unittest.TestCase):
    def _sources(self, *, ballot_outcome: str = "accepted", provider_bundle: dict | None = None):
        pack = load_proof_pack(PACK)
        standards = build_standards_submission(ROOT)
        conformance = build_verifier_conformance_report(pack, provider_bundle=provider_bundle)
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
            ballot_opened_at="2026-07-19T00:00:00Z",
            actor_ref="oidc:standards.example/chair-1",
            actor_role="working-group-chair",
            decided_at="2026-07-19T00:00:00Z",
            effective_at="2026-07-19T01:00:00Z",
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
            effective_at="2026-07-25T03:00:00Z",
            minutes_ref="minutes:trustai-wg/2026-07-25",
            actor_ref="oidc:standards.example/chair-1",
            actor_role="working-group-chair",
            evidence_refs=["minutes:trustai-wg/2026-07-25"],
        )
        return standards, conformance, release, submission, status, ballot

    def _provider_bundle(self, tmp: Path):
        helper = provider_bundle_fixtures.FrameworkRuntimeServiceAuthorityRecordedExportProviderBundleTests()
        bundle, *_ = helper._bundle(tmp)
        return bundle

    def test_standards_body_ballot_system_verifies_and_appends(self):
        standards, conformance, release, submission, status, ballot = self._sources()
        receipt = build_standards_body_ballot_system_receipt(
            ballot,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            ballot_system="LF TrustAI Ballot System",
            endpoint_base="https://ballots.example",
            credential_ref="env:STANDARDS_BALLOT_TOKEN",
            mode="authenticated-export",
            request_method="GET",
            export_ref="LF-TRUSTAI-BALLOT-2026-001:export",
            export_url="https://ballots.example/exports/LF-TRUSTAI-BALLOT-2026-001",
            export_generated_at="2026-07-25T03:30:00Z",
            actor_ref="oidc:standards.example/ballot-system",
            response_status=200,
            response_body={"export_ref": "LF-TRUSTAI-BALLOT-2026-001:export", "status": "published"},
            evidence_refs=["ballot-system:LF-TRUSTAI-BALLOT-2026-001"],
            exported_at="2026-07-25T04:00:00Z",
        )

        result = verify_standards_body_ballot_system_receipt(
            receipt,
            ballot_receipt=ballot,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "standards-body-ballot-system-chain.json", tenant_id="standards-body-ballot-system-local")
            entry = append_standards_body_ballot_system_receipt(
                chain,
                receipt,
                ballot_receipt=ballot,
                submission_receipt=submission,
                status_receipt=status,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

        self.assertEqual(STANDARDS_BODY_BALLOT_SYSTEM_SCHEMA, receipt["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual("authenticated-export", result.mode)
        self.assertEqual("LF-TRUSTAI-BALLOT-2026-001:export", result.export_ref)
        self.assertEqual(["proof-pack"], receipt["ballot"]["conformance_report"]["targets"])
        self.assertEqual(["proof-pack"], receipt["request"]["body"]["conformance_targets"])
        self.assertEqual(["proof-pack"], receipt["export"]["payload"]["submission"]["conformance_report"]["targets"])
        self.assertEqual(STANDARDS_BODY_BALLOT_SYSTEM_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["integration_id"], entry["payload"]["integration_id"])

    def test_standards_body_ballot_system_preserves_provider_bundle_conformance_scope(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            provider_bundle = self._provider_bundle(Path(tmp_dir))
            standards, conformance, release, submission, status, ballot = self._sources(provider_bundle=provider_bundle)
            receipt = build_standards_body_ballot_system_receipt(
                ballot,
                submission_receipt=submission,
                status_receipt=status,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
                exported_at="2026-07-25T04:00:00Z",
            )
            result = verify_standards_body_ballot_system_receipt(
                receipt,
                ballot_receipt=ballot,
                submission_receipt=submission,
                status_receipt=status,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

        expected_targets = ["framework-runtime-service-authority-recorded-export-provider-bundle", "proof-pack"]
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(expected_targets, receipt["ballot"]["conformance_report"]["targets"])
        self.assertEqual(expected_targets, receipt["request"]["body"]["conformance_targets"])
        self.assertEqual(expected_targets, receipt["export"]["payload"]["submission"]["conformance_report"]["targets"])
        self.assertEqual(provider_bundle["bundle_id"], receipt["ballot"]["conformance_report"]["source_provider_bundle"]["bundle_id"])
        self.assertEqual(provider_bundle["bundle_id"], receipt["request"]["body"]["source_provider_bundle"]["bundle_id"])

    def test_standards_body_ballot_system_detects_ballot_hash_tamper(self):
        standards, conformance, release, submission, status, ballot = self._sources()
        receipt = build_standards_body_ballot_system_receipt(
            ballot,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            exported_at="2026-07-25T04:00:00Z",
        )
        tampered = copy.deepcopy(receipt)
        tampered["source_artifacts"][0]["content_hash"] = "changed"

        result = verify_standards_body_ballot_system_receipt(
            tampered,
            ballot_receipt=ballot,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("integration_id" in error for error in result.errors))
        self.assertTrue(any("standards_body_ballot_receipt content_hash mismatch" in error for error in result.errors))

    def test_standards_body_ballot_system_requires_accepted_ballot(self):
        standards, conformance, release, submission, status, ballot = self._sources(ballot_outcome="rejected")

        with self.assertRaisesRegex(ValueError, "requires an accepted"):
            build_standards_body_ballot_system_receipt(
                ballot,
                submission_receipt=submission,
                status_receipt=status,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
                exported_at="2026-07-25T04:00:00Z",
            )


if __name__ == "__main__":
    unittest.main()
