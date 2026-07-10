import copy
import tempfile
import unittest
from pathlib import Path

from tests import test_standards_body_ballot_system
from trustai.chain import EvidenceChain
from trustai.standards_body_ballot_system import build_standards_body_ballot_system_receipt
from trustai.standards_body_provider_posting import (
    STANDARDS_BODY_PROVIDER_POSTING_ENTRY_TYPE,
    STANDARDS_BODY_PROVIDER_POSTING_SCHEMA,
    append_standards_body_provider_posting_receipt,
    build_standards_body_provider_posting_receipt,
    verify_standards_body_provider_posting_receipt,
)


ROOT = Path(__file__).resolve().parents[1]


class StandardsBodyProviderPostingTests(unittest.TestCase):
    def _sources(self, *, provider_bundle: dict | None = None):
        standards, conformance, release, submission, status, ballot = test_standards_body_ballot_system.StandardsBodyBallotSystemTests()._sources(provider_bundle=provider_bundle)
        ballot_system = build_standards_body_ballot_system_receipt(
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
        return standards, conformance, release, submission, status, ballot, ballot_system

    def test_standards_body_provider_posting_verifies_and_appends(self):
        standards, conformance, release, submission, status, ballot, ballot_system = self._sources()
        receipt = build_standards_body_provider_posting_receipt(
            ballot_system,
            ballot_receipt=ballot,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            provider="LF Standards Posting API",
            endpoint_base="https://standards.example",
            credential_ref="env:STANDARDS_API_TOKEN",
            credential_exchange_url="https://standards.example/oauth/token",
            credential_audience="standards-api",
            credential_scope=["ballot:write", "export:publish"],
            mode="provider-posted",
            request_path="/api/v1/ballot-exports",
            posting_ref="LF-TRUSTAI-BALLOT-2026-001:provider-post",
            posting_url="https://standards.example/api/v1/ballot-exports/LF-TRUSTAI-BALLOT-2026-001",
            actor_ref="oidc:standards.example/ballot-system",
            credential_response_status=200,
            credential_response_body={"token_type": "Bearer", "scope": "ballot:write export:publish"},
            response_status=201,
            response_body={"posting_ref": "LF-TRUSTAI-BALLOT-2026-001:provider-post", "status": "published"},
            evidence_refs=["provider-post:LF-TRUSTAI-BALLOT-2026-001"],
            posted_at="2026-07-25T05:00:00Z",
        )

        result = verify_standards_body_provider_posting_receipt(
            receipt,
            ballot_system_receipt=ballot_system,
            ballot_receipt=ballot,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "standards-body-provider-posting-chain.json", tenant_id="standards-body-provider-posting-local")
            entry = append_standards_body_provider_posting_receipt(
                chain,
                receipt,
                ballot_system_receipt=ballot_system,
                ballot_receipt=ballot,
                submission_receipt=submission,
                status_receipt=status,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

        self.assertEqual(STANDARDS_BODY_PROVIDER_POSTING_SCHEMA, receipt["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual("provider-posted", result.mode)
        self.assertEqual(["proof-pack"], receipt["source"]["ballot"]["conformance_report"]["targets"])
        self.assertEqual(["proof-pack"], receipt["request"]["body"]["conformance_targets"])
        self.assertEqual(STANDARDS_BODY_PROVIDER_POSTING_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["posting_id"], entry["payload"]["posting_id"])

    def test_standards_body_provider_posting_preserves_provider_bundle_conformance_scope(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            provider_bundle = test_standards_body_ballot_system.StandardsBodyBallotSystemTests()._provider_bundle(Path(tmp_dir))
            standards, conformance, release, submission, status, ballot, ballot_system = self._sources(provider_bundle=provider_bundle)
            receipt = build_standards_body_provider_posting_receipt(
                ballot_system,
                ballot_receipt=ballot,
                submission_receipt=submission,
                status_receipt=status,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
                posted_at="2026-07-25T05:00:00Z",
            )
            result = verify_standards_body_provider_posting_receipt(
                receipt,
                ballot_system_receipt=ballot_system,
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
        self.assertEqual(expected_targets, receipt["source"]["ballot"]["conformance_report"]["targets"])
        self.assertEqual(expected_targets, receipt["request"]["body"]["conformance_targets"])
        self.assertEqual(provider_bundle["bundle_id"], receipt["source"]["ballot"]["conformance_report"]["source_provider_bundle"]["bundle_id"])
        self.assertEqual(provider_bundle["bundle_id"], receipt["request"]["body"]["source_provider_bundle"]["bundle_id"])

    def test_standards_body_provider_posting_detects_source_hash_tamper(self):
        standards, conformance, release, submission, status, ballot, ballot_system = self._sources()
        receipt = build_standards_body_provider_posting_receipt(
            ballot_system,
            ballot_receipt=ballot,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            posted_at="2026-07-25T05:00:00Z",
        )
        tampered = copy.deepcopy(receipt)
        tampered["source_artifacts"][0]["content_hash"] = "changed"

        result = verify_standards_body_provider_posting_receipt(
            tampered,
            ballot_system_receipt=ballot_system,
            ballot_receipt=ballot,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("posting_id" in error for error in result.errors))
        self.assertTrue(any("standards_body_ballot_system_receipt content_hash mismatch" in error for error in result.errors))

    def test_standards_body_provider_posting_rejects_failed_provider_response(self):
        standards, conformance, release, submission, status, ballot, ballot_system = self._sources()
        receipt = build_standards_body_provider_posting_receipt(
            ballot_system,
            ballot_receipt=ballot,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            mode="provider-posted",
            actor_ref="oidc:standards.example/ballot-system",
            credential_response_status=200,
            credential_response_body={"token_type": "Bearer"},
            response_status=503,
            response_body={"status": "unavailable"},
            posted_at="2026-07-25T05:00:00Z",
        )

        result = verify_standards_body_provider_posting_receipt(
            receipt,
            ballot_system_receipt=ballot_system,
            ballot_receipt=ballot,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("accepted provider response" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
