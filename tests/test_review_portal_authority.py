import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.crypto import sign_value
from tests import test_review_portal_service as service_fixtures

from trustai.review_portal_authority import (
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    PRODUCTION_AUTHORITY_REQUIREMENTS,
    REVIEW_PORTAL_AUTHORITY_ENTRY_TYPE,
    REVIEW_PORTAL_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE,
    REVIEW_PORTAL_AUTHORITY_SCHEMA,
    append_review_portal_authority_dossier,
    append_review_portal_authority_evidence_bundle,
    build_review_portal_authority_dossier,
    build_review_portal_authority_evidence_bundle,
    review_portal_authority_evidence_from_bundle,
    verify_review_portal_authority_dossier,
    verify_review_portal_authority_evidence_bundle,
)

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class ReviewPortalAuthorityTests(unittest.TestCase):
    def _resign_dossier(self, dossier: dict) -> None:
        body = without_keys(dossier, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        dossier["dossier_id"] = dossier_id
        dossier["signatures"] = [sign_value({"dossier_id": dossier_id, "review_portal_authority": body})]

    def _resign_bundle(self, bundle: dict) -> None:
        body = without_keys(bundle, "bundle_id", "signatures")
        bundle_id = content_hash(body)
        bundle["bundle_id"] = bundle_id
        bundle["signatures"] = [sign_value({"bundle_id": bundle_id, "review_portal_authority_evidence_bundle": body})]

    def _authority_evidence_hash(self, requirement_id: str, authority_kind: str) -> str:
        return "sha256:" + content_hash({"review_portal_authority": requirement_id, "authority_kind": authority_kind})

    def _service(self):
        helper = service_fixtures.ReviewPortalServiceTests()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, pack, pack_path, disclosure, disclosure_path, view_path, frontend_bundle_path, _, receipt, _ = helper._fixtures(tmp)
            attestation = helper._attestation(receipt, pack, pack_path, disclosure, disclosure_path, view_path, frontend_bundle_path)
        return {}, attestation

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "hosted-portal-worker-fleet",
                "authority_kind": "hosted-service",
                "evidence_ref": "service:review-portal/regulator-prod",
                "evidence_hash": self._authority_evidence_hash("hosted-portal-worker-fleet", "hosted-service"),
                "description": "Hosted regulator review portal service export.",
                "issuer": "TrustAI Cloud",
                "subject": "aitrade-prod regulator review portal",
                "source_uri": "https://ops.example/trustai/review-portal/regulator-prod",
                "issued_at": "2026-07-08T06:10:00Z",
                "expires_at": "2026-07-15T06:10:00Z",
            },
            {
                "requirement_id": "production-identity-provider-sessions",
                "authority_kind": "identity-provider",
                "evidence_ref": "idp:review-portal/regulator-prod",
                "evidence_hash": self._authority_evidence_hash("production-identity-provider-sessions", "identity-provider"),
                "description": "Identity-provider authentication and session audit export for regulator reviewers.",
                "issuer": "Example IdP",
                "subject": "regulator reviewer sessions",
                "source_uri": "https://idp.example/audit/review-portal/regulator",
                "issued_at": "2026-07-08T06:11:00Z",
                "expires_at": "2026-07-15T06:11:00Z",
            },
        ]

    def _complete_authority_evidence(self) -> list[dict]:
        evidence = []
        for index, requirement in enumerate(PRODUCTION_AUTHORITY_REQUIREMENTS):
            requirement_id = requirement["id"]
            evidence.append(
                {
                    "requirement_id": requirement_id,
                    "authority_kind": requirement["authority_kinds"][0],
                    "evidence_ref": f"authority:review-portal/{requirement_id}",
                    "evidence_hash": self._authority_evidence_hash(requirement_id, requirement["authority_kinds"][0]),
                    "description": f"Retained production authority export for {requirement_id}.",
                    "issuer": "TrustAI Cloud",
                    "subject": "aitrade-prod regulator review portal",
                    "source_uri": f"https://authority.trustai.example/review-portal/{requirement_id}",
                    "issued_at": f"2026-07-08T06:{10 + index:02d}:00Z",
                    "expires_at": f"2026-07-15T06:{10 + index:02d}:00Z",
                }
            )
        return evidence

    def _dossier(self, *, mode: str = "provider-dossier", authority_evidence: list[dict] | None = None):
        sources, attestation = self._service()
        dossier = build_review_portal_authority_dossier(
            attestation,
            **sources,
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:review-portal-authority/regulator-prod",
            authority_ref="authority:review-portal/regulator-prod",
            producer_ref="oidc:trustai.example/review-portal-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-08T06:15:00Z",
        )
        return sources, attestation, dossier

    def test_review_portal_authority_verifies_and_appends(self):
        sources, attestation, dossier = self._dossier()

        result = verify_review_portal_authority_dossier(dossier, service_attestation=attestation, **sources)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="review-portal-authority-test")
            entry = append_review_portal_authority_dossier(chain, dossier, service_attestation=attestation, **sources)

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(REVIEW_PORTAL_AUTHORITY_SCHEMA, dossier["schema"])
        self.assertEqual(2, result.covered_count)
        self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
        self.assertEqual(2, result.fresh_evidence_count)
        self.assertTrue(any("missing for" in warning for warning in result.warnings), result.warnings)
        self.assertEqual(REVIEW_PORTAL_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
        self.assertEqual(attestation["attestation_id"], entry["payload"]["service_attestation_binding"]["attestation_id"])
        self.assertEqual({"deferred": 1, "passed": 5}, entry["payload"]["control_summary"])

    def test_review_portal_authority_normalizes_uppercase_evidence_hash(self):
        expected_hash = self._authority_evidence_hash("hosted-portal-worker-fleet", "hosted-service")
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0]["evidence_hash"] = "sha256:" + expected_hash.removeprefix("sha256:").upper()
        sources, attestation, dossier = self._dossier(authority_evidence=evidence)

        result = verify_review_portal_authority_dossier(dossier, service_attestation=attestation, **sources)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(expected_hash, dossier["authority_evidence"][0]["evidence_hash"])

    def test_review_portal_authority_evidence_bundle_normalizes_uppercase_evidence_hash(self):
        expected_hash = self._authority_evidence_hash("hosted-portal-worker-fleet", "hosted-service")
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0]["evidence_hash"] = "sha256:" + expected_hash.removeprefix("sha256:").upper()
        bundle = build_review_portal_authority_evidence_bundle(
            authority_evidence=evidence,
            mode="authority-export",
            environment="aitrade-prod",
            bundle_ref="bundle:review-portal-authority/regulator-prod",
            issuer_ref="issuer:trustai-cloud/review-portal",
            subject_ref="service:review-portal/regulator-prod",
            authority_ref="authority:review-portal/regulator-prod",
            generated_at="2026-07-08T06:14:00Z",
        )

        result = verify_review_portal_authority_evidence_bundle(bundle)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(expected_hash, bundle["authority_evidence"][0]["evidence_hash"])

    def test_review_portal_authority_rejects_resigned_malformed_evidence_hash(self):
        sources, attestation, dossier = self._dossier()
        tampered = copy.deepcopy(dossier)
        item = tampered["authority_evidence"][0]
        item["evidence_hash"] = "sha256:not-a-real-digest"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        self._resign_dossier(tampered)

        result = verify_review_portal_authority_dossier(tampered, service_attestation=attestation, **sources)

        self.assertFalse(result.ok)
        self.assertIn(
            "invalid review portal authority evidence: evidence_hash must contain a 64-character sha256 digest",
            result.errors,
        )
        self.assertNotIn("dossier_id does not match canonical review portal authority body", result.errors)
        self.assertNotIn("review portal authority signature verification failed", result.errors)
        self.assertNotIn("review portal authority evidence_id does not match evidence body: hosted-portal-worker-fleet", result.errors)

    def test_review_portal_authority_evidence_bundle_rejects_resigned_malformed_evidence_hash(self):
        evidence = self._authority_evidence()
        bundle = build_review_portal_authority_evidence_bundle(
            authority_evidence=evidence,
            mode="authority-export",
            environment="aitrade-prod",
            bundle_ref="bundle:review-portal-authority/regulator-prod",
            issuer_ref="issuer:trustai-cloud/review-portal",
            subject_ref="service:review-portal/regulator-prod",
            authority_ref="authority:review-portal/regulator-prod",
            generated_at="2026-07-08T06:14:00Z",
        )
        tampered = copy.deepcopy(bundle)
        item = tampered["authority_evidence"][0]
        item["evidence_hash"] = "sha256:not-a-real-digest"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        self._resign_bundle(tampered)

        result = verify_review_portal_authority_evidence_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertIn(
            "invalid review portal authority evidence bundle: evidence_hash must contain a 64-character sha256 digest",
            result.errors,
        )
        self.assertNotIn("bundle_id does not match canonical review portal authority evidence bundle body", result.errors)
        self.assertNotIn("review portal authority evidence bundle signature verification failed", result.errors)
        self.assertNotIn("review portal authority evidence bundle evidence_id does not match evidence body: hosted-portal-worker-fleet", result.errors)

    def test_review_portal_authority_detects_service_tamper(self):
        sources, attestation, dossier = self._dossier()
        tampered = copy.deepcopy(attestation)
        tampered["service"]["service_ref"] = "service:review-portal/tampered"

        result = verify_review_portal_authority_dossier(dossier, service_attestation=tampered, **sources)

        self.assertFalse(result.ok)
        self.assertTrue(any("service_attestation_binding does not match" in error for error in result.errors), result.errors)

    def test_review_portal_authority_rejects_resigned_authority_context_mismatch(self):
        sources, attestation, dossier = self._dossier()
        tampered = copy.deepcopy(dossier)
        item = tampered["authority_evidence"][0]
        item["service_context"]["service_ref"] = "review-portal:other"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        self._resign_dossier(tampered)

        result = verify_review_portal_authority_dossier(tampered, service_attestation=attestation, **sources)

        self.assertFalse(result.ok)
        self.assertNotIn("dossier_id does not match canonical review portal authority body", result.errors)
        self.assertNotIn("review portal authority signature verification failed", result.errors)
        self.assertNotIn("review portal authority evidence_id does not match evidence body: hosted-portal-worker-fleet", result.errors)
        self.assertIn("review portal authority service_context does not match service attestation binding: hosted-portal-worker-fleet", result.errors)

    def test_review_portal_authority_detects_control_tamper(self):
        sources, attestation, dossier = self._dossier()
        tampered = copy.deepcopy(dossier)
        tampered["controls"][0]["status"] = "deferred"

        result = verify_review_portal_authority_dossier(tampered, service_attestation=attestation, **sources)

        self.assertFalse(result.ok)
        self.assertTrue(any("controls do not match" in error for error in result.errors), result.errors)

    def test_review_portal_authority_requires_complete_binding_without_sources(self):
        _, _, dossier = self._dossier()
        cases = [
            ("attestation_schema", "service_attestation_binding.attestation_schema is required"),
            ("source_schemas", "service_attestation_binding.source_schemas is required"),
            ("evidence_refs", "service_attestation_binding.evidence_refs is required"),
        ]
        for field, expected_error in cases:
            with self.subTest(field=field):
                tampered = copy.deepcopy(dossier)
                tampered["service_attestation_binding"].pop(field)
                body = without_keys(tampered, "dossier_id", "signatures")
                dossier_id = content_hash(body)
                tampered["dossier_id"] = dossier_id
                tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "review_portal_authority": body})]

                result = verify_review_portal_authority_dossier(tampered)

                self.assertFalse(result.ok)
                self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_review_portal_authority_requires_frontend_bundle_artifact_binding(self):
        sources, attestation, dossier = self._dossier()
        tampered = copy.deepcopy(dossier)
        tampered["service_attestation_binding"].pop("frontend_bundle_artifact_hash")
        body = without_keys(tampered, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        tampered["dossier_id"] = dossier_id
        tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "review_portal_authority": body})]

        result = verify_review_portal_authority_dossier(tampered, service_attestation=attestation, **sources)

        self.assertFalse(result.ok)
        self.assertTrue(any("frontend_bundle_artifact_hash is required" in error for error in result.errors), result.errors)

    def test_review_portal_authority_requires_freshness_when_strict(self):
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0].pop("issued_at")
        evidence[0].pop("expires_at")
        sources, attestation, dossier = self._dossier(authority_evidence=evidence)

        result = verify_review_portal_authority_dossier(dossier, service_attestation=attestation, **sources, require_fresh=True)

        self.assertFalse(result.ok)
        self.assertTrue(any("freshness metadata missing" in error for error in result.errors), result.errors)

    def test_review_portal_authority_rejects_incomplete_production_claim(self):
        sources, attestation, dossier = self._dossier(mode="production-dossier")

        result = verify_review_portal_authority_dossier(dossier, service_attestation=attestation, **sources)

        self.assertFalse(result.ok)
        self.assertTrue(any("production-dossier mode requires" in error for error in result.errors), result.errors)

    def test_review_portal_authority_evidence_bundle_drives_complete_production_dossier(self):
        evidence = self._complete_authority_evidence()
        bundle = build_review_portal_authority_evidence_bundle(
            authority_evidence=evidence,
            mode="production-export",
            environment="aitrade-prod",
            bundle_ref="bundle:review-portal-authority/regulator-prod",
            issuer_ref="issuer:trustai-cloud/review-portal",
            subject_ref="service:review-portal/regulator-prod",
            authority_ref="authority:review-portal/regulator-prod",
            generated_at="2026-07-08T06:30:00Z",
        )

        bundle_result = verify_review_portal_authority_evidence_bundle(
            bundle, require_complete=True, require_fresh=True, now="2026-07-08T06:30:00Z"
        )
        self.assertTrue(bundle_result.ok, bundle_result.errors)
        self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), bundle_result.covered_count)

        sources, attestation = self._service()
        dossier = build_review_portal_authority_dossier(
            attestation,
            **sources,
            mode="production-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:review-portal-authority/regulator-prod",
            authority_ref="authority:review-portal/regulator-prod",
            producer_ref="oidc:trustai.example/review-portal-authority-worker",
            authority_evidence=review_portal_authority_evidence_from_bundle(
                bundle, require_complete=True, require_fresh=True, now="2026-07-08T06:30:00Z"
            ),
            generated_at="2026-07-08T06:30:00Z",
        )
        dossier_result = verify_review_portal_authority_dossier(
            dossier, service_attestation=attestation, **sources, require_complete=True, require_fresh=True, now="2026-07-08T06:30:00Z"
        )
        self.assertTrue(dossier_result.ok, dossier_result.errors)
        self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), dossier_result.covered_count)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="review-portal-authority-bundle-test")
            entry = append_review_portal_authority_evidence_bundle(
                chain, bundle, require_complete=True, require_fresh=True, now="2026-07-08T06:30:00Z"
            )
            self.assertTrue(chain.verify_all().ok)

        self.assertEqual(REVIEW_PORTAL_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
        self.assertEqual({"passed": 5}, entry["payload"]["control_summary"])
        self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), len(entry["payload"]["authority_evidence"]))

    def test_review_portal_authority_evidence_bundle_rejects_placeholder_source_uri(self):
        evidence = self._complete_authority_evidence()
        evidence[0]["source_uri"] = "todo://collect-review-portal-authority-source"
        bundle = build_review_portal_authority_evidence_bundle(
            authority_evidence=evidence,
            mode="production-export",
            environment="aitrade-prod",
            bundle_ref="bundle:review-portal-authority/regulator-prod",
            issuer_ref="issuer:trustai-cloud/review-portal",
            subject_ref="service:review-portal/regulator-prod",
            authority_ref="authority:review-portal/regulator-prod",
            generated_at="2026-07-08T06:30:00Z",
        )

        result = verify_review_portal_authority_evidence_bundle(
            bundle, require_complete=True, require_fresh=True, now="2026-07-08T06:30:00Z"
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("live source_uri values" in error for error in result.errors), result.errors)

    def test_cli_review_portal_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources, attestation, _ = self._dossier()
            service_path = tmp / "review-portal-service-attestation.json"
            bundle_path = tmp / "review-portal-authority-evidence-bundle.json"
            bundle_entry_path = tmp / "review-portal-authority-evidence-bundle-entry.json"
            dossier_path = tmp / "review-portal-authority.json"
            entry_path = tmp / "review-portal-authority-entry.json"
            state_path = tmp / "review-portal-authority-chain.json"
            _write_json(service_path, attestation)

            source_args: list[str] = []
            expected_hash = self._authority_evidence_hash("hosted-portal-worker-fleet", "hosted-service")
            evidence_arg = (
                "hosted-portal-worker-fleet,hosted-service,service:review-portal/regulator-prod,"
                f"{expected_hash},Hosted regulator review portal service export;"
                "issuer=TrustAI Cloud;subject=aitrade-prod regulator review portal;"
                "source_uri=https://ops.example/trustai/review-portal/regulator-prod;"
                "issued_at=2026-07-08T06:10:00Z;expires_at=2026-07-15T06:10:00Z"
            )
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "review-portal-authority-evidence-bundle",
                    "--environment",
                    "aitrade-prod",
                    "--bundle-ref",
                    "bundle:review-portal-authority/regulator-prod",
                    "--issuer-ref",
                    "issuer:trustai-cloud/review-portal",
                    "--subject-ref",
                    "service:review-portal/regulator-prod",
                    "--authority-ref",
                    "authority:review-portal/regulator-prod",
                    "--authority-evidence",
                    evidence_arg,
                    "--generated-at",
                    "2026-07-08T06:14:00Z",
                    "--out",
                    str(bundle_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "review-portal-authority-evidence-bundle-verify", str(bundle_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "review-portal-authority-evidence-bundle-append",
                    str(bundle_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "review-portal-authority-local",
                    "--out",
                    str(bundle_entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "review-portal-authority",
                    str(service_path),
                    *source_args,
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:review-portal-authority/regulator-prod",
                    "--authority-ref",
                    "authority:review-portal/regulator-prod",
                    "--producer-ref",
                    "oidc:trustai.example/review-portal-authority-worker",
                    "--authority-evidence-bundle",
                    str(bundle_path),
                    "--generated-at",
                    "2026-07-08T06:15:00Z",
                    "--out",
                    str(dossier_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "review-portal-authority-verify", str(dossier_path), str(service_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "review-portal-authority-append",
                    str(dossier_path),
                    str(service_path),
                    *source_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "review-portal-authority-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(bundle_path.exists())
            self.assertTrue(bundle_entry_path.exists())
            self.assertTrue(dossier_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
