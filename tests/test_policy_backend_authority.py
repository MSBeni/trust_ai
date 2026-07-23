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
from trustai.policy_backend_authority import (
    POLICY_BACKEND_AUTHORITY_ENTRY_TYPE,
    POLICY_BACKEND_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE,
    POLICY_BACKEND_AUTHORITY_EVIDENCE_BUNDLE_SCHEMA,
    POLICY_BACKEND_AUTHORITY_SCHEMA,
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    PRODUCTION_AUTHORITY_REQUIREMENTS,
    append_policy_backend_authority_dossier,
    append_policy_backend_authority_evidence_bundle,
    build_policy_backend_authority_dossier,
    build_policy_backend_authority_evidence_bundle,
    policy_backend_authority_evidence_from_bundle,
    verify_policy_backend_authority_dossier,
    verify_policy_backend_authority_evidence_bundle,
)
from trustai.policy_backend_service_bundle import build_policy_backend_service_bundle

from tests import test_policy_backend_provider_bundle as bundle_fixtures


ROOT = bundle_fixtures.ROOT


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class PolicyBackendAuthorityTests(unittest.TestCase):
    def _bundle(self, tmp: Path):
        helper = bundle_fixtures.PolicyBackendProviderBundleTests()
        sources, provider_bundle, paths = helper._bundle(tmp)
        service_bundle = build_policy_backend_service_bundle(
            sources["attestation"],
            sources["enforcement"],
            sources["policy"],
            sources["action"],
            sources["pack"],
            sources["policy_decision"],
            sources["policy_export"],
            policy_engine_receipt=sources["engine_receipt"],
            artifact_paths={
                "service_attestation": paths["service_attestation"],
                "enforcement": paths["enforcement"],
                "policy_pack": paths["policy_pack"],
                "runtime_action": paths["runtime_action"],
                "proof_pack": paths["proof_pack"],
                "policy_decision": paths["policy_decision"],
                "policy_export": paths["policy_export"],
                "policy_engine_receipt": paths["policy_engine_receipt"],
            },
            environment="aitrade-prod",
            reviewer_ref="oidc:auditor.example/policy-backend-reviewer",
            generated_at="2026-07-04T05:00:00Z",
        )
        return sources, provider_bundle, service_bundle, paths

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "opa-cedar-backend-fleet",
                "authority_kind": "hosted-service",
                "evidence_ref": "service:policy-backend-fleet/aitrade-prod",
                "evidence_hash": "sha256:policy-backend-fleet-authority",
                "description": "Hosted OPA/Cedar backend fleet deployment export.",
                "issuer": "TrustAI Cloud",
                "subject": "aitrade-prod policy backend fleet",
                "source_uri": "https://ops.example/trustai/policy-backend/aitrade-prod",
                "issued_at": "2026-07-04T00:00:00Z",
                "expires_at": "2026-07-11T00:00:00Z",
            },
            {
                "requirement_id": "scheduler-queue-lease",
                "authority_kind": "provider-api",
                "evidence_ref": "provider:redpanda-postgres/policy-backend/scheduler-queue-lease",
                "evidence_hash": "sha256:policy-backend-scheduler-authority",
                "description": "Provider scheduler, queue, lease, checkpoint, and cursor export.",
                "issuer": "Example Provider",
                "subject": "aitrade-prod policy backend scheduler",
                "source_uri": "https://provider.example/exports/policy-backend/scheduler",
                "issued_at": "2026-07-04T00:10:00Z",
                "expires_at": "2026-07-11T00:10:00Z",
            },
        ]

    def _complete_authority_evidence(self) -> list[dict]:
        rows = []
        for requirement in PRODUCTION_AUTHORITY_REQUIREMENTS:
            requirement_id = requirement["id"]
            authority_kind = requirement["authority_kinds"][0]
            rows.append(
                {
                    "requirement_id": requirement_id,
                    "authority_kind": authority_kind,
                    "evidence_ref": f"authority:policy-backend/{requirement_id}",
                    "evidence_hash": "sha256:" + content_hash(
                        {"policy_backend_authority": requirement_id, "authority_kind": authority_kind}
                    ),
                    "description": f"Policy backend production authority evidence for {requirement_id}.",
                    "issuer": "TrustAI policy backend authority exporter",
                    "subject": f"aitrade-prod policy backend {requirement_id}",
                    "source_uri": f"https://authority.trustai.example/policy-backend/{requirement_id}",
                    "issued_at": "2026-07-04T00:00:00Z",
                    "expires_at": "2026-08-04T00:00:00Z",
                }
            )
        return rows

    def _dossier(self, tmp: Path, *, mode: str = "provider-dossier", authority_evidence: list[dict] | None = None):
        sources, bundle, service_bundle, paths = self._bundle(tmp)
        dossier = build_policy_backend_authority_dossier(
            bundle,
            service_bundles=[service_bundle],
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:policy-backend-authority/lg-trace-001",
            authority_ref="authority:policy-backend/aitrade-prod",
            producer_ref="oidc:trustai.example/policy-backend-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-04T05:20:00Z",
        )
        return sources, bundle, service_bundle, paths, dossier

    def _resign_dossier(self, dossier: dict) -> None:
        body = without_keys(dossier, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        dossier["dossier_id"] = dossier_id
        dossier["signatures"] = [sign_value({"dossier_id": dossier_id, "policy_backend_authority": body})]

    def test_policy_backend_authority_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources, bundle, service_bundle, _, dossier = self._dossier(tmp)

            result = verify_policy_backend_authority_dossier(dossier, provider_bundle=bundle, service_bundles=[service_bundle])
            chain = EvidenceChain.load(tmp / "policy-backend-authority-chain.json", tenant_id="policy-backend-authority-test")
            entry = append_policy_backend_authority_dossier(chain, dossier, provider_bundle=bundle, service_bundles=[service_bundle])

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(POLICY_BACKEND_AUTHORITY_SCHEMA, dossier["schema"])
            self.assertEqual(2, result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
            self.assertEqual(2, result.fresh_evidence_count)
            self.assertTrue(any("missing for" in warning for warning in result.warnings), result.warnings)
            self.assertEqual(POLICY_BACKEND_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual(bundle["bundle_id"], entry["payload"]["provider_bundle_binding"]["bundle_id"])
            self.assertEqual(service_bundle["bundle_id"], entry["payload"]["service_bundle_bindings"][0]["bundle_id"])
            self.assertTrue(entry["payload"]["service_bundle_bindings"][0]["policy_engine_receipt_replayed"])
            self.assertEqual(dossier["authority_evidence"][0]["source_context"], entry["payload"]["authority_evidence"][0]["source_context"])
            self.assertEqual({"deferred": 1, "passed": 6}, entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)
            self.assertTrue(sources["chain"].verify_all().ok)

    def test_policy_backend_authority_requires_provider_bundle_replay(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, _, _, _, dossier = self._dossier(tmp)

            result = verify_policy_backend_authority_dossier(dossier)

            self.assertFalse(result.ok)
            self.assertTrue(any("provider bundle is required" in error for error in result.errors), result.errors)

    def test_policy_backend_authority_detects_bundle_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, bundle, service_bundle, _, dossier = self._dossier(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["source"]["provider"] = "other-provider"

            result = verify_policy_backend_authority_dossier(dossier, provider_bundle=tampered, service_bundles=[service_bundle])

            self.assertFalse(result.ok)
            self.assertTrue(any("provider_bundle_binding does not match" in error for error in result.errors), result.errors)

    def test_policy_backend_authority_detects_service_bundle_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, bundle, service_bundle, _, dossier = self._dossier(tmp)
            tampered = copy.deepcopy(service_bundle)
            tampered["source"]["backend_ref"] = "opa:other-backend"

            result = verify_policy_backend_authority_dossier(dossier, provider_bundle=bundle, service_bundles=[tampered])

            self.assertFalse(result.ok)
            self.assertTrue(any("service_bundle_bindings" in error or "service bundle source" in error for error in result.errors), result.errors)

    def test_policy_backend_authority_requires_complete_bindings_without_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, _, _, _, dossier = self._dossier(tmp)
            cases = [
                (["provider_bundle_binding"], "provider_record_roots", "provider_bundle_binding.provider_record_roots is required"),
                (["provider_bundle_binding"], "policy_engine_receipt_replayed", "provider_bundle_binding.policy_engine_receipt_replayed is required"),
                (["service_bundle_bindings", 0], "service_control_summary", "service_bundle_bindings.service_control_summary is required"),
            ]
            for path, field, expected_error in cases:
                with self.subTest(field=field):
                    tampered = copy.deepcopy(dossier)
                    target = tampered
                    for part in path:
                        target = target[part]
                    target.pop(field)
                    body = without_keys(tampered, "dossier_id", "signatures")
                    dossier_id = content_hash(body)
                    tampered["dossier_id"] = dossier_id
                    tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "policy_backend_authority": body})]

                    result = verify_policy_backend_authority_dossier(tampered)

                    self.assertFalse(result.ok)
                    self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_policy_backend_authority_rejects_resigned_authority_source_context_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, bundle, service_bundle, _, dossier = self._dossier(tmp)
            tampered = copy.deepcopy(dossier)
            item = tampered["authority_evidence"][0]
            item["source_context"]["provider_bundle_hash"] = "sha256:tampered-provider-bundle"
            item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
            self._resign_dossier(tampered)

            result = verify_policy_backend_authority_dossier(tampered, provider_bundle=bundle, service_bundles=[service_bundle])

            self.assertFalse(result.ok)
            self.assertNotIn("dossier_id does not match canonical policy backend authority body", result.errors)
            self.assertNotIn("policy backend authority signature verification failed", result.errors)
            self.assertNotIn("policy backend authority evidence_id does not match evidence body: opa-cedar-backend-fleet", result.errors)
            self.assertIn("policy backend authority source_context does not match source bindings: opa-cedar-backend-fleet", result.errors)

    def test_policy_backend_authority_rejects_resigned_control_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, bundle, service_bundle, _, dossier = self._dossier(tmp)
            tampered = copy.deepcopy(dossier)
            tampered["controls"][0]["status"] = "deferred"
            self._resign_dossier(tampered)

            result = verify_policy_backend_authority_dossier(tampered, provider_bundle=bundle, service_bundles=[service_bundle])

            self.assertFalse(result.ok)
            self.assertNotIn("dossier_id does not match canonical policy backend authority body", result.errors)
            self.assertNotIn("policy backend authority signature verification failed", result.errors)
            self.assertIn("policy backend authority controls do not match dossier body", result.errors)

    def test_policy_backend_authority_requires_freshness_when_strict(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence = [dict(self._authority_evidence()[0])]
            evidence[0].pop("issued_at")
            evidence[0].pop("expires_at")
            _, bundle, service_bundle, _, dossier = self._dossier(tmp, authority_evidence=evidence)

            result = verify_policy_backend_authority_dossier(dossier, provider_bundle=bundle, service_bundles=[service_bundle], require_fresh=True)

            self.assertFalse(result.ok)
            self.assertTrue(any("freshness metadata missing" in error for error in result.errors), result.errors)

    def test_policy_backend_authority_rejects_incomplete_production_claim(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, bundle, service_bundle, _, dossier = self._dossier(tmp, mode="production-dossier")

            result = verify_policy_backend_authority_dossier(dossier, provider_bundle=bundle, service_bundles=[service_bundle])

            self.assertFalse(result.ok)
            self.assertTrue(any("production-dossier mode requires" in error for error in result.errors), result.errors)

    def test_policy_backend_authority_evidence_bundle_drives_complete_production_dossier(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence_rows = self._complete_authority_evidence()
            bundle = build_policy_backend_authority_evidence_bundle(
                authority_evidence=evidence_rows,
                mode="production-export",
                environment="aitrade-prod",
                bundle_ref="bundle:policy-backend-authority/aitrade-prod",
                issuer_ref="oidc:trustai.example/policy-backend-authority-exporter",
                subject_ref="service:policy-backend/opa",
                authority_ref="authority:policy-backend/aitrade-prod",
                generated_at="2026-07-04T05:18:00Z",
            )

            bundle_result = verify_policy_backend_authority_evidence_bundle(
                bundle,
                require_complete=True,
                require_fresh=True,
                now="2026-07-04T05:19:00Z",
            )
            extracted_evidence = policy_backend_authority_evidence_from_bundle(
                bundle,
                require_complete=True,
                require_fresh=True,
                now="2026-07-04T05:19:00Z",
            )
            _, provider_bundle, service_bundle, _ = self._bundle(tmp)
            dossier = build_policy_backend_authority_dossier(
                provider_bundle,
                service_bundles=[service_bundle],
                mode="production-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:policy-backend-authority/lg-trace-001",
                authority_ref="authority:policy-backend/aitrade-prod",
                producer_ref="oidc:trustai.example/policy-backend-authority-worker",
                authority_evidence=extracted_evidence,
                generated_at="2026-07-04T05:20:00Z",
            )
            dossier_result = verify_policy_backend_authority_dossier(
                dossier,
                provider_bundle=provider_bundle,
                service_bundles=[service_bundle],
                require_complete=True,
                require_fresh=True,
                now="2026-07-04T05:21:00Z",
            )
            chain = EvidenceChain.load(tmp / "policy-backend-authority-chain.json", tenant_id="policy-backend-authority-test")
            bundle_entry = append_policy_backend_authority_evidence_bundle(
                chain,
                bundle,
                require_complete=True,
                require_fresh=True,
                now="2026-07-04T05:19:00Z",
            )
            dossier_entry = append_policy_backend_authority_dossier(
                chain,
                dossier,
                provider_bundle=provider_bundle,
                service_bundles=[service_bundle],
                require_complete=True,
                require_fresh=True,
                now="2026-07-04T05:21:00Z",
            )

            self.assertTrue(bundle_result.ok, bundle_result.errors)
            self.assertEqual(POLICY_BACKEND_AUTHORITY_EVIDENCE_BUNDLE_SCHEMA, bundle["schema"])
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), bundle_result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), len(extracted_evidence))
            self.assertTrue(dossier_result.ok, dossier_result.errors)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), dossier_result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), dossier_result.fresh_evidence_count)
            self.assertEqual({"passed": 5}, bundle_entry["payload"]["control_summary"])
            self.assertEqual({"passed": 7}, dossier_entry["payload"]["control_summary"])
            self.assertEqual(POLICY_BACKEND_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE, bundle_entry["entry_type"])
            self.assertEqual(POLICY_BACKEND_AUTHORITY_ENTRY_TYPE, dossier_entry["entry_type"])
            self.assertTrue(chain.verify_all().ok)

    def test_policy_backend_authority_evidence_bundle_rejects_placeholder_source_uri(self):
        evidence_rows = self._complete_authority_evidence()
        evidence_rows[0] = dict(evidence_rows[0])
        evidence_rows[0]["source_uri"] = "todo://collect-policy-backend-authority"
        bundle = build_policy_backend_authority_evidence_bundle(
            authority_evidence=evidence_rows,
            mode="production-export",
            environment="aitrade-prod",
            bundle_ref="bundle:policy-backend-authority/aitrade-prod",
            issuer_ref="oidc:trustai.example/policy-backend-authority-exporter",
            subject_ref="service:policy-backend/opa",
            authority_ref="authority:policy-backend/aitrade-prod",
            generated_at="2026-07-04T05:18:00Z",
        )

        result = verify_policy_backend_authority_evidence_bundle(
            bundle,
            require_complete=True,
            require_fresh=True,
            now="2026-07-04T05:19:00Z",
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("live source_uri" in error for error in result.errors), result.errors)

    def test_cli_policy_backend_authority_evidence_bundle_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, provider_bundle, service_bundle, _ = self._bundle(tmp)
            provider_bundle_path = tmp / "policy-backend-provider-export-bundle.json"
            service_bundle_path = tmp / "policy-backend-service-bundle.json"
            evidence_bundle_path = tmp / "policy-backend-authority-evidence-bundle.json"
            evidence_bundle_entry_path = tmp / "policy-backend-authority-evidence-bundle-entry.json"
            dossier_path = tmp / "policy-backend-authority.json"
            dossier_entry_path = tmp / "policy-backend-authority-entry.json"
            state_path = tmp / "policy-backend-authority-chain.json"
            _write_json(provider_bundle_path, provider_bundle)
            _write_json(service_bundle_path, service_bundle)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            evidence_args: list[str] = []
            for evidence in self._complete_authority_evidence():
                description = evidence["description"].rstrip(".")
                evidence_args.extend(
                    [
                        "--authority-evidence",
                        (
                            f"{evidence['requirement_id']},{evidence['authority_kind']},{evidence['evidence_ref']},"
                            f"{evidence['evidence_hash']},{description};issuer={evidence['issuer']};"
                            f"subject={evidence['subject']};source_uri={evidence['source_uri']};"
                            f"issued_at={evidence['issued_at']};expires_at={evidence['expires_at']}"
                        ),
                    ]
                )

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-authority-evidence-bundle",
                    "--mode",
                    "production-export",
                    "--environment",
                    "aitrade-prod",
                    "--bundle-ref",
                    "bundle:policy-backend-authority/aitrade-prod",
                    "--issuer-ref",
                    "oidc:trustai.example/policy-backend-authority-exporter",
                    "--subject-ref",
                    "service:policy-backend/opa",
                    "--authority-ref",
                    "authority:policy-backend/aitrade-prod",
                    "--generated-at",
                    "2026-07-04T05:18:00Z",
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-04T05:19:00Z",
                    "--out",
                    str(evidence_bundle_path),
                    *evidence_args,
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
                    "policy-backend-authority-evidence-bundle-verify",
                    str(evidence_bundle_path),
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-04T05:19:00Z",
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
                    "policy-backend-authority-evidence-bundle-append",
                    str(evidence_bundle_path),
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-04T05:19:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "policy-backend-authority-local",
                    "--out",
                    str(evidence_bundle_entry_path),
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
                    "policy-backend-authority",
                    str(provider_bundle_path),
                    "--service-bundle",
                    str(service_bundle_path),
                    "--mode",
                    "production-dossier",
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:policy-backend-authority/lg-trace-001",
                    "--authority-ref",
                    "authority:policy-backend/aitrade-prod",
                    "--producer-ref",
                    "oidc:trustai.example/policy-backend-authority-worker",
                    "--authority-evidence-bundle",
                    str(evidence_bundle_path),
                    "--generated-at",
                    "2026-07-04T05:20:00Z",
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-04T05:21:00Z",
                    "--out",
                    str(dossier_path),
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
                    "policy-backend-authority-append",
                    str(dossier_path),
                    "--provider-bundle",
                    str(provider_bundle_path),
                    "--service-bundle",
                    str(service_bundle_path),
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-04T05:21:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "policy-backend-authority-local",
                    "--out",
                    str(dossier_entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(evidence_bundle_path.exists())
            self.assertTrue(evidence_bundle_entry_path.exists())
            self.assertTrue(dossier_path.exists())
            self.assertTrue(dossier_entry_path.exists())

    def test_cli_policy_backend_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, bundle, service_bundle, _, _ = self._dossier(tmp)
            bundle_path = tmp / "policy-backend-provider-export-bundle.json"
            service_bundle_path = tmp / "policy-backend-service-bundle.json"
            dossier_path = tmp / "policy-backend-authority.json"
            entry_path = tmp / "policy-backend-authority-entry.json"
            state_path = tmp / "policy-backend-authority-chain.json"
            _write_json(bundle_path, bundle)
            _write_json(service_bundle_path, service_bundle)

            evidence_arg = (
                "opa-cedar-backend-fleet,hosted-service,service:policy-backend-fleet/aitrade-prod,"
                "sha256:policy-backend-fleet-authority,Hosted OPA/Cedar backend fleet deployment export;"
                "issuer=TrustAI Cloud;subject=aitrade-prod policy backend fleet;"
                "source_uri=https://ops.example/trustai/policy-backend/aitrade-prod;"
                "issued_at=2026-07-04T00:00:00Z;expires_at=2026-07-11T00:00:00Z"
            )
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-authority",
                    str(bundle_path),
                    "--service-bundle",
                    str(service_bundle_path),
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:policy-backend-authority/lg-trace-001",
                    "--authority-ref",
                    "authority:policy-backend/aitrade-prod",
                    "--producer-ref",
                    "oidc:trustai.example/policy-backend-authority-worker",
                    "--authority-evidence",
                    evidence_arg,
                    "--generated-at",
                    "2026-07-04T05:20:00Z",
                    "--out",
                    str(dossier_path),
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
                    "policy-backend-authority-verify",
                    str(dossier_path),
                    "--provider-bundle",
                    str(bundle_path),
                    "--service-bundle",
                    str(service_bundle_path),
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
                    "policy-backend-authority-append",
                    str(dossier_path),
                    "--provider-bundle",
                    str(bundle_path),
                    "--service-bundle",
                    str(service_bundle_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "policy-backend-authority-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(dossier_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
