import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.policy import append_policy_decision, load_policy_pack
from trustai.policy_backend_enforcement import build_policy_backend_enforcement_receipt, write_policy_backend_enforcement_receipt
from trustai.policy_backend_service import build_policy_backend_service_attestation, write_policy_backend_service_attestation
from trustai.policy_backend_service_bundle import (
    POLICY_BACKEND_SERVICE_BUNDLE_ENTRY_TYPE,
    POLICY_BACKEND_SERVICE_BUNDLE_SCHEMA,
    append_policy_backend_service_bundle,
    build_policy_backend_service_bundle,
    extract_policy_backend_service_bundle_sources,
    verify_policy_backend_service_bundle,
    write_policy_backend_service_bundle,
    write_policy_backend_service_bundle_markdown,
)
from trustai.policy_engine import build_policy_engine_receipt, write_policy_engine_receipt
from trustai.policy_export import export_policy_pack, write_policy_export
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
POLICY = ROOT / "examples" / "aitrade" / "policy-pack.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class PolicyBackendServiceBundleTests(unittest.TestCase):
    def _fixtures(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="policy-backend-service-bundle-test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        shadow = load_shadow_replay(SHADOW)
        append_shadow_replay(chain, contract, shadow)
        append_soak_report(chain, contract, load_soak_window(SOAK))
        action = load_action(ACTION)
        append_runtime_attestation(chain, contract, action)
        eval_entry, gate_entry, decision = append_eval_and_gate(
            chain,
            contract,
            shadow_replay_to_eval_results(contract, shadow),
        )
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
        policy = load_policy_pack(POLICY)
        policy_decision = append_policy_decision(
            chain,
            policy,
            action,
            proof_pack=pack,
            now="2026-07-04T02:00:00Z",
        )
        policy_export = export_policy_pack(policy)
        engine_receipt = build_policy_engine_receipt(
            policy,
            action,
            pack,
            policy_decision,
            policy_export=policy_export,
            engine="opa",
            evaluated_at="2026-07-04T02:00:00Z",
        )
        enforcement = build_policy_backend_enforcement_receipt(
            policy,
            action,
            pack,
            policy_decision,
            policy_export=policy_export,
            policy_engine_receipt=engine_receipt,
            backend_ref="opa:trustai-runtime:prod",
            engine="opa",
            endpoint_url="https://opa.example/v1/data/trustai/runtime/allow",
            credential_ref="env:OPA_BACKEND_TOKEN",
            request_hash="sha256:policy-backend-request",
            response_status=200,
            response_hash="sha256:policy-backend-response",
            actor_ref="oidc:trustai.example/runtime-policy",
            latency_ms=18,
            evidence_refs=["evidence:policy-backend/opa-runtime"],
            mode="hosted-backend",
            environment="local",
            enforced_at="2026-07-04T02:00:01Z",
        )
        attestation = build_policy_backend_service_attestation(
            enforcement,
            policy_pack=policy,
            action=action,
            proof_pack=pack,
            decision=policy_decision,
            policy_export=policy_export,
            policy_engine_receipt=engine_receipt,
            environment="aitrade-prod",
            service_ref="policy-backend:trustai/opa-prod",
            service_version="0.1.0",
            engine="opa",
            backend_ref="opa:trustai-runtime:prod",
            endpoint_url="https://opa.example/v1/data/trustai/runtime/allow",
            service_image="ghcr.io/trustai/policy-backend:0.1.0",
            service_image_digest="sha256:trustai-policy-backend-image",
            service_binary_hash="sha256:trustai-policy-backend-binary",
            replicas_min=3,
            replicas_max=9,
            availability_zones=["us-east-1a", "us-east-1b", "us-east-1c"],
            mtls_policy_ref="policy:policy-backend/mtls-required-v0.1",
            auth_policy_ref="policy:policy-backend/oidc-authz-v0.1",
            tenant_isolation_ref="tenant-isolation:aitrade/policy-backend",
            policy_sync_ref="policy-sync:trustai/runtime-policy-bundle",
            admission_policy_ref="admission:policy-backend/signed-bundles-only",
            rate_limit_policy_ref="rate-limit:policy-backend/aitrade",
            circuit_breaker_ref="circuit-breaker:policy-backend/opa",
            cache_store_ref="redis:policy-backend/decision-cache",
            network_policy_ref="netpol:policy-backend/deny-by-default",
            egress_policy_ref="egress:policy-backend/kms-tsa-only",
            decision_log_ref="decision-log:policy-backend/opa",
            decision_log_root="sha256:policy-backend-decision-log-root",
            decision_log_retention_days=2555,
            audit_log_ref="audit-log:policy-backend/service",
            audit_log_root="sha256:policy-backend-service-audit-root",
            retention_until="2033-07-04T00:00:00Z",
            actor_ref="oidc:trustai.example/policy-backend-operator",
            credential_ref="env:POLICY_BACKEND_SERVICE_TOKEN",
            evidence_refs=["evidence:policy-backend/service"],
            attested_at="2026-07-04T04:02:00Z",
        )
        return chain, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement, attestation

    def _write_sources(self, tmp: Path, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement, attestation):
        paths = {
            "service_attestation": tmp / "policy-backend-service-attestation.json",
            "enforcement": tmp / "policy-backend-enforcement.json",
            "policy_pack": tmp / "policy-pack.json",
            "runtime_action": tmp / "runtime-action.json",
            "proof_pack": tmp / "pack.json",
            "policy_decision": tmp / "policy-decision.json",
            "policy_export": tmp / "policy-export.json",
            "policy_engine_receipt": tmp / "policy-engine-receipt.json",
        }
        write_policy_backend_service_attestation(paths["service_attestation"], attestation)
        write_policy_backend_enforcement_receipt(paths["enforcement"], enforcement)
        _write_json(paths["policy_pack"], policy)
        _write_json(paths["runtime_action"], action)
        _write_json(paths["proof_pack"], pack)
        _write_json(paths["policy_decision"], policy_decision)
        write_policy_export(paths["policy_export"], policy_export)
        write_policy_engine_receipt(paths["policy_engine_receipt"], engine_receipt)
        return paths

    def _bundle(self, tmp: Path):
        chain, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement, attestation = self._fixtures(tmp)
        paths = self._write_sources(tmp, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement, attestation)
        bundle = build_policy_backend_service_bundle(
            attestation,
            enforcement,
            policy,
            action,
            pack,
            policy_decision,
            policy_export,
            policy_engine_receipt=engine_receipt,
            artifact_paths=paths,
            environment="aitrade-prod",
            reviewer_ref="oidc:auditor.example/policy-backend-reviewer",
            generated_at="2026-07-04T05:00:00Z",
        )
        return chain, bundle, paths

    def test_policy_backend_service_bundle_verifies_appends_and_extracts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain, bundle, _ = self._bundle(tmp)

            result = verify_policy_backend_service_bundle(bundle)
            entry = append_policy_backend_service_bundle(chain, bundle)
            out_dir = tmp / "extracted"
            extracted = extract_policy_backend_service_bundle_sources(bundle, out_dir)
            markdown_path = tmp / "bundle.md"
            write_policy_backend_service_bundle_markdown(markdown_path, bundle)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(POLICY_BACKEND_SERVICE_BUNDLE_SCHEMA, bundle["schema"])
            self.assertEqual("offline-review", bundle["mode"])
            self.assertEqual(8, bundle["summary"]["source_artifact_count"])
            self.assertTrue(bundle["summary"]["policy_engine_receipt_replayed"])
            self.assertEqual(POLICY_BACKEND_SERVICE_BUNDLE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
            self.assertEqual(8, len(extracted))
            self.assertTrue((out_dir / "service_attestation.json").exists())
            self.assertIn("TrustAI Policy Backend Service Bundle", markdown_path.read_text(encoding="utf-8"))
            self.assertTrue(chain.verify_all().ok)

    def test_policy_backend_service_bundle_rejects_artifact_source_swap(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement, attestation = self._fixtures(tmp)
            paths = self._write_sources(tmp, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement, attestation)
            tampered_export = copy.deepcopy(policy_export)
            tampered_export["policy_pack_version"] = "tampered"
            _write_json(paths["policy_export"], tampered_export)

            with self.assertRaisesRegex(ValueError, "artifact content hash mismatch: policy_export"):
                build_policy_backend_service_bundle(
                    attestation,
                    enforcement,
                    policy,
                    action,
                    pack,
                    policy_decision,
                    policy_export,
                    policy_engine_receipt=engine_receipt,
                    artifact_paths=paths,
                    reviewer_ref="oidc:auditor.example/policy-backend-reviewer",
                )

    def test_policy_backend_service_bundle_rejects_raw_secret(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, bundle, _ = self._bundle(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["enforcement"]["credential"] = "raw-token"

            result = verify_policy_backend_service_bundle(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_policy_backend_service_bundle_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement, attestation = self._fixtures(tmp)
            paths = self._write_sources(tmp, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement, attestation)
            bundle_path = tmp / "policy-backend-service-bundle.json"
            markdown_path = tmp / "policy-backend-service-bundle.md"
            rendered_path = tmp / "rendered.md"
            extracted_dir = tmp / "sources"
            entry_path = tmp / "policy-backend-service-bundle-entry.json"
            state_path = tmp / "policy-backend-service-bundle-chain.json"

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            common = [
                str(paths["service_attestation"]),
                str(paths["enforcement"]),
                str(paths["policy_pack"]),
                str(paths["runtime_action"]),
                "--pack",
                str(paths["proof_pack"]),
                "--decision",
                str(paths["policy_decision"]),
                "--export",
                str(paths["policy_export"]),
                "--policy-engine-receipt",
                str(paths["policy_engine_receipt"]),
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-service-bundle",
                    *common,
                    "--environment",
                    "aitrade-prod",
                    "--reviewer-ref",
                    "oidc:auditor.example/policy-backend-reviewer",
                    "--generated-at",
                    "2026-07-04T05:00:00Z",
                    "--out",
                    str(bundle_path),
                    "--markdown",
                    str(markdown_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run([sys.executable, "-m", "trustai", "policy-backend-service-bundle-verify", str(bundle_path)], cwd=ROOT, env=env, check=True)
            subprocess.run(
                [sys.executable, "-m", "trustai", "policy-backend-service-bundle-render", str(bundle_path), "--out", str(rendered_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "policy-backend-service-bundle-extract", str(bundle_path), "--out-dir", str(extracted_dir)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-service-bundle-append",
                    str(bundle_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "policy-backend-service-bundle-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(bundle_path.exists())
            self.assertTrue(markdown_path.exists())
            self.assertTrue(rendered_path.exists())
            self.assertTrue((extracted_dir / "policy_export.json").exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
