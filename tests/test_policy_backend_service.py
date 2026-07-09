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
from trustai.policy_backend_service import (
    POLICY_BACKEND_SERVICE_ENTRY_TYPE,
    POLICY_BACKEND_SERVICE_SCHEMA,
    append_policy_backend_service_attestation,
    build_policy_backend_service_attestation,
    verify_policy_backend_service_attestation,
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


class PolicyBackendServiceTests(unittest.TestCase):
    def _fixtures(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="policy-backend-service-test")
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
        return chain, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement

    def _attestation(self, enforcement, policy, action, pack, policy_decision, policy_export, engine_receipt, **overrides):
        values = {
            "enforcement_receipt": enforcement,
            "policy_pack": policy,
            "action": action,
            "proof_pack": pack,
            "decision": policy_decision,
            "policy_export": policy_export,
            "policy_engine_receipt": engine_receipt,
            "environment": "aitrade-prod",
            "service_ref": "policy-backend:trustai/opa-prod",
            "service_version": "0.1.0",
            "engine": "opa",
            "backend_ref": "opa:trustai-runtime:prod",
            "endpoint_url": "https://opa.example/v1/data/trustai/runtime/allow",
            "service_image": "ghcr.io/trustai/policy-backend:0.1.0",
            "service_image_digest": "sha256:trustai-policy-backend-image",
            "service_binary_hash": "sha256:trustai-policy-backend-binary",
            "replicas_min": 3,
            "replicas_max": 9,
            "availability_zones": ["us-east-1a", "us-east-1b", "us-east-1c"],
            "mtls_policy_ref": "policy:policy-backend/mtls-required-v0.1",
            "auth_policy_ref": "policy:policy-backend/oidc-authz-v0.1",
            "tenant_isolation_ref": "tenant-isolation:aitrade/policy-backend",
            "policy_sync_ref": "policy-sync:trustai/runtime-policy-bundle",
            "admission_policy_ref": "admission:policy-backend/signed-bundles-only",
            "rate_limit_policy_ref": "rate-limit:policy-backend/aitrade",
            "circuit_breaker_ref": "circuit-breaker:policy-backend/opa",
            "cache_store_ref": "redis:policy-backend/decision-cache",
            "network_policy_ref": "netpol:policy-backend/deny-by-default",
            "egress_policy_ref": "egress:policy-backend/kms-tsa-only",
            "decision_log_ref": "decision-log:policy-backend/opa",
            "decision_log_root": "sha256:policy-backend-decision-log-root",
            "decision_log_retention_days": 2555,
            "audit_log_ref": "audit-log:policy-backend/service",
            "audit_log_root": "sha256:policy-backend-service-audit-root",
            "retention_until": "2033-07-04T00:00:00Z",
            "actor_ref": "oidc:trustai.example/policy-backend-operator",
            "credential_ref": "env:POLICY_BACKEND_SERVICE_TOKEN",
            "evidence_refs": ["evidence:policy-backend/service"],
            "attested_at": "2026-07-04T04:02:00Z",
        }
        values.update(overrides)
        return build_policy_backend_service_attestation(**values)

    def test_policy_backend_service_attestation_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement = self._fixtures(Path(tmp_dir))
            attestation = self._attestation(enforcement, policy, action, pack, policy_decision, policy_export, engine_receipt)

            result = verify_policy_backend_service_attestation(
                attestation,
                enforcement,
                policy_pack=policy,
                action=action,
                proof_pack=pack,
                decision=policy_decision,
                policy_export=policy_export,
                policy_engine_receipt=engine_receipt,
            )
            entry = append_policy_backend_service_attestation(
                chain,
                attestation,
                enforcement,
                policy_pack=policy,
                action=action,
                proof_pack=pack,
                decision=policy_decision,
                policy_export=policy_export,
                policy_engine_receipt=engine_receipt,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(POLICY_BACKEND_SERVICE_SCHEMA, attestation["schema"])
            self.assertEqual("backend-service-attested", attestation["mode"])
            self.assertEqual("opa", attestation["service"]["engine"])
            self.assertEqual(enforcement["backend"]["bundle_hash"], attestation["service"]["bundle_hash"])
            self.assertEqual("env:POLICY_BACKEND_SERVICE_TOKEN", attestation["operation"]["credential"]["ref"])
            self.assertEqual(POLICY_BACKEND_SERVICE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_policy_backend_service_rejects_insecure_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement = self._fixtures(Path(tmp_dir))
            attestation = self._attestation(
                enforcement,
                policy,
                action,
                pack,
                policy_decision,
                policy_export,
                engine_receipt,
                endpoint_url="http://opa.example/v1/data/trustai/runtime/allow",
            )

            result = verify_policy_backend_service_attestation(
                attestation,
                enforcement,
                policy_pack=policy,
                action=action,
                proof_pack=pack,
                decision=policy_decision,
                policy_export=policy_export,
                policy_engine_receipt=engine_receipt,
            )

            self.assertFalse(result.ok)
            self.assertIn("policy backend service service.endpoint_url must use HTTPS", result.errors)

    def test_policy_backend_service_rejects_source_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement = self._fixtures(Path(tmp_dir))
            attestation = self._attestation(enforcement, policy, action, pack, policy_decision, policy_export, engine_receipt)
            tampered = copy.deepcopy(enforcement)
            tampered["backend"]["response_hash"] = "sha256:other-policy-backend-response"

            result = verify_policy_backend_service_attestation(
                attestation,
                tampered,
                policy_pack=policy,
                action=action,
                proof_pack=pack,
                decision=policy_decision,
                policy_export=policy_export,
                policy_engine_receipt=engine_receipt,
            )

            self.assertFalse(result.ok)
            self.assertIn("policy backend service source_artifacts do not match supplied source artifacts", result.errors)

    def test_cli_policy_backend_service_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement = self._fixtures(tmp)
            pack_path = tmp / "pack.json"
            decision_path = tmp / "policy-decision.json"
            export_path = tmp / "policy-export.json"
            engine_receipt_path = tmp / "policy-engine-receipt.json"
            enforcement_path = tmp / "policy-backend-enforcement.json"
            attestation_path = tmp / "policy-backend-service-attestation.json"
            entry_path = tmp / "policy-backend-service-entry.json"
            state_path = tmp / "policy-backend-service-chain.json"
            _write_json(pack_path, pack)
            _write_json(decision_path, policy_decision)
            write_policy_export(export_path, policy_export)
            write_policy_engine_receipt(engine_receipt_path, engine_receipt)
            write_policy_backend_enforcement_receipt(enforcement_path, enforcement)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            common = [
                str(enforcement_path),
                str(POLICY),
                str(ACTION),
                "--pack",
                str(pack_path),
                "--decision",
                str(decision_path),
                "--export",
                str(export_path),
                "--policy-engine-receipt",
                str(engine_receipt_path),
            ]
            service_args = [
                "--environment",
                "aitrade-prod",
                "--service-ref",
                "policy-backend:trustai/opa-prod",
                "--service-version",
                "0.1.0",
                "--engine",
                "opa",
                "--backend-ref",
                "opa:trustai-runtime:prod",
                "--endpoint-url",
                "https://opa.example/v1/data/trustai/runtime/allow",
                "--service-image",
                "ghcr.io/trustai/policy-backend:0.1.0",
                "--service-image-digest",
                "sha256:trustai-policy-backend-image",
                "--service-binary-hash",
                "sha256:trustai-policy-backend-binary",
                "--replicas-min",
                "3",
                "--replicas-max",
                "9",
                "--availability-zone",
                "us-east-1a",
                "--availability-zone",
                "us-east-1b",
                "--availability-zone",
                "us-east-1c",
                "--mtls-policy-ref",
                "policy:policy-backend/mtls-required-v0.1",
                "--auth-policy-ref",
                "policy:policy-backend/oidc-authz-v0.1",
                "--tenant-isolation-ref",
                "tenant-isolation:aitrade/policy-backend",
                "--policy-sync-ref",
                "policy-sync:trustai/runtime-policy-bundle",
                "--admission-policy-ref",
                "admission:policy-backend/signed-bundles-only",
                "--rate-limit-policy-ref",
                "rate-limit:policy-backend/aitrade",
                "--circuit-breaker-ref",
                "circuit-breaker:policy-backend/opa",
                "--cache-store-ref",
                "redis:policy-backend/decision-cache",
                "--network-policy-ref",
                "netpol:policy-backend/deny-by-default",
                "--egress-policy-ref",
                "egress:policy-backend/kms-tsa-only",
                "--decision-log-ref",
                "decision-log:policy-backend/opa",
                "--decision-log-root",
                "sha256:policy-backend-decision-log-root",
                "--decision-log-retention-days",
                "2555",
                "--audit-log-ref",
                "audit-log:policy-backend/service",
                "--audit-log-root",
                "sha256:policy-backend-service-audit-root",
                "--retention-until",
                "2033-07-04T00:00:00Z",
                "--actor-ref",
                "oidc:trustai.example/policy-backend-operator",
                "--credential-ref",
                "env:POLICY_BACKEND_SERVICE_TOKEN",
                "--evidence-ref",
                "evidence:policy-backend/service",
                "--attested-at",
                "2026-07-04T04:02:00Z",
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-service-attestation",
                    *common,
                    *service_args,
                    "--out",
                    str(attestation_path),
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
                    "policy-backend-service-verify",
                    str(attestation_path),
                    *common,
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
                    "policy-backend-service-append",
                    str(attestation_path),
                    *common,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "policy-backend-service-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(attestation_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()