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
from trustai.policy_backend_worker import (
    POLICY_BACKEND_WORKER_ENTRY_TYPE,
    POLICY_BACKEND_WORKER_SCHEMA,
    append_policy_backend_worker_receipt,
    build_policy_backend_worker_receipt,
    verify_policy_backend_worker_receipt,
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


class PolicyBackendWorkerTests(unittest.TestCase):
    def _fixtures(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="policy-backend-worker-test")
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

    def _receipt(self, sources, **overrides):
        values = {
            "service_attestation": sources["attestation"],
            "enforcement_receipt": sources["enforcement"],
            "policy_pack": sources["policy"],
            "action": sources["action"],
            "proof_pack": sources["pack"],
            "decision": sources["policy_decision"],
            "policy_export": sources["policy_export"],
            "policy_engine_receipt": sources["engine_receipt"],
            "mode": "hosted-worker",
            "environment": "aitrade-prod",
            "worker_ref": "worker:policy-backend/opa-enforcement",
            "run_ref": "worker-run:policy-backend/opa/2026-07-04T04:05:00Z",
            "operation_kind": "policy_enforcement",
            "actor_ref": "oidc:trustai.example/policy-backend-worker",
            "schedule_ref": "schedule:policy-backend/opa/continuous",
            "cadence_seconds": 30,
            "lease_ref": "lease:policy-backend/opa/2026-07-04T04:05:00Z",
            "checkpoint_ref": "checkpoint:policy-backend/opa",
            "checkpoint_hash": "sha256:policy-backend-worker-checkpoint",
            "previous_cursor_ref": "cursor:policy-backend/opa/before",
            "next_cursor_ref": "cursor:policy-backend/opa/after",
            "next_run_at": "2026-07-04T04:05:30Z",
            "queue_ref": "queue:policy-backend/opa-enforcement",
            "queue_message_ref": "queue-message:policy-backend/opa/action-123",
            "queue_message_hash": "sha256:policy-backend-worker-queue-message",
            "dead_letter_queue_ref": "queue:policy-backend/opa-dlq",
            "backend_request_ref": "opa-request:policy-backend/opa/action-123",
            "decision_log_ref": "decision-log:policy-backend/opa",
            "decision_log_root": "sha256:policy-backend-worker-decision-log-root",
            "decision_record_hash": "sha256:policy-backend-worker-decision-record",
            "metrics_ref": "metrics:policy-backend/workers",
            "audit_log_ref": "audit-log:policy-backend/service",
            "audit_log_root": "sha256:policy-backend-worker-audit-root",
            "retention_until": "2033-07-04T00:00:00Z",
            "credential_ref": "env:POLICY_BACKEND_SERVICE_TOKEN",
            "backend_credential_ref": "env:OPA_BACKEND_TOKEN",
            "scheduler_export_ref": "aws:scheduler/policy-backend/opa",
            "scheduler_export_hash": "sha256:policy-backend-worker-scheduler-export",
            "queue_export_ref": "sqs:policy-backend/opa-enforcement",
            "queue_export_hash": "sha256:policy-backend-worker-queue-export",
            "lease_export_ref": "dynamodb:policy-backend/leases/opa",
            "lease_export_hash": "sha256:policy-backend-worker-lease-export",
            "decision_log_export_ref": "s3:policy-backend/decision-log/opa",
            "decision_log_export_hash": "sha256:policy-backend-worker-decision-log-export",
            "audit_export_ref": "cloudtrail:policy-backend/service",
            "audit_export_hash": "sha256:policy-backend-worker-audit-export",
            "evidence_refs": ["evidence:policy-backend/worker"],
            "started_at": "2026-07-04T04:05:00Z",
            "completed_at": "2026-07-04T04:05:01Z",
        }
        values.update(overrides)
        return build_policy_backend_worker_receipt(**values)

    def _source_dict(self, tmp: Path):
        chain, policy, action, pack, policy_decision, policy_export, engine_receipt, enforcement, attestation = self._fixtures(tmp)
        return {
            "chain": chain,
            "policy": policy,
            "action": action,
            "pack": pack,
            "policy_decision": policy_decision,
            "policy_export": policy_export,
            "engine_receipt": engine_receipt,
            "enforcement": enforcement,
            "attestation": attestation,
        }

    def test_policy_backend_worker_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._source_dict(Path(tmp_dir))
            receipt = self._receipt(sources)
            result = verify_policy_backend_worker_receipt(
                receipt,
                service_attestation=sources["attestation"],
                enforcement_receipt=sources["enforcement"],
                policy_pack=sources["policy"],
                action=sources["action"],
                proof_pack=sources["pack"],
                decision=sources["policy_decision"],
                policy_export=sources["policy_export"],
                policy_engine_receipt=sources["engine_receipt"],
            )
            entry = append_policy_backend_worker_receipt(
                sources["chain"],
                receipt,
                service_attestation=sources["attestation"],
                enforcement_receipt=sources["enforcement"],
                policy_pack=sources["policy"],
                action=sources["action"],
                proof_pack=sources["pack"],
                decision=sources["policy_decision"],
                policy_export=sources["policy_export"],
                policy_engine_receipt=sources["engine_receipt"],
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(POLICY_BACKEND_WORKER_SCHEMA, receipt["schema"])
            self.assertEqual("hosted-worker", receipt["mode"])
            self.assertEqual("policy_enforcement", receipt["worker"]["operation_kind"])
            self.assertEqual(200, receipt["execution"]["response_status"])
            self.assertEqual("env:OPA_BACKEND_TOKEN", receipt["backend_credential"]["ref"])
            self.assertEqual(POLICY_BACKEND_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])
            self.assertTrue(sources["chain"].verify_all().ok)

    def test_policy_backend_worker_rejects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._source_dict(Path(tmp_dir))
            receipt = self._receipt(sources)
            tampered = copy.deepcopy(sources)
            tampered["enforcement"] = copy.deepcopy(sources["enforcement"])
            tampered["enforcement"]["backend"]["response_hash"] = "sha256:other-policy-backend-response"

            result = verify_policy_backend_worker_receipt(
                receipt,
                service_attestation=tampered["attestation"],
                enforcement_receipt=tampered["enforcement"],
                policy_pack=tampered["policy"],
                action=tampered["action"],
                proof_pack=tampered["pack"],
                decision=tampered["policy_decision"],
                policy_export=tampered["policy_export"],
                policy_engine_receipt=tampered["engine_receipt"],
            )

            self.assertFalse(result.ok)
            self.assertIn("policy backend worker source artifact hash mismatch: policy-backend-enforcement", result.errors)

    def test_policy_backend_worker_rejects_raw_credential(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._source_dict(Path(tmp_dir))
            receipt = self._receipt(sources)
            receipt["backend_credential"] = "raw-token"

            result = verify_policy_backend_worker_receipt(
                receipt,
                service_attestation=sources["attestation"],
                enforcement_receipt=sources["enforcement"],
                policy_pack=sources["policy"],
                action=sources["action"],
                proof_pack=sources["pack"],
                decision=sources["policy_decision"],
                policy_export=sources["policy_export"],
                policy_engine_receipt=sources["engine_receipt"],
            )

            self.assertFalse(result.ok)
            self.assertIn("policy backend worker backend_credential must be a redacted reference", result.errors)
            self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_policy_backend_worker_rejects_wrong_backend_credential_source(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._source_dict(Path(tmp_dir))

            with self.assertRaisesRegex(ValueError, "backend_credential_ref must match enforcement backend credential ref"):
                self._receipt(sources, backend_credential_ref="env:OTHER_OPA_TOKEN")

    def test_cli_policy_backend_worker_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._source_dict(tmp)
            attestation_path = tmp / "policy-backend-service-attestation.json"
            enforcement_path = tmp / "policy-backend-enforcement.json"
            policy_path = tmp / "policy-pack.json"
            action_path = tmp / "runtime-action.json"
            pack_path = tmp / "pack.json"
            decision_path = tmp / "policy-decision.json"
            export_path = tmp / "policy-export.json"
            engine_receipt_path = tmp / "policy-engine-receipt.json"
            receipt_path = tmp / "policy-backend-worker.json"
            entry_path = tmp / "policy-backend-worker-entry.json"
            state_path = tmp / "policy-backend-worker-chain.json"
            write_policy_backend_service_attestation(attestation_path, sources["attestation"])
            write_policy_backend_enforcement_receipt(enforcement_path, sources["enforcement"])
            _write_json(policy_path, sources["policy"])
            _write_json(action_path, sources["action"])
            _write_json(pack_path, sources["pack"])
            _write_json(decision_path, sources["policy_decision"])
            write_policy_export(export_path, sources["policy_export"])
            write_policy_engine_receipt(engine_receipt_path, sources["engine_receipt"])

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            common = [
                str(attestation_path),
                str(enforcement_path),
                str(policy_path),
                str(action_path),
                "--pack",
                str(pack_path),
                "--decision",
                str(decision_path),
                "--export",
                str(export_path),
                "--policy-engine-receipt",
                str(engine_receipt_path),
            ]
            worker_args = [
                "--mode",
                "hosted-worker",
                "--environment",
                "aitrade-prod",
                "--worker-ref",
                "worker:policy-backend/opa-enforcement",
                "--run-ref",
                "worker-run:policy-backend/opa/2026-07-04T04:05:00Z",
                "--operation-kind",
                "policy_enforcement",
                "--actor-ref",
                "oidc:trustai.example/policy-backend-worker",
                "--schedule-ref",
                "schedule:policy-backend/opa/continuous",
                "--cadence-seconds",
                "30",
                "--lease-ref",
                "lease:policy-backend/opa/2026-07-04T04:05:00Z",
                "--checkpoint-ref",
                "checkpoint:policy-backend/opa",
                "--checkpoint-hash",
                "sha256:policy-backend-worker-checkpoint",
                "--previous-cursor-ref",
                "cursor:policy-backend/opa/before",
                "--next-cursor-ref",
                "cursor:policy-backend/opa/after",
                "--next-run-at",
                "2026-07-04T04:05:30Z",
                "--queue-ref",
                "queue:policy-backend/opa-enforcement",
                "--queue-message-ref",
                "queue-message:policy-backend/opa/action-123",
                "--queue-message-hash",
                "sha256:policy-backend-worker-queue-message",
                "--dead-letter-queue-ref",
                "queue:policy-backend/opa-dlq",
                "--backend-request-ref",
                "opa-request:policy-backend/opa/action-123",
                "--decision-log-ref",
                "decision-log:policy-backend/opa",
                "--decision-log-root",
                "sha256:policy-backend-worker-decision-log-root",
                "--decision-record-hash",
                "sha256:policy-backend-worker-decision-record",
                "--metrics-ref",
                "metrics:policy-backend/workers",
                "--audit-log-ref",
                "audit-log:policy-backend/service",
                "--audit-log-root",
                "sha256:policy-backend-worker-audit-root",
                "--retention-until",
                "2033-07-04T00:00:00Z",
                "--credential-ref",
                "env:POLICY_BACKEND_SERVICE_TOKEN",
                "--backend-credential-ref",
                "env:OPA_BACKEND_TOKEN",
                "--scheduler-export-ref",
                "aws:scheduler/policy-backend/opa",
                "--scheduler-export-hash",
                "sha256:policy-backend-worker-scheduler-export",
                "--queue-export-ref",
                "sqs:policy-backend/opa-enforcement",
                "--queue-export-hash",
                "sha256:policy-backend-worker-queue-export",
                "--lease-export-ref",
                "dynamodb:policy-backend/leases/opa",
                "--lease-export-hash",
                "sha256:policy-backend-worker-lease-export",
                "--decision-log-export-ref",
                "s3:policy-backend/decision-log/opa",
                "--decision-log-export-hash",
                "sha256:policy-backend-worker-decision-log-export",
                "--audit-export-ref",
                "cloudtrail:policy-backend/service",
                "--audit-export-hash",
                "sha256:policy-backend-worker-audit-export",
                "--evidence-ref",
                "evidence:policy-backend/worker",
                "--started-at",
                "2026-07-04T04:05:00Z",
                "--completed-at",
                "2026-07-04T04:05:01Z",
            ]

            subprocess.run([sys.executable, "-m", "trustai", "policy-backend-worker", *common, *worker_args, "--out", str(receipt_path)], cwd=ROOT, env=env, check=True)
            subprocess.run([sys.executable, "-m", "trustai", "policy-backend-worker-verify", str(receipt_path), *common], cwd=ROOT, env=env, check=True)
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-worker-append",
                    str(receipt_path),
                    *common,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "policy-backend-worker-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(receipt_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
