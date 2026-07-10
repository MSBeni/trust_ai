import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.delivery import build_provider_delivery
from trustai.provider_delivery_service import build_provider_delivery_service_attestation
from trustai.provider_delivery_worker import (
    PROVIDER_DELIVERY_WORKER_ENTRY_TYPE,
    PROVIDER_DELIVERY_WORKER_SCHEMA,
    append_provider_delivery_worker_receipt,
    build_provider_delivery_worker_receipt,
    verify_provider_delivery_worker_receipt,
)


ROOT = Path(__file__).resolve().parents[1]


def _load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class ProviderDeliveryWorkerTests(unittest.TestCase):
    def _sources(self) -> dict:
        return {
            "service_attestation": _load("artifacts/provider-delivery-service-attestation.json"),
            "delivery": _load("artifacts/github-check-run-delivery.json"),
            "payload": _load("artifacts/github-check-run-payload.json"),
            "provider_operations_service": _load("artifacts/provider-operations-service-attestation.json"),
        }

    def _recorded_response_sources(self) -> dict:
        sources = self._sources()
        provider_response = {
            "status": 202,
            "body": {"ok": True, "id": "local-dispatch-1"},
            "headers": {"Content-Type": "application/json", "X-Request-Id": "local-dispatch-1"},
            "recorded_at": "2026-07-08T05:15:01Z",
            "provider_request_id": "local-dispatch-1",
        }
        delivery = build_provider_delivery(
            sources["payload"],
            endpoint_base="https://api.github.com",
            credential_ref="env:GITHUB_TOKEN",
            mode="recorded-response",
            response_status=provider_response["status"],
            response_body=provider_response["body"],
            response_headers=provider_response["headers"],
            delivered_at="2026-07-08T05:15:00Z",
        )
        service_attestation = build_provider_delivery_service_attestation(
            delivery=delivery,
            payload=sources["payload"],
            provider_operations_service=sources["provider_operations_service"],
            environment="aitrade-prod",
            service_ref="provider-delivery:trustai/github-prod",
            service_version="0.1.0",
            service_image="ghcr.io/trustai/provider-delivery:0.1.0",
            service_image_digest="sha256:trustai-provider-delivery-image",
            service_binary_hash="sha256:trustai-provider-delivery-binary",
            replicas_min=3,
            replicas_max=9,
            availability_zones=["us-east-1a", "us-east-1b", "us-east-1c"],
            dispatch_worker_ref="worker:provider-delivery/github",
            queue_ref="queue:provider-delivery/github",
            dead_letter_queue_ref="queue:provider-delivery/github-dlq",
            idempotency_store_ref="redis:provider-delivery/idempotency",
            retry_policy_ref="retry:provider-delivery/exponential-v0.1",
            outbound_proxy_ref="egress-proxy:provider-delivery",
            provider_endpoint_base="https://api.github.com",
            provider_credential_ref="env:GITHUB_TOKEN",
            mtls_policy_ref="policy:provider-delivery/mtls-required-v0.1",
            auth_policy_ref="policy:provider-delivery/oidc-authz-v0.1",
            network_policy_ref="netpol:provider-delivery/deny-by-default",
            egress_policy_ref="egress:provider-delivery/provider-apis-only",
            rate_limit_policy_ref="rate-limit:provider-delivery/github",
            request_signing_policy_ref="policy:provider-delivery/request-signing-v0.1",
            audit_log_ref="audit-log:provider-delivery/service",
            audit_log_root="sha256:provider-delivery-service-audit-root",
            metrics_ref="metrics:provider-delivery/service",
            alert_policy_ref="alert:provider-delivery/service",
            retention_until="2033-07-08T00:00:00Z",
            actor_ref="oidc:trustai.example/provider-delivery-operator",
            credential_ref="env:PROVIDER_DELIVERY_TOKEN",
            evidence_refs=["evidence:provider-delivery/service"],
            attested_at="2026-07-08T05:10:00Z",
        )
        return {
            **sources,
            "service_attestation": service_attestation,
            "delivery": delivery,
            "provider_response": provider_response,
        }

    def _receipt(self, **overrides):
        sources = self._sources()
        values = {
            **sources,
            "mode": "dispatch-worker",
            "environment": "aitrade-prod",
            "worker_ref": "worker:provider-delivery/github",
            "run_ref": "worker-run:provider-delivery/github/2026-07-08T05:15:00Z",
            "operation_kind": "provider_payload_dispatch",
            "actor_ref": "oidc:trustai.example/provider-delivery-worker",
            "schedule_ref": "schedule:provider-delivery/github/continuous",
            "cadence_seconds": 30,
            "lease_ref": "lease:provider-delivery/github/2026-07-08T05:15:00Z",
            "checkpoint_ref": "checkpoint:provider-delivery/github",
            "checkpoint_hash": "sha256:provider-delivery-worker-checkpoint",
            "previous_cursor_ref": "cursor:provider-delivery/github/before",
            "next_cursor_ref": "cursor:provider-delivery/github/after",
            "next_run_at": "2026-07-08T05:15:30Z",
            "attempt": 1,
            "max_attempts": 3,
            "queue_ref": "queue:provider-delivery/github",
            "queue_message_ref": "queue-message:provider-delivery/github/check-run",
            "dead_letter_queue_ref": "queue:provider-delivery/github-dlq",
            "destination_ref": sources["delivery"]["target_url"],
            "idempotency_record_hash": "sha256:provider-delivery-worker-idempotency",
            "provider_request_ref": "provider-request:github/check-run/2026-07-08T05:15:00Z",
            "request_hash": "sha256:provider-delivery-worker-request",
            "rate_limit_bucket_ref": "github:rate-limit/checks",
            "delivery_log_ref": "delivery-log:provider-delivery/github",
            "delivery_log_root": "sha256:provider-delivery-worker-delivery-root",
            "provider_event_log_ref": "github:check-run-events/aitrade",
            "provider_event_log_root": "sha256:provider-delivery-worker-provider-event-root",
            "metrics_ref": "metrics:provider-delivery/workers",
            "audit_log_ref": "audit-log:provider-delivery/workers",
            "audit_log_root": "sha256:provider-delivery-worker-audit-root",
            "credential_ref": "env:PROVIDER_DELIVERY_WORKER_TOKEN",
            "provider_credential_ref": "env:GITHUB_TOKEN",
            "retention_until": "2033-07-08T00:00:00Z",
            "evidence_refs": ["evidence:provider-delivery/worker"],
            "started_at": "2026-07-08T05:15:00Z",
            "completed_at": "2026-07-08T05:15:01Z",
        }
        values.update(overrides)
        return build_provider_delivery_worker_receipt(**values)

    def test_provider_delivery_worker_verifies_and_appends(self):
        sources = self._sources()
        receipt = self._receipt()
        result = verify_provider_delivery_worker_receipt(receipt, **sources)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-delivery-worker-test")
            entry = append_provider_delivery_worker_receipt(chain, receipt, **sources)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_DELIVERY_WORKER_SCHEMA, receipt["schema"])
        self.assertEqual("dispatch-worker", receipt["mode"])
        self.assertEqual(sources["delivery"]["delivery_id"], receipt["source_delivery"]["delivery_id"])
        self.assertEqual("env:GITHUB_TOKEN", receipt["provider_credential"]["ref"])
        self.assertEqual(PROVIDER_DELIVERY_WORKER_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])

    def test_provider_delivery_worker_replays_provider_response_artifact(self):
        sources = self._recorded_response_sources()
        receipt = self._receipt(**sources)
        result = verify_provider_delivery_worker_receipt(receipt, **sources)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-delivery-worker-response-test")
            entry = append_provider_delivery_worker_receipt(chain, receipt, **sources)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(sources["delivery"]["response"]["body_hash"], receipt["provider_response"]["body_hash"])
        self.assertEqual(202, receipt["provider_response"]["status"])
        self.assertTrue(receipt["provider_response"]["accepted"])
        self.assertIn("headers_hash", receipt["provider_response"])
        self.assertIn("provider-response", {artifact["type"] for artifact in receipt["source_artifacts"]})
        controls = {control["id"]: control["status"] for control in receipt["controls"]}
        self.assertEqual("worker-recorded", controls["provider-response-artifact-replay"])
        self.assertEqual(receipt["provider_response"], entry["payload"]["provider_response"])
        self.assertTrue(chain.verify_all().ok)

    def test_provider_delivery_worker_rejects_provider_response_artifact_tamper(self):
        sources = self._recorded_response_sources()
        receipt = self._receipt(**sources)
        tampered_sources = dict(sources)
        tampered_sources["provider_response"] = copy.deepcopy(sources["provider_response"])
        tampered_sources["provider_response"]["body"]["id"] = "different-response"

        result = verify_provider_delivery_worker_receipt(receipt, **tampered_sources)

        self.assertFalse(result.ok)
        self.assertIn("provider delivery worker source artifact hash mismatch: provider-response", result.errors)
        self.assertTrue(any("provider_response does not match" in error or "provider response source invalid" in error for error in result.errors))

    def test_provider_delivery_worker_rejects_delivery_source_tamper(self):
        sources = self._sources()
        receipt = self._receipt()
        tampered_sources = dict(sources)
        tampered_sources["delivery"] = copy.deepcopy(sources["delivery"])
        tampered_sources["delivery"]["target_url"] = "https://api.github.com/repos/other/repo/check-runs"

        result = verify_provider_delivery_worker_receipt(receipt, **tampered_sources)

        self.assertFalse(result.ok)
        self.assertIn("provider delivery worker source artifact hash mismatch: provider-delivery", result.errors)

    def test_provider_delivery_worker_rejects_raw_credential(self):
        sources = self._sources()
        receipt = self._receipt()
        receipt["provider_credential"] = "github-token-raw"

        result = verify_provider_delivery_worker_receipt(receipt, **sources)

        self.assertFalse(result.ok)
        self.assertIn("worker_operation_id does not match canonical provider delivery worker body", result.errors)
        self.assertIn("provider delivery worker provider_credential must be a redacted reference", result.errors)

    def test_cli_provider_delivery_worker_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            receipt_path = tmp / "provider-delivery-worker.json"
            entry_path = tmp / "provider-delivery-worker-entry.json"
            state_path = tmp / "provider-delivery-worker-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            sources = [
                "artifacts/github-check-run-delivery.json",
                "--service-attestation",
                "artifacts/provider-delivery-service-attestation.json",
                "--payload",
                "artifacts/github-check-run-payload.json",
                "--provider-operations-service",
                "artifacts/provider-operations-service-attestation.json",
            ]
            worker_args = [
                "--mode",
                "dispatch-worker",
                "--environment",
                "aitrade-prod",
                "--worker-ref",
                "worker:provider-delivery/github",
                "--run-ref",
                "worker-run:provider-delivery/github/2026-07-08T05:15:00Z",
                "--operation-kind",
                "provider_payload_dispatch",
                "--actor-ref",
                "oidc:trustai.example/provider-delivery-worker",
                "--schedule-ref",
                "schedule:provider-delivery/github/continuous",
                "--cadence-seconds",
                "30",
                "--lease-ref",
                "lease:provider-delivery/github/2026-07-08T05:15:00Z",
                "--checkpoint-ref",
                "checkpoint:provider-delivery/github",
                "--checkpoint-hash",
                "sha256:provider-delivery-worker-checkpoint",
                "--previous-cursor-ref",
                "cursor:provider-delivery/github/before",
                "--next-cursor-ref",
                "cursor:provider-delivery/github/after",
                "--next-run-at",
                "2026-07-08T05:15:30Z",
                "--queue-ref",
                "queue:provider-delivery/github",
                "--queue-message-ref",
                "queue-message:provider-delivery/github/check-run",
                "--dead-letter-queue-ref",
                "queue:provider-delivery/github-dlq",
                "--destination-ref",
                "https://api.github.com/repos/volelabs/trust_ai/check-runs",
                "--idempotency-record-hash",
                "sha256:provider-delivery-worker-idempotency",
                "--provider-request-ref",
                "provider-request:github/check-run/2026-07-08T05:15:00Z",
                "--request-hash",
                "sha256:provider-delivery-worker-request",
                "--rate-limit-bucket-ref",
                "github:rate-limit/checks",
                "--delivery-log-ref",
                "delivery-log:provider-delivery/github",
                "--delivery-log-root",
                "sha256:provider-delivery-worker-delivery-root",
                "--provider-event-log-ref",
                "github:check-run-events/aitrade",
                "--provider-event-log-root",
                "sha256:provider-delivery-worker-provider-event-root",
                "--metrics-ref",
                "metrics:provider-delivery/workers",
                "--audit-log-ref",
                "audit-log:provider-delivery/workers",
                "--audit-log-root",
                "sha256:provider-delivery-worker-audit-root",
                "--credential-ref",
                "env:PROVIDER_DELIVERY_WORKER_TOKEN",
                "--provider-credential-ref",
                "env:GITHUB_TOKEN",
                "--retention-until",
                "2033-07-08T00:00:00Z",
                "--evidence-ref",
                "evidence:provider-delivery/worker",
                "--started-at",
                "2026-07-08T05:15:00Z",
                "--completed-at",
                "2026-07-08T05:15:01Z",
            ]
            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-delivery-worker", *sources, *worker_args, "--out", str(receipt_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-delivery-worker-verify", str(receipt_path), *sources],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-delivery-worker-append",
                    str(receipt_path),
                    *sources,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-delivery-worker-local",
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
