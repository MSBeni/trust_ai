import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.byoc_operator import write_byoc_operator_attestation
from trustai.chain import EvidenceChain
from trustai.collector_service import write_collector_service_attestation
from trustai.collector_topology import write_collector_topology
from trustai.collector_worker import (
    COLLECTOR_WORKER_ENTRY_TYPE,
    COLLECTOR_WORKER_SCHEMA,
    append_collector_worker_receipt,
    build_collector_worker_receipt,
    verify_collector_worker_receipt,
    write_collector_worker_receipt,
)
from trustai.deployment import write_deployment_manifest

from tests import test_collector_service as service_fixtures

ROOT = service_fixtures.ROOT


class CollectorWorkerTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = service_fixtures.CollectorServiceTests()
        attestation, topology, byoc, deployment, receipt, legal_hold, store_root = helper._attestation(tmp)
        return attestation, topology, byoc, deployment, receipt, legal_hold, store_root

    def _receipt(self, service, topology, byoc, deployment, worm_receipt, legal_hold, store_root, **overrides):
        values = {
            "service_attestation": service,
            "topology": topology,
            "byoc_operator": byoc,
            "deployment_manifest": deployment,
            "worm_receipt": worm_receipt,
            "legal_hold": legal_hold,
            "root": ROOT,
            "store": store_root,
            "mode": "hosted-worker",
            "environment": "aitrade-prod",
            "worker_ref": "worker:collector/otel-batch",
            "run_ref": "worker-run:collector/otel/2026-07-04T04:05:00Z",
            "operation_kind": "otlp_batch_ingest",
            "actor_ref": "oidc:trustai.example/collector-worker",
            "schedule_ref": "schedule:collector/otel/continuous",
            "cadence_seconds": 15,
            "lease_ref": "lease:collector/otel/2026-07-04T04:05:00Z",
            "checkpoint_ref": "checkpoint:collector/otel/aitrade",
            "checkpoint_hash": "sha256:collector-worker-checkpoint",
            "previous_cursor_ref": "cursor:collector/otel/before",
            "next_cursor_ref": "cursor:collector/otel/after",
            "next_run_at": "2026-07-04T04:05:15Z",
            "attempt": 1,
            "max_attempts": 3,
            "tenant_ref": "tenant:aitrade",
            "trace_batch_ref": "trace-batch:aitrade/2026-07-04T04:05:00Z",
            "trace_batch_hash": "sha256:collector-worker-trace-batch",
            "source_endpoint_ref": "otlp:http-v0-ingest",
            "received_span_count": 2,
            "accepted_span_count": 2,
            "rejected_span_count": 0,
            "idempotency_key_hash": "sha256:collector-worker-idempotency-key",
            "replay_cache_hit": False,
            "otlp_request_hash": "sha256:collector-worker-otlp-request",
            "otlp_response_status": 200,
            "otlp_response_hash": "sha256:collector-worker-otlp-response",
            "stream_ref": "redpanda:trustai/collector-events",
            "stream_topic": "trustai.otel.events",
            "partition_ref": "redpanda:trustai/collector-events/0",
            "offset_start": 100,
            "offset_end": 101,
            "stream_message_ref": "stream-message:collector/aitrade/2026-07-04T04:05:00Z",
            "stream_message_hash": "sha256:collector-worker-stream-message",
            "stream_dlq_ref": "redpanda:trustai/collector-events-dlq",
            "clickhouse_batch_ref": "clickhouse:trustai/traces/batch/2026-07-04T04:05:00Z",
            "clickhouse_batch_hash": "sha256:collector-worker-clickhouse-batch",
            "clickhouse_rows_written": 2,
            "postgres_index_ref": "postgres:trustai/control-plane/index/2026-07-04T04:05:00Z",
            "postgres_index_hash": "sha256:collector-worker-postgres-index",
            "postgres_rows_written": 2,
            "control_index_ref": "control-index:collector/aitrade/2026-07-04T04:05:00Z",
            "control_index_hash": "sha256:collector-worker-control-index",
            "mcp_transcript_ref": "mcp-transcript:aitrade/2026-07-04T04:05:00Z",
            "mcp_transcript_hash": "sha256:collector-worker-mcp-transcript",
            "framework_hook_ref": "hook:langgraph/0.3",
            "framework_hook_hash": "sha256:collector-worker-framework-hook",
            "metrics_ref": "metrics:collector/workers",
            "audit_log_ref": "audit-log:collector/workers",
            "audit_log_root": "sha256:collector-worker-audit-root",
            "retention_until": "2033-07-04T00:00:00Z",
            "credential_ref": "env:COLLECTOR_WORKER_TOKEN",
            "evidence_refs": ["evidence:collector/worker"],
            "started_at": "2026-07-04T04:05:00Z",
            "completed_at": "2026-07-04T04:05:02Z",
        }
        values.update(overrides)
        return build_collector_worker_receipt(**values)

    def test_collector_worker_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            service, topology, byoc, deployment, worm_receipt, legal_hold, store_root = self._sources(tmp)
            receipt = self._receipt(service, topology, byoc, deployment, worm_receipt, legal_hold, store_root)
            result = verify_collector_worker_receipt(
                receipt,
                service,
                topology,
                byoc_operator=byoc,
                deployment_manifest=deployment,
                worm_receipt=worm_receipt,
                legal_hold=legal_hold,
                root=ROOT,
                store=store_root,
            )
            chain = EvidenceChain.load(tmp / "collector-worker-chain.json", tenant_id="collector-worker-test")
            entry = append_collector_worker_receipt(
                chain,
                receipt,
                service,
                topology,
                byoc_operator=byoc,
                deployment_manifest=deployment,
                worm_receipt=worm_receipt,
                legal_hold=legal_hold,
                root=ROOT,
                store=store_root,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(COLLECTOR_WORKER_SCHEMA, receipt["schema"])
            self.assertEqual(service["attestation_id"], receipt["service"]["attestation_id"])
            self.assertEqual(topology["topology_id"], receipt["source"]["artifacts"][1]["id"])
            self.assertEqual("env:COLLECTOR_WORKER_TOKEN", receipt["credential"]["ref"])
            self.assertEqual(COLLECTOR_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])
            self.assertEqual({"worker-recorded": 9}, entry["payload"]["control_status_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_collector_worker_detects_topology_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            service, topology, byoc, deployment, worm_receipt, legal_hold, store_root = self._sources(tmp)
            receipt = self._receipt(service, topology, byoc, deployment, worm_receipt, legal_hold, store_root)
            tampered_topology = copy.deepcopy(topology)
            tampered_topology["topology"]["environment"] = "changed"

            result = verify_collector_worker_receipt(
                receipt,
                service,
                tampered_topology,
                byoc_operator=byoc,
                deployment_manifest=deployment,
                worm_receipt=worm_receipt,
                legal_hold=legal_hold,
                root=ROOT,
                store=store_root,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("collector-topology" in error or "service source" in error for error in result.errors))

    def test_collector_worker_rejects_raw_credential(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            service, topology, byoc, deployment, worm_receipt, legal_hold, store_root = self._sources(tmp)
            receipt = self._receipt(service, topology, byoc, deployment, worm_receipt, legal_hold, store_root)
            tampered = copy.deepcopy(receipt)
            tampered["credential"] = "collector-worker-secret"

            result = verify_collector_worker_receipt(
                tampered,
                service,
                topology,
                byoc_operator=byoc,
                deployment_manifest=deployment,
                worm_receipt=worm_receipt,
                legal_hold=legal_hold,
                root=ROOT,
                store=store_root,
            )

            self.assertFalse(result.ok)
            self.assertIn("collector worker credential must be a redacted reference", result.errors)
            self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_collector_worker_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            service, topology, byoc, deployment, worm_receipt, legal_hold, store_root = self._sources(tmp)
            service_path = tmp / "collector-service-attestation.json"
            topology_path = tmp / "collector-topology.json"
            byoc_path = tmp / "byoc-operator-attestation.json"
            deployment_path = tmp / "deployment-manifest.json"
            worm_path = tmp / "worm-receipt.json"
            hold_path = tmp / "legal-hold.json"
            worker_path = tmp / "collector-worker.json"
            entry_path = tmp / "collector-worker-entry.json"
            state_path = tmp / "collector-worker-chain.json"
            write_collector_service_attestation(service_path, service)
            write_collector_topology(topology_path, topology)
            write_byoc_operator_attestation(byoc_path, byoc)
            write_deployment_manifest(deployment_path, deployment)
            worm_path.write_text(json.dumps(worm_receipt, indent=2, sort_keys=True), encoding="utf-8")
            hold_path.write_text(json.dumps(legal_hold, indent=2, sort_keys=True), encoding="utf-8")

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                "--service-attestation",
                str(service_path),
                str(topology_path),
                "--byoc-operator",
                str(byoc_path),
                "--deployment-manifest",
                str(deployment_path),
                "--worm-receipt",
                str(worm_path),
                "--legal-hold",
                str(hold_path),
                "--root",
                str(ROOT),
                "--store",
                str(store_root),
            ]
            worker_args = [
                "--mode",
                "hosted-worker",
                "--environment",
                "aitrade-prod",
                "--worker-ref",
                "worker:collector/otel-batch",
                "--run-ref",
                "worker-run:collector/otel/2026-07-04T04:05:00Z",
                "--operation-kind",
                "otlp_batch_ingest",
                "--actor-ref",
                "oidc:trustai.example/collector-worker",
                "--schedule-ref",
                "schedule:collector/otel/continuous",
                "--cadence-seconds",
                "15",
                "--lease-ref",
                "lease:collector/otel/2026-07-04T04:05:00Z",
                "--checkpoint-ref",
                "checkpoint:collector/otel/aitrade",
                "--checkpoint-hash",
                "sha256:collector-worker-checkpoint",
                "--previous-cursor-ref",
                "cursor:collector/otel/before",
                "--next-cursor-ref",
                "cursor:collector/otel/after",
                "--next-run-at",
                "2026-07-04T04:05:15Z",
                "--tenant-ref",
                "tenant:aitrade",
                "--trace-batch-ref",
                "trace-batch:aitrade/2026-07-04T04:05:00Z",
                "--trace-batch-hash",
                "sha256:collector-worker-trace-batch",
                "--source-endpoint-ref",
                "otlp:http-v0-ingest",
                "--received-span-count",
                "2",
                "--accepted-span-count",
                "2",
                "--rejected-span-count",
                "0",
                "--idempotency-key-hash",
                "sha256:collector-worker-idempotency-key",
                "--otlp-request-hash",
                "sha256:collector-worker-otlp-request",
                "--otlp-response-status",
                "200",
                "--otlp-response-hash",
                "sha256:collector-worker-otlp-response",
                "--stream-ref",
                "redpanda:trustai/collector-events",
                "--stream-topic",
                "trustai.otel.events",
                "--partition-ref",
                "redpanda:trustai/collector-events/0",
                "--offset-start",
                "100",
                "--offset-end",
                "101",
                "--stream-message-ref",
                "stream-message:collector/aitrade/2026-07-04T04:05:00Z",
                "--stream-message-hash",
                "sha256:collector-worker-stream-message",
                "--stream-dlq-ref",
                "redpanda:trustai/collector-events-dlq",
                "--clickhouse-batch-ref",
                "clickhouse:trustai/traces/batch/2026-07-04T04:05:00Z",
                "--clickhouse-batch-hash",
                "sha256:collector-worker-clickhouse-batch",
                "--clickhouse-rows-written",
                "2",
                "--postgres-index-ref",
                "postgres:trustai/control-plane/index/2026-07-04T04:05:00Z",
                "--postgres-index-hash",
                "sha256:collector-worker-postgres-index",
                "--postgres-rows-written",
                "2",
                "--control-index-ref",
                "control-index:collector/aitrade/2026-07-04T04:05:00Z",
                "--control-index-hash",
                "sha256:collector-worker-control-index",
                "--mcp-transcript-ref",
                "mcp-transcript:aitrade/2026-07-04T04:05:00Z",
                "--mcp-transcript-hash",
                "sha256:collector-worker-mcp-transcript",
                "--framework-hook-ref",
                "hook:langgraph/0.3",
                "--framework-hook-hash",
                "sha256:collector-worker-framework-hook",
                "--metrics-ref",
                "metrics:collector/workers",
                "--audit-log-ref",
                "audit-log:collector/workers",
                "--audit-log-root",
                "sha256:collector-worker-audit-root",
                "--retention-until",
                "2033-07-04T00:00:00Z",
                "--credential-ref",
                "env:COLLECTOR_WORKER_TOKEN",
                "--evidence-ref",
                "evidence:collector/worker",
                "--started-at",
                "2026-07-04T04:05:00Z",
                "--completed-at",
                "2026-07-04T04:05:02Z",
            ]

            subprocess.run(
                [sys.executable, "-m", "trustai", "collector-worker", *source_args, *worker_args, "--out", str(worker_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "collector-worker-verify", str(worker_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "collector-worker-append",
                    str(worker_path),
                    *source_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "collector-worker-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(worker_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
