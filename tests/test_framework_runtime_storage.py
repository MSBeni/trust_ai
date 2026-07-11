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
from trustai.framework_adapter_matrix import write_framework_adapter_matrix
from trustai.framework_hook_operation import write_framework_hook_operation
from trustai.framework_hook_release import write_framework_hook_release
from trustai.framework_runtime_audit import write_framework_runtime_audit_receipt
from trustai.framework_runtime_storage import (
    FRAMEWORK_RUNTIME_STORAGE_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_STORAGE_SCHEMA,
    append_framework_runtime_storage_receipt,
    build_framework_runtime_storage_receipt,
    load_framework_runtime_storage_export,
    verify_framework_runtime_storage_receipt,
)
from trustai.framework_runtime_worker import write_framework_runtime_worker_receipt

from tests import test_framework_runtime_worker as worker_fixtures


ROOT = Path(__file__).resolve().parents[1]
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"
AUDIT_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-audit.json"
STORAGE_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-storage-export.json"


class FrameworkRuntimeStorageTests(unittest.TestCase):
    def _sources(self) -> tuple[dict, dict, dict, dict, dict, dict, dict, dict]:
        helper = worker_fixtures.FrameworkRuntimeWorkerTests()
        worker, runtime_audit, audit_export, operation, trace, release, matrix = helper._worker()
        storage_export = load_framework_runtime_storage_export(STORAGE_EXPORT_FIXTURE)
        return storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix

    def _receipt(self) -> tuple[dict, dict, dict, dict, dict, dict, dict, dict, dict]:
        storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._sources()
        receipt = build_framework_runtime_storage_receipt(
            storage_export,
            worker,
            runtime_audit,
            audit_export,
            operation,
            trace,
            release,
            matrix,
            root=ROOT,
            mode="provider-export",
            environment="aitrade-prod",
            provider="redpanda-clickhouse-postgres",
            endpoint_url="https://storage.example/aitrade/framework-runtime/export",
            credential_ref="env:FRAMEWORK_RUNTIME_STORAGE_TOKEN",
            request_hash="sha256:framework-runtime-storage-request",
            response_status=200,
            response_hash="sha256:framework-runtime-storage-response",
            actor_ref="oidc:trustai.example/framework-runtime-storage-worker",
            exported_at="2026-07-09T00:43:00Z",
        )
        return receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix

    def _resign_receipt(self, receipt: dict) -> None:
        body = without_keys(receipt, "storage_receipt_id", "signatures")
        storage_receipt_id = content_hash(body)
        receipt["storage_receipt_id"] = storage_receipt_id
        receipt["signatures"] = [
            sign_value({"storage_receipt_id": storage_receipt_id, "framework_runtime_storage": body})
        ]

    def test_framework_runtime_storage_verifies_and_appends(self):
        receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        result = verify_framework_runtime_storage_receipt(
            receipt,
            storage_export=storage_export,
            worker=worker,
            runtime_audit=runtime_audit,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-runtime-storage-test")
            entry = append_framework_runtime_storage_receipt(
                chain,
                receipt,
                storage_export=storage_export,
                worker=worker,
                runtime_audit=runtime_audit,
                audit_export=audit_export,
                operation=operation,
                trace_payload=trace,
                release=release,
                matrix=matrix,
                root=ROOT,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertTrue(result.warnings)
            self.assertEqual(FRAMEWORK_RUNTIME_STORAGE_SCHEMA, receipt["schema"])
            self.assertEqual(worker["worker_operation_id"], receipt["worker_binding"]["worker_operation_id"])
            self.assertEqual(4, receipt["provider_export"]["storage_record_count"])
            self.assertEqual(4, len(receipt["matched_storage_records"]))
            self.assertEqual("env:FRAMEWORK_RUNTIME_STORAGE_TOKEN", receipt["credential"]["ref"])
            self.assertEqual(FRAMEWORK_RUNTIME_STORAGE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["storage_receipt_id"], entry["payload"]["storage_receipt_id"])
            self.assertEqual(6, entry["payload"]["control_summary"]["passed"])
            self.assertEqual(1, entry["payload"]["control_summary"]["deferred"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_storage_detects_export_tamper(self):
        receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        tampered_export = copy.deepcopy(storage_export)
        tampered_export["stream_records"][0]["stream_message_hash"] = "sha256:wrong"

        result = verify_framework_runtime_storage_receipt(
            receipt,
            storage_export=tampered_export,
            worker=worker,
            runtime_audit=runtime_audit,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("provider export binding does not match" in error for error in result.errors))
        self.assertTrue(any("stream record stream_message_hash does not match" in error for error in result.errors))

    def test_framework_runtime_storage_detects_worker_tamper(self):
        receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        tampered_worker = copy.deepcopy(worker)
        tampered_worker["storage"]["clickhouse_batch_hash"] = "sha256:wrong"

        result = verify_framework_runtime_storage_receipt(
            receipt,
            storage_export=storage_export,
            worker=tampered_worker,
            runtime_audit=runtime_audit,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("worker invalid" in error for error in result.errors))
        self.assertTrue(any("worker binding does not match" in error for error in result.errors))

    def test_framework_runtime_storage_rejects_raw_credential(self):
        receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        tampered = copy.deepcopy(receipt)
        tampered["credential"] = "plain-secret"

        result = verify_framework_runtime_storage_receipt(
            tampered,
            storage_export=storage_export,
            worker=worker,
            runtime_audit=runtime_audit,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertIn("framework runtime storage credential must be a redacted reference", result.errors)
        self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_framework_runtime_storage_requires_source_replay_artifacts_without_sources(self):
        receipt, *_ = self._receipt()

        result = verify_framework_runtime_storage_receipt(receipt)

        self.assertFalse(result.ok)
        self.assertTrue(any("worker source artifacts are required for verification" in error for error in result.errors), result.errors)
        self.assertIn("framework runtime storage export is required for verification", result.errors)

    def test_framework_runtime_storage_requires_complete_signed_summaries(self):
        receipt, *_ = self._receipt()
        cases = [
            ("missing_worker_binding_key", "worker_binding.runtime_process_ref is required"),
            ("missing_provider_export_key", "provider_export.scheduler_record_root is required"),
            ("missing_matched_stream_key", "matched_stream_record.backend is required"),
            ("missing_matched_storage_kind", "matched_storage_records missing: clickhouse_batch"),
            ("missing_matched_scheduler_key", "matched_scheduler_record.checkpoint_hash is required"),
        ]
        for case_name, expected_error in cases:
            with self.subTest(case=case_name):
                tampered = copy.deepcopy(receipt)
                if case_name == "missing_worker_binding_key":
                    tampered["worker_binding"].pop("runtime_process_ref")
                elif case_name == "missing_provider_export_key":
                    tampered["provider_export"].pop("scheduler_record_root")
                elif case_name == "missing_matched_stream_key":
                    tampered["matched_stream_record"].pop("backend")
                elif case_name == "missing_matched_storage_kind":
                    tampered["matched_storage_records"] = [
                        record
                        for record in tampered["matched_storage_records"]
                        if record.get("kind") != "clickhouse_batch"
                    ]
                else:
                    tampered["matched_scheduler_record"].pop("checkpoint_hash")
                self._resign_receipt(tampered)

                result = verify_framework_runtime_storage_receipt(tampered)

                self.assertFalse(result.ok)
                self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_cli_framework_runtime_storage_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._sources()
            matrix_path = tmp / "framework-adapter-matrix.json"
            release_path = tmp / "framework-hook-release.json"
            operation_path = tmp / "framework-hook-operation.json"
            runtime_audit_path = tmp / "framework-runtime-audit.json"
            worker_path = tmp / "framework-runtime-worker.json"
            receipt_path = tmp / "framework-runtime-storage.json"
            entry_path = tmp / "framework-runtime-storage-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_framework_adapter_matrix(matrix_path, matrix)
            write_framework_hook_release(release_path, release)
            write_framework_hook_operation(operation_path, operation)
            write_framework_runtime_audit_receipt(runtime_audit_path, runtime_audit)
            write_framework_runtime_worker_receipt(worker_path, worker)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = [
                "--worker",
                str(worker_path),
                "--runtime-audit",
                str(runtime_audit_path),
                "--audit-export",
                str(AUDIT_EXPORT_FIXTURE),
                "--operation",
                str(operation_path),
                "--trace",
                str(TRACE_FIXTURE),
                "--release",
                str(release_path),
                "--matrix",
                str(matrix_path),
                "--root",
                str(ROOT),
            ]

            subprocess.run(
                base
                + [
                    "framework-runtime-storage",
                    str(STORAGE_EXPORT_FIXTURE),
                ]
                + source_args
                + [
                    "--mode",
                    "provider-export",
                    "--environment",
                    "aitrade-prod",
                    "--provider",
                    "redpanda-clickhouse-postgres",
                    "--endpoint-url",
                    "https://storage.example/aitrade/framework-runtime/export",
                    "--credential-ref",
                    "env:FRAMEWORK_RUNTIME_STORAGE_TOKEN",
                    "--request-hash",
                    "sha256:framework-runtime-storage-request",
                    "--response-status",
                    "200",
                    "--response-hash",
                    "sha256:framework-runtime-storage-response",
                    "--actor-ref",
                    "oidc:trustai.example/framework-runtime-storage-worker",
                    "--exported-at",
                    "2026-07-09T00:43:00Z",
                    "--out",
                    str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base + ["framework-runtime-storage-verify", str(receipt_path), "--storage-export", str(STORAGE_EXPORT_FIXTURE)] + source_args,
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + ["framework-runtime-storage-append", str(receipt_path), "--storage-export", str(STORAGE_EXPORT_FIXTURE)]
                + source_args
                + ["--state", str(state_path), "--tenant", "framework-runtime-storage-cli", "--out", str(entry_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_runtime_storage_receipt(
            receipt,
            storage_export=storage_export,
            worker=worker,
            runtime_audit=runtime_audit,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(receipt["storage_receipt_id"], entry["payload"]["storage_receipt_id"])


if __name__ == "__main__":
    unittest.main()
