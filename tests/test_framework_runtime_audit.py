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
from trustai.framework_adapter_matrix import (
    build_framework_adapter_matrix,
    load_framework_adapter_matrix_source,
    write_framework_adapter_matrix,
)
from trustai.framework_hook_operation import (
    build_framework_hook_operation,
    load_framework_trace_payload,
    write_framework_hook_operation,
)
from trustai.framework_hook_release import (
    build_framework_hook_release,
    load_framework_hook_release_source,
    write_framework_hook_release,
)
from trustai.framework_runtime_audit import (
    FRAMEWORK_RUNTIME_AUDIT_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_AUDIT_SCHEMA,
    append_framework_runtime_audit_receipt,
    build_framework_runtime_audit_receipt,
    load_framework_runtime_audit_export,
    verify_framework_runtime_audit_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
MATRIX_SOURCE = ROOT / "examples" / "aitrade" / "framework-adapter-matrix.json"
HOOK_SOURCE = ROOT / "examples" / "aitrade" / "framework-hook-release.json"
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"
AUDIT_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-audit.json"


class FrameworkRuntimeAuditTests(unittest.TestCase):
    def _matrix(self) -> dict:
        return build_framework_adapter_matrix(
            load_framework_adapter_matrix_source(MATRIX_SOURCE),
            root=ROOT,
            issued_at="2026-07-09T00:00:00Z",
        )

    def _release(self, matrix: dict) -> dict:
        return build_framework_hook_release(
            load_framework_hook_release_source(HOOK_SOURCE),
            matrix,
            root=ROOT,
            released_at="2026-07-09T00:30:00Z",
        )

    def _operation(self) -> tuple[dict, dict, dict, dict]:
        matrix = self._matrix()
        release = self._release(matrix)
        trace = load_framework_trace_payload(TRACE_FIXTURE)
        operation = build_framework_hook_operation(
            trace,
            release,
            matrix,
            framework="langgraph",
            trace_id="lg-trace-001",
            root=ROOT,
            mode="collector-observed",
            environment="aitrade-prod",
            operation_ref="framework-hook-operation:aitrade/langgraph/lg-trace-001",
            runtime_instance_ref="runtime:aitrade/langgraph/prod-worker-1",
            runtime_process_ref="pid:4242",
            collector_service_ref="collector:trustai/otel-prod",
            collector_worker_ref="worker-run:collector/framework-hook/lg-trace-001",
            stream_message_ref="stream-message:collector/framework-hook/lg-trace-001",
            audit_log_ref="audit-log:framework-hooks/aitrade",
            audit_log_root="sha256:framework-hook-operation-audit-root",
            actor_ref="oidc:trustai.example/framework-hook-runtime",
            credential_ref="env:FRAMEWORK_HOOK_TOKEN",
            evidence_refs=["evidence:framework-hook/lg-trace-001"],
            captured_at="2026-07-09T00:40:00Z",
        )
        return operation, trace, release, matrix

    def _receipt(self) -> tuple[dict, dict, dict, dict, dict, dict]:
        operation, trace, release, matrix = self._operation()
        audit_export = load_framework_runtime_audit_export(AUDIT_EXPORT_FIXTURE)
        receipt = build_framework_runtime_audit_receipt(
            audit_export,
            operation,
            trace,
            release,
            matrix,
            root=ROOT,
            mode="provider-export",
            environment="aitrade-prod",
            provider="langgraph-runtime",
            endpoint_url="https://runtime.example/aitrade/audit/framework-hooks",
            credential_ref="env:LANGGRAPH_RUNTIME_AUDIT_TOKEN",
            request_hash="sha256:framework-runtime-audit-request",
            response_status=200,
            response_hash="sha256:framework-runtime-audit-response",
            actor_ref="oidc:trustai.example/framework-runtime-audit-worker",
            exported_at="2026-07-09T00:42:00Z",
        )
        return receipt, audit_export, operation, trace, release, matrix

    def _resign_receipt(self, receipt: dict) -> None:
        body = without_keys(receipt, "runtime_audit_id", "signatures")
        runtime_audit_id = content_hash(body)
        receipt["runtime_audit_id"] = runtime_audit_id
        receipt["signatures"] = [
            sign_value({"runtime_audit_id": runtime_audit_id, "framework_runtime_audit": body})
        ]

    def test_framework_runtime_audit_verifies_and_appends(self):
        receipt, audit_export, operation, trace, release, matrix = self._receipt()
        result = verify_framework_runtime_audit_receipt(
            receipt,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-runtime-audit-test")
            entry = append_framework_runtime_audit_receipt(
                chain,
                receipt,
                audit_export=audit_export,
                operation=operation,
                trace_payload=trace,
                release=release,
                matrix=matrix,
                root=ROOT,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertTrue(result.warnings)
            self.assertEqual(FRAMEWORK_RUNTIME_AUDIT_SCHEMA, receipt["schema"])
            self.assertEqual("lg-trace-001", receipt["operation_binding"]["trace_id"])
            self.assertEqual(2, receipt["audit_export"]["event_count"])
            self.assertEqual("runtime-audit:langgraph:lg-trace-001:hook-capture", receipt["matched_event"]["event_id"])
            self.assertEqual("env:LANGGRAPH_RUNTIME_AUDIT_TOKEN", receipt["credential"]["ref"])
            self.assertEqual(FRAMEWORK_RUNTIME_AUDIT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["runtime_audit_id"], entry["payload"]["runtime_audit_id"])
            self.assertEqual(6, entry["payload"]["control_summary"]["passed"])
            self.assertEqual(1, entry["payload"]["control_summary"]["deferred"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_audit_detects_audit_export_tamper(self):
        receipt, audit_export, operation, trace, release, matrix = self._receipt()
        tampered_export = copy.deepcopy(audit_export)
        tampered_export["events"][0]["trace_id"] = "wrong-trace"

        result = verify_framework_runtime_audit_receipt(
            receipt,
            audit_export=tampered_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("export binding does not match" in error for error in result.errors))
        self.assertTrue(any("does not contain a matching hook operation event" in error for error in result.errors))

    def test_framework_runtime_audit_detects_operation_tamper(self):
        receipt, audit_export, operation, trace, release, matrix = self._receipt()
        tampered_operation = copy.deepcopy(operation)
        tampered_operation["trace"]["event_root"] = "tampered"

        result = verify_framework_runtime_audit_receipt(
            receipt,
            audit_export=audit_export,
            operation=tampered_operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("operation invalid" in error for error in result.errors))
        self.assertTrue(any("operation binding does not match" in error for error in result.errors))

    def test_framework_runtime_audit_rejects_raw_credential(self):
        receipt, audit_export, operation, trace, release, matrix = self._receipt()
        tampered = copy.deepcopy(receipt)
        tampered["credential"] = "plain-secret"

        result = verify_framework_runtime_audit_receipt(
            tampered,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertIn("framework runtime audit credential must be a redacted reference", result.errors)
        self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_framework_runtime_audit_requires_source_replay_artifacts_without_sources(self):
        receipt, *_ = self._receipt()

        result = verify_framework_runtime_audit_receipt(receipt)

        self.assertFalse(result.ok)
        self.assertTrue(any("operation source artifacts are required for verification" in error for error in result.errors), result.errors)
        self.assertIn("framework runtime audit export is required for verification", result.errors)

    def test_framework_runtime_audit_requires_complete_signed_summaries(self):
        receipt, *_ = self._receipt()
        cases = [
            ("missing_operation_binding_key", "operation_binding.runtime_process_ref is required"),
            ("missing_operation_trace_roots", "operation_binding.trace_roots is required"),
            ("invalid_operation_trace_roots", "operation_binding.trace_roots must be an array"),
            ("missing_audit_export_key", "audit_export.next_cursor_ref is required"),
            ("missing_matched_event_key", "matched_event.event_kind is required"),
        ]
        for case_name, expected_error in cases:
            with self.subTest(case=case_name):
                tampered = copy.deepcopy(receipt)
                if case_name == "missing_operation_binding_key":
                    tampered["operation_binding"].pop("runtime_process_ref")
                elif case_name == "missing_operation_trace_roots":
                    tampered["operation_binding"]["trace_roots"] = []
                elif case_name == "invalid_operation_trace_roots":
                    tampered["operation_binding"]["trace_roots"] = "not-a-list"
                elif case_name == "missing_audit_export_key":
                    tampered["audit_export"].pop("next_cursor_ref")
                else:
                    tampered["matched_event"].pop("event_kind")
                self._resign_receipt(tampered)

                result = verify_framework_runtime_audit_receipt(tampered)

                self.assertFalse(result.ok)
                self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_cli_framework_runtime_audit_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            operation, trace, release, matrix = self._operation()
            matrix_path = tmp / "framework-adapter-matrix.json"
            release_path = tmp / "framework-hook-release.json"
            operation_path = tmp / "framework-hook-operation.json"
            receipt_path = tmp / "framework-runtime-audit.json"
            entry_path = tmp / "framework-runtime-audit-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_framework_adapter_matrix(matrix_path, matrix)
            write_framework_hook_release(release_path, release)
            write_framework_hook_operation(operation_path, operation)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]

            subprocess.run(
                base
                + [
                    "framework-runtime-audit",
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
                    "--mode",
                    "provider-export",
                    "--environment",
                    "aitrade-prod",
                    "--provider",
                    "langgraph-runtime",
                    "--endpoint-url",
                    "https://runtime.example/aitrade/audit/framework-hooks",
                    "--credential-ref",
                    "env:LANGGRAPH_RUNTIME_AUDIT_TOKEN",
                    "--request-hash",
                    "sha256:framework-runtime-audit-request",
                    "--response-status",
                    "200",
                    "--response-hash",
                    "sha256:framework-runtime-audit-response",
                    "--actor-ref",
                    "oidc:trustai.example/framework-runtime-audit-worker",
                    "--exported-at",
                    "2026-07-09T00:42:00Z",
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
                base
                + [
                    "framework-runtime-audit-verify",
                    str(receipt_path),
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
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-audit-append",
                    str(receipt_path),
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
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-runtime-audit-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_runtime_audit_receipt(
            receipt,
            audit_export=load_framework_runtime_audit_export(AUDIT_EXPORT_FIXTURE),
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(receipt["runtime_audit_id"], entry["payload"]["runtime_audit_id"])


if __name__ == "__main__":
    unittest.main()
