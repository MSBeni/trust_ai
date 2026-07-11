import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.framework_adapter_matrix import (
    build_framework_adapter_matrix,
    load_framework_adapter_matrix_source,
    write_framework_adapter_matrix,
)
from trustai.framework_hook_operation import (
    FRAMEWORK_HOOK_OPERATION_ENTRY_TYPE,
    FRAMEWORK_HOOK_OPERATION_SCHEMA,
    append_framework_hook_operation,
    build_framework_hook_operation,
    load_framework_trace_payload,
    verify_framework_hook_operation,
)
from trustai.framework_hook_release import (
    build_framework_hook_release,
    load_framework_hook_release_source,
    write_framework_hook_release,
)


ROOT = Path(__file__).resolve().parents[1]
MATRIX_SOURCE = ROOT / "examples" / "aitrade" / "framework-adapter-matrix.json"
HOOK_SOURCE = ROOT / "examples" / "aitrade" / "framework-hook-release.json"
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"


class FrameworkHookOperationTests(unittest.TestCase):
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

    def test_framework_hook_operation_verifies_and_appends(self):
        operation, trace, release, matrix = self._operation()
        result = verify_framework_hook_operation(operation, trace, release, matrix, root=ROOT)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-hook-operation-test")
            entry = append_framework_hook_operation(chain, operation, trace, release, matrix, root=ROOT)

            self.assertTrue(result.ok, result.errors)
            self.assertTrue(result.warnings)
            self.assertEqual(FRAMEWORK_HOOK_OPERATION_SCHEMA, operation["schema"])
            self.assertEqual("lg-trace-001", operation["trace"]["source_trace_id"])
            self.assertEqual(32, len(operation["trace"]["trace_id"]))
            self.assertEqual(2, operation["trace"]["event_count"])
            self.assertTrue(operation["trace"]["trace_roots"])
            self.assertEqual("env:FRAMEWORK_HOOK_TOKEN", operation["operation"]["credential"]["ref"])
            self.assertEqual(FRAMEWORK_HOOK_OPERATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(operation["operation_id"], entry["payload"]["operation_id"])
            self.assertEqual(5, entry["payload"]["control_summary"]["passed"])
            self.assertEqual(1, entry["payload"]["control_summary"]["deferred"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_hook_operation_detects_trace_tamper(self):
        operation, trace, release, matrix = self._operation()
        tampered_trace = copy.deepcopy(trace)
        tampered_trace["traces"][0]["nodes"][0]["decision"] = "tampered"

        result = verify_framework_hook_operation(operation, tampered_trace, release, matrix, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("source_trace_hash mismatch" in error for error in result.errors))
        self.assertTrue(any("event_root mismatch" in error for error in result.errors))

    def test_framework_hook_operation_detects_release_tamper(self):
        operation, trace, release, matrix = self._operation()
        tampered_release = copy.deepcopy(release)
        langgraph_row = next(row for row in tampered_release["entries"] if row["framework"] == "langgraph")
        langgraph_row["hook"]["entrypoint_ref"] = "trustai.framework_hooks:tampered"

        result = verify_framework_hook_operation(operation, trace, tampered_release, matrix, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("release_hash binding mismatch" in error for error in result.errors))
        self.assertTrue(any("entrypoint_ref" in error for error in result.errors))

    def test_framework_hook_operation_rejects_raw_credential(self):
        operation, trace, release, matrix = self._operation()
        tampered = copy.deepcopy(operation)
        tampered["operation"]["credential"] = "plain-secret"

        result = verify_framework_hook_operation(tampered, trace, release, matrix, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("framework hook operation credential must be a redacted reference", result.errors)
        self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_framework_hook_operation_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            matrix = self._matrix()
            release = self._release(matrix)
            matrix_path = tmp / "framework-adapter-matrix.json"
            release_path = tmp / "framework-hook-release.json"
            operation_path = tmp / "framework-hook-operation.json"
            entry_path = tmp / "framework-hook-operation-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_framework_adapter_matrix(matrix_path, matrix)
            write_framework_hook_release(release_path, release)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]

            subprocess.run(
                base
                + [
                    "framework-hook-operation",
                    str(TRACE_FIXTURE),
                    "--release",
                    str(release_path),
                    "--matrix",
                    str(matrix_path),
                    "--framework",
                    "langgraph",
                    "--trace-id",
                    "lg-trace-001",
                    "--root",
                    str(ROOT),
                    "--mode",
                    "collector-observed",
                    "--environment",
                    "aitrade-prod",
                    "--operation-ref",
                    "framework-hook-operation:aitrade/langgraph/lg-trace-001",
                    "--runtime-instance-ref",
                    "runtime:aitrade/langgraph/prod-worker-1",
                    "--runtime-process-ref",
                    "pid:4242",
                    "--collector-service-ref",
                    "collector:trustai/otel-prod",
                    "--collector-worker-ref",
                    "worker-run:collector/framework-hook/lg-trace-001",
                    "--stream-message-ref",
                    "stream-message:collector/framework-hook/lg-trace-001",
                    "--audit-log-ref",
                    "audit-log:framework-hooks/aitrade",
                    "--audit-log-root",
                    "sha256:framework-hook-operation-audit-root",
                    "--actor-ref",
                    "oidc:trustai.example/framework-hook-runtime",
                    "--credential-ref",
                    "env:FRAMEWORK_HOOK_TOKEN",
                    "--evidence-ref",
                    "evidence:framework-hook/lg-trace-001",
                    "--captured-at",
                    "2026-07-09T00:40:00Z",
                    "--out",
                    str(operation_path),
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
                    "framework-hook-operation-verify",
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
                    "framework-hook-operation-append",
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
                    "framework-hook-operation-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            operation = json.loads(operation_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_hook_operation(operation, load_framework_trace_payload(TRACE_FIXTURE), release, matrix, root=ROOT)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(operation["operation_id"], entry["payload"]["operation_id"])


if __name__ == "__main__":
    unittest.main()