import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.reexecution import write_reexecution_report
from trustai.reexecution_isolation import write_reexecution_isolation_attestation
from trustai.reexecution_runner import write_reexecution_runner_evidence
from trustai.reexecution_runner_service import write_reexecution_runner_service_attestation
from trustai.reexecution_runner_worker import (
    REEXECUTION_RUNNER_WORKER_ENTRY_TYPE,
    REEXECUTION_RUNNER_WORKER_SCHEMA,
    append_reexecution_runner_worker_receipt,
    build_reexecution_runner_worker_receipt,
    verify_reexecution_runner_worker_receipt,
    write_reexecution_runner_worker_receipt,
)

from tests import test_reexecution_runner_service as service_fixtures

ROOT = service_fixtures.ROOT


class ReexecutionRunnerWorkerTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = service_fixtures.ReexecutionRunnerServiceTests()
        evidence, policy, report, isolation = helper._sources(tmp)
        service = helper._attestation(evidence, policy, report, isolation)
        return evidence, policy, report, isolation, service

    def _receipt(self, evidence, policy, report, isolation, service, **overrides):
        values = {
            "service_attestation": service,
            "isolation_attestation": isolation,
            "runner_evidence": evidence,
            "policy": policy,
            "report": report,
            "mode": "hosted-worker",
            "environment": "aitrade-prod",
            "worker_ref": "worker:reexecution/runner",
            "run_ref": "worker-run:reexecution/aitrade/2026-07-04T04:08:00Z",
            "operation_kind": "reexecution_run",
            "actor_ref": "oidc:trustai.example/reexecution-runner-worker",
            "schedule_ref": "schedule:reexecution/runner/1m",
            "cadence_seconds": 60,
            "lease_ref": "lease:reexecution/runner/2026-07-04T04:08:00Z",
            "checkpoint_ref": "checkpoint:reexecution/runner/aitrade",
            "checkpoint_hash": "sha256:reexecution-runner-worker-checkpoint",
            "previous_cursor_ref": "cursor:reexecution/runner/before",
            "next_cursor_ref": "cursor:reexecution/runner/after",
            "attempt": 1,
            "max_attempts": 3,
            "queue_ref": "queue:reexecution/runs",
            "queue_message_ref": "queue-message:reexecution/aitrade/2026-07-04T04:08:00Z",
            "dead_letter_queue_ref": "queue:reexecution/runs-dlq",
            "job_ref": "job:reexecution/aitrade/2026-07-04T04:08:00Z",
            "job_hash": "sha256:reexecution-runner-worker-job",
            "artifact_manifest_ref": "s3:trustai-reexecution-artifacts/aitrade/2026-07-04/manifest.json",
            "artifact_manifest_hash": "sha256:reexecution-runner-worker-artifacts",
            "result_bundle_ref": "s3:trustai-reexecution-results/aitrade/2026-07-04/results.json",
            "result_bundle_hash": "sha256:reexecution-runner-worker-results",
            "isolation_audit_ref": "audit-log:reexecution/isolation/runner-worker",
            "isolation_audit_root": "sha256:reexecution-runner-worker-isolation-audit-root",
            "runtime_audit_ref": "audit-log:reexecution/runtime/runner-worker",
            "runtime_audit_root": "sha256:reexecution-runner-worker-runtime-audit-root",
            "request_hash": "sha256:reexecution-runner-worker-request",
            "response_status": 200,
            "response_hash": "sha256:reexecution-runner-worker-response",
            "metrics_ref": "metrics:reexecution/runner-worker",
            "audit_log_ref": "audit-log:reexecution/runner-worker",
            "audit_log_root": "sha256:reexecution-runner-worker-audit-root",
            "credential_ref": "env:REEXECUTION_RUNNER_WORKER_TOKEN",
            "retention_until": "2033-07-04T00:00:00Z",
            "evidence_refs": ["evidence:reexecution/runner-worker"],
            "started_at": "2026-07-04T04:08:00Z",
            "completed_at": "2026-07-04T04:09:00Z",
            "next_run_at": "2026-07-04T04:09:00Z",
        }
        values.update(overrides)
        return build_reexecution_runner_worker_receipt(**values)

    def test_reexecution_runner_worker_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation, service = self._sources(Path(tmp_dir))
            receipt = self._receipt(evidence, policy, report, isolation, service)
            result = verify_reexecution_runner_worker_receipt(
                receipt,
                service_attestation=service,
                isolation_attestation=isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )
            chain = EvidenceChain.load(Path(tmp_dir) / "runner-worker-chain.json", tenant_id="runner-worker-test")
            entry = append_reexecution_runner_worker_receipt(
                chain,
                receipt,
                service_attestation=service,
                isolation_attestation=isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(REEXECUTION_RUNNER_WORKER_SCHEMA, receipt["schema"])
            self.assertEqual("hosted-worker", receipt["mode"])
            self.assertEqual(service["attestation_id"], receipt["service"]["attestation_id"])
            self.assertEqual("env:REEXECUTION_RUNNER_WORKER_TOKEN", receipt["credential"]["ref"])
            self.assertEqual(REEXECUTION_RUNNER_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])
            self.assertEqual({"worker-recorded": 6}, entry["payload"]["control_status_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_reexecution_runner_worker_detects_runner_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation, service = self._sources(Path(tmp_dir))
            receipt = self._receipt(evidence, policy, report, isolation, service)
            tampered_evidence = copy.deepcopy(evidence)
            tampered_evidence["runs"][0]["output"]["hash"] = "sha256:changed-run-output"

            result = verify_reexecution_runner_worker_receipt(
                receipt,
                service_attestation=service,
                isolation_attestation=isolation,
                runner_evidence=tampered_evidence,
                policy=policy,
                report=report,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("runner evidence" in error or "reexecution-runner-evidence" in error for error in result.errors))

    def test_reexecution_runner_worker_rejects_raw_credential(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation, service = self._sources(Path(tmp_dir))
            receipt = self._receipt(evidence, policy, report, isolation, service)
            tampered = copy.deepcopy(receipt)
            tampered["credential"] = "worker-token-secret"

            result = verify_reexecution_runner_worker_receipt(
                tampered,
                service_attestation=service,
                isolation_attestation=isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )

            self.assertFalse(result.ok)
            self.assertIn("re-execution runner worker credential must be a redacted reference", result.errors)
            self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_reexecution_runner_worker_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence, policy, report, isolation, service = self._sources(tmp)
            evidence_path = tmp / "reexecution-runner-evidence.json"
            policy_path = tmp / "reexecution-policy.json"
            report_path = tmp / "reexecution-report.json"
            isolation_path = tmp / "reexecution-isolation-attestation.json"
            service_path = tmp / "reexecution-runner-service-attestation.json"
            worker_path = tmp / "reexecution-runner-worker.json"
            entry_path = tmp / "reexecution-runner-worker-entry.json"
            state_path = tmp / "runner-worker-chain.json"
            write_reexecution_runner_evidence(evidence_path, evidence)
            policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True), encoding="utf-8")
            write_reexecution_report(report_path, report)
            write_reexecution_isolation_attestation(isolation_path, isolation)
            write_reexecution_runner_service_attestation(service_path, service)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                "--service-attestation",
                str(service_path),
                str(isolation_path),
                str(evidence_path),
                "--policy",
                str(policy_path),
                "--report",
                str(report_path),
            ]
            worker_args = [
                "--mode",
                "hosted-worker",
                "--environment",
                "aitrade-prod",
                "--worker-ref",
                "worker:reexecution/runner",
                "--run-ref",
                "worker-run:reexecution/aitrade/2026-07-04T04:08:00Z",
                "--operation-kind",
                "reexecution_run",
                "--actor-ref",
                "oidc:trustai.example/reexecution-runner-worker",
                "--schedule-ref",
                "schedule:reexecution/runner/1m",
                "--cadence-seconds",
                "60",
                "--lease-ref",
                "lease:reexecution/runner/2026-07-04T04:08:00Z",
                "--checkpoint-ref",
                "checkpoint:reexecution/runner/aitrade",
                "--checkpoint-hash",
                "sha256:reexecution-runner-worker-checkpoint",
                "--previous-cursor-ref",
                "cursor:reexecution/runner/before",
                "--next-cursor-ref",
                "cursor:reexecution/runner/after",
                "--queue-ref",
                "queue:reexecution/runs",
                "--queue-message-ref",
                "queue-message:reexecution/aitrade/2026-07-04T04:08:00Z",
                "--dead-letter-queue-ref",
                "queue:reexecution/runs-dlq",
                "--job-ref",
                "job:reexecution/aitrade/2026-07-04T04:08:00Z",
                "--job-hash",
                "sha256:reexecution-runner-worker-job",
                "--artifact-manifest-ref",
                "s3:trustai-reexecution-artifacts/aitrade/2026-07-04/manifest.json",
                "--artifact-manifest-hash",
                "sha256:reexecution-runner-worker-artifacts",
                "--result-bundle-ref",
                "s3:trustai-reexecution-results/aitrade/2026-07-04/results.json",
                "--result-bundle-hash",
                "sha256:reexecution-runner-worker-results",
                "--isolation-audit-ref",
                "audit-log:reexecution/isolation/runner-worker",
                "--isolation-audit-root",
                "sha256:reexecution-runner-worker-isolation-audit-root",
                "--runtime-audit-ref",
                "audit-log:reexecution/runtime/runner-worker",
                "--runtime-audit-root",
                "sha256:reexecution-runner-worker-runtime-audit-root",
                "--request-hash",
                "sha256:reexecution-runner-worker-request",
                "--response-status",
                "200",
                "--response-hash",
                "sha256:reexecution-runner-worker-response",
                "--metrics-ref",
                "metrics:reexecution/runner-worker",
                "--audit-log-ref",
                "audit-log:reexecution/runner-worker",
                "--audit-log-root",
                "sha256:reexecution-runner-worker-audit-root",
                "--credential-ref",
                "env:REEXECUTION_RUNNER_WORKER_TOKEN",
                "--retention-until",
                "2033-07-04T00:00:00Z",
                "--evidence-ref",
                "evidence:reexecution/runner-worker",
                "--started-at",
                "2026-07-04T04:08:00Z",
                "--completed-at",
                "2026-07-04T04:09:00Z",
                "--next-run-at",
                "2026-07-04T04:09:00Z",
            ]

            subprocess.run(
                [sys.executable, "-m", "trustai", "reexecution-runner-worker", *source_args, *worker_args, "--out", str(worker_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "reexecution-runner-worker-verify", str(worker_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "reexecution-runner-worker-append",
                    str(worker_path),
                    *source_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "reexecution-runner-worker-local",
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
