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
from trustai.reexecution_runner_service import (
    REEXECUTION_RUNNER_SERVICE_ENTRY_TYPE,
    REEXECUTION_RUNNER_SERVICE_SCHEMA,
    append_reexecution_runner_service_attestation,
    build_reexecution_runner_service_attestation,
    verify_reexecution_runner_service_attestation,
    write_reexecution_runner_service_attestation,
)

from tests import test_reexecution_isolation as isolation_fixtures

ROOT = isolation_fixtures.ROOT


class ReexecutionRunnerServiceTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = isolation_fixtures.ReexecutionIsolationTests()
        evidence, policy, report = helper._sources(tmp)
        isolation = helper._attestation(evidence, policy, report)
        return evidence, policy, report, isolation

    def _attestation(self, evidence, policy, report, isolation, **overrides):
        values = {
            "isolation_attestation": isolation,
            "runner_evidence": evidence,
            "policy": policy,
            "report": report,
            "mode": "isolated-runner-service",
            "environment": "aitrade-prod",
            "service_ref": "runner-service:trustai/reexecution-prod",
            "service_version": "0.1.0",
            "runner_image": "ghcr.io/trustai/reexecution-runner:0.1.0",
            "runner_image_digest": isolation["isolation"]["runner_image_digest"],
            "runner_binary_hash": "sha256:trustai-reexecution-runner-binary",
            "replicas_min": 3,
            "replicas_max": 9,
            "availability_zones": ["us-east-1a", "us-east-1b", "us-east-1c"],
            "scheduler_ref": "scheduler:reexecution/runner",
            "schedule_cadence_seconds": 60,
            "queue_ref": "queue:reexecution/runs",
            "dead_letter_queue_ref": "queue:reexecution/runs-dlq",
            "lease_store_ref": "postgres:reexecution/leases",
            "checkpoint_store_ref": "postgres:reexecution/checkpoints",
            "max_concurrency": 12,
            "retry_policy_ref": "policy:reexecution/retry-v0.1",
            "isolation_profile_ref": "isolation-profile:reexecution/container-v0.1",
            "admission_policy_ref": "admission:reexecution/signed-plans-only",
            "tenant_isolation_ref": "tenant-isolation:reexecution/aitrade",
            "network_policy_ref": "netpol:reexecution/deny-by-default",
            "egress_policy_ref": "egress-policy:deny-all",
            "artifact_store_ref": "s3:trustai-reexecution-artifacts",
            "result_store_ref": "s3:trustai-reexecution-results",
            "idempotency_store_ref": "postgres:reexecution/idempotency",
            "secret_store_ref": "vault:reexecution/secrets",
            "kms_key_ref": "kms:example/reexecution-runner",
            "metrics_ref": "metrics:reexecution/runner-service",
            "alert_policy_ref": "alert:reexecution/runner-service",
            "audit_log_ref": "audit-log:reexecution/runner-service",
            "audit_log_root": "sha256:reexecution-runner-service-audit-root",
            "retention_until": "2033-07-04T00:00:00Z",
            "actor_ref": "oidc:trustai.example/reexecution-runner-operator",
            "credential_ref": "env:REEXECUTION_RUNNER_SERVICE_TOKEN",
            "evidence_refs": ["evidence:reexecution/runner-service"],
            "attested_at": "2026-07-04T04:07:00Z",
        }
        values.update(overrides)
        return build_reexecution_runner_service_attestation(**values)

    def test_reexecution_runner_service_attestation_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation = self._sources(Path(tmp_dir))
            attestation = self._attestation(evidence, policy, report, isolation)
            result = verify_reexecution_runner_service_attestation(
                attestation,
                isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )
            chain = EvidenceChain.load(Path(tmp_dir) / "runner-service-chain.json", tenant_id="runner-service-test")
            entry = append_reexecution_runner_service_attestation(
                chain,
                attestation,
                isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(REEXECUTION_RUNNER_SERVICE_SCHEMA, attestation["schema"])
            self.assertEqual(isolation["attestation_id"], attestation["source"]["isolation_attestation_id"])
            self.assertEqual("disabled", attestation["execution_controls"]["source_network_mode"])
            self.assertEqual({"service-attested": 6}, entry["payload"]["control_summary"])
            self.assertEqual(REEXECUTION_RUNNER_SERVICE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_reexecution_runner_service_rejects_source_image_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation = self._sources(Path(tmp_dir))
            attestation = self._attestation(evidence, policy, report, isolation)
            tampered = copy.deepcopy(attestation)
            tampered["service"]["runner_image_digest"] = "sha256:other-runner-image"

            result = verify_reexecution_runner_service_attestation(
                tampered,
                isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("attestation_id" in error for error in result.errors))
            self.assertIn("re-execution runner service runner_image_digest does not match source isolation", result.errors)

    def test_reexecution_runner_service_requires_redundant_service_fleet(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation = self._sources(Path(tmp_dir))
            attestation = self._attestation(evidence, policy, report, isolation)
            tampered = copy.deepcopy(attestation)
            tampered["service"]["replicas_min"] = 1
            tampered["service"]["availability_zones"] = ["us-east-1a"]

            result = verify_reexecution_runner_service_attestation(
                tampered,
                isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )

            self.assertFalse(result.ok)
            self.assertIn("re-execution runner service service.replicas_min must be an integer >= 2", result.errors)
            self.assertIn("re-execution runner service service.availability_zones must contain at least two zones", result.errors)

    def test_cli_reexecution_runner_service_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence, policy, report, isolation = self._sources(tmp)
            evidence_path = tmp / "reexecution-runner-evidence.json"
            policy_path = tmp / "reexecution-policy.json"
            report_path = tmp / "reexecution-report.json"
            isolation_path = tmp / "reexecution-isolation-attestation.json"
            attestation_path = tmp / "reexecution-runner-service-attestation.json"
            entry_path = tmp / "reexecution-runner-service-entry.json"
            state_path = tmp / "runner-service-chain.json"
            write_reexecution_runner_evidence(evidence_path, evidence)
            policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True), encoding="utf-8")
            write_reexecution_report(report_path, report)
            write_reexecution_isolation_attestation(isolation_path, isolation)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base_args = [
                str(isolation_path),
                str(evidence_path),
                "--policy",
                str(policy_path),
                "--report",
                str(report_path),
            ]
            service_args = [
                "--environment",
                "aitrade-prod",
                "--service-ref",
                "runner-service:trustai/reexecution-prod",
                "--service-version",
                "0.1.0",
                "--runner-image",
                "ghcr.io/trustai/reexecution-runner:0.1.0",
                "--runner-binary-hash",
                "sha256:trustai-reexecution-runner-binary",
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
                "--scheduler-ref",
                "scheduler:reexecution/runner",
                "--schedule-cadence-seconds",
                "60",
                "--queue-ref",
                "queue:reexecution/runs",
                "--dead-letter-queue-ref",
                "queue:reexecution/runs-dlq",
                "--lease-store-ref",
                "postgres:reexecution/leases",
                "--checkpoint-store-ref",
                "postgres:reexecution/checkpoints",
                "--max-concurrency",
                "12",
                "--retry-policy-ref",
                "policy:reexecution/retry-v0.1",
                "--isolation-profile-ref",
                "isolation-profile:reexecution/container-v0.1",
                "--admission-policy-ref",
                "admission:reexecution/signed-plans-only",
                "--tenant-isolation-ref",
                "tenant-isolation:reexecution/aitrade",
                "--network-policy-ref",
                "netpol:reexecution/deny-by-default",
                "--egress-policy-ref",
                "egress-policy:deny-all",
                "--artifact-store-ref",
                "s3:trustai-reexecution-artifacts",
                "--result-store-ref",
                "s3:trustai-reexecution-results",
                "--idempotency-store-ref",
                "postgres:reexecution/idempotency",
                "--secret-store-ref",
                "vault:reexecution/secrets",
                "--kms-key-ref",
                "kms:example/reexecution-runner",
                "--metrics-ref",
                "metrics:reexecution/runner-service",
                "--alert-policy-ref",
                "alert:reexecution/runner-service",
                "--audit-log-ref",
                "audit-log:reexecution/runner-service",
                "--audit-log-root",
                "sha256:reexecution-runner-service-audit-root",
                "--retention-until",
                "2033-07-04T00:00:00Z",
                "--actor-ref",
                "oidc:trustai.example/reexecution-runner-operator",
                "--credential-ref",
                "env:REEXECUTION_RUNNER_SERVICE_TOKEN",
                "--evidence-ref",
                "evidence:reexecution/runner-service",
                "--attested-at",
                "2026-07-04T04:07:00Z",
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "reexecution-runner-service-attestation",
                    *base_args,
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
                    "reexecution-runner-service-verify",
                    str(attestation_path),
                    *base_args,
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
                    "reexecution-runner-service-append",
                    str(attestation_path),
                    *base_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "reexecution-runner-service-local",
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
