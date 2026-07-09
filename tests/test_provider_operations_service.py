import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.provider_operations_service import (
    PROVIDER_OPERATIONS_SERVICE_ENTRY_TYPE,
    PROVIDER_OPERATIONS_SERVICE_SCHEMA,
    append_provider_operations_service_attestation,
    build_provider_operations_service_attestation,
    verify_provider_operations_service_attestation,
)


ROOT = Path(__file__).resolve().parents[1]


def _load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class ProviderOperationsServiceTests(unittest.TestCase):
    def _sources(self) -> dict:
        return {
            "provider_installation": _load("artifacts/github-provider-installation.json"),
            "provider_ingress": _load("artifacts/provider-ingress.json"),
            "callback_storage": _load("artifacts/provider-callback-storage.json"),
            "lifecycle": _load("artifacts/provider-lifecycle.json"),
            "lifecycle_operation": _load("artifacts/provider-lifecycle-operation.json"),
            "audit_lifecycle_operation": _load("artifacts/provider-audit-lifecycle-operation.json"),
            "audit_worker": _load("artifacts/provider-audit-worker.json"),
            "credential_custody": _load("artifacts/provider-credential-custody.json"),
            "callback_store": _load("artifacts/provider-callback-store.json"),
            "audit_stream": _load("artifacts/provider-audit-stream.json"),
            "audit_correlation": _load("artifacts/github-provider-audit-correlation.json"),
            "callback_store_db_path": str(ROOT / ".trustai" / "provider-callbacks.sqlite"),
        }

    def _attestation(self, **overrides):
        values = {
            **self._sources(),
            "environment": "aitrade-prod",
            "service_ref": "provider-ops:trustai/github-prod",
            "service_version": "0.1.0",
            "service_image": "ghcr.io/trustai/provider-ops:0.1.0",
            "service_image_digest": "sha256:trustai-provider-ops-image",
            "service_binary_hash": "sha256:trustai-provider-ops-binary",
            "replicas_min": 3,
            "replicas_max": 9,
            "availability_zones": ["us-east-1a", "us-east-1b", "us-east-1c"],
            "public_ingress_ref": "ingress:trustai-example",
            "oauth_worker_ref": "worker:provider-oauth/github",
            "callback_worker_ref": "worker:provider-callbacks/github",
            "audit_worker_ref": "worker:provider-audit/github",
            "storage_ref": "postgres:provider-callbacks",
            "vault_ref": "vault:trustai/provider-audit",
            "kms_key_ref": "kms:trustai/provider-audit-token",
            "mtls_policy_ref": "policy:provider-ops/mtls-required-v0.1",
            "auth_policy_ref": "policy:provider-ops/oidc-authz-v0.1",
            "webhook_signature_policy_ref": "policy:provider-ops/webhook-signature-v0.1",
            "replay_window_ref": "replay-window:provider-ops/5m",
            "dedup_store_ref": "sqlite:provider-callbacks/dedup",
            "rate_limit_policy_ref": "rate-limit:provider-ops/github",
            "network_policy_ref": "netpol:provider-ops/deny-by-default",
            "egress_policy_ref": "egress:provider-ops/provider-apis-only",
            "scheduler_ref": "schedule:provider-audit/github/10m",
            "lease_ref": "lease:provider-audit/github",
            "checkpoint_ref": "checkpoint:provider-audit/github",
            "external_call_policy_ref": "policy:provider-ops/external-calls-v0.1",
            "audit_log_ref": "audit-log:provider-ops/service",
            "audit_log_root": "sha256:provider-ops-service-audit-root",
            "retention_until": "2033-07-08T00:00:00Z",
            "actor_ref": "oidc:trustai.example/provider-ops-operator",
            "credential_ref": "env:PROVIDER_OPS_TOKEN",
            "evidence_refs": ["evidence:provider-ops/service"],
            "attested_at": "2026-07-08T05:00:00Z",
        }
        values.update(overrides)
        return build_provider_operations_service_attestation(**values)

    def test_provider_operations_service_verifies_and_appends(self):
        sources = self._sources()
        attestation = self._attestation()
        result = verify_provider_operations_service_attestation(attestation, **sources)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-ops-test")
            entry = append_provider_operations_service_attestation(chain, attestation, **sources)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_OPERATIONS_SERVICE_SCHEMA, attestation["schema"])
        self.assertEqual("provider-operations-attested", attestation["mode"])
        self.assertEqual("github", attestation["service"]["provider"])
        self.assertEqual("env:PROVIDER_OPS_TOKEN", attestation["operation_actor"]["credential"]["ref"])
        self.assertEqual(PROVIDER_OPERATIONS_SERVICE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])

    def test_provider_operations_service_rejects_source_mismatch(self):
        sources = self._sources()
        attestation = self._attestation()
        tampered_sources = dict(sources)
        tampered_sources["provider_ingress"] = copy.deepcopy(sources["provider_ingress"])
        tampered_sources["provider_ingress"]["ingress"]["ingress_ref"] = "ingress:tampered"

        result = verify_provider_operations_service_attestation(attestation, **tampered_sources)

        self.assertFalse(result.ok)
        self.assertIn("provider operations service source_artifacts do not match supplied source artifacts", result.errors)

    def test_provider_operations_service_rejects_weak_replicas(self):
        sources = self._sources()
        attestation = self._attestation(replicas_min=1, availability_zones=["us-east-1a"])

        result = verify_provider_operations_service_attestation(attestation, **sources)

        self.assertFalse(result.ok)
        self.assertIn("provider operations service service.replicas_min must be an integer >= 2", result.errors)
        self.assertIn("provider operations service service.availability_zones must include at least two zones", result.errors)

    def test_cli_provider_operations_service_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            attestation_path = tmp / "provider-operations-service-attestation.json"
            entry_path = tmp / "provider-operations-service-entry.json"
            state_path = tmp / "provider-operations-service-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            sources = [
                "--provider-installation",
                "artifacts/github-provider-installation.json",
                "--provider-ingress",
                "artifacts/provider-ingress.json",
                "--callback-storage",
                "artifacts/provider-callback-storage.json",
                "--lifecycle",
                "artifacts/provider-lifecycle.json",
                "--lifecycle-operation",
                "artifacts/provider-lifecycle-operation.json",
                "--audit-lifecycle-operation",
                "artifacts/provider-audit-lifecycle-operation.json",
                "--audit-worker",
                "artifacts/provider-audit-worker.json",
                "--credential-custody",
                "artifacts/provider-credential-custody.json",
                "--callback-store",
                "artifacts/provider-callback-store.json",
                "--callback-store-db",
                ".trustai/provider-callbacks.sqlite",
                "--audit-stream",
                "artifacts/provider-audit-stream.json",
                "--audit-correlation",
                "artifacts/github-provider-audit-correlation.json",
            ]
            service_args = [
                "--environment",
                "aitrade-prod",
                "--service-ref",
                "provider-ops:trustai/github-prod",
                "--service-version",
                "0.1.0",
                "--service-image",
                "ghcr.io/trustai/provider-ops:0.1.0",
                "--service-image-digest",
                "sha256:trustai-provider-ops-image",
                "--service-binary-hash",
                "sha256:trustai-provider-ops-binary",
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
                "--public-ingress-ref",
                "ingress:trustai-example",
                "--oauth-worker-ref",
                "worker:provider-oauth/github",
                "--callback-worker-ref",
                "worker:provider-callbacks/github",
                "--audit-worker-ref",
                "worker:provider-audit/github",
                "--storage-ref",
                "postgres:provider-callbacks",
                "--vault-ref",
                "vault:trustai/provider-audit",
                "--kms-key-ref",
                "kms:trustai/provider-audit-token",
                "--mtls-policy-ref",
                "policy:provider-ops/mtls-required-v0.1",
                "--auth-policy-ref",
                "policy:provider-ops/oidc-authz-v0.1",
                "--webhook-signature-policy-ref",
                "policy:provider-ops/webhook-signature-v0.1",
                "--replay-window-ref",
                "replay-window:provider-ops/5m",
                "--dedup-store-ref",
                "sqlite:provider-callbacks/dedup",
                "--rate-limit-policy-ref",
                "rate-limit:provider-ops/github",
                "--network-policy-ref",
                "netpol:provider-ops/deny-by-default",
                "--egress-policy-ref",
                "egress:provider-ops/provider-apis-only",
                "--scheduler-ref",
                "schedule:provider-audit/github/10m",
                "--lease-ref",
                "lease:provider-audit/github",
                "--checkpoint-ref",
                "checkpoint:provider-audit/github",
                "--external-call-policy-ref",
                "policy:provider-ops/external-calls-v0.1",
                "--audit-log-ref",
                "audit-log:provider-ops/service",
                "--audit-log-root",
                "sha256:provider-ops-service-audit-root",
                "--retention-until",
                "2033-07-08T00:00:00Z",
                "--actor-ref",
                "oidc:trustai.example/provider-ops-operator",
                "--credential-ref",
                "env:PROVIDER_OPS_TOKEN",
                "--evidence-ref",
                "evidence:provider-ops/service",
                "--attested-at",
                "2026-07-08T05:00:00Z",
            ]

            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-operations-service-attestation", *sources, *service_args, "--out", str(attestation_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-operations-service-verify", str(attestation_path), *sources],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-operations-service-append",
                    str(attestation_path),
                    *sources,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-operations-service-local",
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
