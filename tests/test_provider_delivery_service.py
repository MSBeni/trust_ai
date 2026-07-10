import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.provider_delivery_service import (
    PROVIDER_DELIVERY_SERVICE_ENTRY_TYPE,
    PROVIDER_DELIVERY_SERVICE_SCHEMA,
    append_provider_delivery_service_attestation,
    build_provider_delivery_service_attestation,
    verify_provider_delivery_service_attestation,
)


ROOT = Path(__file__).resolve().parents[1]


def _load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class ProviderDeliveryServiceTests(unittest.TestCase):
    def _sources(self) -> dict:
        return {
            "delivery": _load("artifacts/github-check-run-delivery.json"),
            "payload": _load("artifacts/github-check-run-payload.json"),
            "payload_artifact_path": "artifacts/github-check-run-payload.json",
            "provider_operations_service": _load("artifacts/provider-operations-service-attestation.json"),
        }

    def _attestation(self, **overrides):
        values = {
            **self._sources(),
            "environment": "aitrade-prod",
            "service_ref": "provider-delivery:trustai/github-prod",
            "service_version": "0.1.0",
            "service_image": "ghcr.io/trustai/provider-delivery:0.1.0",
            "service_image_digest": "sha256:trustai-provider-delivery-image",
            "service_binary_hash": "sha256:trustai-provider-delivery-binary",
            "replicas_min": 3,
            "replicas_max": 9,
            "availability_zones": ["us-east-1a", "us-east-1b", "us-east-1c"],
            "dispatch_worker_ref": "worker:provider-delivery/github",
            "queue_ref": "queue:provider-delivery/github",
            "dead_letter_queue_ref": "queue:provider-delivery/github-dlq",
            "idempotency_store_ref": "redis:provider-delivery/idempotency",
            "retry_policy_ref": "retry:provider-delivery/exponential-v0.1",
            "outbound_proxy_ref": "egress-proxy:provider-delivery",
            "provider_endpoint_base": "https://api.github.com",
            "provider_credential_ref": "env:GITHUB_TOKEN",
            "mtls_policy_ref": "policy:provider-delivery/mtls-required-v0.1",
            "auth_policy_ref": "policy:provider-delivery/oidc-authz-v0.1",
            "network_policy_ref": "netpol:provider-delivery/deny-by-default",
            "egress_policy_ref": "egress:provider-delivery/provider-apis-only",
            "rate_limit_policy_ref": "rate-limit:provider-delivery/github",
            "request_signing_policy_ref": "policy:provider-delivery/request-signing-v0.1",
            "audit_log_ref": "audit-log:provider-delivery/service",
            "audit_log_root": "sha256:provider-delivery-service-audit-root",
            "metrics_ref": "metrics:provider-delivery/service",
            "alert_policy_ref": "alert:provider-delivery/service",
            "retention_until": "2033-07-08T00:00:00Z",
            "actor_ref": "oidc:trustai.example/provider-delivery-operator",
            "credential_ref": "env:PROVIDER_DELIVERY_TOKEN",
            "evidence_refs": ["evidence:provider-delivery/service"],
            "attested_at": "2026-07-08T05:10:00Z",
        }
        values.update(overrides)
        return build_provider_delivery_service_attestation(**values)

    def test_provider_delivery_service_verifies_and_appends(self):
        sources = self._sources()
        attestation = self._attestation()
        result = verify_provider_delivery_service_attestation(attestation, **sources)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-delivery-service-test")
            entry = append_provider_delivery_service_attestation(chain, attestation, **sources)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_DELIVERY_SERVICE_SCHEMA, attestation["schema"])
        self.assertEqual("provider-delivery-attested", attestation["mode"])
        self.assertEqual("github", attestation["service"]["provider"])
        self.assertEqual("env:GITHUB_TOKEN", attestation["dispatch"]["provider_credential"]["ref"])
        self.assertEqual(PROVIDER_DELIVERY_SERVICE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])

    def test_provider_delivery_service_replays_delivery_payload_artifact(self):
        sources = self._sources()
        attestation = self._attestation()

        result = verify_provider_delivery_service_attestation(attestation, **sources)

        self.assertTrue(result.ok, result.errors)
        self.assertFalse(any("payload artifact was not replayed" in warning for warning in result.warnings))

        tampered_sources = dict(sources)
        tampered_sources["payload_artifact_path"] = Path(__file__)
        tampered_result = verify_provider_delivery_service_attestation(attestation, **tampered_sources)

        self.assertFalse(tampered_result.ok)
        self.assertTrue(any("payload_artifact" in error for error in tampered_result.errors))

    def test_provider_delivery_service_rejects_delivery_source_mismatch(self):
        sources = self._sources()
        attestation = self._attestation()
        tampered_sources = dict(sources)
        tampered_sources["delivery"] = copy.deepcopy(sources["delivery"])
        tampered_sources["delivery"]["target_url"] = "https://api.github.com/repos/other/repo/check-runs"

        result = verify_provider_delivery_service_attestation(attestation, **tampered_sources)

        self.assertFalse(result.ok)
        self.assertIn("provider delivery service source_artifacts do not match supplied source artifacts", result.errors)

    def test_provider_delivery_service_rejects_wrong_credential_ref(self):
        with self.assertRaises(ValueError):
            self._attestation(provider_credential_ref="env:OTHER_TOKEN")

    def test_provider_delivery_service_rejects_weak_replicas(self):
        sources = self._sources()
        attestation = self._attestation(replicas_min=1, availability_zones=["us-east-1a"])

        result = verify_provider_delivery_service_attestation(attestation, **sources)

        self.assertFalse(result.ok)
        self.assertIn("provider delivery service service.replicas_min must be an integer >= 2", result.errors)
        self.assertIn("provider delivery service service.availability_zones must include at least two zones", result.errors)

    def test_cli_provider_delivery_service_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            attestation_path = tmp / "provider-delivery-service-attestation.json"
            entry_path = tmp / "provider-delivery-service-entry.json"
            state_path = tmp / "provider-delivery-service-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            sources = [
                "artifacts/github-check-run-delivery.json",
                "--payload",
                "artifacts/github-check-run-payload.json",
                "--provider-operations-service",
                "artifacts/provider-operations-service-attestation.json",
            ]
            service_args = [
                "--environment",
                "aitrade-prod",
                "--service-ref",
                "provider-delivery:trustai/github-prod",
                "--service-version",
                "0.1.0",
                "--service-image",
                "ghcr.io/trustai/provider-delivery:0.1.0",
                "--service-image-digest",
                "sha256:trustai-provider-delivery-image",
                "--service-binary-hash",
                "sha256:trustai-provider-delivery-binary",
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
                "--dispatch-worker-ref",
                "worker:provider-delivery/github",
                "--queue-ref",
                "queue:provider-delivery/github",
                "--dead-letter-queue-ref",
                "queue:provider-delivery/github-dlq",
                "--idempotency-store-ref",
                "redis:provider-delivery/idempotency",
                "--retry-policy-ref",
                "retry:provider-delivery/exponential-v0.1",
                "--outbound-proxy-ref",
                "egress-proxy:provider-delivery",
                "--provider-endpoint-base",
                "https://api.github.com",
                "--provider-credential-ref",
                "env:GITHUB_TOKEN",
                "--mtls-policy-ref",
                "policy:provider-delivery/mtls-required-v0.1",
                "--auth-policy-ref",
                "policy:provider-delivery/oidc-authz-v0.1",
                "--network-policy-ref",
                "netpol:provider-delivery/deny-by-default",
                "--egress-policy-ref",
                "egress:provider-delivery/provider-apis-only",
                "--rate-limit-policy-ref",
                "rate-limit:provider-delivery/github",
                "--request-signing-policy-ref",
                "policy:provider-delivery/request-signing-v0.1",
                "--audit-log-ref",
                "audit-log:provider-delivery/service",
                "--audit-log-root",
                "sha256:provider-delivery-service-audit-root",
                "--metrics-ref",
                "metrics:provider-delivery/service",
                "--alert-policy-ref",
                "alert:provider-delivery/service",
                "--retention-until",
                "2033-07-08T00:00:00Z",
                "--actor-ref",
                "oidc:trustai.example/provider-delivery-operator",
                "--credential-ref",
                "env:PROVIDER_DELIVERY_TOKEN",
                "--evidence-ref",
                "evidence:provider-delivery/service",
                "--attested-at",
                "2026-07-08T05:10:00Z",
            ]

            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-delivery-service-attestation", *sources, *service_args, "--out", str(attestation_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-delivery-service-verify",
                    str(attestation_path),
                    "--delivery",
                    "artifacts/github-check-run-delivery.json",
                    "--payload",
                    "artifacts/github-check-run-payload.json",
                    "--provider-operations-service",
                    "artifacts/provider-operations-service-attestation.json",
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
                    "provider-delivery-service-append",
                    str(attestation_path),
                    "--delivery",
                    "artifacts/github-check-run-delivery.json",
                    "--payload",
                    "artifacts/github-check-run-payload.json",
                    "--provider-operations-service",
                    "artifacts/provider-operations-service-attestation.json",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-delivery-service-local",
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
