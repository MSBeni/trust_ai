import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.test_provider_operations_service import build_provider_operations_service_fixture
from trustai.chain import EvidenceChain
from trustai.cicd import build_promotion_check_payload
from trustai.delivery import build_provider_delivery
from trustai.provider_delivery_service import (
    PROVIDER_DELIVERY_SERVICE_ENTRY_TYPE,
    PROVIDER_DELIVERY_SERVICE_SCHEMA,
    append_provider_delivery_service_attestation,
    build_provider_delivery_service_attestation,
    verify_provider_delivery_service_attestation,
)
from trustai.verifier import load_proof_pack, verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "artifacts" / "aitrade-proof-pack.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def build_provider_delivery_sources(tmp: Path) -> dict:
    pack = load_proof_pack(PACK)
    verification = verify_proof_pack(pack)
    payload = build_promotion_check_payload(
        pack,
        verification,
        provider="github",
        commit_sha="0123456789abcdef0123456789abcdef01234567",
        repository="volelabs/trust_ai",
        target_url="https://example.test/proof-pack",
    )
    payload_path = tmp / "github-check-run-payload.json"
    _write_json(payload_path, payload)
    delivery = build_provider_delivery(
        payload,
        endpoint_base="https://api.github.com",
        credential_ref="env:GITHUB_TOKEN",
        mode="dry-run",
        delivered_at="2026-07-08T05:05:00Z",
        payload_artifact_path=payload_path,
    )
    _, provider_operations_service = build_provider_operations_service_fixture(tmp)
    return {
        "delivery": delivery,
        "payload": payload,
        "payload_artifact_path": payload_path,
        "provider_operations_service": provider_operations_service,
    }


def provider_delivery_service_values(sources: dict, **overrides) -> dict:
    values = {
        **sources,
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
    return values


def build_provider_delivery_service_fixture(tmp: Path) -> tuple[dict, dict]:
    sources = build_provider_delivery_sources(tmp)
    return sources, build_provider_delivery_service_attestation(**provider_delivery_service_values(sources))


def write_provider_delivery_sources(tmp: Path, sources: dict) -> dict[str, Path]:
    paths = {
        "delivery": tmp / "github-check-run-delivery.json",
        "payload": tmp / "github-check-run-payload.json",
        "provider_operations_service": tmp / "provider-operations-service-attestation.json",
    }
    _write_json(paths["delivery"], sources["delivery"])
    _write_json(paths["payload"], sources["payload"])
    _write_json(paths["provider_operations_service"], sources["provider_operations_service"])
    return paths


def provider_delivery_source_args(paths: dict[str, Path]) -> list[str]:
    return [
        str(paths["delivery"]),
        "--payload",
        str(paths["payload"]),
        "--provider-operations-service",
        str(paths["provider_operations_service"]),
    ]


class ProviderDeliveryServiceTests(unittest.TestCase):
    def _sources(self) -> dict:
        tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_dir.cleanup)
        return build_provider_delivery_sources(Path(tmp_dir.name))

    def _attestation(self, sources: dict, **overrides):
        return build_provider_delivery_service_attestation(**provider_delivery_service_values(sources, **overrides))

    def test_provider_delivery_service_verifies_and_appends(self):
        sources = self._sources()
        attestation = self._attestation(sources)
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
        attestation = self._attestation(sources)

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
        attestation = self._attestation(sources)
        tampered_sources = dict(sources)
        tampered_sources["delivery"] = copy.deepcopy(sources["delivery"])
        tampered_sources["delivery"]["target_url"] = "https://api.github.com/repos/other/repo/check-runs"

        result = verify_provider_delivery_service_attestation(attestation, **tampered_sources)

        self.assertFalse(result.ok)
        self.assertIn("provider delivery service source_artifacts do not match supplied source artifacts", result.errors)

    def test_provider_delivery_service_rejects_wrong_credential_ref(self):
        sources = self._sources()
        with self.assertRaises(ValueError):
            self._attestation(sources, provider_credential_ref="env:OTHER_TOKEN")

    def test_provider_delivery_service_rejects_weak_replicas(self):
        sources = self._sources()
        attestation = self._attestation(sources, replicas_min=1, availability_zones=["us-east-1a"])

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
            fixture_sources = build_provider_delivery_sources(tmp)
            source_paths = write_provider_delivery_sources(tmp, fixture_sources)
            sources = provider_delivery_source_args(source_paths)
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
                    str(source_paths["delivery"]),
                    "--payload",
                    str(source_paths["payload"]),
                    "--provider-operations-service",
                    str(source_paths["provider_operations_service"]),
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
                    str(source_paths["delivery"]),
                    "--payload",
                    str(source_paths["payload"]),
                    "--provider-operations-service",
                    str(source_paths["provider_operations_service"]),
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
