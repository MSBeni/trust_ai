import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.test_provider_audit_worker import (
    _audit_log,
    _correlation,
    _lifecycle_operation as _audit_lifecycle_operation,
    _stream,
    _worker,
)
from tests.test_provider_callback_store import _delivery, _webhook_and_audit
from tests.test_provider_credential_custody import _custody
from trustai.chain import EvidenceChain
from trustai.provider_callback_storage import build_provider_callback_storage_manifest
from trustai.provider_callback_store import build_provider_callback_store_manifest
from trustai.provider_ingress import build_provider_ingress_manifest
from trustai.provider_installation import build_provider_installation_manifest
from trustai.provider_lifecycle import build_provider_lifecycle_manifest
from trustai.provider_lifecycle_operation import build_provider_lifecycle_operation_receipt
from trustai.provider_operations_service import (
    PROVIDER_OPERATIONS_SERVICE_ENTRY_TYPE,
    PROVIDER_OPERATIONS_SERVICE_SCHEMA,
    append_provider_operations_service_attestation,
    build_provider_operations_service_attestation,
    verify_provider_operations_service_attestation,
)


ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def _provider_installation() -> dict:
    return build_provider_installation_manifest(
        provider="github",
        app_ref="github-app:trustai-local",
        installation_ref="github-installation:123456",
        tenant_ref="github-org:volelabs",
        owner="volelabs",
        repository="volelabs/trust_ai",
        mode="app-installation",
        app_url="https://github.com/apps/trustai-local",
        webhook_url="https://trustai.example/v0/provider-webhooks/github",
        callback_url="https://trustai.example/v0/provider-callbacks/github",
        permissions=["checks:write", "metadata:read"],
        events=["check_suite", "check_run"],
        secret_ref="env:GITHUB_WEBHOOK_SECRET",
        credential_ref="env:GITHUB_APP_PRIVATE_KEY",
        audit_log_ref="github:org-audit-log:volelabs",
        audit_log_scopes=["read:audit_log"],
        installed_at="2026-07-08T03:00:00Z",
    )


def build_provider_operations_sources(tmp: Path) -> dict:
    installation = _provider_installation()
    webhook, _ = _webhook_and_audit()
    delivery = _delivery()
    audit_log = _audit_log()
    audit_correlation = _correlation(audit_log)
    callback_store_artifacts = [installation, webhook, delivery, audit_correlation]
    callback_store_db_path = tmp / "provider-callbacks.sqlite"
    callback_store = build_provider_callback_store_manifest(
        callback_store_db_path,
        source_artifacts=callback_store_artifacts,
        generated_at="2026-07-08T04:00:00Z",
        retention_until="2033-07-08T00:00:00Z",
    )
    provider_ingress = build_provider_ingress_manifest(
        ingress_base_url="https://trustai.example",
        ingress_ref="ingress:trustai-example",
        dns_name="trustai.example",
        mode="byoc-reference",
        environment="test",
        healthcheck_url="https://trustai.example/healthz",
        tls_certificate_ref="cert-manager:trustai-public",
        tls_certificate_fingerprint="sha256:trustai-example-cert",
        waf_ref="waf:trustai-public",
        network_policy_ref="network-policy:provider-callbacks",
        rate_limit_policy_ref="rate-limit:provider-callbacks",
        allowed_source_refs=["github-hooks"],
        replay_window_seconds=300,
        provider_installations=[installation],
        callback_store_manifest=callback_store,
        generated_at="2026-07-08T04:10:00Z",
    )
    callback_storage = build_provider_callback_storage_manifest(
        storage_ref="postgres:provider-callbacks",
        dsn_ref="env:PROVIDER_CALLBACK_POSTGRES_DSN",
        schema_ref="dbschema:provider-callbacks-v0.1",
        migration_ref="migration:provider-callbacks-sqlite-to-postgres-v0.1",
        migration_hash="sha256:provider-callback-storage-migration",
        mode="byoc-reference",
        environment="test",
        engine="managed-postgres",
        primary_region="us-west-2",
        replica_regions=["us-east-1"],
        min_replicas=2,
        backup_policy_ref="backup:provider-callbacks-35d",
        retention_until="2033-07-08T00:00:00Z",
        rpo_seconds=60,
        rto_seconds=300,
        encryption_key_ref="kms:trustai/provider-callbacks",
        network_policy_ref="network-policy:provider-callback-storage",
        monitoring_ref="monitor:provider-callback-storage",
        failover_runbook_ref="runbook:provider-callback-storage-failover",
        callback_store_manifest=callback_store,
        provider_ingress_manifest=provider_ingress,
        generated_at="2026-07-08T04:20:00Z",
    )
    lifecycle = build_provider_lifecycle_manifest(
        provider_installation=installation,
        lifecycle_ref="lifecycle:github-app:trustai-local",
        oauth_callback_url="https://trustai.example/v0/provider-oauth/github/callback",
        authorization_ref="oauth:github:authorization:local",
        token_exchange_ref="oauth:github:token-exchange:local",
        token_store_ref="secret:provider-token-store/github",
        refresh_policy_ref="policy:provider-token-refresh",
        credential_rotation_ref="rotation:github-app-private-key:2026-07",
        revocation_endpoint="https://api.github.com/app/installations/123456/access_tokens",
        revocation_ref="revocation:github-installation:123456",
        uninstall_ref="uninstall:github-installation:123456",
        audit_log_stream_ref="github:audit-log-stream:volelabs",
        mode="byoc-reference",
        environment="test",
        provider_ingress_manifest=provider_ingress,
        callback_storage_manifest=callback_storage,
        generated_at="2026-07-08T04:30:00Z",
    )
    lifecycle_operation = build_provider_lifecycle_operation_receipt(
        lifecycle_manifest=lifecycle,
        operation_kind="token_exchange",
        operation_ref="oauth:github:token-exchange:local",
        endpoint_url="https://github.com/login/oauth/access_token",
        credential_ref="env:GITHUB_APP_CLIENT_SECRET",
        token_ref="secret:provider-token-store/github",
        request_hash="sha256:github-token-exchange-request",
        response_status=200,
        response_hash="sha256:github-token-exchange-response",
        actor_ref="oidc:trustai.example/provider-worker",
        provider_event_ref="github:oauth-token-exchange:local",
        mode="recorded-provider-response",
        environment="test",
        recorded_at="2026-07-08T04:31:00Z",
    )
    audit_lifecycle_operation = _audit_lifecycle_operation(lifecycle)
    audit_stream = _stream(audit_log, installation, lifecycle, audit_correlation)
    audit_worker = _worker(audit_stream, audit_correlation, audit_lifecycle_operation, lifecycle)
    credential_custody = _custody(installation, lifecycle, audit_lifecycle_operation, audit_worker)
    return {
        "provider_installation": installation,
        "provider_ingress": provider_ingress,
        "callback_storage": callback_storage,
        "lifecycle": lifecycle,
        "lifecycle_operation": lifecycle_operation,
        "audit_lifecycle_operation": audit_lifecycle_operation,
        "audit_worker": audit_worker,
        "credential_custody": credential_custody,
        "callback_store": callback_store,
        "callback_store_db_path": callback_store_db_path,
        "callback_store_source_artifacts": callback_store_artifacts,
        "audit_stream": audit_stream,
        "audit_correlation": audit_correlation,
    }


def _service_values(sources: dict, **overrides) -> dict:
    values = {
        **sources,
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
    return values


def build_provider_operations_service_fixture(tmp: Path) -> tuple[dict, dict]:
    sources = build_provider_operations_sources(tmp)
    return sources, build_provider_operations_service_attestation(**_service_values(sources))


def write_provider_operations_sources(tmp: Path, sources: dict) -> dict[str, object]:
    paths: dict[str, object] = {
        "provider_installation": tmp / "github-provider-installation.json",
        "provider_ingress": tmp / "provider-ingress.json",
        "callback_storage": tmp / "provider-callback-storage.json",
        "lifecycle": tmp / "provider-lifecycle.json",
        "lifecycle_operation": tmp / "provider-lifecycle-operation.json",
        "audit_lifecycle_operation": tmp / "provider-audit-lifecycle-operation.json",
        "audit_worker": tmp / "provider-audit-worker.json",
        "credential_custody": tmp / "provider-credential-custody.json",
        "callback_store": tmp / "provider-callback-store.json",
        "audit_stream": tmp / "provider-audit-stream.json",
        "audit_correlation": tmp / "github-provider-audit-correlation.json",
    }
    for key, target in paths.items():
        _write_json(target, sources[key])
    artifact_paths = []
    for index, artifact in enumerate(sources["callback_store_source_artifacts"]):
        target = tmp / f"callback-store-artifact-{index}.json"
        _write_json(target, artifact)
        artifact_paths.append(target)
    paths["callback_store_db_path"] = sources["callback_store_db_path"]
    paths["callback_store_artifacts"] = artifact_paths
    return paths


def provider_operations_source_args(paths: dict[str, object]) -> list[str]:
    args = [
        "--provider-installation", str(paths["provider_installation"]),
        "--provider-ingress", str(paths["provider_ingress"]),
        "--callback-storage", str(paths["callback_storage"]),
        "--lifecycle", str(paths["lifecycle"]),
        "--lifecycle-operation", str(paths["lifecycle_operation"]),
        "--audit-lifecycle-operation", str(paths["audit_lifecycle_operation"]),
        "--audit-worker", str(paths["audit_worker"]),
        "--credential-custody", str(paths["credential_custody"]),
        "--callback-store", str(paths["callback_store"]),
        "--callback-store-db", str(paths["callback_store_db_path"]),
        "--audit-stream", str(paths["audit_stream"]),
        "--audit-correlation", str(paths["audit_correlation"]),
    ]
    for artifact_path in paths["callback_store_artifacts"]:
        args.extend(["--callback-store-artifact", str(artifact_path)])
    return args


class ProviderOperationsServiceTests(unittest.TestCase):
    def _attestation(self, sources: dict, **overrides):
        return build_provider_operations_service_attestation(**_service_values(sources, **overrides))

    def test_provider_operations_service_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = build_provider_operations_sources(Path(tmp_dir))
            attestation = self._attestation(sources)
            result = verify_provider_operations_service_attestation(attestation, **sources)
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-ops-test")
            entry = append_provider_operations_service_attestation(chain, attestation, **sources)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(PROVIDER_OPERATIONS_SERVICE_SCHEMA, attestation["schema"])
            self.assertEqual("provider-operations-attested", attestation["mode"])
            self.assertEqual("github", attestation["service"]["provider"])
            self.assertEqual("env:PROVIDER_OPS_TOKEN", attestation["operation_actor"]["credential"]["ref"])
            self.assertEqual(PROVIDER_OPERATIONS_SERVICE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_provider_operations_service_rejects_source_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = build_provider_operations_sources(Path(tmp_dir))
            attestation = self._attestation(sources)
            tampered_sources = dict(sources)
            tampered_sources["provider_ingress"] = copy.deepcopy(sources["provider_ingress"])
            tampered_sources["provider_ingress"]["ingress"]["ingress_ref"] = "ingress:tampered"

            result = verify_provider_operations_service_attestation(attestation, **tampered_sources)

        self.assertFalse(result.ok)
        self.assertIn("provider operations service source_artifacts do not match supplied source artifacts", result.errors)

    def test_provider_operations_service_rejects_weak_replicas(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = build_provider_operations_sources(Path(tmp_dir))
            attestation = self._attestation(sources, replicas_min=1, availability_zones=["us-east-1a"])
            result = verify_provider_operations_service_attestation(attestation, **sources)

        self.assertFalse(result.ok)
        self.assertIn("provider operations service service.replicas_min must be an integer >= 2", result.errors)
        self.assertIn("provider operations service service.availability_zones must include at least two zones", result.errors)

    def test_cli_provider_operations_service_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = build_provider_operations_sources(tmp)
            source_paths = write_provider_operations_sources(tmp, sources)
            source_args = provider_operations_source_args(source_paths)
            attestation_path = tmp / "provider-operations-service-attestation.json"
            entry_path = tmp / "provider-operations-service-entry.json"
            state_path = tmp / "provider-operations-service-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            service_args = [
                "--environment", "aitrade-prod",
                "--service-ref", "provider-ops:trustai/github-prod",
                "--service-version", "0.1.0",
                "--service-image", "ghcr.io/trustai/provider-ops:0.1.0",
                "--service-image-digest", "sha256:trustai-provider-ops-image",
                "--service-binary-hash", "sha256:trustai-provider-ops-binary",
                "--replicas-min", "3",
                "--replicas-max", "9",
                "--availability-zone", "us-east-1a",
                "--availability-zone", "us-east-1b",
                "--availability-zone", "us-east-1c",
                "--public-ingress-ref", "ingress:trustai-example",
                "--oauth-worker-ref", "worker:provider-oauth/github",
                "--callback-worker-ref", "worker:provider-callbacks/github",
                "--audit-worker-ref", "worker:provider-audit/github",
                "--storage-ref", "postgres:provider-callbacks",
                "--vault-ref", "vault:trustai/provider-audit",
                "--kms-key-ref", "kms:trustai/provider-audit-token",
                "--mtls-policy-ref", "policy:provider-ops/mtls-required-v0.1",
                "--auth-policy-ref", "policy:provider-ops/oidc-authz-v0.1",
                "--webhook-signature-policy-ref", "policy:provider-ops/webhook-signature-v0.1",
                "--replay-window-ref", "replay-window:provider-ops/5m",
                "--dedup-store-ref", "sqlite:provider-callbacks/dedup",
                "--rate-limit-policy-ref", "rate-limit:provider-ops/github",
                "--network-policy-ref", "netpol:provider-ops/deny-by-default",
                "--egress-policy-ref", "egress:provider-ops/provider-apis-only",
                "--scheduler-ref", "schedule:provider-audit/github/10m",
                "--lease-ref", "lease:provider-audit/github",
                "--checkpoint-ref", "checkpoint:provider-audit/github",
                "--external-call-policy-ref", "policy:provider-ops/external-calls-v0.1",
                "--audit-log-ref", "audit-log:provider-ops/service",
                "--audit-log-root", "sha256:provider-ops-service-audit-root",
                "--retention-until", "2033-07-08T00:00:00Z",
                "--actor-ref", "oidc:trustai.example/provider-ops-operator",
                "--credential-ref", "env:PROVIDER_OPS_TOKEN",
                "--evidence-ref", "evidence:provider-ops/service",
                "--attested-at", "2026-07-08T05:00:00Z",
            ]

            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-operations-service-attestation", *source_args, *service_args, "--out", str(attestation_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-operations-service-verify", str(attestation_path), *source_args],
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
                    *source_args,
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
