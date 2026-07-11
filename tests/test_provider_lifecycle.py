import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.provider_callback_storage import build_provider_callback_storage_manifest, write_provider_callback_storage_manifest
from trustai.provider_callback_store import build_provider_callback_store_manifest, write_provider_callback_store_manifest
from trustai.provider_ingress import build_provider_ingress_manifest, write_provider_ingress_manifest
from trustai.provider_installation import build_provider_installation_manifest, write_provider_installation_manifest
from trustai.provider_lifecycle import (
    PROVIDER_LIFECYCLE_ENTRY_TYPE,
    PROVIDER_LIFECYCLE_SCHEMA,
    append_provider_lifecycle_manifest,
    build_provider_lifecycle_manifest,
    verify_provider_lifecycle_manifest,
)


ROOT = Path(__file__).resolve().parents[1]


def _installation() -> dict:
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


def _ingress(installation: dict, callback_store: dict) -> dict:
    return build_provider_ingress_manifest(
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


def _storage(callback_store: dict, ingress: dict) -> dict:
    return build_provider_callback_storage_manifest(
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
        provider_ingress_manifest=ingress,
        generated_at="2026-07-08T04:20:00Z",
    )


def _lifecycle(installation: dict, ingress: dict | None = None, storage: dict | None = None, **overrides) -> dict:
    values = {
        "provider_installation": installation,
        "lifecycle_ref": "lifecycle:github-app:trustai-local",
        "oauth_callback_url": "https://trustai.example/v0/provider-oauth/github/callback",
        "authorization_ref": "oauth:github:authorization:local",
        "token_exchange_ref": "oauth:github:token-exchange:local",
        "token_store_ref": "secret:provider-token-store/github",
        "refresh_policy_ref": "policy:provider-token-refresh",
        "credential_rotation_ref": "rotation:github-app-private-key:2026-07",
        "revocation_endpoint": "https://api.github.com/app/installations/123456/access_tokens",
        "revocation_ref": "revocation:github-installation:123456",
        "uninstall_ref": "uninstall:github-installation:123456",
        "audit_log_stream_ref": "github:audit-log-stream:volelabs",
        "mode": "byoc-reference",
        "environment": "test",
        "provider_ingress_manifest": ingress,
        "callback_storage_manifest": storage,
        "generated_at": "2026-07-08T04:30:00Z",
    }
    values.update(overrides)
    return build_provider_lifecycle_manifest(**values)


class ProviderLifecycleTests(unittest.TestCase):
    def test_provider_lifecycle_manifest_verifies_and_appends(self):
        installation = _installation()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            db_path = tmp / "provider-callbacks.sqlite"
            callback_store = build_provider_callback_store_manifest(
                db_path,
                source_artifacts=[installation],
                generated_at="2026-07-08T04:00:00Z",
                retention_until="2033-07-08T00:00:00Z",
            )
            ingress = _ingress(installation, callback_store)
            storage = _storage(callback_store, ingress)
            manifest = _lifecycle(installation, ingress, storage)

            result = verify_provider_lifecycle_manifest(
                manifest,
                provider_installation=installation,
                provider_ingress_manifest=ingress,
                callback_storage_manifest=storage,
                callback_store_manifest=callback_store,
                callback_store_db_path=db_path,
                callback_store_source_artifacts=[installation],
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(PROVIDER_LIFECYCLE_SCHEMA, manifest["schema"])
            self.assertEqual("github", manifest["lifecycle"]["provider"])
            self.assertEqual(7, len(manifest["operations"]))
            self.assertEqual(3, len(manifest["source_artifacts"]))
            self.assertTrue(manifest["oauth"]["token_store"]["redacted"])
            manifest_json = json.dumps(manifest, sort_keys=True)
            self.assertNotIn("github-token-secret", manifest_json)
            self.assertNotIn("postgres://user:password@", manifest_json)

            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="provider-lifecycle-test")
            entry = append_provider_lifecycle_manifest(
                chain,
                manifest,
                provider_installation=installation,
                provider_ingress_manifest=ingress,
                callback_storage_manifest=storage,
                callback_store_manifest=callback_store,
                callback_store_db_path=db_path,
                callback_store_source_artifacts=[installation],
            )

            self.assertEqual(PROVIDER_LIFECYCLE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(manifest["lifecycle_manifest_id"], entry["payload"]["lifecycle_manifest_id"])
            self.assertNotIn("token_store", entry["payload"]["oauth"])
            self.assertTrue(chain.verify_all().ok)

    def test_provider_lifecycle_rejects_non_https_revocation_endpoint(self):
        installation = _installation()
        manifest = _lifecycle(
            installation,
            revocation_endpoint="http://api.github.com/app/installations/123456/access_tokens",
        )

        result = verify_provider_lifecycle_manifest(manifest, provider_installation=installation)

        self.assertFalse(result.ok)
        self.assertIn("provider lifecycle revocation.endpoint must use HTTPS", result.errors)

    def test_provider_lifecycle_rejects_source_artifact_mismatch(self):
        installation = _installation()
        manifest = _lifecycle(installation)
        tampered = copy.deepcopy(installation)
        tampered["installation"]["repository"] = "volelabs/other"

        result = verify_provider_lifecycle_manifest(manifest, provider_installation=tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("installation record" in error or "source artifact summaries" in error for error in result.errors))

    def test_provider_lifecycle_rejects_raw_token_store(self):
        installation = _installation()
        manifest = _lifecycle(installation)
        manifest["oauth"]["token_store"] = "github-token-secret"

        result = verify_provider_lifecycle_manifest(manifest, provider_installation=installation)

        self.assertFalse(result.ok)
        self.assertTrue(any("redacted reference" in error for error in result.errors))

    def test_cli_provider_lifecycle_round_trip(self):
        installation = _installation()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            db_path = tmp / "provider-callbacks.sqlite"
            callback_store = build_provider_callback_store_manifest(
                db_path,
                source_artifacts=[installation],
                generated_at="2026-07-08T04:00:00Z",
                retention_until="2033-07-08T00:00:00Z",
            )
            ingress = _ingress(installation, callback_store)
            storage = _storage(callback_store, ingress)
            installation_path = tmp / "provider-installation.json"
            callback_store_path = tmp / "provider-callback-store.json"
            ingress_path = tmp / "provider-ingress.json"
            storage_path = tmp / "provider-callback-storage.json"
            lifecycle_path = tmp / "provider-lifecycle.json"
            entry_path = tmp / "provider-lifecycle-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_provider_installation_manifest(installation_path, installation)
            write_provider_callback_store_manifest(callback_store_path, callback_store)
            write_provider_ingress_manifest(ingress_path, ingress)
            write_provider_callback_storage_manifest(storage_path, storage)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            common_sources = [
                "--provider-installation",
                str(installation_path),
                "--provider-ingress",
                str(ingress_path),
                "--callback-storage",
                str(storage_path),
                "--callback-store",
                str(callback_store_path),
                "--callback-store-db",
                str(db_path),
                "--callback-store-artifact",
                str(installation_path),
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-lifecycle",
                    "--lifecycle-ref",
                    "lifecycle:github-app:trustai-local",
                    "--oauth-callback-url",
                    "https://trustai.example/v0/provider-oauth/github/callback",
                    "--authorization-ref",
                    "oauth:github:authorization:local",
                    "--token-exchange-ref",
                    "oauth:github:token-exchange:local",
                    "--token-store-ref",
                    "secret:provider-token-store/github",
                    "--refresh-policy-ref",
                    "policy:provider-token-refresh",
                    "--credential-rotation-ref",
                    "rotation:github-app-private-key:2026-07",
                    "--revocation-endpoint",
                    "https://api.github.com/app/installations/123456/access_tokens",
                    "--revocation-ref",
                    "revocation:github-installation:123456",
                    "--uninstall-ref",
                    "uninstall:github-installation:123456",
                    "--audit-log-stream-ref",
                    "github:audit-log-stream:volelabs",
                    "--mode",
                    "byoc-reference",
                    "--environment",
                    "test",
                    "--generated-at",
                    "2026-07-08T04:30:00Z",
                    *common_sources,
                    "--out",
                    str(lifecycle_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-lifecycle-verify",
                    str(lifecycle_path),
                    *common_sources,
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-lifecycle-append",
                    str(lifecycle_path),
                    *common_sources,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-lifecycle-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            manifest = json.loads(lifecycle_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            result = verify_provider_lifecycle_manifest(
                manifest,
                provider_installation=installation,
                provider_ingress_manifest=ingress,
                callback_storage_manifest=storage,
                callback_store_manifest=callback_store,
                callback_store_db_path=db_path,
                callback_store_source_artifacts=[installation],
            )
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(manifest["lifecycle_manifest_id"], entry["payload"]["lifecycle_manifest_id"])


if __name__ == "__main__":
    unittest.main()
