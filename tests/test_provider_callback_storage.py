import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.provider_callback_storage import (
    PROVIDER_CALLBACK_STORAGE_ENTRY_TYPE,
    PROVIDER_CALLBACK_STORAGE_SCHEMA,
    append_provider_callback_storage_manifest,
    build_provider_callback_storage_manifest,
    verify_provider_callback_storage_manifest,
    write_provider_callback_storage_manifest,
)
from trustai.provider_callback_store import build_provider_callback_store_manifest, write_provider_callback_store_manifest
from trustai.provider_ingress import build_provider_ingress_manifest, write_provider_ingress_manifest
from trustai.provider_installation import build_provider_installation_manifest, write_provider_installation_manifest


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


def _storage_kwargs() -> dict:
    return {
        "storage_ref": "postgres:provider-callbacks",
        "dsn_ref": "env:PROVIDER_CALLBACK_POSTGRES_DSN",
        "schema_ref": "dbschema:provider-callbacks-v0.1",
        "migration_ref": "migration:provider-callbacks-sqlite-to-postgres-v0.1",
        "migration_hash": "sha256:provider-callback-storage-migration",
        "mode": "byoc-reference",
        "environment": "test",
        "engine": "managed-postgres",
        "primary_region": "us-west-2",
        "replica_regions": ["us-east-1"],
        "min_replicas": 2,
        "backup_policy_ref": "backup:provider-callbacks-35d",
        "retention_until": "2033-07-08T00:00:00Z",
        "rpo_seconds": 60,
        "rto_seconds": 300,
        "encryption_key_ref": "kms:trustai/provider-callbacks",
        "network_policy_ref": "network-policy:provider-callback-storage",
        "monitoring_ref": "monitor:provider-callback-storage",
        "failover_runbook_ref": "runbook:provider-callback-storage-failover",
        "generated_at": "2026-07-08T04:20:00Z",
    }


class ProviderCallbackStorageTests(unittest.TestCase):
    def test_provider_callback_storage_manifest_verifies_and_appends(self):
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
            manifest = build_provider_callback_storage_manifest(
                **_storage_kwargs(),
                callback_store_manifest=callback_store,
                provider_ingress_manifest=ingress,
            )
            result = verify_provider_callback_storage_manifest(
                manifest,
                callback_store_manifest=callback_store,
                callback_store_db_path=db_path,
                callback_store_source_artifacts=[installation],
                provider_ingress_manifest=ingress,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(PROVIDER_CALLBACK_STORAGE_SCHEMA, manifest["schema"])
            self.assertEqual("managed-postgres", manifest["storage"]["engine"])
            self.assertEqual(callback_store["store_manifest_id"], manifest["migration_plan"]["source_store_manifest_id"])
            self.assertEqual(2, len(manifest["source_artifacts"]))
            self.assertNotIn("postgres://user:password@", json.dumps(manifest, sort_keys=True))

            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="provider-callback-storage-test")
            entry = append_provider_callback_storage_manifest(
                chain,
                manifest,
                callback_store_manifest=callback_store,
                callback_store_db_path=db_path,
                callback_store_source_artifacts=[installation],
                provider_ingress_manifest=ingress,
            )

            self.assertEqual(PROVIDER_CALLBACK_STORAGE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(manifest["storage_manifest_id"], entry["payload"]["storage_manifest_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_provider_callback_storage_rejects_under_replicated_ha(self):
        installation = _installation()
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "provider-callbacks.sqlite"
            callback_store = build_provider_callback_store_manifest(
                db_path,
                source_artifacts=[installation],
                generated_at="2026-07-08T04:00:00Z",
            )
            manifest = build_provider_callback_storage_manifest(
                **{**_storage_kwargs(), "min_replicas": 1},
                callback_store_manifest=callback_store,
            )

            result = verify_provider_callback_storage_manifest(
                manifest,
                callback_store_manifest=callback_store,
                callback_store_db_path=db_path,
                callback_store_source_artifacts=[installation],
            )

            self.assertFalse(result.ok)
            self.assertIn("provider callback storage min_replicas must be at least 2", result.errors)

    def test_provider_callback_storage_rejects_source_mismatch(self):
        installation = _installation()
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "provider-callbacks.sqlite"
            callback_store = build_provider_callback_store_manifest(
                db_path,
                source_artifacts=[installation],
                generated_at="2026-07-08T04:00:00Z",
            )
            manifest = build_provider_callback_storage_manifest(
                **_storage_kwargs(),
                callback_store_manifest=callback_store,
            )
            tampered = copy.deepcopy(callback_store)
            tampered["summary"]["operation_count"] = 99

            result = verify_provider_callback_storage_manifest(
                manifest,
                callback_store_manifest=tampered,
                callback_store_db_path=db_path,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("source artifact summaries" in error or "migration_plan" in error for error in result.errors))

    def test_cli_provider_callback_storage_round_trip(self):
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
            installation_path = tmp / "provider-installation.json"
            callback_store_path = tmp / "provider-callback-store.json"
            ingress_path = tmp / "provider-ingress.json"
            storage_path = tmp / "provider-callback-storage.json"
            entry_path = tmp / "provider-callback-storage-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_provider_installation_manifest(installation_path, installation)
            write_provider_callback_store_manifest(callback_store_path, callback_store)
            write_provider_ingress_manifest(ingress_path, ingress)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            common_sources = [
                "--callback-store",
                str(callback_store_path),
                "--callback-store-db",
                str(db_path),
                "--callback-store-artifact",
                str(installation_path),
                "--provider-ingress",
                str(ingress_path),
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-callback-storage",
                    "--storage-ref",
                    "postgres:provider-callbacks",
                    "--dsn-ref",
                    "env:PROVIDER_CALLBACK_POSTGRES_DSN",
                    "--schema-ref",
                    "dbschema:provider-callbacks-v0.1",
                    "--migration-ref",
                    "migration:provider-callbacks-sqlite-to-postgres-v0.1",
                    "--migration-hash",
                    "sha256:provider-callback-storage-migration",
                    "--mode",
                    "byoc-reference",
                    "--environment",
                    "test",
                    "--engine",
                    "managed-postgres",
                    "--primary-region",
                    "us-west-2",
                    "--replica-region",
                    "us-east-1",
                    "--backup-policy-ref",
                    "backup:provider-callbacks-35d",
                    "--retention-until",
                    "2033-07-08T00:00:00Z",
                    "--rpo-seconds",
                    "60",
                    "--rto-seconds",
                    "300",
                    "--encryption-key-ref",
                    "kms:trustai/provider-callbacks",
                    "--network-policy-ref",
                    "network-policy:provider-callback-storage",
                    "--monitoring-ref",
                    "monitor:provider-callback-storage",
                    "--failover-runbook-ref",
                    "runbook:provider-callback-storage-failover",
                    "--generated-at",
                    "2026-07-08T04:20:00Z",
                    *common_sources,
                    "--out",
                    str(storage_path),
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
                    "provider-callback-storage-verify",
                    str(storage_path),
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
                    "provider-callback-storage-append",
                    str(storage_path),
                    *common_sources,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-callback-storage-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            manifest = json.loads(storage_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            result = verify_provider_callback_storage_manifest(
                manifest,
                callback_store_manifest=callback_store,
                callback_store_db_path=db_path,
                callback_store_source_artifacts=[installation],
                provider_ingress_manifest=ingress,
            )
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(manifest["storage_manifest_id"], entry["payload"]["storage_manifest_id"])


if __name__ == "__main__":
    unittest.main()
