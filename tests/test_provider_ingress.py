import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.provider_callback_store import (
    build_provider_callback_store_manifest,
    write_provider_callback_store_manifest,
)
from trustai.provider_ingress import (
    PROVIDER_INGRESS_ENTRY_TYPE,
    PROVIDER_INGRESS_SCHEMA,
    append_provider_ingress_manifest,
    build_provider_ingress_manifest,
    verify_provider_ingress_manifest,
    write_provider_ingress_manifest,
)
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


def _ingress_kwargs() -> dict:
    return {
        "ingress_base_url": "https://trustai.example",
        "ingress_ref": "ingress:trustai-example",
        "dns_name": "trustai.example",
        "mode": "byoc-reference",
        "environment": "test",
        "healthcheck_url": "https://trustai.example/healthz",
        "tls_certificate_ref": "cert-manager:trustai-public",
        "tls_certificate_fingerprint": "sha256:trustai-example-cert",
        "waf_ref": "waf:trustai-public",
        "network_policy_ref": "network-policy:provider-callbacks",
        "rate_limit_policy_ref": "rate-limit:provider-callbacks",
        "allowed_source_refs": ["github-hooks"],
        "replay_window_seconds": 300,
        "generated_at": "2026-07-08T04:10:00Z",
    }


class ProviderIngressTests(unittest.TestCase):
    def test_provider_ingress_manifest_verifies_and_appends(self):
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
            manifest = build_provider_ingress_manifest(
                **_ingress_kwargs(),
                provider_installations=[installation],
                callback_store_manifest=callback_store,
            )
            result = verify_provider_ingress_manifest(
                manifest,
                provider_installations=[installation],
                callback_store_manifest=callback_store,
                callback_store_db_path=db_path,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(PROVIDER_INGRESS_SCHEMA, manifest["schema"])
            self.assertEqual(2, len(manifest["endpoints"]))
            self.assertEqual("github-hmac-sha256", manifest["endpoints"][0]["expected_signature"])
            self.assertEqual(2, len(manifest["source_artifacts"]))
            manifest_json = json.dumps(manifest, sort_keys=True)
            self.assertNotIn("env:GITHUB_WEBHOOK_SECRET", manifest_json)
            self.assertNotIn("env:GITHUB_APP_PRIVATE_KEY", manifest_json)

            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="provider-ingress-test")
            entry = append_provider_ingress_manifest(
                chain,
                manifest,
                provider_installations=[installation],
                callback_store_manifest=callback_store,
                callback_store_db_path=db_path,
            )

            self.assertEqual(PROVIDER_INGRESS_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(manifest["ingress_manifest_id"], entry["payload"]["ingress_manifest_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_provider_ingress_rejects_non_https_ingress(self):
        installation = _installation()
        manifest = build_provider_ingress_manifest(
            **{**_ingress_kwargs(), "ingress_base_url": "http://trustai.example"},
            provider_installations=[installation],
        )

        result = verify_provider_ingress_manifest(manifest, provider_installations=[installation])

        self.assertFalse(result.ok)
        self.assertIn("provider ingress base_url must use HTTPS", result.errors)

    def test_provider_ingress_rejects_source_artifact_mismatch(self):
        installation = _installation()
        manifest = build_provider_ingress_manifest(
            **_ingress_kwargs(),
            provider_installations=[installation],
        )
        tampered = copy.deepcopy(installation)
        tampered["installation"]["repository"] = "volelabs/other"

        result = verify_provider_ingress_manifest(manifest, provider_installations=[tampered])

        self.assertFalse(result.ok)
        self.assertIn("provider ingress source artifact summaries do not match supplied artifacts", result.errors)

    def test_cli_provider_ingress_round_trip(self):
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
            installation_path = tmp / "provider-installation.json"
            callback_store_path = tmp / "provider-callback-store.json"
            ingress_path = tmp / "provider-ingress.json"
            entry_path = tmp / "provider-ingress-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_provider_installation_manifest(installation_path, installation)
            write_provider_callback_store_manifest(callback_store_path, callback_store)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            common_args = [
                "--provider-installation",
                str(installation_path),
                "--callback-store",
                str(callback_store_path),
                "--callback-store-db",
                str(db_path),
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-ingress",
                    "--ingress-base-url",
                    "https://trustai.example",
                    "--ingress-ref",
                    "ingress:trustai-example",
                    "--dns-name",
                    "trustai.example",
                    "--mode",
                    "byoc-reference",
                    "--environment",
                    "test",
                    "--healthcheck-url",
                    "https://trustai.example/healthz",
                    "--tls-certificate-ref",
                    "cert-manager:trustai-public",
                    "--tls-certificate-fingerprint",
                    "sha256:trustai-example-cert",
                    "--waf-ref",
                    "waf:trustai-public",
                    "--network-policy-ref",
                    "network-policy:provider-callbacks",
                    "--rate-limit-policy-ref",
                    "rate-limit:provider-callbacks",
                    "--allowed-source-ref",
                    "github-hooks",
                    "--generated-at",
                    "2026-07-08T04:10:00Z",
                    *common_args,
                    "--out",
                    str(ingress_path),
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
                    "provider-ingress-verify",
                    str(ingress_path),
                    *common_args,
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
                    "provider-ingress-append",
                    str(ingress_path),
                    *common_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-ingress-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            manifest = json.loads(ingress_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            result = verify_provider_ingress_manifest(
                manifest,
                provider_installations=[installation],
                callback_store_manifest=callback_store,
                callback_store_db_path=db_path,
            )
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(manifest["ingress_manifest_id"], entry["payload"]["ingress_manifest_id"])


if __name__ == "__main__":
    unittest.main()
