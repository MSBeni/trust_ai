import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.provider_installation import (
    PROVIDER_INSTALLATION_ENTRY_TYPE,
    PROVIDER_INSTALLATION_SCHEMA,
    append_provider_installation_manifest,
    build_provider_installation_manifest,
    verify_provider_installation_manifest,
)


ROOT = Path(__file__).resolve().parents[1]


class ProviderInstallationTests(unittest.TestCase):
    def _manifest(self) -> dict:
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
            evidence_refs=["github-app-installation:123456"],
        )

    def test_provider_installation_manifest_verifies_and_appends_to_chain(self):
        manifest = self._manifest()

        result = verify_provider_installation_manifest(manifest, now="2026-07-08T04:00:00Z")

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_INSTALLATION_SCHEMA, manifest["schema"])
        self.assertEqual("github", manifest["provider"])
        self.assertEqual("github-app:trustai-local", manifest["app"]["app_ref"])
        self.assertTrue(manifest["webhook"]["secret"]["redacted"])
        self.assertTrue(manifest["credential"]["redacted"])
        manifest_json = json.dumps(manifest, sort_keys=True)
        self.assertNotIn("super-secret", manifest_json)
        self.assertNotIn("-----BEGIN", manifest_json)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-installation-test")
            entry = append_provider_installation_manifest(chain, manifest)

            self.assertEqual(PROVIDER_INSTALLATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(manifest["manifest_id"], entry["payload"]["manifest_id"])
            self.assertNotIn("secret", entry["payload"]["webhook"])
            self.assertTrue(chain.verify_all().ok)

    def test_provider_installation_manifest_tamper_is_rejected(self):
        manifest = self._manifest()
        tampered = copy.deepcopy(manifest)
        tampered["capabilities"]["permissions"].append("contents:write")

        result = verify_provider_installation_manifest(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("manifest_id" in error or "signature" in error for error in result.errors))

    def test_provider_installation_manifest_rejects_raw_secret_field(self):
        manifest = self._manifest()
        manifest["webhook"]["secret"] = "super-secret"

        result = verify_provider_installation_manifest(manifest)

        self.assertFalse(result.ok)
        self.assertTrue(any("redacted reference" in error for error in result.errors))

    def test_cli_provider_installation_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            manifest_path = tmp / "provider-installation.json"
            entry_path = tmp / "provider-installation-entry.json"
            state_path = tmp / "evidence-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-installation",
                    "--provider",
                    "github",
                    "--app-ref",
                    "github-app:trustai-local",
                    "--installation-ref",
                    "github-installation:123456",
                    "--tenant-ref",
                    "github-org:volelabs",
                    "--owner",
                    "volelabs",
                    "--repository",
                    "volelabs/trust_ai",
                    "--mode",
                    "app-installation",
                    "--app-url",
                    "https://github.com/apps/trustai-local",
                    "--webhook-url",
                    "https://trustai.example/v0/provider-webhooks/github",
                    "--callback-url",
                    "https://trustai.example/v0/provider-callbacks/github",
                    "--permission",
                    "checks:write",
                    "--permission",
                    "metadata:read",
                    "--event",
                    "check_suite",
                    "--secret-ref",
                    "env:GITHUB_WEBHOOK_SECRET",
                    "--credential-ref",
                    "env:GITHUB_APP_PRIVATE_KEY",
                    "--audit-log-ref",
                    "github:org-audit-log:volelabs",
                    "--audit-log-scope",
                    "read:audit_log",
                    "--installed-at",
                    "2026-07-08T03:00:00Z",
                    "--evidence-ref",
                    "github-app-installation:123456",
                    "--out",
                    str(manifest_path),
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
                    "provider-installation-verify",
                    str(manifest_path),
                    "--now",
                    "2026-07-08T04:00:00Z",
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
                    "provider-installation-append",
                    str(manifest_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-installation-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_provider_installation_manifest(manifest, now="2026-07-08T04:00:00Z")
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(manifest["manifest_id"], entry["payload"]["manifest_id"])


if __name__ == "__main__":
    unittest.main()
