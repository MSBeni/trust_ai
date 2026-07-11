import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.test_provider_audit_worker import (
    WEBHOOK_SECRET,
    _audit_log,
    _correlation,
    _lifecycle,
    _lifecycle_operation,
    _provider_installation,
    _stream,
    _worker,
)
from trustai.chain import EvidenceChain
from trustai.provider_audit_worker import write_provider_audit_worker_receipt
from trustai.provider_credential_custody import (
    PROVIDER_CREDENTIAL_CUSTODY_ENTRY_TYPE,
    PROVIDER_CREDENTIAL_CUSTODY_SCHEMA,
    append_provider_credential_custody_receipt,
    build_provider_credential_custody_receipt,
    verify_provider_credential_custody_receipt,
    write_provider_credential_custody_receipt,
)
from trustai.provider_installation import write_provider_installation_manifest
from trustai.provider_lifecycle import write_provider_lifecycle_manifest
from trustai.provider_lifecycle_operation import write_provider_lifecycle_operation_receipt


ROOT = Path(__file__).resolve().parents[1]


def _sources() -> tuple[dict, dict, dict, dict]:
    audit_log = _audit_log()
    installation = _provider_installation()
    lifecycle = _lifecycle(installation)
    correlation = _correlation(audit_log)
    stream = _stream(audit_log, installation, lifecycle, correlation)
    lifecycle_operation = _lifecycle_operation(lifecycle)
    worker = _worker(stream, correlation, lifecycle_operation, lifecycle)
    return installation, lifecycle, lifecycle_operation, worker


def _custody(
    installation: dict,
    lifecycle: dict,
    lifecycle_operation: dict,
    worker: dict,
    **overrides,
) -> dict:
    values = {
        "credential_ref": "env:GITHUB_AUDIT_LOG_TOKEN",
        "credential_kind": "audit_log_token",
        "custody_ref": "custody:github-audit-token:local",
        "vault_ref": "vault:trustai/provider-audit",
        "kms_provider": "TrustAI Provider Credential Vault",
        "kms_endpoint": "https://vault.example/provider-credentials",
        "key_ref": "kms:trustai/provider-audit-token",
        "key_algorithm": "HMAC-SHA256",
        "policy_ref": "policy:provider-audit-token-custody-v0.1",
        "policy_hash": "sha256:provider-audit-token-custody-policy",
        "rotation_ref": "rotation:github-audit-token:2026-07",
        "revocation_ref": "revocation:github-audit-token",
        "audit_log_ref": "audit-log:trustai/provider-credentials",
        "audit_log_root": "sha256:provider-credential-custody-root",
        "retention_until": "2033-07-08T00:00:00Z",
        "actor_ref": "oidc:trustai.example/provider-audit-worker",
        "allowed_actor_refs": ["oidc:trustai.example/provider-audit-worker"],
        "denied_operation_refs": ["vault:export-secret", "vault:plaintext-read"],
        "quorum_required": 1,
        "quorum_approver_refs": ["oidc:trustai.example/security-admin"],
        "provider_installation": installation,
        "lifecycle_manifest": lifecycle,
        "lifecycle_operation": lifecycle_operation,
        "audit_worker": worker,
        "attestation_ref": "hsm-attestation:trustai/provider-audit-token/2026-07-08",
        "attestation_hash": "sha256:provider-audit-token-attestation",
        "access_grant_ref": "grant:provider-audit-token:worker",
        "evidence_refs": ["evidence:provider-credential-custody/github-audit-token"],
        "response_status": 200,
        "response_hash": "sha256:provider-audit-token-vault-response",
        "mode": "kms-attested",
        "environment": "local",
        "issued_at": "2026-07-08T02:13:00Z",
    }
    values.update(overrides)
    return build_provider_credential_custody_receipt(**values)


class ProviderCredentialCustodyTests(unittest.TestCase):
    def test_provider_credential_custody_verifies_and_appends_to_chain(self):
        installation, lifecycle, lifecycle_operation, worker = _sources()
        receipt = _custody(installation, lifecycle, lifecycle_operation, worker)

        result = verify_provider_credential_custody_receipt(
            receipt,
            provider_installation=installation,
            lifecycle_manifest=lifecycle,
            lifecycle_operation=lifecycle_operation,
            audit_worker=worker,
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_CREDENTIAL_CUSTODY_SCHEMA, receipt["schema"])
        self.assertEqual("github", receipt["provider"])
        self.assertEqual("kms-attested", receipt["mode"])
        self.assertEqual("env:GITHUB_AUDIT_LOG_TOKEN", receipt["credential"]["ref"])
        self.assertIn("env:GITHUB_AUDIT_LOG_TOKEN", receipt["source_credential_refs"])
        self.assertTrue(any(control["id"] == "attested-custody" for control in receipt["controls"]))
        self.assertNotIn(WEBHOOK_SECRET, json.dumps(receipt, sort_keys=True))

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-credential-custody-test")
            entry = append_provider_credential_custody_receipt(
                chain,
                receipt,
                provider_installation=installation,
                lifecycle_manifest=lifecycle,
                lifecycle_operation=lifecycle_operation,
                audit_worker=worker,
            )

            self.assertEqual(PROVIDER_CREDENTIAL_CUSTODY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["custody_id"], entry["payload"]["custody_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_provider_credential_custody_rejects_unknown_credential_ref(self):
        installation, lifecycle, lifecycle_operation, worker = _sources()

        with self.assertRaises(ValueError):
            _custody(
                installation,
                lifecycle,
                lifecycle_operation,
                worker,
                credential_ref="env:UNRELATED_PROVIDER_TOKEN",
            )

    def test_cli_provider_credential_custody_round_trip(self):
        installation, lifecycle, lifecycle_operation, worker = _sources()

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            installation_path = tmp / "provider-installation.json"
            lifecycle_path = tmp / "provider-lifecycle.json"
            lifecycle_operation_path = tmp / "provider-lifecycle-operation.json"
            worker_path = tmp / "provider-audit-worker.json"
            receipt_path = tmp / "provider-credential-custody.json"
            entry_path = tmp / "provider-credential-custody-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_provider_installation_manifest(installation_path, installation)
            write_provider_lifecycle_manifest(lifecycle_path, lifecycle)
            write_provider_lifecycle_operation_receipt(lifecycle_operation_path, lifecycle_operation)
            write_provider_audit_worker_receipt(worker_path, worker)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            common_sources = [
                "--provider-installation",
                str(installation_path),
                "--lifecycle",
                str(lifecycle_path),
                "--lifecycle-operation",
                str(lifecycle_operation_path),
                "--audit-worker",
                str(worker_path),
            ]
            common_custody_args = [
                "--credential-ref",
                "env:GITHUB_AUDIT_LOG_TOKEN",
                "--credential-kind",
                "audit_log_token",
                "--custody-ref",
                "custody:github-audit-token:local",
                "--vault-ref",
                "vault:trustai/provider-audit",
                "--kms-provider",
                "TrustAI Provider Credential Vault",
                "--kms-endpoint",
                "https://vault.example/provider-credentials",
                "--key-ref",
                "kms:trustai/provider-audit-token",
                "--key-algorithm",
                "HMAC-SHA256",
                "--policy-ref",
                "policy:provider-audit-token-custody-v0.1",
                "--policy-hash",
                "sha256:provider-audit-token-custody-policy",
                "--rotation-ref",
                "rotation:github-audit-token:2026-07",
                "--revocation-ref",
                "revocation:github-audit-token",
                "--audit-log-ref",
                "audit-log:trustai/provider-credentials",
                "--audit-log-root",
                "sha256:provider-credential-custody-root",
                "--retention-until",
                "2033-07-08T00:00:00Z",
                "--actor-ref",
                "oidc:trustai.example/provider-audit-worker",
                "--allowed-actor-ref",
                "oidc:trustai.example/provider-audit-worker",
                "--denied-operation-ref",
                "vault:export-secret",
                "--denied-operation-ref",
                "vault:plaintext-read",
                "--quorum-required",
                "1",
                "--quorum-approver-ref",
                "oidc:trustai.example/security-admin",
                "--attestation-ref",
                "hsm-attestation:trustai/provider-audit-token/2026-07-08",
                "--attestation-hash",
                "sha256:provider-audit-token-attestation",
                "--access-grant-ref",
                "grant:provider-audit-token:worker",
                "--evidence-ref",
                "evidence:provider-credential-custody/github-audit-token",
                "--response-status",
                "200",
                "--response-hash",
                "sha256:provider-audit-token-vault-response",
                "--mode",
                "kms-attested",
                "--issued-at",
                "2026-07-08T02:13:00Z",
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-credential-custody",
                    *common_sources,
                    *common_custody_args,
                    "--out",
                    str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-credential-custody-verify", str(receipt_path), *common_sources],
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
                    "provider-credential-custody-append",
                    str(receipt_path),
                    *common_sources,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-credential-custody-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_provider_credential_custody_receipt(
            receipt,
            provider_installation=installation,
            lifecycle_manifest=lifecycle,
            lifecycle_operation=lifecycle_operation,
            audit_worker=worker,
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(receipt["custody_id"], entry["payload"]["custody_id"])


if __name__ == "__main__":
    unittest.main()
