import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests import test_trust_authority_provider
from trustai.chain import EvidenceChain
from trustai.keyring import write_keyring
from trustai.trust_authority import write_trust_authority_receipt
from trustai.trust_authority_kms_enforcement import (
    TRUST_AUTHORITY_KMS_ENFORCEMENT_ENTRY_TYPE,
    TRUST_AUTHORITY_KMS_ENFORCEMENT_SCHEMA,
    append_trust_authority_kms_enforcement_receipt,
    build_trust_authority_kms_enforcement_receipt,
    verify_trust_authority_kms_enforcement_receipt,
)
from trustai.trust_authority_provider import write_trust_authority_provider_attestation


ROOT = Path(__file__).resolve().parents[1]


class TrustAuthorityKmsEnforcementTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        provider_tests = test_trust_authority_provider.TrustAuthorityProviderTests()
        source_chain, keyring, pack, trust_authority = provider_tests._sources(tmp)
        provider = provider_tests._attestation(source_chain, keyring, pack, trust_authority)
        return source_chain, keyring, pack, trust_authority, provider

    def _receipt(self, source_chain, keyring, pack, trust_authority, provider, **overrides):
        values = {
            "provider_attestation": provider,
            "trust_authority_receipt": trust_authority,
            "source_chain": source_chain,
            "keyring": keyring,
            "proof_pack": pack,
            "mode": "provider-enforced",
            "enforcement_ref": "kms-enforcement:trust-authority/provider/2026-07-04",
            "provider": "Example Cloud HSM",
            "provider_endpoint": "https://kms.example/enforcement/trust-authority",
            "credential_ref": "env:TRUST_AUTHORITY_KMS_TOKEN",
            "actor_ref": "oidc:trustai.example/trust-authority-kms-worker",
            "hsm_attestation_ref": "hsm-attestation:example/trust-authority/2026-07-04",
            "hsm_attestation_hash": "sha256:trust-authority-hsm-attestation",
            "key_policy_ref": "policy:kms/trustai-evidence-signing-v0.1",
            "key_policy_hash": "sha256:kms-key-policy",
            "timestamp_policy_ref": "policy:tsa/trustai-timestamping-v0.1",
            "timestamp_policy_hash": "sha256:tsa-policy",
            "timestamp_attestation_ref": "tsa-attestation:example/trust-authority/2026-07-04",
            "timestamp_attestation_hash": "sha256:trust-authority-tsa-attestation",
            "allowed_actor_refs": ["oidc:trustai.example/trust-authority-kms-worker"],
            "denied_operation_refs": ["kms:decrypt", "kms:export-private-key", "tsa:backdate"],
            "quorum_required": 2,
            "quorum_approver_refs": ["oidc:trustai.example/security-admin", "oidc:trustai.example/compliance-admin"],
            "rotation_ref": "rotation:trust-authority/evidence-signing/2026-Q3",
            "revocation_ref": "revocation:trust-authority/evidence-signing",
            "audit_log_ref": "audit-log:trust-authority/provider",
            "audit_log_root": "sha256:trust-authority-provider-audit-root",
            "audit_log_size": 7,
            "evidence_refs": ["evidence:trust-authority/kms-enforcement"],
            "response_status": 200,
            "response_body": {"status": "enforced", "key_ref": "kms:example/trustai/evidence-signing"},
            "enforced_at": "2026-07-04T03:02:00Z",
        }
        values.update(overrides)
        return build_trust_authority_kms_enforcement_receipt(**values)

    def test_trust_authority_kms_enforcement_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_chain, keyring, pack, trust_authority, provider = self._sources(Path(tmp_dir))
            receipt = self._receipt(source_chain, keyring, pack, trust_authority, provider)
            result = verify_trust_authority_kms_enforcement_receipt(
                receipt,
                provider_attestation=provider,
                trust_authority_receipt=trust_authority,
                source_chain=source_chain,
                keyring=keyring,
                proof_pack=pack,
            )
            chain = EvidenceChain.load(Path(tmp_dir) / "trust-authority-kms-chain.json", tenant_id="trust-authority-kms-local")
            entry = append_trust_authority_kms_enforcement_receipt(
                chain,
                receipt,
                provider_attestation=provider,
                trust_authority_receipt=trust_authority,
                source_chain=source_chain,
                keyring=keyring,
                proof_pack=pack,
            )

            self.assertEqual(TRUST_AUTHORITY_KMS_ENFORCEMENT_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("provider-enforced", result.mode)
            self.assertEqual(TRUST_AUTHORITY_KMS_ENFORCEMENT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["enforcement_id"], entry["payload"]["enforcement_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_trust_authority_kms_enforcement_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_chain, keyring, pack, trust_authority, provider = self._sources(Path(tmp_dir))
            receipt = self._receipt(source_chain, keyring, pack, trust_authority, provider)
            tampered = copy.deepcopy(receipt)
            tampered["source_artifacts"][0]["content_hash"] = "changed"

            result = verify_trust_authority_kms_enforcement_receipt(
                tampered,
                provider_attestation=provider,
                trust_authority_receipt=trust_authority,
                source_chain=source_chain,
                keyring=keyring,
                proof_pack=pack,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("enforcement_id" in error for error in result.errors))
            self.assertTrue(any("source artifact trust_authority_provider_attestation content_hash mismatch" in error for error in result.errors))

    def test_trust_authority_kms_enforcement_requires_quorum(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_chain, keyring, pack, trust_authority, provider = self._sources(Path(tmp_dir))
            with self.assertRaisesRegex(ValueError, "quorum_approver_refs"):
                self._receipt(
                    source_chain,
                    keyring,
                    pack,
                    trust_authority,
                    provider,
                    quorum_required=2,
                    quorum_approver_refs=["oidc:trustai.example/security-admin"],
                )

    def test_cli_trust_authority_kms_enforcement_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            source_chain, keyring, pack, trust_authority, provider = self._sources(tmp)
            source_state = tmp / "source-chain.json"
            keyring_path = tmp / "keyring.json"
            pack_path = tmp / "pack.json"
            trust_authority_path = tmp / "trust-authority-receipt.json"
            provider_path = tmp / "trust-authority-provider-attestation.json"
            enforcement_path = tmp / "trust-authority-kms-enforcement.json"
            entry_path = tmp / "trust-authority-kms-enforcement-entry.json"
            enforcement_state = tmp / "trust-authority-kms-chain.json"
            response_body_path = tmp / "kms-response.json"
            source_chain.save()
            write_keyring(keyring_path, keyring)
            write_trust_authority_receipt(trust_authority_path, trust_authority)
            write_trust_authority_provider_attestation(provider_path, provider)
            pack_path.write_text(json.dumps(pack, indent=2, sort_keys=True), encoding="utf-8")
            response_body_path.write_text(json.dumps({"status": "enforced", "key_ref": "kms:example/trustai/evidence-signing"}), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                str(provider_path),
                str(trust_authority_path),
                "--source-state",
                str(source_state),
                "--source-tenant",
                "test",
                "--keyring",
                str(keyring_path),
                "--pack",
                str(pack_path),
            ]
            enforcement_args = [
                "--mode",
                "provider-enforced",
                "--enforcement-ref",
                "kms-enforcement:trust-authority/provider/2026-07-04",
                "--provider",
                "Example Cloud HSM",
                "--provider-endpoint",
                "https://kms.example/enforcement/trust-authority",
                "--credential-ref",
                "env:TRUST_AUTHORITY_KMS_TOKEN",
                "--actor-ref",
                "oidc:trustai.example/trust-authority-kms-worker",
                "--hsm-attestation-ref",
                "hsm-attestation:example/trust-authority/2026-07-04",
                "--hsm-attestation-hash",
                "sha256:trust-authority-hsm-attestation",
                "--key-policy-ref",
                "policy:kms/trustai-evidence-signing-v0.1",
                "--key-policy-hash",
                "sha256:kms-key-policy",
                "--timestamp-policy-ref",
                "policy:tsa/trustai-timestamping-v0.1",
                "--timestamp-policy-hash",
                "sha256:tsa-policy",
                "--timestamp-attestation-ref",
                "tsa-attestation:example/trust-authority/2026-07-04",
                "--timestamp-attestation-hash",
                "sha256:trust-authority-tsa-attestation",
                "--allowed-actor-ref",
                "oidc:trustai.example/trust-authority-kms-worker",
                "--denied-operation-ref",
                "kms:export-private-key",
                "--quorum-required",
                "2",
                "--quorum-approver-ref",
                "oidc:trustai.example/security-admin",
                "--quorum-approver-ref",
                "oidc:trustai.example/compliance-admin",
                "--audit-log-ref",
                "audit-log:trust-authority/provider",
                "--audit-log-root",
                "sha256:trust-authority-provider-audit-root",
                "--audit-log-size",
                "7",
                "--evidence-ref",
                "evidence:trust-authority/kms-enforcement",
                "--response-status",
                "200",
                "--response-body",
                str(response_body_path),
                "--enforced-at",
                "2026-07-04T03:02:00Z",
            ]
            subprocess.run([sys.executable, "-m", "trustai", "trust-authority-kms-enforcement", *source_args, *enforcement_args, "--out", str(enforcement_path)], cwd=ROOT, env=env, check=True)
            subprocess.run([sys.executable, "-m", "trustai", "trust-authority-kms-enforcement-verify", str(enforcement_path), *source_args], cwd=ROOT, env=env, check=True)
            subprocess.run([sys.executable, "-m", "trustai", "trust-authority-kms-enforcement-append", str(enforcement_path), *source_args, "--state", str(enforcement_state), "--tenant", "trust-authority-kms-local", "--out", str(entry_path)], cwd=ROOT, env=env, check=True)

            self.assertTrue(enforcement_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()