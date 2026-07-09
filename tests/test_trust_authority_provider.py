import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.keyring import local_dev_keyring, write_keyring
from trustai.proofpack import compile_proof_pack
from trustai.trust_authority import build_trust_authority_receipt, write_trust_authority_receipt
from trustai.trust_authority_provider import (
    TRUST_AUTHORITY_PROVIDER_ENTRY_TYPE,
    TRUST_AUTHORITY_PROVIDER_SCHEMA,
    append_trust_authority_provider_attestation,
    build_trust_authority_provider_attestation,
    verify_trust_authority_provider_attestation,
    write_trust_authority_provider_attestation,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"


def _sha256_ref(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class TrustAuthorityProviderTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        source_chain = EvidenceChain.load(tmp / "source-chain.json", tenant_id="test")
        contract = load_contract(CONTRACT)
        register_contract(source_chain, contract)
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        eval_entry, gate_entry, decision = append_eval_and_gate(source_chain, contract, results)
        source_chain.save()
        pack = compile_proof_pack(
            source_chain,
            contract,
            eval_entry,
            gate_entry,
            decision,
            out_path=tmp / "pack.json",
        )
        keyring = local_dev_keyring(tenant_id="test")
        trust_authority = build_trust_authority_receipt(source_chain, keyring, proof_pack=pack, generated_at="2026-07-04T03:00:00Z")
        return source_chain, keyring, pack, trust_authority

    def _provider_artifacts(self, tmp: Path) -> dict[str, Path | str]:
        kms_request = tmp / "kms-sign-request.json"
        kms_response = tmp / "kms-sign-response.json"
        tsa_request = tmp / "tsa-request.tsq"
        tsa_response = tmp / "tsa-response.tsr"
        tsa_certificate_chain = tmp / "tsa-certificate-chain.pem"
        kms_request.write_text(json.dumps({"operation": "sign", "key": "kms:example/trustai/evidence-signing", "digest": "trust-authority-receipt"}, sort_keys=True), encoding="utf-8")
        kms_response.write_text(json.dumps({"status": "signed", "signature_ref": "kms-signature:trust-authority/2026-07-04"}, sort_keys=True), encoding="utf-8")
        tsa_request.write_bytes(b"trustai-rfc3161-request\n")
        tsa_response.write_bytes(b"trustai-rfc3161-response\n")
        tsa_certificate_chain.write_text("-----BEGIN CERTIFICATE-----\nTRUSTAI-TSA\n-----END CERTIFICATE-----\n", encoding="utf-8")
        return {
            "kms_request_path": kms_request,
            "kms_response_path": kms_response,
            "tsa_request_path": tsa_request,
            "tsa_response_path": tsa_response,
            "tsa_certificate_chain_path": tsa_certificate_chain,
            "kms_request_hash": _sha256_ref(kms_request),
            "kms_response_hash": _sha256_ref(kms_response),
            "tsa_request_hash": _sha256_ref(tsa_request),
            "tsa_response_hash": _sha256_ref(tsa_response),
            "tsa_certificate_chain_hash": _sha256_ref(tsa_certificate_chain),
        }

    def _attestation(self, source_chain, keyring, pack, trust_authority, **overrides):
        values = {
            "trust_authority_receipt": trust_authority,
            "source_chain": source_chain,
            "keyring": keyring,
            "proof_pack": pack,
            "mode": "provider-attested",
            "environment": "local",
            "kms_provider": "Example Cloud KMS",
            "kms_endpoint": "https://kms.example/sign",
            "kms_key_ref": "kms:example/trustai/evidence-signing",
            "kms_key_algorithm": "HMAC-SHA256",
            "kms_request_hash": "sha256:kms-sign-request",
            "kms_response_status": 200,
            "kms_response_hash": "sha256:kms-sign-response",
            "tsa_provider": "Example RFC3161 TSA",
            "tsa_endpoint": "https://tsa.example/timestamp",
            "tsa_request_hash": "sha256:tsa-request",
            "tsa_response_status": 200,
            "tsa_response_hash": "sha256:tsa-response",
            "tsa_certificate_chain_hash": "sha256:tsa-certificate-chain",
            "actor_ref": "oidc:trustai.example/trust-authority-worker",
            "credential_ref": "env:TRUST_AUTHORITY_PROVIDER_TOKEN",
            "audit_log_ref": "audit-log:trust-authority/provider",
            "audit_log_root": "sha256:trust-authority-provider-audit-root",
            "retention_until": "2033-07-04T00:00:00Z",
            "key_policy_ref": "policy:kms/trustai-evidence-signing-v0.1",
            "key_policy_hash": "sha256:kms-key-policy",
            "timestamp_policy_ref": "policy:tsa/trustai-timestamping-v0.1",
            "timestamp_policy_hash": "sha256:tsa-policy",
            "evidence_refs": ["evidence:trust-authority/provider"],
            "attested_at": "2026-07-04T03:01:00Z",
        }
        values.update(overrides)
        return build_trust_authority_provider_attestation(**values)

    def test_trust_authority_provider_attestation_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            source_chain, keyring, pack, trust_authority = self._sources(tmp)
            provider_artifacts = self._provider_artifacts(tmp)
            attestation = self._attestation(source_chain, keyring, pack, trust_authority, **provider_artifacts)

            result = verify_trust_authority_provider_attestation(
                attestation,
                trust_authority,
                source_chain,
                keyring,
                proof_pack=pack,
                kms_request_path=provider_artifacts["kms_request_path"],
                kms_response_path=provider_artifacts["kms_response_path"],
                tsa_request_path=provider_artifacts["tsa_request_path"],
                tsa_response_path=provider_artifacts["tsa_response_path"],
                tsa_certificate_chain_path=provider_artifacts["tsa_certificate_chain_path"],
            )
            chain = EvidenceChain.load(tmp / "provider-chain.json", tenant_id="trust-authority-provider-test")
            entry = append_trust_authority_provider_attestation(
                chain,
                attestation,
                trust_authority,
                source_chain,
                keyring,
                proof_pack=pack,
                kms_request_path=provider_artifacts["kms_request_path"],
                kms_response_path=provider_artifacts["kms_response_path"],
                tsa_request_path=provider_artifacts["tsa_request_path"],
                tsa_response_path=provider_artifacts["tsa_response_path"],
                tsa_certificate_chain_path=provider_artifacts["tsa_certificate_chain_path"],
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(TRUST_AUTHORITY_PROVIDER_SCHEMA, attestation["schema"])
            self.assertEqual("provider-attested", attestation["mode"])
            self.assertEqual("https://kms.example/sign", attestation["kms"]["endpoint"])
            self.assertEqual("env:TRUST_AUTHORITY_PROVIDER_TOKEN", attestation["operation"]["credential"]["ref"])
            self.assertEqual(5, len(attestation["provider_artifacts"]))
            self.assertIn("provider-artifact-replay", {control["id"] for control in attestation["controls"]})
            self.assertEqual(TRUST_AUTHORITY_PROVIDER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_trust_authority_provider_rejects_artifact_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            source_chain, keyring, pack, trust_authority = self._sources(tmp)
            provider_artifacts = self._provider_artifacts(tmp)
            provider_artifacts["kms_request_hash"] = "sha256:not-the-request"

            with self.assertRaisesRegex(ValueError, "kms_request artifact hash does not match recorded provider hash"):
                self._attestation(source_chain, keyring, pack, trust_authority, **provider_artifacts)

    def test_trust_authority_provider_detects_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            source_chain, keyring, pack, trust_authority = self._sources(tmp)
            provider_artifacts = self._provider_artifacts(tmp)
            attestation = self._attestation(source_chain, keyring, pack, trust_authority, **provider_artifacts)
            Path(provider_artifacts["tsa_response_path"]).write_bytes(b"tampered-tsa-response\n")

            result = verify_trust_authority_provider_attestation(
                attestation,
                trust_authority,
                source_chain,
                keyring,
                proof_pack=pack,
                kms_request_path=provider_artifacts["kms_request_path"],
                kms_response_path=provider_artifacts["kms_response_path"],
                tsa_request_path=provider_artifacts["tsa_request_path"],
                tsa_response_path=provider_artifacts["tsa_response_path"],
                tsa_certificate_chain_path=provider_artifacts["tsa_certificate_chain_path"],
            )

            self.assertFalse(result.ok)
            self.assertIn("trust authority provider provider_artifacts do not match supplied provider artifacts", result.errors)
            self.assertIn("trust authority provider tsa_response artifact hash does not match recorded provider hash", result.errors)

    def test_trust_authority_provider_attestation_rejects_non_https_tsa_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_chain, keyring, pack, trust_authority = self._sources(Path(tmp_dir))
            attestation = self._attestation(source_chain, keyring, pack, trust_authority)
            tampered = copy.deepcopy(attestation)
            tampered["timestamp_authority"]["endpoint"] = "http://tsa.example/timestamp"

            result = verify_trust_authority_provider_attestation(
                tampered,
                trust_authority,
                source_chain,
                keyring,
                proof_pack=pack,
            )

            self.assertFalse(result.ok)
            self.assertIn("trust authority provider timestamp_authority.endpoint must use HTTPS", result.errors)

    def test_trust_authority_provider_attestation_rejects_source_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_chain, keyring, pack, trust_authority = self._sources(Path(tmp_dir))
            attestation = self._attestation(source_chain, keyring, pack, trust_authority)
            tampered = copy.deepcopy(attestation)
            tampered["source_artifacts"][0]["source_hash"] = "changed"

            result = verify_trust_authority_provider_attestation(
                tampered,
                trust_authority,
                source_chain,
                keyring,
                proof_pack=pack,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("attestation_id" in error for error in result.errors))
            self.assertIn("trust authority provider source_artifacts do not match supplied source artifacts", result.errors)

    def test_cli_trust_authority_provider_attestation_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            source_chain, keyring, pack, trust_authority = self._sources(tmp)
            trust_authority_path = tmp / "trust-authority-receipt.json"
            keyring_path = tmp / "keyring.json"
            pack_path = tmp / "pack.json"
            source_state = tmp / "source-chain.json"
            attestation_path = tmp / "trust-authority-provider-attestation.json"
            entry_path = tmp / "trust-authority-provider-entry.json"
            provider_state = tmp / "provider-chain.json"
            source_chain.save()
            write_keyring(keyring_path, keyring)
            write_trust_authority_receipt(trust_authority_path, trust_authority)
            pack_path.write_text(json.dumps(pack, indent=2, sort_keys=True), encoding="utf-8")
            provider_artifacts = self._provider_artifacts(tmp)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
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
            replay_args = [
                "--kms-request",
                str(provider_artifacts["kms_request_path"]),
                "--kms-response",
                str(provider_artifacts["kms_response_path"]),
                "--tsa-request",
                str(provider_artifacts["tsa_request_path"]),
                "--tsa-response",
                str(provider_artifacts["tsa_response_path"]),
                "--tsa-certificate-chain",
                str(provider_artifacts["tsa_certificate_chain_path"]),
            ]
            provider_args = [
                "--kms-provider",
                "Example Cloud KMS",
                "--kms-endpoint",
                "https://kms.example/sign",
                "--kms-key-ref",
                "kms:example/trustai/evidence-signing",
                "--kms-request-hash",
                provider_artifacts["kms_request_hash"],
                "--kms-response-status",
                "200",
                "--kms-response-hash",
                provider_artifacts["kms_response_hash"],
                "--tsa-provider",
                "Example RFC3161 TSA",
                "--tsa-endpoint",
                "https://tsa.example/timestamp",
                "--tsa-request-hash",
                provider_artifacts["tsa_request_hash"],
                "--tsa-response-status",
                "200",
                "--tsa-response-hash",
                provider_artifacts["tsa_response_hash"],
                "--tsa-certificate-chain-hash",
                provider_artifacts["tsa_certificate_chain_hash"],
                "--actor-ref",
                "oidc:trustai.example/trust-authority-worker",
                "--credential-ref",
                "env:TRUST_AUTHORITY_PROVIDER_TOKEN",
                "--audit-log-ref",
                "audit-log:trust-authority/provider",
                "--audit-log-root",
                "sha256:trust-authority-provider-audit-root",
                "--retention-until",
                "2033-07-04T00:00:00Z",
                "--key-policy-ref",
                "policy:kms/trustai-evidence-signing-v0.1",
                "--key-policy-hash",
                "sha256:kms-key-policy",
                "--timestamp-policy-ref",
                "policy:tsa/trustai-timestamping-v0.1",
                "--timestamp-policy-hash",
                "sha256:tsa-policy",
                "--evidence-ref",
                "evidence:trust-authority/provider",
                "--mode",
                "provider-attested",
                "--attested-at",
                "2026-07-04T03:01:00Z",
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "trust-authority-provider-attestation",
                    *source_args,
                    *provider_args,
                    *replay_args,
                    "--out",
                    str(attestation_path),
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
                    "trust-authority-provider-verify",
                    str(attestation_path),
                    *source_args,
                    *replay_args,
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
                    "trust-authority-provider-append",
                    str(attestation_path),
                    *source_args,
                    *replay_args,
                    "--state",
                    str(provider_state),
                    "--tenant",
                    "trust-authority-provider-local",
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
