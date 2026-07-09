import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.anchor import append_anchor, write_anchor
from trustai.anchor_provider import (
    ANCHOR_PROVIDER_ENTRY_TYPE,
    ANCHOR_PROVIDER_SCHEMA,
    append_anchor_provider_receipt,
    build_anchor_provider_receipt,
    verify_anchor_provider_receipt,
)
from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"


class AnchorProviderTests(unittest.TestCase):
    def _source_chain(self, tmp: Path):
        source_chain = EvidenceChain.load(tmp / "source-chain.json", tenant_id="anchor-provider-source")
        register_contract(source_chain, load_contract(CONTRACT))
        anchor_entry = append_anchor(source_chain)
        source_chain.save()
        return source_chain, anchor_entry

    def _receipt(self, source_chain, anchor_entry, **overrides):
        values = {
            "anchor_entry": anchor_entry,
            "source_chain": source_chain,
            "mode": "provider-anchored",
            "environment": "local",
            "provider": "TrustAI Public Transparency Log",
            "endpoint": "https://transparency.example/anchors",
            "publication_ref": "publog:trustai/anchor/2026-07-04",
            "request_hash": "sha256:anchor-provider-request",
            "response_status": 201,
            "response_hash": "sha256:anchor-provider-response",
            "public_log_ref": "rekor:trustai-public-log",
            "public_log_root": "sha256:trustai-public-log-root",
            "public_log_size": 1234,
            "public_log_entry_ref": "rekor-entry:trustai-anchor-aitrade-local",
            "inclusion_proof_hash": "sha256:anchor-provider-inclusion-proof",
            "consistency_proof_hash": "sha256:anchor-provider-consistency-proof",
            "witness_refs": ["witness:lf-trustai", "witness:sigstore"],
            "actor_ref": "oidc:trustai.example/anchor-publisher",
            "credential_ref": "env:ANCHOR_PROVIDER_TOKEN",
            "audit_log_ref": "audit-log:anchor-provider/publication",
            "audit_log_root": "sha256:anchor-provider-audit-root",
            "retention_until": "2033-07-04T00:00:00Z",
            "evidence_refs": ["evidence:anchor-provider/public-log"],
            "published_at": "2026-07-04T00:10:00Z",
        }
        values.update(overrides)
        return build_anchor_provider_receipt(**values)

    def test_anchor_provider_receipt_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            source_chain, anchor_entry = self._source_chain(tmp)
            receipt = self._receipt(source_chain, anchor_entry)

            result = verify_anchor_provider_receipt(receipt, anchor_entry, source_chain=source_chain)
            chain = EvidenceChain.load(tmp / "provider-chain.json", tenant_id="anchor-provider-test")
            entry = append_anchor_provider_receipt(chain, receipt, anchor_entry, source_chain=source_chain)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(ANCHOR_PROVIDER_SCHEMA, receipt["schema"])
            self.assertEqual("provider-anchored", receipt["mode"])
            self.assertEqual("env:ANCHOR_PROVIDER_TOKEN", receipt["operation"]["credential"]["ref"])
            self.assertEqual(ANCHOR_PROVIDER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_anchor_provider_receipt_rejects_public_log_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_chain, anchor_entry = self._source_chain(Path(tmp_dir))
            receipt = self._receipt(source_chain, anchor_entry)
            tampered = copy.deepcopy(receipt)
            tampered["public_log"]["root"] = "not-a-hash"

            result = verify_anchor_provider_receipt(tampered, anchor_entry, source_chain=source_chain)

            self.assertFalse(result.ok)
            self.assertIn("receipt_id does not match canonical anchor provider receipt body", result.errors)
            self.assertIn("anchor provider public_log.root must be a sha256 reference", result.errors)

    def test_anchor_provider_receipt_rejects_source_chain_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            source_chain, anchor_entry = self._source_chain(tmp)
            receipt = self._receipt(source_chain, anchor_entry)
            other_chain = EvidenceChain.load(tmp / "other-source-chain.json", tenant_id="other-source")
            register_contract(other_chain, load_contract(CONTRACT))

            result = verify_anchor_provider_receipt(receipt, anchor_entry, source_chain=other_chain)

            self.assertFalse(result.ok)
            self.assertTrue(any("source chain invalid" in error for error in result.errors))
            self.assertIn("anchor provider source_artifacts do not match supplied source artifacts", result.errors)

    def test_cli_anchor_provider_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            source_chain, anchor_entry = self._source_chain(tmp)
            source_state = tmp / "source-chain.json"
            anchor_path = tmp / "chain-anchor.json"
            receipt_path = tmp / "chain-anchor-provider.json"
            entry_path = tmp / "chain-anchor-provider-entry.json"
            provider_state = tmp / "anchor-provider-chain.json"
            source_chain.save()
            write_anchor(anchor_path, anchor_entry)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = [
                str(anchor_path),
                "--source-state",
                str(source_state),
                "--source-tenant",
                "anchor-provider-source",
            ]
            provider_args = [
                "--provider",
                "TrustAI Public Transparency Log",
                "--endpoint",
                "https://transparency.example/anchors",
                "--publication-ref",
                "publog:trustai/anchor/2026-07-04",
                "--request-hash",
                "sha256:anchor-provider-request",
                "--response-status",
                "201",
                "--response-hash",
                "sha256:anchor-provider-response",
                "--public-log-ref",
                "rekor:trustai-public-log",
                "--public-log-root",
                "sha256:trustai-public-log-root",
                "--public-log-size",
                "1234",
                "--public-log-entry-ref",
                "rekor-entry:trustai-anchor-aitrade-local",
                "--inclusion-proof-hash",
                "sha256:anchor-provider-inclusion-proof",
                "--consistency-proof-hash",
                "sha256:anchor-provider-consistency-proof",
                "--witness-ref",
                "witness:sigstore",
                "--witness-ref",
                "witness:lf-trustai",
                "--actor-ref",
                "oidc:trustai.example/anchor-publisher",
                "--credential-ref",
                "env:ANCHOR_PROVIDER_TOKEN",
                "--audit-log-ref",
                "audit-log:anchor-provider/publication",
                "--audit-log-root",
                "sha256:anchor-provider-audit-root",
                "--retention-until",
                "2033-07-04T00:00:00Z",
                "--evidence-ref",
                "evidence:anchor-provider/public-log",
                "--published-at",
                "2026-07-04T00:10:00Z",
            ]

            subprocess.run(
                base + ["anchor-provider-receipt", *source_args, *provider_args, "--out", str(receipt_path)],
                check=True,
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            subprocess.run(
                base + ["anchor-provider-verify", str(receipt_path), *source_args],
                check=True,
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            subprocess.run(
                base
                + [
                    "anchor-provider-append",
                    str(receipt_path),
                    *source_args,
                    "--state",
                    str(provider_state),
                    "--tenant",
                    "anchor-provider-cli",
                    "--out",
                    str(entry_path),
                ],
                check=True,
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )

            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            chain = EvidenceChain.load(provider_state)
            self.assertEqual(ANCHOR_PROVIDER_ENTRY_TYPE, entry["entry_type"])
            self.assertTrue(chain.verify_all().ok)


if __name__ == "__main__":
    unittest.main()
