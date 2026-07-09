import copy
import json
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.identity_provider_attestation import (
    IDENTITY_PROVIDER_ATTESTATION_ENTRY_TYPE,
    IDENTITY_PROVIDER_ATTESTATION_SCHEMA,
    append_identity_provider_attestation,
    build_identity_provider_attestation,
    verify_identity_provider_attestation,
)
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.trust_network import build_trust_network_manifest
from trustai.vendor_identity import build_vendor_identity_receipt


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
IDENTITY = ROOT / "examples" / "aitrade" / "identity-inventory.json"


class IdentityProviderAttestationTests(unittest.TestCase):
    def _proof_sources(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="identity-provider-test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        append_runtime_attestation(chain, contract, load_action(ACTION))
        shadow = load_shadow_replay(SHADOW)
        append_shadow_replay(chain, contract, shadow)
        append_soak_report(chain, contract, load_soak_window(SOAK))
        eval_entry, gate_entry, decision = append_eval_and_gate(
            chain,
            contract,
            shadow_replay_to_eval_results(contract, shadow),
        )
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
        manifest = build_trust_network_manifest([pack], vendor_names=["aitrade"], buyer="finserv-buyer")
        vendor = build_vendor_identity_receipt(
            [pack],
            vendor="aitrade",
            legal_name="Aitrade Labs Inc.",
            subject_ref="did:web:aitrade.example",
            domain="aitrade.example",
            identity_provider="okta",
            identity_id="okta-agent-aitrade-risk",
            issued_at="2026-07-10T00:00:00Z",
            expires_at="2027-07-10T00:00:00Z",
            trust_network_manifest=manifest,
        )
        payload = json.loads(IDENTITY.read_text(encoding="utf-8"))
        return payload, pack, manifest, vendor

    def test_identity_provider_attestation_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            payload, pack, manifest, vendor = self._proof_sources(tmp)
            attestation = build_identity_provider_attestation(
                payload,
                vendor_identity_receipt=vendor,
                proof_packs=[pack],
                trust_network_manifest=manifest,
                provider="okta",
                identity_id="okta-agent-aitrade-risk",
                issuer="trustai-local",
                tenant_ref="okta:example-org",
                issued_at="2026-07-10T01:00:00Z",
                expires_at="2027-07-10T01:00:00Z",
            )

            result = verify_identity_provider_attestation(
                attestation,
                identity_payload=payload,
                vendor_identity_receipt=vendor,
                proof_packs=[pack],
                trust_network_manifest=manifest,
            )
            chain = EvidenceChain.load(tmp / "identity-chain.json", tenant_id="identity-provider-local")
            entry = append_identity_provider_attestation(
                chain,
                attestation,
                identity_payload=payload,
                vendor_identity_receipt=vendor,
                proof_packs=[pack],
                trust_network_manifest=manifest,
            )

            self.assertEqual(IDENTITY_PROVIDER_ATTESTATION_SCHEMA, attestation["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("okta-agent-aitrade-risk", attestation["subject"]["identity_id"])
            self.assertTrue(attestation["vendor_binding"]["provider_identity_matches_vendor"])
            self.assertEqual(IDENTITY_PROVIDER_ATTESTATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])

    def test_identity_provider_attestation_detects_subject_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload, pack, manifest, vendor = self._proof_sources(Path(tmp_dir))
            attestation = build_identity_provider_attestation(
                payload,
                vendor_identity_receipt=vendor,
                proof_packs=[pack],
                trust_network_manifest=manifest,
                provider="okta",
                identity_id="okta-agent-aitrade-risk",
                issued_at="2026-07-10T01:00:00Z",
            )
            tampered = copy.deepcopy(attestation)
            tampered["subject"]["agent"]["name"] = "changed-agent"

            result = verify_identity_provider_attestation(
                tampered,
                identity_payload=payload,
                vendor_identity_receipt=vendor,
                proof_packs=[pack],
                trust_network_manifest=manifest,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("attestation_id" in error for error in result.errors))
            self.assertTrue(any("subject agent summary" in error for error in result.errors))

    def test_identity_provider_attestation_rejects_missing_subject(self):
        payload = json.loads(IDENTITY.read_text(encoding="utf-8"))

        with self.assertRaisesRegex(ValueError, "did not contain the requested subject"):
            build_identity_provider_attestation(
                payload,
                provider="okta",
                identity_id="missing-agent",
            )


if __name__ == "__main__":
    unittest.main()
