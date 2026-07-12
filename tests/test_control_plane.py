import json
import tempfile
import unittest
from pathlib import Path

from trustai.control_plane import ControlPlane
from trustai.chain import EvidenceChain
from trustai.cicd import append_promotion_status_receipt, build_promotion_check_payload, build_promotion_status_receipt
from trustai.delivery import build_provider_delivery
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.registry import append_inventory, load_inventory
from trustai.anchor import append_anchor
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"
INVENTORY = ROOT / "examples" / "aitrade" / "agent-inventory.json"


class ControlPlaneTests(unittest.TestCase):
    def test_indexes_chain_and_proof_pack(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            append_inventory(chain, load_inventory(INVENTORY))
            results = json.loads(RESULTS.read_text(encoding="utf-8"))
            eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
            append_anchor(chain)
            chain.save()
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
            verification = verify_proof_pack(pack)
            payload = build_promotion_check_payload(
                pack,
                verification,
                provider="github",
                commit_sha="0123456789abcdef0123456789abcdef01234567",
                repository="volelabs/trust_ai",
                target_url="https://example.test/proof-pack",
            )
            delivery = build_provider_delivery(
                payload,
                endpoint_base="https://api.github.com",
                credential_ref="env:GITHUB_TOKEN",
                mode="dry-run",
                delivered_at="2026-07-04T00:00:00Z",
            )
            receipt = build_promotion_status_receipt(
                pack,
                verification,
                payload,
                delivery=delivery,
                attested_at="2026-07-04T00:01:00Z",
            )
            append_promotion_status_receipt(
                chain,
                receipt,
                proof_pack=pack,
                verification=verification,
                payload=payload,
                delivery=delivery,
            )
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                counts = control.index_chain(chain)
                control.index_proof_pack(pack, tmp / "pack.json")
                summary = control.summary()

                self.assertGreaterEqual(counts["chain_entries"], 5)
                self.assertEqual(1, summary["counts"]["contracts"])
                self.assertEqual(2, summary["counts"]["agents"])
                self.assertEqual(1, summary["counts"]["proof_packs"])
                self.assertEqual(1, summary["counts"]["anchors"])
                self.assertEqual(1, summary["counts"]["promotion_statuses"])
                self.assertEqual(1, counts["promotion_statuses"])
                self.assertEqual("passed", summary["latest_proof_pack"]["outcome"])
                self.assertEqual("github", summary["latest_promotion_status"]["provider"])
                self.assertTrue(summary["latest_promotion_status"]["passed"])
                self.assertEqual(2, len(control.agents()))
                self.assertEqual(1, len(control.recent_proof_packs()))
                statuses = control.recent_promotion_statuses()
                self.assertEqual(1, len(statuses))
                self.assertEqual("volelabs/trust_ai", statuses[0]["target_ref"]["repository"])
                self.assertTrue(statuses[0]["provider_status_success"])
            finally:
                control.close()


if __name__ == "__main__":
    unittest.main()
