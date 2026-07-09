import copy
import tempfile
import unittest
from pathlib import Path

from trustai.actuarial import (
    ACTUARIAL_PRODUCT_ENTRY_TYPE,
    ACTUARIAL_PRODUCT_SCHEMA,
    build_actuarial_corpus,
    build_actuarial_product,
    append_actuarial_product,
    verify_actuarial_corpus,
    verify_actuarial_product,
)
from trustai.chain import EvidenceChain
from trustai.consent import append_consent_grant, load_consent
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.lifecycle import append_incident, load_incident
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
CONSENT = ROOT / "examples" / "aitrade" / "insurer-consent.json"
INCIDENT = ROOT / "examples" / "aitrade" / "incident.json"


class ActuarialProductTests(unittest.TestCase):
    def _chain_pack_corpus(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="actuarial-test")
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
        consent = load_consent(CONSENT)
        append_consent_grant(chain, consent)
        append_incident(chain, load_incident(INCIDENT))
        corpus = build_actuarial_corpus(
            chain,
            [pack],
            consent_id=consent["consent_id"],
            require_consent=True,
            now="2026-07-05T00:00:00Z",
            anonymization_salt="actuarial-test-salt",
        )
        return chain, corpus

    def test_actuarial_product_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, corpus = self._chain_pack_corpus(Path(tmp_dir))
            product = build_actuarial_product(
                [corpus],
                product_name="TrustAI reliability benchmark",
                publisher="trustai-local",
                issued_at="2026-07-06T00:00:00Z",
            )
            corpus_result = verify_actuarial_corpus(corpus)
            product_result = verify_actuarial_product(product, corpora=[corpus])
            entry = append_actuarial_product(chain, product, corpora=[corpus])

            self.assertTrue(corpus_result.ok, corpus_result.errors)
            self.assertEqual(ACTUARIAL_PRODUCT_SCHEMA, product["schema"])
            self.assertTrue(product_result.ok, product_result.errors)
            self.assertEqual(1, product["longitudinal"]["corpus_count"])
            self.assertEqual(1, product["aggregate"]["incident_count"])
            self.assertEqual(ACTUARIAL_PRODUCT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(product["product_id"], entry["payload"]["product_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_actuarial_product_detects_tampered_aggregate(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, corpus = self._chain_pack_corpus(Path(tmp_dir))
            product = build_actuarial_product([corpus], issued_at="2026-07-06T00:00:00Z")
            tampered = copy.deepcopy(product)
            tampered["aggregate"]["incident_count"] = 0

            result = verify_actuarial_product(tampered, corpora=[corpus])

            self.assertFalse(result.ok)
            self.assertIn("product_id does not match canonical product body", result.errors)
            self.assertIn("actuarial product aggregate does not match supplied corpora", result.errors)

    def test_actuarial_product_enforces_minimum_record_count(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, corpus = self._chain_pack_corpus(Path(tmp_dir))
            with self.assertRaisesRegex(ValueError, "minimum_record_count"):
                build_actuarial_product([corpus], minimum_record_count=2)


if __name__ == "__main__":
    unittest.main()
