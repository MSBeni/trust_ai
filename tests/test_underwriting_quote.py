import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.consent import INSURER_SCOPE, append_consent_grant, consent_status, load_consent
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.insurer import build_insurer_telemetry
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.underwriting_quote import (
    UNDERWRITING_QUOTE_ENTRY_TYPE,
    UNDERWRITING_QUOTE_SCHEMA,
    append_underwriting_quote,
    build_underwriting_quote,
    verify_underwriting_quote,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
CONSENT = ROOT / "examples" / "aitrade" / "insurer-consent.json"


class UnderwritingQuoteTests(unittest.TestCase):
    def _chain_pack_telemetry(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="quote-test")
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
        active = consent_status(
            chain,
            consent["consent_id"],
            INSURER_SCOPE,
            pack_id=pack["pack_id"],
            contract_id=pack["gate_decision"]["contract_id"],
            now="2026-07-08T00:00:00Z",
        )
        telemetry = build_insurer_telemetry(pack, consent_id=consent["consent_id"], consent=active)
        return chain, telemetry

    def test_underwriting_quote_verifies_discount_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, telemetry = self._chain_pack_telemetry(Path(tmp_dir))
            quote = build_underwriting_quote(
                telemetry,
                underwriter="Example AI Liability Underwriter",
                coverage_limit_usd=1_000_000,
                base_premium_usd=25_000,
                term_start="2026-07-08T00:00:00Z",
                term_end="2027-07-08T00:00:00Z",
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-08-08T00:00:00Z",
            )
            result = verify_underwriting_quote(quote, telemetry=telemetry, now="2026-07-09T00:00:00Z")
            entry = append_underwriting_quote(chain, quote)

            self.assertEqual(UNDERWRITING_QUOTE_SCHEMA, quote["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(15.0, quote["quote"]["discount_percent"])
            self.assertEqual(21250.0, quote["quote"]["quoted_premium_usd"])
            self.assertEqual(UNDERWRITING_QUOTE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(quote["quote_id"], entry["payload"]["quote_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_underwriting_quote_detects_tampered_premium(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, telemetry = self._chain_pack_telemetry(Path(tmp_dir))
            quote = build_underwriting_quote(
                telemetry,
                underwriter="Example AI Liability Underwriter",
                base_premium_usd=25_000,
                coverage_limit_usd=1_000_000,
                term_start="2026-07-08T00:00:00Z",
                term_end="2027-07-08T00:00:00Z",
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-08-08T00:00:00Z",
            )
            tampered = copy.deepcopy(quote)
            tampered["quote"]["quoted_premium_usd"] = 1

            result = verify_underwriting_quote(tampered, telemetry=telemetry, now="2026-09-01T00:00:00Z")

            self.assertFalse(result.ok)
            self.assertIn("quote_id does not match canonical quote body", result.errors)
            self.assertIn("quoted_premium_usd does not match base premium and discount", result.errors)
            self.assertIn("underwriting quote is expired at verification time", result.warnings)


if __name__ == "__main__":
    unittest.main()
