import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.reexecution import (
    REEXECUTION_ENTRY_TYPE,
    REEXECUTION_REPORT_SCHEMA,
    append_reexecution_report,
    build_reexecution_report,
    load_eval_results,
    render_reexecution_markdown,
    verify_reexecution_report,
)
from trustai.reexecution_policy import evaluate_reexecution_policy, load_reexecution_policy
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
POLICY = ROOT / "examples" / "aitrade" / "reexecution-policy.json"
RUNS = [
    ROOT / "examples" / "aitrade" / "eval-results.json",
    ROOT / "examples" / "aitrade" / "eval-results-reexecution-2.json",
    ROOT / "examples" / "aitrade" / "eval-results-reexecution-3.json",
]


class ReexecutionReportTests(unittest.TestCase):
    def _runs(self):
        return [load_eval_results(path) for path in RUNS]

    def test_reexecution_report_verifies_metric_distributions(self):
        contract = load_contract(CONTRACT)
        report = build_reexecution_report(contract, self._runs(), temperature=0, required_pass_rate=1.0)

        result = verify_reexecution_report(report)
        markdown = render_reexecution_markdown(report)
        distributions = {metric["name"]: metric for metric in report["metric_distributions"]}

        self.assertEqual(REEXECUTION_REPORT_SCHEMA, report["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(3, result.run_count)
        self.assertTrue(report["overall"]["passed"])
        self.assertEqual(1.0, distributions["trade_policy_compliance_rate"]["pass_rate"])
        self.assertIn("mean_ci_95", distributions["p95_decision_latency_ms"])
        self.assertIn("TrustAI Re-execution Report", markdown)

    def test_reexecution_report_detects_embedded_run_tamper(self):
        contract = load_contract(CONTRACT)
        report = build_reexecution_report(contract, self._runs())
        tampered = copy.deepcopy(report)
        tampered["source_runs"][0]["results"]["metrics"]["trade_policy_compliance_rate"] = 0.5

        result = verify_reexecution_report(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("report_id" in error for error in result.errors))
        self.assertTrue(any("results_hash mismatch" in error for error in result.errors))
        self.assertTrue(any("source_runs does not match" in error for error in result.errors))

    def test_reexecution_policy_enforces_pins_and_sample_size(self):
        contract = load_contract(CONTRACT)
        policy = load_reexecution_policy(POLICY)
        runs = self._runs()

        policy_result = evaluate_reexecution_policy(
            contract,
            runs,
            policy,
            method="n-run-reexecution",
            seed_policy="recorded-or-fixed-seed",
            temperature=0,
            required_pass_rate=1.0,
        )
        report = build_reexecution_report(contract, runs, temperature=0, policy=policy)
        verification = verify_reexecution_report(report)
        markdown = render_reexecution_markdown(report)

        self.assertTrue(policy_result["passed"], policy_result["errors"])
        self.assertTrue(report["policy_result"]["passed"], report["policy_result"]["errors"])
        self.assertTrue(report["overall"]["policy_passed"])
        self.assertTrue(verification.ok, verification.errors)
        self.assertIn("Policy:", markdown)
        self.assertGreaterEqual(len(policy_result["checks"]), 40)

    def test_reexecution_policy_failure_keeps_report_verifiable_but_failed(self):
        contract = load_contract(CONTRACT)
        policy = load_reexecution_policy(POLICY)
        runs = self._runs()
        runs[1]["environment"]["model"] = "gpt-5-mini-rotated"

        policy_result = evaluate_reexecution_policy(
            contract,
            runs,
            policy,
            method="n-run-reexecution",
            seed_policy="recorded-or-fixed-seed",
            temperature=0,
            required_pass_rate=1.0,
        )
        report = build_reexecution_report(contract, runs, temperature=0, policy=policy)
        verification = verify_reexecution_report(report)

        self.assertFalse(policy_result["passed"])
        self.assertFalse(report["overall"]["passed"])
        self.assertFalse(report["overall"]["policy_passed"])
        self.assertTrue(verification.ok, verification.errors)
        self.assertTrue(verification.warnings)
        self.assertTrue(any("environment pin mismatch" in error for error in policy_result["errors"]))

    def test_reexecution_report_detects_policy_result_tamper(self):
        contract = load_contract(CONTRACT)
        policy = load_reexecution_policy(POLICY)
        report = build_reexecution_report(contract, self._runs(), temperature=0, policy=policy)
        tampered = copy.deepcopy(report)
        tampered["policy_result"]["checks"][0]["passed"] = False

        result = verify_reexecution_report(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("report_id" in error for error in result.errors))
        self.assertTrue(any("policy_result does not match" in error for error in result.errors))

    def test_reexecution_entry_is_included_in_compiled_proof_pack(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            report = build_reexecution_report(contract, self._runs())
            entry = append_reexecution_report(chain, report)
            eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, self._runs()[0])
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
            entry_types = {chain_entry["entry_type"] for chain_entry in pack["chain"]["entries"]}

            self.assertEqual(REEXECUTION_ENTRY_TYPE, entry["entry_type"])
            self.assertIn(REEXECUTION_ENTRY_TYPE, entry_types)
            self.assertTrue(verify_proof_pack(pack).ok)


if __name__ == "__main__":
    unittest.main()
