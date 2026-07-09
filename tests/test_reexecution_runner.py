import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import contract_hash, load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.reexecution import append_reexecution_report, build_reexecution_report, verify_reexecution_report
from trustai.reexecution_policy import load_reexecution_policy
from trustai.reexecution_runner import (
    REEXECUTION_RUNNER_ENTRY_TYPE,
    append_reexecution_runner_evidence,
    load_reexecution_runner_plan,
    run_reexecution_plan,
    runner_results,
    verify_reexecution_runner_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
POLICY = ROOT / "examples" / "aitrade" / "reexecution-policy.json"
PLAN = ROOT / "examples" / "aitrade" / "reexecution-runner-plan.json"
FIXTURE = ROOT / "examples" / "aitrade" / "reexecution_runner_fixture.py"


class ReexecutionRunnerTests(unittest.TestCase):
    def _plan_for_tmp(self, tmp: Path) -> dict:
        contract = load_contract(CONTRACT)
        plan = load_reexecution_runner_plan(PLAN)
        plan["command"] = ["{python}", str(FIXTURE)]
        plan["contract"] = {"id": contract["id"], "hash": contract_hash(contract), "agent": contract.get("agent")}
        for index, run in enumerate(plan["runs"], start=1):
            run["output"] = f"runner-runs/eval-results-runner-{index}.json"
        return plan

    def test_runner_plan_executes_and_appends_chain_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence = run_reexecution_plan(self._plan_for_tmp(tmp), base_dir=tmp)
            result = verify_reexecution_runner_evidence(evidence)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="runner-test")
            entry = append_reexecution_runner_evidence(chain, evidence)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual("passed", evidence["outcome"])
            self.assertEqual(3, result.run_count)
            self.assertEqual(REEXECUTION_RUNNER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(load_contract(CONTRACT)["id"], entry["payload"]["contract_id"])
            self.assertEqual(contract_hash(load_contract(CONTRACT)), entry["payload"]["contract_hash"])
            self.assertEqual(3, len(runner_results(evidence)))

    def test_runner_outputs_feed_policy_bound_reexecution_report(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence = run_reexecution_plan(self._plan_for_tmp(tmp), base_dir=tmp)
            report = build_reexecution_report(
                load_contract(CONTRACT),
                runner_results(evidence),
                temperature=0,
                policy=load_reexecution_policy(POLICY),
            )
            result = verify_reexecution_report(report)

            self.assertTrue(result.ok, result.errors)
            self.assertTrue(report["overall"]["passed"])
            self.assertTrue(report["overall"]["policy_passed"])

    def test_runner_entry_is_included_in_compiled_proof_pack(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            contract = load_contract(CONTRACT)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="runner-test")
            register_contract(chain, contract)
            evidence = run_reexecution_plan(self._plan_for_tmp(tmp), base_dir=tmp)
            runner_entry = append_reexecution_runner_evidence(chain, evidence)
            report = build_reexecution_report(
                contract,
                runner_results(evidence),
                temperature=0,
                policy=load_reexecution_policy(POLICY),
            )
            append_reexecution_report(chain, report)
            eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, runner_results(evidence)[0])
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
            entry_types = {entry["entry_type"] for entry in pack["chain"]["entries"]}

            self.assertEqual(REEXECUTION_RUNNER_ENTRY_TYPE, runner_entry["entry_type"])
            self.assertIn(REEXECUTION_RUNNER_ENTRY_TYPE, entry_types)

    def test_runner_evidence_detects_embedded_output_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence = run_reexecution_plan(self._plan_for_tmp(tmp), base_dir=tmp)
            tampered = copy.deepcopy(evidence)
            tampered["runs"][0]["output"]["results"]["metrics"]["trade_policy_compliance_rate"] = 0.1

            result = verify_reexecution_runner_evidence(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("evidence_id" in error for error in result.errors))
            self.assertTrue(any("run_hash mismatch" in error for error in result.errors))
            self.assertTrue(any("output results_hash mismatch" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
