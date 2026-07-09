import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.auditor import render_auditor_html
from trustai.canonical import content_hash
from trustai.chain import EvidenceChain
from trustai.cicd import build_ci_report, build_promotion_check_payload, build_slack_approval_request
from trustai.compliance import build_compliance_export
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.insurer import build_insurer_telemetry
from trustai.lifecycle import DEMOTION_ENTRY_TYPE, append_soak_failure_demotion
from trustai.mcp_gateway import MCP_TOOL_CALL_ENTRY_TYPE, append_mcp_transcript, load_mcp_transcript
from trustai.proofpack import compile_proof_pack
from trustai.shadow import (
    SHADOW_REPLAY_ENTRY_TYPE,
    SOAK_REPORT_ENTRY_TYPE,
    append_shadow_replay,
    append_soak_report,
    evaluate_shadow_replay,
    evaluate_soak_window,
    load_shadow_replay,
    load_soak_window,
    shadow_replay_to_eval_results,
)
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
MCP = ROOT / "examples" / "aitrade" / "mcp-transcript.json"


class PhaseOneTwoTests(unittest.TestCase):
    def test_shadow_mcp_soak_and_consumption_exports(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)

            shadow = load_shadow_replay(SHADOW)
            shadow_entry = append_shadow_replay(chain, contract, shadow)
            mcp_entries = append_mcp_transcript(chain, load_mcp_transcript(MCP))
            soak_entry = append_soak_report(chain, contract, load_soak_window(SOAK))
            eval_entry, gate_entry, decision = append_eval_and_gate(
                chain,
                contract,
                shadow_replay_to_eval_results(contract, shadow),
            )
            chain.save()
            pack = compile_proof_pack(
                chain,
                contract,
                eval_entry,
                gate_entry,
                decision,
                out_path=tmp / "pack.json",
                pdf_path=tmp / "pack.pdf",
            )

            self.assertEqual(SHADOW_REPLAY_ENTRY_TYPE, shadow_entry["entry_type"])
            self.assertTrue(shadow_entry["payload"]["temporal_holdout"]["passed"])
            self.assertEqual(
                shadow_entry["payload"]["temporal_holdout_manifest"]["manifest_id"],
                shadow_entry["payload"]["temporal_holdout"]["manifest_id"],
            )
            self.assertEqual(
                shadow_entry["payload"]["temporal_holdout_manifest"]["records_root"],
                shadow_entry["payload"]["temporal_holdout"]["records_root"],
            )
            self.assertEqual(MCP_TOOL_CALL_ENTRY_TYPE, mcp_entries[0]["entry_type"])
            self.assertEqual(0, mcp_entries[0]["payload"]["transcript_sequence"])
            self.assertEqual(mcp_entries[0]["payload"]["transcript_node_hash"], mcp_entries[0]["payload"]["transcript_root"])
            self.assertEqual(SOAK_REPORT_ENTRY_TYPE, soak_entry["entry_type"])
            self.assertTrue(verify_proof_pack(pack).ok)
            entry_types = {entry["entry_type"] for entry in pack["chain"]["entries"]}
            self.assertIn(SHADOW_REPLAY_ENTRY_TYPE, entry_types)
            self.assertIn(MCP_TOOL_CALL_ENTRY_TYPE, entry_types)
            self.assertIn(SOAK_REPORT_ENTRY_TYPE, entry_types)

            verification = verify_proof_pack(pack)
            ci_report = build_ci_report(pack, verification, provider="github")
            github_payload = build_promotion_check_payload(
                pack,
                verification,
                provider="github",
                commit_sha="0123456789abcdef0123456789abcdef01234567",
                repository="volelabs/trust_ai",
                target_url="https://example.test/proof-pack",
            )
            gitlab_payload = build_promotion_check_payload(
                pack,
                verification,
                provider="gitlab",
                commit_sha="0123456789abcdef0123456789abcdef01234567",
                repository="123456",
                branch="main",
            )
            slack_request = build_slack_approval_request(
                pack,
                channel="C07TRUSTAI",
                requested_roles=["model_risk"],
                requester="risk@example.com",
            )
            compliance_export = build_compliance_export(pack)
            insurer_export = build_insurer_telemetry(pack)
            auditor_html = render_auditor_html(pack)

            self.assertEqual("success", ci_report["conclusion"])
            self.assertEqual("trustai.github-check-run-payload/0.1", github_payload["schema"])
            self.assertEqual("/repos/volelabs/trust_ai/check-runs", github_payload["request"]["path"])
            self.assertEqual("success", github_payload["request"]["body"]["conclusion"])
            self.assertEqual("trustai.gitlab-status-payload/0.1", gitlab_payload["schema"])
            self.assertEqual("success", gitlab_payload["request"]["body"]["state"])
            self.assertEqual("trustai.slack-approval-request/0.1", slack_request["schema"])
            self.assertEqual(["model_risk"], slack_request["requested_roles"])
            self.assertEqual("/api/chat.postMessage", slack_request["request"]["path"])
            self.assertEqual(5, len(compliance_export["mappings"]))
            self.assertEqual("low", insurer_export["risk_tier"])
            self.assertIn("TrustAI Proof Pack Auditor View", auditor_html)

    def test_proof_pack_verifier_replays_embedded_soak_report(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="soak-pack-test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            shadow = load_shadow_replay(SHADOW)
            append_shadow_replay(chain, contract, shadow)
            soak = copy.deepcopy(load_soak_window(SOAK))
            soak["drift_alarms"] = [
                {
                    "id": "drift-critical-001",
                    "severity": "critical",
                    "description": "Candidate latency distribution drifted outside the contract assumption.",
                }
            ]
            report = evaluate_soak_window(contract, soak)
            chain.append(
                SOAK_REPORT_ENTRY_TYPE,
                {
                    **report,
                    "passed": True,
                    "outcome": "passed",
                    "soak_hash": content_hash(soak),
                    "soak": soak,
                },
                timestamp=report["evaluated_at"],
            )
            eval_entry, gate_entry, decision = append_eval_and_gate(
                chain,
                contract,
                shadow_replay_to_eval_results(contract, shadow),
            )
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertTrue(any("soak report entry" in error and "passed mismatch" in error for error in result.errors))
            self.assertTrue(any("soak report entry" in error and "outcome mismatch" in error for error in result.errors))

    def test_failed_soak_report_can_emit_demotion_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="soak-demotion-test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            soak = copy.deepcopy(load_soak_window(SOAK))
            soak["drift_alarms"] = [
                {
                    "id": "drift-critical-001",
                    "severity": "critical",
                    "description": "Latency drift exceeded the production contract assumption.",
                }
            ]
            soak_entry = append_soak_report(chain, contract, soak)

            demotion_entry = append_soak_failure_demotion(chain, contract, soak_entry)

            self.assertFalse(soak_entry["payload"]["passed"])
            self.assertEqual(DEMOTION_ENTRY_TYPE, demotion_entry["entry_type"])
            self.assertEqual(soak_entry["entry_id"], demotion_entry["payload"]["triggering_entry_id"])
            self.assertEqual("soak_report.completed", demotion_entry["payload"]["trigger"]["entry_type"])
            self.assertEqual("failed", demotion_entry["payload"]["trigger"]["outcome"])
            self.assertEqual("drift-critical-001", demotion_entry["payload"]["trigger"]["blocking_drift_alarms"][0]["id"])
            self.assertIn("blocking drift alarms", demotion_entry["payload"]["reason"])
            self.assertTrue(chain.verify_all().ok)

    def test_cli_soak_report_demotes_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            soak = copy.deepcopy(load_soak_window(SOAK))
            soak["drift_alarms"] = [
                {
                    "id": "drift-critical-cli-001",
                    "severity": "critical",
                    "description": "CLI-triggered soak drift failure.",
                }
            ]
            soak_path = tmp / "failed-soak.json"
            state_path = tmp / "chain.json"
            demotion_path = tmp / "demotion.json"
            soak_path.write_text(json.dumps(soak), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "soak-report",
                    str(CONTRACT),
                    str(soak_path),
                    "--demote-on-failure",
                    "--auto-register",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "soak-demotion-cli",
                    "--demotion-out",
                    str(demotion_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )

            self.assertEqual(1, completed.returncode, completed.stdout + completed.stderr)
            demotion = json.loads(demotion_path.read_text(encoding="utf-8"))
            chain = EvidenceChain.load(state_path, tenant_id="soak-demotion-cli")
            self.assertEqual(DEMOTION_ENTRY_TYPE, demotion["entry_type"])
            self.assertEqual("soak_report.completed", demotion["payload"]["trigger"]["entry_type"])
            self.assertEqual("drift-critical-cli-001", demotion["payload"]["trigger"]["blocking_drift_alarms"][0]["id"])
            self.assertTrue(chain.verify_all().ok)

    def test_shadow_replay_flags_pre_freeze_records(self):
        contract = load_contract(CONTRACT)
        shadow = json.loads(SHADOW.read_text(encoding="utf-8"))
        shadow["records"][0]["timestamp"] = "2026-06-30T23:59:00Z"

        evaluation = evaluate_shadow_replay(contract, shadow)

        self.assertFalse(evaluation["holdout"]["passed"])
        self.assertFalse(evaluation["passed"])
        self.assertTrue(evaluation["holdout"]["errors"])


if __name__ == "__main__":
    unittest.main()
