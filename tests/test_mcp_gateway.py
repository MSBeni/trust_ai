import copy
import json
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.mcp_gateway import (
    MCP_TOOL_CALL_ENTRY_TYPE,
    append_mcp_transcript,
    build_mcp_transcript_chain,
    load_mcp_transcript,
)
from trustai.proofpack import compile_proof_pack
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"
MCP = ROOT / "examples" / "aitrade" / "mcp-transcript.json"


class McpGatewayTests(unittest.TestCase):
    def test_mcp_transcript_hash_chain_binds_order(self):
        calls = load_mcp_transcript(MCP)
        second = copy.deepcopy(calls[0])
        second["request_id"] = "tool-call-002"
        second["timestamp"] = "2026-07-03T12:00:12Z"
        second["tool_name"] = "risk_limit_check"
        second["request"] = {"notional_usd": 7500}
        second["response"] = {"status": "allowed"}

        records = build_mcp_transcript_chain([calls[0], second])
        reversed_records = build_mcp_transcript_chain([second, calls[0]])

        self.assertEqual(2, len(records))
        self.assertEqual(0, records[0]["sequence"])
        self.assertEqual(1, records[1]["sequence"])
        self.assertEqual(2, records[0]["call_count"])
        self.assertIsNone(records[0]["previous_transcript_node_hash"])
        self.assertEqual(records[0]["transcript_node_hash"], records[1]["previous_transcript_node_hash"])
        self.assertEqual(records[1]["transcript_node_hash"], records[0]["transcript_root"])
        self.assertNotEqual(records[0]["transcript_root"], reversed_records[0]["transcript_root"])

    def test_mcp_transcript_entries_include_chain_root(self):
        calls = load_mcp_transcript(MCP)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="mcp-gateway-test")
            entries = append_mcp_transcript(chain, calls)

            self.assertEqual(1, len(entries))
            payload = entries[0]["payload"]
            self.assertEqual(MCP_TOOL_CALL_ENTRY_TYPE, entries[0]["entry_type"])
            self.assertEqual(0, payload["transcript_sequence"])
            self.assertEqual(1, payload["transcript_call_count"])
            self.assertIsNone(payload["previous_transcript_node_hash"])
            self.assertEqual(payload["transcript_node_hash"], payload["transcript_root"])
            self.assertTrue(chain.verify_all().ok)

    def test_proof_pack_verifier_replays_embedded_mcp_transcript_chain(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="mcp-pack-test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            first = load_mcp_transcript(MCP)[0]
            second = copy.deepcopy(first)
            second["request_id"] = "tool-call-002"
            second["timestamp"] = "2026-07-03T12:00:12Z"
            second["tool_name"] = "risk_limit_check"
            second["request"] = {"notional_usd": 7500}
            second["response"] = {"status": "allowed"}

            records = build_mcp_transcript_chain([first, second])
            for record in records:
                normalized = record["tool_call"]
                payload = {
                    "session_id": normalized["session_id"],
                    "request_id": normalized["request_id"],
                    "tool_name": normalized["tool_name"],
                    "contract_hash": normalized["contract_hash"],
                    "request_hash": record["request_hash"],
                    "response_hash": record["response_hash"],
                    "tool_call_hash": record["tool_call_hash"],
                    "transcript_sequence": record["sequence"],
                    "transcript_call_count": record["call_count"],
                    "previous_transcript_node_hash": record["previous_transcript_node_hash"],
                    "transcript_node_hash": record["transcript_node_hash"],
                    "transcript_root": record["transcript_root"],
                    "tool_call": normalized,
                }
                if payload["transcript_sequence"] == 1:
                    payload["previous_transcript_node_hash"] = "sha256:not-the-previous-node"
                chain.append(MCP_TOOL_CALL_ENTRY_TYPE, payload, timestamp=normalized["timestamp"])

            results = json.loads(RESULTS.read_text(encoding="utf-8"))
            eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertTrue(any("previous_transcript_node_hash mismatch" in error for error in result.errors))

    def test_mcp_transcript_rejects_empty_call_list(self):
        with self.assertRaisesRegex(ValueError, "at least one tool call"):
            build_mcp_transcript_chain([])


if __name__ == "__main__":
    unittest.main()