import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.mcp_gateway import (
    MCP_TOOL_CALL_ENTRY_TYPE,
    append_mcp_transcript,
    build_mcp_transcript_chain,
    load_mcp_transcript,
)


ROOT = Path(__file__).resolve().parents[1]
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

    def test_mcp_transcript_rejects_empty_call_list(self):
        with self.assertRaisesRegex(ValueError, "at least one tool call"):
            build_mcp_transcript_chain([])


if __name__ == "__main__":
    unittest.main()