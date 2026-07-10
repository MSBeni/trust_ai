import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.mcp_gateway import (
    MCP_PROXY_CAPTURE_ENTRY_TYPE,
    MCP_TOOL_CALL_ENTRY_TYPE,
    append_mcp_proxy_capture,
    append_mcp_transcript,
    build_mcp_proxy_capture,
    build_mcp_transcript_chain,
    load_mcp_proxy_events,
    load_mcp_transcript,
    verify_mcp_proxy_capture,
)
from trustai.proofpack import compile_proof_pack
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"
MCP = ROOT / "examples" / "aitrade" / "mcp-transcript.json"
MCP_PROXY = ROOT / "examples" / "aitrade" / "mcp-proxy-events.json"
CONTRACT_HASH = "22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2"
AGENT = {
    "name": "aitrade-risk-agent",
    "version": "sha256:0d5bbd8d2357b7d36e0f3f7c5e9a0a3e1f5b7a0d2c4e6f8a9b1c3d5e7f901234",
    "risk_class": "trading-prod-write",
}


def _sha256_ref(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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

    def test_mcp_proxy_capture_derives_signed_transcript_and_redacts(self):
        events = load_mcp_proxy_events(MCP_PROXY)
        capture = build_mcp_proxy_capture(
            events,
            agent=AGENT,
            contract_hash=CONTRACT_HASH,
            proxy_ref="mcp-proxy:trustai/local",
            upstream_ref="mcp-server:aitrade/tools",
            captured_at="2026-07-03T12:00:12Z",
            source_events_path=MCP_PROXY,
        )

        result = verify_mcp_proxy_capture(capture, source_events_path=MCP_PROXY)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(2, capture["event_count"])
        self.assertEqual(1, capture["tool_call_count"])
        self.assertEqual("[REDACTED]", capture["events"][0]["event"]["message"]["authorization"])
        self.assertEqual("place_shadow_order", capture["tool_calls"][0]["tool_name"])
        self.assertEqual({"status": "accepted", "order_id": "shadow-order-20260703-001"}, capture["tool_calls"][0]["response"])
        self.assertIn("request_event_hash", capture["tool_calls"][0]["proxy_capture"])
        self.assertEqual(_sha256_ref(MCP_PROXY), capture["proxy_events_artifact"]["sha256"])
        self.assertEqual(capture["event_chain_root"], capture["proxy_events_artifact"]["event_chain_root"])

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="mcp-proxy-capture-test")
            entry = append_mcp_proxy_capture(chain, capture, source_events_path=MCP_PROXY)
            self.assertEqual(MCP_PROXY_CAPTURE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(capture["capture_id"], entry["payload"]["capture_id"])
            self.assertEqual(capture["proxy_events_artifact"]["sha256"], entry["payload"]["proxy_events_artifact"]["sha256"])
            self.assertTrue(chain.verify_all().ok)

    def test_mcp_proxy_capture_replays_source_event_artifact_bytes(self):
        raw_events_export = json.loads(MCP_PROXY.read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as tmp_dir:
            source_events_path = Path(tmp_dir) / "mcp-proxy-events.json"
            source_events_path.write_text(json.dumps(raw_events_export, indent=2, sort_keys=True), encoding="utf-8")
            events = load_mcp_proxy_events(source_events_path)
            capture = build_mcp_proxy_capture(
                events,
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/local",
                upstream_ref="mcp-server:aitrade/tools",
                captured_at="2026-07-03T12:00:12Z",
                source_events_path=source_events_path,
            )
            result = verify_mcp_proxy_capture(capture, source_events_path=source_events_path)
            artifact_sha = _sha256_ref(source_events_path)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(artifact_sha, capture["proxy_events_artifact"]["sha256"])
        self.assertEqual(capture["event_chain_root"], capture["proxy_events_artifact"]["event_chain_root"])
        self.assertEqual(2, capture["proxy_events_artifact"]["event_count"])

    def test_mcp_proxy_capture_detects_source_event_artifact_byte_tamper(self):
        raw_events_export = json.loads(MCP_PROXY.read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as tmp_dir:
            source_events_path = Path(tmp_dir) / "mcp-proxy-events.json"
            source_events_path.write_text(json.dumps(raw_events_export, indent=2, sort_keys=True), encoding="utf-8")
            events = load_mcp_proxy_events(source_events_path)
            capture = build_mcp_proxy_capture(
                events,
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/local",
                upstream_ref="mcp-server:aitrade/tools",
                captured_at="2026-07-03T12:00:12Z",
                source_events_path=source_events_path,
            )
            source_events_path.write_text(json.dumps(raw_events_export, indent=4, sort_keys=True), encoding="utf-8")
            result = verify_mcp_proxy_capture(capture, source_events_path=source_events_path)

        self.assertFalse(result.ok)
        errors = "\n".join(result.errors)
        self.assertIn("proxy_events_artifact", errors)
        self.assertIn("bytes", errors)

    def test_mcp_proxy_capture_detects_raw_envelope_tamper(self):
        capture = build_mcp_proxy_capture(
            load_mcp_proxy_events(MCP_PROXY),
            agent=AGENT,
            contract_hash=CONTRACT_HASH,
            proxy_ref="mcp-proxy:trustai/local",
            upstream_ref="mcp-server:aitrade/tools",
            captured_at="2026-07-03T12:00:12Z",
        )
        tampered = copy.deepcopy(capture)
        tampered["events"][0]["event"]["message"]["params"]["arguments"]["notional_usd"] = 999999

        result = verify_mcp_proxy_capture(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("capture_id" in error for error in result.errors))
        self.assertTrue(any("message_hash mismatch" in error for error in result.errors))

    def test_mcp_proxy_capture_rejects_unmatched_tool_call(self):
        events = load_mcp_proxy_events(MCP_PROXY)[:1]

        with self.assertRaisesRegex(ValueError, "unmatched MCP tools/call request ids"):
            build_mcp_proxy_capture(
                events,
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/local",
                upstream_ref="mcp-server:aitrade/tools",
            )

    def test_cli_mcp_proxy_capture_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            capture_path = tmp / "mcp-proxy-capture.json"
            entry_path = tmp / "mcp-proxy-capture-entry.json"
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT / "src")

            create = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "mcp-proxy-capture",
                    str(MCP_PROXY),
                    "--agent-name",
                    AGENT["name"],
                    "--agent-version",
                    AGENT["version"],
                    "--risk-class",
                    AGENT["risk_class"],
                    "--contract-hash",
                    CONTRACT_HASH,
                    "--proxy-ref",
                    "mcp-proxy:trustai/local",
                    "--upstream-ref",
                    "mcp-server:aitrade/tools",
                    "--captured-at",
                    "2026-07-03T12:00:12Z",
                    "--out",
                    str(capture_path),
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, create.returncode, create.stderr)

            verify = subprocess.run(
                [sys.executable, "-m", "trustai", "mcp-proxy-capture-verify", str(capture_path), "--events", str(MCP_PROXY)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, verify.returncode, verify.stderr)

            append = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "mcp-proxy-capture-append",
                    str(capture_path),
                    "--events",
                    str(MCP_PROXY),
                    "--state",
                    str(tmp / "chain.json"),
                    "--tenant",
                    "mcp-proxy-cli-test",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, append.returncode, append.stderr)
            self.assertTrue(entry_path.exists())
            receipt = json.loads(capture_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["proxy_events_artifact"]["sha256"], entry["payload"]["proxy_events_artifact"]["sha256"])

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
