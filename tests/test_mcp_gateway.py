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
from trustai.canonical import content_hash, without_keys
from trustai.contracts import load_contract, register_contract
from trustai.crypto import sign_value
from trustai.gate import append_eval_and_gate
from trustai.mcp_gateway import (
    MCP_PROXY_CAPTURE_ENTRY_TYPE,
    MCP_TOOL_CALL_ENTRY_TYPE,
    append_mcp_proxy_capture,
    append_mcp_transcript,
    build_mcp_proxy_capture,
    build_mcp_proxy_event_chain,
    build_mcp_stdio_proxy_event_export,
    build_mcp_transcript_chain,
    load_mcp_client_messages,
    load_mcp_proxy_events,
    load_mcp_transcript,
    verify_mcp_proxy_capture,
    verify_mcp_stdio_proxy_event_export,
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
        self.assertEqual(1, capture["redaction_summary"]["redacted_field_count"])
        self.assertEqual(["message[0].authorization"], capture["redaction_summary"]["redacted_paths"])
        self.assertEqual("[REDACTED]", capture["events"][0]["event"]["message"]["authorization"])
        self.assertEqual("place_shadow_order", capture["tool_calls"][0]["tool_name"])
        self.assertEqual({"status": "accepted", "order_id": "shadow-order-20260703-001"}, capture["tool_calls"][0]["response"])
        self.assertIn("request_event_hash", capture["tool_calls"][0]["proxy_capture"])
        self.assertEqual("result", capture["tool_calls"][0]["proxy_capture"]["response_kind"])
        self.assertEqual("examples/aitrade/mcp-proxy-events.json", capture["proxy_events_artifact"]["path"])
        self.assertEqual(_sha256_ref(MCP_PROXY), capture["proxy_events_artifact"]["sha256"])
        self.assertEqual(capture["event_chain_root"], capture["proxy_events_artifact"]["event_chain_root"])

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="mcp-proxy-capture-test")
            entry = append_mcp_proxy_capture(chain, capture, source_events_path=MCP_PROXY)
            self.assertEqual(MCP_PROXY_CAPTURE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(capture["capture_id"], entry["payload"]["capture_id"])
            self.assertEqual(capture["redaction_summary"], entry["payload"]["redaction_summary"])
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
        self.assertEqual(str(source_events_path).replace("\\", "/"), capture["proxy_events_artifact"]["path"])
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

    def test_mcp_proxy_capture_rejects_resigned_redaction_summary_tamper(self):
        capture = build_mcp_proxy_capture(
            load_mcp_proxy_events(MCP_PROXY),
            agent=AGENT,
            contract_hash=CONTRACT_HASH,
            proxy_ref="mcp-proxy:trustai/local",
            upstream_ref="mcp-server:aitrade/tools",
            captured_at="2026-07-03T12:00:12Z",
        )
        tampered = copy.deepcopy(capture)
        tampered["redaction_summary"]["redacted_field_count"] = 0
        tampered["redaction_summary"]["redacted_paths"] = []
        tampered["redaction_summary"]["redacted_paths_hash"] = content_hash([])
        summary_body = without_keys(tampered["redaction_summary"], "summary_id")
        tampered["redaction_summary"]["summary_id"] = content_hash(summary_body)
        body = without_keys(tampered, "capture_id", "signatures")
        tampered["capture_id"] = content_hash(body)
        tampered["signatures"] = [sign_value({"capture_id": tampered["capture_id"], "mcp_proxy_capture": body})]

        result = verify_mcp_proxy_capture(tampered)

        self.assertFalse(result.ok)
        self.assertFalse(any("capture_id" in error for error in result.errors), result.errors)
        self.assertTrue(any("redaction_summary mismatch" in error for error in result.errors), result.errors)

    def test_mcp_proxy_capture_preserves_jsonrpc_error_response(self):
        events = load_mcp_proxy_events(MCP_PROXY)
        events[1]["message"].pop("result")
        events[1]["message"]["error"] = {
            "code": -32001,
            "message": "risk limit service unavailable",
            "data": {"retryable": True},
        }

        capture = build_mcp_proxy_capture(
            events,
            agent=AGENT,
            contract_hash=CONTRACT_HASH,
            proxy_ref="mcp-proxy:trustai/local",
            upstream_ref="mcp-server:aitrade/tools",
            captured_at="2026-07-03T12:00:12Z",
        )
        result = verify_mcp_proxy_capture(capture)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual("error", capture["tool_calls"][0]["proxy_capture"]["response_kind"])
        self.assertEqual(
            {
                "jsonrpc_error": {
                    "code": -32001,
                    "data": {"retryable": True},
                    "message": "risk limit service unavailable",
                }
            },
            capture["tool_calls"][0]["response"],
        )

    def test_mcp_proxy_capture_rejects_ambiguous_jsonrpc_response(self):
        events = load_mcp_proxy_events(MCP_PROXY)
        events[1]["message"]["error"] = {"code": -32001, "message": "ambiguous response"}

        with self.assertRaisesRegex(ValueError, "exactly one of result or error"):
            build_mcp_proxy_capture(
                events,
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/local",
                upstream_ref="mcp-server:aitrade/tools",
            )

    def test_mcp_proxy_capture_rejects_non_jsonrpc_2_tool_request(self):
        events = load_mcp_proxy_events(MCP_PROXY)
        events[0]["message"]["jsonrpc"] = "1.0"

        with self.assertRaisesRegex(ValueError, "JSON-RPC 2.0"):
            build_mcp_proxy_capture(
                events,
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/local",
                upstream_ref="mcp-server:aitrade/tools",
            )

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

    def test_mcp_proxy_capture_rejects_resigned_cross_session_response(self):
        capture = build_mcp_proxy_capture(
            load_mcp_proxy_events(MCP_PROXY),
            agent=AGENT,
            contract_hash=CONTRACT_HASH,
            proxy_ref="mcp-proxy:trustai/local",
            upstream_ref="mcp-server:aitrade/tools",
            captured_at="2026-07-03T12:00:12Z",
        )
        tampered = copy.deepcopy(capture)
        tampered_events = [copy.deepcopy(record["event"]) for record in capture["events"]]
        tampered_events[1]["session_id"] = "mcp-session-other"
        tampered_records = build_mcp_proxy_event_chain(tampered_events)
        tampered["events"] = tampered_records
        tampered["event_chain_root"] = tampered_records[-1]["event_hash"]
        body = without_keys(tampered, "capture_id", "signatures")
        tampered["capture_id"] = content_hash(body)
        tampered["signatures"] = [sign_value({"capture_id": tampered["capture_id"], "mcp_proxy_capture": body})]

        result = verify_mcp_proxy_capture(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("session_id mismatch" in error for error in result.errors), result.errors)

    def test_mcp_stdio_proxy_runs_upstream_and_writes_signed_capture(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            upstream = tmp / "upstream_mcp.py"
            upstream.write_text(
                "import json, sys\n"
                "for line in sys.stdin:\n"
                "    message = json.loads(line)\n"
                "    params = message.get('params', {})\n"
                "    arguments = params.get('arguments', {})\n"
                "    response = {'jsonrpc': '2.0', 'id': message['id'], 'result': {'status': 'accepted', 'tool': params.get('name'), 'notional_usd': arguments.get('notional_usd')}}\n"
                "    print(json.dumps(response, sort_keys=True), flush=True)\n",
                encoding="utf-8",
            )
            messages = tmp / "client-messages.json"
            stdout_path = tmp / "mcp-proxy-stdio-stdout.jsonl"
            cli_stdout_path = tmp / "mcp-proxy-stdio-stdout-cli.jsonl"
            messages.write_text(
                json.dumps(
                    {
                        "messages": [
                            {
                                "jsonrpc": "2.0",
                                "id": "tool-call-stdio-001",
                                "method": "tools/call",
                                "authorization": "Bearer secret-token",
                                "params": {"name": "place_shadow_order", "arguments": {"notional_usd": 2500}},
                            }
                        ]
                    },
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            loaded_messages = load_mcp_client_messages(messages)
            event_export = build_mcp_stdio_proxy_event_export(
                loaded_messages,
                upstream_command=[sys.executable, str(upstream)],
                session_id="stdio-session-001",
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/stdio-test",
                upstream_ref="mcp-server:test/upstream",
                captured_at="2026-07-03T12:00:12Z",
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )
            event_result = verify_mcp_stdio_proxy_event_export(
                event_export,
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )
            self.assertTrue(event_result.ok, event_result.errors)
            self.assertEqual("trustai.mcp-proxy-stdio-session/0.1", event_export["schema"])
            self.assertEqual(2, event_export["event_count"])
            self.assertEqual(1, event_export["redaction_summary"]["redacted_field_count"])
            self.assertEqual(["message[0].authorization"], event_export["redaction_summary"]["redacted_paths"])
            self.assertEqual("[REDACTED]", event_export["events"][0]["message"]["authorization"])
            self.assertEqual(_sha256_ref(messages), event_export["client_messages_artifact"]["sha256"])
            self.assertEqual(_sha256_ref(stdout_path), event_export["stdout_artifact"]["sha256"])
            tampered_summary = copy.deepcopy(event_export)
            tampered_summary["redaction_summary"]["redacted_field_count"] = 0
            tampered_summary["redaction_summary"]["redacted_paths"] = []
            tampered_summary["redaction_summary"]["redacted_paths_hash"] = content_hash([])
            summary_body = without_keys(tampered_summary["redaction_summary"], "summary_id")
            tampered_summary["redaction_summary"]["summary_id"] = content_hash(summary_body)
            tampered_summary["export_id"] = content_hash(without_keys(tampered_summary, "export_id"))
            tampered_summary_result = verify_mcp_stdio_proxy_event_export(
                tampered_summary,
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )
            self.assertFalse(tampered_summary_result.ok)
            self.assertTrue(
                any("redaction_summary mismatch" in error for error in tampered_summary_result.errors),
                tampered_summary_result.errors,
            )
            stdout_path.write_text(stdout_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            tampered_event_result = verify_mcp_stdio_proxy_event_export(
                event_export,
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )
            self.assertFalse(tampered_event_result.ok)
            self.assertTrue(any("stdout_artifact" in error for error in tampered_event_result.errors), tampered_event_result.errors)
            events_path = tmp / "mcp-proxy-stdio-events.json"
            events_path.write_text(json.dumps(event_export, indent=2, sort_keys=True), encoding="utf-8")
            capture = build_mcp_proxy_capture(
                load_mcp_proxy_events(events_path),
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/stdio-test",
                upstream_ref="mcp-server:test/upstream",
                session_id="stdio-session-001",
                captured_at="2026-07-03T12:00:12Z",
                source_events_path=events_path,
            )
            result = verify_mcp_proxy_capture(capture, source_events_path=events_path)
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("accepted", capture["tool_calls"][0]["response"]["status"])

            capture_path = tmp / "mcp-proxy-stdio-capture.json"
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT / "src")
            cli = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "mcp-proxy-stdio",
                    str(messages),
                    "--upstream-command",
                    sys.executable,
                    "--upstream-arg",
                    str(upstream),
                    "--agent-name",
                    AGENT["name"],
                    "--agent-version",
                    AGENT["version"],
                    "--risk-class",
                    AGENT["risk_class"],
                    "--contract-hash",
                    CONTRACT_HASH,
                    "--proxy-ref",
                    "mcp-proxy:trustai/stdio-test",
                    "--upstream-ref",
                    "mcp-server:test/upstream",
                    "--session-id",
                    "stdio-session-001",
                    "--captured-at",
                    "2026-07-03T12:00:12Z",
                    "--events-out",
                    str(events_path),
                    "--stdout-out",
                    str(cli_stdout_path),
                    "--out",
                    str(capture_path),
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, cli.returncode, cli.stderr)
            self.assertTrue(capture_path.exists())
            self.assertTrue(cli_stdout_path.exists())
            cli_event_export = json.loads(events_path.read_text(encoding="utf-8"))
            self.assertIn("client_messages_artifact", cli_event_export)
            self.assertIn("stdout_artifact", cli_event_export)
            self.assertEqual(_sha256_ref(cli_stdout_path), cli_event_export["stdout_artifact"]["sha256"])
            self.assertTrue(
                verify_mcp_stdio_proxy_event_export(
                    cli_event_export,
                    source_messages_path=messages,
                    stdout_artifact_path=cli_stdout_path,
                ).ok
            )
            cli_capture = json.loads(capture_path.read_text(encoding="utf-8"))
            self.assertTrue(verify_mcp_proxy_capture(cli_capture, source_events_path=events_path).ok)

    def test_mcp_stdio_proxy_records_client_notifications_without_responses(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            upstream = tmp / "upstream_mcp.py"
            upstream.write_text(
                "import json, sys\n"
                "for line in sys.stdin:\n"
                "    message = json.loads(line)\n"
                "    if 'id' not in message:\n"
                "        assert message.get('method') == 'notifications/initialized'\n"
                "        continue\n"
                "    params = message.get('params', {})\n"
                "    arguments = params.get('arguments', {})\n"
                "    response = {'jsonrpc': '2.0', 'id': message['id'], 'result': {'status': 'accepted', 'tool': params.get('name'), 'notional_usd': arguments.get('notional_usd')}}\n"
                "    print(json.dumps(response, sort_keys=True), flush=True)\n",
                encoding="utf-8",
            )
            messages = tmp / "client-messages.json"
            stdout_path = tmp / "mcp-proxy-stdio-stdout.jsonl"
            events_path = tmp / "mcp-proxy-stdio-events.json"
            messages.write_text(
                json.dumps(
                    {
                        "messages": [
                            {
                                "jsonrpc": "2.0",
                                "method": "notifications/initialized",
                                "params": {"authorization": "Bearer secret-token", "client": "aitrade-cli"},
                            },
                            {
                                "jsonrpc": "2.0",
                                "id": "tool-call-stdio-001",
                                "method": "tools/call",
                                "params": {"name": "place_shadow_order", "arguments": {"notional_usd": 2500}},
                            },
                        ]
                    },
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

            event_export = build_mcp_stdio_proxy_event_export(
                load_mcp_client_messages(messages),
                upstream_command=[sys.executable, str(upstream)],
                session_id="stdio-session-001",
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/stdio-test",
                upstream_ref="mcp-server:test/upstream",
                captured_at="2026-07-03T12:00:12Z",
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )
            event_result = verify_mcp_stdio_proxy_event_export(
                event_export,
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )
            events_path.write_text(json.dumps(event_export, indent=2, sort_keys=True), encoding="utf-8")
            capture = build_mcp_proxy_capture(
                load_mcp_proxy_events(events_path),
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/stdio-test",
                upstream_ref="mcp-server:test/upstream",
                session_id="stdio-session-001",
                captured_at="2026-07-03T12:00:12Z",
                source_events_path=events_path,
            )
            capture_result = verify_mcp_proxy_capture(capture, source_events_path=events_path)

        self.assertTrue(event_result.ok, event_result.errors)
        self.assertTrue(capture_result.ok, capture_result.errors)
        self.assertEqual(2, event_export["request_count"])
        self.assertEqual(2, event_export["client_message_count"])
        self.assertEqual(1, event_export["client_notification_count"])
        self.assertEqual(1, event_export["response_count"])
        self.assertEqual(1, event_export["server_message_count"])
        self.assertEqual(3, event_export["event_count"])
        self.assertEqual(1, event_export["tool_call_count"])
        self.assertEqual("notifications/initialized", event_export["events"][0]["message"]["method"])
        self.assertEqual("[REDACTED]", event_export["events"][0]["message"]["params"]["authorization"])
        self.assertEqual("server_to_client", event_export["events"][2]["direction"])
        self.assertEqual(1, event_export["client_messages_artifact"]["client_notification_count"])
        self.assertEqual(1, event_export["stdout_artifact"]["response_count"])
        self.assertEqual("accepted", capture["tool_calls"][0]["response"]["status"])

    def test_mcp_stdio_proxy_event_export_replays_tool_call_count(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            upstream = tmp / "upstream_mcp.py"
            upstream.write_text(
                "import json, sys\n"
                "for line in sys.stdin:\n"
                "    message = json.loads(line)\n"
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'result': {'status': 'accepted'}}, sort_keys=True), flush=True)\n",
                encoding="utf-8",
            )
            messages = tmp / "client-messages.json"
            stdout_path = tmp / "mcp-proxy-stdio-stdout.jsonl"
            messages.write_text(
                json.dumps(
                    {
                        "messages": [
                            {
                                "jsonrpc": "2.0",
                                "id": "tool-call-stdio-001",
                                "method": "tools/call",
                                "params": {"name": "place_shadow_order", "arguments": {"notional_usd": 2500}},
                            }
                        ]
                    },
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            event_export = build_mcp_stdio_proxy_event_export(
                load_mcp_client_messages(messages),
                upstream_command=[sys.executable, str(upstream)],
                session_id="stdio-session-001",
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/stdio-test",
                upstream_ref="mcp-server:test/upstream",
                captured_at="2026-07-03T12:00:12Z",
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )
            tampered = copy.deepcopy(event_export)
            tampered["tool_call_count"] = 0
            tampered["export_id"] = content_hash(without_keys(tampered, "export_id"))

            result = verify_mcp_stdio_proxy_event_export(
                tampered,
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("tool_call_count mismatch" in error for error in result.errors), result.errors)

    def test_mcp_stdio_proxy_event_export_rejects_cross_session_response(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            upstream = tmp / "upstream_mcp.py"
            upstream.write_text(
                "import json, sys\n"
                "for line in sys.stdin:\n"
                "    message = json.loads(line)\n"
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'result': {'status': 'accepted'}}, sort_keys=True), flush=True)\n",
                encoding="utf-8",
            )
            messages = tmp / "client-messages.json"
            stdout_path = tmp / "mcp-proxy-stdio-stdout.jsonl"
            messages.write_text(
                json.dumps(
                    {
                        "messages": [
                            {
                                "jsonrpc": "2.0",
                                "id": "tool-call-stdio-001",
                                "method": "tools/call",
                                "params": {"name": "place_shadow_order", "arguments": {"notional_usd": 2500}},
                            }
                        ]
                    },
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            event_export = build_mcp_stdio_proxy_event_export(
                load_mcp_client_messages(messages),
                upstream_command=[sys.executable, str(upstream)],
                session_id="stdio-session-001",
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/stdio-test",
                upstream_ref="mcp-server:test/upstream",
                captured_at="2026-07-03T12:00:12Z",
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )
            tampered = copy.deepcopy(event_export)
            tampered["events"][1]["session_id"] = "stdio-session-other"
            tampered_records = build_mcp_proxy_event_chain(tampered["events"])
            tampered["event_chain_root"] = tampered_records[-1]["event_hash"]
            tampered["export_id"] = content_hash(without_keys(tampered, "export_id"))

            result = verify_mcp_stdio_proxy_event_export(
                tampered,
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )

        self.assertFalse(result.ok)
        self.assertTrue(any("session_id mismatch" in error for error in result.errors), result.errors)

    def test_mcp_stdio_proxy_event_export_replays_stdout_top_level_digest(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            upstream = tmp / "upstream_mcp.py"
            upstream.write_text(
                "import json, sys\n"
                "for line in sys.stdin:\n"
                "    message = json.loads(line)\n"
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'result': {'status': 'accepted'}}, sort_keys=True), flush=True)\n",
                encoding="utf-8",
            )
            messages = tmp / "client-messages.json"
            stdout_path = tmp / "mcp-proxy-stdio-stdout.jsonl"
            messages.write_text(
                json.dumps(
                    {
                        "messages": [
                            {
                                "jsonrpc": "2.0",
                                "id": "tool-call-stdio-001",
                                "method": "tools/call",
                                "params": {"name": "place_shadow_order", "arguments": {"notional_usd": 2500}},
                            }
                        ]
                    },
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            event_export = build_mcp_stdio_proxy_event_export(
                load_mcp_client_messages(messages),
                upstream_command=[sys.executable, str(upstream)],
                session_id="stdio-session-001",
                agent=AGENT,
                contract_hash=CONTRACT_HASH,
                proxy_ref="mcp-proxy:trustai/stdio-test",
                upstream_ref="mcp-server:test/upstream",
                captured_at="2026-07-03T12:00:12Z",
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )
            tampered = copy.deepcopy(event_export)
            tampered["stdout_sha256"] = "sha256:" + "0" * 64
            tampered["stdout_size_bytes"] = 1
            tampered["export_id"] = content_hash(without_keys(tampered, "export_id"))

            result = verify_mcp_stdio_proxy_event_export(
                tampered,
                source_messages_path=messages,
                stdout_artifact_path=stdout_path,
            )

            self.assertFalse(result.ok)
            errors = "\n".join(result.errors)
            self.assertIn("stdout_sha256 mismatch", errors)
            self.assertIn("stdout_size_bytes mismatch", errors)

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
