from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

MCP_TOOL_CALL_ENTRY_TYPE = "mcp.tool_call.evidenced"
MCP_TRANSCRIPT_CHAIN_SCHEMA = "trustai.mcp-transcript-chain/0.1"
MCP_PROXY_CAPTURE_SCHEMA = "trustai.mcp-proxy-capture/0.1"
MCP_PROXY_CAPTURE_ENTRY_TYPE = "mcp.proxy_capture.evidenced"
MCP_PROXY_STDIO_SESSION_SCHEMA = "trustai.mcp-proxy-stdio-session/0.1"
MCP_PROXY_EVENT_CHAIN_SCHEMA = "trustai.mcp-proxy-event-chain/0.1"
MCP_PROXY_DIRECTIONS = {"client_to_server", "server_to_client"}
JSONRPC_VERSION = "2.0"
MCP_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "credentials",
    "password",
    "secret",
    "token",
}


def load_mcp_transcript(path: str | Path) -> list[dict[str, Any]]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(value, dict) and "tool_calls" in value:
        value = value["tool_calls"]
    if not isinstance(value, list):
        raise ValueError("MCP transcript must contain a list or tool_calls list")
    return [normalize_tool_call(call) for call in value]


def load_mcp_proxy_events(path: str | Path) -> list[dict[str, Any]]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    return _mcp_proxy_events_from_value(value)


def _mcp_proxy_events_from_value(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict) and "events" in value:
        value = value["events"]
    if not isinstance(value, list):
        raise ValueError("MCP proxy events must contain a list or events list")
    return [normalize_mcp_proxy_event(event) for event in value]


def load_mcp_proxy_capture(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("MCP proxy capture must be an object")
    return value


def write_mcp_proxy_capture(path: str | Path, capture: dict[str, Any]) -> None:
    capture_path = Path(path)
    capture_path.parent.mkdir(parents=True, exist_ok=True)
    capture_path.write_text(json.dumps(capture, indent=2, sort_keys=True), encoding="utf-8")


def normalize_tool_call(call: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(call, dict):
        raise ValueError("MCP tool call must be an object")
    required = ("session_id", "request_id", "timestamp", "tool_name", "agent", "contract_hash")
    missing = [field for field in required if not call.get(field)]
    if missing:
        raise ValueError(f"MCP tool call missing required fields: {', '.join(missing)}")
    parse_rfc3339(call["timestamp"])
    agent = call["agent"]
    if not isinstance(agent, dict) or not agent.get("name") or not agent.get("version"):
        raise ValueError("MCP tool call agent must include name and version")
    normalized = json.loads(json.dumps(call, sort_keys=True))
    normalized.setdefault("request", {})
    normalized.setdefault("response", {})
    normalized.setdefault("risk_class", agent.get("risk_class"))
    return normalized


def normalize_mcp_proxy_event(event: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("MCP proxy event must be an object")
    required = ("direction", "timestamp", "session_id", "message")
    missing = [field for field in required if not event.get(field)]
    if missing:
        raise ValueError(f"MCP proxy event missing required fields: {', '.join(missing)}")
    if event["direction"] not in MCP_PROXY_DIRECTIONS:
        raise ValueError(f"unsupported MCP proxy event direction: {event['direction']}")
    parse_rfc3339(event["timestamp"])
    if not isinstance(event["message"], dict):
        raise ValueError("MCP proxy event message must be an object")
    normalized = json.loads(json.dumps(event, sort_keys=True))
    normalized["message"] = _redact_sensitive(normalized["message"])
    return normalized


def load_mcp_client_messages(path: str | Path) -> list[dict[str, Any]]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(value, dict) and "messages" in value:
        value = value["messages"]
    if not isinstance(value, list) or not value:
        raise ValueError("MCP client messages must contain a non-empty list or messages list")
    messages: list[dict[str, Any]] = []
    for index, message in enumerate(value):
        if not isinstance(message, dict):
            raise ValueError(f"MCP client message {index} must be an object")
        if message.get("jsonrpc") != JSONRPC_VERSION:
            raise ValueError(f"MCP client message {index} must use JSON-RPC 2.0")
        if "id" not in message or message.get("id") is None:
            raise ValueError(f"MCP client message {index} missing JSON-RPC id")
        messages.append(json.loads(json.dumps(message, sort_keys=True)))
    return messages


def build_mcp_stdio_proxy_event_export(
    client_messages: list[dict[str, Any]],
    *,
    upstream_command: list[str],
    session_id: str,
    agent: dict[str, Any],
    contract_hash: str,
    proxy_ref: str,
    upstream_ref: str,
    captured_at: str | None = None,
    timeout_seconds: float = 30.0,
    source_messages_path: str | Path | None = None,
    stdout_artifact_path: str | Path | None = None,
) -> dict[str, Any]:
    if not upstream_command:
        raise ValueError("MCP stdio proxy upstream_command is required")
    if not session_id:
        raise ValueError("MCP stdio proxy session_id is required")
    timestamp = captured_at or utc_now()
    parse_rfc3339(timestamp)
    messages = _normalize_client_messages(client_messages)
    stdin_payload = "".join(json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n" for message in messages)
    try:
        completed = subprocess.run(
            upstream_command,
            input=stdin_payload,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"MCP stdio upstream timed out after {timeout_seconds} seconds") from exc
    if completed.returncode != 0:
        raise ValueError(f"MCP stdio upstream exited with status {completed.returncode}: {completed.stderr.strip()}")
    stdout_bytes = completed.stdout.encode("utf-8")
    if stdout_artifact_path is not None:
        stdout_target = Path(stdout_artifact_path)
        stdout_target.parent.mkdir(parents=True, exist_ok=True)
        stdout_target.write_bytes(stdout_bytes)
    responses = _parse_mcp_json_lines(completed.stdout, "upstream stdout")
    if len(responses) != len(messages):
        raise ValueError(f"MCP stdio upstream returned {len(responses)} responses for {len(messages)} requests")
    for index, (request, response) in enumerate(zip(messages, responses)):
        if response.get("id") != request.get("id"):
            raise ValueError(f"MCP stdio response {index} id does not match request id")

    raw_events: list[dict[str, Any]] = []
    for request, response in zip(messages, responses):
        raw_events.append({"direction": "client_to_server", "timestamp": timestamp, "session_id": session_id, "message": request})
        raw_events.append({"direction": "server_to_client", "timestamp": timestamp, "session_id": session_id, "message": response})
    event_records = build_mcp_proxy_event_chain(raw_events)
    redacted_events = [record["event"] for record in event_records]
    tool_calls = _tool_calls_from_proxy_records(
        event_records,
        session_id=session_id,
        agent=agent,
        contract_hash=contract_hash,
    )
    stderr_bytes = completed.stderr.encode("utf-8")
    body = {
        "schema": MCP_PROXY_STDIO_SESSION_SCHEMA,
        "captured_at": timestamp,
        "session_id": session_id,
        "proxy_ref": proxy_ref,
        "upstream_ref": upstream_ref,
        "upstream_command": list(upstream_command),
        "request_count": len(messages),
        "response_count": len(responses),
        "event_count": len(redacted_events),
        "tool_call_count": len(tool_calls),
        "event_chain_root": event_records[-1]["event_hash"],
        "stdout_sha256": "sha256:" + sha256(stdout_bytes).hexdigest(),
        "stdout_size_bytes": len(stdout_bytes),
        "stderr_sha256": "sha256:" + sha256(stderr_bytes).hexdigest(),
        "stderr_size_bytes": len(stderr_bytes),
        "events": redacted_events,
        "limitations": [
            "This local stdio proxy export records one line-delimited JSON-RPC exchange with an upstream MCP server command.",
            "It is a reference gateway path for development and evidence capture; production deployments still require hosted service, identity, KMS, audit-log, and provider authority evidence.",
        ],
    }
    if source_messages_path is not None:
        body["client_messages_artifact"] = _mcp_client_messages_artifact(
            source_messages_path,
            [event["message"] for event in redacted_events if event["direction"] == "client_to_server"],
        )
    if stdout_artifact_path is not None:
        body["stdout_artifact"] = _mcp_stdio_stdout_artifact(
            stdout_artifact_path,
            [event["message"] for event in redacted_events if event["direction"] == "server_to_client"],
        )
    return {**body, "export_id": content_hash(body)}


@dataclass
class McpStdioProxyEventExportVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def verify_mcp_stdio_proxy_event_export(
    export: dict[str, Any],
    *,
    source_messages_path: str | Path | None = None,
    stdout_artifact_path: str | Path | None = None,
) -> McpStdioProxyEventExportVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if export.get("schema") != MCP_PROXY_STDIO_SESSION_SCHEMA:
        errors.append(f"unsupported MCP stdio proxy event export schema: {export.get('schema')}")
    body = without_keys(export, "export_id")
    if export.get("export_id") != content_hash(body):
        errors.append("MCP stdio proxy event export_id does not match canonical export body")
    try:
        parse_rfc3339(str(export.get("captured_at") or ""))
    except ValueError as exc:
        errors.append(f"MCP stdio proxy captured_at invalid: {exc}")
    events = export.get("events")
    if not isinstance(events, list) or not events:
        errors.append("MCP stdio proxy event export events must be a non-empty list")
        events = []
    try:
        event_records = build_mcp_proxy_event_chain(events)
    except (TypeError, ValueError) as exc:
        errors.append(f"MCP stdio proxy event export cannot replay event chain: {exc}")
        event_records = []
    if event_records:
        if export.get("event_count") != len(event_records):
            errors.append("MCP stdio proxy event_count mismatch")
        if export.get("event_chain_root") != event_records[-1]["event_hash"]:
            errors.append("MCP stdio proxy event_chain_root mismatch")
    client_messages = [event.get("message") for event in events if isinstance(event, dict) and event.get("direction") == "client_to_server"]
    stdout_messages = [event.get("message") for event in events if isinstance(event, dict) and event.get("direction") == "server_to_client"]
    if export.get("request_count") != len(client_messages):
        errors.append("MCP stdio proxy request_count mismatch")
    if export.get("response_count") != len(stdout_messages):
        errors.append("MCP stdio proxy response_count mismatch")
    client_artifact = export.get("client_messages_artifact")
    if client_artifact is not None:
        if not isinstance(client_artifact, dict):
            errors.append("MCP stdio proxy client_messages_artifact must be an object")
        elif source_messages_path is None:
            errors.append("MCP stdio proxy client_messages_artifact requires source_messages_path for byte replay")
        else:
            try:
                expected_artifact = _mcp_client_messages_artifact(source_messages_path, client_messages)
            except ValueError as exc:
                errors.append(f"MCP stdio proxy client_messages_artifact invalid: {exc}")
            else:
                if client_artifact != expected_artifact:
                    errors.append("MCP stdio proxy client_messages_artifact does not match supplied client message bytes")
    elif source_messages_path is not None:
        warnings.append("MCP stdio proxy client message bytes were supplied but are not bound in this export")
    stdout_artifact = export.get("stdout_artifact")
    if stdout_artifact is not None:
        if not isinstance(stdout_artifact, dict):
            errors.append("MCP stdio proxy stdout_artifact must be an object")
        elif stdout_artifact_path is None:
            errors.append("MCP stdio proxy stdout_artifact requires stdout_artifact_path for byte replay")
        else:
            try:
                expected_artifact = _mcp_stdio_stdout_artifact(stdout_artifact_path, stdout_messages)
            except ValueError as exc:
                errors.append(f"MCP stdio proxy stdout_artifact invalid: {exc}")
            else:
                if stdout_artifact != expected_artifact:
                    errors.append("MCP stdio proxy stdout_artifact does not match supplied stdout bytes")
    elif stdout_artifact_path is not None:
        warnings.append("MCP stdio proxy stdout bytes were supplied but are not bound in this export")
    return McpStdioProxyEventExportVerification(ok=not errors, errors=errors, warnings=warnings)


def _normalize_client_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(messages, list) or not messages:
        raise ValueError("MCP stdio proxy requires at least one client message")
    normalized: list[dict[str, Any]] = []
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise ValueError(f"MCP client message {index} must be an object")
        _require_jsonrpc_2(message, f"MCP client message {index}")
        if "id" not in message or message.get("id") is None:
            raise ValueError(f"MCP client message {index} missing JSON-RPC id")
        normalized.append(json.loads(json.dumps(message, sort_keys=True)))
    return normalized


def _parse_mcp_json_lines(text: str, label: str) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label} line {line_number} is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError(f"{label} line {line_number} must be a JSON object")
        _require_jsonrpc_2(parsed, f"{label} line {line_number}")
        messages.append(parsed)
    return messages


def build_mcp_proxy_capture(
    events: list[dict[str, Any]],
    *,
    agent: dict[str, Any],
    contract_hash: str,
    proxy_ref: str,
    upstream_ref: str,
    session_id: str | None = None,
    captured_at: str | None = None,
    source_events_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if not isinstance(agent, dict) or not agent.get("name") or not agent.get("version"):
        raise ValueError("MCP proxy capture agent must include name and version")
    if not contract_hash:
        raise ValueError("MCP proxy capture contract_hash is required")
    if not proxy_ref:
        raise ValueError("MCP proxy capture proxy_ref is required")
    if not upstream_ref:
        raise ValueError("MCP proxy capture upstream_ref is required")

    event_records = build_mcp_proxy_event_chain(events)
    capture_session_id = session_id or event_records[0]["event"]["session_id"]
    tool_calls = _tool_calls_from_proxy_records(
        event_records,
        session_id=capture_session_id,
        agent=agent,
        contract_hash=contract_hash,
    )
    transcript_records = build_mcp_transcript_chain(tool_calls)
    body = {
        "schema": MCP_PROXY_CAPTURE_SCHEMA,
        "captured_at": captured_at or utc_now(),
        "proxy_ref": proxy_ref,
        "upstream_ref": upstream_ref,
        "session_id": capture_session_id,
        "contract_hash": contract_hash,
        "agent": json.loads(json.dumps(agent, sort_keys=True)),
        "event_count": len(event_records),
        "tool_call_count": len(tool_calls),
        "event_chain_root": event_records[-1]["event_hash"],
        "transcript_root": transcript_records[-1]["transcript_root"],
        "events": event_records,
        "tool_calls": tool_calls,
    }
    if source_events_path is not None:
        body["proxy_events_artifact"] = _mcp_proxy_events_artifact(source_events_path, [record["event"] for record in event_records])
    capture_id = content_hash(body)
    return {
        **body,
        "capture_id": capture_id,
        "signatures": [sign_value({"capture_id": capture_id, "mcp_proxy_capture": body}, key)],
    }


def build_mcp_proxy_event_chain(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized_events = [normalize_mcp_proxy_event(event) for event in events]
    if not normalized_events:
        raise ValueError("MCP proxy capture must contain at least one event")

    records: list[dict[str, Any]] = []
    previous_event_hash: str | None = None
    for index, normalized in enumerate(normalized_events):
        event_body = {
            "schema": MCP_PROXY_EVENT_CHAIN_SCHEMA,
            "sequence": index,
            "direction": normalized["direction"],
            "timestamp": normalized["timestamp"],
            "session_id": normalized["session_id"],
            "message_hash": content_hash(normalized["message"]),
            "previous_event_hash": previous_event_hash,
        }
        event_hash = content_hash(event_body)
        records.append({**event_body, "event_hash": event_hash, "event": normalized})
        previous_event_hash = event_hash
    return records


@dataclass
class McpProxyCaptureVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def verify_mcp_proxy_capture(
    capture: dict[str, Any],
    *,
    source_events_path: str | Path | None = None,
    key: str | None = None,
) -> McpProxyCaptureVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if capture.get("schema") != MCP_PROXY_CAPTURE_SCHEMA:
        errors.append(f"unsupported MCP proxy capture schema: {capture.get('schema')}")

    body = without_keys(capture, "capture_id", "signatures")
    expected_capture_id = content_hash(body)
    if capture.get("capture_id") != expected_capture_id:
        errors.append("capture_id does not match canonical capture body")

    signatures = capture.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append("MCP proxy capture must include at least one signature")
    else:
        signed_value = {"capture_id": capture.get("capture_id"), "mcp_proxy_capture": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("no MCP proxy capture signature verifies")

    try:
        parse_rfc3339(capture.get("captured_at", ""))
    except (TypeError, ValueError) as exc:
        errors.append(f"captured_at invalid: {exc}")

    events = capture.get("events")
    if not isinstance(events, list) or not events:
        errors.append("MCP proxy capture events missing")
        events = []
    event_payloads: list[dict[str, Any]] = []
    for index, record in enumerate(events):
        if not isinstance(record, dict):
            errors.append(f"MCP proxy event record {index} must be an object")
            continue
        event = record.get("event")
        if not isinstance(event, dict):
            errors.append(f"MCP proxy event record {index} missing event")
            continue
        event_payloads.append(event)

    expected_records: list[dict[str, Any]] = []
    if event_payloads:
        try:
            expected_records = build_mcp_proxy_event_chain(event_payloads)
        except (TypeError, ValueError) as exc:
            errors.append(f"MCP proxy event chain cannot replay: {exc}")
        else:
            if capture.get("event_count") != len(expected_records):
                errors.append("event_count mismatch")
            if capture.get("event_chain_root") != expected_records[-1]["event_hash"]:
                errors.append("event_chain_root mismatch")
            for index, (actual, expected) in enumerate(zip(events, expected_records)):
                for field in (
                    "sequence",
                    "direction",
                    "timestamp",
                    "session_id",
                    "message_hash",
                    "previous_event_hash",
                    "event_hash",
                ):
                    if actual.get(field) != expected.get(field):
                        errors.append(f"MCP proxy event record {index} {field} mismatch")

        for index, event in enumerate(event_payloads):
            errors.extend(f"MCP proxy event record {index} {error}" for error in _redaction_errors(event.get("message")))

        artifact = capture.get("proxy_events_artifact")
        if artifact is not None:
            if not isinstance(artifact, dict):
                errors.append("MCP proxy capture proxy_events_artifact must be an object")
            elif source_events_path is None:
                errors.append("MCP proxy capture proxy_events_artifact requires source_events_path for byte replay")
            else:
                try:
                    expected_artifact = _mcp_proxy_events_artifact(source_events_path, event_payloads)
                except ValueError as exc:
                    errors.append(f"MCP proxy capture proxy_events_artifact invalid: {exc}")
                else:
                    if artifact != expected_artifact:
                        errors.append("MCP proxy capture proxy_events_artifact does not match supplied source event bytes")

    if expected_records:
        try:
            expected_tool_calls = _tool_calls_from_proxy_records(
                expected_records,
                session_id=_require_text(capture.get("session_id"), "session_id"),
                agent=capture.get("agent", {}),
                contract_hash=_require_text(capture.get("contract_hash"), "contract_hash"),
            )
        except (TypeError, ValueError) as exc:
            errors.append(f"MCP proxy tool call derivation failed: {exc}")
            expected_tool_calls = []
        actual_tool_calls = capture.get("tool_calls")
        if not isinstance(actual_tool_calls, list):
            errors.append("tool_calls must be a list")
            actual_tool_calls = []
        try:
            normalized_actual = [normalize_tool_call(call) for call in actual_tool_calls]
        except (TypeError, ValueError) as exc:
            errors.append(f"tool_calls invalid: {exc}")
            normalized_actual = []
        if normalized_actual != expected_tool_calls:
            errors.append("tool_calls do not match replayed MCP proxy events")
        if capture.get("tool_call_count") != len(expected_tool_calls):
            errors.append("tool_call_count mismatch")
        if expected_tool_calls:
            expected_transcript = build_mcp_transcript_chain(expected_tool_calls)
            if capture.get("transcript_root") != expected_transcript[-1]["transcript_root"]:
                errors.append("transcript_root mismatch")

    if errors:
        return McpProxyCaptureVerification(ok=False, errors=errors, warnings=warnings)
    if capture.get("tool_call_count", 0) == 0:
        warnings.append("MCP proxy capture contains no tool calls")
    return McpProxyCaptureVerification(ok=True, errors=[], warnings=warnings)


def append_mcp_proxy_capture(
    chain: EvidenceChain,
    capture: dict[str, Any],
    *,
    source_events_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_mcp_proxy_capture(capture, source_events_path=source_events_path, key=key)
    if not result.ok:
        raise ValueError("; ".join(result.errors))
    payload = {
        "schema": MCP_PROXY_CAPTURE_ENTRY_TYPE,
        "capture_id": capture["capture_id"],
        "proxy_ref": capture["proxy_ref"],
        "upstream_ref": capture["upstream_ref"],
        "session_id": capture["session_id"],
        "contract_hash": capture["contract_hash"],
        "agent": capture["agent"],
        "event_count": capture["event_count"],
        "tool_call_count": capture["tool_call_count"],
        "event_chain_root": capture["event_chain_root"],
        "transcript_root": capture["transcript_root"],
        "proxy_events_artifact": capture.get("proxy_events_artifact"),
        "event_hashes": [event["event_hash"] for event in capture["events"]],
        "tool_call_hashes": [content_hash(call) for call in capture["tool_calls"]],
    }
    return chain.append(MCP_PROXY_CAPTURE_ENTRY_TYPE, payload, key=key, timestamp=capture["captured_at"])


def append_mcp_transcript(
    chain: EvidenceChain,
    calls: list[dict[str, Any]],
    key: str | None = None,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for record in build_mcp_transcript_chain(calls):
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
        entries.append(
            chain.append(MCP_TOOL_CALL_ENTRY_TYPE, payload, key=key, timestamp=normalized["timestamp"])
        )
    return entries


def build_mcp_transcript_chain(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized_calls = [normalize_tool_call(call) for call in calls]
    if not normalized_calls:
        raise ValueError("MCP transcript must contain at least one tool call")

    records: list[dict[str, Any]] = []
    previous_node_hash: str | None = None
    call_count = len(normalized_calls)
    for index, normalized in enumerate(normalized_calls):
        tool_call_hash = content_hash(normalized)
        node_body = {
            "schema": MCP_TRANSCRIPT_CHAIN_SCHEMA,
            "sequence": index,
            "call_count": call_count,
            "previous_transcript_node_hash": previous_node_hash,
            "tool_call_hash": tool_call_hash,
        }
        transcript_node_hash = content_hash(node_body)
        records.append(
            {
                **node_body,
                "transcript_node_hash": transcript_node_hash,
                "request_hash": content_hash(normalized.get("request", {})),
                "response_hash": content_hash(normalized.get("response", {})),
                "tool_call": normalized,
            }
        )
        previous_node_hash = transcript_node_hash

    transcript_root = records[-1]["transcript_node_hash"]
    return [{**record, "transcript_root": transcript_root} for record in records]


@dataclass
class McpTranscriptVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def verify_mcp_transcript_entries(
    entries: list[dict[str, Any]],
    contract_hash: str | None = None,
) -> McpTranscriptVerification:
    errors: list[str] = []
    warnings: list[str] = []
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for entry in entries:
        prefix = f"mcp tool call entry {entry.get('index')}"
        payload = entry.get("payload")
        if not isinstance(payload, dict):
            errors.append(f"{prefix} payload missing")
            continue
        tool_call = payload.get("tool_call")
        if not isinstance(tool_call, dict):
            errors.append(f"{prefix} missing tool_call payload")
            continue
        try:
            normalized = normalize_tool_call(tool_call)
        except (TypeError, ValueError) as exc:
            errors.append(f"{prefix} invalid tool_call: {exc}")
            continue

        if contract_hash and payload.get("contract_hash") != contract_hash:
            errors.append(f"{prefix} references a different contract hash")
        for field in ("session_id", "request_id", "tool_name", "contract_hash"):
            if payload.get(field) != normalized.get(field):
                errors.append(f"{prefix} {field} mismatch")
        if entry.get("timestamp") != normalized.get("timestamp"):
            errors.append(f"{prefix} timestamp mismatch")
        if payload.get("request_hash") != content_hash(normalized.get("request", {})):
            errors.append(f"{prefix} request_hash mismatch")
        if payload.get("response_hash") != content_hash(normalized.get("response", {})):
            errors.append(f"{prefix} response_hash mismatch")
        if payload.get("tool_call_hash") != content_hash(normalized):
            errors.append(f"{prefix} tool_call_hash mismatch")

        sequence = payload.get("transcript_sequence")
        call_count = payload.get("transcript_call_count")
        transcript_root = payload.get("transcript_root")
        if not isinstance(sequence, int) or sequence < 0:
            errors.append(f"{prefix} transcript_sequence invalid")
            continue
        if not isinstance(call_count, int) or call_count <= 0:
            errors.append(f"{prefix} transcript_call_count invalid")
            continue
        if not isinstance(transcript_root, str) or not transcript_root:
            errors.append(f"{prefix} transcript_root missing")
            continue
        grouped.setdefault((normalized["session_id"], transcript_root), []).append(entry)

    for (session_id, transcript_root), group_entries in grouped.items():
        group_prefix = f"mcp transcript {session_id}/{transcript_root}"
        payloads = [entry["payload"] for entry in group_entries]
        call_counts = {payload.get("transcript_call_count") for payload in payloads}
        if len(call_counts) != 1:
            errors.append(f"{group_prefix} transcript_call_count inconsistent")
            continue
        call_count = next(iter(call_counts))
        if not isinstance(call_count, int) or call_count <= 0:
            errors.append(f"{group_prefix} transcript_call_count invalid")
            continue
        if len(group_entries) != call_count:
            errors.append(f"{group_prefix} incomplete: expected {call_count} entries, found {len(group_entries)}")
            continue
        sequences = [payload.get("transcript_sequence") for payload in payloads]
        if len(set(sequences)) != len(sequences):
            errors.append(f"{group_prefix} transcript_sequence duplicated")
            continue
        if set(sequences) != set(range(call_count)):
            errors.append(f"{group_prefix} transcript_sequence range mismatch")
            continue

        ordered_entries = sorted(group_entries, key=lambda item: item["payload"]["transcript_sequence"])
        try:
            expected_records = build_mcp_transcript_chain([entry["payload"]["tool_call"] for entry in ordered_entries])
        except (TypeError, ValueError) as exc:
            errors.append(f"{group_prefix} cannot replay transcript: {exc}")
            continue

        for entry, expected in zip(ordered_entries, expected_records):
            prefix = f"mcp tool call entry {entry.get('index')}"
            payload = entry["payload"]
            expected_fields = {
                "transcript_sequence": expected["sequence"],
                "transcript_call_count": expected["call_count"],
                "previous_transcript_node_hash": expected["previous_transcript_node_hash"],
                "transcript_node_hash": expected["transcript_node_hash"],
                "transcript_root": expected["transcript_root"],
                "tool_call_hash": expected["tool_call_hash"],
                "request_hash": expected["request_hash"],
                "response_hash": expected["response_hash"],
            }
            for field, expected_value in expected_fields.items():
                if payload.get(field) != expected_value:
                    errors.append(f"{prefix} {field} mismatch")

    return McpTranscriptVerification(ok=not errors, errors=errors, warnings=warnings)


def _tool_calls_from_proxy_records(
    records: list[dict[str, Any]],
    *,
    session_id: str,
    agent: dict[str, Any],
    contract_hash: str,
) -> list[dict[str, Any]]:
    if not isinstance(agent, dict) or not agent.get("name") or not agent.get("version"):
        raise ValueError("MCP proxy capture agent must include name and version")
    requests: dict[tuple[str, str | int], dict[str, Any]] = {}
    calls: list[dict[str, Any]] = []
    for record in records:
        event = record["event"]
        message = event["message"]
        if event["direction"] == "client_to_server" and message.get("method") == "tools/call":
            request_id, request_key = _jsonrpc_request_identity(message, "MCP tools/call request")
            _require_jsonrpc_2(message, f"MCP tools/call request {request_id}")
            if "result" in message or "error" in message:
                raise ValueError(f"MCP tools/call request {request_id} must not contain result or error")
            if request_key in requests:
                raise ValueError(f"duplicate MCP tools/call request id: {request_id}")
            params = message.get("params")
            if not isinstance(params, dict):
                raise ValueError(f"MCP tools/call request {request_id} params must be an object")
            tool_name = params.get("name") or params.get("tool_name")
            if not isinstance(tool_name, str) or not tool_name:
                raise ValueError(f"MCP tools/call request {request_id} missing tool name")
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                raise ValueError(f"MCP tools/call request {request_id} arguments must be an object")
            requests[request_key] = {
                "record": record,
                "request_id": request_id,
                "tool_name": tool_name,
                "arguments": arguments,
            }
        elif event["direction"] == "server_to_client" and ("result" in message or "error" in message):
            request_id, request_key = _jsonrpc_request_identity(message, "MCP tools/call response")
            if request_key not in requests:
                continue
            request = requests.pop(request_key)
            response_kind, response = _jsonrpc_response_payload(message, request_id)
            call = {
                "session_id": session_id,
                "request_id": request["request_id"],
                "timestamp": request["record"]["timestamp"],
                "tool_name": request["tool_name"],
                "contract_hash": contract_hash,
                "agent": json.loads(json.dumps(agent, sort_keys=True)),
                "risk_class": agent.get("risk_class"),
                "request": request["arguments"],
                "response": response,
                "proxy_capture": {
                    "request_event_hash": request["record"]["event_hash"],
                    "response_event_hash": record["event_hash"],
                    "response_kind": response_kind,
                },
            }
            calls.append(normalize_tool_call(call))
    if requests:
        request_ids = [request["request_id"] for request in requests.values()]
        raise ValueError("unmatched MCP tools/call request ids: " + ", ".join(sorted(request_ids)))
    if not calls:
        raise ValueError("MCP proxy capture must include at least one matched tools/call request/response")
    return calls


def _require_jsonrpc_2(message: dict[str, Any], context: str) -> None:
    if message.get("jsonrpc") != JSONRPC_VERSION:
        raise ValueError(f"{context} must use JSON-RPC 2.0")


def _jsonrpc_request_identity(message: dict[str, Any], context: str) -> tuple[str, tuple[str, str | int]]:
    if "id" not in message or message.get("id") is None:
        raise ValueError(f"{context} missing JSON-RPC id")
    message_id = message["id"]
    if isinstance(message_id, bool):
        raise ValueError(f"{context} JSON-RPC id must be a non-empty string or integer")
    if isinstance(message_id, str):
        if not message_id:
            raise ValueError(f"{context} JSON-RPC id must be a non-empty string or integer")
        return message_id, ("string", message_id)
    if isinstance(message_id, int):
        return f"number:{message_id}", ("number", message_id)
    raise ValueError(f"{context} JSON-RPC id must be a non-empty string or integer")


def _jsonrpc_response_payload(message: dict[str, Any], request_id: str) -> tuple[str, dict[str, Any]]:
    _require_jsonrpc_2(message, f"MCP tools/call response {request_id}")
    if "method" in message or "params" in message:
        raise ValueError(f"MCP tools/call response {request_id} must not contain method or params")
    has_result = "result" in message
    has_error = "error" in message
    if has_result == has_error:
        raise ValueError(f"MCP tools/call response {request_id} must contain exactly one of result or error")
    if has_error:
        error = message["error"]
        if not isinstance(error, dict):
            raise ValueError(f"MCP tools/call response {request_id} error must be an object")
        if not isinstance(error.get("message"), str) or type(error.get("code")) is not int:
            raise ValueError(f"MCP tools/call response {request_id} error must include integer code and message")
        return "error", {"jsonrpc_error": json.loads(json.dumps(error, sort_keys=True))}
    response = message["result"]
    if not isinstance(response, dict):
        response = {"value": response}
    return "result", response


def _redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if _is_sensitive_key(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_sensitive(item)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]
    return value


def _redaction_errors(value: Any, path: str = "message") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if _is_sensitive_key(str(key)) and item != "[REDACTED]":
                errors.append(f"sensitive field {child_path} is not redacted")
            errors.extend(_redaction_errors(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_redaction_errors(item, f"{path}[{index}]"))
    return errors


def _mcp_client_messages_artifact(path: str | Path, expected_redacted_messages: list[dict[str, Any]]) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        raise ValueError(f"MCP client messages artifact file missing: {path}")
    data = target.read_bytes()
    try:
        parsed = json.loads(data.decode("utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"MCP client messages artifact JSON invalid: {exc}") from exc
    messages = _normalize_client_messages(parsed.get("messages") if isinstance(parsed, dict) and "messages" in parsed else parsed)
    redacted_messages = [_redact_sensitive(message) for message in messages]
    if redacted_messages != expected_redacted_messages:
        raise ValueError("MCP client messages artifact content does not match redacted client events")
    body = {
        "path": str(path).replace("\\", "/"),
        "sha256": "sha256:" + sha256(data).hexdigest(),
        "size_bytes": len(data),
        "source_content_hash": content_hash(parsed),
        "redacted_messages_hash": content_hash(redacted_messages),
        "request_count": len(redacted_messages),
        "message_hashes": [content_hash(message) for message in redacted_messages],
    }
    return {**body, "artifact_id": content_hash(body)}


def _mcp_stdio_stdout_artifact(path: str | Path, expected_redacted_responses: list[dict[str, Any]]) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        raise ValueError(f"MCP stdio stdout artifact file missing: {path}")
    data = target.read_bytes()
    text = data.decode("utf-8-sig")
    responses = _parse_mcp_json_lines(text, "MCP stdio stdout artifact")
    normalized_responses = [json.loads(json.dumps(response, sort_keys=True)) for response in responses]
    redacted_responses = [_redact_sensitive(response) for response in normalized_responses]
    if redacted_responses != expected_redacted_responses:
        raise ValueError("MCP stdio stdout artifact content does not match redacted server events")
    body = {
        "path": str(path).replace("\\", "/"),
        "sha256": "sha256:" + sha256(data).hexdigest(),
        "size_bytes": len(data),
        "stdout_content_hash": content_hash(text),
        "redacted_responses_hash": content_hash(redacted_responses),
        "response_count": len(redacted_responses),
        "response_hashes": [content_hash(response) for response in redacted_responses],
    }
    return {**body, "artifact_id": content_hash(body)}


def _mcp_proxy_events_artifact(path: str | Path, normalized_events: list[dict[str, Any]]) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        raise ValueError(f"MCP proxy events artifact file missing: {path}")
    data = target.read_bytes()
    try:
        parsed = json.loads(data.decode("utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"MCP proxy events artifact JSON invalid: {exc}") from exc
    normalized_from_file = _mcp_proxy_events_from_value(parsed)
    expected_normalized = [normalize_mcp_proxy_event(event) for event in normalized_events]
    if normalized_from_file != expected_normalized:
        raise ValueError("MCP proxy events artifact content does not match supplied redacted proxy events")
    event_records = build_mcp_proxy_event_chain(normalized_from_file)
    body = {
        "path": str(path).replace("\\", "/"),
        "sha256": "sha256:" + sha256(data).hexdigest(),
        "size_bytes": len(data),
        "source_content_hash": content_hash(parsed),
        "redacted_events_hash": content_hash(normalized_from_file),
        "event_count": len(normalized_from_file),
        "event_chain_root": event_records[-1]["event_hash"],
    }
    return {**body, "artifact_id": content_hash(body)}


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(part in lowered for part in MCP_SENSITIVE_KEYS)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value
