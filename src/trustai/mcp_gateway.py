from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339
from .chain import EvidenceChain

MCP_TOOL_CALL_ENTRY_TYPE = "mcp.tool_call.evidenced"
MCP_TRANSCRIPT_CHAIN_SCHEMA = "trustai.mcp-transcript-chain/0.1"


def load_mcp_transcript(path: str | Path) -> list[dict[str, Any]]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(value, dict) and "tool_calls" in value:
        value = value["tool_calls"]
    if not isinstance(value, list):
        raise ValueError("MCP transcript must contain a list or tool_calls list")
    return [normalize_tool_call(call) for call in value]


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
