from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339
from .chain import EvidenceChain

MCP_TOOL_CALL_ENTRY_TYPE = "mcp.tool_call.evidenced"


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
    for call in calls:
        normalized = normalize_tool_call(call)
        payload = {
            "session_id": normalized["session_id"],
            "request_id": normalized["request_id"],
            "tool_name": normalized["tool_name"],
            "contract_hash": normalized["contract_hash"],
            "request_hash": content_hash(normalized.get("request", {})),
            "response_hash": content_hash(normalized.get("response", {})),
            "tool_call_hash": content_hash(normalized),
            "tool_call": normalized,
        }
        entries.append(
            chain.append(MCP_TOOL_CALL_ENTRY_TYPE, payload, key=key, timestamp=normalized["timestamp"])
        )
    return entries
