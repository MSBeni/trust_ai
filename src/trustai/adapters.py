from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now
from .chain import EvidenceChain
from .ingest import append_events, normalize_event

ADAPTER_SCHEMA_URL = "trustai.framework-adapter/0.1"
SUPPORTED_FRAMEWORKS = {
    "langgraph",
    "openai_agents",
    "openai",
    "claude_agent",
    "claude",
    "crewai",
    "bedrock",
    "vertex",
}


def load_framework_events(path: str | Path) -> list[dict[str, Any]]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    return framework_payload_to_events(value)


def framework_payload_to_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("framework trace payload must be an object")
    if isinstance(payload.get("traces"), list):
        events: list[dict[str, Any]] = []
        for trace in payload["traces"]:
            events.extend(framework_trace_to_events(trace))
        if not events:
            raise ValueError("framework trace payload did not produce events")
        return events
    return framework_trace_to_events(payload)


def framework_trace_to_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    framework = _framework(payload)
    if framework in {"langgraph"}:
        events = _langgraph_events(payload, framework)
    elif framework in {"openai_agents", "openai"}:
        events = _openai_events(payload, framework)
    elif framework in {"claude_agent", "claude"}:
        events = _claude_events(payload, framework)
    elif framework == "crewai":
        events = _crewai_events(payload, framework)
    elif framework == "bedrock":
        events = _bedrock_events(payload, framework)
    elif framework == "vertex":
        events = _vertex_events(payload, framework)
    else:
        raise ValueError(f"unsupported framework adapter: {framework}")
    if not events:
        raise ValueError(f"{framework} trace did not produce events")
    return events


def append_framework_events(
    chain: EvidenceChain,
    payload: dict[str, Any],
    key: str | None = None,
) -> list[dict[str, Any]]:
    return append_events(chain, framework_payload_to_events(payload), key=key)


def _framework(payload: dict[str, Any]) -> str:
    framework = str(payload.get("framework", "")).strip().lower().replace("-", "_")
    if not framework:
        raise ValueError("framework trace payload missing framework")
    return framework


def _metadata(payload: dict[str, Any]) -> dict[str, Any]:
    agent = payload.get("agent")
    if not isinstance(agent, dict):
        raise ValueError("framework trace payload missing agent")
    contract_hash = payload.get("contract_hash") or payload.get("contractHash")
    if not contract_hash:
        raise ValueError("framework trace payload missing contract_hash")
    return {
        "agent": agent,
        "contract_hash": contract_hash,
        "risk_class": payload.get("risk_class") or payload.get("riskClass") or agent.get("risk_class"),
        "trace_id": payload.get("trace_id")
        or payload.get("traceId")
        or payload.get("run_id")
        or payload.get("runId")
        or content_hash({"framework": payload.get("framework"), "trace": payload.get("trace", payload)})[:32],
        "timestamp": payload.get("timestamp") or payload.get("started_at") or payload.get("created_at"),
    }


def _list(payload: dict[str, Any], *keys: str) -> list[Any]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
    trace = payload.get("trace")
    if isinstance(trace, dict):
        for key in keys:
            value = trace.get(key)
            if isinstance(value, list):
                return value
    return []


def _first(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if mapping.get(key) not in (None, ""):
            return mapping[key]
    return None


def _timestamp(payload: dict[str, Any], item: dict[str, Any]) -> str:
    return (
        _first(item, "timestamp", "time", "created_at", "started_at", "completed_at", "end_time")
        or _metadata(payload).get("timestamp")
        or utc_now()
    )


def _span_id(framework: str, item: dict[str, Any], index: int) -> str:
    return str(
        _first(item, "span_id", "spanId", "id", "run_id", "runId", "node_id", "task_id", "tool_call_id")
        or content_hash({"framework": framework, "index": index, "item": item})[:16]
    )


def _base_attrs(framework: str, item: dict[str, Any], kind: str) -> dict[str, Any]:
    return {
        "trustai.adapter.framework": framework,
        "trustai.adapter.kind": kind,
        "trustai.adapter.payload_hash": content_hash(item),
    }


def _event(
    payload: dict[str, Any],
    framework: str,
    item: dict[str, Any],
    index: int,
    event_name: str,
    attributes: dict[str, Any],
) -> dict[str, Any]:
    meta = _metadata(payload)
    return normalize_event(
        {
            "trace_id": str(meta["trace_id"]),
            "span_id": _span_id(framework, item, index),
            "parent_span_id": _first(item, "parent_span_id", "parentSpanId", "parent_id"),
            "timestamp": _timestamp(payload, item),
            "event_name": event_name,
            "schema_url": ADAPTER_SCHEMA_URL,
            "contract_hash": meta["contract_hash"],
            "agent": meta["agent"],
            "risk_class": meta.get("risk_class"),
            "attributes": {key: value for key, value in attributes.items() if value is not None},
        }
    )


def _tool_event(
    payload: dict[str, Any],
    framework: str,
    item: dict[str, Any],
    index: int,
    tool: dict[str, Any],
) -> dict[str, Any]:
    attributes = {
        **_base_attrs(framework, item, "tool_call"),
        "tool.name": _first(tool, "name", "tool_name", "function_name", "id"),
        "tool.arguments": _first(tool, "arguments", "args", "input", "parameters"),
        "tool.result": _first(tool, "result", "output", "content"),
        "tool.status": _first(tool, "status", "state"),
    }
    return _event(payload, framework, {**item, "tool": tool}, index, "gen_ai.tool.call", attributes)


def _decision_or_step(
    payload: dict[str, Any],
    framework: str,
    item: dict[str, Any],
    index: int,
    *,
    kind: str = "step",
) -> dict[str, Any]:
    decision = _first(item, "decision", "final_answer", "output", "result")
    event_name = "gen_ai.agent.decision" if decision is not None else f"gen_ai.agent.{kind}"
    attributes = {
        **_base_attrs(framework, item, kind),
        "agent.step.name": _first(item, "name", "node", "node_name", "task", "step"),
        "agent.decision": decision,
        "agent.status": _first(item, "status", "state"),
        "agent.input_hash": content_hash(item.get("input")) if "input" in item else None,
        "agent.output_hash": content_hash(item.get("output")) if "output" in item else None,
    }
    return _event(payload, framework, item, index, event_name, attributes)


def _tool_calls(item: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("tool_calls", "toolCalls", "tools"):
        value = item.get(key)
        if isinstance(value, list):
            return [tool for tool in value if isinstance(tool, dict)]
    for key in ("tool_call", "toolCall", "function_call", "tool_use", "toolUse"):
        value = item.get(key)
        if isinstance(value, dict):
            return [value]
    return []


def _langgraph_events(payload: dict[str, Any], framework: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(_list(payload, "nodes", "steps", "events")):
        if not isinstance(item, dict):
            continue
        tools = _tool_calls(item)
        if tools:
            for tool_index, tool in enumerate(tools):
                events.append(_tool_event(payload, framework, item, index * 100 + tool_index, tool))
        if not tools or _first(item, "decision", "output", "result") is not None:
            events.append(_decision_or_step(payload, framework, item, index, kind="node"))
    return events


def _openai_events(payload: dict[str, Any], framework: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(_list(payload, "items", "events", "responses", "steps")):
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type", "")).lower()
        tools = _tool_calls(item)
        if item_type in {"tool_call", "function_call", "tool"} and not tools:
            tools = [item]
        if tools:
            for tool_index, tool in enumerate(tools):
                events.append(_tool_event(payload, framework, item, index * 100 + tool_index, tool))
        elif item_type in {"message", "assistant_message", "response"} or _first(item, "content", "output_text"):
            events.append(
                _event(
                    payload,
                    framework,
                    item,
                    index,
                    "gen_ai.agent.message",
                    {
                        **_base_attrs(framework, item, "message"),
                        "message.role": item.get("role"),
                        "message.content_hash": content_hash(_first(item, "content", "output_text")),
                        "response.id": item.get("response_id") or item.get("id"),
                    },
                )
            )
        else:
            events.append(_decision_or_step(payload, framework, item, index))
    return events


def _claude_events(payload: dict[str, Any], framework: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for message_index, message in enumerate(_list(payload, "messages", "events")):
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        blocks = content if isinstance(content, list) else []
        tool_blocks = [
            block
            for block in blocks
            if isinstance(block, dict) and str(block.get("type", "")).lower() in {"tool_use", "tool_result"}
        ]
        if tool_blocks:
            for block_index, block in enumerate(tool_blocks):
                tool = {
                    "id": block.get("id") or block.get("tool_use_id"),
                    "name": block.get("name"),
                    "input": block.get("input"),
                    "content": block.get("content"),
                    "status": block.get("type"),
                }
                events.append(_tool_event(payload, framework, message, message_index * 100 + block_index, tool))
        if message.get("role") == "assistant" and not tool_blocks:
            events.append(
                _event(
                    payload,
                    framework,
                    message,
                    message_index,
                    "gen_ai.agent.message",
                    {
                        **_base_attrs(framework, message, "message"),
                        "message.role": message.get("role"),
                        "message.content_hash": content_hash(content),
                    },
                )
            )
    return events


def _crewai_events(payload: dict[str, Any], framework: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, task in enumerate(_list(payload, "tasks", "events", "steps")):
        if not isinstance(task, dict):
            continue
        for tool_index, tool in enumerate(_tool_calls(task)):
            events.append(_tool_event(payload, framework, task, index * 100 + tool_index, tool))
        events.append(_decision_or_step(payload, framework, task, index, kind="task"))
    return events


def _bedrock_events(payload: dict[str, Any], framework: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(_list(payload, "invocations", "events", "steps")):
        if not isinstance(item, dict):
            continue
        tools = _tool_calls(item)
        if str(item.get("type", "")).lower() in {"tooluse", "tool_use"} and not tools:
            tools = [item]
        if tools:
            for tool_index, tool in enumerate(tools):
                events.append(_tool_event(payload, framework, item, index * 100 + tool_index, tool))
        else:
            events.append(_decision_or_step(payload, framework, item, index, kind="invocation"))
    return events


def _vertex_events(payload: dict[str, Any], framework: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, item in enumerate(_list(payload, "events", "steps", "function_calls", "functionCalls")):
        if not isinstance(item, dict):
            continue
        tools = _tool_calls(item)
        if str(item.get("type", "")).lower() in {"function_call", "tool_call"} and not tools:
            tools = [item]
        if tools:
            for tool_index, tool in enumerate(tools):
                events.append(_tool_event(payload, framework, item, index * 100 + tool_index, tool))
        else:
            events.append(_decision_or_step(payload, framework, item, index))
    return events
