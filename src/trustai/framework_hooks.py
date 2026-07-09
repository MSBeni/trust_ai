from __future__ import annotations

from typing import Any

from .adapters import framework_trace_to_events

FRAMEWORK_HOOK_ENTRYPOINTS = {
    "langgraph": {
        "runtime_package": "langgraph",
        "module_ref": "trustai.framework_hooks",
        "entrypoint_ref": "trustai.framework_hooks:capture_langgraph_trace",
        "collector_hook_ref": "hook:langgraph/0.2",
    },
    "openai_agents": {
        "runtime_package": "openai-agents-python",
        "module_ref": "trustai.framework_hooks",
        "entrypoint_ref": "trustai.framework_hooks:capture_openai_agents_trace",
        "collector_hook_ref": "hook:openai-agents/0.1",
    },
    "claude_agent": {
        "runtime_package": "anthropic-agent-sdk",
        "module_ref": "trustai.framework_hooks",
        "entrypoint_ref": "trustai.framework_hooks:capture_claude_agent_trace",
        "collector_hook_ref": "hook:claude-agent-sdk/0.1",
    },
    "crewai": {
        "runtime_package": "crewai",
        "module_ref": "trustai.framework_hooks",
        "entrypoint_ref": "trustai.framework_hooks:capture_crewai_trace",
        "collector_hook_ref": "hook:crewai/0.130",
    },
    "bedrock": {
        "runtime_package": "aws-bedrock-agent-runtime",
        "module_ref": "trustai.framework_hooks",
        "entrypoint_ref": "trustai.framework_hooks:capture_bedrock_trace",
        "collector_hook_ref": "hook:bedrock/2026-06",
    },
    "vertex": {
        "runtime_package": "google-cloud-aiplatform-agent-runtime",
        "module_ref": "trustai.framework_hooks",
        "entrypoint_ref": "trustai.framework_hooks:capture_vertex_trace",
        "collector_hook_ref": "hook:vertex/2026-06",
    },
}


def capture_framework_trace(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return framework_trace_to_events(payload)


def capture_langgraph_trace(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return capture_framework_trace({**payload, "framework": "langgraph"})


def capture_openai_agents_trace(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return capture_framework_trace({**payload, "framework": "openai_agents"})


def capture_claude_agent_trace(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return capture_framework_trace({**payload, "framework": "claude_agent"})


def capture_crewai_trace(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return capture_framework_trace({**payload, "framework": "crewai"})


def capture_bedrock_trace(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return capture_framework_trace({**payload, "framework": "bedrock"})


def capture_vertex_trace(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return capture_framework_trace({**payload, "framework": "vertex"})