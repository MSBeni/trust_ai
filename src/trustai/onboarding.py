from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

SELF_SERVE_ONBOARDING_SCHEMA = "trustai.self-serve-onboarding/0.1"
SELF_SERVE_ONBOARDING_ENTRY_TYPE = "onboarding.self_serve.completed"
SDK_SCOPES = {"python", "typescript", "python-typescript"}
GATEWAY_MODES = {"otel-only", "mcp-gateway", "sdk-gateway"}

REQUIRED_SOURCE_PATHS = (
    "docs/specs/python-sdk-v0.1.md",
    "docs/specs/typescript-sdk-v0.1.md",
    "docs/specs/otel-ingest-v0.1.md",
    "docs/specs/mcp-gateway-v0.1.md",
    "src/trustai/cli.py",
    "src/trustai/sdk.py",
    "src/trustai/ingest.py",
    "src/trustai/mcp_gateway.py",
    "src/trustai/proofpack.py",
    "sdk/typescript/src/index.mjs",
    "examples/aitrade/verification-contract.yaml",
    "examples/aitrade/agent-inventory.json",
    "examples/aitrade/delegation.json",
    "examples/aitrade/runtime-action.json",
    "examples/aitrade/shadow-replay.json",
    "examples/aitrade/soak-window.json",
    "examples/aitrade/reexecution-policy.json",
    "examples/aitrade/reexecution-runner-plan.json",
    "examples/aitrade/mcp-transcript.json",
    "examples/aitrade/mcp-stdio-client-messages.json",
    "examples/aitrade/mcp-stdio-upstream.py",
    "examples/aitrade/otel-events.json",
)
QUICKSTART_SOURCE_TARGETS: dict[str, tuple[str, ...]] = {
    "instrument-python-sdk": ("src/trustai/sdk.py", "docs/specs/python-sdk-v0.1.md"),
    "instrument-typescript-sdk": ("sdk/typescript/src/index.mjs", "docs/specs/typescript-sdk-v0.1.md"),
    "initialize-local-chain": ("src/trustai/cli.py",),
    "register-contract": ("src/trustai/cli.py", "examples/aitrade/verification-contract.yaml"),
    "generate-demo-proof-pack": (
        "src/trustai/cli.py",
        "src/trustai/proofpack.py",
        "examples/aitrade/verification-contract.yaml",
        "examples/aitrade/agent-inventory.json",
        "examples/aitrade/otel-events.json",
        "examples/aitrade/mcp-transcript.json",
        "examples/aitrade/delegation.json",
        "examples/aitrade/runtime-action.json",
        "examples/aitrade/shadow-replay.json",
        "examples/aitrade/soak-window.json",
        "examples/aitrade/reexecution-policy.json",
        "examples/aitrade/reexecution-runner-plan.json",
    ),
    "verify-pack": ("src/trustai/cli.py", "src/trustai/proofpack.py"),
    "capture-mcp-transcript": ("src/trustai/cli.py", "src/trustai/mcp_gateway.py", "docs/specs/mcp-gateway-v0.1.md", "examples/aitrade/mcp-transcript.json"),
    "capture-mcp-stdio-proxy": (
        "src/trustai/cli.py",
        "src/trustai/mcp_gateway.py",
        "docs/specs/mcp-gateway-v0.1.md",
        "examples/aitrade/mcp-stdio-client-messages.json",
        "examples/aitrade/mcp-stdio-upstream.py",
    ),
    "ingest-otel-events": ("src/trustai/cli.py", "src/trustai/ingest.py", "docs/specs/otel-ingest-v0.1.md", "examples/aitrade/otel-events.json"),
}

QUICKSTART_GENERATED_TARGETS: dict[str, tuple[str, ...]] = {
    "initialize-local-chain": (".trustai/demo/evidence-chain.json",),
    "generate-demo-proof-pack": (
        ".trustai/demo/evidence-chain.json",
        "artifacts/aitrade-proof-pack.json",
        "artifacts/aitrade-proof-pack.pdf",
        "artifacts/reexecution-runner-evidence.json",
        "artifacts/reexecution-report.json",
        "artifacts/reexecution-report.md",
    ),
    "verify-pack": ("artifacts/aitrade-proof-pack.json",),
    "capture-mcp-transcript": (".trustai/demo/evidence-chain.json",),
    "capture-mcp-stdio-proxy": ("artifacts/mcp-proxy-stdio-events.json", "artifacts/mcp-proxy-stdio-capture.json"),
    "ingest-otel-events": (".trustai/demo/evidence-chain.json",),
}

CLI_ADD_PARSER_PATTERN = re.compile(r'add_parser\("([^"]+)"')


@dataclass
class SelfServeOnboardingVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_self_serve_onboarding_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("self-serve onboarding receipt must contain an object")
    return value


def write_self_serve_onboarding_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_self_serve_onboarding_receipt(
    root: str | Path,
    *,
    onboarding_ref: str,
    tenant_ref: str,
    agent_ref: str,
    requester_ref: str,
    environment: str = "local",
    sdk_scope: str = "python-typescript",
    gateway_mode: str = "sdk-gateway",
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if sdk_scope not in SDK_SCOPES:
        raise ValueError(f"sdk_scope must be one of {sorted(SDK_SCOPES)}")
    if gateway_mode not in GATEWAY_MODES:
        raise ValueError(f"gateway_mode must be one of {sorted(GATEWAY_MODES)}")
    for value, field in (
        (onboarding_ref, "onboarding_ref"),
        (tenant_ref, "tenant_ref"),
        (agent_ref, "agent_ref"),
        (requester_ref, "requester_ref"),
        (environment, "environment"),
    ):
        _require_text(value, field)

    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    root_path = Path(root)
    source_artifacts = [_file_binding(root_path, relative_path) for relative_path in REQUIRED_SOURCE_PATHS]
    quickstart_steps = _quickstart_steps(sdk_scope, gateway_mode)
    quickstart_replay = _quickstart_replay(root_path, quickstart_steps)
    body: dict[str, Any] = {
        "schema": SELF_SERVE_ONBOARDING_SCHEMA,
        "generated_at": timestamp,
        "onboarding_ref": onboarding_ref,
        "tenant_ref": tenant_ref,
        "agent_ref": agent_ref,
        "requester_ref": requester_ref,
        "environment": environment,
        "sdk_scope": sdk_scope,
        "gateway_mode": gateway_mode,
        "source_artifacts": source_artifacts,
        "quickstart_steps": quickstart_steps,
        "quickstart_replay": quickstart_replay,
        "controls": _controls(source_artifacts, quickstart_replay, sdk_scope, gateway_mode),
        "limitations": [
            "This receipt proves the local self-serve SDK, OTel ingest, MCP gateway, examples, and quickstart commands are present and hash-bound.",
            "It does not claim a hosted onboarding portal, metered billing, or live user signup flow.",
            "Production PLG onboarding still requires hosted account creation, identity, billing, usage metering, and support operations evidence.",
        ],
    }
    receipt_id = content_hash(body)
    return {
        **body,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "self_serve_onboarding": body}, key)],
    }


def verify_self_serve_onboarding_receipt(
    receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> SelfServeOnboardingVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if receipt.get("schema") != SELF_SERVE_ONBOARDING_SCHEMA:
        errors.append(f"unsupported self-serve onboarding schema: {receipt.get('schema')}")
    body = without_keys(receipt, "receipt_id", "signatures")
    if receipt.get("receipt_id") != content_hash(body):
        errors.append("receipt_id does not match canonical self-serve onboarding body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("self-serve onboarding receipt must include at least one signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "self_serve_onboarding": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("self-serve onboarding signature verification failed")
    try:
        parse_rfc3339(str(receipt.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"self-serve onboarding generated_at invalid: {exc}")
    for field in ("onboarding_ref", "tenant_ref", "agent_ref", "requester_ref", "environment"):
        if not receipt.get(field):
            errors.append(f"self-serve onboarding {field} is required")
    sdk_scope = receipt.get("sdk_scope")
    if sdk_scope not in SDK_SCOPES:
        errors.append("self-serve onboarding sdk_scope is unsupported")
    gateway_mode = receipt.get("gateway_mode")
    if gateway_mode not in GATEWAY_MODES:
        errors.append("self-serve onboarding gateway_mode is unsupported")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("self-serve onboarding source_artifacts must be a list")
        artifacts = []
    expected_paths = set(REQUIRED_SOURCE_PATHS)
    seen_paths: set[str] = set()
    root_path = Path(root)
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("self-serve onboarding source artifact must be an object")
            continue
        path = str(artifact.get("path") or "")
        if path in seen_paths:
            errors.append(f"duplicate self-serve onboarding source artifact: {path}")
        seen_paths.add(path)
        if path not in expected_paths:
            errors.append(f"unexpected self-serve onboarding source artifact: {path}")
            continue
        try:
            expected = _file_binding(root_path, path)
        except FileNotFoundError:
            errors.append(f"self-serve onboarding source artifact is missing: {path}")
            continue
        if artifact != expected:
            errors.append(f"self-serve onboarding source artifact hash mismatch: {path}")
    missing = sorted(expected_paths - seen_paths)
    if missing:
        errors.append("self-serve onboarding source artifacts missing: " + ", ".join(missing))

    expected_steps = _quickstart_steps(str(sdk_scope), str(gateway_mode)) if sdk_scope in SDK_SCOPES and gateway_mode in GATEWAY_MODES else []
    if receipt.get("quickstart_steps") != expected_steps:
        errors.append("self-serve onboarding quickstart_steps do not match sdk_scope and gateway_mode")
    expected_replay = _quickstart_replay(root_path, expected_steps) if expected_steps else []
    if receipt.get("quickstart_replay") != expected_replay:
        errors.append("self-serve onboarding quickstart_replay does not match local CLI/source replay")
    expected_controls = _controls(artifacts, expected_replay, str(sdk_scope), str(gateway_mode)) if sdk_scope in SDK_SCOPES and gateway_mode in GATEWAY_MODES else []
    if receipt.get("controls") != expected_controls:
        errors.append("self-serve onboarding controls do not match receipt body")
    if gateway_mode == "otel-only":
        warnings.append("self-serve onboarding omits MCP gateway quickstart path")
    return SelfServeOnboardingVerification(ok=not errors, errors=errors, warnings=warnings)


def append_self_serve_onboarding_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_self_serve_onboarding_receipt(receipt, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid self-serve onboarding receipt: " + "; ".join(result.errors))
    payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "onboarding_ref": receipt.get("onboarding_ref"),
        "tenant_ref": receipt.get("tenant_ref"),
        "agent_ref": receipt.get("agent_ref"),
        "requester_ref": receipt.get("requester_ref"),
        "environment": receipt.get("environment"),
        "sdk_scope": receipt.get("sdk_scope"),
        "gateway_mode": receipt.get("gateway_mode"),
        "source_artifact_count": len(receipt.get("source_artifacts", [])),
        "quickstart_step_count": len(receipt.get("quickstart_steps", [])),
        "quickstart_replay_count": len(receipt.get("quickstart_replay", [])),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(SELF_SERVE_ONBOARDING_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("generated_at"))


def _file_binding(root: Path, relative_path: str) -> dict[str, Any]:
    target = root / relative_path
    data = target.read_bytes()
    return {
        "path": relative_path,
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _quickstart_steps(sdk_scope: str, gateway_mode: str) -> list[dict[str, str]]:
    steps = [
        {
            "id": "initialize-local-chain",
            "title": "Initialize a local tenant evidence chain",
            "command": "python -m trustai init --state .trustai/demo/evidence-chain.json --tenant local-self-serve",
        },
        {
            "id": "register-contract",
            "title": "Register a pre-declared verification contract",
            "command": "python -m trustai register examples/aitrade/verification-contract.yaml --state .trustai/demo/evidence-chain.json --tenant local-self-serve",
        },
        {
            "id": "generate-demo-proof-pack",
            "title": "Generate the bundled aitrade proof pack",
            "command": "python -m trustai demo",
        },
        {
            "id": "verify-pack",
            "title": "Verify the resulting proof pack offline",
            "command": "python -m trustai verify artifacts/aitrade-proof-pack.json",
        },
    ]
    if sdk_scope in {"python", "python-typescript"}:
        steps.insert(
            0,
            {
                "id": "instrument-python-sdk",
                "title": "Instrument Python agents with TrustAI SDK events",
                "command": "python -c \"from trustai.sdk import TrustAIClient; print(TrustAIClient)\"",
            },
        )
    if sdk_scope in {"typescript", "python-typescript"}:
        steps.insert(
            1,
            {
                "id": "instrument-typescript-sdk",
                "title": "Instrument Node.js agents with TrustAI SDK events",
                "command": "node sdk/typescript/src/index.mjs --help",
            },
        )
    if gateway_mode in {"mcp-gateway", "sdk-gateway"}:
        steps.append(
            {
                "id": "capture-mcp-transcript",
                "title": "Capture MCP tool-call evidence without agent code changes",
                "command": "python -m trustai mcp-capture examples/aitrade/mcp-transcript.json --state .trustai/demo/evidence-chain.json --tenant local-self-serve",
            }
        )
        steps.append(
            {
                "id": "capture-mcp-stdio-proxy",
                "title": "Run the MCP stdio proxy and write a signed capture",
                "command": "python -m trustai mcp-proxy-stdio examples/aitrade/mcp-stdio-client-messages.json --upstream-command python --upstream-arg examples/aitrade/mcp-stdio-upstream.py --agent-name aitrade-risk-agent --agent-version sha256:0d5bbd8d2357b7d36e0f3f7c5e9a0a3e1f5b7a0d2c4e6f8a9b1c3d5e7f901234 --risk-class trading-prod-write --contract-hash 22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2 --proxy-ref mcp-proxy:trustai/stdio-local --upstream-ref mcp-server:aitrade/stdio-example --session-id stdio-demo-001 --captured-at 2026-07-03T12:00:12Z --events-out artifacts/mcp-proxy-stdio-events.json --out artifacts/mcp-proxy-stdio-capture.json",
            }
        )
    else:
        steps.append(
            {
                "id": "ingest-otel-events",
                "title": "Ingest OTel-style GenAI events directly",
                "command": "python -m trustai ingest examples/aitrade/otel-events.json --state .trustai/demo/evidence-chain.json --tenant local-self-serve",
            }
        )
    return steps


def _quickstart_replay(root: Path, steps: list[dict[str, str]]) -> list[dict[str, Any]]:
    registered_commands = _registered_trustai_commands(root)
    replay: list[dict[str, Any]] = []
    for step in steps:
        step_id = str(step.get("id") or "")
        command = str(step.get("command") or "")
        parsed = _parse_quickstart_command(command, registered_commands)
        source_bindings = [_file_binding(root, path) for path in QUICKSTART_SOURCE_TARGETS.get(step_id, ())]
        command_valid = bool(parsed.get("recognized")) and bool(parsed.get("registered")) and all(binding.get("sha256") for binding in source_bindings)
        replay.append(
            {
                "id": step_id,
                "command": command,
                "tool": parsed.get("tool"),
                "subcommand": parsed.get("subcommand"),
                "recognized": parsed.get("recognized"),
                "registered": parsed.get("registered"),
                "source_bindings": source_bindings,
                "generated_targets": list(QUICKSTART_GENERATED_TARGETS.get(step_id, ())),
                "command_valid": command_valid,
            }
        )
    return replay


def _registered_trustai_commands(root: Path) -> set[str]:
    cli_source = (root / "src/trustai/cli.py").read_text(encoding="utf-8-sig")
    return set(CLI_ADD_PARSER_PATTERN.findall(cli_source))


def _parse_quickstart_command(command: str, registered_commands: set[str]) -> dict[str, Any]:
    try:
        parts = shlex.split(command, posix=False)
    except ValueError:
        return {"tool": None, "subcommand": None, "recognized": False, "registered": False}
    if len(parts) >= 4 and parts[0] == "python" and parts[1] == "-m" and parts[2] == "trustai":
        subcommand = parts[3]
        return {
            "tool": "trustai-cli",
            "subcommand": subcommand,
            "recognized": True,
            "registered": subcommand in registered_commands,
        }
    if len(parts) >= 3 and parts[0] == "python" and parts[1] == "-c" and "trustai.sdk" in command:
        return {"tool": "python-import", "subcommand": "trustai.sdk.TrustAIClient", "recognized": True, "registered": True}
    if len(parts) >= 2 and parts[0] == "node" and parts[1] == "sdk/typescript/src/index.mjs":
        return {"tool": "node-script", "subcommand": "sdk/typescript/src/index.mjs", "recognized": True, "registered": True}
    return {"tool": None, "subcommand": None, "recognized": False, "registered": False}


def _controls(
    source_artifacts: list[dict[str, Any]],
    quickstart_replay: list[dict[str, Any]],
    sdk_scope: str,
    gateway_mode: str,
) -> list[dict[str, str]]:
    paths = {artifact.get("path") for artifact in source_artifacts if isinstance(artifact, dict)}
    replay_ok = bool(quickstart_replay) and all(item.get("command_valid") is True for item in quickstart_replay)
    return [
        {
            "id": "python-sdk-quickstart-bound",
            "status": "passed" if sdk_scope in {"python", "python-typescript"} and "src/trustai/sdk.py" in paths else "not-applicable",
            "detail": "Python SDK source and spec are hash-bound for self-serve instrumentation.",
        },
        {
            "id": "typescript-sdk-quickstart-bound",
            "status": "passed" if sdk_scope in {"typescript", "python-typescript"} and "sdk/typescript/src/index.mjs" in paths else "not-applicable",
            "detail": "TypeScript SDK source and spec are hash-bound for Node.js instrumentation.",
        },
        {
            "id": "otel-ingest-quickstart-bound",
            "status": "passed" if "src/trustai/ingest.py" in paths and "docs/specs/otel-ingest-v0.1.md" in paths and "examples/aitrade/otel-events.json" in paths else "failed",
            "detail": "OTel ingest source, spec, and event example are available for direct self-serve event capture.",
        },
        {
            "id": "mcp-gateway-quickstart-bound",
            "status": "passed"
            if gateway_mode in {"mcp-gateway", "sdk-gateway"}
            and "src/trustai/mcp_gateway.py" in paths
            and "examples/aitrade/mcp-transcript.json" in paths
            and "examples/aitrade/mcp-stdio-client-messages.json" in paths
            and "examples/aitrade/mcp-stdio-upstream.py" in paths
            else "not-applicable",
            "detail": "MCP gateway source, spec, transcript example, and runnable stdio proxy examples are hash-bound when selected.",
        },
        {
            "id": "verification-contract-example-bound",
            "status": "passed" if "examples/aitrade/verification-contract.yaml" in paths else "failed",
            "detail": "A pre-registration contract example is included in the onboarding path.",
        },
        {
            "id": "demo-proof-pack-generation-bound",
            "status": "passed"
            if "src/trustai/proofpack.py" in paths
            and "examples/aitrade/agent-inventory.json" in paths
            and "examples/aitrade/shadow-replay.json" in paths
            and "examples/aitrade/reexecution-runner-plan.json" in paths
            else "failed",
            "detail": "The bundled demo proof-pack compiler and aitrade input fixtures are hash-bound before the offline verify quickstart step.",
        },
        {
            "id": "quickstart-command-replay-bound",
            "status": "passed" if replay_ok and "src/trustai/cli.py" in paths else "failed",
            "detail": "Quickstart commands replay against registered TrustAI CLI subcommands and hash-bound local source targets.",
        },
        {
            "id": "hosted-plg-claim-limited",
            "status": "passed",
            "detail": "Receipt is limited to local SDK/gateway onboarding and does not claim hosted signup, billing, metering, or support operations.",
        },
    ]


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    if not isinstance(controls, list):
        return summary
    for control in controls:
        status = str(control.get("status", "unknown")) if isinstance(control, dict) else "unknown"
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"self-serve onboarding {field} is required")
