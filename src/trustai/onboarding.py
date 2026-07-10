from __future__ import annotations

import hashlib
import json
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
    "src/trustai/sdk.py",
    "src/trustai/ingest.py",
    "src/trustai/mcp_gateway.py",
    "sdk/typescript/src/index.mjs",
    "examples/aitrade/verification-contract.yaml",
    "examples/aitrade/mcp-transcript.json",
)


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
        "quickstart_steps": _quickstart_steps(sdk_scope, gateway_mode),
        "controls": _controls(source_artifacts, sdk_scope, gateway_mode),
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
    expected_controls = _controls(artifacts, str(sdk_scope), str(gateway_mode)) if sdk_scope in SDK_SCOPES and gateway_mode in GATEWAY_MODES else []
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
    else:
        steps.append(
            {
                "id": "ingest-otel-events",
                "title": "Ingest OTel-style GenAI events directly",
                "command": "python -m trustai ingest examples/aitrade/otel-events.json --state .trustai/demo/evidence-chain.json --tenant local-self-serve",
            }
        )
    return steps


def _controls(source_artifacts: list[dict[str, Any]], sdk_scope: str, gateway_mode: str) -> list[dict[str, str]]:
    paths = {artifact.get("path") for artifact in source_artifacts if isinstance(artifact, dict)}
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
            "status": "passed" if "src/trustai/ingest.py" in paths and "docs/specs/otel-ingest-v0.1.md" in paths else "failed",
            "detail": "OTel ingest source and spec are available for direct self-serve event capture.",
        },
        {
            "id": "mcp-gateway-quickstart-bound",
            "status": "passed" if gateway_mode in {"mcp-gateway", "sdk-gateway"} and "src/trustai/mcp_gateway.py" in paths else "not-applicable",
            "detail": "MCP gateway source, spec, and transcript example are hash-bound when selected.",
        },
        {
            "id": "verification-contract-example-bound",
            "status": "passed" if "examples/aitrade/verification-contract.yaml" in paths else "failed",
            "detail": "A pre-registration contract example is included in the onboarding path.",
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
