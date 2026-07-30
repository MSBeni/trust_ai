from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .mcp_gateway import (
    verify_mcp_proxy_capture,
    verify_mcp_stdio_proxy_event_export,
)
from .mcp_gateway_authority import verify_mcp_gateway_authority_evidence_bundle

MCP_GATEWAY_REVIEW_BUNDLE_SCHEMA = "trustai.mcp-gateway-review-bundle/0.1"
MCP_GATEWAY_REVIEW_BUNDLE_ENTRY_TYPE = "mcp.gateway_review_bundle.attested"
MCP_GATEWAY_REVIEW_BUNDLE_MODES = {"offline-review", "proxy-capture-review", "production-review"}


@dataclass
class McpGatewayReviewBundleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_mcp_gateway_review_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("MCP gateway review bundle must contain an object")
    return value


def write_mcp_gateway_review_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def build_mcp_gateway_review_bundle(
    capture: dict[str, Any],
    *,
    source_events_path: str | Path | None = None,
    capture_path: str | Path | None = None,
    stdio_export: dict[str, Any] | None = None,
    stdio_export_path: str | Path | None = None,
    source_messages_path: str | Path | None = None,
    stdout_artifact_path: str | Path | None = None,
    authority_evidence_bundle: dict[str, Any] | None = None,
    authority_evidence_bundle_path: str | Path | None = None,
    mode: str = "offline-review",
    bundle_ref: str,
    reviewer_ref: str,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in MCP_GATEWAY_REVIEW_BUNDLE_MODES:
        raise ValueError(f"mode must be one of {sorted(MCP_GATEWAY_REVIEW_BUNDLE_MODES)}")
    _require_text(bundle_ref, "bundle_ref")
    _require_text(reviewer_ref, "reviewer_ref")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    capture_result = verify_mcp_proxy_capture(capture, source_events_path=source_events_path, key=key)
    if not capture_result.ok:
        raise ValueError("invalid MCP proxy capture source: " + "; ".join(capture_result.errors))
    stdio_result = None
    if stdio_export is not None:
        stdio_result = verify_mcp_stdio_proxy_event_export(
            stdio_export,
            source_messages_path=source_messages_path,
            stdout_artifact_path=stdout_artifact_path,
        )
        if not stdio_result.ok:
            raise ValueError("invalid MCP stdio export source: " + "; ".join(stdio_result.errors))
    authority_result = None
    if authority_evidence_bundle is not None:
        authority_result = verify_mcp_gateway_authority_evidence_bundle(authority_evidence_bundle, key=key)
        if not authority_result.ok:
            raise ValueError("invalid MCP gateway authority evidence bundle source: " + "; ".join(authority_result.errors))

    source_artifacts = _source_artifacts(
        capture_path=capture_path,
        source_events_path=source_events_path,
        stdio_export_path=stdio_export_path,
        source_messages_path=source_messages_path,
        stdout_artifact_path=stdout_artifact_path,
        authority_evidence_bundle_path=authority_evidence_bundle_path,
    )
    body: dict[str, Any] = {
        "schema": MCP_GATEWAY_REVIEW_BUNDLE_SCHEMA,
        "mode": mode,
        "generated_at": timestamp,
        "bundle_ref": bundle_ref,
        "reviewer_ref": reviewer_ref,
        "capture_receipt": capture,
        "capture_binding": _capture_binding(capture),
        "stdio_export": stdio_export,
        "stdio_export_binding": _stdio_binding(stdio_export) if stdio_export is not None else None,
        "authority_evidence_bundle": authority_evidence_bundle,
        "authority_evidence_bundle_binding": _authority_bundle_binding(authority_evidence_bundle) if authority_evidence_bundle is not None else None,
        "source_artifacts": source_artifacts,
        "summary": _summary(capture, stdio_export, authority_evidence_bundle, source_artifacts),
        "controls": _controls(
            mode,
            capture=capture,
            stdio_export=stdio_export,
            authority_evidence_bundle=authority_evidence_bundle,
            source_events_path=source_events_path,
            source_messages_path=source_messages_path,
            stdout_artifact_path=stdout_artifact_path,
        ),
        "limitations": [
            "This bundle packages a signed MCP proxy capture with optional stdio export and authority evidence for offline reviewer handoff.",
            "Retained raw proxy event, client message, and stdout artifact byte replay is verified when those source paths are supplied.",
            "Production-review mode is a review artifact; production MCP authority still requires complete fresh provider-owned authority evidence.",
        ],
    }
    bundle_id = content_hash(body)
    signed_value = {"bundle_id": bundle_id, "mcp_gateway_review_bundle": body}
    return {**body, "bundle_id": bundle_id, "signatures": [sign_value(signed_value, key)]}


def verify_mcp_gateway_review_bundle(
    bundle: dict[str, Any],
    *,
    source_events_path: str | Path | None = None,
    source_messages_path: str | Path | None = None,
    stdout_artifact_path: str | Path | None = None,
    key: str | None = None,
) -> McpGatewayReviewBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if bundle.get("schema") != MCP_GATEWAY_REVIEW_BUNDLE_SCHEMA:
        errors.append(f"unsupported MCP gateway review bundle schema: {bundle.get('schema')}")
    body = without_keys(bundle, "bundle_id", "signatures")
    if bundle.get("bundle_id") != content_hash(body):
        errors.append("bundle_id does not match canonical MCP gateway review bundle body")
    signatures = bundle.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append("MCP gateway review bundle must include at least one signature")
    else:
        signed_value = {"bundle_id": bundle.get("bundle_id"), "mcp_gateway_review_bundle": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("MCP gateway review bundle signature verification failed")
    mode = bundle.get("mode")
    if mode not in MCP_GATEWAY_REVIEW_BUNDLE_MODES:
        errors.append("MCP gateway review bundle mode is unsupported")
    try:
        parse_rfc3339(str(bundle.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"MCP gateway review bundle generated_at invalid: {exc}")
    for field in ("bundle_ref", "reviewer_ref"):
        if not bundle.get(field):
            errors.append(f"MCP gateway review bundle {field} is required")

    capture = bundle.get("capture_receipt")
    if not isinstance(capture, dict):
        errors.append("MCP gateway review bundle capture_receipt must be an object")
        capture = {}
    else:
        capture_result = verify_mcp_proxy_capture(capture, source_events_path=source_events_path, key=key)
        errors.extend(f"review bundle capture invalid: {error}" for error in capture_result.errors)
        warnings.extend(f"review bundle capture warning: {warning}" for warning in capture_result.warnings)
        expected_capture_binding = _capture_binding(capture)
        if bundle.get("capture_binding") != expected_capture_binding:
            errors.append("MCP gateway review bundle capture_binding does not match embedded capture")

    stdio_export = bundle.get("stdio_export")
    if stdio_export is not None:
        if not isinstance(stdio_export, dict):
            errors.append("MCP gateway review bundle stdio_export must be an object")
        else:
            stdio_result = verify_mcp_stdio_proxy_event_export(
                stdio_export,
                source_messages_path=source_messages_path,
                stdout_artifact_path=stdout_artifact_path,
            )
            errors.extend(f"review bundle stdio export invalid: {error}" for error in stdio_result.errors)
            warnings.extend(f"review bundle stdio export warning: {warning}" for warning in stdio_result.warnings)
            if bundle.get("stdio_export_binding") != _stdio_binding(stdio_export):
                errors.append("MCP gateway review bundle stdio_export_binding does not match embedded stdio export")
    elif bundle.get("stdio_export_binding") is not None:
        errors.append("MCP gateway review bundle stdio_export_binding is present without stdio_export")

    authority_bundle = bundle.get("authority_evidence_bundle")
    if authority_bundle is not None:
        if not isinstance(authority_bundle, dict):
            errors.append("MCP gateway review bundle authority_evidence_bundle must be an object")
        else:
            authority_result = verify_mcp_gateway_authority_evidence_bundle(authority_bundle, key=key)
            errors.extend(f"review bundle authority evidence bundle invalid: {error}" for error in authority_result.errors)
            warnings.extend(f"review bundle authority evidence bundle warning: {warning}" for warning in authority_result.warnings)
            if bundle.get("authority_evidence_bundle_binding") != _authority_bundle_binding(authority_bundle):
                errors.append("MCP gateway review bundle authority_evidence_bundle_binding does not match embedded authority evidence bundle")
    elif bundle.get("authority_evidence_bundle_binding") is not None:
        errors.append("MCP gateway review bundle authority_evidence_bundle_binding is present without authority_evidence_bundle")

    source_artifacts = bundle.get("source_artifacts")
    if not isinstance(source_artifacts, list):
        errors.append("MCP gateway review bundle source_artifacts must be a list")
        source_artifacts = []
    expected_summary = _summary(capture, stdio_export if isinstance(stdio_export, dict) else None, authority_bundle if isinstance(authority_bundle, dict) else None, source_artifacts)
    if bundle.get("summary") != expected_summary:
        errors.append("MCP gateway review bundle summary does not match embedded sources")
    expected_controls = _controls(
        str(mode),
        capture=capture,
        stdio_export=stdio_export if isinstance(stdio_export, dict) else None,
        authority_evidence_bundle=authority_bundle if isinstance(authority_bundle, dict) else None,
        source_events_path=source_events_path,
        source_messages_path=source_messages_path,
        stdout_artifact_path=stdout_artifact_path,
    )
    if bundle.get("controls") != expected_controls:
        errors.append("MCP gateway review bundle controls do not match verification inputs")
    if mode == "production-review" and authority_bundle is None:
        errors.append("production-review mode requires an embedded MCP gateway authority evidence bundle")
    return McpGatewayReviewBundleVerification(ok=not errors, errors=errors, warnings=warnings)


def append_mcp_gateway_review_bundle(
    chain: EvidenceChain,
    bundle: dict[str, Any],
    *,
    source_events_path: str | Path | None = None,
    source_messages_path: str | Path | None = None,
    stdout_artifact_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_mcp_gateway_review_bundle(
        bundle,
        source_events_path=source_events_path,
        source_messages_path=source_messages_path,
        stdout_artifact_path=stdout_artifact_path,
        key=key,
    )
    if not result.ok:
        raise ValueError("; ".join(result.errors))
    payload = {
        "schema": MCP_GATEWAY_REVIEW_BUNDLE_ENTRY_TYPE,
        "bundle_id": bundle["bundle_id"],
        "mode": bundle["mode"],
        "bundle_ref": bundle["bundle_ref"],
        "reviewer_ref": bundle["reviewer_ref"],
        "capture_binding": bundle["capture_binding"],
        "stdio_export_binding": bundle.get("stdio_export_binding"),
        "authority_evidence_bundle_binding": bundle.get("authority_evidence_bundle_binding"),
        "summary": bundle["summary"],
        "control_summary": _control_summary(bundle.get("controls", [])),
        "source_artifacts": bundle.get("source_artifacts", []),
    }
    return chain.append(MCP_GATEWAY_REVIEW_BUNDLE_ENTRY_TYPE, payload, key=key, timestamp=bundle["generated_at"])


def _capture_binding(capture: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": capture.get("schema"),
        "capture_id": capture.get("capture_id"),
        "capture_hash": content_hash(capture),
        "captured_at": capture.get("captured_at"),
        "proxy_ref": capture.get("proxy_ref"),
        "upstream_ref": capture.get("upstream_ref"),
        "session_id": capture.get("session_id"),
        "contract_hash": capture.get("contract_hash"),
        "agent": capture.get("agent"),
        "event_count": capture.get("event_count"),
        "tool_call_count": capture.get("tool_call_count"),
        "event_chain_root": capture.get("event_chain_root"),
        "transcript_root": capture.get("transcript_root"),
        "redaction_summary": capture.get("redaction_summary"),
        "proxy_events_artifact": capture.get("proxy_events_artifact"),
        "event_hashes": [event.get("event_hash") for event in capture.get("events", []) if isinstance(event, dict)],
        "tool_call_hashes": [content_hash(call) for call in capture.get("tool_calls", []) if isinstance(call, dict)],
    }


def _stdio_binding(stdio_export: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": stdio_export.get("schema"),
        "export_id": stdio_export.get("export_id"),
        "export_hash": content_hash(stdio_export),
        "captured_at": stdio_export.get("captured_at"),
        "session_id": stdio_export.get("session_id"),
        "request_count": stdio_export.get("request_count"),
        "response_count": stdio_export.get("response_count"),
        "event_count": stdio_export.get("event_count"),
        "tool_call_count": stdio_export.get("tool_call_count"),
        "event_chain_root": stdio_export.get("event_chain_root"),
        "stdout_sha256": stdio_export.get("stdout_sha256"),
        "stdout_size_bytes": stdio_export.get("stdout_size_bytes"),
        "client_messages_artifact": stdio_export.get("client_messages_artifact"),
        "stdout_artifact": stdio_export.get("stdout_artifact"),
    }


def _authority_bundle_binding(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": bundle.get("schema"),
        "bundle_id": bundle.get("bundle_id"),
        "bundle_hash": content_hash(bundle),
        "mode": bundle.get("mode"),
        "environment": bundle.get("environment"),
        "bundle_ref": bundle.get("bundle_ref"),
        "authority_ref": bundle.get("authority_ref"),
        "covered_requirement_count": bundle.get("summary", {}).get("covered_requirement_count"),
        "missing_requirement_count": bundle.get("summary", {}).get("missing_requirement_count"),
    }


def _source_artifacts(**paths: str | Path | None) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for role, path in paths.items():
        if path is not None:
            artifacts.append(_source_artifact(role, path))
    return artifacts


def _source_artifact(role: str, path: str | Path) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        raise ValueError(f"MCP gateway review bundle source artifact missing: {path}")
    data = target.read_bytes()
    body = {
        "role": role.replace("_path", "").replace("_", "-"),
        "path": _artifact_path(target),
        "sha256": "sha256:" + sha256(data).hexdigest(),
        "size_bytes": len(data),
    }
    if _is_json_artifact(target, data):
        try:
            body["content_hash"] = content_hash(json.loads(data.decode("utf-8-sig")))
        except json.JSONDecodeError:
            body["content_hash_error"] = "invalid-json"
    return {**body, "artifact_id": content_hash(body)}


def _summary(
    capture: dict[str, Any],
    stdio_export: dict[str, Any] | None,
    authority_evidence_bundle: dict[str, Any] | None,
    source_artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    redaction_summary = capture.get("redaction_summary") if isinstance(capture, dict) else {}
    authority_summary = authority_evidence_bundle.get("summary", {}) if isinstance(authority_evidence_bundle, dict) else {}
    return {
        "capture_count": 1 if isinstance(capture, dict) and capture else 0,
        "stdio_export_count": 1 if stdio_export is not None else 0,
        "authority_evidence_bundle_count": 1 if authority_evidence_bundle is not None else 0,
        "source_artifact_count": len(source_artifacts),
        "tool_call_count": capture.get("tool_call_count") if isinstance(capture, dict) else None,
        "event_count": capture.get("event_count") if isinstance(capture, dict) else None,
        "redacted_field_count": redaction_summary.get("redacted_field_count") if isinstance(redaction_summary, dict) else None,
        "authority_covered_requirement_count": authority_summary.get("covered_requirement_count"),
        "authority_missing_requirement_count": authority_summary.get("missing_requirement_count"),
    }


def _controls(
    mode: str,
    *,
    capture: dict[str, Any],
    stdio_export: dict[str, Any] | None,
    authority_evidence_bundle: dict[str, Any] | None,
    source_events_path: str | Path | None,
    source_messages_path: str | Path | None,
    stdout_artifact_path: str | Path | None,
) -> list[dict[str, Any]]:
    controls = [
        {
            "id": "proxy-capture-signature-and-chain",
            "status": "passed" if capture else "failed",
            "evidence": capture.get("capture_id") if isinstance(capture, dict) else None,
        },
        {
            "id": "retained-proxy-event-byte-replay",
            "status": "passed" if source_events_path else "deferred",
            "evidence": str(source_events_path) if source_events_path else "source events artifact not supplied during this verification",
        },
        {
            "id": "redaction-summary-recomputed",
            "status": "passed" if isinstance(capture, dict) and capture.get("redaction_summary") else "failed",
            "evidence": capture.get("redaction_summary", {}).get("summary_id") if isinstance(capture, dict) else None,
        },
        {
            "id": "stdio-export-byte-replay",
            "status": "passed" if stdio_export is not None and source_messages_path and stdout_artifact_path else ("deferred" if stdio_export is not None else "not-applicable"),
            "evidence": stdio_export.get("export_id") if isinstance(stdio_export, dict) else None,
        },
        {
            "id": "authority-evidence-bundle",
            "status": "passed" if authority_evidence_bundle is not None else "deferred",
            "evidence": authority_evidence_bundle.get("bundle_id") if isinstance(authority_evidence_bundle, dict) else "production authority evidence not embedded",
        },
        {
            "id": "production-review-authority",
            "status": "passed" if mode != "production-review" or authority_evidence_bundle is not None else "failed",
            "evidence": mode,
        },
    ]
    return controls


def _control_summary(controls: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        status = str(control.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
    return summary


def _is_json_artifact(path: Path, data: bytes) -> bool:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return True
    stripped = data.lstrip()
    return stripped.startswith(b"{") or stripped.startswith(b"[")


def _artifact_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return str(path).replace("\\", "/")


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value
