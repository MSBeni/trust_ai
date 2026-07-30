from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_hook_operation import verify_framework_hook_operation

FRAMEWORK_RUNTIME_AUDIT_SCHEMA = "trustai.framework-runtime-audit/0.1"
FRAMEWORK_RUNTIME_AUDIT_ENTRY_TYPE = "framework_runtime.audit_exported"
FRAMEWORK_RUNTIME_AUDIT_MODES = {"local-export", "provider-export", "production-export"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")
OPERATION_BINDING_EXPECTED_FIELDS = (
    "operation_id",
    "operation_hash",
    "operation_ref",
    "operation_mode",
    "operation_environment",
    "captured_at",
    "framework",
    "runtime_package",
    "runtime_version",
    "runtime_instance_ref",
    "runtime_process_ref",
    "collector_hook_ref",
    "hook_release_hash",
    "release_id",
    "release_hash",
    "matrix_id",
    "matrix_hash",
    "trace_id",
    "source_trace_id",
    "source_trace_hash",
    "event_count",
    "event_root",
    "trace_roots",
    "operation_audit_log_ref",
    "operation_audit_log_root",
)
OPERATION_BINDING_REQUIRED_FIELDS = tuple(
    field for field in OPERATION_BINDING_EXPECTED_FIELDS if field != "runtime_process_ref"
)
AUDIT_EXPORT_EXPECTED_FIELDS = (
    "export_ref",
    "schema",
    "provider",
    "environment",
    "runtime_instance_ref",
    "runtime_process_ref",
    "audit_log_ref",
    "audit_log_root",
    "window_start",
    "window_end",
    "cursor_ref",
    "next_cursor_ref",
    "hash",
    "event_count",
    "event_root",
)
AUDIT_EXPORT_REQUIRED_FIELDS = (
    "export_ref",
    "schema",
    "provider",
    "environment",
    "runtime_instance_ref",
    "audit_log_ref",
    "audit_log_root",
    "window_start",
    "window_end",
    "hash",
    "event_count",
    "event_root",
)
MATCHED_EVENT_EXPECTED_FIELDS = (
    "event_id",
    "event_kind",
    "timestamp",
    "event_hash",
    "framework",
    "trace_id",
    "operation_ref",
    "runtime_instance_ref",
    "collector_hook_ref",
)


@dataclass
class FrameworkRuntimeAuditVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_runtime_audit_export(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime audit export must contain an object")
    return value


def load_framework_runtime_audit_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime audit receipt must contain an object")
    return value


def write_framework_runtime_audit_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_runtime_audit_receipt(
    audit_export: dict[str, Any],
    operation: dict[str, Any],
    trace_payload: dict[str, Any],
    release: dict[str, Any],
    matrix: dict[str, Any],
    *,
    root: str | Path = ".",
    mode: str = "provider-export",
    environment: str = "local",
    provider: str,
    endpoint_url: str,
    credential_ref: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    actor_ref: str,
    exported_at: str | None = None,
    trace_source_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in FRAMEWORK_RUNTIME_AUDIT_MODES:
        raise ValueError(f"mode must be one of {sorted(FRAMEWORK_RUNTIME_AUDIT_MODES)}")
    normalized_provider = _require_provider(provider)
    for value, field in (
        (environment, "environment"),
        (endpoint_url, "endpoint_url"),
        (credential_ref, "credential_ref"),
        (request_hash, "request_hash"),
        (response_hash, "response_hash"),
        (actor_ref, "actor_ref"),
    ):
        _require_text(value, field)
    if not isinstance(response_status, int):
        raise ValueError("framework runtime audit response_status must be an integer")
    timestamp = exported_at or utc_now()
    parse_rfc3339(timestamp)

    operation_result = verify_framework_hook_operation(
        operation,
        trace_payload,
        release,
        matrix,
        root=root,
        trace_source_path=trace_source_path,
        key=key,
    )
    if not operation_result.ok:
        raise ValueError("invalid framework hook operation: " + "; ".join(operation_result.errors))

    events = _normalize_audit_events(audit_export)
    if not events:
        raise ValueError("framework runtime audit export must contain at least one event")
    window_start = _require_text(audit_export.get("window_start"), "audit_export.window_start")
    window_end = _require_text(audit_export.get("window_end"), "audit_export.window_end")
    start = parse_rfc3339(window_start)
    end = parse_rfc3339(window_end)
    if end < start:
        raise ValueError("framework runtime audit export window_end must be at or after window_start")
    audit_log_ref = _require_text(audit_export.get("audit_log_ref"), "audit_export.audit_log_ref")
    audit_log_root = _require_text(audit_export.get("audit_log_root"), "audit_export.audit_log_root")

    binding = _operation_binding(operation)
    matches = _matching_events(events, binding)
    if len(matches) != 1:
        raise ValueError("framework runtime audit export must contain exactly one matching hook operation event")
    matched_event = matches[0]
    _require_audit_event_fields(matched_event)
    _validate_audit_event_against_binding(matched_event, binding)
    _validate_event_timestamp(matched_event, start, end)

    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_AUDIT_SCHEMA,
        "mode": mode,
        "environment": environment,
        "exported_at": timestamp,
        "provider": normalized_provider,
        "operation_binding": binding,
        "audit_export": {
            "export_ref": audit_export.get("export_ref"),
            "schema": audit_export.get("schema"),
            "provider": _normalize_provider(audit_export.get("provider")),
            "environment": audit_export.get("environment"),
            "runtime_instance_ref": audit_export.get("runtime_instance_ref"),
            "runtime_process_ref": audit_export.get("runtime_process_ref"),
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "window_start": window_start,
            "window_end": window_end,
            "cursor_ref": audit_export.get("cursor_ref"),
            "next_cursor_ref": audit_export.get("next_cursor_ref"),
            "hash": content_hash(audit_export),
            "event_count": len(events),
            "event_root": content_hash(events),
        },
        "matched_event": {
            "event_id": matched_event.get("event_id") or matched_event.get("id"),
            "event_kind": matched_event.get("event_kind") or matched_event.get("type") or matched_event.get("event"),
            "timestamp": matched_event.get("timestamp") or matched_event.get("occurred_at"),
            "event_hash": content_hash(matched_event),
            "framework": matched_event.get("framework"),
            "trace_id": matched_event.get("trace_id") or matched_event.get("traceId"),
            "operation_ref": matched_event.get("operation_ref") or matched_event.get("framework_hook_operation_ref"),
            "runtime_instance_ref": matched_event.get("runtime_instance_ref"),
            "collector_hook_ref": matched_event.get("collector_hook_ref"),
        },
        "provider_exchange": {
            "endpoint_url": endpoint_url,
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
            "success": 200 <= response_status < 300,
            "actor_ref": actor_ref,
        },
        "credential": _redacted_ref(credential_ref),
        "controls": _controls(
            mode=mode,
            endpoint_url=endpoint_url,
            request_hash=request_hash,
            response_status=response_status,
            response_hash=response_hash,
            audit_export=audit_export,
            matched_event=matched_event,
        ),
        "limitations": [
            "This receipt binds a framework hook operation to a provider or runtime audit export and provider endpoint evidence.",
            "It stores audit export hashes, event roots, and one matched event hash; raw audit exports are replayed by offline verification when supplied.",
            "It does not prove continuously operated production runtime authority unless mode is production-export and paired with live provider/runtime-owned export evidence.",
        ],
    }
    runtime_audit_id = content_hash(body)
    return {
        **body,
        "runtime_audit_id": runtime_audit_id,
        "signatures": [sign_value({"runtime_audit_id": runtime_audit_id, "framework_runtime_audit": body}, key)],
    }


def verify_framework_runtime_audit_receipt(
    receipt: dict[str, Any],
    *,
    audit_export: dict[str, Any] | None = None,
    operation: dict[str, Any] | None = None,
    trace_payload: dict[str, Any] | None = None,
    release: dict[str, Any] | None = None,
    matrix: dict[str, Any] | None = None,
    root: str | Path = ".",
    trace_source_path: str | Path | None = None,
    key: str | None = None,
) -> FrameworkRuntimeAuditVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != FRAMEWORK_RUNTIME_AUDIT_SCHEMA:
        errors.append(f"unsupported framework runtime audit schema: {receipt.get('schema')}")
    body = without_keys(receipt, "runtime_audit_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("runtime_audit_id") != expected_id:
        errors.append("runtime_audit_id does not match canonical framework runtime audit body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime audit receipt must include at least one signature")
    else:
        signed_value = {"runtime_audit_id": receipt.get("runtime_audit_id"), "framework_runtime_audit": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime audit signature verification failed")

    mode = receipt.get("mode")
    if mode not in FRAMEWORK_RUNTIME_AUDIT_MODES:
        errors.append("framework runtime audit mode is unsupported")
    elif mode != "production-export":
        warnings.append(f"framework runtime audit mode is {mode}; continuously operated production runtime authority is not claimed")

    try:
        parse_rfc3339(str(receipt.get("exported_at") or ""))
    except ValueError as exc:
        errors.append(f"framework runtime audit exported_at invalid: {exc}")

    provider = _normalize_provider(receipt.get("provider"))
    if not provider:
        errors.append("framework runtime audit provider is required")
    operation_binding = receipt.get("operation_binding", {})
    if not isinstance(operation_binding, dict):
        errors.append("framework runtime audit operation_binding must be an object")
        operation_binding = {}
    _verify_operation_binding(
        operation_binding,
        operation,
        trace_payload,
        release,
        matrix,
        root,
        trace_source_path,
        key,
        errors,
        warnings,
    )
    _verify_audit_export_binding(receipt, audit_export, operation_binding, errors, warnings)
    _verify_provider_exchange(receipt.get("provider_exchange"), errors)
    _verify_redacted_ref(receipt.get("credential"), "framework runtime audit credential", errors)

    controls = receipt.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("framework runtime audit controls are required")
    _check_no_secret_values(receipt, errors)
    return FrameworkRuntimeAuditVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_runtime_audit_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    audit_export: dict[str, Any],
    operation: dict[str, Any],
    trace_payload: dict[str, Any],
    release: dict[str, Any],
    matrix: dict[str, Any],
    root: str | Path = ".",
    trace_source_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_framework_runtime_audit_receipt(
        receipt,
        audit_export=audit_export,
        operation=operation,
        trace_payload=trace_payload,
        release=release,
        matrix=matrix,
        root=root,
        trace_source_path=trace_source_path,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid framework runtime audit receipt: " + "; ".join(result.errors))
    payload = {
        "runtime_audit_id": receipt["runtime_audit_id"],
        "runtime_audit_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "exported_at": receipt.get("exported_at"),
        "provider": receipt.get("provider"),
        "operation_binding": receipt.get("operation_binding"),
        "audit_export": receipt.get("audit_export"),
        "matched_event": receipt.get("matched_event"),
        "provider_exchange": receipt.get("provider_exchange"),
        "credential": receipt.get("credential"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(FRAMEWORK_RUNTIME_AUDIT_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("exported_at"))


def _operation_binding(operation: dict[str, Any]) -> dict[str, Any]:
    runtime = operation.get("runtime", {}) if isinstance(operation.get("runtime"), dict) else {}
    hook = operation.get("hook", {}) if isinstance(operation.get("hook"), dict) else {}
    trace = operation.get("trace", {}) if isinstance(operation.get("trace"), dict) else {}
    op = operation.get("operation", {}) if isinstance(operation.get("operation"), dict) else {}
    audit_log = operation.get("audit_log", {}) if isinstance(operation.get("audit_log"), dict) else {}
    release_binding = operation.get("release_binding", {}) if isinstance(operation.get("release_binding"), dict) else {}
    return {
        "operation_id": operation.get("operation_id"),
        "operation_hash": content_hash(operation),
        "operation_ref": op.get("operation_ref"),
        "operation_mode": operation.get("mode"),
        "operation_environment": operation.get("environment"),
        "captured_at": operation.get("captured_at"),
        "framework": runtime.get("framework"),
        "runtime_package": runtime.get("package"),
        "runtime_version": runtime.get("version"),
        "runtime_instance_ref": runtime.get("instance_ref"),
        "runtime_process_ref": runtime.get("process_ref"),
        "collector_hook_ref": hook.get("collector_hook_ref"),
        "hook_release_hash": hook.get("hook_release_hash"),
        "release_id": release_binding.get("release_id"),
        "release_hash": release_binding.get("release_hash"),
        "matrix_id": release_binding.get("matrix_id"),
        "matrix_hash": release_binding.get("matrix_hash"),
        "trace_id": trace.get("trace_id"),
        "source_trace_id": trace.get("source_trace_id"),
        "source_trace_hash": trace.get("source_trace_hash"),
        "event_count": trace.get("event_count"),
        "event_root": trace.get("event_root"),
        "trace_roots": _normalized_list(trace.get("trace_roots")),
        "operation_audit_log_ref": audit_log.get("ref"),
        "operation_audit_log_root": audit_log.get("root"),
    }


def _verify_operation_binding(
    binding: dict[str, Any],
    operation: dict[str, Any] | None,
    trace_payload: dict[str, Any] | None,
    release: dict[str, Any] | None,
    matrix: dict[str, Any] | None,
    root: str | Path,
    trace_source_path: str | Path | None,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    for field in OPERATION_BINDING_EXPECTED_FIELDS:
        if field not in binding:
            errors.append(f"framework runtime audit operation_binding.{field} is required")
    for field in OPERATION_BINDING_REQUIRED_FIELDS:
        if binding.get(field) in (None, "", [], {}):
            errors.append(f"framework runtime audit operation_binding.{field} is required")
    if "trace_roots" in binding and not isinstance(binding.get("trace_roots"), list):
        errors.append("framework runtime audit operation_binding.trace_roots must be an array")
    if "event_count" in binding and (not isinstance(binding.get("event_count"), int) or binding.get("event_count") < 1):
        errors.append("framework runtime audit operation_binding.event_count must be a positive integer")
    missing_sources = [
        source_type
        for source_type, value in (
            ("framework-hook-operation", operation),
            ("framework-trace", trace_payload),
            ("framework-hook-release", release),
            ("framework-adapter-matrix", matrix),
        )
        if value is None
    ]
    if missing_sources:
        errors.append("framework runtime audit operation source artifacts are required for verification: " + ", ".join(missing_sources))
        return
    result = verify_framework_hook_operation(
        operation,
        trace_payload,
        release,
        matrix,
        root=root,
        trace_source_path=trace_source_path,
        key=key,
    )
    if not result.ok:
        errors.extend(f"framework runtime audit operation invalid: {error}" for error in result.errors)
    expected = _operation_binding(operation)
    if binding != expected:
        errors.append("framework runtime audit operation binding does not match supplied framework hook operation")


def _verify_audit_export_binding(
    receipt: dict[str, Any],
    audit_export: dict[str, Any] | None,
    operation_binding: dict[str, Any],
    errors: list[str],
    warnings: list[str],
) -> None:
    record = receipt.get("audit_export", {})
    if not isinstance(record, dict):
        errors.append("framework runtime audit audit_export must be an object")
        record = {}
    for field in AUDIT_EXPORT_EXPECTED_FIELDS:
        if field not in record:
            errors.append(f"framework runtime audit audit_export.{field} is required")
    for field in AUDIT_EXPORT_REQUIRED_FIELDS:
        if record.get(field) in (None, "", [], {}):
            errors.append(f"framework runtime audit audit_export.{field} is required")
    if "event_count" in record and (not isinstance(record.get("event_count"), int) or record.get("event_count") < 1):
        errors.append("framework runtime audit audit_export.event_count must be a positive integer")
    try:
        start = parse_rfc3339(str(record.get("window_start") or ""))
        end = parse_rfc3339(str(record.get("window_end") or ""))
        if end < start:
            errors.append("framework runtime audit window_end must be at or after window_start")
    except ValueError as exc:
        errors.append(f"framework runtime audit window timestamp invalid: {exc}")
        start = end = None
    if not _is_hash_ref(str(record.get("audit_log_root") or "")):
        errors.append("framework runtime audit audit_log_root must be a sha256 reference")
    _verify_matched_event_summary(receipt.get("matched_event"), errors)
    if audit_export is None:
        errors.append("framework runtime audit export is required for verification")
        return
    try:
        events = _normalize_audit_events(audit_export)
    except ValueError as exc:
        errors.append(f"framework runtime audit export invalid: {exc}")
        events = []
    expected_record = {
        "export_ref": audit_export.get("export_ref"),
        "schema": audit_export.get("schema"),
        "provider": _normalize_provider(audit_export.get("provider")),
        "environment": audit_export.get("environment"),
        "runtime_instance_ref": audit_export.get("runtime_instance_ref"),
        "runtime_process_ref": audit_export.get("runtime_process_ref"),
        "audit_log_ref": audit_export.get("audit_log_ref"),
        "audit_log_root": audit_export.get("audit_log_root"),
        "window_start": audit_export.get("window_start"),
        "window_end": audit_export.get("window_end"),
        "cursor_ref": audit_export.get("cursor_ref"),
        "next_cursor_ref": audit_export.get("next_cursor_ref"),
        "hash": content_hash(audit_export),
        "event_count": len(events),
        "event_root": content_hash(events),
    }
    if record != expected_record:
        errors.append("framework runtime audit export binding does not match supplied audit export")
    if record.get("provider") and receipt.get("provider") != record.get("provider"):
        errors.append("framework runtime audit provider does not match audit export provider")
    if record.get("runtime_instance_ref") and operation_binding.get("runtime_instance_ref") != record.get("runtime_instance_ref"):
        errors.append("framework runtime audit runtime instance does not match operation binding")
    if record.get("runtime_process_ref") and operation_binding.get("runtime_process_ref") != record.get("runtime_process_ref"):
        errors.append("framework runtime audit runtime process does not match operation binding")

    matched_record = receipt.get("matched_event", {})
    if not isinstance(matched_record, dict):
        errors.append("framework runtime audit matched_event must be an object")
        matched_record = {}
    matches = _matching_events(events, operation_binding)
    if not matches:
        errors.append("framework runtime audit export does not contain a matching hook operation event")
        return
    if len(matches) > 1:
        errors.append("framework runtime audit export contains multiple matching hook operation events")
        return
    matched_event = matches[0]
    expected_match = {
        "event_id": matched_event.get("event_id") or matched_event.get("id"),
        "event_kind": matched_event.get("event_kind") or matched_event.get("type") or matched_event.get("event"),
        "timestamp": matched_event.get("timestamp") or matched_event.get("occurred_at"),
        "event_hash": content_hash(matched_event),
        "framework": matched_event.get("framework"),
        "trace_id": matched_event.get("trace_id") or matched_event.get("traceId"),
        "operation_ref": matched_event.get("operation_ref") or matched_event.get("framework_hook_operation_ref"),
        "runtime_instance_ref": matched_event.get("runtime_instance_ref"),
        "collector_hook_ref": matched_event.get("collector_hook_ref"),
    }
    if matched_record != expected_match:
        errors.append("framework runtime audit matched event binding does not match supplied audit export")
    try:
        _require_audit_event_fields(matched_event)
        _validate_audit_event_against_binding(matched_event, operation_binding)
        if start is not None and end is not None:
            _validate_event_timestamp(matched_event, start, end)
    except ValueError as exc:
        errors.append(str(exc))


def _verify_matched_event_summary(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime audit matched_event must be an object")
        return
    for field in MATCHED_EVENT_EXPECTED_FIELDS:
        if field not in value:
            errors.append(f"framework runtime audit matched_event.{field} is required")
    for field in MATCHED_EVENT_EXPECTED_FIELDS:
        if value.get(field) in (None, "", [], {}):
            errors.append(f"framework runtime audit matched_event.{field} is required")
    if value.get("event_hash") and not _is_hash_ref(str(value.get("event_hash"))):
        errors.append("framework runtime audit matched_event.event_hash must be a sha256 reference")
    if value.get("timestamp"):
        try:
            parse_rfc3339(str(value.get("timestamp")))
        except ValueError as exc:
            errors.append(f"framework runtime audit matched_event.timestamp invalid: {exc}")


def _verify_provider_exchange(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime audit provider_exchange must be an object")
        return
    for field in ("endpoint_url", "request_hash", "response_status", "response_hash", "actor_ref"):
        if not value.get(field):
            errors.append(f"framework runtime audit provider_exchange.{field} is required")
    endpoint_url = str(value.get("endpoint_url") or "")
    if not _valid_url(endpoint_url):
        errors.append("framework runtime audit endpoint_url must be an absolute URL")
    elif not _is_https(endpoint_url):
        errors.append("framework runtime audit endpoint_url must use HTTPS")
    for field in ("request_hash", "response_hash"):
        if not _is_hash_ref(str(value.get(field) or "")):
            errors.append(f"framework runtime audit provider_exchange.{field} must be a sha256 reference")
    response_status = value.get("response_status")
    if not isinstance(response_status, int) or response_status < 100 or response_status > 599:
        errors.append("framework runtime audit response_status must be an HTTP status code")
    elif value.get("success") is not (200 <= response_status < 300):
        errors.append("framework runtime audit success must match response_status")


def _normalize_audit_events(audit_export: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(audit_export, dict):
        raise ValueError("framework runtime audit export must contain an object")
    raw_events = audit_export.get("events") or audit_export.get("audit_events") or audit_export.get("records")
    if not isinstance(raw_events, list):
        raise ValueError("framework runtime audit export events must be an array")
    events: list[dict[str, Any]] = []
    for event in raw_events:
        if not isinstance(event, dict):
            raise ValueError("framework runtime audit export events must contain objects")
        events.append(event)
    return events


def _matching_events(events: list[dict[str, Any]], binding: dict[str, Any]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    accepted_trace_ids = {
        str(value)
        for value in (binding.get("trace_id"), binding.get("source_trace_id"))
        if value not in (None, "")
    }
    for event in events:
        operation_ref = event.get("operation_ref") or event.get("framework_hook_operation_ref")
        operation_id = event.get("operation_id") or event.get("framework_hook_operation_id")
        operation_matches = operation_ref == binding.get("operation_ref") or operation_id == binding.get("operation_id")
        if not operation_matches:
            continue
        if str(event.get("framework") or "").strip().lower().replace("-", "_") != str(binding.get("framework") or ""):
            continue
        event_trace_id = str(event.get("trace_id") or event.get("traceId") or "")
        if event_trace_id not in accepted_trace_ids:
            continue
        if str(event.get("runtime_instance_ref") or "") != str(binding.get("runtime_instance_ref") or ""):
            continue
        matches.append(event)
    return matches


def _require_audit_event_fields(event: dict[str, Any]) -> None:
    for field in ("framework", "runtime_instance_ref", "collector_hook_ref"):
        if not event.get(field):
            raise ValueError(f"framework runtime audit matched event {field} is required")
    if not (event.get("trace_id") or event.get("traceId")):
        raise ValueError("framework runtime audit matched event trace_id is required")
    if not (event.get("operation_ref") or event.get("framework_hook_operation_ref") or event.get("operation_id")):
        raise ValueError("framework runtime audit matched event operation_ref or operation_id is required")
    if not (event.get("timestamp") or event.get("occurred_at")):
        raise ValueError("framework runtime audit matched event timestamp is required")


def _validate_audit_event_against_binding(event: dict[str, Any], binding: dict[str, Any]) -> None:
    accepted_trace_ids = {
        str(value)
        for value in (binding.get("trace_id"), binding.get("source_trace_id"))
        if value not in (None, "")
    }
    event_trace_id = str(event.get("trace_id") or event.get("traceId") or "")
    if event_trace_id not in accepted_trace_ids:
        raise ValueError("framework runtime audit matched event trace_id does not match operation binding")
    comparisons = {
        "collector_hook_ref": "collector_hook_ref",
        "hook_release_hash": "hook_release_hash",
        "source_trace_hash": "source_trace_hash",
        "event_root": "event_root",
    }
    for event_field, binding_field in comparisons.items():
        if event.get(event_field) and event.get(event_field) != binding.get(binding_field):
            raise ValueError(f"framework runtime audit matched event {event_field} does not match operation binding")
    if event.get("runtime_process_ref") and event.get("runtime_process_ref") != binding.get("runtime_process_ref"):
        raise ValueError("framework runtime audit matched event runtime_process_ref does not match operation binding")
    if event.get("operation_audit_log_ref") and event.get("operation_audit_log_ref") != binding.get("operation_audit_log_ref"):
        raise ValueError("framework runtime audit matched event operation_audit_log_ref does not match operation binding")


def _validate_event_timestamp(event: dict[str, Any], start: Any, end: Any) -> None:
    event_timestamp = parse_rfc3339(str(event.get("timestamp") or event.get("occurred_at") or ""))
    if event_timestamp < start or event_timestamp > end:
        raise ValueError("framework runtime audit matched event timestamp is outside export window")


def _controls(
    *,
    mode: str,
    endpoint_url: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    audit_export: dict[str, Any],
    matched_event: dict[str, Any],
) -> list[dict[str, Any]]:
    has_window = bool(audit_export.get("window_start") and audit_export.get("window_end"))
    has_cursor = bool(audit_export.get("cursor_ref") or audit_export.get("next_cursor_ref"))
    endpoint_bound = _is_https(endpoint_url) and _is_hash_ref(request_hash) and _is_hash_ref(response_hash) and 100 <= response_status <= 599
    production = mode == "production-export" and endpoint_bound and bool(audit_export.get("audit_log_root")) and bool(matched_event)
    return [
        {
            "id": "framework-hook-operation-replayed",
            "status": "passed",
            "description": "Runtime audit receipt is bound to a replay-verified framework hook operation.",
        },
        {
            "id": "runtime-audit-export-replayed",
            "status": "passed",
            "description": "Runtime/provider audit export hash, event count, and event root are recorded for offline replay.",
        },
        {
            "id": "runtime-audit-event-match",
            "status": "passed",
            "description": "One provider/runtime audit event matches the framework, trace, operation, runtime instance, and hook ref.",
        },
        {
            "id": "provider-runtime-endpoint-evidence",
            "status": "passed" if endpoint_bound else "failed",
            "description": "Provider/runtime export endpoint, request hash, response status, and response hash are bound.",
        },
        {
            "id": "audit-window-and-cursor",
            "status": "passed" if has_window and has_cursor else "deferred" if has_window else "failed",
            "description": "Audit export window and cursor references delimit replayable runtime audit retrieval scope.",
        },
        {
            "id": "runtime-audit-log-root",
            "status": "passed" if audit_export.get("audit_log_ref") and audit_export.get("audit_log_root") else "failed",
            "description": "Runtime-owned audit log reference and root are bound to the export.",
        },
        {
            "id": "production-runtime-authority",
            "status": "passed" if production else "deferred",
            "description": "Continuous production runtime authority is claimed only for production export evidence.",
        },
    ]


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _normalize_provider(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    return normalized or None


def _require_provider(value: Any) -> str:
    normalized = _normalize_provider(value)
    if not normalized:
        raise ValueError("framework runtime audit provider is required")
    return normalized


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"framework runtime audit {field} is required")
    return value.strip()


def _normalized_list(values: Any) -> list[str]:
    if not values:
        return []
    if not isinstance(values, list):
        return []
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def _is_https(value: str | None) -> bool:
    return bool(value and urlparse(value).scheme.lower() == "https")


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value.removeprefix("sha256:"))
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _redacted_ref(ref: str | None) -> dict[str, Any]:
    if not ref:
        raise ValueError("framework runtime audit credential_ref is required")
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _check_no_secret_values(value: Any, errors: list[str], *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, item):
                    pass
                elif not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"framework runtime audit secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    return key.endswith("_ref") and isinstance(value, str) and bool(value.strip())
