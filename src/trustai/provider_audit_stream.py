from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .provider_audit import verify_provider_audit_correlation
from .provider_installation import verify_provider_installation_manifest
from .provider_lifecycle import verify_provider_lifecycle_manifest

PROVIDER_AUDIT_STREAM_SCHEMA = "trustai.provider-audit-stream/0.1"
PROVIDER_AUDIT_STREAM_ENTRY_TYPE = "provider_audit.stream_recorded"

AUDIT_STREAM_MODES = {"local-reference", "recorded-provider-stream", "provider-audit-stream", "http-dispatch", "production-design"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ProviderAuditStreamVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_provider_audit_stream_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider audit stream receipt must contain an object")
    return value


def write_provider_audit_stream_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_provider_audit_stream_receipt(
    audit_log: Any,
    *,
    provider: str,
    stream_ref: str,
    endpoint_url: str,
    credential_ref: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    actor_ref: str,
    window_start: str,
    window_end: str,
    audit_log_ref: str | None = None,
    cursor_ref: str | None = None,
    next_cursor_ref: str | None = None,
    provider_installation: dict[str, Any] | None = None,
    lifecycle_manifest: dict[str, Any] | None = None,
    correlation: dict[str, Any] | None = None,
    mode: str = "recorded-provider-stream",
    environment: str = "local",
    recorded_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in AUDIT_STREAM_MODES:
        raise ValueError("mode must be local-reference, recorded-provider-stream, provider-audit-stream, http-dispatch, or production-design")
    normalized_provider = _require_provider(provider)
    for value, field in (
        (stream_ref, "stream_ref"),
        (endpoint_url, "endpoint_url"),
        (credential_ref, "credential_ref"),
        (request_hash, "request_hash"),
        (response_hash, "response_hash"),
        (actor_ref, "actor_ref"),
        (window_start, "window_start"),
        (window_end, "window_end"),
    ):
        _require_text(value, field)
    timestamp = recorded_at or utc_now()
    parse_rfc3339(timestamp)
    start = parse_rfc3339(window_start)
    end = parse_rfc3339(window_end)
    if end < start:
        raise ValueError("window_end must be at or after window_start")
    if not isinstance(response_status, int):
        raise ValueError("response_status must be an integer")
    events = _normalize_audit_events(audit_log)
    if not events:
        raise ValueError("provider audit stream audit_log must contain at least one event")

    body: dict[str, Any] = {
        "schema": PROVIDER_AUDIT_STREAM_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": timestamp,
        "provider": normalized_provider,
        "stream": {
            "stream_ref": stream_ref,
            "audit_log_ref": audit_log_ref or stream_ref,
            "endpoint_url": endpoint_url,
            "window_start": window_start,
            "window_end": window_end,
            "cursor_ref": cursor_ref,
            "next_cursor_ref": next_cursor_ref,
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
            "success": 200 <= response_status < 300,
            "actor_ref": actor_ref,
        },
        "audit_log": {
            "hash": content_hash(audit_log),
            "event_count": len(events),
        },
        "credential": _redacted_ref(credential_ref),
        "bindings": _bindings(
            provider_installation=provider_installation,
            lifecycle_manifest=lifecycle_manifest,
            correlation=correlation,
        ),
        "controls": _controls(
            mode=mode,
            endpoint_url=endpoint_url,
            request_hash=request_hash,
            response_status=response_status,
            response_hash=response_hash,
            credential_ref=credential_ref,
            stream_ref=stream_ref,
            window_start=window_start,
            window_end=window_end,
            cursor_ref=cursor_ref,
            next_cursor_ref=next_cursor_ref,
            provider_installation=provider_installation,
            lifecycle_manifest=lifecycle_manifest,
            correlation=correlation,
        ),
        "limitations": [
            "This receipt records provider audit-log stream or export evidence, provider endpoint hashes, and redacted credential references.",
            "It stores audit-log hashes and event counts, not raw provider credentials or full provider response bodies.",
            "It does not prove continuously operated hosted retrieval unless mode is provider-audit-stream or http-dispatch and paired with deployment, ingress, storage, and monitoring evidence.",
        ],
    }
    receipt_id = content_hash(body)
    return {
        **body,
        "stream_receipt_id": receipt_id,
        "signatures": [sign_value({"stream_receipt_id": receipt_id, "provider_audit_stream": body}, key)],
    }


def verify_provider_audit_stream_receipt(
    receipt: dict[str, Any],
    *,
    audit_log: Any | None = None,
    provider_installation: dict[str, Any] | None = None,
    lifecycle_manifest: dict[str, Any] | None = None,
    correlation: dict[str, Any] | None = None,
    key: str | None = None,
) -> ProviderAuditStreamVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != PROVIDER_AUDIT_STREAM_SCHEMA:
        errors.append(f"unsupported provider audit stream schema: {receipt.get('schema')}")
    body = without_keys(receipt, "stream_receipt_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("stream_receipt_id") != expected_id:
        errors.append("stream_receipt_id does not match canonical provider audit stream body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider audit stream receipt must include at least one signature")
    else:
        signed_value = {"stream_receipt_id": receipt.get("stream_receipt_id"), "provider_audit_stream": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider audit stream signature verification failed")

    try:
        parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"provider audit stream recorded_at invalid: {exc}")

    mode = receipt.get("mode")
    if mode not in AUDIT_STREAM_MODES:
        errors.append("provider audit stream mode is unsupported")
    elif mode not in {"provider-audit-stream", "http-dispatch"}:
        warnings.append(f"provider audit stream mode is {mode}; live hosted provider retrieval is not claimed")

    provider = _normalize_provider(receipt.get("provider"))
    if not provider:
        errors.append("provider audit stream provider is required")

    stream = receipt.get("stream", {})
    if not isinstance(stream, dict):
        errors.append("provider audit stream stream must be an object")
        stream = {}
    for field in ("stream_ref", "audit_log_ref", "endpoint_url", "window_start", "window_end", "request_hash", "response_hash", "actor_ref"):
        if not stream.get(field):
            errors.append(f"provider audit stream stream.{field} is required")
    endpoint_url = str(stream.get("endpoint_url") or "")
    if not _valid_url(endpoint_url):
        errors.append("provider audit stream endpoint_url must be an absolute URL")
    elif not _is_https(endpoint_url):
        errors.append("provider audit stream endpoint_url must use HTTPS")
    for field in ("request_hash", "response_hash"):
        if not _is_hash_ref(str(stream.get(field) or "")):
            errors.append(f"provider audit stream stream.{field} must be a sha256 reference")
    response_status = stream.get("response_status")
    if not isinstance(response_status, int) or response_status < 100 or response_status > 599:
        errors.append("provider audit stream response_status must be an HTTP status code")
    elif stream.get("success") is not (200 <= response_status < 300):
        errors.append("provider audit stream success must match response_status")
    try:
        start = parse_rfc3339(str(stream.get("window_start") or ""))
        end = parse_rfc3339(str(stream.get("window_end") or ""))
        if end < start:
            errors.append("provider audit stream window_end must be at or after window_start")
    except ValueError as exc:
        errors.append(f"provider audit stream window timestamp invalid: {exc}")

    _verify_redacted_ref(receipt.get("credential"), "provider audit stream credential", errors)

    audit_record = receipt.get("audit_log", {})
    if not isinstance(audit_record, dict):
        errors.append("provider audit stream audit_log must be an object")
        audit_record = {}
    if audit_log is None:
        warnings.append("provider audit stream audit log was not supplied; audit log hash and event count were not replayed")
    else:
        try:
            events = _normalize_audit_events(audit_log)
        except ValueError as exc:
            errors.append(f"provider audit stream audit log invalid: {exc}")
            events = []
        if audit_record.get("hash") != content_hash(audit_log):
            errors.append("provider audit stream audit log hash does not match supplied audit log")
        if audit_record.get("event_count") != len(events):
            errors.append("provider audit stream audit log event_count does not match supplied audit log")

    bindings = receipt.get("bindings", {})
    if not isinstance(bindings, dict):
        errors.append("provider audit stream bindings must be an object")
        bindings = {}

    _verify_installation_binding(bindings, provider_installation, provider, key, errors, warnings)
    _verify_lifecycle_binding(bindings, lifecycle_manifest, provider, str(stream.get("stream_ref") or ""), key, errors, warnings)
    _verify_correlation_binding(bindings, correlation, audit_log, provider, key, errors, warnings)

    controls = receipt.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("provider audit stream controls are required")
    _check_no_secret_values(receipt, errors)

    return ProviderAuditStreamVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_audit_stream_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    audit_log: Any | None = None,
    provider_installation: dict[str, Any] | None = None,
    lifecycle_manifest: dict[str, Any] | None = None,
    correlation: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_audit_stream_receipt(
        receipt,
        audit_log=audit_log,
        provider_installation=provider_installation,
        lifecycle_manifest=lifecycle_manifest,
        correlation=correlation,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid provider audit stream receipt: " + "; ".join(result.errors))
    payload = {
        "stream_receipt_id": receipt["stream_receipt_id"],
        "stream_receipt_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "stream": receipt.get("stream"),
        "audit_log": receipt.get("audit_log"),
        "credential": receipt.get("credential"),
        "bindings": receipt.get("bindings"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(PROVIDER_AUDIT_STREAM_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("recorded_at"))


def _bindings(
    *,
    provider_installation: dict[str, Any] | None,
    lifecycle_manifest: dict[str, Any] | None,
    correlation: dict[str, Any] | None,
) -> dict[str, Any]:
    bindings: dict[str, Any] = {}
    if provider_installation is not None:
        audit_log = provider_installation.get("audit_log", {}) if isinstance(provider_installation.get("audit_log"), dict) else {}
        installation = provider_installation.get("installation", {}) if isinstance(provider_installation.get("installation"), dict) else {}
        app = provider_installation.get("app", {}) if isinstance(provider_installation.get("app"), dict) else {}
        bindings["provider_installation"] = {
            "manifest_id": provider_installation.get("manifest_id"),
            "manifest_hash": content_hash(provider_installation),
            "provider": provider_installation.get("provider"),
            "app_ref": app.get("app_ref"),
            "installation_ref": installation.get("installation_ref"),
            "tenant_ref": installation.get("tenant_ref"),
            "audit_log_ref": audit_log.get("ref"),
            "audit_log_scopes": list(audit_log.get("scopes", [])) if isinstance(audit_log.get("scopes"), list) else [],
        }
    if lifecycle_manifest is not None:
        lifecycle = lifecycle_manifest.get("lifecycle", {}) if isinstance(lifecycle_manifest.get("lifecycle"), dict) else {}
        operation_refs = [
            operation.get("operation_ref")
            for operation in lifecycle_manifest.get("operations", [])
            if isinstance(operation, dict) and operation.get("kind") == "audit_log_stream_binding"
        ]
        bindings["provider_lifecycle"] = {
            "lifecycle_manifest_id": lifecycle_manifest.get("lifecycle_manifest_id"),
            "lifecycle_manifest_hash": content_hash(lifecycle_manifest),
            "lifecycle_ref": lifecycle.get("lifecycle_ref"),
            "provider": lifecycle.get("provider"),
            "environment": lifecycle.get("environment"),
            "audit_log_stream_refs": operation_refs,
        }
    if correlation is not None:
        bindings["provider_audit_correlation"] = {
            "correlation_id": correlation.get("correlation_id"),
            "correlation_hash": content_hash(correlation),
            "provider": correlation.get("provider"),
            "audit_log": correlation.get("audit_log"),
            "match_count": len(correlation.get("matches", [])) if isinstance(correlation.get("matches"), list) else 0,
        }
    return bindings


def _verify_installation_binding(
    bindings: dict[str, Any],
    provider_installation: dict[str, Any] | None,
    provider: str | None,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    bound = bindings.get("provider_installation")
    if provider_installation is None:
        if bound:
            warnings.append("provider audit stream installation binding was recorded but source manifest was not supplied")
        else:
            warnings.append("provider audit stream provider installation manifest was not supplied")
        return
    result = verify_provider_installation_manifest(provider_installation, key=key)
    if not result.ok:
        errors.extend(f"provider audit stream installation invalid: {error}" for error in result.errors)
    warnings.extend(f"provider audit stream installation warning: {warning}" for warning in result.warnings)
    expected = _bindings(provider_installation=provider_installation, lifecycle_manifest=None, correlation=None).get("provider_installation")
    if bound != expected:
        errors.append("provider audit stream installation binding does not match supplied manifest")
    if provider and provider_installation.get("provider") != provider:
        errors.append("provider audit stream installation provider does not match receipt provider")
    audit_log = provider_installation.get("audit_log", {}) if isinstance(provider_installation.get("audit_log"), dict) else {}
    if not audit_log.get("ref") or not audit_log.get("scopes"):
        errors.append("provider audit stream installation must include audit_log ref and scopes")


def _verify_lifecycle_binding(
    bindings: dict[str, Any],
    lifecycle_manifest: dict[str, Any] | None,
    provider: str | None,
    stream_ref: str,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    bound = bindings.get("provider_lifecycle")
    if lifecycle_manifest is None:
        if bound:
            warnings.append("provider audit stream lifecycle binding was recorded but source manifest was not supplied")
        else:
            warnings.append("provider audit stream lifecycle manifest was not supplied")
        return
    result = verify_provider_lifecycle_manifest(lifecycle_manifest, key=key)
    if not result.ok:
        errors.extend(f"provider audit stream lifecycle invalid: {error}" for error in result.errors)
    warnings.extend(f"provider audit stream lifecycle warning: {warning}" for warning in result.warnings)
    expected = _bindings(provider_installation=None, lifecycle_manifest=lifecycle_manifest, correlation=None).get("provider_lifecycle")
    if bound != expected:
        errors.append("provider audit stream lifecycle binding does not match supplied manifest")
    lifecycle = lifecycle_manifest.get("lifecycle", {}) if isinstance(lifecycle_manifest.get("lifecycle"), dict) else {}
    if provider and lifecycle.get("provider") != provider:
        errors.append("provider audit stream lifecycle provider does not match receipt provider")
    refs = expected.get("audit_log_stream_refs", []) if isinstance(expected, dict) else []
    if stream_ref not in refs:
        errors.append("provider audit stream stream_ref is not declared by supplied lifecycle manifest")


def _verify_correlation_binding(
    bindings: dict[str, Any],
    correlation: dict[str, Any] | None,
    audit_log: Any | None,
    provider: str | None,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    bound = bindings.get("provider_audit_correlation")
    if correlation is None:
        if bound:
            warnings.append("provider audit stream correlation binding was recorded but source correlation was not supplied")
        return
    result = verify_provider_audit_correlation(correlation, audit_log=audit_log, key=key)
    if not result.ok:
        errors.extend(f"provider audit stream correlation invalid: {error}" for error in result.errors)
    warnings.extend(f"provider audit stream correlation warning: {warning}" for warning in result.warnings)
    expected = _bindings(provider_installation=None, lifecycle_manifest=None, correlation=correlation).get("provider_audit_correlation")
    if bound != expected:
        errors.append("provider audit stream correlation binding does not match supplied correlation")
    if provider and correlation.get("provider") != provider:
        errors.append("provider audit stream correlation provider does not match receipt provider")


def _controls(
    *,
    mode: str,
    endpoint_url: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    credential_ref: str,
    stream_ref: str,
    window_start: str,
    window_end: str,
    cursor_ref: str | None,
    next_cursor_ref: str | None,
    provider_installation: dict[str, Any] | None,
    lifecycle_manifest: dict[str, Any] | None,
    correlation: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    has_window = bool(window_start and window_end)
    return [
        {
            "id": "provider-audit-stream-binding",
            "status": "implemented" if stream_ref else "planned-production",
            "description": "Audit stream receipt is bound to a stable provider audit-log stream reference.",
        },
        {
            "id": "provider-audit-endpoint-evidence",
            "status": "implemented" if _is_https(endpoint_url) and _is_hash_ref(request_hash) and _is_hash_ref(response_hash) and 100 <= response_status <= 599 else "planned-production",
            "description": "Provider audit endpoint, request hash, response status, and response hash are recorded.",
        },
        {
            "id": "redacted-provider-audit-credential",
            "status": "implemented" if credential_ref else "planned-production",
            "description": "Provider audit credentials are represented only by redacted references.",
        },
        {
            "id": "audit-window-and-cursor",
            "status": "implemented" if has_window and (cursor_ref or next_cursor_ref) else "local-reference" if has_window else "planned-production",
            "description": "Audit stream window and optional cursor references delimit replayable provider retrieval scope.",
        },
        {
            "id": "provider-installation-audit-scope",
            "status": "implemented" if provider_installation is not None else "planned-production",
            "description": "Audit stream is bound to provider installation audit-log reference and scopes when supplied.",
        },
        {
            "id": "provider-lifecycle-audit-stream-ref",
            "status": "implemented" if lifecycle_manifest is not None else "planned-production",
            "description": "Audit stream is bound to the provider lifecycle audit_log_stream_binding operation when supplied.",
        },
        {
            "id": "audit-correlation-binding",
            "status": "implemented" if correlation is not None else "not-applicable",
            "description": "Audit stream can bind the retrieved/exported audit log to a TrustAI provider audit correlation receipt.",
        },
        {
            "id": "live-provider-audit-stream",
            "status": "implemented" if mode in {"provider-audit-stream", "http-dispatch"} else "planned-production",
            "description": "Receipt claims live provider audit retrieval only in live modes.",
        },
    ]


def _normalize_audit_events(audit_log: Any) -> list[dict[str, Any]]:
    if isinstance(audit_log, list):
        raw_events = audit_log
    elif isinstance(audit_log, dict):
        raw_events = audit_log.get("events") or audit_log.get("audit_events") or audit_log.get("records")
        if raw_events is None:
            raw_events = [audit_log]
    else:
        raise ValueError("provider audit stream audit_log must contain an object or array")
    if not isinstance(raw_events, list):
        raise ValueError("provider audit stream audit_log events must be an array")
    events: list[dict[str, Any]] = []
    for event in raw_events:
        if not isinstance(event, dict):
            raise ValueError("provider audit stream audit_log events must contain objects")
        events.append(event)
    return events


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _normalize_provider(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    return normalized or None


def _require_provider(value: Any) -> str:
    normalized = _normalize_provider(value)
    if not normalized:
        raise ValueError("provider is required")
    return normalized


def _valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def _is_https(value: str | None) -> bool:
    return bool(value and urlparse(value).scheme.lower() == "https")


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value.removeprefix("sha256:"))
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _require_text(value: str | None, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _check_no_secret_values(value: Any, errors: list[str], *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, item):
                    pass
                elif not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"provider audit stream secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    return key.endswith("_ref") and isinstance(value, str) and bool(value.strip())
