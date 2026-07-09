from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .provider_lifecycle import verify_provider_lifecycle_manifest

PROVIDER_LIFECYCLE_OPERATION_SCHEMA = "trustai.provider-lifecycle-operation/0.1"
PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE = "provider_lifecycle.operation_recorded"

OPERATION_MODES = {"local-reference", "recorded-provider-response", "http-dispatch", "provider-audit-stream", "production-design"}
OPERATION_KINDS = {
    "authorization_callback",
    "token_exchange",
    "token_refresh_policy",
    "credential_rotation",
    "revocation_workflow",
    "uninstall_workflow",
    "audit_log_stream_binding",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ProviderLifecycleOperationVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_provider_lifecycle_operation_receipt(
    *,
    lifecycle_manifest: dict[str, Any],
    operation_kind: str,
    operation_ref: str,
    endpoint_url: str,
    credential_ref: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    actor_ref: str,
    provider_event_ref: str,
    token_ref: str | None = None,
    audit_log_ref: str | None = None,
    idempotency_key: str | None = None,
    mode: str = "recorded-provider-response",
    environment: str = "local",
    recorded_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in OPERATION_MODES:
        raise ValueError("mode must be local-reference, recorded-provider-response, http-dispatch, provider-audit-stream, or production-design")
    if operation_kind not in OPERATION_KINDS:
        raise ValueError("operation_kind is unsupported")
    for value, field in (
        (operation_ref, "operation_ref"),
        (endpoint_url, "endpoint_url"),
        (credential_ref, "credential_ref"),
        (request_hash, "request_hash"),
        (response_hash, "response_hash"),
        (actor_ref, "actor_ref"),
        (provider_event_ref, "provider_event_ref"),
    ):
        _require_text(value, field)
    timestamp = recorded_at or utc_now()
    parse_rfc3339(timestamp)
    if not isinstance(response_status, int):
        raise ValueError("response_status must be an integer")
    lifecycle = _lifecycle_record(lifecycle_manifest)
    operation = {
        "kind": operation_kind,
        "operation_ref": operation_ref,
        "provider_event_ref": provider_event_ref,
        "endpoint_url": endpoint_url,
        "request_hash": request_hash,
        "response_status": response_status,
        "response_hash": response_hash,
        "success": 200 <= response_status < 300,
        "actor_ref": actor_ref,
        "idempotency_key": idempotency_key or content_hash(
            {
                "lifecycle_manifest_id": lifecycle.get("lifecycle_manifest_id"),
                "operation_kind": operation_kind,
                "operation_ref": operation_ref,
                "request_hash": request_hash,
                "endpoint_url": endpoint_url,
            }
        )[:32],
    }
    body: dict[str, Any] = {
        "schema": PROVIDER_LIFECYCLE_OPERATION_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": timestamp,
        "provider": lifecycle.get("provider"),
        "lifecycle": lifecycle,
        "operation": operation,
        "credential": _redacted_ref(credential_ref),
        "controls": _controls(
            mode=mode,
            operation_kind=operation_kind,
            endpoint_url=endpoint_url,
            request_hash=request_hash,
            response_status=response_status,
            response_hash=response_hash,
            credential_ref=credential_ref,
            token_ref=token_ref,
            audit_log_ref=audit_log_ref,
        ),
        "limitations": [
            "This receipt attests a recorded provider lifecycle operation and provider response hash.",
            "It does not reveal provider tokens, private keys, client secrets, or raw request/response bodies.",
            "It does not prove live hosted operation unless the mode is http-dispatch or provider-audit-stream and the surrounding deployment evidence is supplied.",
        ],
    }
    if token_ref:
        body["token_store"] = _redacted_ref(token_ref)
    if audit_log_ref:
        body["audit_log"] = {"ref": audit_log_ref}
    operation_receipt_id = content_hash(body)
    return {
        **body,
        "operation_receipt_id": operation_receipt_id,
        "signatures": [sign_value({"operation_receipt_id": operation_receipt_id, "provider_lifecycle_operation": body}, key)],
    }


def verify_provider_lifecycle_operation_receipt(
    receipt: dict[str, Any],
    *,
    lifecycle_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> ProviderLifecycleOperationVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != PROVIDER_LIFECYCLE_OPERATION_SCHEMA:
        errors.append(f"unsupported provider lifecycle operation schema: {receipt.get('schema')}")
    body = without_keys(receipt, "operation_receipt_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("operation_receipt_id") != expected_id:
        errors.append("operation_receipt_id does not match canonical provider lifecycle operation body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider lifecycle operation receipt must include at least one signature")
    else:
        signed_value = {"operation_receipt_id": receipt.get("operation_receipt_id"), "provider_lifecycle_operation": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider lifecycle operation signature verification failed")

    try:
        parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"provider lifecycle operation recorded_at invalid: {exc}")

    mode = receipt.get("mode")
    if mode not in OPERATION_MODES:
        errors.append("provider lifecycle operation mode is unsupported")
    elif mode not in {"http-dispatch", "provider-audit-stream"}:
        warnings.append(f"provider lifecycle operation mode is {mode}; live hosted provider operation is not claimed")

    lifecycle = receipt.get("lifecycle", {})
    if not isinstance(lifecycle, dict):
        errors.append("provider lifecycle operation lifecycle must be an object")
        lifecycle = {}
    for field in ("lifecycle_manifest_id", "lifecycle_manifest_hash", "lifecycle_ref", "provider", "environment"):
        if not lifecycle.get(field):
            errors.append(f"provider lifecycle operation lifecycle.{field} is required")
    if receipt.get("provider") != lifecycle.get("provider"):
        errors.append("provider lifecycle operation provider must match lifecycle provider")

    operation = receipt.get("operation", {})
    if not isinstance(operation, dict):
        errors.append("provider lifecycle operation operation must be an object")
        operation = {}
    if operation.get("kind") not in OPERATION_KINDS:
        errors.append(f"provider lifecycle operation kind unsupported: {operation.get('kind')}")
    for field in ("operation_ref", "provider_event_ref", "endpoint_url", "request_hash", "response_hash", "actor_ref", "idempotency_key"):
        if not operation.get(field):
            errors.append(f"provider lifecycle operation operation.{field} is required")
    endpoint_url = str(operation.get("endpoint_url") or "")
    if not _valid_url(endpoint_url):
        errors.append("provider lifecycle operation endpoint_url must be an absolute URL")
    elif not _is_https(endpoint_url):
        errors.append("provider lifecycle operation endpoint_url must use HTTPS")
    for field in ("request_hash", "response_hash"):
        if not _is_hash_ref(str(operation.get(field) or "")):
            errors.append(f"provider lifecycle operation operation.{field} must be a sha256 reference")
    response_status = operation.get("response_status")
    if not isinstance(response_status, int) or response_status < 100 or response_status > 599:
        errors.append("provider lifecycle operation response_status must be an HTTP status code")
    elif operation.get("success") is not (200 <= response_status < 300):
        errors.append("provider lifecycle operation success must match response_status")

    _verify_redacted_ref(receipt.get("credential"), "provider lifecycle operation credential", errors)
    if receipt.get("token_store") is not None:
        _verify_redacted_ref(receipt.get("token_store"), "provider lifecycle operation token_store", errors)
    if operation.get("kind") == "audit_log_stream_binding":
        audit_log = receipt.get("audit_log", {})
        if not isinstance(audit_log, dict) or not audit_log.get("ref"):
            errors.append("provider lifecycle operation audit_log.ref is required for audit_log_stream_binding")

    if lifecycle_manifest is None:
        warnings.append("provider lifecycle operation lifecycle manifest was not supplied; lifecycle hash was not replayed")
    else:
        lifecycle_result = verify_provider_lifecycle_manifest(lifecycle_manifest, key=key)
        if not lifecycle_result.ok:
            errors.extend(f"provider lifecycle operation lifecycle invalid: {error}" for error in lifecycle_result.errors)
        warnings.extend(f"provider lifecycle operation lifecycle warning: {warning}" for warning in lifecycle_result.warnings)
        expected_lifecycle = _lifecycle_record(lifecycle_manifest)
        if lifecycle != expected_lifecycle:
            errors.append("provider lifecycle operation lifecycle record does not match supplied lifecycle manifest")
        if not _operation_matches_lifecycle(lifecycle_manifest, str(operation.get("kind") or ""), str(operation.get("operation_ref") or "")):
            errors.append("provider lifecycle operation kind/ref is not declared by supplied lifecycle manifest")

    controls = receipt.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("provider lifecycle operation controls are required")
    _check_no_secret_values(receipt, errors)

    return ProviderLifecycleOperationVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_lifecycle_operation_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    lifecycle_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_lifecycle_operation_receipt(receipt, lifecycle_manifest=lifecycle_manifest, key=key)
    if not result.ok:
        raise ValueError("invalid provider lifecycle operation receipt: " + "; ".join(result.errors))
    payload = {
        "operation_receipt_id": receipt["operation_receipt_id"],
        "operation_receipt_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "lifecycle": receipt.get("lifecycle"),
        "operation": receipt.get("operation"),
        "credential": receipt.get("credential"),
        "token_store": receipt.get("token_store"),
        "audit_log": receipt.get("audit_log"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("recorded_at"))


def load_provider_lifecycle_operation_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider lifecycle operation receipt must contain an object")
    return value


def write_provider_lifecycle_operation_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _lifecycle_record(lifecycle_manifest: dict[str, Any]) -> dict[str, Any]:
    lifecycle = lifecycle_manifest.get("lifecycle", {}) if isinstance(lifecycle_manifest.get("lifecycle"), dict) else {}
    return {
        "lifecycle_manifest_id": lifecycle_manifest.get("lifecycle_manifest_id"),
        "lifecycle_manifest_hash": content_hash(lifecycle_manifest),
        "lifecycle_ref": lifecycle.get("lifecycle_ref"),
        "provider": lifecycle.get("provider"),
        "environment": lifecycle.get("environment"),
        "operation_count": len(lifecycle_manifest.get("operations", [])) if isinstance(lifecycle_manifest.get("operations"), list) else 0,
    }


def _operation_matches_lifecycle(lifecycle_manifest: dict[str, Any], operation_kind: str, operation_ref: str) -> bool:
    for operation in lifecycle_manifest.get("operations", []) if isinstance(lifecycle_manifest.get("operations"), list) else []:
        if isinstance(operation, dict) and operation.get("kind") == operation_kind and operation.get("operation_ref") == operation_ref:
            return True
    return False


def _controls(
    *,
    mode: str,
    operation_kind: str,
    endpoint_url: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    credential_ref: str,
    token_ref: str | None,
    audit_log_ref: str | None,
) -> list[dict[str, Any]]:
    return [
        {
            "id": "lifecycle-operation-binding",
            "status": "implemented" if operation_kind in OPERATION_KINDS else "planned-production",
            "description": "Operation receipt is bound to a declared provider lifecycle operation kind and reference.",
        },
        {
            "id": "provider-endpoint-evidence",
            "status": "implemented" if _is_https(endpoint_url) and _is_hash_ref(request_hash) and _is_hash_ref(response_hash) else "planned-production",
            "description": "Provider endpoint, request hash, response status, and response hash are recorded.",
        },
        {
            "id": "redacted-provider-credential",
            "status": "implemented" if credential_ref else "planned-production",
            "description": "Provider credentials are represented only by redacted references.",
        },
        {
            "id": "redacted-token-reference",
            "status": "implemented" if token_ref else "not-applicable",
            "description": "Provider token material is represented only by a redacted token-store reference when present.",
        },
        {
            "id": "revocation-or-uninstall-operation",
            "status": "implemented" if operation_kind in {"revocation_workflow", "uninstall_workflow"} and 200 <= response_status < 300 else "not-applicable",
            "description": "Revocation and uninstall operations are represented by provider response evidence.",
        },
        {
            "id": "audit-log-stream-operation",
            "status": "implemented" if operation_kind == "audit_log_stream_binding" and audit_log_ref else "not-applicable",
            "description": "Provider audit-log stream operation is tied to an audit-log reference.",
        },
        {
            "id": "live-provider-dispatch",
            "status": "implemented" if mode in {"http-dispatch", "provider-audit-stream"} else "planned-production",
            "description": "Receipt claims live provider dispatch or provider audit stream operation only in live modes.",
        },
    ]


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
                    errors.append(f"provider lifecycle operation secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    return key.endswith("_ref") and isinstance(value, str) and bool(value.strip())
