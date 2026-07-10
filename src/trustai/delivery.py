from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, content_hash, sha256_hex, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

PROVIDER_DELIVERY_SCHEMA = "trustai.provider-delivery/0.1"
PROVIDER_DELIVERY_ENTRY_TYPE = "provider_delivery.recorded"
PROVIDER_DELIVERY_MODES = {"dry-run", "recorded-response", "http-dispatch"}
DEFAULT_DISPATCH_TIMEOUT_SECONDS = 10.0


@dataclass
class ProviderDeliveryVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_provider_payload(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider payload must contain an object")
    return value


def load_provider_delivery(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider delivery file must contain an object")
    return value


def build_provider_delivery(
    payload: dict[str, Any],
    *,
    endpoint_base: str,
    credential_ref: str,
    mode: str = "dry-run",
    response_status: int | None = None,
    response_body: Any | None = None,
    response_headers: dict[str, Any] | None = None,
    request_headers: dict[str, Any] | None = None,
    delivered_at: str | None = None,
    payload_artifact_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _validate_payload(payload)
    if mode not in PROVIDER_DELIVERY_MODES:
        raise ValueError("mode must be dry-run, recorded-response, or http-dispatch")
    if not endpoint_base:
        raise ValueError("endpoint_base is required")
    if not credential_ref:
        raise ValueError("credential_ref is required")
    request = payload["request"]
    request_body = request.get("body")
    body: dict[str, Any] = {
        "schema": PROVIDER_DELIVERY_SCHEMA,
        "mode": mode,
        "provider": payload.get("provider"),
        "payload_schema": payload.get("schema"),
        "payload_hash": _payload_hash(payload),
        "pack_id": payload.get("pack_id"),
        "contract_id": payload.get("contract_id"),
        "contract_hash": payload.get("contract_hash"),
        "request": {
            "method": request.get("method"),
            "path": request.get("path"),
            "body_hash": content_hash(request_body),
        },
        "endpoint_base": endpoint_base.rstrip("/"),
        "target_url": f"{endpoint_base.rstrip('/')}{request.get('path')}",
        "credential": {
            "ref": credential_ref,
            "redacted": True,
        },
        "idempotency_key": content_hash(
            {
                "provider": payload.get("provider"),
                "payload_hash": _payload_hash(payload),
                "target_url": f"{endpoint_base.rstrip('/')}{request.get('path')}",
            }
        )[:32],
        "delivered_at": delivered_at or utc_now(),
    }
    if request_headers:
        redacted_request_headers = _redacted_headers(request_headers)
        body["request"]["header_names"] = sorted(redacted_request_headers)
        body["request"]["headers_hash"] = content_hash(redacted_request_headers)
    if mode in {"recorded-response", "http-dispatch"}:
        if response_status is None:
            raise ValueError("response_status is required for recorded-response and http-dispatch modes")
        response_record = {
            "status": response_status,
            "body_hash": content_hash(response_body),
            "accepted": 200 <= response_status < 300,
        }
        if response_headers is not None:
            response_record["headers_hash"] = content_hash(_redacted_headers(response_headers))
        body["response"] = response_record
    if payload_artifact_path is not None:
        body["payload_artifact"] = _payload_artifact(payload_artifact_path, payload)
    delivery_id = content_hash(body)
    return {
        **body,
        "delivery_id": delivery_id,
        "signatures": [sign_value({"delivery_id": delivery_id, "delivery": body}, key)],
    }


def verify_provider_delivery(
    delivery: dict[str, Any],
    payload: dict[str, Any] | None = None,
    *,
    payload_artifact_path: str | Path | None = None,
    key: str | None = None,
) -> ProviderDeliveryVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if delivery.get("schema") != PROVIDER_DELIVERY_SCHEMA:
        errors.append(f"unsupported provider delivery schema: {delivery.get('schema')}")
    body = without_keys(delivery, "delivery_id", "signatures")
    expected_delivery_id = content_hash(body)
    if delivery.get("delivery_id") != expected_delivery_id:
        errors.append("delivery_id does not match canonical delivery body")

    signatures = delivery.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider delivery must include at least one signature")
    else:
        signed_value = {"delivery_id": delivery.get("delivery_id"), "delivery": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider delivery signature verification failed")

    if delivery.get("mode") not in PROVIDER_DELIVERY_MODES:
        errors.append("provider delivery mode must be dry-run, recorded-response, or http-dispatch")
    if not delivery.get("provider"):
        errors.append("provider delivery provider is required")
    if not delivery.get("target_url"):
        errors.append("provider delivery target_url is required")
    credential = delivery.get("credential", {})
    if not isinstance(credential, dict) or not credential.get("ref") or credential.get("redacted") is not True:
        errors.append("provider delivery credential reference must be redacted")

    request = delivery.get("request", {})
    if not isinstance(request, dict) or not request.get("method") or not request.get("path") or not request.get("body_hash"):
        errors.append("provider delivery request method, path, and body_hash are required")

    if payload is None and payload_artifact_path is not None:
        try:
            payload = load_provider_payload(payload_artifact_path)
        except (OSError, ValueError) as exc:
            errors.append(f"provider delivery payload artifact could not be loaded: {exc}")

    if delivery.get("mode") == "dry-run":
        warnings.append("provider delivery is a dry-run receipt; no provider response is claimed")
    else:
        response = delivery.get("response", {})
        if not isinstance(response, dict) or response.get("status") is None or not response.get("body_hash"):
            errors.append("recorded-response and http-dispatch deliveries must include response status and body_hash")
        if delivery.get("mode") == "http-dispatch":
            if not request.get("header_names") or not request.get("headers_hash"):
                errors.append("http-dispatch delivery must include request header names and headers_hash")
            if not isinstance(response, dict) or not response.get("headers_hash"):
                errors.append("http-dispatch delivery must include response headers_hash")

    if payload is not None:
        payload_errors = _payload_errors(payload)
        errors.extend(f"payload invalid: {error}" for error in payload_errors)
        if delivery.get("provider") != payload.get("provider"):
            errors.append("delivery provider does not match payload")
        if delivery.get("payload_schema") != payload.get("schema"):
            errors.append("delivery payload_schema does not match payload")
        if delivery.get("payload_hash") != _payload_hash(payload):
            errors.append("delivery payload_hash does not match payload")
        if delivery.get("pack_id") != payload.get("pack_id"):
            errors.append("delivery pack_id does not match payload")
        if delivery.get("contract_id") != payload.get("contract_id"):
            errors.append("delivery contract_id does not match payload")
        if delivery.get("contract_hash") != payload.get("contract_hash"):
            errors.append("delivery contract_hash does not match payload")
        payload_request = payload.get("request", {})
        if isinstance(payload_request, dict):
            if request.get("method") != payload_request.get("method"):
                errors.append("delivery request method does not match payload")
            if request.get("path") != payload_request.get("path"):
                errors.append("delivery request path does not match payload")
            if request.get("body_hash") != content_hash(payload_request.get("body")):
                errors.append("delivery request body_hash does not match payload body")

    payload_artifact = delivery.get("payload_artifact")
    if payload_artifact is not None:
        if not isinstance(payload_artifact, dict):
            errors.append("provider delivery payload_artifact must be an object")
        elif payload_artifact_path is None:
            if payload is None:
                warnings.append("provider delivery payload artifact and payload were not replayed")
            else:
                warnings.append("provider delivery payload artifact was not replayed")
        elif payload is not None:
            try:
                expected_artifact = _payload_artifact(payload_artifact_path, payload)
            except (OSError, ValueError) as exc:
                errors.append(f"provider delivery payload_artifact replay failed: {exc}")
            else:
                if payload_artifact != expected_artifact:
                    errors.append("provider delivery payload_artifact bytes do not match retained payload file")

    return ProviderDeliveryVerification(ok=not errors, errors=errors, warnings=warnings)


def dispatch_provider_payload(
    payload: dict[str, Any],
    *,
    endpoint_base: str,
    credential_ref: str,
    timeout_seconds: float = DEFAULT_DISPATCH_TIMEOUT_SECONDS,
    auth_header: str = "Authorization",
    auth_scheme: str = "Bearer",
    delivered_at: str | None = None,
    payload_artifact_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _validate_payload(payload)
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if not endpoint_base:
        raise ValueError("endpoint_base is required")
    if not credential_ref:
        raise ValueError("credential_ref is required")

    request = payload["request"]
    method = str(request.get("method") or "POST").upper()
    target_url = f"{endpoint_base.rstrip('/')}{request.get('path')}"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "TrustAI-Provider-Dispatch/0.1",
    }
    secret = _credential_secret(credential_ref)
    if auth_header:
        headers[auth_header] = f"{auth_scheme} {secret}".strip() if auth_scheme else secret

    data = None if method in {"GET", "HEAD"} else canonical_bytes(request.get("body"))
    http_request = urllib.request.Request(target_url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(http_request, timeout=timeout_seconds) as response:
            response_status = int(response.getcode())
            response_body = response.read().decode("utf-8", errors="replace")
            response_headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        response_status = int(exc.code)
        response_body = exc.read().decode("utf-8", errors="replace")
        response_headers = dict(exc.headers.items()) if exc.headers else {}

    return build_provider_delivery(
        payload,
        endpoint_base=endpoint_base,
        credential_ref=credential_ref,
        mode="http-dispatch",
        response_status=response_status,
        response_body=response_body,
        response_headers=response_headers,
        request_headers=headers,
        delivered_at=delivered_at,
        payload_artifact_path=payload_artifact_path,
        key=key,
    )


def append_provider_delivery(
    chain: EvidenceChain,
    delivery: dict[str, Any],
    payload: dict[str, Any] | None = None,
    *,
    payload_artifact_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_delivery(delivery, payload, payload_artifact_path=payload_artifact_path, key=key)
    if not result.ok:
        raise ValueError("invalid provider delivery: " + "; ".join(result.errors))
    entry_payload = {
        "delivery_id": delivery["delivery_id"],
        "delivery_hash": content_hash(delivery),
        "provider": delivery.get("provider"),
        "mode": delivery.get("mode"),
        "payload_hash": delivery.get("payload_hash"),
        "pack_id": delivery.get("pack_id"),
        "contract_id": delivery.get("contract_id"),
        "contract_hash": delivery.get("contract_hash"),
        "request": delivery.get("request"),
        "target_url": delivery.get("target_url"),
        "response": delivery.get("response"),
        "payload_artifact": delivery.get("payload_artifact"),
    }
    return chain.append(PROVIDER_DELIVERY_ENTRY_TYPE, entry_payload, key=key, timestamp=delivery.get("delivered_at"))


def write_provider_delivery(path: str | Path, delivery: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(delivery, indent=2, sort_keys=True), encoding="utf-8")


def _validate_payload(payload: dict[str, Any]) -> None:
    errors = _payload_errors(payload)
    if errors:
        raise ValueError("invalid provider payload: " + "; ".join(errors))


def _payload_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["payload must be an object"]
    if not payload.get("schema"):
        errors.append("schema is required")
    if not payload.get("provider"):
        errors.append("provider is required")
    request = payload.get("request")
    if not isinstance(request, dict):
        errors.append("request object is required")
    else:
        for field in ("method", "path", "body"):
            if request.get(field) is None:
                errors.append(f"request.{field} is required")
    if payload.get("payload_hash") != _payload_hash(payload):
        errors.append("payload_hash does not match payload body")
    return errors


def _payload_hash(payload: dict[str, Any]) -> str:
    return content_hash(without_keys(payload, "payload_hash"))


def _payload_artifact(path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        raise ValueError(f"provider payload artifact is not a file: {target}")
    raw = target.read_bytes()
    try:
        parsed = json.loads(raw.decode("utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"provider payload artifact is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("provider payload artifact must contain an object")
    if content_hash(parsed) != content_hash(payload):
        raise ValueError("provider payload artifact content does not match supplied payload")
    artifact_body = {
        "path": str(target).replace("\\", "/"),
        "sha256": sha256_hex(raw),
        "size_bytes": len(raw),
        "content_hash": content_hash(parsed),
        "payload_hash": _payload_hash(parsed),
    }
    return {**artifact_body, "artifact_id": content_hash(artifact_body)}

def _credential_secret(credential_ref: str) -> str:
    if not credential_ref.startswith("env:"):
        raise ValueError("http dispatch requires an env: credential_ref")
    env_name = credential_ref[4:]
    if not env_name:
        raise ValueError("credential_ref env name is required")
    secret = os.environ.get(env_name)
    if not secret:
        raise ValueError(f"credential environment variable is not set: {env_name}")
    return secret


def _redacted_headers(headers: dict[str, Any]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        normalized = str(name).lower()
        if any(marker in normalized for marker in ("authorization", "cookie", "secret", "token", "key")):
            redacted[normalized] = "<redacted>"
        else:
            redacted[normalized] = str(value)
    return dict(sorted(redacted.items()))
