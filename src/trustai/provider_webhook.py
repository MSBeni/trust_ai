from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, sha256_hex, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

PROVIDER_WEBHOOK_SCHEMA = "trustai.provider-webhook/0.1"
PROVIDER_WEBHOOK_ENTRY_TYPE = "provider_webhook.recorded"
SUPPORTED_PROVIDER_WEBHOOKS = {"github", "gitlab"}


@dataclass
class ProviderWebhookVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def validate_provider_webhook_signature(
    provider: str,
    body: bytes | str,
    headers: Mapping[str, Any],
    secret: str,
) -> dict[str, Any]:
    provider = _normalize_provider(provider)
    if not secret:
        raise ValueError(f"{provider} webhook secret is required")
    body_bytes = _body_bytes(body)
    normalized_headers = _normalize_headers(headers)
    if provider == "github":
        return _validate_github_webhook(body_bytes, normalized_headers, secret)
    if provider == "gitlab":
        return _validate_gitlab_webhook(normalized_headers, secret)
    raise ValueError(f"unsupported provider webhook: {provider}")


def provider_webhook_identity(
    provider: str,
    body: bytes | str,
    headers: Mapping[str, Any],
    secret: str,
) -> dict[str, Any]:
    provider = _normalize_provider(provider)
    body_bytes = _body_bytes(body)
    normalized_headers = _normalize_headers(headers)
    metadata = validate_provider_webhook_signature(provider, body_bytes, normalized_headers, secret)
    identity = {
        "schema": "trustai.provider-webhook-dedup-key/0.1",
        "provider": provider,
        "event": metadata.get("event"),
        "delivery_id": metadata.get("delivery_id"),
        "payload_sha256": sha256_hex(body_bytes),
    }
    return {
        **identity,
        "dedup_key": content_hash(identity),
        "verification_method": metadata["method"],
        "verification_value_hash": metadata["value_hash"],
    }


def build_provider_webhook_receipt(
    provider: str,
    body: bytes | str,
    headers: Mapping[str, Any],
    secret: str,
    *,
    received_at: str | None = None,
    body_artifact_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    provider = _normalize_provider(provider)
    body_bytes = _body_bytes(body)
    normalized_headers = _normalize_headers(headers)
    metadata = validate_provider_webhook_signature(provider, body_bytes, normalized_headers, secret)
    timestamp = received_at or utc_now()
    parse_rfc3339(timestamp)
    redacted_headers = _redacted_headers(normalized_headers)
    body_record = {
        "schema": PROVIDER_WEBHOOK_SCHEMA,
        "provider": provider,
        "received_at": timestamp,
        "payload": {
            "sha256": sha256_hex(body_bytes),
            "size_bytes": len(body_bytes),
            "content_type": normalized_headers.get("content-type"),
        },
        "request_headers": {
            "header_names": sorted(normalized_headers),
            "headers_hash": content_hash(redacted_headers),
        },
        "webhook": {
            "event": metadata.get("event"),
            "delivery_id": metadata.get("delivery_id"),
        },
        "verification": {
            "provider_signature_verified": True,
            "method": metadata["method"],
            "header": metadata["header"],
            "value_hash": metadata["value_hash"],
        },
    }
    if body_artifact_path is not None:
        body_record["payload_artifact"] = _provider_webhook_payload_artifact(body_artifact_path, body_bytes)
    receipt_id = content_hash(body_record)
    return {
        **body_record,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "provider_webhook": body_record}, key)],
    }


def verify_provider_webhook_receipt(
    receipt: dict[str, Any],
    body: bytes | str | None = None,
    *,
    headers: Mapping[str, Any] | None = None,
    secret: str | None = None,
    body_artifact_path: str | Path | None = None,
    key: str | None = None,
) -> ProviderWebhookVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != PROVIDER_WEBHOOK_SCHEMA:
        errors.append(f"unsupported provider webhook schema: {receipt.get('schema')}")
    provider = receipt.get("provider")
    if provider not in SUPPORTED_PROVIDER_WEBHOOKS:
        errors.append(f"unsupported provider webhook provider: {provider}")

    body_record = without_keys(receipt, "receipt_id", "signatures")
    expected_receipt_id = content_hash(body_record)
    if receipt.get("receipt_id") != expected_receipt_id:
        errors.append("receipt_id does not match canonical provider webhook body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider webhook receipt must include at least one signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "provider_webhook": body_record}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider webhook receipt signature verification failed")

    try:
        parse_rfc3339(str(receipt.get("received_at") or ""))
    except ValueError as exc:
        errors.append(f"provider webhook received_at invalid: {exc}")

    payload = receipt.get("payload", {})
    if not isinstance(payload, dict):
        errors.append("provider webhook payload must be an object")
        payload = {}
    if not payload.get("sha256") or payload.get("size_bytes") is None:
        errors.append("provider webhook payload sha256 and size_bytes are required")

    request_headers = receipt.get("request_headers", {})
    if not isinstance(request_headers, dict) or not request_headers.get("header_names") or not request_headers.get("headers_hash"):
        errors.append("provider webhook request_headers header_names and headers_hash are required")

    webhook = receipt.get("webhook", {})
    if not isinstance(webhook, dict) or not webhook.get("event"):
        errors.append("provider webhook event is required")

    verification = receipt.get("verification", {})
    if not isinstance(verification, dict):
        errors.append("provider webhook verification must be an object")
        verification = {}
    if verification.get("provider_signature_verified") is not True:
        errors.append("provider webhook receipt must claim provider_signature_verified true")
    if not verification.get("method") or not verification.get("header") or not verification.get("value_hash"):
        errors.append("provider webhook verification method, header, and value_hash are required")

    body_bytes: bytes | None = None
    if body is None and body_artifact_path is not None:
        try:
            body_bytes = Path(body_artifact_path).read_bytes()
        except OSError as exc:
            errors.append(f"provider webhook payload artifact could not be loaded: {exc}")
    elif body is None:
        warnings.append("provider webhook payload body not supplied; payload hash was not replayed")
    else:
        body_bytes = _body_bytes(body)
    if body_bytes is not None:
        if payload.get("sha256") != sha256_hex(body_bytes):
            errors.append("provider webhook payload sha256 does not match supplied body")
        if payload.get("size_bytes") != len(body_bytes):
            errors.append("provider webhook payload size_bytes does not match supplied body")

    payload_artifact = receipt.get("payload_artifact")
    if payload_artifact is not None:
        if not isinstance(payload_artifact, dict):
            errors.append("provider webhook payload_artifact must be an object")
        elif body_artifact_path is None:
            if body is not None:
                errors.append("provider webhook payload_artifact requires body_artifact_path for byte replay")
            else:
                warnings.append("provider webhook payload artifact was not replayed")
        elif body_bytes is not None:
            try:
                expected_artifact = _provider_webhook_payload_artifact(body_artifact_path, body_bytes)
            except ValueError as exc:
                errors.append(f"provider webhook payload_artifact invalid: {exc}")
            else:
                if payload_artifact != expected_artifact:
                    errors.append("provider webhook payload_artifact does not match supplied body artifact bytes")

    if headers is None and secret is None:
        warnings.append("provider webhook provider signature was not replayed")
    elif headers is None or not secret or body_bytes is None:
        errors.append("provider webhook signature replay requires body, headers, and secret")
    else:
        try:
            normalized_headers = _normalize_headers(headers)
            metadata = validate_provider_webhook_signature(str(provider), body_bytes, normalized_headers, secret)
            if webhook.get("event") != metadata.get("event"):
                errors.append("provider webhook event does not match supplied headers")
            if webhook.get("delivery_id") != metadata.get("delivery_id"):
                errors.append("provider webhook delivery_id does not match supplied headers")
            if verification.get("method") != metadata.get("method"):
                errors.append("provider webhook verification method does not match supplied headers")
            if verification.get("header") != metadata.get("header"):
                errors.append("provider webhook verification header does not match supplied headers")
            if verification.get("value_hash") != metadata.get("value_hash"):
                errors.append("provider webhook verification value_hash does not match supplied headers")
            if isinstance(request_headers, dict) and request_headers.get("headers_hash") != content_hash(_redacted_headers(normalized_headers)):
                errors.append("provider webhook request header hash does not match supplied headers")
        except ValueError as exc:
            errors.append(f"provider webhook signature replay failed: {exc}")

    return ProviderWebhookVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_webhook_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    body: bytes | str | None = None,
    *,
    headers: Mapping[str, Any] | None = None,
    secret: str | None = None,
    body_artifact_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_webhook_receipt(receipt, body, headers=headers, secret=secret, body_artifact_path=body_artifact_path, key=key)
    if not result.ok:
        raise ValueError("invalid provider webhook receipt: " + "; ".join(result.errors))
    payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "received_at": receipt.get("received_at"),
        "webhook": receipt.get("webhook"),
        "payload": receipt.get("payload"),
        "payload_artifact": receipt.get("payload_artifact"),
        "request_headers": receipt.get("request_headers"),
        "verification": receipt.get("verification"),
    }
    return chain.append(PROVIDER_WEBHOOK_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("received_at"))


def load_provider_webhook_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider webhook receipt must contain an object")
    return value


def write_provider_webhook_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _provider_webhook_artifact_path(path: Path) -> str:
    if not path.is_absolute():
        return path.as_posix()
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _provider_webhook_payload_artifact(path: str | Path, body: bytes | str) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        raise ValueError(f"provider webhook payload artifact file missing: {path}")
    data = target.read_bytes()
    body_bytes = _body_bytes(body)
    if data != body_bytes:
        raise ValueError("provider webhook payload artifact bytes do not match supplied body")
    artifact_body = {
        "path": _provider_webhook_artifact_path(target),
        "sha256": sha256_hex(data),
        "size_bytes": len(data),
    }
    return {**artifact_body, "artifact_id": content_hash(artifact_body)}


def _validate_github_webhook(body: bytes, headers: Mapping[str, str], secret: str) -> dict[str, Any]:
    signature = headers.get("x-hub-signature-256")
    if not signature:
        raise ValueError("X-Hub-Signature-256 header is required")
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("GitHub webhook signature verification failed")
    event = headers.get("x-github-event")
    delivery_id = headers.get("x-github-delivery")
    if not event:
        raise ValueError("X-GitHub-Event header is required")
    if not delivery_id:
        raise ValueError("X-GitHub-Delivery header is required")
    return {
        "event": event,
        "delivery_id": delivery_id,
        "method": "github-hmac-sha256",
        "header": "X-Hub-Signature-256",
        "value_hash": sha256_hex(signature.encode("utf-8")),
    }


def _validate_gitlab_webhook(headers: Mapping[str, str], secret: str) -> dict[str, Any]:
    token = headers.get("x-gitlab-token")
    if not token:
        raise ValueError("X-Gitlab-Token header is required")
    if not hmac.compare_digest(secret, token):
        raise ValueError("GitLab webhook token verification failed")
    event = headers.get("x-gitlab-event")
    if not event:
        raise ValueError("X-Gitlab-Event header is required")
    return {
        "event": event,
        "delivery_id": headers.get("x-gitlab-webhook-uuid") or headers.get("x-gitlab-event-uuid"),
        "method": "gitlab-shared-token",
        "header": "X-Gitlab-Token",
        "value_hash": sha256_hex(token.encode("utf-8")),
    }


def _normalize_provider(provider: str) -> str:
    normalized = str(provider or "").strip().lower()
    if normalized not in SUPPORTED_PROVIDER_WEBHOOKS:
        raise ValueError(f"unsupported provider webhook: {provider}")
    return normalized


def _body_bytes(body: bytes | str) -> bytes:
    return body if isinstance(body, bytes) else str(body).encode("utf-8")


def _normalize_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        normalized[str(name).strip().lower()] = str(value)
    return normalized


def _redacted_headers(headers: Mapping[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        normalized = str(name).lower()
        if any(marker in normalized for marker in ("authorization", "cookie", "secret", "token", "signature", "key")):
            redacted[normalized] = "<redacted>"
        else:
            redacted[normalized] = str(value)
    return dict(sorted(redacted.items()))
