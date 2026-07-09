from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .identity import SUPPORTED_IDENTITY_PROVIDERS
from .identity_provider_attestation import verify_identity_provider_attestation

IDENTITY_PROVIDER_SESSION_SCHEMA = "trustai.identity-provider-session/0.1"
IDENTITY_PROVIDER_SESSION_ENTRY_TYPE = "identity.provider.session_recorded"
IDENTITY_PROVIDER_SESSION_MODES = {
    "local-reference",
    "recorded-provider-response",
    "provider-event-stream",
    "hosted-session",
    "production-design",
}
IDENTITY_PROVIDER_SESSION_EVENT_KINDS = {
    "agent_login",
    "token_introspection",
    "token_refresh",
    "session_revocation",
    "app_assignment",
    "api_access",
    "scim_sync",
    "risk_signal",
    "account_lifecycle",
}
IDENTITY_PROVIDER_SESSION_DECISIONS = {"allowed", "denied", "revoked", "expired"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class IdentityProviderSessionVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_identity_provider_session_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("identity provider session receipt must contain an object")
    return value


def write_identity_provider_session_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_identity_provider_session_receipt(
    identity_provider_attestation: dict[str, Any],
    *,
    identity_payload: dict[str, Any] | None = None,
    identity_payload_path: str | Path | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    mode: str = "recorded-provider-response",
    environment: str = "local",
    provider_tenant_ref: str,
    session_ref: str,
    event_ref: str,
    event_kind: str,
    provider_event_id: str,
    actor_ref: str,
    authn_method: str = "oauth2-client-credentials",
    assurance_level: str = "aal2",
    scope_refs: list[str] | None = None,
    audience_refs: list[str] | None = None,
    decision: str = "allowed",
    risk_level: str = "low",
    endpoint_url: str,
    credential_ref: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    session_log_ref: str,
    session_log_root: str,
    audit_log_ref: str,
    audit_log_root: str,
    source_ip_hash: str | None = None,
    device_ref: str | None = None,
    user_agent_hash: str | None = None,
    session_started_at: str,
    session_expires_at: str | None = None,
    observed_at: str,
    retention_until: str,
    evidence_refs: list[str] | None = None,
    recorded_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in IDENTITY_PROVIDER_SESSION_MODES:
        raise ValueError(f"mode must be one of {sorted(IDENTITY_PROVIDER_SESSION_MODES)}")
    if event_kind not in IDENTITY_PROVIDER_SESSION_EVENT_KINDS:
        raise ValueError("event_kind is unsupported")
    if decision not in IDENTITY_PROVIDER_SESSION_DECISIONS:
        raise ValueError(f"decision must be one of {sorted(IDENTITY_PROVIDER_SESSION_DECISIONS)}")

    for value, field in (
        (environment, "environment"),
        (provider_tenant_ref, "provider_tenant_ref"),
        (session_ref, "session_ref"),
        (event_ref, "event_ref"),
        (provider_event_id, "provider_event_id"),
        (actor_ref, "actor_ref"),
        (authn_method, "authn_method"),
        (assurance_level, "assurance_level"),
        (risk_level, "risk_level"),
        (endpoint_url, "endpoint_url"),
        (credential_ref, "credential_ref"),
        (request_hash, "request_hash"),
        (response_hash, "response_hash"),
        (session_log_ref, "session_log_ref"),
        (session_log_root, "session_log_root"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (session_started_at, "session_started_at"),
        (observed_at, "observed_at"),
        (retention_until, "retention_until"),
    ):
        _require_text(value, field)
    if not isinstance(response_status, int):
        raise ValueError("response_status must be an integer")
    if not _valid_url(endpoint_url):
        raise ValueError("endpoint_url must be an absolute URL")
    if not _is_https(endpoint_url):
        raise ValueError("endpoint_url must use HTTPS")
    for value, field in (
        (request_hash, "request_hash"),
        (response_hash, "response_hash"),
        (session_log_root, "session_log_root"),
        (audit_log_root, "audit_log_root"),
    ):
        if not _is_hash_ref(value):
            raise ValueError(f"{field} must be a sha256 reference")
    for value, field in ((source_ip_hash, "source_ip_hash"), (user_agent_hash, "user_agent_hash")):
        if value is not None and not _is_hash_ref(value):
            raise ValueError(f"{field} must be a sha256 reference")

    attestation_result = verify_identity_provider_attestation(
        identity_provider_attestation,
        identity_payload=identity_payload,
        identity_payload_path=identity_payload_path,
        vendor_identity_receipt=vendor_identity_receipt,
        proof_packs=proof_packs,
        trust_network_manifest=trust_network_manifest,
        key=key,
    )
    if not attestation_result.ok:
        raise ValueError("invalid identity provider attestation source: " + "; ".join(attestation_result.errors))

    timestamp = recorded_at or utc_now()
    _validate_times(
        recorded_at=timestamp,
        session_started_at=session_started_at,
        session_expires_at=session_expires_at,
        observed_at=observed_at,
        retention_until=retention_until,
    )

    attestation_binding = _attestation_binding(identity_provider_attestation)
    provider = attestation_binding["provider"]
    subject = attestation_binding["subject"]
    body = {
        "schema": IDENTITY_PROVIDER_SESSION_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": timestamp,
        "provider": provider,
        "identity_attestation": attestation_binding,
        "session": {
            "session_ref": session_ref,
            "event_ref": event_ref,
            "event_kind": event_kind,
            "provider_event_id": provider_event_id,
            "provider_tenant_ref": provider_tenant_ref,
            "subject_ref": subject.get("subject_ref"),
            "identity_provider": subject.get("identity_provider"),
            "identity_id": subject.get("identity_id"),
            "identity_record_hash": subject.get("identity_record_hash"),
            "actor_ref": actor_ref,
            "started_at": session_started_at,
            "expires_at": session_expires_at,
            "observed_at": observed_at,
        },
        "authentication_context": {
            "method": authn_method,
            "assurance_level": assurance_level,
            "scope_refs": sorted(scope_refs or []),
            "audience_refs": sorted(audience_refs or []),
            "decision": decision,
            "risk_level": risk_level,
        },
        "provider_evidence": {
            "endpoint_url": endpoint_url,
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
            "success": 200 <= response_status < 300,
            "session_log_ref": session_log_ref,
            "session_log_root": session_log_root,
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "source_ip_hash": source_ip_hash,
            "device_ref": device_ref,
            "user_agent_hash": user_agent_hash,
            "credential": _redacted_ref(credential_ref),
            "retention_until": retention_until,
        },
        "operations": {
            "evidence_refs": sorted(evidence_refs or []),
        },
        "controls": _controls(mode=mode, event_kind=event_kind, decision=decision),
        "limitations": [
            "This receipt binds an identity-provider session, token, or account event to an existing TrustAI identity-provider attestation.",
            "It stores request, response, session-log, and audit-log hashes, not provider tokens, raw session payloads, credentials, IP addresses, or user-agent strings.",
            "Production deployments should pair this receipt with provider-authenticated event streams, immutable identity-provider audit exports, and operated session revocation propagation.",
        ],
    }
    session_id = content_hash(body)
    return {
        **body,
        "session_id": session_id,
        "signatures": [sign_value({"session_id": session_id, "identity_provider_session": body}, key)],
    }


def verify_identity_provider_session_receipt(
    receipt: dict[str, Any],
    *,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    identity_payload_path: str | Path | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> IdentityProviderSessionVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != IDENTITY_PROVIDER_SESSION_SCHEMA:
        errors.append(f"unsupported identity provider session schema: {receipt.get('schema')}")
    body = without_keys(receipt, "session_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("session_id") != expected_id:
        errors.append("session_id does not match canonical identity provider session body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("identity provider session receipt must include at least one signature")
    else:
        signed_value = {"session_id": receipt.get("session_id"), "identity_provider_session": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("identity provider session signature verification failed")

    mode = receipt.get("mode")
    if mode not in IDENTITY_PROVIDER_SESSION_MODES:
        errors.append("identity provider session mode is unsupported")
    elif mode not in {"provider-event-stream", "hosted-session"}:
        warnings.append(f"identity provider session mode is {mode}; live provider session operation is not claimed")

    provider = receipt.get("provider")
    if provider not in SUPPORTED_IDENTITY_PROVIDERS:
        errors.append(f"unsupported identity provider session provider: {provider}")

    attestation_binding = receipt.get("identity_attestation", {})
    if not isinstance(attestation_binding, dict):
        errors.append("identity provider session identity_attestation must be an object")
        attestation_binding = {}
    for field in ("attestation_id", "attestation_hash", "provider", "subject"):
        if not attestation_binding.get(field):
            errors.append(f"identity provider session identity_attestation.{field} is required")
    if provider != attestation_binding.get("provider"):
        errors.append("identity provider session provider must match identity attestation provider")

    _verify_session(receipt.get("session"), provider, errors)
    _verify_authentication_context(receipt.get("authentication_context"), errors)
    _verify_provider_evidence(receipt.get("provider_evidence"), receipt.get("recorded_at"), now, errors)
    _check_no_secret_values(receipt, errors)

    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("identity provider session controls are required")

    if identity_provider_attestation is None:
        warnings.append("identity provider attestation source not supplied; attestation hash was not replayed")
    else:
        attestation_result = verify_identity_provider_attestation(
            identity_provider_attestation,
            identity_payload=identity_payload,
            identity_payload_path=identity_payload_path,
            vendor_identity_receipt=vendor_identity_receipt,
            proof_packs=proof_packs,
            trust_network_manifest=trust_network_manifest,
            key=key,
            now=now,
        )
        if not attestation_result.ok:
            errors.extend(f"source identity provider attestation invalid: {error}" for error in attestation_result.errors)
        warnings.extend(f"source identity provider warning: {warning}" for warning in attestation_result.warnings)
        expected_binding = _attestation_binding(identity_provider_attestation)
        if attestation_binding != expected_binding:
            errors.append("identity provider session attestation binding does not match supplied attestation")
        session = receipt.get("session", {}) if isinstance(receipt.get("session"), dict) else {}
        subject = expected_binding.get("subject", {})
        if session.get("identity_id") != subject.get("identity_id"):
            errors.append("identity provider session identity_id does not match supplied attestation subject")
        if session.get("identity_record_hash") != subject.get("identity_record_hash"):
            errors.append("identity provider session identity_record_hash does not match supplied attestation subject")

    return IdentityProviderSessionVerification(ok=not errors, errors=errors, warnings=warnings)


def append_identity_provider_session_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    identity_payload_path: str | Path | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_identity_provider_session_receipt(
        receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_payload=identity_payload,
        identity_payload_path=identity_payload_path,
        vendor_identity_receipt=vendor_identity_receipt,
        proof_packs=proof_packs,
        trust_network_manifest=trust_network_manifest,
        key=key,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid identity provider session receipt: " + "; ".join(result.errors))
    payload = {
        "session_id": receipt["session_id"],
        "session_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "mode": receipt.get("mode"),
        "identity_attestation": receipt.get("identity_attestation"),
        "session": receipt.get("session"),
        "authentication_context": receipt.get("authentication_context"),
        "provider_evidence": {
            key: value
            for key, value in (receipt.get("provider_evidence") or {}).items()
            if key not in {"credential"}
        },
    }
    return chain.append(
        IDENTITY_PROVIDER_SESSION_ENTRY_TYPE,
        payload,
        key=key,
        timestamp=receipt.get("recorded_at"),
    )


def _attestation_binding(attestation: dict[str, Any]) -> dict[str, Any]:
    authentication = attestation.get("authentication", {}) if isinstance(attestation, dict) else {}
    subject = attestation.get("subject", {}) if isinstance(attestation, dict) else {}
    return {
        "attestation_id": attestation.get("attestation_id"),
        "attestation_hash": content_hash(attestation),
        "provider": authentication.get("provider") or subject.get("identity_provider"),
        "tenant_ref": authentication.get("tenant_ref"),
        "subject": {
            "subject_ref": subject.get("subject_ref"),
            "identity_provider": subject.get("identity_provider"),
            "identity_id": subject.get("identity_id"),
            "identity_record_hash": subject.get("identity_record_hash"),
            "agent": subject.get("agent"),
        },
    }


def _verify_session(value: Any, provider: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("identity provider session session must be an object")
        return
    for field in (
        "session_ref",
        "event_ref",
        "event_kind",
        "provider_event_id",
        "provider_tenant_ref",
        "identity_provider",
        "identity_id",
        "identity_record_hash",
        "actor_ref",
        "started_at",
        "observed_at",
    ):
        if not value.get(field):
            errors.append(f"identity provider session session.{field} is required")
    if value.get("event_kind") not in IDENTITY_PROVIDER_SESSION_EVENT_KINDS:
        errors.append(f"identity provider session event_kind unsupported: {value.get('event_kind')}")
    if value.get("identity_provider") != provider:
        errors.append("identity provider session subject provider must match receipt provider")
    try:
        parse_rfc3339(str(value.get("started_at") or ""))
        observed = parse_rfc3339(str(value.get("observed_at") or ""))
        expires_at = value.get("expires_at")
        if expires_at and parse_rfc3339(str(expires_at)) <= observed:
            errors.append("identity provider session expires_at must be after observed_at")
    except ValueError as exc:
        errors.append(f"identity provider session timestamp invalid: {exc}")


def _verify_authentication_context(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("identity provider session authentication_context must be an object")
        return
    for field in ("method", "assurance_level", "decision", "risk_level"):
        if not value.get(field):
            errors.append(f"identity provider session authentication_context.{field} is required")
    if value.get("decision") not in IDENTITY_PROVIDER_SESSION_DECISIONS:
        errors.append(f"identity provider session decision unsupported: {value.get('decision')}")
    for field in ("scope_refs", "audience_refs"):
        if not _is_string_list(value.get(field)):
            errors.append(f"identity provider session authentication_context.{field} must be a string array")


def _verify_provider_evidence(value: Any, recorded_at: Any, now: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("identity provider session provider_evidence must be an object")
        return
    for field in (
        "endpoint_url",
        "request_hash",
        "response_hash",
        "session_log_ref",
        "session_log_root",
        "audit_log_ref",
        "audit_log_root",
        "retention_until",
    ):
        if not value.get(field):
            errors.append(f"identity provider session provider_evidence.{field} is required")
    endpoint_url = str(value.get("endpoint_url") or "")
    if not _valid_url(endpoint_url):
        errors.append("identity provider session endpoint_url must be an absolute URL")
    elif not _is_https(endpoint_url):
        errors.append("identity provider session endpoint_url must use HTTPS")
    for field in ("request_hash", "response_hash", "session_log_root", "audit_log_root"):
        if not _is_hash_ref(str(value.get(field) or "")):
            errors.append(f"identity provider session provider_evidence.{field} must be a sha256 reference")
    for field in ("source_ip_hash", "user_agent_hash"):
        if value.get(field) is not None and not _is_hash_ref(str(value.get(field) or "")):
            errors.append(f"identity provider session provider_evidence.{field} must be a sha256 reference")
    status = value.get("response_status")
    if not isinstance(status, int) or status < 100 or status > 599:
        errors.append("identity provider session response_status must be an HTTP status code")
    elif value.get("success") is not (200 <= status < 300):
        errors.append("identity provider session success must match response_status")
    _verify_redacted_ref(value.get("credential"), "identity provider session credential", errors)
    try:
        recorded = parse_rfc3339(str(recorded_at or ""))
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if retention <= recorded:
            errors.append("identity provider session retention_until must be after recorded_at")
        if now and parse_rfc3339(now) > retention:
            errors.append("identity provider session retention has expired")
    except ValueError as exc:
        errors.append(f"identity provider session provider_evidence timestamp invalid: {exc}")


def _validate_times(
    *,
    recorded_at: str,
    session_started_at: str,
    session_expires_at: str | None,
    observed_at: str,
    retention_until: str,
) -> None:
    recorded = parse_rfc3339(recorded_at)
    started = parse_rfc3339(session_started_at)
    observed = parse_rfc3339(observed_at)
    retention = parse_rfc3339(retention_until)
    if observed < started:
        raise ValueError("observed_at must be after or equal to session_started_at")
    if recorded < observed:
        raise ValueError("recorded_at must be after or equal to observed_at")
    if retention <= recorded:
        raise ValueError("retention_until must be after recorded_at")
    if session_expires_at and parse_rfc3339(session_expires_at) <= observed:
        raise ValueError("session_expires_at must be after observed_at")


def _controls(*, mode: str, event_kind: str, decision: str) -> list[dict[str, str]]:
    live_status = "implemented-reference" if mode in {"provider-event-stream", "hosted-session"} else "planned-production"
    return [
        {
            "id": "identity-attestation-binding",
            "status": "implemented-reference",
            "description": "Session evidence is bound to the canonical hash of an identity-provider attestation.",
        },
        {
            "id": "provider-session-event-hashes",
            "status": "implemented-reference",
            "description": "Provider request, response, session-log, and audit-log roots are recorded as hashes.",
        },
        {
            "id": "redacted-session-credential",
            "status": "implemented-reference",
            "description": "Provider credential material is represented only by a redacted reference.",
        },
        {
            "id": "live-provider-session-event",
            "status": live_status,
            "description": f"Receipt records {event_kind} with {decision} decision; production claims require provider-authenticated stream or hosted-session mode.",
        },
    ]


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    return {"ref": ref, "redacted": True} if ref else None


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


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value)


def _require_text(value: str | None, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"identity provider session secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and _is_string_list(value):
        return True
    return False
