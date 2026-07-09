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
from .identity_provider_session import verify_identity_provider_session_receipt

IDENTITY_PROVIDER_LIFECYCLE_OPERATION_SCHEMA = "trustai.identity-provider-lifecycle-operation/0.1"
IDENTITY_PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE = "identity.provider.lifecycle_operation_recorded"
IDENTITY_PROVIDER_LIFECYCLE_OPERATION_MODES = {
    "local-reference",
    "recorded-provider-response",
    "provider-event-stream",
    "hosted-lifecycle-worker",
    "production-design",
}
IDENTITY_PROVIDER_LIFECYCLE_OPERATION_KINDS = {
    "account_create",
    "account_update",
    "account_suspend",
    "account_reactivate",
    "account_deactivate",
    "account_delete",
    "app_assignment",
    "app_unassignment",
    "token_revocation",
    "session_revocation",
    "scim_sync",
    "risk_policy_update",
}
IDENTITY_PROVIDER_LIFECYCLE_TARGET_STATES = {
    "active",
    "assigned",
    "unassigned",
    "suspended",
    "deactivated",
    "deleted",
    "revoked",
    "synced",
    "updated",
    "denied",
    "failed",
}
IDENTITY_PROVIDER_LIFECYCLE_OUTCOMES = {"succeeded", "failed", "denied", "noop"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class IdentityProviderLifecycleOperationVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_identity_provider_lifecycle_operation_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("identity provider lifecycle operation receipt must contain an object")
    return value


def write_identity_provider_lifecycle_operation_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_identity_provider_lifecycle_operation_receipt(
    identity_provider_attestation: dict[str, Any],
    *,
    identity_provider_session_receipt: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    identity_payload_path: str | Path | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    mode: str = "recorded-provider-response",
    environment: str = "local",
    provider_tenant_ref: str,
    operation_ref: str,
    operation_kind: str,
    provider_operation_id: str,
    actor_ref: str,
    target_state: str,
    outcome: str = "succeeded",
    endpoint_url: str,
    credential_ref: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    system_log_ref: str,
    system_log_root: str,
    audit_log_ref: str,
    audit_log_root: str,
    requested_at: str,
    completed_at: str,
    retention_until: str,
    idempotency_key: str | None = None,
    reason_ref: str | None = None,
    approval_ref: str | None = None,
    change_ticket_ref: str | None = None,
    previous_identity_record_hash: str | None = None,
    resulting_identity_record_hash: str | None = None,
    evidence_refs: list[str] | None = None,
    recorded_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in IDENTITY_PROVIDER_LIFECYCLE_OPERATION_MODES:
        raise ValueError(f"mode must be one of {sorted(IDENTITY_PROVIDER_LIFECYCLE_OPERATION_MODES)}")
    if operation_kind not in IDENTITY_PROVIDER_LIFECYCLE_OPERATION_KINDS:
        raise ValueError("operation_kind is unsupported")
    if target_state not in IDENTITY_PROVIDER_LIFECYCLE_TARGET_STATES:
        raise ValueError(f"target_state must be one of {sorted(IDENTITY_PROVIDER_LIFECYCLE_TARGET_STATES)}")
    if outcome not in IDENTITY_PROVIDER_LIFECYCLE_OUTCOMES:
        raise ValueError(f"outcome must be one of {sorted(IDENTITY_PROVIDER_LIFECYCLE_OUTCOMES)}")

    for value, field in (
        (environment, "environment"),
        (provider_tenant_ref, "provider_tenant_ref"),
        (operation_ref, "operation_ref"),
        (provider_operation_id, "provider_operation_id"),
        (actor_ref, "actor_ref"),
        (endpoint_url, "endpoint_url"),
        (credential_ref, "credential_ref"),
        (request_hash, "request_hash"),
        (response_hash, "response_hash"),
        (system_log_ref, "system_log_ref"),
        (system_log_root, "system_log_root"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (requested_at, "requested_at"),
        (completed_at, "completed_at"),
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
        (system_log_root, "system_log_root"),
        (audit_log_root, "audit_log_root"),
    ):
        if not _is_hash_ref(value):
            raise ValueError(f"{field} must be a sha256 reference")
    for value, field in (
        (previous_identity_record_hash, "previous_identity_record_hash"),
        (resulting_identity_record_hash, "resulting_identity_record_hash"),
    ):
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

    if identity_provider_session_receipt is not None:
        session_result = verify_identity_provider_session_receipt(
            identity_provider_session_receipt,
            identity_provider_attestation=identity_provider_attestation,
            identity_payload=identity_payload,
            identity_payload_path=identity_payload_path,
            vendor_identity_receipt=vendor_identity_receipt,
            proof_packs=proof_packs,
            trust_network_manifest=trust_network_manifest,
            key=key,
        )
        if not session_result.ok:
            raise ValueError("invalid identity provider session source: " + "; ".join(session_result.errors))

    timestamp = recorded_at or utc_now()
    _validate_times(
        recorded_at=timestamp,
        requested_at=requested_at,
        completed_at=completed_at,
        retention_until=retention_until,
    )
    _validate_lifecycle_state(operation_kind, target_state, outcome, response_status)

    attestation_binding = _attestation_binding(identity_provider_attestation)
    subject = attestation_binding["subject"]
    provider = attestation_binding["provider"]
    previous_hash = previous_identity_record_hash or subject.get("identity_record_hash")
    operation = {
        "kind": operation_kind,
        "operation_ref": operation_ref,
        "provider_operation_id": provider_operation_id,
        "provider_tenant_ref": provider_tenant_ref,
        "subject_ref": subject.get("subject_ref"),
        "identity_provider": subject.get("identity_provider"),
        "identity_id": subject.get("identity_id"),
        "identity_record_hash": subject.get("identity_record_hash"),
        "actor_ref": actor_ref,
        "target_state": target_state,
        "outcome": outcome,
        "requested_at": requested_at,
        "completed_at": completed_at,
        "idempotency_key": idempotency_key
        or content_hash(
            {
                "attestation_id": attestation_binding.get("attestation_id"),
                "operation_kind": operation_kind,
                "operation_ref": operation_ref,
                "request_hash": request_hash,
                "endpoint_url": endpoint_url,
            }
        )[:32],
    }
    change_refs = {
        "reason_ref": reason_ref,
        "approval_ref": approval_ref,
        "change_ticket_ref": change_ticket_ref,
    }
    body: dict[str, Any] = {
        "schema": IDENTITY_PROVIDER_LIFECYCLE_OPERATION_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": timestamp,
        "provider": provider,
        "identity_attestation": attestation_binding,
        "operation": operation,
        "change_refs": {key: value for key, value in change_refs.items() if value},
        "provider_evidence": {
            "endpoint_url": endpoint_url,
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
            "success": 200 <= response_status < 300,
            "system_log_ref": system_log_ref,
            "system_log_root": system_log_root,
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "previous_identity_record_hash": previous_hash,
            "resulting_identity_record_hash": resulting_identity_record_hash,
            "credential": _redacted_ref(credential_ref),
            "retention_until": retention_until,
        },
        "source_session": _session_binding(identity_provider_session_receipt) if identity_provider_session_receipt else None,
        "operations": {
            "evidence_refs": sorted(evidence_refs or []),
        },
        "controls": _controls(
            mode=mode,
            operation_kind=operation_kind,
            target_state=target_state,
            has_session=identity_provider_session_receipt is not None,
            has_resulting_hash=bool(resulting_identity_record_hash),
        ),
        "limitations": [
            "This receipt binds an identity-provider account, application, token, or session lifecycle operation to an existing TrustAI identity-provider attestation.",
            "It stores provider request, response, system-log, and audit-log hashes, not provider tokens, raw account payloads, credentials, IP addresses, or user-agent strings.",
            "Production deployments should pair this receipt with provider-authenticated lifecycle workers, immutable identity-provider audit exports, and independently retained propagation logs.",
        ],
    }
    operation_id = content_hash(body)
    return {
        **body,
        "operation_id": operation_id,
        "signatures": [sign_value({"operation_id": operation_id, "identity_provider_lifecycle_operation": body}, key)],
    }


def verify_identity_provider_lifecycle_operation_receipt(
    receipt: dict[str, Any],
    *,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_provider_session_receipt: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    identity_payload_path: str | Path | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> IdentityProviderLifecycleOperationVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != IDENTITY_PROVIDER_LIFECYCLE_OPERATION_SCHEMA:
        errors.append(f"unsupported identity provider lifecycle operation schema: {receipt.get('schema')}")
    body = without_keys(receipt, "operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("operation_id") != expected_id:
        errors.append("operation_id does not match canonical identity provider lifecycle operation body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("identity provider lifecycle operation receipt must include at least one signature")
    else:
        signed_value = {"operation_id": receipt.get("operation_id"), "identity_provider_lifecycle_operation": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("identity provider lifecycle operation signature verification failed")

    mode = receipt.get("mode")
    if mode not in IDENTITY_PROVIDER_LIFECYCLE_OPERATION_MODES:
        errors.append("identity provider lifecycle operation mode is unsupported")
    elif mode not in {"provider-event-stream", "hosted-lifecycle-worker"}:
        warnings.append(f"identity provider lifecycle operation mode is {mode}; live provider lifecycle operation is not claimed")

    provider = receipt.get("provider")
    if provider not in SUPPORTED_IDENTITY_PROVIDERS:
        errors.append(f"unsupported identity provider lifecycle operation provider: {provider}")

    attestation_binding = receipt.get("identity_attestation", {})
    if not isinstance(attestation_binding, dict):
        errors.append("identity provider lifecycle operation identity_attestation must be an object")
        attestation_binding = {}
    for field in ("attestation_id", "attestation_hash", "provider", "subject"):
        if not attestation_binding.get(field):
            errors.append(f"identity provider lifecycle operation identity_attestation.{field} is required")
    if provider != attestation_binding.get("provider"):
        errors.append("identity provider lifecycle operation provider must match identity attestation provider")

    operation = receipt.get("operation")
    _verify_operation(operation, provider, receipt.get("recorded_at"), errors)
    _verify_provider_evidence(
        receipt.get("provider_evidence"),
        receipt.get("recorded_at"),
        operation.get("outcome") if isinstance(operation, dict) else None,
        now,
        errors,
    )
    _verify_change_refs(receipt.get("change_refs"), errors)
    _check_no_secret_values(receipt, errors)

    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("identity provider lifecycle operation controls are required")

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
            errors.append("identity provider lifecycle operation attestation binding does not match supplied attestation")
        operation_value = receipt.get("operation", {}) if isinstance(receipt.get("operation"), dict) else {}
        subject = expected_binding.get("subject", {})
        if operation_value.get("identity_id") != subject.get("identity_id"):
            errors.append("identity provider lifecycle operation identity_id does not match supplied attestation subject")
        if operation_value.get("identity_record_hash") != subject.get("identity_record_hash"):
            errors.append("identity provider lifecycle operation identity_record_hash does not match supplied attestation subject")

    source_session = receipt.get("source_session")
    if identity_provider_session_receipt is None:
        if source_session:
            warnings.append("identity provider session source not supplied; session hash was not replayed")
    else:
        session_result = verify_identity_provider_session_receipt(
            identity_provider_session_receipt,
            identity_provider_attestation=identity_provider_attestation,
            identity_payload=identity_payload,
            identity_payload_path=identity_payload_path,
            vendor_identity_receipt=vendor_identity_receipt,
            proof_packs=proof_packs,
            trust_network_manifest=trust_network_manifest,
            key=key,
            now=now,
        )
        if not session_result.ok:
            errors.extend(f"source identity provider session invalid: {error}" for error in session_result.errors)
        warnings.extend(f"source identity provider session warning: {warning}" for warning in session_result.warnings)
        expected_session = _session_binding(identity_provider_session_receipt)
        if source_session != expected_session:
            errors.append("identity provider lifecycle operation session binding does not match supplied session receipt")
        operation_value = receipt.get("operation", {}) if isinstance(receipt.get("operation"), dict) else {}
        if expected_session.get("identity_id") != operation_value.get("identity_id"):
            errors.append("identity provider lifecycle operation session identity_id does not match operation identity_id")
        if expected_session.get("provider") != provider:
            errors.append("identity provider lifecycle operation session provider does not match receipt provider")

    return IdentityProviderLifecycleOperationVerification(ok=not errors, errors=errors, warnings=warnings)


def append_identity_provider_lifecycle_operation_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_provider_session_receipt: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    identity_payload_path: str | Path | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_identity_provider_lifecycle_operation_receipt(
        receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_provider_session_receipt=identity_provider_session_receipt,
        identity_payload=identity_payload,
        identity_payload_path=identity_payload_path,
        vendor_identity_receipt=vendor_identity_receipt,
        proof_packs=proof_packs,
        trust_network_manifest=trust_network_manifest,
        key=key,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid identity provider lifecycle operation receipt: " + "; ".join(result.errors))
    evidence = receipt.get("provider_evidence") or {}
    payload = {
        "operation_id": receipt["operation_id"],
        "operation_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "identity_attestation": receipt.get("identity_attestation"),
        "source_session": receipt.get("source_session"),
        "operation": receipt.get("operation"),
        "change_refs": receipt.get("change_refs"),
        "provider_evidence": {key: value for key, value in evidence.items() if key != "credential"},
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(
        IDENTITY_PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE,
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


def _session_binding(receipt: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(receipt, dict):
        return None
    session = receipt.get("session", {}) if isinstance(receipt.get("session"), dict) else {}
    return {
        "session_id": receipt.get("session_id"),
        "session_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "session_ref": session.get("session_ref"),
        "event_ref": session.get("event_ref"),
        "event_kind": session.get("event_kind"),
        "provider_event_id": session.get("provider_event_id"),
        "identity_id": session.get("identity_id"),
        "identity_record_hash": session.get("identity_record_hash"),
        "observed_at": session.get("observed_at"),
    }


def _verify_operation(value: Any, provider: Any, recorded_at: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("identity provider lifecycle operation operation must be an object")
        return
    for field in (
        "kind",
        "operation_ref",
        "provider_operation_id",
        "provider_tenant_ref",
        "identity_provider",
        "identity_id",
        "identity_record_hash",
        "actor_ref",
        "target_state",
        "outcome",
        "requested_at",
        "completed_at",
        "idempotency_key",
    ):
        if not value.get(field):
            errors.append(f"identity provider lifecycle operation operation.{field} is required")
    if value.get("kind") not in IDENTITY_PROVIDER_LIFECYCLE_OPERATION_KINDS:
        errors.append(f"identity provider lifecycle operation kind unsupported: {value.get('kind')}")
    if value.get("target_state") not in IDENTITY_PROVIDER_LIFECYCLE_TARGET_STATES:
        errors.append(f"identity provider lifecycle operation target_state unsupported: {value.get('target_state')}")
    if value.get("outcome") not in IDENTITY_PROVIDER_LIFECYCLE_OUTCOMES:
        errors.append(f"identity provider lifecycle operation outcome unsupported: {value.get('outcome')}")
    if value.get("identity_provider") != provider:
        errors.append("identity provider lifecycle operation subject provider must match receipt provider")
    _validate_state_pair(str(value.get("kind") or ""), str(value.get("target_state") or ""), errors)
    try:
        requested = parse_rfc3339(str(value.get("requested_at") or ""))
        completed = parse_rfc3339(str(value.get("completed_at") or ""))
        recorded = parse_rfc3339(str(recorded_at or ""))
        if completed < requested:
            errors.append("identity provider lifecycle operation completed_at must be after or equal to requested_at")
        if recorded < completed:
            errors.append("identity provider lifecycle operation recorded_at must be after or equal to completed_at")
    except ValueError as exc:
        errors.append(f"identity provider lifecycle operation timestamp invalid: {exc}")


def _verify_provider_evidence(value: Any, recorded_at: Any, outcome: Any, now: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("identity provider lifecycle operation provider_evidence must be an object")
        return
    for field in (
        "endpoint_url",
        "request_hash",
        "response_hash",
        "system_log_ref",
        "system_log_root",
        "audit_log_ref",
        "audit_log_root",
        "previous_identity_record_hash",
        "retention_until",
    ):
        if not value.get(field):
            errors.append(f"identity provider lifecycle operation provider_evidence.{field} is required")
    endpoint_url = str(value.get("endpoint_url") or "")
    if not _valid_url(endpoint_url):
        errors.append("identity provider lifecycle operation endpoint_url must be an absolute URL")
    elif not _is_https(endpoint_url):
        errors.append("identity provider lifecycle operation endpoint_url must use HTTPS")
    for field in (
        "request_hash",
        "response_hash",
        "system_log_root",
        "audit_log_root",
        "previous_identity_record_hash",
    ):
        if not _is_hash_ref(str(value.get(field) or "")):
            errors.append(f"identity provider lifecycle operation provider_evidence.{field} must be a sha256 reference")
    if value.get("resulting_identity_record_hash") is not None and not _is_hash_ref(str(value.get("resulting_identity_record_hash") or "")):
        errors.append("identity provider lifecycle operation provider_evidence.resulting_identity_record_hash must be a sha256 reference")
    status = value.get("response_status")
    if not isinstance(status, int) or status < 100 or status > 599:
        errors.append("identity provider lifecycle operation response_status must be an HTTP status code")
    else:
        success = 200 <= status < 300
        if value.get("success") is not success:
            errors.append("identity provider lifecycle operation success must match response_status")
        if success and outcome in {"failed", "denied"}:
            errors.append("identity provider lifecycle operation successful response cannot have failed or denied outcome")
        if not success and outcome == "succeeded":
            errors.append("identity provider lifecycle operation succeeded outcome requires a 2xx response")
    _verify_redacted_ref(value.get("credential"), "identity provider lifecycle operation credential", errors)
    try:
        recorded = parse_rfc3339(str(recorded_at or ""))
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if retention <= recorded:
            errors.append("identity provider lifecycle operation retention_until must be after recorded_at")
        if now and parse_rfc3339(now) > retention:
            errors.append("identity provider lifecycle operation retention has expired")
    except ValueError as exc:
        errors.append(f"identity provider lifecycle operation provider_evidence timestamp invalid: {exc}")


def _verify_change_refs(value: Any, errors: list[str]) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        errors.append("identity provider lifecycle operation change_refs must be an object")
        return
    for field, item in value.items():
        if field not in {"reason_ref", "approval_ref", "change_ticket_ref"}:
            errors.append(f"identity provider lifecycle operation change_refs.{field} is unsupported")
        if not isinstance(item, str) or not item.strip():
            errors.append(f"identity provider lifecycle operation change_refs.{field} must be a non-empty string")


def _validate_times(*, recorded_at: str, requested_at: str, completed_at: str, retention_until: str) -> None:
    requested = parse_rfc3339(requested_at)
    completed = parse_rfc3339(completed_at)
    recorded = parse_rfc3339(recorded_at)
    retention = parse_rfc3339(retention_until)
    if completed < requested:
        raise ValueError("completed_at must be after or equal to requested_at")
    if recorded < completed:
        raise ValueError("recorded_at must be after or equal to completed_at")
    if retention <= recorded:
        raise ValueError("retention_until must be after recorded_at")


def _validate_lifecycle_state(operation_kind: str, target_state: str, outcome: str, response_status: int) -> None:
    errors: list[str] = []
    _validate_state_pair(operation_kind, target_state, errors)
    if errors:
        raise ValueError("; ".join(errors))
    success = 200 <= response_status < 300
    if success and outcome in {"failed", "denied"}:
        raise ValueError("successful response cannot have failed or denied outcome")
    if not success and outcome == "succeeded":
        raise ValueError("succeeded outcome requires a 2xx response")


def _validate_state_pair(operation_kind: str, target_state: str, errors: list[str]) -> None:
    required = {
        "account_suspend": "suspended",
        "account_reactivate": "active",
        "account_deactivate": "deactivated",
        "account_delete": "deleted",
        "app_assignment": "assigned",
        "app_unassignment": "unassigned",
        "token_revocation": "revoked",
        "session_revocation": "revoked",
        "scim_sync": "synced",
    }
    expected = required.get(operation_kind)
    if expected and target_state != expected:
        errors.append(f"identity provider lifecycle operation {operation_kind} target_state must be {expected}")


def _controls(
    *,
    mode: str,
    operation_kind: str,
    target_state: str,
    has_session: bool,
    has_resulting_hash: bool,
) -> list[dict[str, str]]:
    live_status = "implemented-reference" if mode in {"provider-event-stream", "hosted-lifecycle-worker"} else "planned-production"
    return [
        {
            "id": "identity-attestation-binding",
            "status": "implemented-reference",
            "description": "Lifecycle operation evidence is bound to the canonical hash of an identity-provider attestation.",
        },
        {
            "id": "provider-lifecycle-request-response-hashes",
            "status": "implemented-reference",
            "description": "Provider request, response, system-log, and audit-log roots are recorded as hashes.",
        },
        {
            "id": "identity-lifecycle-target-state",
            "status": "implemented-reference",
            "description": f"Operation {operation_kind} records target state {target_state}.",
        },
        {
            "id": "identity-session-source-binding",
            "status": "implemented-reference" if has_session else "not-applicable",
            "description": "Optional source session receipt ties the lifecycle operation to a provider-observed session or token event.",
        },
        {
            "id": "resulting-identity-record-hash",
            "status": "implemented-reference" if has_resulting_hash else "not-applicable",
            "description": "Resulting identity record hash is bound when the provider operation mutates account state.",
        },
        {
            "id": "redacted-lifecycle-credential",
            "status": "implemented-reference",
            "description": "Provider lifecycle credentials are represented only by redacted references.",
        },
        {
            "id": "live-identity-provider-lifecycle-operation",
            "status": live_status,
            "description": "Receipt claims live provider lifecycle operation only in provider-event-stream or hosted-lifecycle-worker mode.",
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
                    errors.append(f"identity provider lifecycle operation secret-like field must be redacted reference: {child_path}")
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
