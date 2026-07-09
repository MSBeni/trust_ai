from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .identity import SUPPORTED_IDENTITY_PROVIDERS
from .identity_provider_lifecycle_operation import verify_identity_provider_lifecycle_operation_receipt

IDENTITY_PROVIDER_LIFECYCLE_WORKER_SCHEMA = "trustai.identity-provider-lifecycle-worker/0.1"
IDENTITY_PROVIDER_LIFECYCLE_WORKER_ENTRY_TYPE = "identity.provider.lifecycle_worker_recorded"
IDENTITY_PROVIDER_LIFECYCLE_WORKER_MODES = {
    "local-reference",
    "scheduled-worker",
    "hosted-worker",
    "provider-event-stream-worker",
    "production-design",
}
IDENTITY_PROVIDER_LIFECYCLE_WORKER_OPERATION_KINDS = {
    "lifecycle_operation_propagation",
    "account_state_reconcile",
    "app_assignment_propagation",
    "token_revocation_propagation",
    "session_revocation_propagation",
    "scim_sync_reconcile",
    "dead_letter_replay",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class IdentityProviderLifecycleWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_identity_provider_lifecycle_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("identity provider lifecycle worker receipt must contain an object")
    return value


def write_identity_provider_lifecycle_worker_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_identity_provider_lifecycle_worker_receipt(
    lifecycle_operation_receipt: dict[str, Any],
    *,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_provider_session_receipt: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    identity_payload_path: str | Path | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    mode: str = "scheduled-worker",
    environment: str = "local",
    worker_ref: str,
    run_ref: str,
    operation_kind: str,
    actor_ref: str,
    schedule_ref: str,
    cadence_seconds: int,
    lease_ref: str,
    checkpoint_ref: str,
    queue_ref: str,
    destination_ref: str,
    propagation_log_ref: str,
    propagation_log_root: str,
    metrics_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    credential_ref: str,
    started_at: str,
    retention_until: str,
    completed_at: str | None = None,
    checkpoint_hash: str | None = None,
    previous_cursor_ref: str | None = None,
    next_cursor_ref: str | None = None,
    attempt: int = 1,
    max_attempts: int = 3,
    queue_message_ref: str | None = None,
    account_state_log_ref: str | None = None,
    account_state_log_root: str | None = None,
    session_revocation_log_ref: str | None = None,
    session_revocation_log_root: str | None = None,
    token_revocation_log_ref: str | None = None,
    token_revocation_log_root: str | None = None,
    request_hash: str | None = None,
    response_status: int | None = None,
    response_hash: str | None = None,
    next_run_at: str | None = None,
    error_ref: str | None = None,
    evidence_refs: list[str] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in IDENTITY_PROVIDER_LIFECYCLE_WORKER_MODES:
        raise ValueError(f"mode must be one of {sorted(IDENTITY_PROVIDER_LIFECYCLE_WORKER_MODES)}")
    if operation_kind not in IDENTITY_PROVIDER_LIFECYCLE_WORKER_OPERATION_KINDS:
        raise ValueError(f"operation_kind must be one of {sorted(IDENTITY_PROVIDER_LIFECYCLE_WORKER_OPERATION_KINDS)}")
    if not isinstance(lifecycle_operation_receipt, dict):
        raise ValueError("lifecycle_operation_receipt must be an object")
    for value, field in (
        (worker_ref, "worker_ref"),
        (run_ref, "run_ref"),
        (actor_ref, "actor_ref"),
        (schedule_ref, "schedule_ref"),
        (lease_ref, "lease_ref"),
        (checkpoint_ref, "checkpoint_ref"),
        (queue_ref, "queue_ref"),
        (destination_ref, "destination_ref"),
        (propagation_log_ref, "propagation_log_ref"),
        (propagation_log_root, "propagation_log_root"),
        (metrics_ref, "metrics_ref"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (credential_ref, "credential_ref"),
        (started_at, "started_at"),
        (retention_until, "retention_until"),
    ):
        _require_text(value, field)
    completed = completed_at or utc_now()
    _validate_times(started_at=started_at, completed_at=completed, retention_until=retention_until, next_run_at=next_run_at)
    if not isinstance(cadence_seconds, int) or cadence_seconds <= 0:
        raise ValueError("cadence_seconds must be a positive integer")
    if not isinstance(attempt, int) or attempt < 1:
        raise ValueError("attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < attempt:
        raise ValueError("max_attempts must be greater than or equal to attempt")
    for field, value in (
        ("checkpoint_hash", checkpoint_hash),
        ("propagation_log_root", propagation_log_root),
        ("account_state_log_root", account_state_log_root),
        ("session_revocation_log_root", session_revocation_log_root),
        ("token_revocation_log_root", token_revocation_log_root),
        ("request_hash", request_hash),
        ("response_hash", response_hash),
        ("audit_log_root", audit_log_root),
    ):
        if value and not _is_hash_ref(str(value)):
            raise ValueError(f"{field} must be a sha256 reference")
    if response_status is not None and (not isinstance(response_status, int) or response_status < 100 or response_status > 599):
        raise ValueError("response_status must be an HTTP status code")

    source_result = verify_identity_provider_lifecycle_operation_receipt(
        lifecycle_operation_receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_provider_session_receipt=identity_provider_session_receipt,
        identity_payload=identity_payload,
        identity_payload_path=identity_payload_path,
        vendor_identity_receipt=vendor_identity_receipt,
        proof_packs=proof_packs,
        trust_network_manifest=trust_network_manifest,
        key=key,
    )
    if not source_result.ok:
        raise ValueError("invalid identity provider lifecycle operation source: " + "; ".join(source_result.errors))

    source_operation = _source_operation_record(lifecycle_operation_receipt)
    provider = source_operation.get("provider")
    if provider not in SUPPORTED_IDENTITY_PROVIDERS:
        raise ValueError("source lifecycle operation provider is unsupported")
    source_success = source_operation.get("outcome") in {"succeeded", "noop"} and source_operation.get("success") is True
    worker_success = not error_ref and source_success and (response_status is None or 200 <= response_status < 300)
    body: dict[str, Any] = {
        "schema": IDENTITY_PROVIDER_LIFECYCLE_WORKER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": completed,
        "provider": provider,
        "source_operation": source_operation,
        "worker": {
            "worker_ref": worker_ref,
            "run_ref": run_ref,
            "operation_kind": operation_kind,
            "actor_ref": actor_ref,
            "started_at": started_at,
            "completed_at": completed,
            "attempt": attempt,
            "max_attempts": max_attempts,
            "success": worker_success,
            "error_ref": error_ref,
        },
        "scheduler": {
            "schedule_ref": schedule_ref,
            "cadence_seconds": cadence_seconds,
            "lease_ref": lease_ref,
            "checkpoint_ref": checkpoint_ref,
            "checkpoint_hash": checkpoint_hash,
            "previous_cursor_ref": previous_cursor_ref,
            "next_cursor_ref": next_cursor_ref,
            "next_run_at": next_run_at,
        },
        "propagation": {
            "queue_ref": queue_ref,
            "queue_message_ref": queue_message_ref,
            "destination_ref": destination_ref,
            "propagation_log_ref": propagation_log_ref,
            "propagation_log_root": propagation_log_root,
            "account_state_log_ref": account_state_log_ref,
            "account_state_log_root": account_state_log_root,
            "session_revocation_log_ref": session_revocation_log_ref,
            "session_revocation_log_root": session_revocation_log_root,
            "token_revocation_log_ref": token_revocation_log_ref,
            "token_revocation_log_root": token_revocation_log_root,
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
        },
        "observability": {
            "metrics_ref": metrics_ref,
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "retention_until": retention_until,
        },
        "credential": _redacted_ref(credential_ref),
        "operations": {
            "evidence_refs": sorted(evidence_refs or []),
        },
        "controls": _controls(
            mode=mode,
            operation_kind=operation_kind,
            source_operation=source_operation,
            checkpoint_hash=checkpoint_hash,
            propagation_log_root=propagation_log_root,
            account_state_log_root=account_state_log_root,
            session_revocation_log_root=session_revocation_log_root,
            token_revocation_log_root=token_revocation_log_root,
            response_status=response_status,
            credential_ref=credential_ref,
        ),
        "limitations": [
            "This receipt records a scheduled or hosted identity-provider lifecycle worker run and the source lifecycle operation it propagated.",
            "It stores redacted credential references, scheduler leases, checkpoints, source receipt hashes, propagation log roots, and cursor metadata, not provider credentials or raw provider payloads.",
            "It proves continuously operated hosted identity-provider lifecycle propagation only when paired with deployment, storage, monitoring, and live provider dispatch evidence.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [sign_value({"worker_operation_id": worker_operation_id, "identity_provider_lifecycle_worker": body}, key)],
    }


def verify_identity_provider_lifecycle_worker_receipt(
    receipt: dict[str, Any],
    *,
    lifecycle_operation_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_provider_session_receipt: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    identity_payload_path: str | Path | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> IdentityProviderLifecycleWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != IDENTITY_PROVIDER_LIFECYCLE_WORKER_SCHEMA:
        errors.append(f"unsupported identity provider lifecycle worker schema: {receipt.get('schema')}")
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append("worker_operation_id does not match canonical identity provider lifecycle worker body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("identity provider lifecycle worker receipt must include at least one signature")
    else:
        signed_value = {"worker_operation_id": receipt.get("worker_operation_id"), "identity_provider_lifecycle_worker": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("identity provider lifecycle worker signature verification failed")

    mode = receipt.get("mode")
    if mode not in IDENTITY_PROVIDER_LIFECYCLE_WORKER_MODES:
        errors.append("identity provider lifecycle worker mode is unsupported")
    elif mode not in {"hosted-worker", "provider-event-stream-worker"}:
        warnings.append(f"identity provider lifecycle worker mode is {mode}; continuously hosted identity-provider lifecycle worker operation is not claimed")
    provider = receipt.get("provider")
    if provider not in SUPPORTED_IDENTITY_PROVIDERS:
        errors.append(f"unsupported identity provider lifecycle worker provider: {provider}")

    source_operation = receipt.get("source_operation", {})
    _verify_source_operation(source_operation, provider, errors)
    _verify_worker(receipt.get("worker"), receipt.get("recorded_at"), errors)
    _verify_scheduler(receipt.get("scheduler"), errors)
    _verify_propagation(receipt.get("propagation"), errors)
    _verify_observability(receipt.get("observability"), receipt.get("recorded_at"), now, errors)
    _verify_redacted_ref(receipt.get("credential"), "identity provider lifecycle worker credential", errors)
    _check_no_secret_values(receipt, errors)
    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("identity provider lifecycle worker controls are required")

    if lifecycle_operation_receipt is None:
        warnings.append("identity provider lifecycle operation source not supplied; source operation hash was not replayed")
    else:
        source_result = verify_identity_provider_lifecycle_operation_receipt(
            lifecycle_operation_receipt,
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
        if not source_result.ok:
            errors.extend(f"source identity provider lifecycle operation invalid: {error}" for error in source_result.errors)
        warnings.extend(f"source identity provider lifecycle operation warning: {warning}" for warning in source_result.warnings)
        expected_source = _source_operation_record(lifecycle_operation_receipt)
        if source_operation != expected_source:
            errors.append("identity provider lifecycle worker source operation does not match supplied lifecycle operation receipt")

    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    propagation = receipt.get("propagation", {}) if isinstance(receipt.get("propagation"), dict) else {}
    response_status = propagation.get("response_status")
    response_success = response_status is None or (isinstance(response_status, int) and 200 <= response_status < 300)
    source_success = isinstance(source_operation, dict) and source_operation.get("outcome") in {"succeeded", "noop"} and source_operation.get("success") is True
    expected_success = not worker.get("error_ref") and source_success and response_success
    if isinstance(worker.get("success"), bool) and worker.get("success") is not expected_success:
        errors.append("identity provider lifecycle worker success must match source operation, response status, and error_ref")

    return IdentityProviderLifecycleWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_identity_provider_lifecycle_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    lifecycle_operation_receipt: dict[str, Any] | None = None,
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
    result = verify_identity_provider_lifecycle_worker_receipt(
        receipt,
        lifecycle_operation_receipt=lifecycle_operation_receipt,
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
        raise ValueError("invalid identity provider lifecycle worker receipt: " + "; ".join(result.errors))
    payload = {
        "worker_operation_id": receipt["worker_operation_id"],
        "worker_operation_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "source_operation": receipt.get("source_operation"),
        "worker": receipt.get("worker"),
        "scheduler": receipt.get("scheduler"),
        "propagation": receipt.get("propagation"),
        "observability": receipt.get("observability"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(
        IDENTITY_PROVIDER_LIFECYCLE_WORKER_ENTRY_TYPE,
        payload,
        key=key,
        timestamp=receipt.get("recorded_at"),
    )


def _source_operation_record(receipt: dict[str, Any]) -> dict[str, Any]:
    operation = receipt.get("operation", {}) if isinstance(receipt, dict) else {}
    evidence = receipt.get("provider_evidence", {}) if isinstance(receipt, dict) else {}
    return {
        "operation_id": receipt.get("operation_id"),
        "operation_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "kind": operation.get("kind"),
        "operation_ref": operation.get("operation_ref"),
        "provider_operation_id": operation.get("provider_operation_id"),
        "identity_id": operation.get("identity_id"),
        "identity_record_hash": operation.get("identity_record_hash"),
        "target_state": operation.get("target_state"),
        "outcome": operation.get("outcome"),
        "completed_at": operation.get("completed_at"),
        "success": evidence.get("success"),
        "system_log_root": evidence.get("system_log_root"),
        "audit_log_root": evidence.get("audit_log_root"),
    }


def _verify_source_operation(value: Any, provider: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("identity provider lifecycle worker source_operation must be an object")
        return
    for field in (
        "operation_id",
        "operation_hash",
        "provider",
        "kind",
        "operation_ref",
        "provider_operation_id",
        "identity_id",
        "identity_record_hash",
        "target_state",
        "outcome",
        "completed_at",
        "system_log_root",
        "audit_log_root",
    ):
        if value.get(field) in (None, ""):
            errors.append(f"identity provider lifecycle worker source_operation.{field} is required")
    if value.get("provider") != provider:
        errors.append("identity provider lifecycle worker source provider must match receipt provider")
    for field in ("operation_hash", "identity_record_hash", "system_log_root", "audit_log_root"):
        if not _is_hash_ref(str(value.get(field) or "")):
            errors.append(f"identity provider lifecycle worker source_operation.{field} must be a sha256 reference")
    try:
        parse_rfc3339(str(value.get("completed_at") or ""))
    except ValueError as exc:
        errors.append(f"identity provider lifecycle worker source_operation.completed_at invalid: {exc}")


def _verify_worker(value: Any, recorded_at: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("identity provider lifecycle worker worker must be an object")
        return
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at", "attempt", "max_attempts", "success"):
        if value.get(field) in (None, ""):
            errors.append(f"identity provider lifecycle worker worker.{field} is required")
    if value.get("operation_kind") not in IDENTITY_PROVIDER_LIFECYCLE_WORKER_OPERATION_KINDS:
        errors.append(f"identity provider lifecycle worker operation kind unsupported: {value.get('operation_kind')}")
    try:
        started = parse_rfc3339(str(value.get("started_at") or ""))
        completed = parse_rfc3339(str(value.get("completed_at") or ""))
        recorded = parse_rfc3339(str(recorded_at or ""))
        if completed < started:
            errors.append("identity provider lifecycle worker completed_at must be after or equal to started_at")
        if recorded != completed:
            errors.append("identity provider lifecycle worker recorded_at must equal worker.completed_at")
    except ValueError as exc:
        errors.append(f"identity provider lifecycle worker timestamp invalid: {exc}")
    attempt = value.get("attempt")
    max_attempts = value.get("max_attempts")
    if not isinstance(attempt, int) or attempt < 1:
        errors.append("identity provider lifecycle worker attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < (attempt if isinstance(attempt, int) else 1):
        errors.append("identity provider lifecycle worker max_attempts must be greater than or equal to attempt")
    if not isinstance(value.get("success"), bool):
        errors.append("identity provider lifecycle worker success must be a boolean")


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("identity provider lifecycle worker scheduler must be an object")
        return
    for field in ("schedule_ref", "cadence_seconds", "lease_ref", "checkpoint_ref"):
        if value.get(field) in (None, ""):
            errors.append(f"identity provider lifecycle worker scheduler.{field} is required")
    cadence = value.get("cadence_seconds")
    if not isinstance(cadence, int) or cadence <= 0:
        errors.append("identity provider lifecycle worker scheduler.cadence_seconds must be a positive integer")
    if value.get("checkpoint_hash") and not _is_hash_ref(str(value.get("checkpoint_hash"))):
        errors.append("identity provider lifecycle worker scheduler.checkpoint_hash must be a sha256 reference")
    if value.get("next_run_at"):
        try:
            parse_rfc3339(str(value.get("next_run_at")))
        except ValueError as exc:
            errors.append(f"identity provider lifecycle worker scheduler.next_run_at invalid: {exc}")


def _verify_propagation(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("identity provider lifecycle worker propagation must be an object")
        return
    for field in ("queue_ref", "destination_ref", "propagation_log_ref", "propagation_log_root"):
        if not value.get(field):
            errors.append(f"identity provider lifecycle worker propagation.{field} is required")
    for field in (
        "propagation_log_root",
        "account_state_log_root",
        "session_revocation_log_root",
        "token_revocation_log_root",
        "request_hash",
        "response_hash",
    ):
        if value.get(field) and not _is_hash_ref(str(value.get(field))):
            errors.append(f"identity provider lifecycle worker propagation.{field} must be a sha256 reference")
    status = value.get("response_status")
    if status is not None and (not isinstance(status, int) or status < 100 or status > 599):
        errors.append("identity provider lifecycle worker propagation.response_status must be an HTTP status code")


def _verify_observability(value: Any, recorded_at: Any, now: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("identity provider lifecycle worker observability must be an object")
        return
    for field in ("metrics_ref", "audit_log_ref", "audit_log_root", "retention_until"):
        if not value.get(field):
            errors.append(f"identity provider lifecycle worker observability.{field} is required")
    if not _is_hash_ref(str(value.get("audit_log_root") or "")):
        errors.append("identity provider lifecycle worker observability.audit_log_root must be a sha256 reference")
    try:
        recorded = parse_rfc3339(str(recorded_at or ""))
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if retention <= recorded:
            errors.append("identity provider lifecycle worker retention_until must be after recorded_at")
        if now and parse_rfc3339(now) > retention:
            errors.append("identity provider lifecycle worker retention has expired")
    except ValueError as exc:
        errors.append(f"identity provider lifecycle worker observability timestamp invalid: {exc}")


def _validate_times(*, started_at: str, completed_at: str, retention_until: str, next_run_at: str | None) -> None:
    started = parse_rfc3339(started_at)
    completed = parse_rfc3339(completed_at)
    retention = parse_rfc3339(retention_until)
    if completed < started:
        raise ValueError("completed_at must be after or equal to started_at")
    if retention <= completed:
        raise ValueError("retention_until must be after completed_at")
    if next_run_at:
        parse_rfc3339(next_run_at)


def _controls(
    *,
    mode: str,
    operation_kind: str,
    source_operation: dict[str, Any],
    checkpoint_hash: str | None,
    propagation_log_root: str,
    account_state_log_root: str | None,
    session_revocation_log_root: str | None,
    token_revocation_log_root: str | None,
    response_status: int | None,
    credential_ref: str,
) -> list[dict[str, str]]:
    live_status = "implemented-reference" if mode in {"hosted-worker", "provider-event-stream-worker"} else "planned-production"
    return [
        {
            "id": "identity-lifecycle-operation-source-binding",
            "status": "implemented-reference",
            "description": "Worker receipt is bound to a canonical identity-provider lifecycle operation receipt hash.",
        },
        {
            "id": "scheduler-lease-checkpoint",
            "status": "implemented-reference" if checkpoint_hash else "planned-production",
            "description": "Worker schedule, lease, checkpoint, and optional checkpoint hash are recorded.",
        },
        {
            "id": "identity-lifecycle-propagation-log",
            "status": "implemented-reference" if _is_hash_ref(propagation_log_root) else "planned-production",
            "description": f"Propagation log root is bound for {operation_kind}.",
        },
        {
            "id": "account-session-token-propagation-roots",
            "status": "implemented-reference" if any((account_state_log_root, session_revocation_log_root, token_revocation_log_root)) else "not-applicable",
            "description": "Account-state, session-revocation, and token-revocation log roots are bound when supplied.",
        },
        {
            "id": "source-operation-success-propagation",
            "status": "implemented-reference" if source_operation.get("success") is True and source_operation.get("outcome") in {"succeeded", "noop"} else "planned-production",
            "description": "Worker success is constrained by source lifecycle operation outcome and optional propagation response status.",
        },
        {
            "id": "provider-propagation-response",
            "status": "implemented-reference" if response_status is not None else "not-applicable",
            "description": "Optional downstream propagation response status and hashes are recorded when supplied.",
        },
        {
            "id": "redacted-lifecycle-worker-credential",
            "status": "implemented-reference" if credential_ref else "planned-production",
            "description": "Identity-provider worker credentials are represented only by redacted references.",
        },
        {
            "id": "hosted-identity-lifecycle-worker",
            "status": live_status,
            "description": "Receipt claims hosted worker operation only in hosted-worker or provider-event-stream-worker mode.",
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
                    errors.append(f"identity provider lifecycle worker secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if value is None:
        return True
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and _is_string_list(value):
        return True
    if (key.endswith("_root") or key.endswith("_hash")) and isinstance(value, str) and _is_hash_ref(value):
        return True
    return False

