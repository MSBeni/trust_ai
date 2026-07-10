from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .policy_backend_service import verify_policy_backend_service_attestation

POLICY_BACKEND_WORKER_SCHEMA = "trustai.policy-backend-worker/0.1"
POLICY_BACKEND_WORKER_ENTRY_TYPE = "policy_backend.worker_recorded"
POLICY_BACKEND_WORKER_MODES = {"local-reference", "scheduled-worker", "hosted-worker", "production-design"}
POLICY_BACKEND_WORKER_OPERATION_KINDS = {
    "policy_enforcement",
    "policy_sync",
    "decision_log_export",
    "audit_log_export",
    "backend_health_check",
}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class PolicyBackendWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_policy_backend_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("policy backend worker receipt must contain an object")
    return value


def write_policy_backend_worker_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_policy_backend_worker_receipt(
    service_attestation: dict[str, Any],
    enforcement_receipt: dict[str, Any],
    policy_pack: dict[str, Any],
    action: dict[str, Any],
    proof_pack: dict[str, Any],
    decision: dict[str, Any],
    policy_export: dict[str, Any],
    *,
    policy_engine_receipt: dict[str, Any] | None = None,
    mode: str = "hosted-worker",
    environment: str = "local",
    worker_ref: str,
    run_ref: str,
    operation_kind: str,
    actor_ref: str,
    schedule_ref: str,
    cadence_seconds: int,
    lease_ref: str,
    checkpoint_ref: str,
    checkpoint_hash: str,
    previous_cursor_ref: str | None = None,
    next_cursor_ref: str | None = None,
    next_run_at: str | None = None,
    attempt: int = 1,
    max_attempts: int = 3,
    queue_ref: str,
    queue_message_ref: str,
    queue_message_hash: str,
    dead_letter_queue_ref: str | None = None,
    backend_request_ref: str | None = None,
    request_hash: str | None = None,
    response_status: int | None = None,
    response_hash: str | None = None,
    decision_log_ref: str,
    decision_log_root: str,
    decision_record_hash: str | None = None,
    metrics_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    credential_ref: str,
    backend_credential_ref: str,
    scheduler_export_ref: str | None = None,
    scheduler_export_hash: str | None = None,
    queue_export_ref: str | None = None,
    queue_export_hash: str | None = None,
    lease_export_ref: str | None = None,
    lease_export_hash: str | None = None,
    decision_log_export_ref: str | None = None,
    decision_log_export_hash: str | None = None,
    audit_export_ref: str | None = None,
    audit_export_hash: str | None = None,
    evidence_refs: list[str] | None = None,
    started_at: str,
    completed_at: str | None = None,
    error_ref: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in POLICY_BACKEND_WORKER_MODES:
        raise ValueError(f"mode must be one of {sorted(POLICY_BACKEND_WORKER_MODES)}")
    if operation_kind not in POLICY_BACKEND_WORKER_OPERATION_KINDS:
        raise ValueError(f"operation_kind must be one of {sorted(POLICY_BACKEND_WORKER_OPERATION_KINDS)}")
    service_result = verify_policy_backend_service_attestation(
        service_attestation,
        enforcement_receipt,
        policy_pack=policy_pack,
        action=action,
        proof_pack=proof_pack,
        decision=decision,
        policy_export=policy_export,
        policy_engine_receipt=policy_engine_receipt,
        key=key,
    )
    if not service_result.ok:
        raise ValueError("invalid policy backend service source: " + "; ".join(service_result.errors))

    completed = completed_at or utc_now()
    started = parse_rfc3339(started_at)
    finished = parse_rfc3339(completed)
    retention = parse_rfc3339(retention_until)
    if finished < started:
        raise ValueError("completed_at must be at or after started_at")
    if retention <= finished:
        raise ValueError("retention_until must be after completed_at")
    if next_run_at:
        parse_rfc3339(next_run_at)
    if not isinstance(cadence_seconds, int) or cadence_seconds <= 0:
        raise ValueError("cadence_seconds must be a positive integer")
    if not isinstance(attempt, int) or attempt < 1:
        raise ValueError("attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < attempt:
        raise ValueError("max_attempts must be greater than or equal to attempt")

    for value, field in (
        (environment, "environment"),
        (worker_ref, "worker_ref"),
        (run_ref, "run_ref"),
        (actor_ref, "actor_ref"),
        (schedule_ref, "schedule_ref"),
        (lease_ref, "lease_ref"),
        (checkpoint_ref, "checkpoint_ref"),
        (checkpoint_hash, "checkpoint_hash"),
        (queue_ref, "queue_ref"),
        (queue_message_ref, "queue_message_ref"),
        (queue_message_hash, "queue_message_hash"),
        (decision_log_ref, "decision_log_ref"),
        (decision_log_root, "decision_log_root"),
        (metrics_ref, "metrics_ref"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (retention_until, "retention_until"),
        (credential_ref, "credential_ref"),
        (backend_credential_ref, "backend_credential_ref"),
        (started_at, "started_at"),
    ):
        _require_text(value, field)

    service = _service_record(service_attestation)
    enforcement = _enforcement_record(enforcement_receipt)
    service_credential = service.get("operation_credential", {}) if isinstance(service.get("operation_credential"), dict) else {}
    if service_credential.get("ref") and service_credential.get("ref") != credential_ref:
        raise ValueError("credential_ref must match policy backend service operation credential ref")
    backend_credential = enforcement_receipt.get("credential", {}) if isinstance(enforcement_receipt.get("credential"), dict) else {}
    if backend_credential.get("ref") and backend_credential.get("ref") != backend_credential_ref:
        raise ValueError("backend_credential_ref must match enforcement backend credential ref")
    if decision_log_ref != service.get("decision_log_ref"):
        raise ValueError("decision_log_ref must match policy backend service operation decision_log_ref")
    if audit_log_ref != service.get("audit_log_ref"):
        raise ValueError("audit_log_ref must match policy backend service audit_log_ref")

    resolved_request_hash = request_hash or enforcement.get("request_hash")
    resolved_response_status = response_status if response_status is not None else enforcement.get("response_status")
    resolved_response_hash = response_hash or enforcement.get("response_hash")
    if not isinstance(resolved_response_status, int) or resolved_response_status < 100 or resolved_response_status > 599:
        raise ValueError("response_status must be an HTTP status code")

    for field, value in (
        ("checkpoint_hash", checkpoint_hash),
        ("queue_message_hash", queue_message_hash),
        ("request_hash", resolved_request_hash),
        ("response_hash", resolved_response_hash),
        ("decision_log_root", decision_log_root),
        ("decision_record_hash", decision_record_hash),
        ("audit_log_root", audit_log_root),
        ("scheduler_export_hash", scheduler_export_hash),
        ("queue_export_hash", queue_export_hash),
        ("lease_export_hash", lease_export_hash),
        ("decision_log_export_hash", decision_log_export_hash),
        ("audit_export_hash", audit_export_hash),
    ):
        if value and not _is_sha256_ref(str(value)):
            raise ValueError(f"{field} must be a sha256 reference")

    source_artifacts = _source_artifacts(
        service_attestation,
        enforcement_receipt,
        policy_pack,
        action,
        proof_pack,
        decision,
        policy_export,
        policy_engine_receipt,
    )
    provider_exports = _provider_exports(
        scheduler_export_ref=scheduler_export_ref,
        scheduler_export_hash=scheduler_export_hash,
        queue_export_ref=queue_export_ref,
        queue_export_hash=queue_export_hash,
        lease_export_ref=lease_export_ref,
        lease_export_hash=lease_export_hash,
        decision_log_export_ref=decision_log_export_ref,
        decision_log_export_hash=decision_log_export_hash,
        audit_export_ref=audit_export_ref,
        audit_export_hash=audit_export_hash,
    )
    response_success = 200 <= resolved_response_status < 300
    success = not error_ref and response_success
    body: dict[str, Any] = {
        "schema": POLICY_BACKEND_WORKER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": completed,
        "service": service,
        "source_enforcement": enforcement,
        "source": _source_summary(source_artifacts, service_attestation, enforcement_receipt),
        "worker": {
            "worker_ref": worker_ref,
            "run_ref": run_ref,
            "operation_kind": operation_kind,
            "actor_ref": actor_ref,
            "started_at": started_at,
            "completed_at": completed,
            "attempt": attempt,
            "max_attempts": max_attempts,
            "success": success,
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
        "execution": {
            "queue_ref": queue_ref,
            "queue_message_ref": queue_message_ref,
            "queue_message_hash": queue_message_hash,
            "dead_letter_queue_ref": dead_letter_queue_ref,
            "backend_ref": enforcement.get("backend_ref"),
            "engine": enforcement.get("engine"),
            "endpoint_url": enforcement.get("endpoint_url"),
            "bundle_ref": enforcement.get("bundle_ref"),
            "bundle_hash": enforcement.get("bundle_hash"),
            "backend_request_ref": backend_request_ref,
            "request_hash": resolved_request_hash,
            "response_status": resolved_response_status,
            "response_hash": resolved_response_hash,
            "response_accepted": response_success,
        },
        "observability": {
            "decision_log_ref": decision_log_ref,
            "decision_log_root": decision_log_root,
            "decision_record_hash": decision_record_hash,
            "metrics_ref": metrics_ref,
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "retention_until": retention_until,
            "evidence_refs": sorted(evidence_refs or []),
        },
        "provider_exports": provider_exports,
        "credential": _redacted_ref(credential_ref),
        "backend_credential": _redacted_ref(backend_credential_ref),
        "source_artifacts": source_artifacts,
        "controls": _controls(
            service=service,
            enforcement=enforcement,
            source_artifacts=source_artifacts,
            mode=mode,
            cadence_seconds=cadence_seconds,
            checkpoint_hash=checkpoint_hash,
            queue_message_hash=queue_message_hash,
            request_hash=resolved_request_hash,
            response_hash=resolved_response_hash,
            response_status=resolved_response_status,
            decision_log_root=decision_log_root,
            audit_log_root=audit_log_root,
            provider_exports=provider_exports,
            success=success,
        ),
        "limitations": [
            "This receipt records one policy backend worker operation and replays the signed OPA/Cedar service attestation source.",
            "It binds scheduler cadence, lease, checkpoint, queue message, backend request/response, decision-log, audit-log, provider-export, and redacted credential evidence.",
            "It stores hashes and redacted credential references, not raw OPA/Cedar requests, policy decisions, or backend credentials.",
            "It does not claim continuously operated production OPA/Cedar infrastructure unless paired with provider-native scheduler, queue, lease, decision-log, audit-log, KMS, and immutable export evidence.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [sign_value({"worker_operation_id": worker_operation_id, "policy_backend_worker": body}, key)],
    }


def verify_policy_backend_worker_receipt(
    receipt: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    enforcement_receipt: dict[str, Any] | None = None,
    policy_pack: dict[str, Any] | None = None,
    action: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    policy_export: dict[str, Any] | None = None,
    policy_engine_receipt: dict[str, Any] | None = None,
    key: str | None = None,
) -> PolicyBackendWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != POLICY_BACKEND_WORKER_SCHEMA:
        errors.append(f"unsupported policy backend worker schema: {receipt.get('schema')}")
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append("worker_operation_id does not match canonical policy backend worker body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("policy backend worker receipt must include at least one signature")
    else:
        signed_value = {"worker_operation_id": receipt.get("worker_operation_id"), "policy_backend_worker": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("policy backend worker signature verification failed")

    try:
        recorded = parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"policy backend worker recorded_at invalid: {exc}")
        recorded = None
    mode = receipt.get("mode")
    if mode not in POLICY_BACKEND_WORKER_MODES:
        errors.append("policy backend worker mode is unsupported")
    elif mode not in {"scheduled-worker", "hosted-worker"}:
        warnings.append(f"policy backend worker mode is {mode}; hosted worker operation is not fully claimed")

    _verify_service(receipt.get("service"), errors)
    _verify_source_enforcement(receipt.get("source_enforcement"), errors)
    _verify_source(receipt.get("source"), errors)
    _verify_worker(receipt.get("worker"), recorded, errors)
    _verify_scheduler(receipt.get("scheduler"), errors)
    _verify_execution(receipt.get("execution"), errors)
    _verify_observability(receipt.get("observability"), recorded, errors)
    _verify_provider_exports(receipt.get("provider_exports"), errors)
    _verify_redacted_ref(receipt.get("credential"), "policy backend worker credential", errors)
    _verify_redacted_ref(receipt.get("backend_credential"), "policy backend worker backend_credential", errors)
    _verify_source_artifacts(receipt.get("source_artifacts"), errors)
    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("policy backend worker controls are required")

    if service_attestation is None:
        warnings.append("policy backend worker service attestation artifact was not supplied; service source was not replayed")
    else:
        _compare_source_hash(receipt, "policy-backend-service-attestation", service_attestation, errors)
        service_hash = receipt.get("service", {}).get("attestation_hash") if isinstance(receipt.get("service"), dict) else None
        if service_hash != content_hash(service_attestation):
            errors.append("policy backend worker service.attestation_hash does not match supplied service attestation")

    if enforcement_receipt is None:
        warnings.append("policy backend worker enforcement artifact was not supplied; enforcement source was not replayed")
    else:
        _compare_source_hash(receipt, "policy-backend-enforcement", enforcement_receipt, errors)
        enforcement_hash = receipt.get("source_enforcement", {}).get("enforcement_hash") if isinstance(receipt.get("source_enforcement"), dict) else None
        if enforcement_hash != content_hash(enforcement_receipt):
            errors.append("policy backend worker source_enforcement.enforcement_hash does not match supplied enforcement receipt")

    for source_type, source_value in (
        ("policy-pack", policy_pack),
        ("runtime-action", action),
        ("proof-pack", proof_pack),
        ("policy-decision", decision),
        ("policy-export", policy_export),
        ("policy-engine-receipt", policy_engine_receipt),
    ):
        if source_value is not None:
            _compare_source_hash(receipt, source_type, source_value, errors)

    if service_attestation is not None and enforcement_receipt is not None:
        if all(source is not None for source in (policy_pack, action, proof_pack, decision, policy_export)):
            result = verify_policy_backend_service_attestation(
                service_attestation,
                enforcement_receipt,
                policy_pack=policy_pack,
                action=action,
                proof_pack=proof_pack,
                decision=decision,
                policy_export=policy_export,
                policy_engine_receipt=policy_engine_receipt,
                key=key,
            )
            if not result.ok:
                errors.extend(f"policy backend worker service source: {error}" for error in result.errors)
            warnings.extend(f"policy backend worker service source: {warning}" for warning in result.warnings)
        else:
            warnings.append("policy backend worker source artifacts were not fully supplied; service source replay was not performed")
        _check_supplied_source_matches(receipt, service_attestation, enforcement_receipt, errors)

    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    execution = receipt.get("execution", {}) if isinstance(receipt.get("execution"), dict) else {}
    response_status = execution.get("response_status")
    response_success = isinstance(response_status, int) and 200 <= response_status < 300
    expected_success = not worker.get("error_ref") and response_success
    if isinstance(worker.get("success"), bool) and worker.get("success") is not expected_success:
        errors.append("policy backend worker success must match response status and error_ref")
    if isinstance(execution.get("response_accepted"), bool) and execution.get("response_accepted") is not response_success:
        errors.append("policy backend worker execution.response_accepted must match response_status")

    _check_no_secret_values(receipt, errors)
    return PolicyBackendWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_policy_backend_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    enforcement_receipt: dict[str, Any] | None = None,
    policy_pack: dict[str, Any] | None = None,
    action: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    policy_export: dict[str, Any] | None = None,
    policy_engine_receipt: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_policy_backend_worker_receipt(
        receipt,
        service_attestation=service_attestation,
        enforcement_receipt=enforcement_receipt,
        policy_pack=policy_pack,
        action=action,
        proof_pack=proof_pack,
        decision=decision,
        policy_export=policy_export,
        policy_engine_receipt=policy_engine_receipt,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid policy backend worker receipt: " + "; ".join(result.errors))
    payload = {
        "worker_operation_id": receipt["worker_operation_id"],
        "worker_operation_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "service": receipt.get("service"),
        "source_enforcement": receipt.get("source_enforcement"),
        "source": receipt.get("source"),
        "worker": receipt.get("worker"),
        "scheduler": receipt.get("scheduler"),
        "execution": receipt.get("execution"),
        "observability": receipt.get("observability"),
        "provider_exports": receipt.get("provider_exports"),
        "credential": receipt.get("credential"),
        "backend_credential": receipt.get("backend_credential"),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(POLICY_BACKEND_WORKER_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("recorded_at"))


def _service_record(attestation: dict[str, Any]) -> dict[str, Any]:
    service = attestation.get("service", {}) if isinstance(attestation.get("service"), dict) else {}
    operation = attestation.get("operation", {}) if isinstance(attestation.get("operation"), dict) else {}
    audit_log = attestation.get("audit_log", {}) if isinstance(attestation.get("audit_log"), dict) else {}
    credential = operation.get("credential", {}) if isinstance(operation.get("credential"), dict) else {}
    return {
        "attestation_id": attestation.get("attestation_id"),
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "service_ref": service.get("service_ref"),
        "service_version": service.get("version"),
        "engine": service.get("engine"),
        "backend_ref": service.get("backend_ref"),
        "endpoint_url": service.get("endpoint_url"),
        "service_image_digest": service.get("service_image_digest"),
        "service_binary_hash": service.get("service_binary_hash"),
        "bundle_ref": service.get("bundle_ref"),
        "bundle_hash": service.get("bundle_hash"),
        "decision_log_ref": operation.get("decision_log_ref"),
        "decision_log_root": operation.get("decision_log_root"),
        "operation_credential": _redacted_ref(credential.get("ref")),
        "audit_log_ref": audit_log.get("audit_log_ref"),
        "service_audit_log_root": audit_log.get("root"),
    }


def _enforcement_record(receipt: dict[str, Any]) -> dict[str, Any]:
    backend = receipt.get("backend", {}) if isinstance(receipt.get("backend"), dict) else {}
    decision = receipt.get("decision", {}) if isinstance(receipt.get("decision"), dict) else {}
    backend_decision = receipt.get("backend_decision", {}) if isinstance(receipt.get("backend_decision"), dict) else {}
    credential = receipt.get("credential", {}) if isinstance(receipt.get("credential"), dict) else {}
    return {
        "enforcement_id": receipt.get("enforcement_id"),
        "enforcement_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "enforced_at": receipt.get("enforced_at"),
        "backend_ref": backend.get("backend_ref"),
        "engine": backend.get("engine"),
        "endpoint_url": backend.get("endpoint_url"),
        "bundle_ref": backend.get("bundle_ref"),
        "bundle_hash": backend.get("bundle_hash"),
        "request_hash": backend.get("request_hash"),
        "response_status": backend.get("response_status"),
        "response_hash": backend.get("response_hash"),
        "backend_success": backend.get("success"),
        "backend_credential": _redacted_ref(credential.get("ref")),
        "decision_hash": decision.get("hash"),
        "decision_outcome": decision.get("outcome"),
        "decision_passed": decision.get("passed"),
        "backend_decision_outcome": backend_decision.get("outcome"),
        "backend_decision_allowed": backend_decision.get("allowed"),
    }


def _source_artifacts(*sources: Any) -> list[dict[str, Any]]:
    names = (
        "policy-backend-service-attestation",
        "policy-backend-enforcement",
        "policy-pack",
        "runtime-action",
        "proof-pack",
        "policy-decision",
        "policy-export",
        "policy-engine-receipt",
    )
    records: list[dict[str, Any]] = []
    for source_type, value in zip(names, sources):
        if value is not None:
            records.append({"type": source_type, "id": _source_id(value), "schema": value.get("schema") if isinstance(value, dict) else None, "hash": content_hash(value)})
    return records


def _source_summary(records: list[dict[str, Any]], service_attestation: dict[str, Any], enforcement_receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_count": len(records),
        "source_hash": content_hash(records),
        "schemas": sorted({str(record.get("schema")) for record in records if record.get("schema")}),
        "required_types": sorted(record["type"] for record in records),
        "service_attestation_id": service_attestation.get("attestation_id"),
        "service_attestation_hash": content_hash(service_attestation),
        "enforcement_id": enforcement_receipt.get("enforcement_id"),
        "enforcement_hash": content_hash(enforcement_receipt),
        "artifacts": records,
    }


def _provider_exports(**values: str | None) -> dict[str, Any]:
    groups = {
        "scheduler": ("scheduler_export_ref", "scheduler_export_hash"),
        "queue": ("queue_export_ref", "queue_export_hash"),
        "lease": ("lease_export_ref", "lease_export_hash"),
        "decision_log": ("decision_log_export_ref", "decision_log_export_hash"),
        "audit": ("audit_export_ref", "audit_export_hash"),
    }
    exports: dict[str, Any] = {}
    for name, (ref_key, hash_key) in groups.items():
        ref = values.get(ref_key)
        hash_value = values.get(hash_key)
        if ref or hash_value:
            exports[name] = {"ref": ref, "hash": hash_value}
    return exports


def _controls(
    *,
    service: dict[str, Any],
    enforcement: dict[str, Any],
    source_artifacts: list[dict[str, Any]],
    mode: str,
    cadence_seconds: int,
    checkpoint_hash: str,
    queue_message_hash: str,
    request_hash: str | None,
    response_hash: str | None,
    response_status: int,
    decision_log_root: str,
    audit_log_root: str,
    provider_exports: dict[str, Any],
    success: bool,
) -> list[dict[str, str]]:
    provider_export_names = {name for name, record in provider_exports.items() if isinstance(record, dict) and record.get("ref") and record.get("hash")}
    return [
        {
            "id": "policy-backend-service-source-replay",
            "status": "worker-recorded" if service.get("attestation_hash") and enforcement.get("enforcement_hash") and len(source_artifacts) >= 7 else "planned-production",
            "description": "Worker receipt is bound to policy backend service attestation, enforcement receipt, policy, action, proof-pack, decision, and export source hashes.",
        },
        {
            "id": "policy-backend-hosted-worker-mode",
            "status": "worker-recorded" if mode in {"scheduled-worker", "hosted-worker"} else "planned-production",
            "description": "Worker mode records scheduled or hosted OPA/Cedar backend operation intent.",
        },
        {
            "id": "policy-backend-scheduler-lease-checkpoint",
            "status": "worker-recorded" if cadence_seconds > 0 and _is_sha256_ref(checkpoint_hash) else "planned-production",
            "description": "Scheduler cadence, lease ownership, checkpoint reference, and checkpoint hash are bound.",
        },
        {
            "id": "policy-backend-queue-message",
            "status": "worker-recorded" if _is_sha256_ref(queue_message_hash) else "planned-production",
            "description": "Queue message reference and hash are bound to the worker operation.",
        },
        {
            "id": "policy-backend-request-response",
            "status": "worker-recorded" if _is_sha256_ref(str(request_hash or "")) and _is_sha256_ref(str(response_hash or "")) and 100 <= response_status <= 599 else "planned-production",
            "description": "OPA/Cedar backend request hash, response status, and response hash are bound.",
        },
        {
            "id": "policy-backend-decision-audit-roots",
            "status": "worker-recorded" if _is_sha256_ref(decision_log_root) and _is_sha256_ref(audit_log_root) else "planned-production",
            "description": "Decision-log and worker audit-log roots are bound.",
        },
        {
            "id": "policy-backend-provider-export-binding",
            "status": "worker-recorded" if {"scheduler", "queue", "lease", "decision_log", "audit"} <= provider_export_names else "local-reference",
            "description": "Provider-native scheduler, queue, lease, decision-log, and audit exports are hash-bound when supplied.",
        },
        {
            "id": "policy-backend-worker-success-recorded",
            "status": "worker-recorded" if success else "failed",
            "description": "Worker outcome is explicitly recorded.",
        },
    ]


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend worker service must be an object")
        return
    for field in ("attestation_id", "attestation_hash", "mode", "environment", "service_ref", "service_version", "engine", "backend_ref", "endpoint_url", "bundle_ref", "bundle_hash", "decision_log_ref", "decision_log_root", "audit_log_ref", "service_audit_log_root"):
        if value.get(field) in (None, ""):
            errors.append(f"policy backend worker service.{field} is required")
    for field in ("attestation_hash", "service_image_digest", "service_binary_hash", "bundle_hash", "decision_log_root", "service_audit_log_root"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"policy backend worker service.{field} must be a sha256 reference")
    _verify_redacted_ref(value.get("operation_credential"), "policy backend worker service.operation_credential", errors)


def _verify_source_enforcement(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend worker source_enforcement must be an object")
        return
    for field in ("enforcement_id", "enforcement_hash", "mode", "environment", "enforced_at", "backend_ref", "engine", "endpoint_url", "bundle_ref", "bundle_hash", "request_hash", "response_status", "response_hash", "decision_hash"):
        if value.get(field) in (None, ""):
            errors.append(f"policy backend worker source_enforcement.{field} is required")
    for field in ("enforcement_hash", "bundle_hash", "request_hash", "response_hash", "decision_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"policy backend worker source_enforcement.{field} must be a sha256 reference")
    status = value.get("response_status")
    if not isinstance(status, int) or status < 100 or status > 599:
        errors.append("policy backend worker source_enforcement.response_status must be an HTTP status code")
    _verify_redacted_ref(value.get("backend_credential"), "policy backend worker source_enforcement.backend_credential", errors)


def _verify_source(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend worker source must be an object")
        return
    if not isinstance(value.get("source_count"), int) or value.get("source_count") < 7:
        errors.append("policy backend worker source.source_count must include service, enforcement, policy, action, proof, decision, and export sources")
    if not _is_sha256_ref(str(value.get("source_hash") or "")):
        errors.append("policy backend worker source.source_hash must be a sha256 reference")
    required = value.get("required_types", [])
    for required_type in ("policy-backend-service-attestation", "policy-backend-enforcement", "policy-pack", "runtime-action", "proof-pack", "policy-decision", "policy-export"):
        if not isinstance(required, list) or required_type not in required:
            errors.append(f"policy backend worker source must include {required_type}")


def _verify_worker(value: Any, recorded: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend worker worker must be an object")
        return
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at", "attempt", "max_attempts", "success"):
        if value.get(field) in (None, ""):
            errors.append(f"policy backend worker worker.{field} is required")
    if value.get("operation_kind") not in POLICY_BACKEND_WORKER_OPERATION_KINDS:
        errors.append("policy backend worker worker.operation_kind is unsupported")
    try:
        started = parse_rfc3339(str(value.get("started_at") or ""))
        completed = parse_rfc3339(str(value.get("completed_at") or ""))
        if completed < started:
            errors.append("policy backend worker worker.completed_at must be at or after started_at")
        if recorded and completed != recorded:
            errors.append("policy backend worker recorded_at must equal worker.completed_at")
    except ValueError as exc:
        errors.append(f"policy backend worker worker timestamp invalid: {exc}")
    attempt = value.get("attempt")
    max_attempts = value.get("max_attempts")
    if not isinstance(attempt, int) or attempt < 1:
        errors.append("policy backend worker worker.attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < (attempt if isinstance(attempt, int) else 1):
        errors.append("policy backend worker worker.max_attempts must be greater than or equal to attempt")
    if not isinstance(value.get("success"), bool):
        errors.append("policy backend worker worker.success must be a boolean")
    if value.get("success") is False and not value.get("error_ref"):
        errors.append("policy backend worker worker.error_ref is required when success is false")


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend worker scheduler must be an object")
        return
    for field in ("schedule_ref", "lease_ref", "checkpoint_ref", "checkpoint_hash"):
        if not value.get(field):
            errors.append(f"policy backend worker scheduler.{field} is required")
    if not isinstance(value.get("cadence_seconds"), int) or value.get("cadence_seconds") <= 0:
        errors.append("policy backend worker scheduler.cadence_seconds must be positive")
    if value.get("checkpoint_hash") and not _is_sha256_ref(str(value.get("checkpoint_hash"))):
        errors.append("policy backend worker scheduler.checkpoint_hash must be a sha256 reference")
    if value.get("next_run_at"):
        try:
            parse_rfc3339(str(value.get("next_run_at")))
        except ValueError as exc:
            errors.append(f"policy backend worker scheduler.next_run_at invalid: {exc}")


def _verify_execution(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend worker execution must be an object")
        return
    for field in ("queue_ref", "queue_message_ref", "queue_message_hash", "backend_ref", "engine", "endpoint_url", "bundle_ref", "bundle_hash", "request_hash", "response_status", "response_hash", "response_accepted"):
        if value.get(field) in (None, ""):
            errors.append(f"policy backend worker execution.{field} is required")
    for field in ("queue_message_hash", "bundle_hash", "request_hash", "response_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"policy backend worker execution.{field} must be a sha256 reference")
    status = value.get("response_status")
    if not isinstance(status, int) or status < 100 or status > 599:
        errors.append("policy backend worker execution.response_status must be an HTTP status code")
    if not isinstance(value.get("response_accepted"), bool):
        errors.append("policy backend worker execution.response_accepted must be a boolean")


def _verify_observability(value: Any, recorded: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend worker observability must be an object")
        return
    for field in ("decision_log_ref", "decision_log_root", "metrics_ref", "audit_log_ref", "audit_log_root", "retention_until"):
        if not value.get(field):
            errors.append(f"policy backend worker observability.{field} is required")
    for field in ("decision_log_root", "decision_record_hash", "audit_log_root"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"policy backend worker observability.{field} must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if recorded and retention <= recorded:
            errors.append("policy backend worker observability.retention_until must be after recorded_at")
    except ValueError as exc:
        errors.append(f"policy backend worker observability.retention_until invalid: {exc}")
    if not isinstance(value.get("evidence_refs", []), list):
        errors.append("policy backend worker observability.evidence_refs must be a list")


def _verify_provider_exports(value: Any, errors: list[str]) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        errors.append("policy backend worker provider_exports must be an object")
        return
    for name, record in value.items():
        if name not in {"scheduler", "queue", "lease", "decision_log", "audit"}:
            errors.append(f"policy backend worker provider_exports.{name} is unsupported")
            continue
        if not isinstance(record, dict):
            errors.append(f"policy backend worker provider_exports.{name} must be an object")
            continue
        if not record.get("ref") or not record.get("hash"):
            errors.append(f"policy backend worker provider_exports.{name} ref and hash are required")
        elif not _is_sha256_ref(str(record.get("hash"))):
            errors.append(f"policy backend worker provider_exports.{name}.hash must be a sha256 reference")


def _verify_source_artifacts(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append("policy backend worker source_artifacts must be a non-empty list")
        return
    required = {"policy-backend-service-attestation", "policy-backend-enforcement", "policy-pack", "runtime-action", "proof-pack", "policy-decision", "policy-export"}
    actual = {item.get("type") for item in value if isinstance(item, dict)}
    missing = sorted(required - actual)
    if missing:
        errors.append("policy backend worker source_artifacts missing: " + ", ".join(missing))
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"policy backend worker source_artifacts[{index}] must be an object")
            continue
        if not item.get("type") or not item.get("hash"):
            errors.append(f"policy backend worker source_artifacts[{index}] type and hash are required")
        elif not _is_sha256_ref(str(item.get("hash"))):
            errors.append(f"policy backend worker source_artifacts[{index}].hash must be a sha256 reference")


def _check_supplied_source_matches(receipt: dict[str, Any], service_attestation: dict[str, Any], enforcement_receipt: dict[str, Any], errors: list[str]) -> None:
    expected_service = _service_record(service_attestation)
    if receipt.get("service") != expected_service:
        errors.append("policy backend worker service record does not match supplied service attestation")
    expected_enforcement = _enforcement_record(enforcement_receipt)
    if receipt.get("source_enforcement") != expected_enforcement:
        errors.append("policy backend worker source_enforcement record does not match supplied enforcement receipt")
    execution = receipt.get("execution", {}) if isinstance(receipt.get("execution"), dict) else {}
    for execution_field, enforcement_field in (
        ("backend_ref", "backend_ref"),
        ("engine", "engine"),
        ("endpoint_url", "endpoint_url"),
        ("bundle_ref", "bundle_ref"),
        ("bundle_hash", "bundle_hash"),
        ("request_hash", "request_hash"),
        ("response_status", "response_status"),
        ("response_hash", "response_hash"),
    ):
        if execution.get(execution_field) != expected_enforcement.get(enforcement_field):
            errors.append(f"policy backend worker execution.{execution_field} does not match enforcement {enforcement_field}")


def _compare_source_hash(receipt: dict[str, Any], source_type: str, value: Any, errors: list[str]) -> None:
    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("policy backend worker source_artifacts must be a list")
        return
    actual = content_hash(value)
    if not any(isinstance(item, dict) and item.get("type") == source_type and item.get("hash") == actual for item in artifacts):
        errors.append(f"policy backend worker source artifact hash mismatch: {source_type}")


def _source_id(value: Any) -> Any:
    if not isinstance(value, dict):
        return None
    for key_name in ("attestation_id", "enforcement_id", "receipt_id", "pack_id", "policy_pack_id", "entry_id", "id", "schema"):
        if value.get(key_name):
            return value.get(key_name)
    return value.get("schema")


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"policy backend worker {field} is required")


def _is_sha256_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value[7:])
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(lowered, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"policy backend worker secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if value is None:
        return True
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        return True
    if (key.endswith("_root") or key.endswith("_hash")) and isinstance(value, str) and value.startswith("sha256:"):
        return True
    return False
