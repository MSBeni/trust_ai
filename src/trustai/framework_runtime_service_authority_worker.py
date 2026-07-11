from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_runtime_service_authority import verify_framework_runtime_service_authority_dossier

FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_SCHEMA = "trustai.framework-runtime-service-authority-worker/0.1"
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_ENTRY_TYPE = "framework_runtime.service_authority_worker_recorded"
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_MODES = {
    "local-reference",
    "scheduled-worker",
    "hosted-worker",
    "production-design",
}
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_OPERATION_KINDS = {
    "authority_evidence_refresh",
    "authority_dossier_reconcile",
    "freshness_recheck",
    "production_gap_alert",
    "provider_authority_reconcile",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")
AUTHORITY_BINDING_EXPECTED_FIELDS = (
    "dossier_id",
    "dossier_hash",
    "schema",
    "mode",
    "environment",
    "generated_at",
    "dossier_ref",
    "authority_ref",
    "producer_ref",
    "provider_receipt_id",
    "provider_receipt_hash",
    "service_worker_operation_id",
    "authority_evidence_count",
    "covered_requirement_count",
    "missing_requirement_count",
    "freshness_window_count",
    "status",
)
AUTHORITY_BINDING_REQUIRED_FIELDS = AUTHORITY_BINDING_EXPECTED_FIELDS
AUTHORITY_BINDING_COUNT_FIELDS = (
    "authority_evidence_count",
    "covered_requirement_count",
    "missing_requirement_count",
    "freshness_window_count",
)
SOURCE_ARTIFACT_KINDS = (
    "framework-runtime-service-authority-dossier",
    "framework-runtime-service-provider-receipt",
    "framework-runtime-service-provider-export",
    "framework-runtime-service-worker",
    "framework-runtime-service-attestation",
    "framework-runtime-storage-receipt",
    "framework-runtime-storage-export",
    "framework-runtime-worker",
    "framework-runtime-audit-receipt",
    "framework-runtime-audit-export",
    "framework-hook-operation",
    "framework-trace-payload",
    "framework-hook-release",
    "framework-adapter-matrix",
)


@dataclass
class FrameworkRuntimeServiceAuthorityWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_runtime_service_authority_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime service authority worker receipt must contain an object")
    return value


def write_framework_runtime_service_authority_worker_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_runtime_service_authority_worker_receipt(
    authority_dossier: dict[str, Any],
    *,
    provider_receipt: dict[str, Any],
    provider_export: dict[str, Any],
    service_worker: dict[str, Any],
    service_attestation: dict[str, Any],
    storage_receipt: dict[str, Any],
    storage_export: dict[str, Any],
    worker: dict[str, Any],
    runtime_audit: dict[str, Any],
    audit_export: dict[str, Any],
    operation: dict[str, Any],
    trace_payload: dict[str, Any],
    release: dict[str, Any],
    matrix: dict[str, Any],
    root: str | Path = ".",
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
    checkpoint_hash: str,
    previous_cursor_ref: str | None = None,
    next_cursor_ref: str | None = None,
    attempt: int = 1,
    max_attempts: int = 3,
    queue_ref: str,
    queue_message_ref: str,
    queue_message_hash: str,
    dead_letter_queue_ref: str | None = None,
    authority_request_ref: str,
    dossier_storage_ref: str,
    dossier_storage_hash: str,
    report_storage_ref: str | None = None,
    report_storage_hash: str | None = None,
    request_hash: str | None = None,
    response_status: int | None = None,
    response_hash: str | None = None,
    metrics_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    started_at: str,
    completed_at: str | None = None,
    next_run_at: str | None = None,
    error_ref: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_MODES:
        raise ValueError(f"mode must be one of {sorted(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_MODES)}")
    if operation_kind not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_OPERATION_KINDS:
        raise ValueError(f"operation_kind must be one of {sorted(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_OPERATION_KINDS)}")
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
    if response_status is not None and (not isinstance(response_status, int) or response_status < 100 or response_status > 599):
        raise ValueError("response_status must be an HTTP status code")
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
        (authority_request_ref, "authority_request_ref"),
        (dossier_storage_ref, "dossier_storage_ref"),
        (dossier_storage_hash, "dossier_storage_hash"),
        (metrics_ref, "metrics_ref"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (retention_until, "retention_until"),
        (credential_ref, "credential_ref"),
        (started_at, "started_at"),
    ):
        _require_text(value, field)
    for field, value in (
        ("checkpoint_hash", checkpoint_hash),
        ("queue_message_hash", queue_message_hash),
        ("dossier_storage_hash", dossier_storage_hash),
        ("report_storage_hash", report_storage_hash),
        ("request_hash", request_hash),
        ("response_hash", response_hash),
        ("audit_log_root", audit_log_root),
    ):
        if value and not _is_sha256_ref(str(value)):
            raise ValueError(f"{field} must be a sha256 reference")
    if dossier_storage_hash != content_hash(authority_dossier):
        raise ValueError("dossier_storage_hash must match the supplied authority dossier hash")

    dossier_result = verify_framework_runtime_service_authority_dossier(
        authority_dossier,
        provider_receipt=provider_receipt,
        provider_export=provider_export,
        service_worker=service_worker,
        service_attestation=service_attestation,
        storage_receipt=storage_receipt,
        storage_export=storage_export,
        worker=worker,
        runtime_audit=runtime_audit,
        audit_export=audit_export,
        operation=operation,
        trace_payload=trace_payload,
        release=release,
        matrix=matrix,
        root=root,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=completed,
    )
    if not dossier_result.ok:
        raise ValueError("invalid framework runtime service authority source: " + "; ".join(dossier_result.errors))

    authority = _authority_record(authority_dossier)
    execution = _execution_record(
        authority_dossier,
        queue_ref=queue_ref,
        queue_message_ref=queue_message_ref,
        queue_message_hash=queue_message_hash,
        dead_letter_queue_ref=dead_letter_queue_ref,
        authority_request_ref=authority_request_ref,
        dossier_storage_ref=dossier_storage_ref,
        dossier_storage_hash=dossier_storage_hash,
        report_storage_ref=report_storage_ref,
        report_storage_hash=report_storage_hash,
        request_hash=request_hash,
        response_status=response_status,
        response_hash=response_hash,
    )
    success = not error_ref and (response_status is None or 200 <= response_status < 300)
    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": completed,
        "authority": authority,
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
        "execution": execution,
        "observability": {
            "metrics_ref": metrics_ref,
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "retention_until": retention_until,
        },
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": evidence_refs or [],
        "require_complete": require_complete,
        "require_fresh": require_fresh,
        "source_artifacts": _source_artifacts(
            authority_dossier,
            provider_receipt,
            provider_export,
            service_worker,
            service_attestation,
            storage_receipt,
            storage_export,
            worker,
            runtime_audit,
            audit_export,
            operation,
            trace_payload,
            release,
            matrix,
        ),
        "controls": _controls(authority_dossier, execution, success, require_complete, require_fresh),
        "limitations": [
            "This receipt records a scheduled framework runtime service authority refresh worker operation.",
            "It binds worker storage, queue, request/response, metrics, audit, and authority dossier hashes; it does not fetch live provider APIs by itself.",
            "It does not prove continuously operated production infrastructure unless paired with live scheduler, queue, storage, and immutable audit exports from the operating environment.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [
            sign_value(
                {"worker_operation_id": worker_operation_id, "framework_runtime_service_authority_worker": body},
                key,
            )
        ],
    }


def verify_framework_runtime_service_authority_worker_receipt(
    receipt: dict[str, Any],
    *,
    authority_dossier: dict[str, Any] | None = None,
    provider_receipt: dict[str, Any] | None = None,
    provider_export: dict[str, Any] | None = None,
    service_worker: dict[str, Any] | None = None,
    service_attestation: dict[str, Any] | None = None,
    storage_receipt: dict[str, Any] | None = None,
    storage_export: dict[str, Any] | None = None,
    worker: dict[str, Any] | None = None,
    runtime_audit: dict[str, Any] | None = None,
    audit_export: dict[str, Any] | None = None,
    operation: dict[str, Any] | None = None,
    trace_payload: dict[str, Any] | None = None,
    release: dict[str, Any] | None = None,
    matrix: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool | None = None,
    require_fresh: bool | None = None,
    now: str | None = None,
) -> FrameworkRuntimeServiceAuthorityWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if receipt.get("schema") != FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_SCHEMA:
        errors.append(f"unsupported framework runtime service authority worker schema: {receipt.get('schema')}")
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append("worker_operation_id does not match canonical framework runtime service authority worker body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime service authority worker receipt must include at least one signature")
    else:
        signed_value = {
            "worker_operation_id": receipt.get("worker_operation_id"),
            "framework_runtime_service_authority_worker": body,
        }
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime service authority worker signature verification failed")

    recorded = _parse_required_timestamp(receipt.get("recorded_at"), "recorded_at", errors)
    mode = receipt.get("mode")
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_MODES:
        errors.append("framework runtime service authority worker mode is unsupported")
    elif mode != "hosted-worker":
        warnings.append(f"framework runtime service authority worker mode is {mode}; continuously hosted worker operation is not claimed")
    _verify_authority(receipt.get("authority"), errors)
    _verify_worker(receipt.get("worker"), errors)
    _verify_scheduler(receipt.get("scheduler"), errors)
    _verify_execution(receipt.get("execution"), errors)
    _verify_observability(receipt.get("observability"), recorded, errors)
    _verify_redacted_ref(receipt.get("credential"), "framework runtime service authority worker credential", errors)
    _verify_source_artifacts(receipt.get("source_artifacts"), errors)

    effective_require_complete = receipt.get("require_complete") if require_complete is None else require_complete
    effective_require_fresh = receipt.get("require_fresh") if require_fresh is None else require_fresh
    if not isinstance(effective_require_complete, bool):
        errors.append("framework runtime service authority worker require_complete must be boolean")
        effective_require_complete = False
    if not isinstance(effective_require_fresh, bool):
        errors.append("framework runtime service authority worker require_fresh must be boolean")
        effective_require_fresh = False
    if authority_dossier is None:
        warnings.append("framework runtime service authority worker authority dossier artifact was not supplied; source was not replayed")
    else:
        expected_authority = _authority_record(authority_dossier)
        if receipt.get("authority") != expected_authority:
            errors.append("framework runtime service authority worker authority binding does not match supplied authority dossier")
        expected_execution = receipt.get("execution", {})
        if isinstance(expected_execution, dict):
            if expected_execution.get("authority_evidence_root") != content_hash(authority_dossier.get("authority_evidence", [])):
                errors.append("framework runtime service authority worker authority_evidence_root does not match supplied authority dossier")
            if expected_execution.get("missing_requirement_root") != content_hash(authority_dossier.get("summary", {}).get("missing_requirement_ids", [])):
                errors.append("framework runtime service authority worker missing_requirement_root does not match supplied authority dossier")
            if expected_execution.get("dossier_storage_hash") != content_hash(authority_dossier):
                errors.append("framework runtime service authority worker dossier_storage_hash does not match supplied authority dossier")
        if provider_receipt is None:
            warnings.append("framework runtime service authority worker provider receipt artifact was not supplied; authority source was not fully replayed")
        else:
            result = verify_framework_runtime_service_authority_dossier(
                authority_dossier,
                provider_receipt=provider_receipt,
                provider_export=provider_export,
                service_worker=service_worker,
                service_attestation=service_attestation,
                storage_receipt=storage_receipt,
                storage_export=storage_export,
                worker=worker,
                runtime_audit=runtime_audit,
                audit_export=audit_export,
                operation=operation,
                trace_payload=trace_payload,
                release=release,
                matrix=matrix,
                root=root,
                key=key,
                require_complete=effective_require_complete,
                require_fresh=effective_require_fresh,
                now=now or receipt.get("recorded_at"),
            )
            if not result.ok:
                errors.extend(f"framework runtime service authority worker source: {error}" for error in result.errors)
            warnings.extend(f"framework runtime service authority worker source: {warning}" for warning in result.warnings)
    _compare_source_hash(receipt, "framework-runtime-service-authority-dossier", authority_dossier, errors)
    _compare_source_hash(receipt, "framework-runtime-service-provider-receipt", provider_receipt, errors)
    _compare_source_hash(receipt, "framework-runtime-service-provider-export", provider_export, errors)
    _compare_source_hash(receipt, "framework-runtime-service-worker", service_worker, errors)
    _compare_source_hash(receipt, "framework-runtime-service-attestation", service_attestation, errors)
    _compare_source_hash(receipt, "framework-runtime-storage-receipt", storage_receipt, errors)
    _compare_source_hash(receipt, "framework-runtime-storage-export", storage_export, errors)
    _compare_source_hash(receipt, "framework-runtime-worker", worker, errors)
    _compare_source_hash(receipt, "framework-runtime-audit-receipt", runtime_audit, errors)
    _compare_source_hash(receipt, "framework-runtime-audit-export", audit_export, errors)
    _compare_source_hash(receipt, "framework-hook-operation", operation, errors)
    _compare_source_hash(receipt, "framework-trace-payload", trace_payload, errors)
    _compare_source_hash(receipt, "framework-hook-release", release, errors)
    _compare_source_hash(receipt, "framework-adapter-matrix", matrix, errors)
    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("framework runtime service authority worker controls are required")
    _check_no_secret_values(receipt, errors)
    return FrameworkRuntimeServiceAuthorityWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_runtime_service_authority_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    authority_dossier: dict[str, Any],
    provider_receipt: dict[str, Any],
    provider_export: dict[str, Any],
    service_worker: dict[str, Any],
    service_attestation: dict[str, Any],
    storage_receipt: dict[str, Any],
    storage_export: dict[str, Any],
    worker: dict[str, Any],
    runtime_audit: dict[str, Any],
    audit_export: dict[str, Any],
    operation: dict[str, Any],
    trace_payload: dict[str, Any],
    release: dict[str, Any],
    matrix: dict[str, Any],
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool | None = None,
    require_fresh: bool | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_framework_runtime_service_authority_worker_receipt(
        receipt,
        authority_dossier=authority_dossier,
        provider_receipt=provider_receipt,
        provider_export=provider_export,
        service_worker=service_worker,
        service_attestation=service_attestation,
        storage_receipt=storage_receipt,
        storage_export=storage_export,
        worker=worker,
        runtime_audit=runtime_audit,
        audit_export=audit_export,
        operation=operation,
        trace_payload=trace_payload,
        release=release,
        matrix=matrix,
        root=root,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid framework runtime service authority worker receipt: " + "; ".join(result.errors))
    payload = {
        "worker_operation_id": receipt["worker_operation_id"],
        "worker_operation_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "authority": receipt.get("authority"),
        "worker": receipt.get("worker"),
        "scheduler": receipt.get("scheduler"),
        "execution": receipt.get("execution"),
        "observability": receipt.get("observability"),
        "credential": receipt.get("credential"),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(
        FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_ENTRY_TYPE,
        payload,
        key=key,
        timestamp=receipt.get("recorded_at"),
    )


def _authority_record(dossier: dict[str, Any]) -> dict[str, Any]:
    summary = dossier.get("summary", {}) if isinstance(dossier.get("summary"), dict) else {}
    provider = dossier.get("provider_receipt_binding", {}) if isinstance(dossier.get("provider_receipt_binding"), dict) else {}
    return {
        "dossier_id": dossier.get("dossier_id"),
        "dossier_hash": content_hash(dossier),
        "schema": dossier.get("schema"),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "provider_receipt_id": provider.get("provider_receipt_id"),
        "provider_receipt_hash": provider.get("provider_receipt_hash"),
        "service_worker_operation_id": provider.get("service_worker_operation_id"),
        "authority_evidence_count": summary.get("evidence_count"),
        "covered_requirement_count": summary.get("covered_requirement_count"),
        "missing_requirement_count": summary.get("missing_requirement_count"),
        "freshness_window_count": summary.get("freshness_window_count"),
        "status": summary.get("status"),
    }


def _execution_record(authority_dossier: dict[str, Any], **values: Any) -> dict[str, Any]:
    summary = authority_dossier.get("summary", {}) if isinstance(authority_dossier.get("summary"), dict) else {}
    return {
        **values,
        "authority_evidence_root": content_hash(authority_dossier.get("authority_evidence", [])),
        "missing_requirement_root": content_hash(summary.get("missing_requirement_ids", [])),
        "dossier_summary_hash": content_hash(summary),
    }


def _source_artifacts(*artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"kind": name, "hash": content_hash(artifact)}
        for name, artifact in zip(SOURCE_ARTIFACT_KINDS, artifacts)
        if isinstance(artifact, dict)
    ]


def _controls(
    authority_dossier: dict[str, Any],
    execution: dict[str, Any],
    success: bool,
    require_complete: bool,
    require_fresh: bool,
) -> list[dict[str, Any]]:
    summary = authority_dossier.get("summary", {}) if isinstance(authority_dossier.get("summary"), dict) else {}
    complete = summary.get("missing_requirement_count") == 0
    evidence_count = summary.get("evidence_count") or 0
    freshness_complete = evidence_count > 0 and summary.get("freshness_window_count") == evidence_count
    return [
        {
            "name": "authority_source_replayed",
            "status": "passed",
            "detail": "The worker builder replayed the authority dossier and provider/source chain.",
        },
        {
            "name": "worker_operation_succeeded",
            "status": "passed" if success else "failed",
            "detail": "The authority refresh worker completed without error and with a successful response status.",
        },
        {
            "name": "authority_outputs_stored",
            "status": "passed" if execution.get("dossier_storage_hash") == content_hash(authority_dossier) else "failed",
            "detail": "The worker output binds the stored authority dossier hash.",
        },
        {
            "name": "authority_evidence_refreshed",
            "status": "passed" if evidence_count > 0 else "deferred",
            "detail": "At least one authority evidence item is present in the refreshed dossier.",
        },
        {
            "name": "freshness_windows_enforced",
            "status": "passed" if require_fresh and freshness_complete else "deferred",
            "detail": "Freshness windows are enforced when the worker runs with require_fresh.",
        },
        {
            "name": "complete_live_authority",
            "status": "passed" if require_complete and complete else "deferred",
            "detail": "Every production authority requirement must be covered before live authority is complete.",
        },
    ]


def _verify_authority(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority worker authority must be an object")
        return
    for field in AUTHORITY_BINDING_EXPECTED_FIELDS:
        if field not in value:
            errors.append(f"framework runtime service authority worker authority.{field} is required")
    for field in AUTHORITY_BINDING_REQUIRED_FIELDS:
        if value.get(field) in (None, "", [], {}):
            errors.append(f"framework runtime service authority worker authority.{field} is required")
    for field in AUTHORITY_BINDING_COUNT_FIELDS:
        if not isinstance(value.get(field), int) or value.get(field) < 0:
            errors.append(f"framework runtime service authority worker authority.{field} must be non-negative")
    if not isinstance(value.get("authority_evidence_count"), int) or value.get("authority_evidence_count") <= 0:
        errors.append("framework runtime service authority worker authority.authority_evidence_count must be positive")
    for field in ("generated_at",):
        _parse_required_timestamp(value.get(field), f"authority.{field}", errors)


def _verify_worker(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority worker worker must be an object")
        return
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at"):
        if not value.get(field):
            errors.append(f"framework runtime service authority worker worker.{field} is required")
    if value.get("operation_kind") not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_OPERATION_KINDS:
        errors.append("framework runtime service authority worker operation_kind is unsupported")
    started = _parse_required_timestamp(value.get("started_at"), "worker.started_at", errors)
    completed = _parse_required_timestamp(value.get("completed_at"), "worker.completed_at", errors)
    if started and completed and completed < started:
        errors.append("framework runtime service authority worker completed_at is before started_at")
    if not isinstance(value.get("attempt"), int) or value.get("attempt") < 1:
        errors.append("framework runtime service authority worker attempt must be a positive integer")
    if not isinstance(value.get("max_attempts"), int) or value.get("max_attempts") < value.get("attempt", 0):
        errors.append("framework runtime service authority worker max_attempts must be greater than or equal to attempt")


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority worker scheduler must be an object")
        return
    for field in ("schedule_ref", "lease_ref", "checkpoint_ref", "checkpoint_hash"):
        if not value.get(field):
            errors.append(f"framework runtime service authority worker scheduler.{field} is required")
    if not isinstance(value.get("cadence_seconds"), int) or value.get("cadence_seconds") <= 0:
        errors.append("framework runtime service authority worker scheduler.cadence_seconds must be positive")
    if value.get("checkpoint_hash") and not _is_sha256_ref(str(value.get("checkpoint_hash"))):
        errors.append("framework runtime service authority worker scheduler.checkpoint_hash must be a sha256 reference")
    if value.get("next_run_at"):
        _parse_required_timestamp(value.get("next_run_at"), "scheduler.next_run_at", errors)


def _verify_execution(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority worker execution must be an object")
        return
    for field in (
        "queue_ref",
        "queue_message_ref",
        "queue_message_hash",
        "authority_request_ref",
        "dossier_storage_ref",
        "dossier_storage_hash",
        "authority_evidence_root",
        "missing_requirement_root",
        "dossier_summary_hash",
    ):
        if not value.get(field):
            errors.append(f"framework runtime service authority worker execution.{field} is required")
    for field in (
        "queue_message_hash",
        "dossier_storage_hash",
        "report_storage_hash",
        "request_hash",
        "response_hash",
        "authority_evidence_root",
        "missing_requirement_root",
        "dossier_summary_hash",
    ):
        field_value = value.get(field)
        if field_value and not _is_sha256_ref(str(field_value)):
            errors.append(f"framework runtime service authority worker execution.{field} must be a sha256 reference")
    if value.get("response_status") is not None and (not isinstance(value.get("response_status"), int) or value.get("response_status") < 100 or value.get("response_status") > 599):
        errors.append("framework runtime service authority worker execution.response_status must be an HTTP status code")


def _verify_observability(value: Any, recorded: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority worker observability must be an object")
        return
    for field in ("metrics_ref", "audit_log_ref", "audit_log_root", "retention_until"):
        if not value.get(field):
            errors.append(f"framework runtime service authority worker observability.{field} is required")
    if value.get("audit_log_root") and not _is_sha256_ref(str(value.get("audit_log_root"))):
        errors.append("framework runtime service authority worker observability.audit_log_root must be a sha256 reference")
    retention = _parse_required_timestamp(value.get("retention_until"), "observability.retention_until", errors)
    if recorded and retention and retention <= recorded:
        errors.append("framework runtime service authority worker retention_until must be after recorded_at")


def _verify_source_artifacts(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append("framework runtime service authority worker source_artifacts are required")
        return
    actual_kinds: set[str] = set()
    duplicate_kinds: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"framework runtime service authority worker source_artifacts[{index}] must be an object")
            continue
        kind = item.get("kind")
        if not kind:
            errors.append(f"framework runtime service authority worker source_artifacts[{index}].kind is required")
        elif not isinstance(kind, str):
            errors.append(f"framework runtime service authority worker source_artifacts[{index}].kind must be a string")
        else:
            if kind in actual_kinds:
                duplicate_kinds.add(kind)
            actual_kinds.add(kind)
        if not item.get("hash") or not _is_sha256_ref(str(item.get("hash"))):
            errors.append(f"framework runtime service authority worker source_artifacts[{index}].hash must be a sha256 reference")
    expected_kinds = set(SOURCE_ARTIFACT_KINDS)
    missing = sorted(expected_kinds - actual_kinds)
    extra = sorted(actual_kinds - expected_kinds)
    if missing:
        errors.append("framework runtime service authority worker source_artifacts missing: " + ", ".join(missing))
    if extra:
        errors.append("framework runtime service authority worker source_artifacts unsupported: " + ", ".join(extra))
    if duplicate_kinds:
        errors.append("framework runtime service authority worker source_artifacts duplicate: " + ", ".join(sorted(duplicate_kinds)))


def _compare_source_hash(receipt: dict[str, Any], kind: str, artifact: dict[str, Any] | None, errors: list[str]) -> None:
    if artifact is None:
        return
    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        return
    expected = content_hash(artifact)
    for item in artifacts:
        if isinstance(item, dict) and item.get("kind") == kind:
            if item.get("hash") != expected:
                errors.append(f"framework runtime service authority worker source artifact hash mismatch: {kind}")
            return
    errors.append(f"framework runtime service authority worker source artifact missing: {kind}")


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


def _parse_required_timestamp(value: Any, field: str, errors: list[str]) -> Any:
    if not value:
        errors.append(f"framework runtime service authority worker {field} is required")
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"framework runtime service authority worker {field} invalid: {exc}")
        return None


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"framework runtime service authority worker {field} is required")


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
                    errors.append(f"framework runtime service authority worker secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        return True
    return False
