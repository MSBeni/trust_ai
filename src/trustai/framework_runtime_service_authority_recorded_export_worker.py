from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_runtime_service_authority_recorded_export import verify_framework_runtime_service_authority_recorded_export

FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_SCHEMA = (
    "trustai.framework-runtime-service-authority-recorded-export-worker/0.1"
)
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_ENTRY_TYPE = (
    "framework_runtime.service_authority_recorded_export_worker_recorded"
)
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_MODES = {
    "local-worker",
    "scheduled-worker",
    "hosted-worker",
    "production-worker",
}
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_OPERATION_KINDS = {
    "recorded_export_capture",
    "recorded_export_replay",
    "artifact_retention_refresh",
    "provider_export_archive",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")
RECORDED_EXPORT_BINDING_EXPECTED_FIELDS = (
    "recorded_export_id",
    "recorded_export_hash",
    "schema",
    "mode",
    "environment",
    "recorded_at",
    "attestation_id",
    "attestation_hash",
    "dossier_id",
    "dossier_hash",
    "authority_ref",
    "artifact_count",
    "artifact_root",
    "artifact_sha256_root",
    "artifact_content_root",
    "retention_until",
)
RECORDED_EXPORT_BINDING_REQUIRED_FIELDS = RECORDED_EXPORT_BINDING_EXPECTED_FIELDS
SOURCE_ARTIFACT_KINDS = (
    "framework-runtime-service-authority-recorded-export",
    "framework-runtime-service-authority-attestation",
    "framework-runtime-service-authority-provider-receipt",
    "framework-runtime-service-authority-provider-export",
    "framework-runtime-service-authority-worker",
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
class FrameworkRuntimeServiceAuthorityRecordedExportWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_runtime_service_authority_recorded_export_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime service authority recorded export worker receipt must contain an object")
    return value


def write_framework_runtime_service_authority_recorded_export_worker_receipt(
    path: str | Path, receipt: dict[str, Any]
) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_runtime_service_authority_recorded_export_worker_receipt(
    recorded_export: dict[str, Any],
    *,
    authority_attestation: dict[str, Any],
    authority_provider_receipt: dict[str, Any],
    authority_provider_export: dict[str, Any],
    authority_worker: dict[str, Any],
    authority_dossier: dict[str, Any],
    service_provider_receipt: dict[str, Any],
    service_provider_export: dict[str, Any],
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
    artifact_paths: dict[str, str | Path],
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
    recorded_export_ref: str,
    recorded_export_storage_ref: str,
    recorded_export_storage_hash: str,
    artifact_archive_ref: str,
    artifact_archive_hash: str,
    artifact_manifest_ref: str,
    artifact_manifest_hash: str,
    storage_write_ref: str,
    storage_write_hash: str,
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
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_MODES:
        raise ValueError(
            "mode must be one of "
            f"{sorted(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_MODES)}"
        )
    if operation_kind not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_OPERATION_KINDS:
        raise ValueError(
            "operation_kind must be one of "
            f"{sorted(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_OPERATION_KINDS)}"
        )
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
    if response_status is not None and (
        not isinstance(response_status, int) or response_status < 100 or response_status > 599
    ):
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
        (recorded_export_ref, "recorded_export_ref"),
        (recorded_export_storage_ref, "recorded_export_storage_ref"),
        (recorded_export_storage_hash, "recorded_export_storage_hash"),
        (artifact_archive_ref, "artifact_archive_ref"),
        (artifact_archive_hash, "artifact_archive_hash"),
        (artifact_manifest_ref, "artifact_manifest_ref"),
        (artifact_manifest_hash, "artifact_manifest_hash"),
        (storage_write_ref, "storage_write_ref"),
        (storage_write_hash, "storage_write_hash"),
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
        ("recorded_export_storage_hash", recorded_export_storage_hash),
        ("artifact_archive_hash", artifact_archive_hash),
        ("artifact_manifest_hash", artifact_manifest_hash),
        ("storage_write_hash", storage_write_hash),
        ("request_hash", request_hash),
        ("response_hash", response_hash),
        ("audit_log_root", audit_log_root),
    ):
        if value and not _is_sha256_ref(str(value)):
            raise ValueError(f"{field} must be a sha256 reference")
    if recorded_export_storage_hash != content_hash(recorded_export):
        raise ValueError("recorded_export_storage_hash must match the supplied recorded export hash")
    if artifact_manifest_hash != content_hash(recorded_export.get("recorded_artifacts", {})):
        raise ValueError("artifact_manifest_hash must match the recorded export artifact manifest hash")

    source_result = verify_framework_runtime_service_authority_recorded_export(
        recorded_export,
        authority_attestation=authority_attestation,
        authority_provider_receipt=authority_provider_receipt,
        authority_provider_export=authority_provider_export,
        authority_worker=authority_worker,
        authority_dossier=authority_dossier,
        service_provider_receipt=service_provider_receipt,
        service_provider_export=service_provider_export,
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
        artifact_paths=artifact_paths,
        root=root,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=completed,
    )
    if not source_result.ok:
        raise ValueError(
            "invalid framework runtime service authority recorded export source: "
            + "; ".join(source_result.errors)
        )

    binding = _recorded_export_binding(recorded_export)
    execution = _execution_record(
        recorded_export,
        queue_ref=queue_ref,
        queue_message_ref=queue_message_ref,
        queue_message_hash=queue_message_hash,
        dead_letter_queue_ref=dead_letter_queue_ref,
        recorded_export_ref=recorded_export_ref,
        recorded_export_storage_ref=recorded_export_storage_ref,
        recorded_export_storage_hash=recorded_export_storage_hash,
        artifact_archive_ref=artifact_archive_ref,
        artifact_archive_hash=artifact_archive_hash,
        artifact_manifest_ref=artifact_manifest_ref,
        artifact_manifest_hash=artifact_manifest_hash,
        storage_write_ref=storage_write_ref,
        storage_write_hash=storage_write_hash,
        request_hash=request_hash,
        response_status=response_status,
        response_hash=response_hash,
    )
    success = not error_ref and (response_status is None or 200 <= response_status < 300)
    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": completed,
        "recorded_export": binding,
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
            recorded_export,
            authority_attestation,
            authority_provider_receipt,
            authority_provider_export,
            authority_worker,
            authority_dossier,
            service_provider_receipt,
            service_provider_export,
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
        "controls": _controls(mode, recorded_export, execution, success),
        "limitations": [
            "This receipt records a scheduled framework runtime service authority recorded-export worker operation.",
            "It binds worker queue, scheduler, archive, storage write, request/response, metrics, and audit evidence to the recorded-export source.",
            "It does not prove continuously operated production infrastructure unless mode is production-worker and the source recorded export is production-recorded-export with live provider-owned evidence.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [
            sign_value(
                {
                    "worker_operation_id": worker_operation_id,
                    "framework_runtime_service_authority_recorded_export_worker": body,
                },
                key,
            )
        ],
    }


def verify_framework_runtime_service_authority_recorded_export_worker_receipt(
    receipt: dict[str, Any],
    *,
    recorded_export: dict[str, Any] | None = None,
    authority_attestation: dict[str, Any] | None = None,
    authority_provider_receipt: dict[str, Any] | None = None,
    authority_provider_export: dict[str, Any] | None = None,
    authority_worker: dict[str, Any] | None = None,
    authority_dossier: dict[str, Any] | None = None,
    service_provider_receipt: dict[str, Any] | None = None,
    service_provider_export: dict[str, Any] | None = None,
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
    artifact_paths: dict[str, str | Path] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool | None = None,
    require_fresh: bool | None = None,
    now: str | None = None,
) -> FrameworkRuntimeServiceAuthorityRecordedExportWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if receipt.get("schema") != FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_SCHEMA:
        errors.append(
            "unsupported framework runtime service authority recorded export worker schema: "
            f"{receipt.get('schema')}"
        )
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append(
            "worker_operation_id does not match canonical framework runtime service authority recorded export worker body"
        )
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime service authority recorded export worker receipt must include at least one signature")
    else:
        signed_value = {
            "worker_operation_id": receipt.get("worker_operation_id"),
            "framework_runtime_service_authority_recorded_export_worker": body,
        }
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime service authority recorded export worker signature verification failed")

    recorded = _parse_required_timestamp(receipt.get("recorded_at"), "recorded_at", errors)
    mode = receipt.get("mode")
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_MODES:
        errors.append("framework runtime service authority recorded export worker mode is unsupported")
    elif mode not in {"hosted-worker", "production-worker"}:
        warnings.append(
            f"framework runtime service authority recorded export worker mode is {mode}; continuously hosted worker operation is not claimed"
        )
    _verify_recorded_export_binding(receipt.get("recorded_export"), errors)
    _verify_worker(receipt.get("worker"), errors)
    _verify_scheduler(receipt.get("scheduler"), errors)
    _verify_execution(receipt.get("execution"), errors)
    _verify_observability(receipt.get("observability"), recorded, errors)
    _verify_redacted_ref(
        receipt.get("credential"),
        "framework runtime service authority recorded export worker credential",
        errors,
    )
    _verify_source_artifacts(receipt.get("source_artifacts"), errors)

    effective_require_complete = receipt.get("require_complete") if require_complete is None else require_complete
    effective_require_fresh = receipt.get("require_fresh") if require_fresh is None else require_fresh
    if not isinstance(effective_require_complete, bool):
        errors.append("framework runtime service authority recorded export worker require_complete must be boolean")
        effective_require_complete = False
    if not isinstance(effective_require_fresh, bool):
        errors.append("framework runtime service authority recorded export worker require_fresh must be boolean")
        effective_require_fresh = False

    if recorded_export is None:
        errors.append(
            "framework runtime service authority recorded export worker source receipt is required for verification"
        )
    else:
        if receipt.get("recorded_export") != _recorded_export_binding(recorded_export):
            errors.append(
                "framework runtime service authority recorded export worker recorded export binding does not match supplied recorded export"
            )
        execution = receipt.get("execution", {})
        if isinstance(execution, dict):
            if execution.get("recorded_export_storage_hash") != content_hash(recorded_export):
                errors.append(
                    "framework runtime service authority recorded export worker recorded_export_storage_hash does not match supplied recorded export"
                )
            if execution.get("artifact_manifest_hash") != content_hash(recorded_export.get("recorded_artifacts", {})):
                errors.append(
                    "framework runtime service authority recorded export worker artifact_manifest_hash does not match supplied recorded export"
                )
            artifacts = recorded_export.get("recorded_artifacts", {})
            if isinstance(artifacts, dict):
                if execution.get("artifact_root") != artifacts.get("artifact_root"):
                    errors.append(
                        "framework runtime service authority recorded export worker artifact_root does not match supplied recorded export"
                    )
                summary = artifacts.get("summary", {}) if isinstance(artifacts.get("summary"), dict) else {}
                if execution.get("artifact_content_root") != summary.get("content_root"):
                    errors.append(
                        "framework runtime service authority recorded export worker artifact_content_root does not match supplied recorded export"
                    )
        if authority_attestation is None:
            errors.append(
                "framework runtime service authority recorded export worker nested source artifacts are required for verification"
            )
        else:
            result = verify_framework_runtime_service_authority_recorded_export(
                recorded_export,
                authority_attestation=authority_attestation,
                authority_provider_receipt=authority_provider_receipt,
                authority_provider_export=authority_provider_export,
                authority_worker=authority_worker,
                authority_dossier=authority_dossier,
                service_provider_receipt=service_provider_receipt,
                service_provider_export=service_provider_export,
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
                artifact_paths=artifact_paths,
                root=root,
                key=key,
                require_complete=effective_require_complete,
                require_fresh=effective_require_fresh,
                now=now or receipt.get("recorded_at"),
            )
            if not result.ok:
                errors.extend(
                    f"framework runtime service authority recorded export worker source: {error}"
                    for error in result.errors
                )
            warnings.extend(
                f"framework runtime service authority recorded export worker source: {warning}"
                for warning in result.warnings
            )
    _verify_production_claim(receipt, recorded_export, errors)
    _compare_source_hash(receipt, "framework-runtime-service-authority-recorded-export", recorded_export, errors)
    _compare_source_hash(receipt, "framework-runtime-service-authority-attestation", authority_attestation, errors)
    _compare_source_hash(receipt, "framework-runtime-service-authority-provider-receipt", authority_provider_receipt, errors)
    _compare_source_hash(receipt, "framework-runtime-service-authority-provider-export", authority_provider_export, errors)
    _compare_source_hash(receipt, "framework-runtime-service-authority-worker", authority_worker, errors)
    _compare_source_hash(receipt, "framework-runtime-service-authority-dossier", authority_dossier, errors)
    _compare_source_hash(receipt, "framework-runtime-service-provider-receipt", service_provider_receipt, errors)
    _compare_source_hash(receipt, "framework-runtime-service-provider-export", service_provider_export, errors)
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
        errors.append("framework runtime service authority recorded export worker controls are required")
    _check_no_secret_values(receipt, errors)
    return FrameworkRuntimeServiceAuthorityRecordedExportWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_runtime_service_authority_recorded_export_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    recorded_export: dict[str, Any],
    authority_attestation: dict[str, Any],
    authority_provider_receipt: dict[str, Any],
    authority_provider_export: dict[str, Any],
    authority_worker: dict[str, Any],
    authority_dossier: dict[str, Any],
    service_provider_receipt: dict[str, Any],
    service_provider_export: dict[str, Any],
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
    artifact_paths: dict[str, str | Path],
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool | None = None,
    require_fresh: bool | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_framework_runtime_service_authority_recorded_export_worker_receipt(
        receipt,
        recorded_export=recorded_export,
        authority_attestation=authority_attestation,
        authority_provider_receipt=authority_provider_receipt,
        authority_provider_export=authority_provider_export,
        authority_worker=authority_worker,
        authority_dossier=authority_dossier,
        service_provider_receipt=service_provider_receipt,
        service_provider_export=service_provider_export,
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
        artifact_paths=artifact_paths,
        root=root,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError(
            "invalid framework runtime service authority recorded export worker receipt: "
            + "; ".join(result.errors)
        )
    payload = {
        "worker_operation_id": receipt["worker_operation_id"],
        "worker_operation_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "recorded_export": receipt.get("recorded_export"),
        "worker": receipt.get("worker"),
        "scheduler": receipt.get("scheduler"),
        "execution": receipt.get("execution"),
        "observability": receipt.get("observability"),
        "credential": receipt.get("credential"),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(
        FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_ENTRY_TYPE,
        payload,
        key=key,
        timestamp=receipt.get("recorded_at"),
    )


def _recorded_export_binding(recorded_export: dict[str, Any]) -> dict[str, Any]:
    source = recorded_export.get("source", {}) if isinstance(recorded_export.get("source"), dict) else {}
    artifacts = recorded_export.get("recorded_artifacts", {}) if isinstance(recorded_export.get("recorded_artifacts"), dict) else {}
    summary = artifacts.get("summary", {}) if isinstance(artifacts.get("summary"), dict) else {}
    return {
        "recorded_export_id": recorded_export.get("recorded_export_id"),
        "recorded_export_hash": content_hash(recorded_export),
        "schema": recorded_export.get("schema"),
        "mode": recorded_export.get("mode"),
        "environment": recorded_export.get("environment"),
        "recorded_at": recorded_export.get("recorded_at"),
        "attestation_id": source.get("attestation_id"),
        "attestation_hash": source.get("attestation_hash"),
        "dossier_id": source.get("dossier_id"),
        "dossier_hash": source.get("dossier_hash"),
        "authority_ref": source.get("authority_ref"),
        "artifact_count": artifacts.get("artifact_count"),
        "artifact_root": artifacts.get("artifact_root"),
        "artifact_sha256_root": summary.get("sha256_root"),
        "artifact_content_root": summary.get("content_root"),
        "retention_until": (recorded_export.get("retention") or {}).get("retention_until")
        if isinstance(recorded_export.get("retention"), dict)
        else None,
    }


def _execution_record(recorded_export: dict[str, Any], **values: Any) -> dict[str, Any]:
    artifacts = recorded_export.get("recorded_artifacts", {}) if isinstance(recorded_export.get("recorded_artifacts"), dict) else {}
    summary = artifacts.get("summary", {}) if isinstance(artifacts.get("summary"), dict) else {}
    return {
        **values,
        "artifact_count": artifacts.get("artifact_count"),
        "artifact_root": artifacts.get("artifact_root"),
        "artifact_sha256_root": summary.get("sha256_root"),
        "artifact_content_root": summary.get("content_root"),
        "artifact_summary_hash": content_hash(summary),
    }


def _source_artifacts(*artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"kind": name, "hash": content_hash(artifact)}
        for name, artifact in zip(SOURCE_ARTIFACT_KINDS, artifacts)
        if isinstance(artifact, dict)
    ]


def _controls(mode: str, recorded_export: dict[str, Any], execution: dict[str, Any], success: bool) -> list[dict[str, Any]]:
    artifacts = recorded_export.get("recorded_artifacts", {}) if isinstance(recorded_export.get("recorded_artifacts"), dict) else {}
    return [
        {
            "name": "recorded_export_source_replayed",
            "status": "passed" if recorded_export.get("recorded_export_id") else "failed",
            "detail": "The worker builder replayed the recorded-export receipt and its nested source artifacts.",
        },
        {
            "name": "worker_operation_succeeded",
            "status": "passed" if success else "failed",
            "detail": "The recorded-export worker completed without error and with a successful response status.",
        },
        {
            "name": "recorded_export_stored",
            "status": "passed" if execution.get("recorded_export_storage_hash") == content_hash(recorded_export) else "failed",
            "detail": "The worker output binds the stored recorded-export receipt hash.",
        },
        {
            "name": "artifact_archive_bound",
            "status": "passed"
            if execution.get("artifact_archive_hash")
            and execution.get("artifact_manifest_hash") == content_hash(artifacts)
            else "failed",
            "detail": "The worker binds an artifact archive hash and manifest hash to the recorded export.",
        },
        {
            "name": "storage_write_bound",
            "status": "passed" if execution.get("storage_write_ref") and execution.get("storage_write_hash") else "failed",
            "detail": "The worker records the storage write reference and hash for the retained export archive.",
        },
        {
            "name": "production_worker_claim_limited",
            "status": "passed"
            if mode != "production-worker" or recorded_export.get("mode") == "production-recorded-export"
            else "failed",
            "detail": "Production-worker mode requires a production-recorded-export source.",
        },
    ]


def _verify_recorded_export_binding(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority recorded export worker recorded_export must be an object")
        return
    for field in RECORDED_EXPORT_BINDING_EXPECTED_FIELDS:
        if field not in value:
            errors.append(f"framework runtime service authority recorded export worker recorded_export.{field} is required")
    for field in RECORDED_EXPORT_BINDING_REQUIRED_FIELDS:
        if value.get(field) in (None, "", [], {}):
            errors.append(f"framework runtime service authority recorded export worker recorded_export.{field} is required")
    if not isinstance(value.get("artifact_count"), int) or value.get("artifact_count") <= 0:
        errors.append("framework runtime service authority recorded export worker recorded_export.artifact_count must be positive")
    _parse_required_timestamp(value.get("recorded_at"), "recorded_export.recorded_at", errors)
    _parse_required_timestamp(value.get("retention_until"), "recorded_export.retention_until", errors)


def _verify_worker(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority recorded export worker worker must be an object")
        return
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at"):
        if not value.get(field):
            errors.append(f"framework runtime service authority recorded export worker worker.{field} is required")
    if value.get("operation_kind") not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_OPERATION_KINDS:
        errors.append("framework runtime service authority recorded export worker operation_kind is unsupported")
    started = _parse_required_timestamp(value.get("started_at"), "worker.started_at", errors)
    completed = _parse_required_timestamp(value.get("completed_at"), "worker.completed_at", errors)
    if started and completed and completed < started:
        errors.append("framework runtime service authority recorded export worker completed_at is before started_at")
    if not isinstance(value.get("attempt"), int) or value.get("attempt") < 1:
        errors.append("framework runtime service authority recorded export worker attempt must be a positive integer")
    if not isinstance(value.get("max_attempts"), int) or value.get("max_attempts") < value.get("attempt", 0):
        errors.append("framework runtime service authority recorded export worker max_attempts must be greater than or equal to attempt")


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority recorded export worker scheduler must be an object")
        return
    for field in ("schedule_ref", "lease_ref", "checkpoint_ref", "checkpoint_hash"):
        if not value.get(field):
            errors.append(f"framework runtime service authority recorded export worker scheduler.{field} is required")
    if not isinstance(value.get("cadence_seconds"), int) or value.get("cadence_seconds") <= 0:
        errors.append("framework runtime service authority recorded export worker scheduler.cadence_seconds must be positive")
    if value.get("checkpoint_hash") and not _is_sha256_ref(str(value.get("checkpoint_hash"))):
        errors.append("framework runtime service authority recorded export worker scheduler.checkpoint_hash must be a sha256 reference")
    if value.get("next_run_at"):
        _parse_required_timestamp(value.get("next_run_at"), "scheduler.next_run_at", errors)


def _verify_execution(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority recorded export worker execution must be an object")
        return
    for field in (
        "queue_ref",
        "queue_message_ref",
        "queue_message_hash",
        "recorded_export_ref",
        "recorded_export_storage_ref",
        "recorded_export_storage_hash",
        "artifact_archive_ref",
        "artifact_archive_hash",
        "artifact_manifest_ref",
        "artifact_manifest_hash",
        "storage_write_ref",
        "storage_write_hash",
        "artifact_count",
        "artifact_root",
        "artifact_sha256_root",
        "artifact_content_root",
        "artifact_summary_hash",
    ):
        if value.get(field) is None:
            errors.append(f"framework runtime service authority recorded export worker execution.{field} is required")
    for field in (
        "queue_message_hash",
        "recorded_export_storage_hash",
        "artifact_archive_hash",
        "artifact_manifest_hash",
        "storage_write_hash",
        "request_hash",
        "response_hash",
        "artifact_root",
        "artifact_sha256_root",
        "artifact_content_root",
        "artifact_summary_hash",
    ):
        field_value = value.get(field)
        if field_value and not _is_sha256_ref(str(field_value)):
            errors.append(f"framework runtime service authority recorded export worker execution.{field} must be a sha256 reference")
    if value.get("response_status") is not None and (
        not isinstance(value.get("response_status"), int) or value.get("response_status") < 100 or value.get("response_status") > 599
    ):
        errors.append("framework runtime service authority recorded export worker execution.response_status must be an HTTP status code")


def _verify_observability(value: Any, recorded: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority recorded export worker observability must be an object")
        return
    for field in ("metrics_ref", "audit_log_ref", "audit_log_root", "retention_until"):
        if not value.get(field):
            errors.append(f"framework runtime service authority recorded export worker observability.{field} is required")
    if value.get("audit_log_root") and not _is_sha256_ref(str(value.get("audit_log_root"))):
        errors.append("framework runtime service authority recorded export worker observability.audit_log_root must be a sha256 reference")
    retention = _parse_required_timestamp(value.get("retention_until"), "observability.retention_until", errors)
    if recorded and retention and retention <= recorded:
        errors.append("framework runtime service authority recorded export worker retention_until must be after recorded_at")


def _verify_source_artifacts(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append("framework runtime service authority recorded export worker source_artifacts are required")
        return
    actual_kinds: set[str] = set()
    duplicate_kinds: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"framework runtime service authority recorded export worker source_artifacts[{index}] must be an object")
            continue
        kind = item.get("kind")
        if not kind:
            errors.append(f"framework runtime service authority recorded export worker source_artifacts[{index}].kind is required")
        elif not isinstance(kind, str):
            errors.append(f"framework runtime service authority recorded export worker source_artifacts[{index}].kind must be a string")
        else:
            if kind in actual_kinds:
                duplicate_kinds.add(kind)
            actual_kinds.add(kind)
        if not item.get("hash") or not _is_sha256_ref(str(item.get("hash"))):
            errors.append(f"framework runtime service authority recorded export worker source_artifacts[{index}].hash must be a sha256 reference")
    expected_kinds = set(SOURCE_ARTIFACT_KINDS)
    missing = sorted(expected_kinds - actual_kinds)
    extra = sorted(actual_kinds - expected_kinds)
    if missing:
        errors.append("framework runtime service authority recorded export worker source_artifacts missing: " + ", ".join(missing))
    if extra:
        errors.append("framework runtime service authority recorded export worker source_artifacts unsupported: " + ", ".join(extra))
    if duplicate_kinds:
        errors.append("framework runtime service authority recorded export worker source_artifacts duplicate: " + ", ".join(sorted(duplicate_kinds)))


def _verify_production_claim(receipt: dict[str, Any], recorded_export: dict[str, Any] | None, errors: list[str]) -> None:
    if receipt.get("mode") != "production-worker":
        return
    source_mode = recorded_export.get("mode") if isinstance(recorded_export, dict) else (receipt.get("recorded_export") or {}).get("mode")
    if source_mode != "production-recorded-export":
        errors.append("production-worker mode requires a production-recorded-export source")


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
                errors.append(f"framework runtime service authority recorded export worker source artifact hash mismatch: {kind}")
            return
    errors.append(f"framework runtime service authority recorded export worker source artifact missing: {kind}")


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


def _parse_required_timestamp(value: Any, field: str, errors: list[str]) -> Any:
    if not value:
        errors.append(f"framework runtime service authority recorded export worker {field} is required")
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"framework runtime service authority recorded export worker {field} invalid: {exc}")
        return None


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"framework runtime service authority recorded export worker {field} is required")


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
                    errors.append(
                        "framework runtime service authority recorded export worker secret-like field must be redacted reference: "
                        f"{child_path}"
                    )
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
