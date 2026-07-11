from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_runtime_service import verify_framework_runtime_service_attestation

FRAMEWORK_RUNTIME_SERVICE_WORKER_SCHEMA = "trustai.framework-runtime-service-worker/0.1"
FRAMEWORK_RUNTIME_SERVICE_WORKER_ENTRY_TYPE = "framework_runtime.service_worker_recorded"
FRAMEWORK_RUNTIME_SERVICE_WORKER_MODES = {"local-reference", "scheduled-worker", "hosted-worker", "production-design"}
FRAMEWORK_RUNTIME_SERVICE_WORKER_OPERATION_KINDS = {
    "runtime_audit_replay",
    "storage_export_reconcile",
    "stream_storage_reconcile",
    "checkpoint_compact",
    "control_index_reconcile",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")
SERVICE_SUMMARY_EXPECTED_FIELDS = (
    "attestation_id",
    "attestation_hash",
    "mode",
    "environment",
    "service_ref",
    "service_version",
    "service_image_digest",
    "service_binary_hash",
    "runtime_worker_ref",
    "queue_ref",
    "dead_letter_queue_ref",
    "lease_store_ref",
    "checkpoint_store_ref",
    "cursor_store_ref",
    "idempotency_store_ref",
    "max_concurrency",
    "stream_ref",
    "stream_topic",
    "stream_dlq_ref",
    "worm_store_ref",
    "clickhouse_ref",
    "postgres_ref",
    "kms_key_ref",
    "audit_log_root",
)
SERVICE_SUMMARY_REQUIRED_FIELDS = SERVICE_SUMMARY_EXPECTED_FIELDS
SOURCE_SUMMARY_EXPECTED_FIELDS = (
    "source_count",
    "source_hash",
    "schemas",
    "required_types",
    "storage_receipt_id",
    "storage_receipt_hash",
    "provider_export_hash",
    "artifacts",
)
SOURCE_ARTIFACT_TYPES = (
    "framework-runtime-service-attestation",
    "framework-runtime-storage",
    "framework-runtime-storage-export",
    "framework-runtime-worker",
    "framework-runtime-audit",
    "framework-runtime-audit-export",
    "framework-hook-operation",
    "framework-trace",
    "framework-hook-release",
    "framework-adapter-matrix",
)


@dataclass
class FrameworkRuntimeServiceWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_runtime_service_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime service worker receipt must contain an object")
    return value


def write_framework_runtime_service_worker_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_runtime_service_worker_receipt(
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
    *,
    root: str | Path = ".",
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
    attempt: int = 1,
    max_attempts: int = 3,
    queue_ref: str,
    queue_message_ref: str,
    queue_message_hash: str,
    dead_letter_queue_ref: str | None = None,
    runtime_worker_ref: str,
    stream_message_ref: str,
    stream_message_hash: str,
    storage_object_ref: str,
    storage_object_hash: str,
    clickhouse_batch_ref: str,
    clickhouse_batch_hash: str,
    postgres_index_ref: str,
    postgres_index_hash: str,
    control_index_ref: str,
    control_index_hash: str,
    request_hash: str | None = None,
    response_status: int | None = None,
    response_hash: str | None = None,
    metrics_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    started_at: str,
    completed_at: str | None = None,
    next_run_at: str | None = None,
    error_ref: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in FRAMEWORK_RUNTIME_SERVICE_WORKER_MODES:
        raise ValueError(f"mode must be one of {sorted(FRAMEWORK_RUNTIME_SERVICE_WORKER_MODES)}")
    if operation_kind not in FRAMEWORK_RUNTIME_SERVICE_WORKER_OPERATION_KINDS:
        raise ValueError(f"operation_kind must be one of {sorted(FRAMEWORK_RUNTIME_SERVICE_WORKER_OPERATION_KINDS)}")
    service_result = verify_framework_runtime_service_attestation(
        service_attestation,
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
    )
    if not service_result.ok:
        raise ValueError("invalid framework runtime service source: " + "; ".join(service_result.errors))

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
        (runtime_worker_ref, "runtime_worker_ref"),
        (stream_message_ref, "stream_message_ref"),
        (stream_message_hash, "stream_message_hash"),
        (storage_object_ref, "storage_object_ref"),
        (storage_object_hash, "storage_object_hash"),
        (clickhouse_batch_ref, "clickhouse_batch_ref"),
        (clickhouse_batch_hash, "clickhouse_batch_hash"),
        (postgres_index_ref, "postgres_index_ref"),
        (postgres_index_hash, "postgres_index_hash"),
        (control_index_ref, "control_index_ref"),
        (control_index_hash, "control_index_hash"),
        (metrics_ref, "metrics_ref"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (retention_until, "retention_until"),
        (credential_ref, "credential_ref"),
        (started_at, "started_at"),
    ):
        _require_text(value, field)
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
    for field, value in (
        ("checkpoint_hash", checkpoint_hash),
        ("queue_message_hash", queue_message_hash),
        ("stream_message_hash", stream_message_hash),
        ("storage_object_hash", storage_object_hash),
        ("clickhouse_batch_hash", clickhouse_batch_hash),
        ("postgres_index_hash", postgres_index_hash),
        ("control_index_hash", control_index_hash),
        ("request_hash", request_hash),
        ("response_hash", response_hash),
        ("audit_log_root", audit_log_root),
    ):
        if value and not _is_sha256_ref(str(value)):
            raise ValueError(f"{field} must be a sha256 reference")

    service = _service_record(service_attestation)
    if runtime_worker_ref != service.get("runtime_worker_ref"):
        raise ValueError("runtime_worker_ref must match framework runtime service scheduler runtime_worker_ref")
    if queue_ref != service.get("queue_ref"):
        raise ValueError("queue_ref must match framework runtime service scheduler queue_ref")
    if dead_letter_queue_ref and dead_letter_queue_ref != service.get("dead_letter_queue_ref"):
        raise ValueError("dead_letter_queue_ref must match framework runtime service scheduler dead_letter_queue_ref")
    source_artifacts = _source_artifacts(
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
    )
    source = _source_summary(source_artifacts, storage_receipt)
    response_success = response_status is None or 200 <= response_status < 300
    success = not error_ref and response_success
    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_SERVICE_WORKER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": completed,
        "service": service,
        "source": source,
        "worker": {
            "worker_ref": worker_ref,
            "run_ref": run_ref,
            "operation_kind": operation_kind,
            "actor_ref": actor_ref,
            "runtime_worker_ref": runtime_worker_ref,
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
            "stream_message_ref": stream_message_ref,
            "stream_message_hash": stream_message_hash,
            "storage_object_ref": storage_object_ref,
            "storage_object_hash": storage_object_hash,
            "clickhouse_batch_ref": clickhouse_batch_ref,
            "clickhouse_batch_hash": clickhouse_batch_hash,
            "postgres_index_ref": postgres_index_ref,
            "postgres_index_hash": postgres_index_hash,
            "control_index_ref": control_index_ref,
            "control_index_hash": control_index_hash,
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
        },
        "observability": {
            "metrics_ref": metrics_ref,
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "retention_until": retention_until,
            "evidence_refs": sorted(evidence_refs or []),
        },
        "credential": _redacted_ref(credential_ref),
        "source_artifacts": source_artifacts,
        "controls": _controls(service, source, mode, cadence_seconds, checkpoint_hash, queue_message_hash, storage_object_hash, clickhouse_batch_hash, postgres_index_hash, control_index_hash, audit_log_root, success),
        "limitations": [
            "This receipt records a framework runtime service worker operation and replays the signed service attestation source.",
            "It binds queue, lease, checkpoint, cursor, stream, WORM, ClickHouse, Postgres, control-index, request/response, metrics, audit, retention, and credential-redaction evidence.",
            "It does not claim continuously operated production infrastructure unless backed by provider-native scheduler, queue, lease, KMS, stream, database, and immutable audit-log exports.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [sign_value({"worker_operation_id": worker_operation_id, "framework_runtime_service_worker": body}, key)],
    }


def verify_framework_runtime_service_worker_receipt(
    receipt: dict[str, Any],
    *,
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
) -> FrameworkRuntimeServiceWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != FRAMEWORK_RUNTIME_SERVICE_WORKER_SCHEMA:
        errors.append(f"unsupported framework runtime service worker schema: {receipt.get('schema')}")
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append("worker_operation_id does not match canonical framework runtime service worker body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime service worker receipt must include at least one signature")
    else:
        signed_value = {"worker_operation_id": receipt.get("worker_operation_id"), "framework_runtime_service_worker": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime service worker signature verification failed")

    try:
        recorded = parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"framework runtime service worker recorded_at invalid: {exc}")
        recorded = None
    mode = receipt.get("mode")
    if mode not in FRAMEWORK_RUNTIME_SERVICE_WORKER_MODES:
        errors.append("framework runtime service worker mode is unsupported")
    elif mode != "hosted-worker":
        warnings.append(f"framework runtime service worker mode is {mode}; continuously hosted worker operation is not claimed")

    _verify_service(receipt.get("service"), errors)
    _verify_source(receipt.get("source"), errors)
    _verify_worker(receipt.get("worker"), errors)
    _verify_scheduler(receipt.get("scheduler"), errors)
    _verify_execution(receipt.get("execution"), errors)
    _verify_observability(receipt.get("observability"), recorded, errors)
    _verify_redacted_ref(receipt.get("credential"), "framework runtime service worker credential", errors)
    _verify_source_artifacts(receipt.get("source_artifacts"), errors)

    if service_attestation is None:
        errors.append("framework runtime service worker service attestation artifact is required for verification")
    else:
        _compare_source_hash(receipt, "framework-runtime-service-attestation", service_attestation, errors)
        service_hash = receipt.get("service", {}).get("attestation_hash") if isinstance(receipt.get("service"), dict) else None
        if service_hash != content_hash(service_attestation):
            errors.append("framework runtime service worker service.attestation_hash does not match supplied service attestation")
        service_sources = (
            ("framework-runtime-storage", storage_receipt),
            ("framework-runtime-storage-export", storage_export),
            ("framework-runtime-worker", worker),
            ("framework-runtime-audit", runtime_audit),
            ("framework-runtime-audit-export", audit_export),
            ("framework-hook-operation", operation),
            ("framework-trace", trace_payload),
            ("framework-hook-release", release),
            ("framework-adapter-matrix", matrix),
        )
        missing_sources = [source_type for source_type, value in service_sources if value is None]
        if missing_sources:
            errors.append("framework runtime service worker source artifacts are required for verification: " + ", ".join(missing_sources))
        else:
            result = verify_framework_runtime_service_attestation(
                service_attestation,
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
            )
            if not result.ok:
                errors.extend(f"framework runtime service worker service source: {error}" for error in result.errors)
            warnings.extend(f"framework runtime service worker service source: {warning}" for warning in result.warnings)

    for source_type, value in (
        ("framework-runtime-storage", storage_receipt),
        ("framework-runtime-storage-export", storage_export),
        ("framework-runtime-worker", worker),
        ("framework-runtime-audit", runtime_audit),
        ("framework-runtime-audit-export", audit_export),
        ("framework-hook-operation", operation),
        ("framework-trace", trace_payload),
        ("framework-hook-release", release),
        ("framework-adapter-matrix", matrix),
    ):
        if isinstance(value, dict):
            _compare_source_hash(receipt, source_type, value, errors)
    if isinstance(storage_receipt, dict):
        source_hash = receipt.get("source", {}).get("storage_receipt_hash") if isinstance(receipt.get("source"), dict) else None
        if source_hash != content_hash(storage_receipt):
            errors.append("framework runtime service worker source.storage_receipt_hash does not match supplied storage receipt")
    _check_no_secret_values(receipt, errors)
    return FrameworkRuntimeServiceWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_runtime_service_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
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
) -> dict[str, Any]:
    result = verify_framework_runtime_service_worker_receipt(
        receipt,
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
    )
    if not result.ok:
        raise ValueError("invalid framework runtime service worker receipt: " + "; ".join(result.errors))
    payload = {
        "worker_operation_id": receipt["worker_operation_id"],
        "worker_operation_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "service": receipt.get("service"),
        "source": receipt.get("source"),
        "worker": receipt.get("worker"),
        "scheduler": receipt.get("scheduler"),
        "execution": receipt.get("execution"),
        "observability": receipt.get("observability"),
        "credential": receipt.get("credential"),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(FRAMEWORK_RUNTIME_SERVICE_WORKER_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("recorded_at"))

def _service_record(attestation: dict[str, Any]) -> dict[str, Any]:
    service = attestation.get("service", {}) if isinstance(attestation, dict) and isinstance(attestation.get("service"), dict) else {}
    scheduler = attestation.get("scheduler", {}) if isinstance(attestation, dict) and isinstance(attestation.get("scheduler"), dict) else {}
    storage = attestation.get("storage_backends", {}) if isinstance(attestation, dict) and isinstance(attestation.get("storage_backends"), dict) else {}
    security = attestation.get("security", {}) if isinstance(attestation, dict) and isinstance(attestation.get("security"), dict) else {}
    observability = attestation.get("observability", {}) if isinstance(attestation, dict) and isinstance(attestation.get("observability"), dict) else {}
    return {
        "attestation_id": attestation.get("attestation_id") if isinstance(attestation, dict) else None,
        "attestation_hash": content_hash(attestation) if isinstance(attestation, dict) else None,
        "mode": attestation.get("mode") if isinstance(attestation, dict) else None,
        "environment": attestation.get("environment") if isinstance(attestation, dict) else None,
        "service_ref": service.get("service_ref"),
        "service_version": service.get("version"),
        "service_image_digest": service.get("service_image_digest"),
        "service_binary_hash": service.get("service_binary_hash"),
        "runtime_worker_ref": scheduler.get("runtime_worker_ref"),
        "queue_ref": scheduler.get("queue_ref"),
        "dead_letter_queue_ref": scheduler.get("dead_letter_queue_ref"),
        "lease_store_ref": scheduler.get("lease_store_ref"),
        "checkpoint_store_ref": scheduler.get("checkpoint_store_ref"),
        "cursor_store_ref": scheduler.get("cursor_store_ref"),
        "idempotency_store_ref": scheduler.get("idempotency_store_ref"),
        "max_concurrency": scheduler.get("max_concurrency"),
        "stream_ref": storage.get("stream_ref"),
        "stream_topic": storage.get("stream_topic"),
        "stream_dlq_ref": storage.get("stream_dlq_ref"),
        "worm_store_ref": storage.get("worm_store_ref"),
        "clickhouse_ref": storage.get("clickhouse_ref"),
        "postgres_ref": storage.get("postgres_ref"),
        "kms_key_ref": security.get("kms_key_ref"),
        "audit_log_root": observability.get("audit_log_root"),
    }


def _source_artifacts(*sources: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for source_type, value in zip(SOURCE_ARTIFACT_TYPES, sources):
        records.append({"type": source_type, "id": _source_id(value), "schema": value.get("schema"), "hash": content_hash(value)})
    return records


def _source_summary(records: list[dict[str, Any]], storage_receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_count": len(records),
        "source_hash": content_hash(records),
        "schemas": sorted({str(record.get("schema")) for record in records if record.get("schema")}),
        "required_types": sorted(record["type"] for record in records),
        "storage_receipt_id": storage_receipt.get("storage_receipt_id"),
        "storage_receipt_hash": content_hash(storage_receipt),
        "provider_export_hash": storage_receipt.get("provider_export", {}).get("hash") if isinstance(storage_receipt.get("provider_export"), dict) else None,
        "artifacts": records,
    }


def _controls(
    service: dict[str, Any],
    source: dict[str, Any],
    mode: str,
    cadence_seconds: int,
    checkpoint_hash: str,
    queue_message_hash: str,
    storage_object_hash: str,
    clickhouse_batch_hash: str,
    postgres_index_hash: str,
    control_index_hash: str,
    audit_log_root: str,
    success: bool,
) -> list[dict[str, str]]:
    storage_writes_ok = all(_is_sha256_ref(value) for value in (storage_object_hash, clickhouse_batch_hash, postgres_index_hash, control_index_hash))
    return [
        {
            "id": "framework-runtime-service-source-replay",
            "status": "worker-recorded" if source.get("source_count", 0) >= 10 and service.get("attestation_hash") else "planned-production",
            "description": "Worker receipt is bound to service, storage, runtime, hook, release, and adapter source hashes.",
        },
        {
            "id": "framework-runtime-hosted-worker-mode",
            "status": "worker-recorded" if mode == "hosted-worker" else "planned-production",
            "description": "Worker mode records hosted framework runtime operation intent.",
        },
        {
            "id": "framework-runtime-scheduler-lease-checkpoint",
            "status": "worker-recorded" if cadence_seconds > 0 and _is_sha256_ref(checkpoint_hash) and service.get("lease_store_ref") and service.get("checkpoint_store_ref") else "planned-production",
            "description": "Schedule, lease, checkpoint, cadence, and checkpoint hash are bound.",
        },
        {
            "id": "framework-runtime-queue-message",
            "status": "worker-recorded" if service.get("queue_ref") and _is_sha256_ref(queue_message_hash) else "planned-production",
            "description": "Queue reference and queue message hash are bound.",
        },
        {
            "id": "framework-runtime-stream-storage-writes",
            "status": "worker-recorded" if storage_writes_ok and service.get("stream_ref") and service.get("worm_store_ref") else "planned-production",
            "description": "Stream, WORM, ClickHouse, Postgres, and control-index write hashes are bound.",
        },
        {
            "id": "framework-runtime-worker-audit-retention",
            "status": "worker-recorded" if _is_sha256_ref(audit_log_root) and service.get("audit_log_root") else "planned-production",
            "description": "Worker audit root and service audit root are bound.",
        },
        {
            "id": "framework-runtime-worker-success-recorded",
            "status": "worker-recorded" if success else "failed",
            "description": "Worker outcome is explicitly recorded.",
        },
    ]

def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service worker service must be an object")
        return
    for field in SERVICE_SUMMARY_EXPECTED_FIELDS:
        if field not in value:
            errors.append(f"framework runtime service worker service.{field} is required")
    for field in SERVICE_SUMMARY_REQUIRED_FIELDS:
        if value.get(field) in (None, "", [], {}):
            errors.append(f"framework runtime service worker service.{field} is required")
    if not isinstance(value.get("max_concurrency"), int) or value.get("max_concurrency") <= 0:
        errors.append("framework runtime service worker service.max_concurrency must be positive")
    for field in ("attestation_hash", "service_image_digest", "service_binary_hash", "audit_log_root"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"framework runtime service worker service.{field} must be a sha256 reference")


def _verify_source(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service worker source must be an object")
        return
    for field in SOURCE_SUMMARY_EXPECTED_FIELDS:
        if field not in value:
            errors.append(f"framework runtime service worker source.{field} is required")
    for field in SOURCE_SUMMARY_EXPECTED_FIELDS:
        if value.get(field) in (None, "", [], {}):
            errors.append(f"framework runtime service worker source.{field} is required")
    if value.get("source_count") != len(SOURCE_ARTIFACT_TYPES):
        errors.append("framework runtime service worker source.source_count must match expected source artifact count")
    if not _is_sha256_ref(str(value.get("source_hash") or "")):
        errors.append("framework runtime service worker source.source_hash must be a sha256 reference")
    required = value.get("required_types", [])
    if required != sorted(SOURCE_ARTIFACT_TYPES):
        errors.append("framework runtime service worker source.required_types must match expected source artifact types")
    artifacts = value.get("artifacts")
    _verify_source_artifact_records(artifacts, "source.artifacts", errors)
    if isinstance(artifacts, list) and value.get("source_hash") != content_hash(artifacts):
        errors.append("framework runtime service worker source.source_hash does not match artifacts")
    if not value.get("storage_receipt_id") or not value.get("storage_receipt_hash"):
        errors.append("framework runtime service worker source must include storage receipt binding")


def _verify_worker(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service worker worker must be an object")
        return
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "runtime_worker_ref", "started_at", "completed_at"):
        if not value.get(field):
            errors.append(f"framework runtime service worker worker.{field} is required")
    if value.get("operation_kind") not in FRAMEWORK_RUNTIME_SERVICE_WORKER_OPERATION_KINDS:
        errors.append("framework runtime service worker worker.operation_kind is unsupported")
    try:
        started = parse_rfc3339(str(value.get("started_at") or ""))
        completed = parse_rfc3339(str(value.get("completed_at") or ""))
        if completed < started:
            errors.append("framework runtime service worker worker.completed_at must be at or after started_at")
    except ValueError as exc:
        errors.append(f"framework runtime service worker worker timestamp invalid: {exc}")
    if not isinstance(value.get("attempt"), int) or value.get("attempt") < 1:
        errors.append("framework runtime service worker worker.attempt must be a positive integer")
    if not isinstance(value.get("max_attempts"), int) or value.get("max_attempts") < value.get("attempt", 1):
        errors.append("framework runtime service worker worker.max_attempts must be greater than or equal to attempt")
    if value.get("success") is False and not value.get("error_ref"):
        errors.append("framework runtime service worker worker.error_ref is required when success is false")


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service worker scheduler must be an object")
        return
    for field in ("schedule_ref", "lease_ref", "checkpoint_ref", "checkpoint_hash"):
        if not value.get(field):
            errors.append(f"framework runtime service worker scheduler.{field} is required")
    if not isinstance(value.get("cadence_seconds"), int) or value.get("cadence_seconds") <= 0:
        errors.append("framework runtime service worker scheduler.cadence_seconds must be positive")
    if value.get("checkpoint_hash") and not _is_sha256_ref(str(value.get("checkpoint_hash"))):
        errors.append("framework runtime service worker scheduler.checkpoint_hash must be a sha256 reference")
    if value.get("next_run_at"):
        try:
            parse_rfc3339(str(value.get("next_run_at")))
        except ValueError as exc:
            errors.append(f"framework runtime service worker scheduler.next_run_at invalid: {exc}")


def _verify_execution(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service worker execution must be an object")
        return
    for field in ("queue_ref", "queue_message_ref", "queue_message_hash", "stream_message_ref", "stream_message_hash", "storage_object_ref", "storage_object_hash", "clickhouse_batch_ref", "clickhouse_batch_hash", "postgres_index_ref", "postgres_index_hash", "control_index_ref", "control_index_hash"):
        if not value.get(field):
            errors.append(f"framework runtime service worker execution.{field} is required")
    for field in ("queue_message_hash", "stream_message_hash", "storage_object_hash", "clickhouse_batch_hash", "postgres_index_hash", "control_index_hash", "request_hash", "response_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"framework runtime service worker execution.{field} must be a sha256 reference")
    status = value.get("response_status")
    if status is not None and (not isinstance(status, int) or status < 100 or status > 599):
        errors.append("framework runtime service worker execution.response_status must be an HTTP status code")


def _verify_observability(value: Any, recorded: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service worker observability must be an object")
        return
    for field in ("metrics_ref", "audit_log_ref", "audit_log_root", "retention_until"):
        if not value.get(field):
            errors.append(f"framework runtime service worker observability.{field} is required")
    if value.get("audit_log_root") and not _is_sha256_ref(str(value.get("audit_log_root"))):
        errors.append("framework runtime service worker observability.audit_log_root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if recorded and retention <= recorded:
            errors.append("framework runtime service worker observability.retention_until must be after recorded_at")
    except ValueError as exc:
        errors.append(f"framework runtime service worker observability.retention_until invalid: {exc}")
    if not isinstance(value.get("evidence_refs", []), list):
        errors.append("framework runtime service worker observability.evidence_refs must be a list")

def _verify_source_artifacts(value: Any, errors: list[str]) -> None:
    _verify_source_artifact_records(value, "source_artifacts", errors)



def _verify_source_artifact_records(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"framework runtime service worker {label} must be a non-empty list")
        return
    actual_types: set[str] = set()
    duplicate_types: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"framework runtime service worker {label}[{index}] must be an object")
            continue
        source_type = item.get("type")
        if not source_type:
            errors.append(f"framework runtime service worker {label}[{index}].type is required")
        elif not isinstance(source_type, str):
            errors.append(f"framework runtime service worker {label}[{index}].type must be a string")
        else:
            if source_type in actual_types:
                duplicate_types.add(source_type)
            actual_types.add(source_type)
        if not item.get("hash"):
            errors.append(f"framework runtime service worker {label}[{index}].hash is required")
        elif not _is_sha256_ref(str(item.get("hash"))):
            errors.append(f"framework runtime service worker {label}[{index}].hash must be a sha256 reference")
    expected_types = set(SOURCE_ARTIFACT_TYPES)
    missing = sorted(expected_types - actual_types)
    extra = sorted(actual_types - expected_types)
    if missing:
        errors.append(f"framework runtime service worker {label} missing: " + ", ".join(missing))
    if extra:
        errors.append(f"framework runtime service worker {label} unsupported: " + ", ".join(extra))
    if duplicate_types:
        errors.append(f"framework runtime service worker {label} duplicate: " + ", ".join(sorted(duplicate_types)))


def _compare_source_hash(receipt: dict[str, Any], source_type: str, value: dict[str, Any], errors: list[str]) -> None:
    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("framework runtime service worker source_artifacts must be a list")
        return
    actual = content_hash(value)
    if not any(isinstance(item, dict) and item.get("type") == source_type and item.get("hash") == actual for item in artifacts):
        errors.append(f"framework runtime service worker source_artifacts missing current hash for {source_type}")


def _source_id(value: dict[str, Any]) -> str | None:
    for field in ("attestation_id", "storage_receipt_id", "worker_operation_id", "runtime_audit_id", "operation_id", "release_id", "matrix_id", "export_ref", "trace_id", "schema"):
        if value.get(field):
            return str(value.get(field))
    return None


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
        raise ValueError(f"framework runtime service worker {field} is required")


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
                    errors.append(f"framework runtime service worker secret-like field must be redacted reference: {child_path}")
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