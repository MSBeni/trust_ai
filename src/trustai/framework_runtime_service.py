from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_runtime_storage import verify_framework_runtime_storage_receipt

FRAMEWORK_RUNTIME_SERVICE_SCHEMA = "trustai.framework-runtime-service-attestation/0.1"
FRAMEWORK_RUNTIME_SERVICE_ENTRY_TYPE = "framework_runtime.service_attested"
FRAMEWORK_RUNTIME_SERVICE_MODES = {"local-reference", "hosted-runtime-service", "production-design"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class FrameworkRuntimeServiceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_runtime_service_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime service attestation must contain an object")
    return value


def write_framework_runtime_service_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_runtime_service_attestation(
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
    mode: str = "hosted-runtime-service",
    environment: str = "local",
    service_ref: str,
    service_version: str,
    service_image: str,
    service_image_digest: str,
    service_binary_hash: str,
    replicas_min: int,
    replicas_max: int,
    availability_zones: list[str] | None = None,
    runtime_worker_ref: str,
    scheduler_ref: str,
    schedule_cadence_seconds: int,
    queue_ref: str,
    dead_letter_queue_ref: str,
    lease_store_ref: str,
    lease_store_hash: str,
    checkpoint_store_ref: str,
    checkpoint_store_hash: str,
    cursor_store_ref: str,
    idempotency_store_ref: str,
    retry_policy_ref: str,
    max_concurrency: int,
    stream_backend: str,
    stream_ref: str,
    stream_topic: str,
    stream_dlq_ref: str,
    worm_store_ref: str,
    object_lock_policy_ref: str,
    clickhouse_ref: str,
    clickhouse_schema_hash: str,
    clickhouse_backup_ref: str,
    postgres_ref: str,
    postgres_schema_hash: str,
    postgres_backup_ref: str,
    mtls_policy_ref: str,
    auth_policy_ref: str,
    tenant_isolation_ref: str,
    admission_policy_ref: str,
    rate_limit_policy_ref: str,
    network_policy_ref: str,
    egress_policy_ref: str,
    secret_store_ref: str,
    kms_key_ref: str,
    metrics_ref: str,
    alert_policy_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    access_log_ref: str,
    access_log_root: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in FRAMEWORK_RUNTIME_SERVICE_MODES:
        raise ValueError(f"mode must be one of {sorted(FRAMEWORK_RUNTIME_SERVICE_MODES)}")
    source_result = verify_framework_runtime_storage_receipt(
        storage_receipt,
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
    if not source_result.ok:
        raise ValueError("invalid framework runtime storage source: " + "; ".join(source_result.errors))

    timestamp = attested_at or utc_now()
    parse_rfc3339(timestamp)
    retention = parse_rfc3339(retention_until)
    if retention <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after attested_at")
    if replicas_min < 1:
        raise ValueError("replicas_min must be at least 1")
    if replicas_max < replicas_min:
        raise ValueError("replicas_max must be greater than or equal to replicas_min")
    if schedule_cadence_seconds < 1:
        raise ValueError("schedule_cadence_seconds must be positive")
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be positive")

    for field, value in {
        "service_ref": service_ref,
        "service_version": service_version,
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "runtime_worker_ref": runtime_worker_ref,
        "scheduler_ref": scheduler_ref,
        "queue_ref": queue_ref,
        "dead_letter_queue_ref": dead_letter_queue_ref,
        "lease_store_ref": lease_store_ref,
        "lease_store_hash": lease_store_hash,
        "checkpoint_store_ref": checkpoint_store_ref,
        "checkpoint_store_hash": checkpoint_store_hash,
        "cursor_store_ref": cursor_store_ref,
        "idempotency_store_ref": idempotency_store_ref,
        "retry_policy_ref": retry_policy_ref,
        "stream_backend": stream_backend,
        "stream_ref": stream_ref,
        "stream_topic": stream_topic,
        "stream_dlq_ref": stream_dlq_ref,
        "worm_store_ref": worm_store_ref,
        "object_lock_policy_ref": object_lock_policy_ref,
        "clickhouse_ref": clickhouse_ref,
        "clickhouse_schema_hash": clickhouse_schema_hash,
        "clickhouse_backup_ref": clickhouse_backup_ref,
        "postgres_ref": postgres_ref,
        "postgres_schema_hash": postgres_schema_hash,
        "postgres_backup_ref": postgres_backup_ref,
        "mtls_policy_ref": mtls_policy_ref,
        "auth_policy_ref": auth_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "admission_policy_ref": admission_policy_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "secret_store_ref": secret_store_ref,
        "kms_key_ref": kms_key_ref,
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "access_log_ref": access_log_ref,
        "access_log_root": access_log_root,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
    }.items():
        _require_text(value, field)
    for field, value in (
        ("service_image_digest", service_image_digest),
        ("service_binary_hash", service_binary_hash),
        ("lease_store_hash", lease_store_hash),
        ("checkpoint_store_hash", checkpoint_store_hash),
        ("clickhouse_schema_hash", clickhouse_schema_hash),
        ("postgres_schema_hash", postgres_schema_hash),
        ("audit_log_root", audit_log_root),
        ("access_log_root", access_log_root),
    ):
        if not _is_hash_ref(value):
            raise ValueError(f"{field} must be a sha256 reference")

    source = _source_record(storage_receipt)
    storage_binding = storage_receipt.get("worker_binding", {}) if isinstance(storage_receipt.get("worker_binding"), dict) else {}
    if runtime_worker_ref != storage_binding.get("worker_ref"):
        raise ValueError("runtime_worker_ref must match framework runtime worker ref")
    if stream_ref != storage_binding.get("stream_ref"):
        raise ValueError("stream_ref must match framework runtime worker stream_ref")
    if stream_topic != storage_binding.get("stream_topic"):
        raise ValueError("stream_topic must match framework runtime worker stream_topic")

    service = {
        "service_ref": service_ref,
        "version": service_version,
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "replicas_min": replicas_min,
        "replicas_max": replicas_max,
        "availability_zones": sorted(set(availability_zones or [])),
    }
    scheduler = {
        "runtime_worker_ref": runtime_worker_ref,
        "scheduler_ref": scheduler_ref,
        "cadence_seconds": schedule_cadence_seconds,
        "queue_ref": queue_ref,
        "dead_letter_queue_ref": dead_letter_queue_ref,
        "lease_store_ref": lease_store_ref,
        "lease_store_hash": lease_store_hash,
        "checkpoint_store_ref": checkpoint_store_ref,
        "checkpoint_store_hash": checkpoint_store_hash,
        "cursor_store_ref": cursor_store_ref,
        "idempotency_store_ref": idempotency_store_ref,
        "retry_policy_ref": retry_policy_ref,
        "max_concurrency": max_concurrency,
        "source_schedule_ref": storage_binding.get("schedule_ref"),
        "source_lease_ref": storage_binding.get("lease_ref"),
        "source_checkpoint_ref": storage_binding.get("checkpoint_ref"),
    }
    storage_backends = {
        "stream_backend": stream_backend,
        "stream_ref": stream_ref,
        "stream_topic": stream_topic,
        "stream_dlq_ref": stream_dlq_ref,
        "worm_store_ref": worm_store_ref,
        "object_lock_policy_ref": object_lock_policy_ref,
        "clickhouse_ref": clickhouse_ref,
        "clickhouse_schema_hash": clickhouse_schema_hash,
        "clickhouse_backup_ref": clickhouse_backup_ref,
        "postgres_ref": postgres_ref,
        "postgres_schema_hash": postgres_schema_hash,
        "postgres_backup_ref": postgres_backup_ref,
        "source_storage_receipt_id": storage_receipt.get("storage_receipt_id"),
        "source_export_hash": storage_receipt.get("provider_export", {}).get("hash") if isinstance(storage_receipt.get("provider_export"), dict) else None,
    }
    security = {
        "mtls_policy_ref": mtls_policy_ref,
        "auth_policy_ref": auth_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "admission_policy_ref": admission_policy_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "secret_store_ref": secret_store_ref,
        "kms_key_ref": kms_key_ref,
    }
    observability = {
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "access_log_ref": access_log_ref,
        "access_log_root": access_log_root,
        "retention_until": retention_until,
    }
    operation_actor = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_SERVICE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": source,
        "service": service,
        "scheduler": scheduler,
        "storage_backends": storage_backends,
        "security": security,
        "observability": observability,
        "operation_actor": operation_actor,
        "source_artifacts": _source_artifacts(
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
        "controls": _controls(service, scheduler, storage_backends, security, observability),
        "limitations": [
            "This attestation binds framework runtime receipt evidence to a hosted service control plane.",
            "It records service image and binary hashes, scheduler/queue/lease/checkpoint stores, stream/storage backends, tenant controls, metrics, alerting, and audit roots.",
            "It does not prove continuously operated production infrastructure unless paired with live orchestrator, scheduler, KMS, stream, database, and audit-log provider exports.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "framework_runtime_service": body}, key)],
    }


def verify_framework_runtime_service_attestation(
    attestation: dict[str, Any],
    *,
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
) -> FrameworkRuntimeServiceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != FRAMEWORK_RUNTIME_SERVICE_SCHEMA:
        errors.append(f"unsupported framework runtime service attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical framework runtime service attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime service attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "framework_runtime_service": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime service attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"framework runtime service attested_at invalid: {exc}")
        attested = None
    mode = attestation.get("mode")
    if mode not in FRAMEWORK_RUNTIME_SERVICE_MODES:
        errors.append("framework runtime service mode is unsupported")
    elif mode != "hosted-runtime-service":
        warnings.append(f"framework runtime service mode is {mode}; hosted runtime service operation is not claimed")

    _verify_service(attestation.get("service"), errors)
    _verify_scheduler(attestation.get("scheduler"), errors)
    _verify_storage_backends(attestation.get("storage_backends"), errors)
    _verify_required_object(attestation.get("security"), "security", errors)
    _verify_observability(attestation.get("observability"), attested, errors)
    _verify_actor(attestation.get("operation_actor"), errors)
    _verify_source(attestation, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace_payload, release, matrix, root, key, errors, warnings)

    controls = attestation.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("framework runtime service controls are required")
    _check_no_secret_values(attestation, errors)
    return FrameworkRuntimeServiceVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_runtime_service_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    *,
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
    result = verify_framework_runtime_service_attestation(
        attestation,
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
        raise ValueError("invalid framework runtime service attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "source": attestation.get("source"),
        "service": attestation.get("service"),
        "scheduler": attestation.get("scheduler"),
        "storage_backends": attestation.get("storage_backends"),
        "security": attestation.get("security"),
        "observability": attestation.get("observability"),
        "operation_actor": attestation.get("operation_actor"),
        "control_summary": _status_summary(attestation.get("controls", [])),
    }
    return chain.append(FRAMEWORK_RUNTIME_SERVICE_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _source_record(storage_receipt: dict[str, Any]) -> dict[str, Any]:
    binding = storage_receipt.get("worker_binding", {}) if isinstance(storage_receipt.get("worker_binding"), dict) else {}
    export = storage_receipt.get("provider_export", {}) if isinstance(storage_receipt.get("provider_export"), dict) else {}
    return {
        "storage_receipt_id": storage_receipt.get("storage_receipt_id"),
        "storage_receipt_hash": content_hash(storage_receipt),
        "storage_mode": storage_receipt.get("mode"),
        "storage_provider": storage_receipt.get("provider"),
        "provider_export_hash": export.get("hash"),
        "provider_export_ref": export.get("export_ref"),
        "stream_record_root": export.get("stream_record_root"),
        "storage_record_root": export.get("storage_record_root"),
        "scheduler_record_root": export.get("scheduler_record_root"),
        "worker_operation_id": binding.get("worker_operation_id"),
        "worker_operation_hash": binding.get("worker_operation_hash"),
        "runtime_audit_id": binding.get("runtime_audit_id"),
        "operation_ref": binding.get("operation_ref"),
        "framework": binding.get("framework"),
        "trace_id": binding.get("trace_id"),
        "runtime_instance_ref": binding.get("runtime_instance_ref"),
        "stream_ref": binding.get("stream_ref"),
        "stream_topic": binding.get("stream_topic"),
        "storage_object_hash": binding.get("storage_object_hash"),
        "clickhouse_batch_hash": binding.get("clickhouse_batch_hash"),
        "postgres_index_hash": binding.get("postgres_index_hash"),
        "control_index_hash": binding.get("control_index_hash"),
    }


def _source_artifacts(*sources: dict[str, Any]) -> list[dict[str, Any]]:
    names = (
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
    records: list[dict[str, Any]] = []
    for name, source in zip(names, sources):
        records.append({"type": name, "id": _source_id(source), "hash": content_hash(source)})
    return records


def _verify_source(
    attestation: dict[str, Any],
    storage_receipt: dict[str, Any] | None,
    storage_export: dict[str, Any] | None,
    worker: dict[str, Any] | None,
    runtime_audit: dict[str, Any] | None,
    audit_export: dict[str, Any] | None,
    operation: dict[str, Any] | None,
    trace_payload: dict[str, Any] | None,
    release: dict[str, Any] | None,
    matrix: dict[str, Any] | None,
    root: str | Path,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    source = attestation.get("source", {})
    if not isinstance(source, dict):
        errors.append("framework runtime service source must be an object")
        source = {}
    for field in ("storage_receipt_id", "storage_receipt_hash", "worker_operation_id", "runtime_audit_id", "provider_export_hash", "stream_record_root", "storage_record_root"):
        if not source.get(field):
            errors.append(f"framework runtime service source.{field} is required")
    if not all(item is not None for item in (storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace_payload, release, matrix)):
        warnings.append("framework runtime service source artifacts were not fully supplied; storage export replay was not performed")
        return
    result = verify_framework_runtime_storage_receipt(
        storage_receipt or {},
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
        errors.extend(f"framework runtime service storage source invalid: {error}" for error in result.errors)
    expected_source = _source_record(storage_receipt or {})
    if source != expected_source:
        errors.append("framework runtime service source summary does not match supplied storage receipt")
    expected_artifacts = _source_artifacts(storage_receipt or {}, storage_export or {}, worker or {}, runtime_audit or {}, audit_export or {}, operation or {}, trace_payload or {}, release or {}, matrix or {})
    if attestation.get("source_artifacts") != expected_artifacts:
        errors.append("framework runtime service source_artifacts do not match supplied source artifacts")


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service service must be an object")
        return
    for field in ("service_ref", "version", "service_image", "service_image_digest", "service_binary_hash"):
        if not value.get(field):
            errors.append(f"framework runtime service service.{field} is required")
    for field in ("service_image_digest", "service_binary_hash"):
        if value.get(field) and not _is_hash_ref(str(value.get(field))):
            errors.append(f"framework runtime service service.{field} must be a sha256 reference")
    replicas_min = value.get("replicas_min")
    replicas_max = value.get("replicas_max")
    if not isinstance(replicas_min, int) or replicas_min < 1:
        errors.append("framework runtime service replicas_min must be at least 1")
    if not isinstance(replicas_max, int) or not isinstance(replicas_min, int) or replicas_max < replicas_min:
        errors.append("framework runtime service replicas_max must be greater than or equal to replicas_min")
    if not isinstance(value.get("availability_zones", []), list):
        errors.append("framework runtime service availability_zones must be an array")


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service scheduler must be an object")
        return
    for field in ("runtime_worker_ref", "scheduler_ref", "queue_ref", "dead_letter_queue_ref", "lease_store_ref", "lease_store_hash", "checkpoint_store_ref", "checkpoint_store_hash", "cursor_store_ref", "idempotency_store_ref", "retry_policy_ref"):
        if not value.get(field):
            errors.append(f"framework runtime service scheduler.{field} is required")
    for field in ("lease_store_hash", "checkpoint_store_hash"):
        if value.get(field) and not _is_hash_ref(str(value.get(field))):
            errors.append(f"framework runtime service scheduler.{field} must be a sha256 reference")
    cadence = value.get("cadence_seconds")
    if not isinstance(cadence, int) or cadence < 1:
        errors.append("framework runtime service scheduler.cadence_seconds must be positive")
    max_concurrency = value.get("max_concurrency")
    if not isinstance(max_concurrency, int) or max_concurrency < 1:
        errors.append("framework runtime service scheduler.max_concurrency must be positive")


def _verify_storage_backends(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service storage_backends must be an object")
        return
    for field in ("stream_backend", "stream_ref", "stream_topic", "stream_dlq_ref", "worm_store_ref", "object_lock_policy_ref", "clickhouse_ref", "clickhouse_schema_hash", "clickhouse_backup_ref", "postgres_ref", "postgres_schema_hash", "postgres_backup_ref", "source_storage_receipt_id", "source_export_hash"):
        if not value.get(field):
            errors.append(f"framework runtime service storage_backends.{field} is required")
    for field in ("clickhouse_schema_hash", "postgres_schema_hash"):
        if value.get(field) and not _is_hash_ref(str(value.get(field))):
            errors.append(f"framework runtime service storage_backends.{field} must be a sha256 reference")


def _verify_required_object(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"framework runtime service {name} must be an object")
        return
    for field, item in value.items():
        if item in (None, ""):
            errors.append(f"framework runtime service {name}.{field} is required")


def _verify_observability(value: Any, attested: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service observability must be an object")
        return
    for field in ("metrics_ref", "alert_policy_ref", "audit_log_ref", "audit_log_root", "access_log_ref", "access_log_root", "retention_until"):
        if not value.get(field):
            errors.append(f"framework runtime service observability.{field} is required")
    for field in ("audit_log_root", "access_log_root"):
        if value.get(field) and not _is_hash_ref(str(value.get(field))):
            errors.append(f"framework runtime service observability.{field} must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("framework runtime service retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"framework runtime service retention_until invalid: {exc}")


def _verify_actor(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service operation_actor must be an object")
        return
    if not value.get("actor_ref"):
        errors.append("framework runtime service operation_actor.actor_ref is required")
    _verify_redacted_ref(value.get("credential"), "framework runtime service credential", errors)
    if not isinstance(value.get("evidence_refs", []), list):
        errors.append("framework runtime service operation_actor.evidence_refs must be an array")


def _controls(
    service: dict[str, Any],
    scheduler: dict[str, Any],
    storage_backends: dict[str, Any],
    security: dict[str, Any],
    observability: dict[str, Any],
) -> list[dict[str, Any]]:
    replica_ok = service.get("replicas_min", 0) >= 2 and len(service.get("availability_zones", [])) >= 2
    scheduler_ok = bool(scheduler.get("queue_ref") and scheduler.get("lease_store_ref") and scheduler.get("checkpoint_store_ref"))
    storage_ok = bool(storage_backends.get("stream_ref") and storage_backends.get("worm_store_ref") and storage_backends.get("clickhouse_ref") and storage_backends.get("postgres_ref"))
    security_ok = all(security.get(field) for field in ("mtls_policy_ref", "auth_policy_ref", "tenant_isolation_ref", "network_policy_ref", "egress_policy_ref", "kms_key_ref"))
    observability_ok = _is_hash_ref(str(observability.get("audit_log_root") or "")) and _is_hash_ref(str(observability.get("access_log_root") or ""))
    return [
        {"id": "framework-runtime-storage-source-replayed", "status": "passed", "description": "Service attestation is bound to a verified runtime storage export receipt."},
        {"id": "runtime-service-image-bound", "status": "passed" if _is_hash_ref(str(service.get("service_image_digest") or "")) and _is_hash_ref(str(service.get("service_binary_hash") or "")) else "failed", "description": "Runtime service image digest and binary hash are recorded."},
        {"id": "runtime-service-ha-replicas", "status": "passed" if replica_ok else "deferred", "description": "Runtime service records a multi-replica, multi-AZ floor."},
        {"id": "runtime-scheduler-queue-lease", "status": "passed" if scheduler_ok else "failed", "description": "Scheduler, queue, lease, checkpoint, cursor, idempotency, and retry controls are recorded."},
        {"id": "runtime-stream-storage-backends", "status": "passed" if storage_ok else "failed", "description": "Stream, WORM, ClickHouse, and Postgres backends are bound."},
        {"id": "runtime-service-security-controls", "status": "passed" if security_ok else "failed", "description": "mTLS, authz, tenant isolation, network, egress, secret store, and KMS refs are recorded."},
        {"id": "runtime-service-observability", "status": "passed" if observability_ok else "failed", "description": "Metrics, alerting, audit root, access root, and retention are recorded."},
    ]


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _source_id(source: dict[str, Any]) -> Any:
    for field in ("storage_receipt_id", "worker_operation_id", "runtime_audit_id", "operation_id", "release_id", "matrix_id"):
        if source.get(field):
            return source.get(field)
    return source.get("export_ref") or source.get("trace_id") or source.get("schema")


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"framework runtime service {field} is required")
    return value.strip()


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value.removeprefix("sha256:"))
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _redacted_ref(ref: str | None) -> dict[str, Any]:
    if not ref:
        raise ValueError("framework runtime service credential_ref is required")
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _check_no_secret_values(value: Any, errors: list[str], *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, item):
                    pass
                elif not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"framework runtime service secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    return key.endswith("_ref") and isinstance(value, str) and bool(value.strip())
