from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .collector_service import verify_collector_service_attestation
from .crypto import sign_value, verify_value

COLLECTOR_WORKER_SCHEMA = "trustai.collector-worker/0.1"
COLLECTOR_WORKER_ENTRY_TYPE = "collector.worker_recorded"
COLLECTOR_WORKER_MODES = {
    "local-reference",
    "hosted-worker",
    "ingest-worker",
    "streaming-worker",
    "production-design",
}
COLLECTOR_WORKER_OPERATION_KINDS = {
    "otlp_batch_ingest",
    "stream_publish",
    "clickhouse_flush",
    "postgres_index",
    "mcp_transcript_capture",
    "framework_event_capture",
    "provider_callback_capture",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class CollectorWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_collector_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("collector worker receipt must contain an object")
    return value


def write_collector_worker_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_collector_worker_receipt(
    service_attestation: dict[str, Any],
    topology: dict[str, Any],
    *,
    byoc_operator: dict[str, Any] | None = None,
    deployment_manifest: dict[str, Any] | None = None,
    worm_receipt: dict[str, Any] | None = None,
    legal_hold: dict[str, Any] | None = None,
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
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
    checkpoint_hash: str | None = None,
    previous_cursor_ref: str | None = None,
    next_cursor_ref: str | None = None,
    next_run_at: str | None = None,
    attempt: int = 1,
    max_attempts: int = 3,
    tenant_ref: str,
    trace_batch_ref: str,
    trace_batch_hash: str,
    source_endpoint_ref: str,
    received_span_count: int,
    accepted_span_count: int,
    rejected_span_count: int = 0,
    idempotency_key_hash: str,
    replay_cache_hit: bool = False,
    otlp_request_hash: str | None = None,
    otlp_response_status: int | None = None,
    otlp_response_hash: str | None = None,
    stream_ref: str,
    stream_topic: str,
    partition_ref: str | None = None,
    offset_start: int | None = None,
    offset_end: int | None = None,
    stream_message_ref: str,
    stream_message_hash: str,
    stream_dlq_ref: str | None = None,
    clickhouse_batch_ref: str,
    clickhouse_batch_hash: str,
    clickhouse_rows_written: int,
    postgres_index_ref: str,
    postgres_index_hash: str,
    postgres_rows_written: int,
    control_index_ref: str,
    control_index_hash: str,
    mcp_transcript_ref: str | None = None,
    mcp_transcript_hash: str | None = None,
    framework_hook_ref: str | None = None,
    framework_hook_hash: str | None = None,
    metrics_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    started_at: str,
    completed_at: str | None = None,
    error_ref: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in COLLECTOR_WORKER_MODES:
        raise ValueError(f"mode must be one of {sorted(COLLECTOR_WORKER_MODES)}")
    if operation_kind not in COLLECTOR_WORKER_OPERATION_KINDS:
        raise ValueError(f"operation_kind must be one of {sorted(COLLECTOR_WORKER_OPERATION_KINDS)}")
    if not isinstance(service_attestation, dict):
        raise ValueError("service_attestation must be an object")
    if not isinstance(topology, dict):
        raise ValueError("topology must be an object")

    for value, field in (
        (environment, "environment"),
        (worker_ref, "worker_ref"),
        (run_ref, "run_ref"),
        (actor_ref, "actor_ref"),
        (schedule_ref, "schedule_ref"),
        (lease_ref, "lease_ref"),
        (checkpoint_ref, "checkpoint_ref"),
        (tenant_ref, "tenant_ref"),
        (trace_batch_ref, "trace_batch_ref"),
        (trace_batch_hash, "trace_batch_hash"),
        (source_endpoint_ref, "source_endpoint_ref"),
        (idempotency_key_hash, "idempotency_key_hash"),
        (stream_ref, "stream_ref"),
        (stream_topic, "stream_topic"),
        (stream_message_ref, "stream_message_ref"),
        (stream_message_hash, "stream_message_hash"),
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
    for value, field in (
        (received_span_count, "received_span_count"),
        (accepted_span_count, "accepted_span_count"),
        (rejected_span_count, "rejected_span_count"),
        (clickhouse_rows_written, "clickhouse_rows_written"),
        (postgres_rows_written, "postgres_rows_written"),
    ):
        if not isinstance(value, int) or value < 0:
            raise ValueError(f"{field} must be a non-negative integer")
    if accepted_span_count + rejected_span_count > received_span_count:
        raise ValueError("accepted_span_count plus rejected_span_count cannot exceed received_span_count")
    if otlp_response_status is not None and (not isinstance(otlp_response_status, int) or otlp_response_status < 100 or otlp_response_status > 599):
        raise ValueError("otlp_response_status must be an HTTP status code")
    if offset_start is not None and (not isinstance(offset_start, int) or offset_start < 0):
        raise ValueError("offset_start must be a non-negative integer")
    if offset_end is not None and (not isinstance(offset_end, int) or offset_end < 0):
        raise ValueError("offset_end must be a non-negative integer")
    if offset_start is not None and offset_end is not None and offset_end < offset_start:
        raise ValueError("offset_end must be greater than or equal to offset_start")

    for field, value in (
        ("checkpoint_hash", checkpoint_hash),
        ("trace_batch_hash", trace_batch_hash),
        ("idempotency_key_hash", idempotency_key_hash),
        ("otlp_request_hash", otlp_request_hash),
        ("otlp_response_hash", otlp_response_hash),
        ("stream_message_hash", stream_message_hash),
        ("clickhouse_batch_hash", clickhouse_batch_hash),
        ("postgres_index_hash", postgres_index_hash),
        ("control_index_hash", control_index_hash),
        ("mcp_transcript_hash", mcp_transcript_hash),
        ("framework_hook_hash", framework_hook_hash),
        ("audit_log_root", audit_log_root),
    ):
        if value and not _is_sha256_ref(str(value)):
            raise ValueError(f"{field} must be a sha256 reference")

    service_result = verify_collector_service_attestation(
        service_attestation,
        topology,
        byoc_operator=byoc_operator,
        deployment_manifest=deployment_manifest,
        worm_receipt=worm_receipt,
        legal_hold=legal_hold,
        root=root,
        store=store,
        key=key,
    )
    if not service_result.ok:
        raise ValueError("invalid collector service source: " + "; ".join(service_result.errors))

    service = _service_record(service_attestation)
    source_artifacts = _source_artifacts(
        service_attestation=service_attestation,
        topology=topology,
        byoc_operator=byoc_operator,
        deployment_manifest=deployment_manifest,
        worm_receipt=worm_receipt,
        legal_hold=legal_hold,
    )
    source = _source_summary(source_artifacts)
    response_success = otlp_response_status is None or 200 <= otlp_response_status < 300
    success = not error_ref and response_success and rejected_span_count == 0
    body: dict[str, Any] = {
        "schema": COLLECTOR_WORKER_SCHEMA,
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
        "ingestion": {
            "tenant_ref": tenant_ref,
            "trace_batch_ref": trace_batch_ref,
            "trace_batch_hash": trace_batch_hash,
            "source_endpoint_ref": source_endpoint_ref,
            "received_span_count": received_span_count,
            "accepted_span_count": accepted_span_count,
            "rejected_span_count": rejected_span_count,
            "idempotency_key_hash": idempotency_key_hash,
            "replay_cache_hit": replay_cache_hit,
            "otlp_request_hash": otlp_request_hash,
            "otlp_response_status": otlp_response_status,
            "otlp_response_hash": otlp_response_hash,
        },
        "streaming": {
            "stream_ref": stream_ref,
            "topic": stream_topic,
            "partition_ref": partition_ref,
            "offset_start": offset_start,
            "offset_end": offset_end,
            "stream_message_ref": stream_message_ref,
            "stream_message_hash": stream_message_hash,
            "dead_letter_queue_ref": stream_dlq_ref,
        },
        "storage": {
            "clickhouse_batch_ref": clickhouse_batch_ref,
            "clickhouse_batch_hash": clickhouse_batch_hash,
            "clickhouse_rows_written": clickhouse_rows_written,
            "postgres_index_ref": postgres_index_ref,
            "postgres_index_hash": postgres_index_hash,
            "postgres_rows_written": postgres_rows_written,
            "control_index_ref": control_index_ref,
            "control_index_hash": control_index_hash,
            "mcp_transcript_ref": mcp_transcript_ref,
            "mcp_transcript_hash": mcp_transcript_hash,
            "framework_hook_ref": framework_hook_ref,
            "framework_hook_hash": framework_hook_hash,
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
        "controls": _controls(
            mode=mode,
            service=service,
            source=source,
            cadence_seconds=cadence_seconds,
            checkpoint_hash=checkpoint_hash,
            trace_batch_hash=trace_batch_hash,
            idempotency_key_hash=idempotency_key_hash,
            stream_message_hash=stream_message_hash,
            clickhouse_batch_hash=clickhouse_batch_hash,
            postgres_index_hash=postgres_index_hash,
            audit_log_root=audit_log_root,
            credential_ref=credential_ref,
            success=success,
        ),
        "limitations": [
            "This receipt records a collector worker operation and replays the signed collector service source.",
            "It binds scheduler, idempotency, stream offset, ClickHouse/Postgres write, MCP/framework capture, metrics, audit, and credential-redaction evidence.",
            "It stores trace batch hashes and references, not raw trace payloads.",
            "It does not claim a live continuously operated collector fleet unless backed by production scheduler, stream, storage, and immutable audit exports.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [sign_value({"worker_operation_id": worker_operation_id, "collector_worker": body}, key)],
    }


def verify_collector_worker_receipt(
    receipt: dict[str, Any],
    service_attestation: dict[str, Any] | None = None,
    topology: dict[str, Any] | None = None,
    *,
    byoc_operator: dict[str, Any] | None = None,
    deployment_manifest: dict[str, Any] | None = None,
    worm_receipt: dict[str, Any] | None = None,
    legal_hold: dict[str, Any] | None = None,
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
    key: str | None = None,
) -> CollectorWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != COLLECTOR_WORKER_SCHEMA:
        errors.append(f"unsupported collector worker schema: {receipt.get('schema')}")
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append("worker_operation_id does not match canonical collector worker body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("collector worker receipt must include at least one signature")
    else:
        signed_value = {"worker_operation_id": receipt.get("worker_operation_id"), "collector_worker": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("collector worker signature verification failed")

    try:
        recorded = parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"collector worker recorded_at invalid: {exc}")
        recorded = None

    mode = receipt.get("mode")
    if mode not in COLLECTOR_WORKER_MODES:
        errors.append("collector worker mode is unsupported")
    elif mode not in {"hosted-worker", "ingest-worker", "streaming-worker"}:
        warnings.append(f"collector worker mode is {mode}; continuously hosted collector worker operation is not claimed")

    _verify_service(receipt.get("service"), errors)
    _verify_source(receipt.get("source"), errors)
    _verify_worker(receipt.get("worker"), errors)
    _verify_scheduler(receipt.get("scheduler"), errors)
    _verify_ingestion(receipt.get("ingestion"), errors)
    _verify_streaming(receipt.get("streaming"), errors)
    _verify_storage(receipt.get("storage"), errors)
    _verify_observability(receipt.get("observability"), recorded, errors)
    _verify_redacted_ref(receipt.get("credential"), "collector worker credential", errors)
    _verify_source_artifacts(receipt.get("source_artifacts"), errors)
    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("collector worker controls are required")

    if service_attestation is None:
        warnings.append("collector service attestation artifact was not supplied; service hash was not replayed")
    else:
        _compare_source_hash(receipt, "collector-service-attestation", service_attestation, errors)
        service_hash = receipt.get("service", {}).get("attestation_hash") if isinstance(receipt.get("service"), dict) else None
        if service_hash != content_hash(service_attestation):
            errors.append("collector worker service.attestation_hash does not match supplied service attestation")
        service_result = verify_collector_service_attestation(
            service_attestation,
            topology,
            byoc_operator=byoc_operator,
            deployment_manifest=deployment_manifest,
            worm_receipt=worm_receipt,
            legal_hold=legal_hold,
            root=root,
            store=store,
            key=key,
        )
        if not service_result.ok:
            errors.extend(f"collector worker service source: {error}" for error in service_result.errors)
        warnings.extend(f"collector worker service source: {warning}" for warning in service_result.warnings)

    for source_type, source_value in (
        ("collector-topology", topology),
        ("byoc-operator-attestation", byoc_operator),
        ("deployment-manifest", deployment_manifest),
        ("worm-receipt", worm_receipt),
        ("legal-hold", legal_hold),
    ):
        if source_value is not None:
            _compare_source_hash(receipt, source_type, source_value, errors)

    _check_no_secret_values(receipt, errors)
    return CollectorWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_collector_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    service_attestation: dict[str, Any] | None = None,
    topology: dict[str, Any] | None = None,
    *,
    byoc_operator: dict[str, Any] | None = None,
    deployment_manifest: dict[str, Any] | None = None,
    worm_receipt: dict[str, Any] | None = None,
    legal_hold: dict[str, Any] | None = None,
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_collector_worker_receipt(
        receipt,
        service_attestation,
        topology,
        byoc_operator=byoc_operator,
        deployment_manifest=deployment_manifest,
        worm_receipt=worm_receipt,
        legal_hold=legal_hold,
        root=root,
        store=store,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid collector worker receipt: " + "; ".join(result.errors))
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
        "ingestion": receipt.get("ingestion"),
        "streaming": receipt.get("streaming"),
        "storage": receipt.get("storage"),
        "observability": receipt.get("observability"),
        "credential": receipt.get("credential"),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(COLLECTOR_WORKER_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("recorded_at"))


def _service_record(attestation: dict[str, Any]) -> dict[str, Any]:
    service = attestation.get("service", {}) if isinstance(attestation, dict) and isinstance(attestation.get("service"), dict) else {}
    streaming = attestation.get("streaming", {}) if isinstance(attestation, dict) and isinstance(attestation.get("streaming"), dict) else {}
    storage = attestation.get("storage", {}) if isinstance(attestation, dict) and isinstance(attestation.get("storage"), dict) else {}
    clickhouse = storage.get("clickhouse", {}) if isinstance(storage.get("clickhouse"), dict) else {}
    postgres = storage.get("postgres", {}) if isinstance(storage.get("postgres"), dict) else {}
    security = attestation.get("security", {}) if isinstance(attestation, dict) and isinstance(attestation.get("security"), dict) else {}
    mcp_proxy = attestation.get("mcp_proxy", {}) if isinstance(attestation, dict) and isinstance(attestation.get("mcp_proxy"), dict) else {}
    audit_log = attestation.get("audit_log", {}) if isinstance(attestation, dict) and isinstance(attestation.get("audit_log"), dict) else {}
    return {
        "attestation_id": attestation.get("attestation_id") if isinstance(attestation, dict) else None,
        "attestation_hash": content_hash(attestation) if isinstance(attestation, dict) else None,
        "mode": attestation.get("mode") if isinstance(attestation, dict) else None,
        "environment": attestation.get("environment") if isinstance(attestation, dict) else None,
        "service_ref": service.get("service_ref"),
        "service_version": service.get("version"),
        "collector_image_digest": service.get("collector_image_digest"),
        "stream_ref": streaming.get("stream_ref"),
        "stream_topic": streaming.get("topic"),
        "stream_dlq_ref": streaming.get("dead_letter_queue_ref"),
        "replay_cache_ref": security.get("replay_cache_ref"),
        "idempotency_store_ref": security.get("idempotency_store_ref"),
        "clickhouse_ref": clickhouse.get("ref"),
        "postgres_ref": postgres.get("ref"),
        "mcp_proxy_ref": mcp_proxy.get("proxy_ref"),
        "framework_hook_refs": mcp_proxy.get("framework_hook_refs"),
        "audit_log_root": audit_log.get("root"),
    }


def _source_artifacts(
    *,
    service_attestation: dict[str, Any] | None,
    topology: dict[str, Any] | None,
    byoc_operator: dict[str, Any] | None,
    deployment_manifest: dict[str, Any] | None,
    worm_receipt: dict[str, Any] | None,
    legal_hold: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for source_type, value in (
        ("collector-service-attestation", service_attestation),
        ("collector-topology", topology),
        ("byoc-operator-attestation", byoc_operator),
        ("deployment-manifest", deployment_manifest),
        ("worm-receipt", worm_receipt),
        ("legal-hold", legal_hold),
    ):
        if isinstance(value, dict):
            records.append({"type": source_type, "id": _source_id(value), "schema": value.get("schema"), "hash": content_hash(value)})
    return records


def _source_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_count": len(records),
        "source_hash": content_hash(records),
        "schemas": sorted({str(record.get("schema")) for record in records if record.get("schema")}),
        "required_types": sorted(record["type"] for record in records),
        "artifacts": records,
    }


def _source_id(value: dict[str, Any]) -> str | None:
    for field in (
        "attestation_id",
        "topology_id",
        "manifest_id",
        "receipt_id",
        "hold_id",
        "object_id",
        "entry_id",
        "id",
    ):
        if value.get(field):
            return str(value.get(field))
    return None


def _controls(
    *,
    mode: str,
    service: dict[str, Any],
    source: dict[str, Any],
    cadence_seconds: int,
    checkpoint_hash: str | None,
    trace_batch_hash: str,
    idempotency_key_hash: str,
    stream_message_hash: str,
    clickhouse_batch_hash: str,
    postgres_index_hash: str,
    audit_log_root: str,
    credential_ref: str,
    success: bool,
) -> list[dict[str, str]]:
    return [
        {
            "id": "collector-service-source-bound",
            "status": "worker-recorded" if source.get("source_count", 0) >= 2 and service.get("attestation_hash") else "planned-production",
            "description": "Worker run is bound to signed collector service and topology source hashes.",
        },
        {
            "id": "hosted-collector-worker-operation",
            "status": "worker-recorded" if mode in {"hosted-worker", "ingest-worker", "streaming-worker"} else "planned-production",
            "description": "Receipt records hosted collector worker operation only in worker modes.",
        },
        {
            "id": "collector-scheduler-lease-checkpoint",
            "status": "worker-recorded" if cadence_seconds > 0 and checkpoint_hash else "planned-production",
            "description": "Scheduler cadence, lease ownership, checkpoint reference, and checkpoint hash are bound.",
        },
        {
            "id": "trace-batch-idempotency",
            "status": "worker-recorded" if _is_sha256_ref(trace_batch_hash) and _is_sha256_ref(idempotency_key_hash) and service.get("idempotency_store_ref") else "planned-production",
            "description": "Trace batch and idempotency key hashes are bound to the service idempotency store.",
        },
        {
            "id": "streaming-bus-write",
            "status": "worker-recorded" if _is_sha256_ref(stream_message_hash) and service.get("stream_ref") else "planned-production",
            "description": "Stream target, topic, offsets, and message hash are bound.",
        },
        {
            "id": "trace-and-control-storage-writes",
            "status": "worker-recorded" if _is_sha256_ref(clickhouse_batch_hash) and _is_sha256_ref(postgres_index_hash) and service.get("clickhouse_ref") and service.get("postgres_ref") else "planned-production",
            "description": "ClickHouse trace-store and Postgres control-plane write hashes are bound.",
        },
        {
            "id": "collector-observability-audit",
            "status": "worker-recorded" if _is_sha256_ref(audit_log_root) else "planned-production",
            "description": "Metrics reference, immutable audit root, and retention window are bound.",
        },
        {
            "id": "redacted-worker-credential",
            "status": "worker-recorded" if credential_ref else "planned-production",
            "description": "Worker credential material is represented only by a redacted reference.",
        },
        {
            "id": "collector-worker-success-recorded",
            "status": "worker-recorded" if success else "failed",
            "description": "Worker outcome is explicitly recorded.",
        },
    ]


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector worker service must be an object")
        return
    for field in (
        "attestation_id",
        "attestation_hash",
        "mode",
        "environment",
        "service_ref",
        "service_version",
        "collector_image_digest",
        "stream_ref",
        "stream_topic",
        "stream_dlq_ref",
        "replay_cache_ref",
        "idempotency_store_ref",
        "clickhouse_ref",
        "postgres_ref",
        "mcp_proxy_ref",
        "audit_log_root",
    ):
        if value.get(field) in (None, ""):
            errors.append(f"collector worker service.{field} is required")
    for field in ("attestation_hash", "collector_image_digest", "audit_log_root"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"collector worker service.{field} must be a sha256 reference")


def _verify_source(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector worker source must be an object")
        return
    if value.get("source_count", 0) < 2:
        errors.append("collector worker source.source_count must include service and topology sources")
    if not _is_sha256_ref(str(value.get("source_hash") or "")):
        errors.append("collector worker source.source_hash must be a sha256 reference")
    required = value.get("required_types", [])
    if not isinstance(required, list) or "collector-service-attestation" not in required or "collector-topology" not in required:
        errors.append("collector worker source must include collector-service-attestation and collector-topology")


def _verify_worker(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector worker worker must be an object")
        return
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at"):
        if not value.get(field):
            errors.append(f"collector worker worker.{field} is required")
    if value.get("operation_kind") not in COLLECTOR_WORKER_OPERATION_KINDS:
        errors.append("collector worker worker.operation_kind is unsupported")
    try:
        started = parse_rfc3339(str(value.get("started_at") or ""))
        completed = parse_rfc3339(str(value.get("completed_at") or ""))
        if completed < started:
            errors.append("collector worker worker.completed_at must be at or after started_at")
    except ValueError as exc:
        errors.append(f"collector worker worker timestamp invalid: {exc}")
    if not isinstance(value.get("attempt"), int) or value.get("attempt") < 1:
        errors.append("collector worker worker.attempt must be a positive integer")
    if not isinstance(value.get("max_attempts"), int) or value.get("max_attempts") < value.get("attempt", 1):
        errors.append("collector worker worker.max_attempts must be greater than or equal to attempt")
    if value.get("success") is False and not value.get("error_ref"):
        errors.append("collector worker worker.error_ref is required when success is false")


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector worker scheduler must be an object")
        return
    for field in ("schedule_ref", "lease_ref", "checkpoint_ref"):
        if not value.get(field):
            errors.append(f"collector worker scheduler.{field} is required")
    if not isinstance(value.get("cadence_seconds"), int) or value.get("cadence_seconds") <= 0:
        errors.append("collector worker scheduler.cadence_seconds must be positive")
    if value.get("checkpoint_hash") and not _is_sha256_ref(str(value.get("checkpoint_hash"))):
        errors.append("collector worker scheduler.checkpoint_hash must be a sha256 reference")
    if value.get("next_run_at"):
        try:
            parse_rfc3339(str(value.get("next_run_at")))
        except ValueError as exc:
            errors.append(f"collector worker scheduler.next_run_at invalid: {exc}")


def _verify_ingestion(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector worker ingestion must be an object")
        return
    for field in ("tenant_ref", "trace_batch_ref", "trace_batch_hash", "source_endpoint_ref", "idempotency_key_hash"):
        if not value.get(field):
            errors.append(f"collector worker ingestion.{field} is required")
    for field in ("trace_batch_hash", "idempotency_key_hash", "otlp_request_hash", "otlp_response_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"collector worker ingestion.{field} must be a sha256 reference")
    for field in ("received_span_count", "accepted_span_count", "rejected_span_count"):
        if not isinstance(value.get(field), int) or value.get(field) < 0:
            errors.append(f"collector worker ingestion.{field} must be a non-negative integer")
    if isinstance(value.get("accepted_span_count"), int) and isinstance(value.get("rejected_span_count"), int) and isinstance(value.get("received_span_count"), int):
        if value["accepted_span_count"] + value["rejected_span_count"] > value["received_span_count"]:
            errors.append("collector worker ingestion accepted/rejected spans cannot exceed received spans")
    status = value.get("otlp_response_status")
    if status is not None and (not isinstance(status, int) or status < 100 or status > 599):
        errors.append("collector worker ingestion.otlp_response_status must be an HTTP status code")
    if not isinstance(value.get("replay_cache_hit"), bool):
        errors.append("collector worker ingestion.replay_cache_hit must be a boolean")


def _verify_streaming(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector worker streaming must be an object")
        return
    for field in ("stream_ref", "topic", "stream_message_ref", "stream_message_hash"):
        if not value.get(field):
            errors.append(f"collector worker streaming.{field} is required")
    if value.get("stream_message_hash") and not _is_sha256_ref(str(value.get("stream_message_hash"))):
        errors.append("collector worker streaming.stream_message_hash must be a sha256 reference")
    for field in ("offset_start", "offset_end"):
        if value.get(field) is not None and (not isinstance(value.get(field), int) or value.get(field) < 0):
            errors.append(f"collector worker streaming.{field} must be a non-negative integer")
    if isinstance(value.get("offset_start"), int) and isinstance(value.get("offset_end"), int) and value["offset_end"] < value["offset_start"]:
        errors.append("collector worker streaming.offset_end must be greater than or equal to offset_start")


def _verify_storage(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector worker storage must be an object")
        return
    for field in (
        "clickhouse_batch_ref",
        "clickhouse_batch_hash",
        "postgres_index_ref",
        "postgres_index_hash",
        "control_index_ref",
        "control_index_hash",
    ):
        if not value.get(field):
            errors.append(f"collector worker storage.{field} is required")
    for field in ("clickhouse_batch_hash", "postgres_index_hash", "control_index_hash", "mcp_transcript_hash", "framework_hook_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"collector worker storage.{field} must be a sha256 reference")
    for field in ("clickhouse_rows_written", "postgres_rows_written"):
        if not isinstance(value.get(field), int) or value.get(field) < 0:
            errors.append(f"collector worker storage.{field} must be a non-negative integer")


def _verify_observability(value: Any, recorded: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector worker observability must be an object")
        return
    for field in ("metrics_ref", "audit_log_ref", "audit_log_root", "retention_until"):
        if not value.get(field):
            errors.append(f"collector worker observability.{field} is required")
    if value.get("audit_log_root") and not _is_sha256_ref(str(value.get("audit_log_root"))):
        errors.append("collector worker observability.audit_log_root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if recorded and retention <= recorded:
            errors.append("collector worker observability.retention_until must be after recorded_at")
    except ValueError as exc:
        errors.append(f"collector worker observability.retention_until invalid: {exc}")
    if not isinstance(value.get("evidence_refs", []), list):
        errors.append("collector worker observability.evidence_refs must be a list")


def _verify_source_artifacts(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append("collector worker source_artifacts must be a non-empty list")
        return
    required_types = {item.get("type") for item in value if isinstance(item, dict)}
    for required in ("collector-service-attestation", "collector-topology"):
        if required not in required_types:
            errors.append(f"collector worker source_artifacts must include {required}")
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"collector worker source_artifacts[{index}] must be an object")
            continue
        if not item.get("type") or not item.get("hash"):
            errors.append(f"collector worker source_artifacts[{index}] type and hash are required")
        elif not _is_sha256_ref(str(item.get("hash"))):
            errors.append(f"collector worker source_artifacts[{index}].hash must be a sha256 reference")


def _compare_source_hash(receipt: dict[str, Any], source_type: str, value: dict[str, Any], errors: list[str]) -> None:
    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("collector worker source_artifacts must be a list")
        return
    actual = content_hash(value)
    if not any(isinstance(item, dict) and item.get("type") == source_type and item.get("hash") == actual for item in artifacts):
        errors.append(f"collector worker source_artifacts missing current hash for {source_type}")


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


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
                    errors.append(f"collector worker secret-like field must be redacted reference: {child_path}")
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
