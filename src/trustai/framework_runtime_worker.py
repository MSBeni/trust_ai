from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_runtime_audit import verify_framework_runtime_audit_receipt

FRAMEWORK_RUNTIME_WORKER_SCHEMA = "trustai.framework-runtime-worker/0.1"
FRAMEWORK_RUNTIME_WORKER_ENTRY_TYPE = "framework_runtime.worker_recorded"
FRAMEWORK_RUNTIME_WORKER_MODES = {"local-reference", "runtime-worker", "hosted-worker", "production-design"}
FRAMEWORK_RUNTIME_WORKER_OPERATION_KINDS = {
    "audit_export_reconcile",
    "hook_capture_ingest",
    "stream_storage_flush",
    "retry_reconcile",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")
SOURCE_SUMMARY_EXPECTED_FIELDS = (
    "runtime_audit_id",
    "runtime_audit_hash",
    "runtime_audit_mode",
    "provider",
    "exported_at",
    "operation_id",
    "operation_hash",
    "operation_ref",
    "framework",
    "trace_id",
    "runtime_instance_ref",
    "runtime_process_ref",
    "collector_hook_ref",
    "hook_release_hash",
    "source_trace_hash",
    "event_root",
    "trace_roots",
    "audit_export_ref",
    "audit_export_hash",
    "audit_event_root",
    "audit_log_ref",
    "audit_log_root",
    "window_start",
    "window_end",
    "cursor_ref",
    "next_cursor_ref",
    "matched_event_id",
    "matched_event_hash",
)
SOURCE_SUMMARY_REQUIRED_FIELDS = tuple(
    field for field in SOURCE_SUMMARY_EXPECTED_FIELDS if field != "runtime_process_ref"
)


@dataclass
class FrameworkRuntimeWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_runtime_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime worker receipt must contain an object")
    return value


def write_framework_runtime_worker_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_runtime_worker_receipt(
    runtime_audit: dict[str, Any],
    audit_export: dict[str, Any],
    operation: dict[str, Any],
    trace_payload: dict[str, Any],
    release: dict[str, Any],
    matrix: dict[str, Any],
    *,
    root: str | Path = ".",
    mode: str = "runtime-worker",
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
    stream_ref: str,
    stream_topic: str,
    partition_ref: str | None = None,
    offset_start: int | None = None,
    offset_end: int | None = None,
    stream_message_ref: str,
    stream_message_hash: str,
    stream_dlq_ref: str | None = None,
    storage_object_ref: str,
    storage_object_hash: str,
    clickhouse_batch_ref: str,
    clickhouse_batch_hash: str,
    clickhouse_rows_written: int,
    postgres_index_ref: str,
    postgres_index_hash: str,
    postgres_rows_written: int,
    control_index_ref: str,
    control_index_hash: str,
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
    if mode not in FRAMEWORK_RUNTIME_WORKER_MODES:
        raise ValueError(f"mode must be one of {sorted(FRAMEWORK_RUNTIME_WORKER_MODES)}")
    if operation_kind not in FRAMEWORK_RUNTIME_WORKER_OPERATION_KINDS:
        raise ValueError(f"operation_kind must be one of {sorted(FRAMEWORK_RUNTIME_WORKER_OPERATION_KINDS)}")
    for value, field in (
        (environment, "environment"),
        (worker_ref, "worker_ref"),
        (run_ref, "run_ref"),
        (actor_ref, "actor_ref"),
        (schedule_ref, "schedule_ref"),
        (lease_ref, "lease_ref"),
        (checkpoint_ref, "checkpoint_ref"),
        (stream_ref, "stream_ref"),
        (stream_topic, "stream_topic"),
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
    for value, field in (
        (clickhouse_rows_written, "clickhouse_rows_written"),
        (postgres_rows_written, "postgres_rows_written"),
    ):
        if not isinstance(value, int) or value < 0:
            raise ValueError(f"{field} must be a non-negative integer")
    if offset_start is not None and (not isinstance(offset_start, int) or offset_start < 0):
        raise ValueError("offset_start must be a non-negative integer")
    if offset_end is not None and (not isinstance(offset_end, int) or offset_end < 0):
        raise ValueError("offset_end must be a non-negative integer")
    if offset_start is not None and offset_end is not None and offset_end < offset_start:
        raise ValueError("offset_end must be greater than or equal to offset_start")
    for field, value in (
        ("checkpoint_hash", checkpoint_hash),
        ("stream_message_hash", stream_message_hash),
        ("storage_object_hash", storage_object_hash),
        ("clickhouse_batch_hash", clickhouse_batch_hash),
        ("postgres_index_hash", postgres_index_hash),
        ("control_index_hash", control_index_hash),
        ("audit_log_root", audit_log_root),
    ):
        if value and not _is_hash_ref(str(value)):
            raise ValueError(f"{field} must be a sha256 reference")

    result = verify_framework_runtime_audit_receipt(
        runtime_audit,
        audit_export=audit_export,
        operation=operation,
        trace_payload=trace_payload,
        release=release,
        matrix=matrix,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid framework runtime audit source: " + "; ".join(result.errors))

    source = _source_record(runtime_audit)
    success = not error_ref
    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_WORKER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": completed,
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
        "runtime": {
            "provider": source.get("provider"),
            "framework": source.get("framework"),
            "runtime_instance_ref": source.get("runtime_instance_ref"),
            "runtime_process_ref": source.get("runtime_process_ref"),
            "operation_ref": source.get("operation_ref"),
            "trace_id": source.get("trace_id"),
            "collector_hook_ref": source.get("collector_hook_ref"),
            "hook_release_hash": source.get("hook_release_hash"),
        },
        "stream": {
            "stream_ref": stream_ref,
            "stream_topic": stream_topic,
            "partition_ref": partition_ref,
            "offset_start": offset_start,
            "offset_end": offset_end,
            "stream_message_ref": stream_message_ref,
            "stream_message_hash": stream_message_hash,
            "stream_dlq_ref": stream_dlq_ref,
            "runtime_export_ref": source.get("audit_export_ref"),
            "runtime_event_ref": source.get("matched_event_id"),
            "runtime_audit_log_ref": source.get("audit_log_ref"),
            "runtime_audit_log_root": source.get("audit_log_root"),
        },
        "storage": {
            "storage_object_ref": storage_object_ref,
            "storage_object_hash": storage_object_hash,
            "clickhouse_batch_ref": clickhouse_batch_ref,
            "clickhouse_batch_hash": clickhouse_batch_hash,
            "clickhouse_rows_written": clickhouse_rows_written,
            "postgres_index_ref": postgres_index_ref,
            "postgres_index_hash": postgres_index_hash,
            "postgres_rows_written": postgres_rows_written,
            "control_index_ref": control_index_ref,
            "control_index_hash": control_index_hash,
        },
        "observability": {
            "metrics_ref": metrics_ref,
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "retention_until": retention_until,
            "evidence_refs": _normalized_list(evidence_refs),
        },
        "credential": _redacted_ref(credential_ref),
        "controls": _controls(
            mode=mode,
            source=source,
            schedule_ref=schedule_ref,
            lease_ref=lease_ref,
            checkpoint_ref=checkpoint_ref,
            next_cursor_ref=next_cursor_ref,
            stream_message_hash=stream_message_hash,
            storage_object_hash=storage_object_hash,
            clickhouse_batch_hash=clickhouse_batch_hash,
            postgres_index_hash=postgres_index_hash,
            control_index_hash=control_index_hash,
            audit_log_root=audit_log_root,
        ),
        "limitations": [
            "This receipt records a framework runtime worker run that processed a verified runtime audit export into stream and storage evidence.",
            "It stores scheduler, stream, storage, metrics, audit-root, and source receipt hashes, not provider credentials or raw audit export bodies.",
            "It proves continuously operated production runtime processing only when paired with live scheduler/lease storage, provider stream/storage exports, and immutable production audit logs.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [sign_value({"worker_operation_id": worker_operation_id, "framework_runtime_worker": body}, key)],
    }


def verify_framework_runtime_worker_receipt(
    receipt: dict[str, Any],
    *,
    runtime_audit: dict[str, Any] | None = None,
    audit_export: dict[str, Any] | None = None,
    operation: dict[str, Any] | None = None,
    trace_payload: dict[str, Any] | None = None,
    release: dict[str, Any] | None = None,
    matrix: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> FrameworkRuntimeWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != FRAMEWORK_RUNTIME_WORKER_SCHEMA:
        errors.append(f"unsupported framework runtime worker schema: {receipt.get('schema')}")
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append("worker_operation_id does not match canonical framework runtime worker body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime worker receipt must include at least one signature")
    else:
        signed_value = {"worker_operation_id": receipt.get("worker_operation_id"), "framework_runtime_worker": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime worker signature verification failed")

    mode = receipt.get("mode")
    if mode not in FRAMEWORK_RUNTIME_WORKER_MODES:
        errors.append("framework runtime worker mode is unsupported")
    elif mode not in {"runtime-worker", "hosted-worker"}:
        warnings.append(f"framework runtime worker mode is {mode}; continuously operated runtime worker is not claimed")

    try:
        parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"framework runtime worker recorded_at invalid: {exc}")

    _verify_source(receipt.get("source"), runtime_audit, audit_export, operation, trace_payload, release, matrix, root, key, errors, warnings)
    _verify_worker(receipt.get("worker"), errors)
    _verify_scheduler(receipt.get("scheduler"), errors)
    _verify_runtime(receipt.get("runtime"), receipt.get("source"), errors)
    _verify_stream(receipt.get("stream"), receipt.get("source"), errors)
    _verify_storage(receipt.get("storage"), errors)
    _verify_observability(receipt.get("observability"), receipt.get("worker"), errors)
    _verify_redacted_ref(receipt.get("credential"), "framework runtime worker credential", errors)
    controls = receipt.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("framework runtime worker controls are required")
    _check_no_secret_values(receipt, errors)
    return FrameworkRuntimeWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_runtime_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    runtime_audit: dict[str, Any],
    audit_export: dict[str, Any],
    operation: dict[str, Any],
    trace_payload: dict[str, Any],
    release: dict[str, Any],
    matrix: dict[str, Any],
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_framework_runtime_worker_receipt(
        receipt,
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
        raise ValueError("invalid framework runtime worker receipt: " + "; ".join(result.errors))
    payload = {
        "worker_operation_id": receipt["worker_operation_id"],
        "worker_operation_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "source": receipt.get("source"),
        "worker": receipt.get("worker"),
        "scheduler": receipt.get("scheduler"),
        "runtime": receipt.get("runtime"),
        "stream": receipt.get("stream"),
        "storage": receipt.get("storage"),
        "observability": receipt.get("observability"),
        "credential": receipt.get("credential"),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(FRAMEWORK_RUNTIME_WORKER_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("recorded_at"))


def _source_record(runtime_audit: dict[str, Any]) -> dict[str, Any]:
    binding = runtime_audit.get("operation_binding", {}) if isinstance(runtime_audit.get("operation_binding"), dict) else {}
    export = runtime_audit.get("audit_export", {}) if isinstance(runtime_audit.get("audit_export"), dict) else {}
    matched = runtime_audit.get("matched_event", {}) if isinstance(runtime_audit.get("matched_event"), dict) else {}
    return {
        "runtime_audit_id": runtime_audit.get("runtime_audit_id"),
        "runtime_audit_hash": content_hash(runtime_audit),
        "runtime_audit_mode": runtime_audit.get("mode"),
        "provider": runtime_audit.get("provider"),
        "exported_at": runtime_audit.get("exported_at"),
        "operation_id": binding.get("operation_id"),
        "operation_hash": binding.get("operation_hash"),
        "operation_ref": binding.get("operation_ref"),
        "framework": binding.get("framework"),
        "trace_id": binding.get("trace_id"),
        "runtime_instance_ref": binding.get("runtime_instance_ref"),
        "runtime_process_ref": binding.get("runtime_process_ref"),
        "collector_hook_ref": binding.get("collector_hook_ref"),
        "hook_release_hash": binding.get("hook_release_hash"),
        "source_trace_hash": binding.get("source_trace_hash"),
        "event_root": binding.get("event_root"),
        "trace_roots": _normalized_list(binding.get("trace_roots")),
        "audit_export_ref": export.get("export_ref"),
        "audit_export_hash": export.get("hash"),
        "audit_event_root": export.get("event_root"),
        "audit_log_ref": export.get("audit_log_ref"),
        "audit_log_root": export.get("audit_log_root"),
        "window_start": export.get("window_start"),
        "window_end": export.get("window_end"),
        "cursor_ref": export.get("cursor_ref"),
        "next_cursor_ref": export.get("next_cursor_ref"),
        "matched_event_id": matched.get("event_id"),
        "matched_event_hash": matched.get("event_hash"),
    }


def _verify_source(
    value: Any,
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
    if not isinstance(value, dict):
        errors.append("framework runtime worker source must be an object")
        value = {}
    for field in SOURCE_SUMMARY_EXPECTED_FIELDS:
        if field not in value:
            errors.append(f"framework runtime worker source.{field} is required")
    for field in SOURCE_SUMMARY_REQUIRED_FIELDS:
        if value.get(field) in (None, "", [], {}):
            errors.append(f"framework runtime worker source.{field} is required")
    if "trace_roots" in value and not isinstance(value.get("trace_roots"), list):
        errors.append("framework runtime worker source.trace_roots must be an array")
    missing_sources = [
        source_type
        for source_type, source_value in (
            ("framework-runtime-audit", runtime_audit),
            ("framework-runtime-audit-export", audit_export),
            ("framework-hook-operation", operation),
            ("framework-trace", trace_payload),
            ("framework-hook-release", release),
            ("framework-adapter-matrix", matrix),
        )
        if source_value is None
    ]
    if missing_sources:
        errors.append("framework runtime worker source artifacts are required for verification: " + ", ".join(missing_sources))
        return
    result = verify_framework_runtime_audit_receipt(
        runtime_audit or {},
        audit_export=audit_export,
        operation=operation,
        trace_payload=trace_payload,
        release=release,
        matrix=matrix,
        root=root,
        key=key,
    )
    if not result.ok:
        errors.extend(f"framework runtime worker runtime audit invalid: {error}" for error in result.errors)
    expected = _source_record(runtime_audit or {})
    if value != expected:
        errors.append("framework runtime worker source binding does not match supplied runtime audit receipt")


def _verify_worker(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime worker worker must be an object")
        return
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at", "attempt", "max_attempts", "success"):
        if value.get(field) in (None, ""):
            errors.append(f"framework runtime worker worker.{field} is required")
    if value.get("operation_kind") not in FRAMEWORK_RUNTIME_WORKER_OPERATION_KINDS:
        errors.append(f"framework runtime worker operation kind unsupported: {value.get('operation_kind')}")
    try:
        started = parse_rfc3339(str(value.get("started_at") or ""))
        completed = parse_rfc3339(str(value.get("completed_at") or ""))
        if completed < started:
            errors.append("framework runtime worker completed_at must be at or after started_at")
    except ValueError as exc:
        errors.append(f"framework runtime worker timestamp invalid: {exc}")
    attempt = value.get("attempt")
    max_attempts = value.get("max_attempts")
    if not isinstance(attempt, int) or attempt < 1:
        errors.append("framework runtime worker attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < (attempt if isinstance(attempt, int) else 1):
        errors.append("framework runtime worker max_attempts must be greater than or equal to attempt")
    if not isinstance(value.get("success"), bool):
        errors.append("framework runtime worker success must be a boolean")
    if value.get("error_ref") and value.get("success") is True:
        errors.append("framework runtime worker success cannot be true when error_ref is set")


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime worker scheduler must be an object")
        return
    for field in ("schedule_ref", "cadence_seconds", "lease_ref", "checkpoint_ref"):
        if value.get(field) in (None, ""):
            errors.append(f"framework runtime worker scheduler.{field} is required")
    cadence_seconds = value.get("cadence_seconds")
    if not isinstance(cadence_seconds, int) or cadence_seconds <= 0:
        errors.append("framework runtime worker scheduler.cadence_seconds must be a positive integer")
    if value.get("checkpoint_hash") and not _is_hash_ref(str(value.get("checkpoint_hash"))):
        errors.append("framework runtime worker scheduler.checkpoint_hash must be a sha256 reference")
    if value.get("next_run_at"):
        try:
            parse_rfc3339(str(value.get("next_run_at")))
        except ValueError as exc:
            errors.append(f"framework runtime worker scheduler.next_run_at invalid: {exc}")


def _verify_runtime(value: Any, source: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime worker runtime must be an object")
        return
    source = source if isinstance(source, dict) else {}
    for field in ("provider", "framework", "runtime_instance_ref", "operation_ref", "trace_id", "collector_hook_ref"):
        if not value.get(field):
            errors.append(f"framework runtime worker runtime.{field} is required")
        elif source.get(field) and value.get(field) != source.get(field):
            errors.append(f"framework runtime worker runtime.{field} does not match source binding")
    for field in ("runtime_process_ref", "hook_release_hash"):
        if source.get(field) and value.get(field) != source.get(field):
            errors.append(f"framework runtime worker runtime.{field} does not match source binding")


def _verify_stream(value: Any, source: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime worker stream must be an object")
        return
    source = source if isinstance(source, dict) else {}
    for field in ("stream_ref", "stream_topic", "stream_message_ref", "stream_message_hash", "runtime_event_ref", "runtime_audit_log_ref", "runtime_audit_log_root"):
        if not value.get(field):
            errors.append(f"framework runtime worker stream.{field} is required")
    if value.get("stream_message_hash") and not _is_hash_ref(str(value.get("stream_message_hash"))):
        errors.append("framework runtime worker stream.stream_message_hash must be a sha256 reference")
    if value.get("runtime_audit_log_root") and not _is_hash_ref(str(value.get("runtime_audit_log_root"))):
        errors.append("framework runtime worker stream.runtime_audit_log_root must be a sha256 reference")
    for field, source_field in (
        ("runtime_export_ref", "audit_export_ref"),
        ("runtime_event_ref", "matched_event_id"),
        ("runtime_audit_log_ref", "audit_log_ref"),
        ("runtime_audit_log_root", "audit_log_root"),
    ):
        if source.get(source_field) and value.get(field) != source.get(source_field):
            errors.append(f"framework runtime worker stream.{field} does not match source binding")
    offset_start = value.get("offset_start")
    offset_end = value.get("offset_end")
    if offset_start is not None and (not isinstance(offset_start, int) or offset_start < 0):
        errors.append("framework runtime worker stream.offset_start must be a non-negative integer")
    if offset_end is not None and (not isinstance(offset_end, int) or offset_end < 0):
        errors.append("framework runtime worker stream.offset_end must be a non-negative integer")
    if isinstance(offset_start, int) and isinstance(offset_end, int) and offset_end < offset_start:
        errors.append("framework runtime worker stream.offset_end must be greater than or equal to offset_start")


def _verify_storage(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime worker storage must be an object")
        return
    for field in ("storage_object_ref", "storage_object_hash", "clickhouse_batch_ref", "clickhouse_batch_hash", "clickhouse_rows_written", "postgres_index_ref", "postgres_index_hash", "postgres_rows_written", "control_index_ref", "control_index_hash"):
        if value.get(field) in (None, ""):
            errors.append(f"framework runtime worker storage.{field} is required")
    for field in ("storage_object_hash", "clickhouse_batch_hash", "postgres_index_hash", "control_index_hash"):
        if value.get(field) and not _is_hash_ref(str(value.get(field))):
            errors.append(f"framework runtime worker storage.{field} must be a sha256 reference")
    for field in ("clickhouse_rows_written", "postgres_rows_written"):
        if not isinstance(value.get(field), int) or value.get(field) < 0:
            errors.append(f"framework runtime worker storage.{field} must be a non-negative integer")


def _verify_observability(value: Any, worker: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime worker observability must be an object")
        return
    for field in ("metrics_ref", "audit_log_ref", "audit_log_root", "retention_until"):
        if not value.get(field):
            errors.append(f"framework runtime worker observability.{field} is required")
    if value.get("audit_log_root") and not _is_hash_ref(str(value.get("audit_log_root"))):
        errors.append("framework runtime worker observability.audit_log_root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        completed = parse_rfc3339(str((worker if isinstance(worker, dict) else {}).get("completed_at") or ""))
        if retention <= completed:
            errors.append("framework runtime worker observability.retention_until must be after completed_at")
    except ValueError as exc:
        errors.append(f"framework runtime worker observability timestamp invalid: {exc}")
    if not isinstance(value.get("evidence_refs", []), list):
        errors.append("framework runtime worker observability.evidence_refs must be an array")


def _controls(
    *,
    mode: str,
    source: dict[str, Any],
    schedule_ref: str,
    lease_ref: str,
    checkpoint_ref: str,
    next_cursor_ref: str | None,
    stream_message_hash: str,
    storage_object_hash: str,
    clickhouse_batch_hash: str,
    postgres_index_hash: str,
    control_index_hash: str,
    audit_log_root: str,
) -> list[dict[str, Any]]:
    storage_bound = all(_is_hash_ref(value) for value in (storage_object_hash, clickhouse_batch_hash, postgres_index_hash, control_index_hash))
    production = mode in {"runtime-worker", "hosted-worker"} and storage_bound and _is_hash_ref(audit_log_root)
    return [
        {
            "id": "runtime-audit-source-replayed",
            "status": "passed" if source.get("runtime_audit_id") and source.get("runtime_audit_hash") else "failed",
            "description": "Worker receipt is bound to a verified framework runtime audit receipt.",
        },
        {
            "id": "scheduler-lease-checkpoint",
            "status": "passed" if schedule_ref and lease_ref and checkpoint_ref else "failed",
            "description": "Worker run records scheduler cadence, lease, and checkpoint references.",
        },
        {
            "id": "cursor-continuity",
            "status": "passed" if source.get("cursor_ref") and next_cursor_ref else "deferred",
            "description": "Source export cursor and worker next cursor are recorded for replay continuity.",
        },
        {
            "id": "runtime-stream-message-bound",
            "status": "passed" if _is_hash_ref(stream_message_hash) else "failed",
            "description": "Runtime audit event processing is bound to a stream message hash.",
        },
        {
            "id": "provider-stream-storage-bound",
            "status": "passed" if storage_bound else "failed",
            "description": "Runtime export object, ClickHouse batch, Postgres index, and control index hashes are recorded.",
        },
        {
            "id": "immutable-worker-audit-root",
            "status": "passed" if _is_hash_ref(audit_log_root) and _is_hash_ref(str(source.get("audit_log_root") or "")) else "failed",
            "description": "Worker audit root and runtime audit-log root are hash-bound.",
        },
        {
            "id": "production-runtime-worker-authority",
            "status": "passed" if production else "deferred",
            "description": "Continuous runtime worker authority is claimed only when worker mode and storage/audit evidence are present.",
        },
    ]


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"framework runtime worker {field} is required")
    return value.strip()


def _normalized_list(values: Any) -> list[str]:
    if not values:
        return []
    if not isinstance(values, list):
        raise ValueError("framework runtime worker list fields must be arrays")
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value.removeprefix("sha256:"))
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _redacted_ref(ref: str | None) -> dict[str, Any]:
    if not ref:
        raise ValueError("framework runtime worker credential_ref is required")
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
                    errors.append(f"framework runtime worker secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    return key.endswith("_ref") and isinstance(value, str) and bool(value.strip())
