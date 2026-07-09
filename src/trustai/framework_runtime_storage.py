from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_runtime_worker import verify_framework_runtime_worker_receipt

FRAMEWORK_RUNTIME_STORAGE_SCHEMA = "trustai.framework-runtime-storage/0.1"
FRAMEWORK_RUNTIME_STORAGE_ENTRY_TYPE = "framework_runtime.storage_exported"
FRAMEWORK_RUNTIME_STORAGE_MODES = {"local-export", "provider-export", "production-export"}
REQUIRED_STORAGE_KINDS = {"worm_object", "clickhouse_batch", "postgres_index", "control_index"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class FrameworkRuntimeStorageVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_runtime_storage_export(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime storage export must contain an object")
    return value


def load_framework_runtime_storage_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime storage receipt must contain an object")
    return value


def write_framework_runtime_storage_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_runtime_storage_receipt(
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
    mode: str = "provider-export",
    environment: str = "local",
    provider: str,
    endpoint_url: str,
    credential_ref: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    actor_ref: str,
    exported_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in FRAMEWORK_RUNTIME_STORAGE_MODES:
        raise ValueError(f"mode must be one of {sorted(FRAMEWORK_RUNTIME_STORAGE_MODES)}")
    normalized_provider = _require_provider(provider)
    for value, field in (
        (environment, "environment"),
        (endpoint_url, "endpoint_url"),
        (credential_ref, "credential_ref"),
        (request_hash, "request_hash"),
        (response_hash, "response_hash"),
        (actor_ref, "actor_ref"),
    ):
        _require_text(value, field)
    if not isinstance(response_status, int):
        raise ValueError("framework runtime storage response_status must be an integer")
    timestamp = exported_at or utc_now()
    parse_rfc3339(timestamp)

    worker_result = verify_framework_runtime_worker_receipt(
        worker,
        runtime_audit=runtime_audit,
        audit_export=audit_export,
        operation=operation,
        trace_payload=trace_payload,
        release=release,
        matrix=matrix,
        root=root,
        key=key,
    )
    if not worker_result.ok:
        raise ValueError("invalid framework runtime worker source: " + "; ".join(worker_result.errors))

    stream_records = _records(storage_export, "stream_records")
    storage_records = _records(storage_export, "storage_records")
    scheduler_records = _records(storage_export, "scheduler_records")
    if not stream_records:
        raise ValueError("framework runtime storage export must contain stream_records")
    if not storage_records:
        raise ValueError("framework runtime storage export must contain storage_records")
    window_start = _require_text(storage_export.get("window_start"), "storage_export.window_start")
    window_end = _require_text(storage_export.get("window_end"), "storage_export.window_end")
    start = parse_rfc3339(window_start)
    end = parse_rfc3339(window_end)
    if end < start:
        raise ValueError("framework runtime storage export window_end must be at or after window_start")
    audit_log_ref = _require_text(storage_export.get("audit_log_ref"), "storage_export.audit_log_ref")
    audit_log_root = _require_text(storage_export.get("audit_log_root"), "storage_export.audit_log_root")

    binding = _worker_binding(worker)
    matched_stream = _matching_stream_record(stream_records, binding)
    matched_storage = _matching_storage_records(storage_records, binding)
    matched_scheduler = _matching_scheduler_record(scheduler_records, binding)
    _validate_stream_record(matched_stream, binding)
    _validate_storage_records(matched_storage, binding)
    _validate_scheduler_record(matched_scheduler, binding)

    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_STORAGE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "exported_at": timestamp,
        "provider": normalized_provider,
        "worker_binding": binding,
        "provider_export": {
            "export_ref": storage_export.get("export_ref"),
            "schema": storage_export.get("schema"),
            "provider": _normalize_provider(storage_export.get("provider")),
            "environment": storage_export.get("environment"),
            "window_start": window_start,
            "window_end": window_end,
            "cursor_ref": storage_export.get("cursor_ref"),
            "next_cursor_ref": storage_export.get("next_cursor_ref"),
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "hash": content_hash(storage_export),
            "stream_record_count": len(stream_records),
            "stream_record_root": content_hash(stream_records),
            "storage_record_count": len(storage_records),
            "storage_record_root": content_hash(storage_records),
            "scheduler_record_count": len(scheduler_records),
            "scheduler_record_root": content_hash(scheduler_records),
        },
        "matched_stream_record": _stream_record_summary(matched_stream),
        "matched_storage_records": [_storage_record_summary(record) for record in matched_storage],
        "matched_scheduler_record": _scheduler_record_summary(matched_scheduler),
        "provider_exchange": {
            "endpoint_url": endpoint_url,
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
            "success": 200 <= response_status < 300,
            "actor_ref": actor_ref,
        },
        "credential": _redacted_ref(credential_ref),
        "controls": _controls(
            mode=mode,
            endpoint_url=endpoint_url,
            request_hash=request_hash,
            response_status=response_status,
            response_hash=response_hash,
            matched_storage=matched_storage,
            matched_scheduler=matched_scheduler,
            audit_log_root=audit_log_root,
        ),
        "limitations": [
            "This receipt binds a verified framework runtime worker to provider-native stream and storage export records.",
            "It stores provider export hashes, record roots, matched stream/storage/scheduler record hashes, and endpoint evidence, not raw provider credentials or database contents.",
            "It does not prove continuously operated production storage authority unless mode is production-export and paired with live provider-owned export evidence.",
        ],
    }
    storage_receipt_id = content_hash(body)
    return {
        **body,
        "storage_receipt_id": storage_receipt_id,
        "signatures": [sign_value({"storage_receipt_id": storage_receipt_id, "framework_runtime_storage": body}, key)],
    }


def verify_framework_runtime_storage_receipt(
    receipt: dict[str, Any],
    *,
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
) -> FrameworkRuntimeStorageVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != FRAMEWORK_RUNTIME_STORAGE_SCHEMA:
        errors.append(f"unsupported framework runtime storage schema: {receipt.get('schema')}")
    body = without_keys(receipt, "storage_receipt_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("storage_receipt_id") != expected_id:
        errors.append("storage_receipt_id does not match canonical framework runtime storage body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime storage receipt must include at least one signature")
    else:
        signed_value = {"storage_receipt_id": receipt.get("storage_receipt_id"), "framework_runtime_storage": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime storage signature verification failed")

    mode = receipt.get("mode")
    if mode not in FRAMEWORK_RUNTIME_STORAGE_MODES:
        errors.append("framework runtime storage mode is unsupported")
    elif mode != "production-export":
        warnings.append(f"framework runtime storage mode is {mode}; live provider-owned stream/storage export is not claimed")
    try:
        parse_rfc3339(str(receipt.get("exported_at") or ""))
    except ValueError as exc:
        errors.append(f"framework runtime storage exported_at invalid: {exc}")
    if not _normalize_provider(receipt.get("provider")):
        errors.append("framework runtime storage provider is required")

    worker_binding = receipt.get("worker_binding", {})
    if not isinstance(worker_binding, dict):
        errors.append("framework runtime storage worker_binding must be an object")
        worker_binding = {}
    _verify_worker_binding(worker_binding, worker, runtime_audit, audit_export, operation, trace_payload, release, matrix, root, key, errors, warnings)
    _verify_provider_export_binding(receipt, storage_export, worker_binding, errors, warnings)
    _verify_provider_exchange(receipt.get("provider_exchange"), errors)
    _verify_redacted_ref(receipt.get("credential"), "framework runtime storage credential", errors)
    controls = receipt.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("framework runtime storage controls are required")
    _check_no_secret_values(receipt, errors)
    return FrameworkRuntimeStorageVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_runtime_storage_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
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
    result = verify_framework_runtime_storage_receipt(
        receipt,
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
        raise ValueError("invalid framework runtime storage receipt: " + "; ".join(result.errors))
    payload = {
        "storage_receipt_id": receipt["storage_receipt_id"],
        "storage_receipt_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "exported_at": receipt.get("exported_at"),
        "provider": receipt.get("provider"),
        "worker_binding": receipt.get("worker_binding"),
        "provider_export": receipt.get("provider_export"),
        "matched_stream_record": receipt.get("matched_stream_record"),
        "matched_storage_records": receipt.get("matched_storage_records"),
        "matched_scheduler_record": receipt.get("matched_scheduler_record"),
        "provider_exchange": receipt.get("provider_exchange"),
        "credential": receipt.get("credential"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(FRAMEWORK_RUNTIME_STORAGE_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("exported_at"))


def _worker_binding(worker: dict[str, Any]) -> dict[str, Any]:
    source = worker.get("source", {}) if isinstance(worker.get("source"), dict) else {}
    worker_record = worker.get("worker", {}) if isinstance(worker.get("worker"), dict) else {}
    scheduler = worker.get("scheduler", {}) if isinstance(worker.get("scheduler"), dict) else {}
    runtime = worker.get("runtime", {}) if isinstance(worker.get("runtime"), dict) else {}
    stream = worker.get("stream", {}) if isinstance(worker.get("stream"), dict) else {}
    storage = worker.get("storage", {}) if isinstance(worker.get("storage"), dict) else {}
    observability = worker.get("observability", {}) if isinstance(worker.get("observability"), dict) else {}
    return {
        "worker_operation_id": worker.get("worker_operation_id"),
        "worker_operation_hash": content_hash(worker),
        "worker_ref": worker_record.get("worker_ref"),
        "run_ref": worker_record.get("run_ref"),
        "operation_kind": worker_record.get("operation_kind"),
        "runtime_audit_id": source.get("runtime_audit_id"),
        "runtime_audit_hash": source.get("runtime_audit_hash"),
        "operation_id": source.get("operation_id"),
        "operation_ref": source.get("operation_ref"),
        "framework": runtime.get("framework"),
        "trace_id": runtime.get("trace_id"),
        "runtime_instance_ref": runtime.get("runtime_instance_ref"),
        "runtime_process_ref": runtime.get("runtime_process_ref"),
        "runtime_event_ref": stream.get("runtime_event_ref"),
        "stream_ref": stream.get("stream_ref"),
        "stream_topic": stream.get("stream_topic"),
        "partition_ref": stream.get("partition_ref"),
        "offset_start": stream.get("offset_start"),
        "offset_end": stream.get("offset_end"),
        "stream_message_ref": stream.get("stream_message_ref"),
        "stream_message_hash": stream.get("stream_message_hash"),
        "storage_object_ref": storage.get("storage_object_ref"),
        "storage_object_hash": storage.get("storage_object_hash"),
        "clickhouse_batch_ref": storage.get("clickhouse_batch_ref"),
        "clickhouse_batch_hash": storage.get("clickhouse_batch_hash"),
        "clickhouse_rows_written": storage.get("clickhouse_rows_written"),
        "postgres_index_ref": storage.get("postgres_index_ref"),
        "postgres_index_hash": storage.get("postgres_index_hash"),
        "postgres_rows_written": storage.get("postgres_rows_written"),
        "control_index_ref": storage.get("control_index_ref"),
        "control_index_hash": storage.get("control_index_hash"),
        "schedule_ref": scheduler.get("schedule_ref"),
        "lease_ref": scheduler.get("lease_ref"),
        "checkpoint_ref": scheduler.get("checkpoint_ref"),
        "checkpoint_hash": scheduler.get("checkpoint_hash"),
        "previous_cursor_ref": scheduler.get("previous_cursor_ref"),
        "next_cursor_ref": scheduler.get("next_cursor_ref"),
        "worker_audit_log_ref": observability.get("audit_log_ref"),
        "worker_audit_log_root": observability.get("audit_log_root"),
        "runtime_audit_log_ref": stream.get("runtime_audit_log_ref"),
        "runtime_audit_log_root": stream.get("runtime_audit_log_root"),
    }


def _verify_worker_binding(
    binding: dict[str, Any],
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
    for field in ("worker_operation_id", "worker_operation_hash", "run_ref", "runtime_audit_id", "stream_message_hash", "storage_object_hash", "clickhouse_batch_hash", "postgres_index_hash", "control_index_hash"):
        if not binding.get(field):
            errors.append(f"framework runtime storage worker_binding.{field} is required")
    if not all(source is not None for source in (worker, runtime_audit, audit_export, operation, trace_payload, release, matrix)):
        warnings.append("framework runtime storage worker/runtime-audit/operation/trace/release/matrix replay was not fully supplied")
        return
    result = verify_framework_runtime_worker_receipt(
        worker or {},
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
        errors.extend(f"framework runtime storage worker invalid: {error}" for error in result.errors)
    expected = _worker_binding(worker or {})
    if binding != expected:
        errors.append("framework runtime storage worker binding does not match supplied worker receipt")


def _verify_provider_export_binding(
    receipt: dict[str, Any],
    storage_export: dict[str, Any] | None,
    binding: dict[str, Any],
    errors: list[str],
    warnings: list[str],
) -> None:
    record = receipt.get("provider_export", {})
    if not isinstance(record, dict):
        errors.append("framework runtime storage provider_export must be an object")
        record = {}
    for field in ("window_start", "window_end", "audit_log_ref", "audit_log_root", "hash", "stream_record_root", "storage_record_root"):
        if not record.get(field):
            errors.append(f"framework runtime storage provider_export.{field} is required")
    try:
        start = parse_rfc3339(str(record.get("window_start") or ""))
        end = parse_rfc3339(str(record.get("window_end") or ""))
        if end < start:
            errors.append("framework runtime storage provider_export window_end must be at or after window_start")
    except ValueError as exc:
        errors.append(f"framework runtime storage provider_export window timestamp invalid: {exc}")
    if not _is_hash_ref(str(record.get("audit_log_root") or "")):
        errors.append("framework runtime storage provider_export.audit_log_root must be a sha256 reference")
    if storage_export is None:
        warnings.append("framework runtime storage export was not supplied; stream/storage export hashes were not replayed")
        return

    try:
        stream_records = _records(storage_export, "stream_records")
        storage_records = _records(storage_export, "storage_records")
        scheduler_records = _records(storage_export, "scheduler_records")
    except ValueError as exc:
        errors.append(str(exc))
        return
    expected_record = {
        "export_ref": storage_export.get("export_ref"),
        "schema": storage_export.get("schema"),
        "provider": _normalize_provider(storage_export.get("provider")),
        "environment": storage_export.get("environment"),
        "window_start": storage_export.get("window_start"),
        "window_end": storage_export.get("window_end"),
        "cursor_ref": storage_export.get("cursor_ref"),
        "next_cursor_ref": storage_export.get("next_cursor_ref"),
        "audit_log_ref": storage_export.get("audit_log_ref"),
        "audit_log_root": storage_export.get("audit_log_root"),
        "hash": content_hash(storage_export),
        "stream_record_count": len(stream_records),
        "stream_record_root": content_hash(stream_records),
        "storage_record_count": len(storage_records),
        "storage_record_root": content_hash(storage_records),
        "scheduler_record_count": len(scheduler_records),
        "scheduler_record_root": content_hash(scheduler_records),
    }
    if record != expected_record:
        errors.append("framework runtime storage provider export binding does not match supplied storage export")
    if record.get("provider") and receipt.get("provider") != record.get("provider"):
        errors.append("framework runtime storage provider does not match storage export provider")
    try:
        matched_stream = _matching_stream_record(stream_records, binding)
        matched_storage = _matching_storage_records(storage_records, binding)
        matched_scheduler = _matching_scheduler_record(scheduler_records, binding)
        _validate_stream_record(matched_stream, binding)
        _validate_storage_records(matched_storage, binding)
        _validate_scheduler_record(matched_scheduler, binding)
    except ValueError as exc:
        errors.append(str(exc))
        return
    if receipt.get("matched_stream_record") != _stream_record_summary(matched_stream):
        errors.append("framework runtime storage matched stream record does not match supplied storage export")
    if receipt.get("matched_storage_records") != [_storage_record_summary(item) for item in matched_storage]:
        errors.append("framework runtime storage matched storage records do not match supplied storage export")
    if receipt.get("matched_scheduler_record") != _scheduler_record_summary(matched_scheduler):
        errors.append("framework runtime storage matched scheduler record does not match supplied storage export")


def _records(storage_export: dict[str, Any], field: str) -> list[dict[str, Any]]:
    raw = storage_export.get(field)
    if raw is None and field == "scheduler_records":
        return []
    if not isinstance(raw, list):
        raise ValueError(f"framework runtime storage export {field} must be an array")
    records: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError(f"framework runtime storage export {field} must contain objects")
        records.append(item)
    return records


def _matching_stream_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    matches = [
        record
        for record in records
        if record.get("worker_run_ref") == binding.get("run_ref")
        and record.get("stream_message_ref") == binding.get("stream_message_ref")
        and record.get("runtime_event_ref") == binding.get("runtime_event_ref")
    ]
    if len(matches) != 1:
        raise ValueError("framework runtime storage export must contain exactly one matching stream record")
    return matches[0]


def _matching_storage_records(records: list[dict[str, Any]], binding: dict[str, Any]) -> list[dict[str, Any]]:
    matches = [
        record
        for record in records
        if record.get("worker_run_ref") == binding.get("run_ref")
        and record.get("runtime_event_ref") == binding.get("runtime_event_ref")
    ]
    kinds = {str(record.get("kind") or "") for record in matches}
    if kinds != REQUIRED_STORAGE_KINDS:
        missing = ", ".join(sorted(REQUIRED_STORAGE_KINDS - kinds))
        extra = ", ".join(sorted(kinds - REQUIRED_STORAGE_KINDS))
        detail = f" missing={missing}" if missing else ""
        detail += f" extra={extra}" if extra else ""
        raise ValueError("framework runtime storage export must contain matching WORM, ClickHouse, Postgres, and control-index records" + detail)
    return sorted(matches, key=lambda item: str(item.get("kind") or ""))


def _matching_scheduler_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    matches = [record for record in records if record.get("worker_run_ref") == binding.get("run_ref")]
    if len(matches) != 1:
        raise ValueError("framework runtime storage export must contain exactly one matching scheduler record")
    return matches[0]


def _validate_stream_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    comparisons = {
        "stream_ref": "stream_ref",
        "stream_topic": "stream_topic",
        "partition_ref": "partition_ref",
        "offset_start": "offset_start",
        "offset_end": "offset_end",
        "stream_message_hash": "stream_message_hash",
        "runtime_audit_log_ref": "runtime_audit_log_ref",
        "runtime_audit_log_root": "runtime_audit_log_root",
    }
    _compare_record(record, binding, comparisons, "stream")
    if not _is_hash_ref(str(record.get("stream_message_hash") or "")):
        raise ValueError("framework runtime storage stream record stream_message_hash must be a sha256 reference")
    if record.get("runtime_audit_id") and record.get("runtime_audit_id") != binding.get("runtime_audit_id"):
        raise ValueError("framework runtime storage stream record runtime_audit_id does not match worker binding")


def _validate_storage_records(records: list[dict[str, Any]], binding: dict[str, Any]) -> None:
    expected = {
        "worm_object": ("storage_object_ref", "storage_object_hash", None),
        "clickhouse_batch": ("clickhouse_batch_ref", "clickhouse_batch_hash", "clickhouse_rows_written"),
        "postgres_index": ("postgres_index_ref", "postgres_index_hash", "postgres_rows_written"),
        "control_index": ("control_index_ref", "control_index_hash", None),
    }
    for record in records:
        kind = str(record.get("kind") or "")
        ref_field, hash_field, rows_field = expected[kind]
        if record.get("ref") != binding.get(ref_field):
            raise ValueError(f"framework runtime storage {kind} ref does not match worker binding")
        if record.get("hash") != binding.get(hash_field):
            raise ValueError(f"framework runtime storage {kind} hash does not match worker binding")
        if not _is_hash_ref(str(record.get("hash") or "")):
            raise ValueError(f"framework runtime storage {kind} hash must be a sha256 reference")
        if rows_field and record.get("row_count") != binding.get(rows_field):
            raise ValueError(f"framework runtime storage {kind} row_count does not match worker binding")


def _validate_scheduler_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    comparisons = {
        "schedule_ref": "schedule_ref",
        "lease_ref": "lease_ref",
        "checkpoint_ref": "checkpoint_ref",
        "checkpoint_hash": "checkpoint_hash",
        "previous_cursor_ref": "previous_cursor_ref",
        "next_cursor_ref": "next_cursor_ref",
    }
    _compare_record(record, binding, comparisons, "scheduler")
    if record.get("checkpoint_hash") and not _is_hash_ref(str(record.get("checkpoint_hash"))):
        raise ValueError("framework runtime storage scheduler record checkpoint_hash must be a sha256 reference")


def _compare_record(record: dict[str, Any], binding: dict[str, Any], fields: dict[str, str], name: str) -> None:
    for record_field, binding_field in fields.items():
        if record.get(record_field) != binding.get(binding_field):
            raise ValueError(f"framework runtime storage {name} record {record_field} does not match worker binding")


def _stream_record_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": record.get("record_id"),
        "record_hash": content_hash(record),
        "backend": record.get("backend"),
        "stream_ref": record.get("stream_ref"),
        "stream_topic": record.get("stream_topic"),
        "partition_ref": record.get("partition_ref"),
        "offset_start": record.get("offset_start"),
        "offset_end": record.get("offset_end"),
        "stream_message_ref": record.get("stream_message_ref"),
        "stream_message_hash": record.get("stream_message_hash"),
        "runtime_event_ref": record.get("runtime_event_ref"),
    }


def _storage_record_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": record.get("record_id"),
        "record_hash": content_hash(record),
        "kind": record.get("kind"),
        "ref": record.get("ref"),
        "hash": record.get("hash"),
        "row_count": record.get("row_count"),
        "backend": record.get("backend"),
    }


def _scheduler_record_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": record.get("record_id"),
        "record_hash": content_hash(record),
        "schedule_ref": record.get("schedule_ref"),
        "lease_ref": record.get("lease_ref"),
        "checkpoint_ref": record.get("checkpoint_ref"),
        "checkpoint_hash": record.get("checkpoint_hash"),
        "previous_cursor_ref": record.get("previous_cursor_ref"),
        "next_cursor_ref": record.get("next_cursor_ref"),
    }


def _verify_provider_exchange(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime storage provider_exchange must be an object")
        return
    for field in ("endpoint_url", "request_hash", "response_status", "response_hash", "actor_ref"):
        if not value.get(field):
            errors.append(f"framework runtime storage provider_exchange.{field} is required")
    endpoint_url = str(value.get("endpoint_url") or "")
    if not _valid_url(endpoint_url):
        errors.append("framework runtime storage endpoint_url must be an absolute URL")
    elif not _is_https(endpoint_url):
        errors.append("framework runtime storage endpoint_url must use HTTPS")
    for field in ("request_hash", "response_hash"):
        if not _is_hash_ref(str(value.get(field) or "")):
            errors.append(f"framework runtime storage provider_exchange.{field} must be a sha256 reference")
    response_status = value.get("response_status")
    if not isinstance(response_status, int) or response_status < 100 or response_status > 599:
        errors.append("framework runtime storage response_status must be an HTTP status code")
    elif value.get("success") is not (200 <= response_status < 300):
        errors.append("framework runtime storage success must match response_status")


def _controls(
    *,
    mode: str,
    endpoint_url: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    matched_storage: list[dict[str, Any]],
    matched_scheduler: dict[str, Any],
    audit_log_root: str,
) -> list[dict[str, Any]]:
    endpoint_bound = _is_https(endpoint_url) and _is_hash_ref(request_hash) and _is_hash_ref(response_hash) and 100 <= response_status <= 599
    storage_kinds = {str(record.get("kind") or "") for record in matched_storage}
    storage_bound = storage_kinds == REQUIRED_STORAGE_KINDS and all(_is_hash_ref(str(record.get("hash") or "")) for record in matched_storage)
    scheduler_bound = bool(matched_scheduler.get("lease_ref") and matched_scheduler.get("checkpoint_ref"))
    production = mode == "production-export" and endpoint_bound and storage_bound and scheduler_bound and _is_hash_ref(audit_log_root)
    return [
        {"id": "framework-runtime-worker-replayed", "status": "passed", "description": "Provider export is bound to a verified framework runtime worker receipt."},
        {"id": "provider-stream-export-bound", "status": "passed" if endpoint_bound else "failed", "description": "Provider export endpoint, request hash, response status, and response hash are recorded."},
        {"id": "stream-message-export-matched", "status": "passed", "description": "Exported stream record matches the worker stream message and runtime event."},
        {"id": "provider-storage-export-matched", "status": "passed" if storage_bound else "failed", "description": "WORM object, ClickHouse, Postgres, and control-index export records match the worker storage hashes."},
        {"id": "scheduler-export-matched", "status": "passed" if scheduler_bound else "failed", "description": "Provider scheduler export records lease and checkpoint continuity."},
        {"id": "immutable-storage-export-audit-root", "status": "passed" if _is_hash_ref(audit_log_root) else "failed", "description": "Provider-owned stream/storage export audit root is hash-bound."},
        {"id": "production-stream-storage-authority", "status": "passed" if production else "deferred", "description": "Live production stream/storage authority is claimed only with production export evidence."},
    ]


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _normalize_provider(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    return normalized or None


def _require_provider(value: Any) -> str:
    normalized = _normalize_provider(value)
    if not normalized:
        raise ValueError("framework runtime storage provider is required")
    return normalized


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"framework runtime storage {field} is required")
    return value.strip()


def _valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def _is_https(value: str | None) -> bool:
    return bool(value and urlparse(value).scheme.lower() == "https")


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value.removeprefix("sha256:"))
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _redacted_ref(ref: str | None) -> dict[str, Any]:
    if not ref:
        raise ValueError("framework runtime storage credential_ref is required")
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
                    errors.append(f"framework runtime storage secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    return key.endswith("_ref") and isinstance(value, str) and bool(value.strip())
