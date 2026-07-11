from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_runtime_service_worker import verify_framework_runtime_service_worker_receipt

FRAMEWORK_RUNTIME_SERVICE_PROVIDER_SCHEMA = "trustai.framework-runtime-service-provider-export/0.1"
FRAMEWORK_RUNTIME_SERVICE_PROVIDER_ENTRY_TYPE = "framework_runtime.service_provider_exported"
FRAMEWORK_RUNTIME_SERVICE_PROVIDER_MODES = {"local-export", "provider-export", "production-export"}
REQUIRED_STORAGE_KINDS = {"worm_object", "clickhouse_batch", "postgres_index", "control_index"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")
SERVICE_WORKER_BINDING_EXPECTED_FIELDS = (
    "worker_operation_id",
    "worker_operation_hash",
    "service_attestation_id",
    "service_attestation_hash",
    "service_ref",
    "runtime_worker_ref",
    "run_ref",
    "worker_ref",
    "operation_kind",
    "storage_receipt_id",
    "storage_receipt_hash",
    "queue_ref",
    "queue_message_ref",
    "queue_message_hash",
    "dead_letter_queue_ref",
    "schedule_ref",
    "lease_ref",
    "checkpoint_ref",
    "checkpoint_hash",
    "previous_cursor_ref",
    "next_cursor_ref",
    "kms_key_ref",
    "stream_ref",
    "stream_topic",
    "stream_message_ref",
    "stream_message_hash",
    "storage_object_ref",
    "storage_object_hash",
    "clickhouse_batch_ref",
    "clickhouse_batch_hash",
    "postgres_index_ref",
    "postgres_index_hash",
    "control_index_ref",
    "control_index_hash",
    "request_hash",
    "response_hash",
    "metrics_ref",
    "worker_audit_log_ref",
    "worker_audit_log_root",
)
SERVICE_WORKER_BINDING_REQUIRED_FIELDS = (
    "worker_operation_id",
    "worker_operation_hash",
    "service_attestation_id",
    "service_attestation_hash",
    "service_ref",
    "runtime_worker_ref",
    "run_ref",
    "worker_ref",
    "operation_kind",
    "storage_receipt_id",
    "storage_receipt_hash",
    "queue_ref",
    "queue_message_ref",
    "queue_message_hash",
    "schedule_ref",
    "lease_ref",
    "checkpoint_ref",
    "checkpoint_hash",
    "kms_key_ref",
    "stream_ref",
    "stream_topic",
    "stream_message_ref",
    "stream_message_hash",
    "storage_object_ref",
    "storage_object_hash",
    "clickhouse_batch_ref",
    "clickhouse_batch_hash",
    "postgres_index_ref",
    "postgres_index_hash",
    "control_index_ref",
    "control_index_hash",
    "request_hash",
    "response_hash",
    "metrics_ref",
    "worker_audit_log_ref",
    "worker_audit_log_root",
)
PROVIDER_EXPORT_EXPECTED_FIELDS = (
    "export_ref",
    "schema",
    "provider",
    "environment",
    "window_start",
    "window_end",
    "cursor_ref",
    "next_cursor_ref",
    "audit_log_ref",
    "audit_log_root",
    "hash",
    "scheduler_record_count",
    "scheduler_record_root",
    "queue_record_count",
    "queue_record_root",
    "kms_record_count",
    "kms_record_root",
    "stream_record_count",
    "stream_record_root",
    "storage_record_count",
    "storage_record_root",
    "audit_record_count",
    "audit_record_root",
)
PROVIDER_EXPORT_REQUIRED_FIELDS = PROVIDER_EXPORT_EXPECTED_FIELDS
PROVIDER_EXPORT_COUNT_FIELDS = (
    "scheduler_record_count",
    "queue_record_count",
    "kms_record_count",
    "stream_record_count",
    "storage_record_count",
    "audit_record_count",
)


@dataclass
class FrameworkRuntimeServiceProviderVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_runtime_service_provider_export(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime service provider export must contain an object")
    return value


def load_framework_runtime_service_provider_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime service provider receipt must contain an object")
    return value


def write_framework_runtime_service_provider_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_runtime_service_provider_receipt(
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
    if mode not in FRAMEWORK_RUNTIME_SERVICE_PROVIDER_MODES:
        raise ValueError(f"mode must be one of {sorted(FRAMEWORK_RUNTIME_SERVICE_PROVIDER_MODES)}")
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
        raise ValueError("framework runtime service provider response_status must be an integer")
    timestamp = exported_at or utc_now()
    parse_rfc3339(timestamp)

    worker_result = verify_framework_runtime_service_worker_receipt(
        service_worker,
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
    if not worker_result.ok:
        raise ValueError("invalid framework runtime service worker source: " + "; ".join(worker_result.errors))

    window_start = _require_text(provider_export.get("window_start"), "provider_export.window_start")
    window_end = _require_text(provider_export.get("window_end"), "provider_export.window_end")
    start = parse_rfc3339(window_start)
    end = parse_rfc3339(window_end)
    if end < start:
        raise ValueError("framework runtime service provider export window_end must be at or after window_start")
    audit_log_ref = _require_text(provider_export.get("audit_log_ref"), "provider_export.audit_log_ref")
    audit_log_root = _require_text(provider_export.get("audit_log_root"), "provider_export.audit_log_root")

    service = _service_worker_binding(service_worker)
    scheduler_records = _records(provider_export, "scheduler_records")
    queue_records = _records(provider_export, "queue_records")
    kms_records = _records(provider_export, "kms_records")
    stream_records = _records(provider_export, "stream_records")
    storage_records = _records(provider_export, "storage_records")
    audit_records = _records(provider_export, "audit_records")
    matched_scheduler = _matching_scheduler_record(scheduler_records, service)
    matched_queue = _matching_queue_record(queue_records, service)
    matched_kms = _matching_kms_record(kms_records, service)
    matched_stream = _matching_stream_record(stream_records, service)
    matched_storage = _matching_storage_records(storage_records, service)
    matched_audit = _matching_audit_record(audit_records, service)
    _validate_scheduler_record(matched_scheduler, service)
    _validate_queue_record(matched_queue, service)
    _validate_kms_record(matched_kms, service)
    _validate_stream_record(matched_stream, service)
    _validate_storage_records(matched_storage, service)
    _validate_audit_record(matched_audit, service)

    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_SERVICE_PROVIDER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "exported_at": timestamp,
        "provider": normalized_provider,
        "service_worker_binding": service,
        "provider_export": {
            "export_ref": provider_export.get("export_ref"),
            "schema": provider_export.get("schema"),
            "provider": _normalize_provider(provider_export.get("provider")),
            "environment": provider_export.get("environment"),
            "window_start": window_start,
            "window_end": window_end,
            "cursor_ref": provider_export.get("cursor_ref"),
            "next_cursor_ref": provider_export.get("next_cursor_ref"),
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "hash": content_hash(provider_export),
            "scheduler_record_count": len(scheduler_records),
            "scheduler_record_root": content_hash(scheduler_records),
            "queue_record_count": len(queue_records),
            "queue_record_root": content_hash(queue_records),
            "kms_record_count": len(kms_records),
            "kms_record_root": content_hash(kms_records),
            "stream_record_count": len(stream_records),
            "stream_record_root": content_hash(stream_records),
            "storage_record_count": len(storage_records),
            "storage_record_root": content_hash(storage_records),
            "audit_record_count": len(audit_records),
            "audit_record_root": content_hash(audit_records),
        },
        "matched_scheduler_record": _record_summary(matched_scheduler),
        "matched_queue_record": _record_summary(matched_queue),
        "matched_kms_record": _record_summary(matched_kms),
        "matched_stream_record": _record_summary(matched_stream),
        "matched_storage_records": [_record_summary(record) for record in matched_storage],
        "matched_audit_record": _record_summary(matched_audit),
        "provider_exchange": {
            "endpoint_url": endpoint_url,
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
            "success": 200 <= response_status < 300,
            "actor_ref": actor_ref,
        },
        "credential": _redacted_ref(credential_ref),
        "controls": _controls(mode, endpoint_url, request_hash, response_status, response_hash, matched_storage, matched_kms, matched_audit, audit_log_root),
        "limitations": [
            "This receipt binds a verified framework runtime service worker operation to provider-native scheduler, queue, KMS, stream, storage, and audit export records.",
            "It stores provider export hashes, record roots, matched record hashes, and endpoint evidence, not raw provider credentials or database contents.",
            "It does not prove continuously operated production infrastructure unless mode is production-export and paired with live provider-owned export evidence.",
        ],
    }
    provider_receipt_id = content_hash(body)
    return {
        **body,
        "provider_receipt_id": provider_receipt_id,
        "signatures": [sign_value({"provider_receipt_id": provider_receipt_id, "framework_runtime_service_provider": body}, key)],
    }

def verify_framework_runtime_service_provider_receipt(
    receipt: dict[str, Any],
    *,
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
) -> FrameworkRuntimeServiceProviderVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != FRAMEWORK_RUNTIME_SERVICE_PROVIDER_SCHEMA:
        errors.append(f"unsupported framework runtime service provider schema: {receipt.get('schema')}")
    body = without_keys(receipt, "provider_receipt_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("provider_receipt_id") != expected_id:
        errors.append("provider_receipt_id does not match canonical framework runtime service provider body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime service provider receipt must include at least one signature")
    else:
        signed_value = {"provider_receipt_id": receipt.get("provider_receipt_id"), "framework_runtime_service_provider": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime service provider signature verification failed")

    mode = receipt.get("mode")
    if mode not in FRAMEWORK_RUNTIME_SERVICE_PROVIDER_MODES:
        errors.append("framework runtime service provider mode is unsupported")
    elif mode != "production-export":
        warnings.append(f"framework runtime service provider mode is {mode}; live provider-owned service export is not claimed")
    try:
        parse_rfc3339(str(receipt.get("exported_at") or ""))
    except ValueError as exc:
        errors.append(f"framework runtime service provider exported_at invalid: {exc}")
    if not _normalize_provider(receipt.get("provider")):
        errors.append("framework runtime service provider provider is required")

    binding = receipt.get("service_worker_binding", {})
    if not isinstance(binding, dict):
        errors.append("framework runtime service provider service_worker_binding must be an object")
        binding = {}
    _verify_service_worker_binding(binding, service_worker, service_attestation, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace_payload, release, matrix, root, key, errors, warnings)
    _verify_provider_export_binding(receipt, provider_export, binding, errors, warnings)
    _verify_provider_exchange(receipt.get("provider_exchange"), errors)
    _verify_redacted_ref(receipt.get("credential"), "framework runtime service provider credential", errors)
    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("framework runtime service provider controls are required")
    _check_no_secret_values(receipt, errors)
    return FrameworkRuntimeServiceProviderVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_runtime_service_provider_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
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
) -> dict[str, Any]:
    result = verify_framework_runtime_service_provider_receipt(
        receipt,
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
    )
    if not result.ok:
        raise ValueError("invalid framework runtime service provider receipt: " + "; ".join(result.errors))
    payload = {
        "provider_receipt_id": receipt["provider_receipt_id"],
        "provider_receipt_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "exported_at": receipt.get("exported_at"),
        "provider": receipt.get("provider"),
        "service_worker_binding": receipt.get("service_worker_binding"),
        "provider_export": receipt.get("provider_export"),
        "matched_scheduler_record": receipt.get("matched_scheduler_record"),
        "matched_queue_record": receipt.get("matched_queue_record"),
        "matched_kms_record": receipt.get("matched_kms_record"),
        "matched_stream_record": receipt.get("matched_stream_record"),
        "matched_storage_records": receipt.get("matched_storage_records"),
        "matched_audit_record": receipt.get("matched_audit_record"),
        "provider_exchange": receipt.get("provider_exchange"),
        "credential": receipt.get("credential"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(FRAMEWORK_RUNTIME_SERVICE_PROVIDER_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("exported_at"))

def _service_worker_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    service = receipt.get("service", {}) if isinstance(receipt.get("service"), dict) else {}
    source = receipt.get("source", {}) if isinstance(receipt.get("source"), dict) else {}
    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    scheduler = receipt.get("scheduler", {}) if isinstance(receipt.get("scheduler"), dict) else {}
    execution = receipt.get("execution", {}) if isinstance(receipt.get("execution"), dict) else {}
    observability = receipt.get("observability", {}) if isinstance(receipt.get("observability"), dict) else {}
    return {
        "worker_operation_id": receipt.get("worker_operation_id"),
        "worker_operation_hash": content_hash(receipt),
        "service_attestation_id": service.get("attestation_id"),
        "service_attestation_hash": service.get("attestation_hash"),
        "service_ref": service.get("service_ref"),
        "runtime_worker_ref": worker.get("runtime_worker_ref"),
        "run_ref": worker.get("run_ref"),
        "worker_ref": worker.get("worker_ref"),
        "operation_kind": worker.get("operation_kind"),
        "storage_receipt_id": source.get("storage_receipt_id"),
        "storage_receipt_hash": source.get("storage_receipt_hash"),
        "queue_ref": execution.get("queue_ref"),
        "queue_message_ref": execution.get("queue_message_ref"),
        "queue_message_hash": execution.get("queue_message_hash"),
        "dead_letter_queue_ref": execution.get("dead_letter_queue_ref"),
        "schedule_ref": scheduler.get("schedule_ref"),
        "lease_ref": scheduler.get("lease_ref"),
        "checkpoint_ref": scheduler.get("checkpoint_ref"),
        "checkpoint_hash": scheduler.get("checkpoint_hash"),
        "previous_cursor_ref": scheduler.get("previous_cursor_ref"),
        "next_cursor_ref": scheduler.get("next_cursor_ref"),
        "kms_key_ref": service.get("kms_key_ref"),
        "stream_ref": service.get("stream_ref"),
        "stream_topic": service.get("stream_topic"),
        "stream_message_ref": execution.get("stream_message_ref"),
        "stream_message_hash": execution.get("stream_message_hash"),
        "storage_object_ref": execution.get("storage_object_ref"),
        "storage_object_hash": execution.get("storage_object_hash"),
        "clickhouse_batch_ref": execution.get("clickhouse_batch_ref"),
        "clickhouse_batch_hash": execution.get("clickhouse_batch_hash"),
        "postgres_index_ref": execution.get("postgres_index_ref"),
        "postgres_index_hash": execution.get("postgres_index_hash"),
        "control_index_ref": execution.get("control_index_ref"),
        "control_index_hash": execution.get("control_index_hash"),
        "request_hash": execution.get("request_hash"),
        "response_hash": execution.get("response_hash"),
        "metrics_ref": observability.get("metrics_ref"),
        "worker_audit_log_ref": observability.get("audit_log_ref"),
        "worker_audit_log_root": observability.get("audit_log_root"),
    }


def _verify_service_worker_binding(
    binding: dict[str, Any],
    service_worker: dict[str, Any] | None,
    service_attestation: dict[str, Any] | None,
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
    for field in SERVICE_WORKER_BINDING_EXPECTED_FIELDS:
        if field not in binding:
            errors.append(f"framework runtime service provider binding.{field} is required")
    for field in SERVICE_WORKER_BINDING_REQUIRED_FIELDS:
        if binding.get(field) in (None, "", []):
            errors.append(f"framework runtime service provider binding.{field} is required")
    if service_worker is None:
        warnings.append("framework runtime service provider service worker artifact was not supplied; worker source was not replayed")
        return
    expected = _service_worker_binding(service_worker)
    if binding != expected:
        errors.append("framework runtime service provider service_worker_binding does not match supplied service worker")
    result = verify_framework_runtime_service_worker_receipt(
        service_worker,
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
        errors.extend(f"framework runtime service provider worker source: {error}" for error in result.errors)
    warnings.extend(f"framework runtime service provider worker source: {warning}" for warning in result.warnings)


def _verify_provider_export_binding(receipt: dict[str, Any], provider_export: dict[str, Any] | None, binding: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    export = receipt.get("provider_export", {})
    if not isinstance(export, dict):
        errors.append("framework runtime service provider provider_export must be an object")
        return
    for field in PROVIDER_EXPORT_EXPECTED_FIELDS:
        if field not in export:
            errors.append(f"framework runtime service provider provider_export.{field} is required")
    for field in PROVIDER_EXPORT_REQUIRED_FIELDS:
        if export.get(field) in (None, "", []):
            errors.append(f"framework runtime service provider provider_export.{field} is required")
    for field in PROVIDER_EXPORT_COUNT_FIELDS:
        if not isinstance(export.get(field), int) or export.get(field) <= 0:
            errors.append(f"framework runtime service provider provider_export.{field} must be positive")
    if provider_export is None:
        warnings.append("framework runtime service provider export artifact was not supplied; provider records were not replayed")
        return
    if export.get("hash") != content_hash(provider_export):
        errors.append("framework runtime service provider export hash does not match supplied provider export")
    scheduler_records = _records(provider_export, "scheduler_records")
    queue_records = _records(provider_export, "queue_records")
    kms_records = _records(provider_export, "kms_records")
    stream_records = _records(provider_export, "stream_records")
    storage_records = _records(provider_export, "storage_records")
    audit_records = _records(provider_export, "audit_records")
    expected = {
        "scheduler_record_count": len(scheduler_records),
        "scheduler_record_root": content_hash(scheduler_records),
        "queue_record_count": len(queue_records),
        "queue_record_root": content_hash(queue_records),
        "kms_record_count": len(kms_records),
        "kms_record_root": content_hash(kms_records),
        "stream_record_count": len(stream_records),
        "stream_record_root": content_hash(stream_records),
        "storage_record_count": len(storage_records),
        "storage_record_root": content_hash(storage_records),
        "audit_record_count": len(audit_records),
        "audit_record_root": content_hash(audit_records),
    }
    for field, value in expected.items():
        if export.get(field) != value:
            errors.append(f"framework runtime service provider export {field} does not match supplied provider export")
    try:
        _validate_scheduler_record(_matching_scheduler_record(scheduler_records, binding), binding)
        _validate_queue_record(_matching_queue_record(queue_records, binding), binding)
        _validate_kms_record(_matching_kms_record(kms_records, binding), binding)
        _validate_stream_record(_matching_stream_record(stream_records, binding), binding)
        _validate_storage_records(_matching_storage_records(storage_records, binding), binding)
        _validate_audit_record(_matching_audit_record(audit_records, binding), binding)
    except ValueError as exc:
        errors.append(f"framework runtime service provider export record mismatch: {exc}")

def _matching_scheduler_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    return _find_record(records, lambda record: record.get("worker_run_ref") == binding.get("run_ref") and record.get("lease_ref") == binding.get("lease_ref"), "scheduler")


def _matching_queue_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    return _find_record(records, lambda record: record.get("queue_message_ref") == binding.get("queue_message_ref"), "queue")


def _matching_kms_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    return _find_record(records, lambda record: record.get("worker_run_ref") == binding.get("run_ref") and record.get("kms_key_ref") == binding.get("kms_key_ref"), "kms")


def _matching_stream_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    return _find_record(records, lambda record: record.get("stream_message_ref") == binding.get("stream_message_ref"), "stream")


def _matching_storage_records(records: list[dict[str, Any]], binding: dict[str, Any]) -> list[dict[str, Any]]:
    matched: list[dict[str, Any]] = []
    expected = {
        "worm_object": (binding.get("storage_object_ref"), binding.get("storage_object_hash")),
        "clickhouse_batch": (binding.get("clickhouse_batch_ref"), binding.get("clickhouse_batch_hash")),
        "postgres_index": (binding.get("postgres_index_ref"), binding.get("postgres_index_hash")),
        "control_index": (binding.get("control_index_ref"), binding.get("control_index_hash")),
    }
    for kind, (ref, expected_hash) in expected.items():
        matched.append(_find_record(records, lambda record, k=kind, r=ref, h=expected_hash: record.get("kind") == k and record.get("ref") == r and record.get("hash") == h, kind))
    return matched


def _matching_audit_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    return _find_record(records, lambda record: record.get("audit_log_ref") == binding.get("worker_audit_log_ref"), "audit")


def _find_record(records: list[dict[str, Any]], predicate: Any, name: str) -> dict[str, Any]:
    for record in records:
        if predicate(record):
            return record
    raise ValueError(f"missing matching {name} record")


def _validate_scheduler_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    for field in ("schedule_ref", "lease_ref", "checkpoint_ref", "checkpoint_hash", "previous_cursor_ref", "next_cursor_ref"):
        if record.get(field) != binding.get(field):
            raise ValueError(f"scheduler record {field} does not match worker binding")


def _validate_queue_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    for field in ("queue_ref", "queue_message_ref", "queue_message_hash"):
        if record.get(field) != binding.get(field):
            raise ValueError(f"queue record {field} does not match worker binding")
    if binding.get("dead_letter_queue_ref") and record.get("dead_letter_queue_ref") != binding.get("dead_letter_queue_ref"):
        raise ValueError("queue record dead_letter_queue_ref does not match worker binding")


def _validate_kms_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    if record.get("kms_key_ref") != binding.get("kms_key_ref"):
        raise ValueError("kms record kms_key_ref does not match service binding")
    if record.get("worker_run_ref") != binding.get("run_ref"):
        raise ValueError("kms record worker_run_ref does not match worker binding")
    if record.get("request_hash") != binding.get("request_hash"):
        raise ValueError("kms record request_hash does not match worker binding")
    if record.get("response_hash") != binding.get("response_hash"):
        raise ValueError("kms record response_hash does not match worker binding")


def _validate_stream_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    for field in ("stream_ref", "stream_topic", "stream_message_ref", "stream_message_hash"):
        if record.get(field) != binding.get(field):
            raise ValueError(f"stream record {field} does not match worker binding")


def _validate_storage_records(records: list[dict[str, Any]], binding: dict[str, Any]) -> None:
    kinds = {record.get("kind") for record in records}
    if kinds != REQUIRED_STORAGE_KINDS:
        raise ValueError("storage records must include worm_object, clickhouse_batch, postgres_index, and control_index")
    for record in records:
        kind = record.get("kind")
        if kind == "worm_object" and (record.get("ref") != binding.get("storage_object_ref") or record.get("hash") != binding.get("storage_object_hash")):
            raise ValueError("worm_object record does not match worker binding")
        if kind == "clickhouse_batch" and (record.get("ref") != binding.get("clickhouse_batch_ref") or record.get("hash") != binding.get("clickhouse_batch_hash")):
            raise ValueError("clickhouse_batch record does not match worker binding")
        if kind == "postgres_index" and (record.get("ref") != binding.get("postgres_index_ref") or record.get("hash") != binding.get("postgres_index_hash")):
            raise ValueError("postgres_index record does not match worker binding")
        if kind == "control_index" and (record.get("ref") != binding.get("control_index_ref") or record.get("hash") != binding.get("control_index_hash")):
            raise ValueError("control_index record does not match worker binding")


def _validate_audit_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    if record.get("audit_log_ref") != binding.get("worker_audit_log_ref"):
        raise ValueError("audit record audit_log_ref does not match worker binding")
    if record.get("audit_log_root") != binding.get("worker_audit_log_root"):
        raise ValueError("audit record audit_log_root does not match worker binding")


def _record_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": record.get("record_id"),
        "kind": record.get("kind"),
        "ref": record.get("ref") or record.get("queue_message_ref") or record.get("stream_message_ref") or record.get("lease_ref") or record.get("audit_log_ref") or record.get("kms_key_ref"),
        "hash": record.get("hash") or record.get("queue_message_hash") or record.get("stream_message_hash") or record.get("checkpoint_hash") or record.get("audit_log_root") or record.get("response_hash"),
        "record_hash": content_hash(record),
    }


def _records(export: dict[str, Any], name: str) -> list[dict[str, Any]]:
    value = export.get(name, [])
    if not isinstance(value, list):
        raise ValueError(f"framework runtime service provider export {name} must be a list")
    if not value:
        raise ValueError(f"framework runtime service provider export {name} is required")
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"framework runtime service provider export {name}[{index}] must be an object")
    return value

def _verify_provider_exchange(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service provider provider_exchange must be an object")
        return
    for field in ("endpoint_url", "request_hash", "response_status", "response_hash", "actor_ref"):
        if value.get(field) in (None, ""):
            errors.append(f"framework runtime service provider provider_exchange.{field} is required")
    endpoint = str(value.get("endpoint_url") or "")
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        errors.append("framework runtime service provider provider_exchange.endpoint_url must be an absolute HTTP(S) URL")
    if value.get("request_hash") and not _is_sha256_ref(str(value.get("request_hash"))):
        errors.append("framework runtime service provider provider_exchange.request_hash must be a sha256 reference")
    if value.get("response_hash") and not _is_sha256_ref(str(value.get("response_hash"))):
        errors.append("framework runtime service provider provider_exchange.response_hash must be a sha256 reference")
    status = value.get("response_status")
    if not isinstance(status, int) or status < 100 or status > 599:
        errors.append("framework runtime service provider provider_exchange.response_status must be an HTTP status code")


def _controls(
    mode: str,
    endpoint_url: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    matched_storage: list[dict[str, Any]],
    matched_kms: dict[str, Any],
    matched_audit: dict[str, Any],
    audit_log_root: str,
) -> list[dict[str, str]]:
    endpoint_ok = bool(urlparse(endpoint_url).netloc) and _is_sha256_ref(request_hash) and _is_sha256_ref(response_hash) and 200 <= response_status < 300
    return [
        {
            "id": "framework-runtime-provider-export-mode",
            "status": "passed" if mode in {"provider-export", "production-export"} else "deferred",
            "description": "Provider export mode records provider-native service worker evidence.",
        },
        {
            "id": "framework-runtime-provider-endpoint-bound",
            "status": "passed" if endpoint_ok else "failed",
            "description": "Provider endpoint, request hash, response hash, response status, and actor are recorded.",
        },
        {
            "id": "framework-runtime-provider-scheduler-queue",
            "status": "passed",
            "description": "Scheduler lease/checkpoint/cursor and queue message records are replayed.",
        },
        {
            "id": "framework-runtime-provider-kms",
            "status": "passed" if matched_kms.get("kms_key_ref") and matched_kms.get("response_hash") else "failed",
            "description": "KMS key and operation response hash are replayed.",
        },
        {
            "id": "framework-runtime-provider-stream-storage",
            "status": "passed" if len(matched_storage) == len(REQUIRED_STORAGE_KINDS) else "failed",
            "description": "Stream, WORM, ClickHouse, Postgres, and control-index provider records are replayed.",
        },
        {
            "id": "framework-runtime-provider-audit-root",
            "status": "passed" if _is_sha256_ref(audit_log_root) and matched_audit.get("audit_log_root") else "failed",
            "description": "Provider export audit root and worker audit record are replayed.",
        },
    ]


def _redacted_ref(ref: str | None) -> dict[str, Any]:
    if not ref:
        raise ValueError("framework runtime service provider credential_ref is required")
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _require_provider(value: Any) -> str:
    normalized = _normalize_provider(value)
    if not normalized:
        raise ValueError("framework runtime service provider provider is required")
    return normalized


def _normalize_provider(value: Any) -> str:
    return str(value or "").strip().lower()


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"framework runtime service provider {field} is required")
    return value.strip()


def _is_sha256_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value[7:])
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(lowered, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"framework runtime service provider secret-like field must be redacted reference: {child_path}")
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