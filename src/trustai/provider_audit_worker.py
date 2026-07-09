from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .provider_audit import verify_provider_audit_correlation
from .provider_audit_stream import verify_provider_audit_stream_receipt
from .provider_lifecycle import verify_provider_lifecycle_manifest
from .provider_lifecycle_operation import verify_provider_lifecycle_operation_receipt

PROVIDER_AUDIT_WORKER_SCHEMA = "trustai.provider-audit-worker/0.1"
PROVIDER_AUDIT_WORKER_ENTRY_TYPE = "provider_audit.worker_recorded"

WORKER_MODES = {"local-reference", "scheduled-worker", "hosted-worker", "provider-authenticated-streamer", "production-design"}
WORKER_OPERATION_KINDS = {"audit_stream_poll", "audit_correlation", "stream_and_correlate", "retry_reconcile"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ProviderAuditWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_provider_audit_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider audit worker receipt must contain an object")
    return value


def write_provider_audit_worker_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_provider_audit_worker_receipt(
    *,
    stream_receipts: list[dict[str, Any]],
    worker_ref: str,
    run_ref: str,
    operation_kind: str,
    actor_ref: str,
    schedule_ref: str,
    cadence_seconds: int,
    lease_ref: str,
    checkpoint_ref: str,
    credential_ref: str,
    started_at: str,
    completed_at: str | None = None,
    correlations: list[dict[str, Any]] | None = None,
    lifecycle_operation: dict[str, Any] | None = None,
    lifecycle_manifest: dict[str, Any] | None = None,
    checkpoint_hash: str | None = None,
    previous_cursor_ref: str | None = None,
    next_cursor_ref: str | None = None,
    attempt: int = 1,
    max_attempts: int = 3,
    next_run_at: str | None = None,
    error_ref: str | None = None,
    mode: str = "scheduled-worker",
    environment: str = "local",
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in WORKER_MODES:
        raise ValueError("mode must be local-reference, scheduled-worker, hosted-worker, provider-authenticated-streamer, or production-design")
    if operation_kind not in WORKER_OPERATION_KINDS:
        raise ValueError("operation_kind is unsupported")
    if not isinstance(stream_receipts, list) or not stream_receipts:
        raise ValueError("stream_receipts must contain at least one provider audit stream receipt")
    for value, field in (
        (worker_ref, "worker_ref"),
        (run_ref, "run_ref"),
        (actor_ref, "actor_ref"),
        (schedule_ref, "schedule_ref"),
        (lease_ref, "lease_ref"),
        (checkpoint_ref, "checkpoint_ref"),
        (credential_ref, "credential_ref"),
        (started_at, "started_at"),
    ):
        _require_text(value, field)
    completed = completed_at or utc_now()
    start = parse_rfc3339(started_at)
    end = parse_rfc3339(completed)
    if end < start:
        raise ValueError("completed_at must be at or after started_at")
    if next_run_at:
        parse_rfc3339(next_run_at)
    if not isinstance(cadence_seconds, int) or cadence_seconds <= 0:
        raise ValueError("cadence_seconds must be a positive integer")
    if not isinstance(attempt, int) or attempt < 1:
        raise ValueError("attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < attempt:
        raise ValueError("max_attempts must be greater than or equal to attempt")

    stream_records = _stream_records(stream_receipts)
    correlation_records = _correlation_records(correlations or [])
    lifecycle_operation_record = _lifecycle_operation_record(lifecycle_operation)
    lifecycle_record = _lifecycle_record(lifecycle_manifest)
    provider = _derive_provider(stream_records, correlation_records, lifecycle_operation_record, lifecycle_record)
    success = (
        not error_ref
        and all(record.get("success") is True for record in stream_records)
        and (lifecycle_operation_record is None or lifecycle_operation_record.get("success") is True)
    )

    body: dict[str, Any] = {
        "schema": PROVIDER_AUDIT_WORKER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": completed,
        "provider": provider,
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
        "sources": {
            "stream_receipts": stream_records,
            "correlations": correlation_records,
            "lifecycle_operation": lifecycle_operation_record,
            "lifecycle": lifecycle_record,
        },
        "credential": _redacted_ref(credential_ref),
        "controls": _controls(
            mode=mode,
            operation_kind=operation_kind,
            stream_records=stream_records,
            correlation_records=correlation_records,
            lifecycle_operation_record=lifecycle_operation_record,
            lifecycle_record=lifecycle_record,
            schedule_ref=schedule_ref,
            cadence_seconds=cadence_seconds,
            lease_ref=lease_ref,
            checkpoint_ref=checkpoint_ref,
            credential_ref=credential_ref,
            next_cursor_ref=next_cursor_ref,
        ),
        "limitations": [
            "This receipt records a scheduled or hosted provider audit worker run and the source audit stream/correlation evidence it processed.",
            "It stores redacted credential references, scheduler leases, checkpoints, source receipt hashes, and cursor metadata, not provider credentials or raw provider response bodies.",
            "It proves continuously operated hosted audit streaming only when paired with deployment, ingress, storage, monitoring, and live provider dispatch evidence.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [sign_value({"worker_operation_id": worker_operation_id, "provider_audit_worker": body}, key)],
    }


def verify_provider_audit_worker_receipt(
    receipt: dict[str, Any],
    *,
    stream_receipts: list[dict[str, Any]] | None = None,
    correlations: list[dict[str, Any]] | None = None,
    lifecycle_operation: dict[str, Any] | None = None,
    lifecycle_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> ProviderAuditWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != PROVIDER_AUDIT_WORKER_SCHEMA:
        errors.append(f"unsupported provider audit worker schema: {receipt.get('schema')}")
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append("worker_operation_id does not match canonical provider audit worker body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider audit worker receipt must include at least one signature")
    else:
        signed_value = {"worker_operation_id": receipt.get("worker_operation_id"), "provider_audit_worker": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider audit worker signature verification failed")

    try:
        parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"provider audit worker recorded_at invalid: {exc}")

    mode = receipt.get("mode")
    if mode not in WORKER_MODES:
        errors.append("provider audit worker mode is unsupported")
    elif mode not in {"hosted-worker", "provider-authenticated-streamer"}:
        warnings.append(f"provider audit worker mode is {mode}; continuously hosted provider audit operation is not claimed")

    provider = _normalize_provider(receipt.get("provider"))
    if not provider:
        errors.append("provider audit worker provider is required")

    worker = receipt.get("worker", {})
    if not isinstance(worker, dict):
        errors.append("provider audit worker worker must be an object")
        worker = {}
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at", "attempt", "max_attempts", "success"):
        if worker.get(field) in (None, ""):
            errors.append(f"provider audit worker worker.{field} is required")
    if worker.get("operation_kind") not in WORKER_OPERATION_KINDS:
        errors.append(f"provider audit worker operation kind unsupported: {worker.get('operation_kind')}")
    try:
        started = parse_rfc3339(str(worker.get("started_at") or ""))
        completed = parse_rfc3339(str(worker.get("completed_at") or ""))
        if completed < started:
            errors.append("provider audit worker completed_at must be at or after started_at")
    except ValueError as exc:
        errors.append(f"provider audit worker timestamp invalid: {exc}")
    attempt = worker.get("attempt")
    max_attempts = worker.get("max_attempts")
    if not isinstance(attempt, int) or attempt < 1:
        errors.append("provider audit worker attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < (attempt if isinstance(attempt, int) else 1):
        errors.append("provider audit worker max_attempts must be greater than or equal to attempt")
    if not isinstance(worker.get("success"), bool):
        errors.append("provider audit worker success must be a boolean")

    scheduler = receipt.get("scheduler", {})
    if not isinstance(scheduler, dict):
        errors.append("provider audit worker scheduler must be an object")
        scheduler = {}
    for field in ("schedule_ref", "cadence_seconds", "lease_ref", "checkpoint_ref"):
        if scheduler.get(field) in (None, ""):
            errors.append(f"provider audit worker scheduler.{field} is required")
    cadence_seconds = scheduler.get("cadence_seconds")
    if not isinstance(cadence_seconds, int) or cadence_seconds <= 0:
        errors.append("provider audit worker scheduler.cadence_seconds must be a positive integer")
    checkpoint_hash = scheduler.get("checkpoint_hash")
    if checkpoint_hash and not _is_hash_ref(str(checkpoint_hash)):
        errors.append("provider audit worker scheduler.checkpoint_hash must be a sha256 reference")
    if scheduler.get("next_run_at"):
        try:
            parse_rfc3339(str(scheduler.get("next_run_at")))
        except ValueError as exc:
            errors.append(f"provider audit worker next_run_at invalid: {exc}")

    _verify_redacted_ref(receipt.get("credential"), "provider audit worker credential", errors)

    sources = receipt.get("sources", {})
    if not isinstance(sources, dict):
        errors.append("provider audit worker sources must be an object")
        sources = {}
    stream_records = sources.get("stream_receipts", [])
    if not isinstance(stream_records, list) or not stream_records:
        errors.append("provider audit worker sources.stream_receipts must contain at least one receipt")
        stream_records = []
    for record in stream_records:
        if not isinstance(record, dict):
            errors.append("provider audit worker stream source records must be objects")
            continue
        if record.get("provider") != provider:
            errors.append("provider audit worker stream source provider does not match receipt provider")
        for field in ("stream_receipt_id", "stream_receipt_hash", "stream_ref", "window_start", "window_end", "audit_log"):
            if record.get(field) in (None, ""):
                errors.append(f"provider audit worker stream source {field} is required")

    if stream_receipts is None:
        warnings.append("provider audit worker stream receipts were not supplied; stream receipt hashes were not replayed")
    else:
        expected_stream_records = _stream_records(stream_receipts)
        if stream_records != expected_stream_records:
            errors.append("provider audit worker stream source records do not match supplied stream receipts")
        for stream_receipt in stream_receipts:
            stream_result = verify_provider_audit_stream_receipt(stream_receipt, key=key)
            if not stream_result.ok:
                errors.extend(f"provider audit worker stream receipt invalid: {error}" for error in stream_result.errors)
            warnings.extend(f"provider audit worker stream warning: {warning}" for warning in stream_result.warnings)

    correlation_records = sources.get("correlations", [])
    if not isinstance(correlation_records, list):
        errors.append("provider audit worker sources.correlations must be a list")
        correlation_records = []
    if worker.get("operation_kind") in {"audit_correlation", "stream_and_correlate"} and not correlation_records:
        errors.append("provider audit worker correlation operation requires at least one correlation source")
    for record in correlation_records:
        if not isinstance(record, dict):
            errors.append("provider audit worker correlation source records must be objects")
            continue
        if record.get("provider") != provider:
            errors.append("provider audit worker correlation source provider does not match receipt provider")
        if record.get("audit_log", {}).get("hash") not in _stream_audit_hashes(stream_records):
            errors.append("provider audit worker correlation audit_log hash does not match any stream receipt audit_log hash")

    if correlations is None:
        if correlation_records:
            warnings.append("provider audit worker correlations were not supplied; correlation hashes were not replayed")
    else:
        expected_correlation_records = _correlation_records(correlations)
        if correlation_records != expected_correlation_records:
            errors.append("provider audit worker correlation source records do not match supplied correlations")
        for correlation in correlations:
            correlation_result = verify_provider_audit_correlation(correlation, key=key)
            if not correlation_result.ok:
                errors.extend(f"provider audit worker correlation invalid: {error}" for error in correlation_result.errors)
            warnings.extend(f"provider audit worker correlation warning: {warning}" for warning in correlation_result.warnings)

    lifecycle_operation_record = sources.get("lifecycle_operation")
    if lifecycle_operation_record is not None and not isinstance(lifecycle_operation_record, dict):
        errors.append("provider audit worker sources.lifecycle_operation must be an object")
        lifecycle_operation_record = None
    if lifecycle_operation_record and lifecycle_operation_record.get("provider") != provider:
        errors.append("provider audit worker lifecycle operation provider does not match receipt provider")
    if lifecycle_operation is None:
        if lifecycle_operation_record:
            warnings.append("provider audit worker lifecycle operation was not supplied; operation hash was not replayed")
    else:
        operation_result = verify_provider_lifecycle_operation_receipt(lifecycle_operation, lifecycle_manifest=lifecycle_manifest, key=key)
        if not operation_result.ok:
            errors.extend(f"provider audit worker lifecycle operation invalid: {error}" for error in operation_result.errors)
        warnings.extend(f"provider audit worker lifecycle operation warning: {warning}" for warning in operation_result.warnings)
        if lifecycle_operation_record != _lifecycle_operation_record(lifecycle_operation):
            errors.append("provider audit worker lifecycle operation record does not match supplied receipt")

    lifecycle_record = sources.get("lifecycle")
    if lifecycle_record is not None and not isinstance(lifecycle_record, dict):
        errors.append("provider audit worker sources.lifecycle must be an object")
        lifecycle_record = None
    if lifecycle_record and lifecycle_record.get("provider") != provider:
        errors.append("provider audit worker lifecycle provider does not match receipt provider")
    if lifecycle_manifest is None:
        if lifecycle_record:
            warnings.append("provider audit worker lifecycle manifest was not supplied; lifecycle hash was not replayed")
    else:
        lifecycle_result = verify_provider_lifecycle_manifest(lifecycle_manifest, key=key)
        if not lifecycle_result.ok:
            errors.extend(f"provider audit worker lifecycle invalid: {error}" for error in lifecycle_result.errors)
        warnings.extend(f"provider audit worker lifecycle warning: {warning}" for warning in lifecycle_result.warnings)
        if lifecycle_record != _lifecycle_record(lifecycle_manifest):
            errors.append("provider audit worker lifecycle record does not match supplied manifest")

    next_cursor_ref = scheduler.get("next_cursor_ref")
    last_stream_next_cursor = _last_stream_next_cursor(stream_records)
    if next_cursor_ref and last_stream_next_cursor and next_cursor_ref != last_stream_next_cursor:
        errors.append("provider audit worker scheduler.next_cursor_ref does not match last stream receipt next_cursor_ref")

    controls = receipt.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("provider audit worker controls are required")
    _check_no_secret_values(receipt, errors)

    return ProviderAuditWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_audit_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    stream_receipts: list[dict[str, Any]] | None = None,
    correlations: list[dict[str, Any]] | None = None,
    lifecycle_operation: dict[str, Any] | None = None,
    lifecycle_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_audit_worker_receipt(
        receipt,
        stream_receipts=stream_receipts,
        correlations=correlations,
        lifecycle_operation=lifecycle_operation,
        lifecycle_manifest=lifecycle_manifest,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid provider audit worker receipt: " + "; ".join(result.errors))
    payload = {
        "worker_operation_id": receipt["worker_operation_id"],
        "worker_operation_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "worker": receipt.get("worker"),
        "scheduler": receipt.get("scheduler"),
        "sources": receipt.get("sources"),
        "credential": receipt.get("credential"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(PROVIDER_AUDIT_WORKER_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("recorded_at"))


def _stream_records(stream_receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for receipt in stream_receipts:
        if not isinstance(receipt, dict):
            raise ValueError("stream_receipts must contain provider audit stream receipt objects")
        stream = receipt.get("stream", {}) if isinstance(receipt.get("stream"), dict) else {}
        records.append(
            {
                "stream_receipt_id": receipt.get("stream_receipt_id"),
                "stream_receipt_hash": content_hash(receipt),
                "provider": receipt.get("provider"),
                "stream_ref": stream.get("stream_ref"),
                "audit_log_ref": stream.get("audit_log_ref"),
                "window_start": stream.get("window_start"),
                "window_end": stream.get("window_end"),
                "cursor_ref": stream.get("cursor_ref"),
                "next_cursor_ref": stream.get("next_cursor_ref"),
                "success": stream.get("success"),
                "audit_log": receipt.get("audit_log"),
            }
        )
    return records


def _correlation_records(correlations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for correlation in correlations:
        if not isinstance(correlation, dict):
            raise ValueError("correlations must contain provider audit correlation objects")
        records.append(
            {
                "correlation_id": correlation.get("correlation_id"),
                "correlation_hash": content_hash(correlation),
                "provider": correlation.get("provider"),
                "audit_log_ref": correlation.get("audit_log_ref"),
                "audit_log": correlation.get("audit_log"),
                "match_count": len(correlation.get("matches", [])) if isinstance(correlation.get("matches"), list) else 0,
            }
        )
    return records


def _lifecycle_operation_record(receipt: dict[str, Any] | None) -> dict[str, Any] | None:
    if receipt is None:
        return None
    operation = receipt.get("operation", {}) if isinstance(receipt.get("operation"), dict) else {}
    return {
        "operation_receipt_id": receipt.get("operation_receipt_id"),
        "operation_receipt_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "recorded_at": receipt.get("recorded_at"),
        "operation_kind": operation.get("kind"),
        "operation_ref": operation.get("operation_ref"),
        "provider_event_ref": operation.get("provider_event_ref"),
        "success": operation.get("success"),
    }


def _lifecycle_record(manifest: dict[str, Any] | None) -> dict[str, Any] | None:
    if manifest is None:
        return None
    lifecycle = manifest.get("lifecycle", {}) if isinstance(manifest.get("lifecycle"), dict) else {}
    return {
        "lifecycle_manifest_id": manifest.get("lifecycle_manifest_id"),
        "lifecycle_manifest_hash": content_hash(manifest),
        "lifecycle_ref": lifecycle.get("lifecycle_ref"),
        "provider": lifecycle.get("provider"),
        "environment": lifecycle.get("environment"),
    }


def _derive_provider(
    stream_records: list[dict[str, Any]],
    correlation_records: list[dict[str, Any]],
    lifecycle_operation_record: dict[str, Any] | None,
    lifecycle_record: dict[str, Any] | None,
) -> str:
    providers: set[str] = set()
    for record in stream_records + correlation_records:
        provider = _normalize_provider(record.get("provider"))
        if provider:
            providers.add(provider)
    for record in (lifecycle_operation_record, lifecycle_record):
        if record:
            provider = _normalize_provider(record.get("provider"))
            if provider:
                providers.add(provider)
    if not providers:
        raise ValueError("provider audit worker provider could not be derived from source receipts")
    if len(providers) > 1:
        raise ValueError("provider audit worker source providers must match")
    return providers.pop()


def _controls(
    *,
    mode: str,
    operation_kind: str,
    stream_records: list[dict[str, Any]],
    correlation_records: list[dict[str, Any]],
    lifecycle_operation_record: dict[str, Any] | None,
    lifecycle_record: dict[str, Any] | None,
    schedule_ref: str,
    cadence_seconds: int,
    lease_ref: str,
    checkpoint_ref: str,
    credential_ref: str,
    next_cursor_ref: str | None,
) -> list[dict[str, Any]]:
    return [
        {
            "id": "provider-audit-worker-source-stream",
            "status": "implemented" if stream_records and all(record.get("success") is True for record in stream_records) else "planned-production",
            "description": "Worker run is bound to successful signed provider audit stream receipt sources.",
        },
        {
            "id": "provider-audit-correlation-worker",
            "status": "implemented" if correlation_records else "not-applicable" if operation_kind == "audit_stream_poll" else "planned-production",
            "description": "Worker run is bound to signed provider audit correlation receipts when correlation work is claimed.",
        },
        {
            "id": "provider-lifecycle-operation-binding",
            "status": "implemented" if lifecycle_operation_record else "planned-production",
            "description": "Worker run can bind the provider lifecycle operation that authorized or refreshed the audit stream.",
        },
        {
            "id": "provider-lifecycle-binding",
            "status": "implemented" if lifecycle_record else "planned-production",
            "description": "Worker run can bind the provider lifecycle manifest that declares audit-log stream operation references.",
        },
        {
            "id": "worker-scheduler-lease",
            "status": "implemented" if schedule_ref and cadence_seconds > 0 and lease_ref else "planned-production",
            "description": "Worker run records scheduler cadence and lease ownership metadata.",
        },
        {
            "id": "worker-checkpoint-continuity",
            "status": "implemented" if checkpoint_ref and next_cursor_ref else "local-reference" if checkpoint_ref else "planned-production",
            "description": "Worker run records a checkpoint and cursor handoff for replayable stream continuity.",
        },
        {
            "id": "redacted-worker-credential",
            "status": "implemented" if credential_ref else "planned-production",
            "description": "Provider audit worker credential material is represented only by a redacted reference.",
        },
        {
            "id": "continuously-hosted-audit-worker",
            "status": "implemented" if mode in {"hosted-worker", "provider-authenticated-streamer"} else "planned-production",
            "description": "Receipt claims continuous hosted worker operation only in hosted audit-worker modes.",
        },
    ]


def _stream_audit_hashes(stream_records: list[Any]) -> set[str]:
    hashes: set[str] = set()
    for record in stream_records:
        if isinstance(record, dict):
            audit_log = record.get("audit_log", {})
            if isinstance(audit_log, dict) and audit_log.get("hash"):
                hashes.add(str(audit_log["hash"]))
    return hashes


def _last_stream_next_cursor(stream_records: list[Any]) -> str | None:
    records = [record for record in stream_records if isinstance(record, dict)]
    if not records:
        return None
    last = sorted(records, key=lambda record: str(record.get("window_end") or ""))[-1]
    cursor = last.get("next_cursor_ref")
    return str(cursor) if cursor else None


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


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value.removeprefix("sha256:"))
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _require_text(value: str | None, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _normalize_provider(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized or None


def _check_no_secret_values(value: Any, errors: list[str], *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, item):
                    pass
                elif not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"provider audit worker secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    return key.endswith("_ref") and isinstance(value, str) and bool(value.strip())
