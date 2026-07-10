from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .policy_backend_worker import verify_policy_backend_worker_receipt

POLICY_BACKEND_PROVIDER_SCHEMA = "trustai.policy-backend-provider-export/0.1"
POLICY_BACKEND_PROVIDER_ENTRY_TYPE = "policy_backend.provider_exported"
POLICY_BACKEND_PROVIDER_MODES = {"local-export", "provider-export", "production-export"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class PolicyBackendProviderVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_policy_backend_provider_export(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("policy backend provider export must contain an object")
    return value


def load_policy_backend_provider_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("policy backend provider receipt must contain an object")
    return value


def write_policy_backend_provider_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_policy_backend_provider_receipt(
    provider_export: dict[str, Any],
    worker_receipt: dict[str, Any],
    service_attestation: dict[str, Any],
    enforcement_receipt: dict[str, Any],
    policy_pack: dict[str, Any],
    action: dict[str, Any],
    proof_pack: dict[str, Any],
    decision: dict[str, Any],
    policy_export: dict[str, Any],
    *,
    policy_engine_receipt: dict[str, Any] | None = None,
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
    if mode not in POLICY_BACKEND_PROVIDER_MODES:
        raise ValueError(f"mode must be one of {sorted(POLICY_BACKEND_PROVIDER_MODES)}")
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
        raise ValueError("policy backend provider response_status must be an integer")
    timestamp = exported_at or utc_now()
    parse_rfc3339(timestamp)

    worker_result = verify_policy_backend_worker_receipt(
        worker_receipt,
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
    if not worker_result.ok:
        raise ValueError("invalid policy backend worker source: " + "; ".join(worker_result.errors))

    window_start = _require_text(provider_export.get("window_start"), "provider_export.window_start")
    window_end = _require_text(provider_export.get("window_end"), "provider_export.window_end")
    start = parse_rfc3339(window_start)
    end = parse_rfc3339(window_end)
    if end < start:
        raise ValueError("policy backend provider export window_end must be at or after window_start")
    audit_log_ref = _require_text(provider_export.get("audit_log_ref"), "provider_export.audit_log_ref")
    audit_log_root = _require_text(provider_export.get("audit_log_root"), "provider_export.audit_log_root")

    binding = _worker_binding(worker_receipt)
    scheduler_records = _records(provider_export, "scheduler_records")
    queue_records = _records(provider_export, "queue_records")
    lease_records = _records(provider_export, "lease_records")
    backend_records = _records(provider_export, "backend_records")
    decision_log_records = _records(provider_export, "decision_log_records")
    audit_records = _records(provider_export, "audit_records")
    matched_scheduler = _matching_scheduler_record(scheduler_records, binding)
    matched_queue = _matching_queue_record(queue_records, binding)
    matched_lease = _matching_lease_record(lease_records, binding)
    matched_backend = _matching_backend_record(backend_records, binding)
    matched_decision_log = _matching_decision_log_record(decision_log_records, binding)
    matched_audit = _matching_audit_record(audit_records, binding)
    _validate_scheduler_record(matched_scheduler, binding)
    _validate_queue_record(matched_queue, binding)
    _validate_lease_record(matched_lease, binding)
    _validate_backend_record(matched_backend, binding)
    _validate_decision_log_record(matched_decision_log, binding)
    _validate_audit_record(matched_audit, binding)

    body: dict[str, Any] = {
        "schema": POLICY_BACKEND_PROVIDER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "exported_at": timestamp,
        "provider": normalized_provider,
        "worker_binding": binding,
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
            "lease_record_count": len(lease_records),
            "lease_record_root": content_hash(lease_records),
            "backend_record_count": len(backend_records),
            "backend_record_root": content_hash(backend_records),
            "decision_log_record_count": len(decision_log_records),
            "decision_log_record_root": content_hash(decision_log_records),
            "audit_record_count": len(audit_records),
            "audit_record_root": content_hash(audit_records),
        },
        "matched_scheduler_record": _record_summary(matched_scheduler),
        "matched_queue_record": _record_summary(matched_queue),
        "matched_lease_record": _record_summary(matched_lease),
        "matched_backend_record": _record_summary(matched_backend),
        "matched_decision_log_record": _record_summary(matched_decision_log),
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
        "controls": _controls(
            mode=mode,
            endpoint_url=endpoint_url,
            request_hash=request_hash,
            response_status=response_status,
            response_hash=response_hash,
            audit_log_root=audit_log_root,
            matched_backend=matched_backend,
            matched_decision_log=matched_decision_log,
            matched_audit=matched_audit,
        ),
        "limitations": [
            "This receipt binds a verified policy backend worker operation to provider-native scheduler, queue, lease, backend, decision-log, and audit export records.",
            "It stores provider export hashes, record roots, matched record hashes, and endpoint evidence, not raw provider credentials, OPA/Cedar request bodies, or decision log contents.",
            "It does not prove continuously operated production infrastructure unless mode is production-export and paired with live provider-owned export evidence.",
        ],
    }
    provider_receipt_id = content_hash(body)
    return {
        **body,
        "provider_receipt_id": provider_receipt_id,
        "signatures": [sign_value({"provider_receipt_id": provider_receipt_id, "policy_backend_provider": body}, key)],
    }


def verify_policy_backend_provider_receipt(
    receipt: dict[str, Any],
    *,
    provider_export: dict[str, Any] | None = None,
    worker_receipt: dict[str, Any] | None = None,
    service_attestation: dict[str, Any] | None = None,
    enforcement_receipt: dict[str, Any] | None = None,
    policy_pack: dict[str, Any] | None = None,
    action: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    policy_export: dict[str, Any] | None = None,
    policy_engine_receipt: dict[str, Any] | None = None,
    key: str | None = None,
) -> PolicyBackendProviderVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != POLICY_BACKEND_PROVIDER_SCHEMA:
        errors.append(f"unsupported policy backend provider schema: {receipt.get('schema')}")
    body = without_keys(receipt, "provider_receipt_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("provider_receipt_id") != expected_id:
        errors.append("provider_receipt_id does not match canonical policy backend provider body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("policy backend provider receipt must include at least one signature")
    else:
        signed_value = {"provider_receipt_id": receipt.get("provider_receipt_id"), "policy_backend_provider": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("policy backend provider signature verification failed")

    mode = receipt.get("mode")
    if mode not in POLICY_BACKEND_PROVIDER_MODES:
        errors.append("policy backend provider mode is unsupported")
    elif mode != "production-export":
        warnings.append(f"policy backend provider mode is {mode}; live provider-owned policy backend export is not claimed")
    try:
        parse_rfc3339(str(receipt.get("exported_at") or ""))
    except ValueError as exc:
        errors.append(f"policy backend provider exported_at invalid: {exc}")
    if not _normalize_provider(receipt.get("provider")):
        errors.append("policy backend provider provider is required")

    binding = receipt.get("worker_binding", {})
    if not isinstance(binding, dict):
        errors.append("policy backend provider worker_binding must be an object")
        binding = {}
    _verify_worker_binding(
        binding,
        worker_receipt,
        service_attestation,
        enforcement_receipt,
        policy_pack,
        action,
        proof_pack,
        decision,
        policy_export,
        policy_engine_receipt,
        key,
        errors,
        warnings,
    )
    _verify_provider_export_binding(receipt, provider_export, binding, errors, warnings)
    _verify_provider_exchange(receipt.get("provider_exchange"), errors)
    _verify_redacted_ref(receipt.get("credential"), "policy backend provider credential", errors)
    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("policy backend provider controls are required")
    _check_no_secret_values(receipt, errors)
    return PolicyBackendProviderVerification(ok=not errors, errors=errors, warnings=warnings)


def append_policy_backend_provider_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    provider_export: dict[str, Any],
    worker_receipt: dict[str, Any],
    service_attestation: dict[str, Any],
    enforcement_receipt: dict[str, Any],
    policy_pack: dict[str, Any],
    action: dict[str, Any],
    proof_pack: dict[str, Any],
    decision: dict[str, Any],
    policy_export: dict[str, Any],
    policy_engine_receipt: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_policy_backend_provider_receipt(
        receipt,
        provider_export=provider_export,
        worker_receipt=worker_receipt,
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
        raise ValueError("invalid policy backend provider receipt: " + "; ".join(result.errors))
    payload = {
        "provider_receipt_id": receipt["provider_receipt_id"],
        "provider_receipt_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "provider": receipt.get("provider"),
        "worker_operation_id": receipt.get("worker_binding", {}).get("worker_operation_id"),
        "run_ref": receipt.get("worker_binding", {}).get("run_ref"),
        "provider_export": receipt.get("provider_export"),
        "matched_scheduler_record": receipt.get("matched_scheduler_record"),
        "matched_queue_record": receipt.get("matched_queue_record"),
        "matched_lease_record": receipt.get("matched_lease_record"),
        "matched_backend_record": receipt.get("matched_backend_record"),
        "matched_decision_log_record": receipt.get("matched_decision_log_record"),
        "matched_audit_record": receipt.get("matched_audit_record"),
        "provider_exchange": receipt.get("provider_exchange"),
        "credential_ref": receipt.get("credential", {}).get("ref"),
        "controls_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(POLICY_BACKEND_PROVIDER_ENTRY_TYPE, payload)


def _worker_binding(worker_receipt: dict[str, Any]) -> dict[str, Any]:
    worker = worker_receipt.get("worker", {}) if isinstance(worker_receipt.get("worker"), dict) else {}
    scheduler = worker_receipt.get("scheduler", {}) if isinstance(worker_receipt.get("scheduler"), dict) else {}
    execution = worker_receipt.get("execution", {}) if isinstance(worker_receipt.get("execution"), dict) else {}
    observability = worker_receipt.get("observability", {}) if isinstance(worker_receipt.get("observability"), dict) else {}
    service = worker_receipt.get("service", {}) if isinstance(worker_receipt.get("service"), dict) else {}
    source_enforcement = worker_receipt.get("source_enforcement", {}) if isinstance(worker_receipt.get("source_enforcement"), dict) else {}
    return {
        "worker_operation_id": worker_receipt.get("worker_operation_id"),
        "worker_operation_hash": content_hash(worker_receipt),
        "service_attestation_id": service.get("attestation_id"),
        "enforcement_id": source_enforcement.get("enforcement_id"),
        "run_ref": worker.get("run_ref"),
        "operation_kind": worker.get("operation_kind"),
        "schedule_ref": scheduler.get("schedule_ref"),
        "lease_ref": scheduler.get("lease_ref"),
        "checkpoint_ref": scheduler.get("checkpoint_ref"),
        "checkpoint_hash": scheduler.get("checkpoint_hash"),
        "previous_cursor_ref": scheduler.get("previous_cursor_ref"),
        "next_cursor_ref": scheduler.get("next_cursor_ref"),
        "next_run_at": scheduler.get("next_run_at"),
        "queue_ref": execution.get("queue_ref"),
        "queue_message_ref": execution.get("queue_message_ref"),
        "queue_message_hash": execution.get("queue_message_hash"),
        "dead_letter_queue_ref": execution.get("dead_letter_queue_ref"),
        "backend_ref": execution.get("backend_ref"),
        "engine": execution.get("engine"),
        "endpoint_url": execution.get("endpoint_url"),
        "bundle_ref": execution.get("bundle_ref"),
        "bundle_hash": execution.get("bundle_hash"),
        "backend_request_ref": execution.get("backend_request_ref"),
        "request_hash": execution.get("request_hash"),
        "response_status": execution.get("response_status"),
        "response_hash": execution.get("response_hash"),
        "response_accepted": execution.get("response_accepted"),
        "decision_hash": source_enforcement.get("decision_hash"),
        "decision_log_ref": observability.get("decision_log_ref"),
        "decision_log_root": observability.get("decision_log_root"),
        "decision_record_hash": observability.get("decision_record_hash"),
        "metrics_ref": observability.get("metrics_ref"),
        "audit_log_ref": observability.get("audit_log_ref"),
        "audit_log_root": observability.get("audit_log_root"),
    }


def _verify_worker_binding(
    binding: dict[str, Any],
    worker_receipt: dict[str, Any] | None,
    service_attestation: dict[str, Any] | None,
    enforcement_receipt: dict[str, Any] | None,
    policy_pack: dict[str, Any] | None,
    action: dict[str, Any] | None,
    proof_pack: dict[str, Any] | None,
    decision: dict[str, Any] | None,
    policy_export: dict[str, Any] | None,
    policy_engine_receipt: dict[str, Any] | None,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    for field in (
        "worker_operation_id",
        "worker_operation_hash",
        "service_attestation_id",
        "enforcement_id",
        "run_ref",
        "operation_kind",
        "schedule_ref",
        "lease_ref",
        "checkpoint_ref",
        "checkpoint_hash",
        "queue_ref",
        "queue_message_ref",
        "queue_message_hash",
        "backend_ref",
        "engine",
        "endpoint_url",
        "bundle_ref",
        "bundle_hash",
        "request_hash",
        "response_status",
        "response_hash",
        "decision_hash",
        "decision_log_ref",
        "decision_log_root",
        "audit_log_ref",
        "audit_log_root",
    ):
        if binding.get(field) in (None, ""):
            errors.append(f"policy backend provider binding.{field} is required")
    if worker_receipt is None:
        warnings.append("policy backend provider worker artifact was not supplied; worker source was not replayed")
        return
    expected = _worker_binding(worker_receipt)
    if binding != expected:
        errors.append("policy backend provider worker_binding does not match supplied worker receipt")
    result = verify_policy_backend_worker_receipt(
        worker_receipt,
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
        errors.extend(f"policy backend provider worker source: {error}" for error in result.errors)
    warnings.extend(f"policy backend provider worker source: {warning}" for warning in result.warnings)


def _verify_provider_export_binding(receipt: dict[str, Any], provider_export: dict[str, Any] | None, binding: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    export = receipt.get("provider_export", {})
    if not isinstance(export, dict):
        errors.append("policy backend provider provider_export must be an object")
        return
    for field in ("hash", "scheduler_record_root", "queue_record_root", "lease_record_root", "backend_record_root", "decision_log_record_root", "audit_record_root", "audit_log_root"):
        if not export.get(field):
            errors.append(f"policy backend provider provider_export.{field} is required")
    if provider_export is None:
        warnings.append("policy backend provider export artifact was not supplied; provider records were not replayed")
        return
    if export.get("hash") != content_hash(provider_export):
        errors.append("policy backend provider export hash does not match supplied provider export")
    scheduler_records = _records(provider_export, "scheduler_records")
    queue_records = _records(provider_export, "queue_records")
    lease_records = _records(provider_export, "lease_records")
    backend_records = _records(provider_export, "backend_records")
    decision_log_records = _records(provider_export, "decision_log_records")
    audit_records = _records(provider_export, "audit_records")
    expected = {
        "scheduler_record_count": len(scheduler_records),
        "scheduler_record_root": content_hash(scheduler_records),
        "queue_record_count": len(queue_records),
        "queue_record_root": content_hash(queue_records),
        "lease_record_count": len(lease_records),
        "lease_record_root": content_hash(lease_records),
        "backend_record_count": len(backend_records),
        "backend_record_root": content_hash(backend_records),
        "decision_log_record_count": len(decision_log_records),
        "decision_log_record_root": content_hash(decision_log_records),
        "audit_record_count": len(audit_records),
        "audit_record_root": content_hash(audit_records),
    }
    for field, value in expected.items():
        if export.get(field) != value:
            errors.append(f"policy backend provider export {field} does not match supplied provider export")
    try:
        _validate_scheduler_record(_matching_scheduler_record(scheduler_records, binding), binding)
        _validate_queue_record(_matching_queue_record(queue_records, binding), binding)
        _validate_lease_record(_matching_lease_record(lease_records, binding), binding)
        _validate_backend_record(_matching_backend_record(backend_records, binding), binding)
        _validate_decision_log_record(_matching_decision_log_record(decision_log_records, binding), binding)
        _validate_audit_record(_matching_audit_record(audit_records, binding), binding)
    except ValueError as exc:
        errors.append(f"policy backend provider export record mismatch: {exc}")


def _matching_scheduler_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    return _find_record(records, lambda record: record.get("worker_run_ref") == binding.get("run_ref") and record.get("lease_ref") == binding.get("lease_ref"), "scheduler")


def _matching_queue_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    return _find_record(records, lambda record: record.get("queue_message_ref") == binding.get("queue_message_ref"), "queue")


def _matching_lease_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    return _find_record(records, lambda record: record.get("worker_run_ref") == binding.get("run_ref") and record.get("lease_ref") == binding.get("lease_ref"), "lease")


def _matching_backend_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    return _find_record(records, lambda record: record.get("backend_request_ref") == binding.get("backend_request_ref") and record.get("request_hash") == binding.get("request_hash"), "backend")


def _matching_decision_log_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    return _find_record(records, lambda record: record.get("decision_log_ref") == binding.get("decision_log_ref") and record.get("decision_record_hash") == binding.get("decision_record_hash"), "decision_log")


def _matching_audit_record(records: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    return _find_record(records, lambda record: record.get("audit_log_ref") == binding.get("audit_log_ref") and record.get("audit_log_root") == binding.get("audit_log_root"), "audit")


def _find_record(records: list[dict[str, Any]], predicate: Any, name: str) -> dict[str, Any]:
    for record in records:
        if predicate(record):
            return record
    raise ValueError(f"missing matching {name} record")


def _validate_scheduler_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    for field in ("schedule_ref", "lease_ref", "checkpoint_ref", "checkpoint_hash", "previous_cursor_ref", "next_cursor_ref", "next_run_at"):
        if record.get(field) != binding.get(field):
            raise ValueError(f"scheduler record {field} does not match worker binding")


def _validate_queue_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    for field in ("queue_ref", "queue_message_ref", "queue_message_hash"):
        if record.get(field) != binding.get(field):
            raise ValueError(f"queue record {field} does not match worker binding")
    if binding.get("dead_letter_queue_ref") and record.get("dead_letter_queue_ref") != binding.get("dead_letter_queue_ref"):
        raise ValueError("queue record dead_letter_queue_ref does not match worker binding")


def _validate_lease_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    for field in ("lease_ref", "checkpoint_ref", "checkpoint_hash", "previous_cursor_ref", "next_cursor_ref"):
        if record.get(field) != binding.get(field):
            raise ValueError(f"lease record {field} does not match worker binding")
    if record.get("worker_run_ref") != binding.get("run_ref"):
        raise ValueError("lease record worker_run_ref does not match worker binding")


def _validate_backend_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    for field in ("backend_ref", "engine", "endpoint_url", "bundle_ref", "bundle_hash", "backend_request_ref", "request_hash", "response_status", "response_hash", "response_accepted", "decision_hash"):
        if record.get(field) != binding.get(field):
            raise ValueError(f"backend record {field} does not match worker binding")


def _validate_decision_log_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    for field in ("decision_log_ref", "decision_log_root", "decision_record_hash", "decision_hash"):
        if record.get(field) != binding.get(field):
            raise ValueError(f"decision log record {field} does not match worker binding")


def _validate_audit_record(record: dict[str, Any], binding: dict[str, Any]) -> None:
    for field in ("audit_log_ref", "audit_log_root", "metrics_ref"):
        if record.get(field) != binding.get(field):
            raise ValueError(f"audit record {field} does not match worker binding")


def _record_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": record.get("record_id"),
        "kind": record.get("kind"),
        "ref": record.get("ref") or record.get("queue_message_ref") or record.get("lease_ref") or record.get("backend_request_ref") or record.get("decision_log_ref") or record.get("audit_log_ref"),
        "hash": record.get("hash") or record.get("queue_message_hash") or record.get("checkpoint_hash") or record.get("response_hash") or record.get("decision_record_hash") or record.get("audit_log_root"),
        "record_hash": content_hash(record),
    }


def _records(export: dict[str, Any], name: str) -> list[dict[str, Any]]:
    value = export.get(name, [])
    if not isinstance(value, list):
        raise ValueError(f"policy backend provider export {name} must be a list")
    if not value:
        raise ValueError(f"policy backend provider export {name} is required")
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"policy backend provider export {name}[{index}] must be an object")
    return value


def _verify_provider_exchange(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend provider provider_exchange must be an object")
        return
    for field in ("endpoint_url", "request_hash", "response_status", "response_hash", "actor_ref"):
        if value.get(field) in (None, ""):
            errors.append(f"policy backend provider provider_exchange.{field} is required")
    endpoint = str(value.get("endpoint_url") or "")
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        errors.append("policy backend provider provider_exchange.endpoint_url must be an absolute HTTP(S) URL")
    if value.get("request_hash") and not _is_sha256_ref(str(value.get("request_hash"))):
        errors.append("policy backend provider provider_exchange.request_hash must be a sha256 reference")
    if value.get("response_hash") and not _is_sha256_ref(str(value.get("response_hash"))):
        errors.append("policy backend provider provider_exchange.response_hash must be a sha256 reference")
    status = value.get("response_status")
    if not isinstance(status, int) or status < 100 or status > 599:
        errors.append("policy backend provider provider_exchange.response_status must be an HTTP status code")


def _controls(
    mode: str,
    endpoint_url: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    audit_log_root: str,
    matched_backend: dict[str, Any],
    matched_decision_log: dict[str, Any],
    matched_audit: dict[str, Any],
) -> list[dict[str, str]]:
    endpoint_ok = bool(urlparse(endpoint_url).netloc) and _is_sha256_ref(request_hash) and _is_sha256_ref(response_hash) and 200 <= response_status < 300
    return [
        {
            "id": "policy-backend-provider-export-mode",
            "status": "passed" if mode in {"provider-export", "production-export"} else "deferred",
            "description": "Provider export mode records provider-native policy backend worker evidence.",
        },
        {
            "id": "policy-backend-provider-endpoint-bound",
            "status": "passed" if endpoint_ok else "failed",
            "description": "Provider endpoint, request hash, response hash, response status, and actor are recorded.",
        },
        {
            "id": "policy-backend-provider-scheduler-queue-lease",
            "status": "passed",
            "description": "Scheduler, queue, lease, checkpoint, and cursor records are replayed.",
        },
        {
            "id": "policy-backend-provider-backend-response",
            "status": "passed" if matched_backend.get("response_hash") and matched_backend.get("response_accepted") else "failed",
            "description": "OPA/Cedar backend request and response evidence is replayed.",
        },
        {
            "id": "policy-backend-provider-decision-log",
            "status": "passed" if matched_decision_log.get("decision_record_hash") and matched_decision_log.get("decision_log_root") else "failed",
            "description": "Decision-log root and matched decision record hash are replayed.",
        },
        {
            "id": "policy-backend-provider-audit-root",
            "status": "passed" if _is_sha256_ref(audit_log_root) and matched_audit.get("audit_log_root") else "failed",
            "description": "Provider export audit root and worker audit record are replayed.",
        },
    ]


def _redacted_ref(ref: str | None) -> dict[str, Any]:
    if not ref:
        raise ValueError("policy backend provider credential_ref is required")
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _require_provider(value: Any) -> str:
    normalized = _normalize_provider(value)
    if not normalized:
        raise ValueError("policy backend provider provider is required")
    return normalized


def _normalize_provider(value: Any) -> str:
    return str(value or "").strip().lower()


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"policy backend provider {field} is required")
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
                    errors.append(f"policy backend provider secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        return True
    if (key.endswith("_root") or key.endswith("_hash")) and isinstance(value, str) and value.startswith("sha256:"):
        return True
    return False
