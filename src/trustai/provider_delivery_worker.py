from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .delivery import verify_provider_delivery
from .provider_delivery_service import verify_provider_delivery_service_attestation

PROVIDER_DELIVERY_WORKER_SCHEMA = "trustai.provider-delivery-worker/0.1"
PROVIDER_DELIVERY_WORKER_ENTRY_TYPE = "provider.delivery_worker_recorded"
PROVIDER_DELIVERY_WORKER_MODES = {
    "local-reference",
    "scheduled-worker",
    "dispatch-worker",
    "hosted-worker",
    "production-design",
}
PROVIDER_DELIVERY_WORKER_OPERATION_KINDS = {
    "provider_payload_dispatch",
    "provider_response_record",
    "provider_retry",
    "provider_dlq_enqueue",
    "provider_status_reconcile",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ProviderDeliveryWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_provider_delivery_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider delivery worker receipt must contain an object")
    return value


def write_provider_delivery_worker_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_provider_delivery_worker_receipt(
    service_attestation: dict[str, Any],
    delivery: dict[str, Any],
    *,
    payload: dict[str, Any] | None = None,
    provider_operations_service: dict[str, Any] | None = None,
    mode: str = "dispatch-worker",
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
    queue_ref: str,
    queue_message_ref: str | None = None,
    dead_letter_queue_ref: str,
    destination_ref: str,
    idempotency_record_hash: str | None = None,
    provider_request_ref: str | None = None,
    request_hash: str | None = None,
    response_status: int | None = None,
    response_hash: str | None = None,
    rate_limit_bucket_ref: str | None = None,
    retry_after_seconds: int | None = None,
    delivery_log_ref: str,
    delivery_log_root: str,
    provider_event_log_ref: str | None = None,
    provider_event_log_root: str | None = None,
    metrics_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    credential_ref: str,
    provider_credential_ref: str,
    retention_until: str,
    evidence_refs: list[str] | None = None,
    started_at: str,
    completed_at: str | None = None,
    error_ref: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in PROVIDER_DELIVERY_WORKER_MODES:
        raise ValueError(f"mode must be one of {sorted(PROVIDER_DELIVERY_WORKER_MODES)}")
    if operation_kind not in PROVIDER_DELIVERY_WORKER_OPERATION_KINDS:
        raise ValueError(f"operation_kind must be one of {sorted(PROVIDER_DELIVERY_WORKER_OPERATION_KINDS)}")
    if not isinstance(service_attestation, dict):
        raise ValueError("service_attestation must be an object")
    if not isinstance(delivery, dict):
        raise ValueError("delivery must be an object")

    for value, field in (
        (environment, "environment"),
        (worker_ref, "worker_ref"),
        (run_ref, "run_ref"),
        (actor_ref, "actor_ref"),
        (schedule_ref, "schedule_ref"),
        (lease_ref, "lease_ref"),
        (checkpoint_ref, "checkpoint_ref"),
        (queue_ref, "queue_ref"),
        (dead_letter_queue_ref, "dead_letter_queue_ref"),
        (destination_ref, "destination_ref"),
        (delivery_log_ref, "delivery_log_ref"),
        (delivery_log_root, "delivery_log_root"),
        (metrics_ref, "metrics_ref"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (credential_ref, "credential_ref"),
        (provider_credential_ref, "provider_credential_ref"),
        (retention_until, "retention_until"),
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
    if retry_after_seconds is not None and (not isinstance(retry_after_seconds, int) or retry_after_seconds < 0):
        raise ValueError("retry_after_seconds must be a non-negative integer")

    delivery_credential = delivery.get("credential", {}) if isinstance(delivery.get("credential"), dict) else {}
    if delivery_credential.get("ref") != provider_credential_ref:
        raise ValueError("provider_credential_ref must match delivery credential ref")
    service_credential = service_attestation.get("dispatch", {}).get("provider_credential", {})
    if isinstance(service_credential, dict) and service_credential.get("ref") != provider_credential_ref:
        raise ValueError("provider_credential_ref must match service dispatch provider credential ref")

    service_result = verify_provider_delivery_service_attestation(
        service_attestation,
        delivery=delivery,
        payload=payload,
        provider_operations_service=provider_operations_service,
        key=key,
    )
    if not service_result.ok:
        raise ValueError("invalid provider delivery service source: " + "; ".join(service_result.errors))

    delivery_result = verify_provider_delivery(delivery, payload, key=key)
    if not delivery_result.ok:
        raise ValueError("invalid provider delivery source: " + "; ".join(delivery_result.errors))

    service = _service_record(service_attestation)
    if service.get("queue_ref") and queue_ref != service.get("queue_ref"):
        raise ValueError("queue_ref must match provider delivery service queue_ref")
    if service.get("dead_letter_queue_ref") and dead_letter_queue_ref != service.get("dead_letter_queue_ref"):
        raise ValueError("dead_letter_queue_ref must match provider delivery service dead_letter_queue_ref")

    source_delivery = _delivery_record(delivery)
    if destination_ref != source_delivery.get("target_url"):
        raise ValueError("destination_ref must match delivery target_url")

    resolved_request_hash = request_hash or source_delivery.get("request_body_hash")
    response = delivery.get("response", {}) if isinstance(delivery.get("response"), dict) else {}
    resolved_response_status = response_status if response_status is not None else response.get("status")
    resolved_response_hash = response_hash or response.get("body_hash")
    resolved_idempotency_hash = idempotency_record_hash or content_hash(
        {"delivery_id": delivery.get("delivery_id"), "idempotency_key": delivery.get("idempotency_key")}
    )

    for field, value in (
        ("checkpoint_hash", checkpoint_hash),
        ("idempotency_record_hash", resolved_idempotency_hash),
        ("request_hash", resolved_request_hash),
        ("response_hash", resolved_response_hash),
        ("delivery_log_root", delivery_log_root),
        ("provider_event_log_root", provider_event_log_root),
        ("audit_log_root", audit_log_root),
    ):
        if value and not _is_sha256_ref(str(value)):
            raise ValueError(f"{field} must be a sha256 reference")

    response_success = resolved_response_status is None or 200 <= int(resolved_response_status) < 300
    source_response_success = source_delivery.get("response_accepted")
    if source_response_success is False:
        response_success = False
    success = not error_ref and response_success

    source_artifacts = _source_artifacts(
        service_attestation=service_attestation,
        delivery=delivery,
        payload=payload,
        provider_operations_service=provider_operations_service,
    )
    body: dict[str, Any] = {
        "schema": PROVIDER_DELIVERY_WORKER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": completed,
        "service": service,
        "source_delivery": source_delivery,
        "source": _source_summary(source_artifacts),
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
        "dispatch": {
            "queue_ref": queue_ref,
            "queue_message_ref": queue_message_ref,
            "dead_letter_queue_ref": dead_letter_queue_ref,
            "destination_ref": destination_ref,
            "idempotency_key": delivery.get("idempotency_key"),
            "idempotency_record_hash": resolved_idempotency_hash,
            "provider_request_ref": provider_request_ref,
            "request_hash": resolved_request_hash,
            "response_status": resolved_response_status,
            "response_hash": resolved_response_hash,
            "response_accepted": response_success,
            "rate_limit_bucket_ref": rate_limit_bucket_ref,
            "retry_after_seconds": retry_after_seconds,
        },
        "observability": {
            "delivery_log_ref": delivery_log_ref,
            "delivery_log_root": delivery_log_root,
            "provider_event_log_ref": provider_event_log_ref,
            "provider_event_log_root": provider_event_log_root,
            "metrics_ref": metrics_ref,
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "retention_until": retention_until,
            "evidence_refs": sorted(evidence_refs or []),
        },
        "credential": _redacted_ref(credential_ref),
        "provider_credential": _redacted_ref(provider_credential_ref),
        "source_artifacts": source_artifacts,
        "controls": _controls(
            mode=mode,
            service=service,
            source_delivery=source_delivery,
            cadence_seconds=cadence_seconds,
            checkpoint_hash=checkpoint_hash,
            idempotency_record_hash=resolved_idempotency_hash,
            delivery_log_root=delivery_log_root,
            provider_event_log_root=provider_event_log_root,
            audit_log_root=audit_log_root,
            response_status=resolved_response_status,
            credential_ref=credential_ref,
            provider_credential_ref=provider_credential_ref,
            success=success,
        ),
        "limitations": [
            "This receipt records one provider delivery worker operation and replays the signed delivery service source.",
            "It binds scheduler lease/checkpoint state, queue/DLQ metadata, idempotency evidence, provider request/response hashes, delivery and audit roots, and redacted worker/provider credentials.",
            "It stores provider payload and response hashes, not raw provider API tokens or OAuth material.",
            "It does not claim continuously operated external provider dispatch unless paired with production scheduler, queue, credential custody, provider response, and immutable provider/audit-log exports.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [sign_value({"worker_operation_id": worker_operation_id, "provider_delivery_worker": body}, key)],
    }


def verify_provider_delivery_worker_receipt(
    receipt: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    delivery: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    provider_operations_service: dict[str, Any] | None = None,
    key: str | None = None,
) -> ProviderDeliveryWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != PROVIDER_DELIVERY_WORKER_SCHEMA:
        errors.append(f"unsupported provider delivery worker schema: {receipt.get('schema')}")
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append("worker_operation_id does not match canonical provider delivery worker body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider delivery worker receipt must include at least one signature")
    else:
        signed_value = {"worker_operation_id": receipt.get("worker_operation_id"), "provider_delivery_worker": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider delivery worker signature verification failed")

    try:
        recorded = parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"provider delivery worker recorded_at invalid: {exc}")
        recorded = None

    mode = receipt.get("mode")
    if mode not in PROVIDER_DELIVERY_WORKER_MODES:
        errors.append("provider delivery worker mode is unsupported")
    elif mode not in {"dispatch-worker", "hosted-worker"}:
        warnings.append(f"provider delivery worker mode is {mode}; hosted dispatch worker operation is not fully claimed")

    _verify_service(receipt.get("service"), errors)
    _verify_source_delivery(receipt.get("source_delivery"), errors)
    _verify_source(receipt.get("source"), errors)
    _verify_worker(receipt.get("worker"), receipt.get("recorded_at"), errors)
    _verify_scheduler(receipt.get("scheduler"), errors)
    _verify_dispatch(receipt.get("dispatch"), errors)
    _verify_observability(receipt.get("observability"), recorded, errors)
    _verify_redacted_ref(receipt.get("credential"), "provider delivery worker credential", errors)
    _verify_redacted_ref(receipt.get("provider_credential"), "provider delivery worker provider_credential", errors)
    _verify_source_artifacts(receipt.get("source_artifacts"), errors)
    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("provider delivery worker controls are required")

    if service_attestation is None:
        warnings.append("provider delivery service attestation artifact was not supplied; service hash was not replayed")
    else:
        _compare_source_hash(receipt, "provider-delivery-service-attestation", service_attestation, errors)
        service_hash = receipt.get("service", {}).get("attestation_hash") if isinstance(receipt.get("service"), dict) else None
        if service_hash != content_hash(service_attestation):
            errors.append("provider delivery worker service.attestation_hash does not match supplied service attestation")
        service_result = verify_provider_delivery_service_attestation(
            service_attestation,
            delivery=delivery,
            payload=payload,
            provider_operations_service=provider_operations_service,
            key=key,
        )
        if not service_result.ok:
            errors.extend(f"provider delivery worker service source: {error}" for error in service_result.errors)
        warnings.extend(f"provider delivery worker service source: {warning}" for warning in service_result.warnings)

    if delivery is not None:
        _compare_source_hash(receipt, "provider-delivery", delivery, errors)
        delivery_hash = receipt.get("source_delivery", {}).get("delivery_hash") if isinstance(receipt.get("source_delivery"), dict) else None
        if delivery_hash != content_hash(delivery):
            errors.append("provider delivery worker source_delivery.delivery_hash does not match supplied delivery")
        delivery_result = verify_provider_delivery(delivery, payload, key=key)
        if not delivery_result.ok:
            errors.extend(f"provider delivery worker delivery source: {error}" for error in delivery_result.errors)
        warnings.extend(f"provider delivery worker delivery source: {warning}" for warning in delivery_result.warnings)

    for source_type, source_value in (
        ("provider-payload", payload),
        ("provider-operations-service-attestation", provider_operations_service),
    ):
        if source_value is not None:
            _compare_source_hash(receipt, source_type, source_value, errors)

    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    dispatch = receipt.get("dispatch", {}) if isinstance(receipt.get("dispatch"), dict) else {}
    response_status = dispatch.get("response_status")
    response_success = response_status is None or (isinstance(response_status, int) and 200 <= response_status < 300)
    expected_success = not worker.get("error_ref") and response_success
    if isinstance(worker.get("success"), bool) and worker.get("success") is not expected_success:
        errors.append("provider delivery worker success must match response status and error_ref")
    if isinstance(dispatch.get("response_accepted"), bool) and dispatch.get("response_accepted") is not response_success:
        errors.append("provider delivery worker dispatch.response_accepted must match response_status")

    _check_no_secret_values(receipt, errors)
    return ProviderDeliveryWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_delivery_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    delivery: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    provider_operations_service: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_delivery_worker_receipt(
        receipt,
        service_attestation=service_attestation,
        delivery=delivery,
        payload=payload,
        provider_operations_service=provider_operations_service,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid provider delivery worker receipt: " + "; ".join(result.errors))
    payload_value = {
        "worker_operation_id": receipt["worker_operation_id"],
        "worker_operation_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "service": receipt.get("service"),
        "source_delivery": receipt.get("source_delivery"),
        "source": receipt.get("source"),
        "worker": receipt.get("worker"),
        "scheduler": receipt.get("scheduler"),
        "dispatch": receipt.get("dispatch"),
        "observability": receipt.get("observability"),
        "credential": receipt.get("credential"),
        "provider_credential": receipt.get("provider_credential"),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(PROVIDER_DELIVERY_WORKER_ENTRY_TYPE, payload_value, key=key, timestamp=receipt.get("recorded_at"))


def _service_record(attestation: dict[str, Any]) -> dict[str, Any]:
    service = attestation.get("service", {}) if isinstance(attestation.get("service"), dict) else {}
    dispatch = attestation.get("dispatch", {}) if isinstance(attestation.get("dispatch"), dict) else {}
    security = attestation.get("security", {}) if isinstance(attestation.get("security"), dict) else {}
    observability = attestation.get("observability", {}) if isinstance(attestation.get("observability"), dict) else {}
    provider_credential = dispatch.get("provider_credential", {}) if isinstance(dispatch.get("provider_credential"), dict) else {}
    return {
        "attestation_id": attestation.get("attestation_id"),
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "service_ref": service.get("service_ref"),
        "service_version": service.get("version"),
        "provider": service.get("provider"),
        "dispatch_worker_ref": dispatch.get("dispatch_worker_ref"),
        "queue_ref": dispatch.get("queue_ref"),
        "dead_letter_queue_ref": dispatch.get("dead_letter_queue_ref"),
        "idempotency_store_ref": dispatch.get("idempotency_store_ref"),
        "retry_policy_ref": dispatch.get("retry_policy_ref"),
        "outbound_proxy_ref": dispatch.get("outbound_proxy_ref"),
        "provider_endpoint_base": dispatch.get("provider_endpoint_base"),
        "provider_credential": _redacted_ref(provider_credential.get("ref")),
        "source_delivery_id": dispatch.get("source_delivery_id"),
        "source_delivery_mode": dispatch.get("source_delivery_mode"),
        "rate_limit_policy_ref": security.get("rate_limit_policy_ref"),
        "request_signing_policy_ref": security.get("request_signing_policy_ref"),
        "service_audit_log_root": observability.get("audit_log_root"),
    }


def _delivery_record(delivery: dict[str, Any]) -> dict[str, Any]:
    request = delivery.get("request", {}) if isinstance(delivery.get("request"), dict) else {}
    response = delivery.get("response", {}) if isinstance(delivery.get("response"), dict) else {}
    return {
        "delivery_id": delivery.get("delivery_id"),
        "delivery_hash": content_hash(delivery),
        "mode": delivery.get("mode"),
        "provider": delivery.get("provider"),
        "target_url": delivery.get("target_url"),
        "payload_hash": delivery.get("payload_hash"),
        "pack_id": delivery.get("pack_id"),
        "contract_id": delivery.get("contract_id"),
        "contract_hash": delivery.get("contract_hash"),
        "request_method": request.get("method"),
        "request_path": request.get("path"),
        "request_body_hash": request.get("body_hash"),
        "idempotency_key": delivery.get("idempotency_key"),
        "response_status": response.get("status"),
        "response_body_hash": response.get("body_hash"),
        "response_accepted": response.get("accepted"),
    }


def _source_artifacts(
    *,
    service_attestation: dict[str, Any] | None,
    delivery: dict[str, Any] | None,
    payload: dict[str, Any] | None,
    provider_operations_service: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for source_type, value in (
        ("provider-delivery-service-attestation", service_attestation),
        ("provider-delivery", delivery),
        ("provider-payload", payload),
        ("provider-operations-service-attestation", provider_operations_service),
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


def _source_id(value: dict[str, Any]) -> Any:
    for key_name in ("attestation_id", "delivery_id", "payload_hash", "pack_id", "id"):
        if value.get(key_name):
            return value.get(key_name)
    return value.get("schema")


def _controls(
    *,
    mode: str,
    service: dict[str, Any],
    source_delivery: dict[str, Any],
    cadence_seconds: int,
    checkpoint_hash: str | None,
    idempotency_record_hash: str | None,
    delivery_log_root: str,
    provider_event_log_root: str | None,
    audit_log_root: str,
    response_status: int | None,
    credential_ref: str,
    provider_credential_ref: str,
    success: bool,
) -> list[dict[str, str]]:
    return [
        {"id": "provider-delivery-service-source-bound", "status": "worker-recorded" if service.get("attestation_hash") and source_delivery.get("delivery_hash") else "planned-production", "description": "Worker run is bound to signed delivery service and source delivery hashes."},
        {"id": "hosted-provider-delivery-worker-operation", "status": "worker-recorded" if mode in {"dispatch-worker", "hosted-worker"} else "planned-production", "description": "Receipt records hosted provider delivery worker operation only in worker modes."},
        {"id": "delivery-worker-scheduler-lease", "status": "worker-recorded" if cadence_seconds > 0 and checkpoint_hash else "planned-production", "description": "Scheduler cadence, lease ownership, checkpoint reference, and checkpoint hash are bound."},
        {"id": "delivery-worker-idempotency", "status": "worker-recorded" if idempotency_record_hash and service.get("idempotency_store_ref") else "planned-production", "description": "Provider delivery idempotency record is bound to the service idempotency store."},
        {"id": "provider-target-and-request-bound", "status": "worker-recorded" if source_delivery.get("target_url") and source_delivery.get("request_body_hash") else "planned-production", "description": "Provider target URL, request path, request body hash, and payload hash are bound."},
        {"id": "provider-response-bound", "status": "worker-recorded" if response_status is not None else "local-reference", "description": "Provider response status and optional response hash are bound when available."},
        {"id": "delivery-and-provider-log-roots", "status": "worker-recorded" if delivery_log_root and audit_log_root else "planned-production", "description": "Delivery log and worker audit roots are bound; provider event roots are optional when provider exports exist."},
        {"id": "provider-event-log-binding", "status": "worker-recorded" if provider_event_log_root else "local-reference", "description": "Provider-owned event log root is bound when supplied."},
        {"id": "redacted-provider-delivery-credentials", "status": "worker-recorded" if credential_ref and provider_credential_ref else "planned-production", "description": "TrustAI worker and provider credential material is represented only by redacted references."},
        {"id": "provider-delivery-worker-success-recorded", "status": "worker-recorded" if success else "failed", "description": "Worker outcome is explicitly recorded."},
    ]


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider delivery worker service must be an object")
        return
    for field in (
        "attestation_id",
        "attestation_hash",
        "mode",
        "environment",
        "service_ref",
        "service_version",
        "provider",
        "dispatch_worker_ref",
        "queue_ref",
        "dead_letter_queue_ref",
        "idempotency_store_ref",
        "retry_policy_ref",
        "outbound_proxy_ref",
        "provider_endpoint_base",
        "source_delivery_id",
        "source_delivery_mode",
        "rate_limit_policy_ref",
        "request_signing_policy_ref",
        "service_audit_log_root",
    ):
        if value.get(field) in (None, ""):
            errors.append(f"provider delivery worker service.{field} is required")
    for field in ("attestation_hash", "service_audit_log_root"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"provider delivery worker service.{field} must be a sha256 reference")
    _verify_redacted_ref(value.get("provider_credential"), "provider delivery worker service.provider_credential", errors)


def _verify_source_delivery(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider delivery worker source_delivery must be an object")
        return
    for field in ("delivery_id", "delivery_hash", "mode", "provider", "target_url", "payload_hash", "request_method", "request_path", "request_body_hash", "idempotency_key"):
        if value.get(field) in (None, ""):
            errors.append(f"provider delivery worker source_delivery.{field} is required")
    for field in ("delivery_hash", "payload_hash", "request_body_hash", "contract_hash", "response_body_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"provider delivery worker source_delivery.{field} must be a sha256 reference")
    status = value.get("response_status")
    if status is not None and (not isinstance(status, int) or status < 100 or status > 599):
        errors.append("provider delivery worker source_delivery.response_status must be an HTTP status code")


def _verify_source(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider delivery worker source must be an object")
        return
    if not isinstance(value.get("source_count"), int) or value.get("source_count") < 2:
        errors.append("provider delivery worker source.source_count must include service and delivery sources")
    if not _is_sha256_ref(str(value.get("source_hash") or "")):
        errors.append("provider delivery worker source.source_hash must be a sha256 reference")
    required = value.get("required_types", [])
    if not isinstance(required, list) or "provider-delivery-service-attestation" not in required or "provider-delivery" not in required:
        errors.append("provider delivery worker source must include provider-delivery-service-attestation and provider-delivery")


def _verify_worker(value: Any, recorded_at: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider delivery worker worker must be an object")
        return
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at", "attempt", "max_attempts", "success"):
        if value.get(field) in (None, ""):
            errors.append(f"provider delivery worker worker.{field} is required")
    if value.get("operation_kind") not in PROVIDER_DELIVERY_WORKER_OPERATION_KINDS:
        errors.append("provider delivery worker worker.operation_kind is unsupported")
    try:
        started = parse_rfc3339(str(value.get("started_at") or ""))
        completed = parse_rfc3339(str(value.get("completed_at") or ""))
        recorded = parse_rfc3339(str(recorded_at or ""))
        if completed < started:
            errors.append("provider delivery worker worker.completed_at must be at or after started_at")
        if completed != recorded:
            errors.append("provider delivery worker recorded_at must equal worker.completed_at")
    except ValueError as exc:
        errors.append(f"provider delivery worker timestamp invalid: {exc}")
    attempt = value.get("attempt")
    max_attempts = value.get("max_attempts")
    if not isinstance(attempt, int) or attempt < 1:
        errors.append("provider delivery worker worker.attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < (attempt if isinstance(attempt, int) else 1):
        errors.append("provider delivery worker worker.max_attempts must be greater than or equal to attempt")
    if not isinstance(value.get("success"), bool):
        errors.append("provider delivery worker worker.success must be a boolean")
    if value.get("success") is False and not value.get("error_ref"):
        errors.append("provider delivery worker worker.error_ref is required when success is false")


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider delivery worker scheduler must be an object")
        return
    for field in ("schedule_ref", "cadence_seconds", "lease_ref", "checkpoint_ref"):
        if value.get(field) in (None, ""):
            errors.append(f"provider delivery worker scheduler.{field} is required")
    if not isinstance(value.get("cadence_seconds"), int) or value.get("cadence_seconds") <= 0:
        errors.append("provider delivery worker scheduler.cadence_seconds must be positive")
    if value.get("checkpoint_hash") and not _is_sha256_ref(str(value.get("checkpoint_hash"))):
        errors.append("provider delivery worker scheduler.checkpoint_hash must be a sha256 reference")
    if value.get("next_run_at"):
        try:
            parse_rfc3339(str(value.get("next_run_at")))
        except ValueError as exc:
            errors.append(f"provider delivery worker scheduler.next_run_at invalid: {exc}")


def _verify_dispatch(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider delivery worker dispatch must be an object")
        return
    for field in ("queue_ref", "dead_letter_queue_ref", "destination_ref", "idempotency_key", "idempotency_record_hash", "request_hash", "response_accepted"):
        if value.get(field) in (None, ""):
            errors.append(f"provider delivery worker dispatch.{field} is required")
    for field in ("idempotency_record_hash", "request_hash", "response_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"provider delivery worker dispatch.{field} must be a sha256 reference")
    status = value.get("response_status")
    if status is not None and (not isinstance(status, int) or status < 100 or status > 599):
        errors.append("provider delivery worker dispatch.response_status must be an HTTP status code")
    if not isinstance(value.get("response_accepted"), bool):
        errors.append("provider delivery worker dispatch.response_accepted must be a boolean")
    retry_after = value.get("retry_after_seconds")
    if retry_after is not None and (not isinstance(retry_after, int) or retry_after < 0):
        errors.append("provider delivery worker dispatch.retry_after_seconds must be a non-negative integer")


def _verify_observability(value: Any, recorded_at: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider delivery worker observability must be an object")
        return
    for field in ("delivery_log_ref", "delivery_log_root", "metrics_ref", "audit_log_ref", "audit_log_root", "retention_until"):
        if value.get(field) in (None, ""):
            errors.append(f"provider delivery worker observability.{field} is required")
    for field in ("delivery_log_root", "provider_event_log_root", "audit_log_root"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"provider delivery worker observability.{field} must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if recorded_at and retention <= recorded_at:
            errors.append("provider delivery worker retention_until must be after recorded_at")
    except ValueError as exc:
        errors.append(f"provider delivery worker observability.retention_until invalid: {exc}")
    refs = value.get("evidence_refs", [])
    if not isinstance(refs, list) or not all(isinstance(item, str) and item for item in refs):
        errors.append("provider delivery worker observability.evidence_refs must be a list of strings")


def _verify_source_artifacts(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or len(value) < 2:
        errors.append("provider delivery worker source_artifacts must include service and delivery artifacts")
        return
    for item in value:
        if not isinstance(item, dict):
            errors.append("provider delivery worker source_artifacts entries must be objects")
            continue
        for field in ("type", "hash"):
            if not item.get(field):
                errors.append(f"provider delivery worker source_artifacts entry missing {field}")
        if item.get("hash") and not _is_sha256_ref(str(item.get("hash"))):
            errors.append("provider delivery worker source_artifacts hash must be a sha256 reference")


def _compare_source_hash(receipt: dict[str, Any], source_type: str, source_value: dict[str, Any], errors: list[str]) -> None:
    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("provider delivery worker source_artifacts must be a list")
        return
    expected_hash = content_hash(source_value)
    matches = [artifact for artifact in artifacts if isinstance(artifact, dict) and artifact.get("type") == source_type]
    if not matches:
        errors.append(f"provider delivery worker source artifact missing: {source_type}")
        return
    if not any(artifact.get("hash") == expected_hash for artifact in matches):
        errors.append(f"provider delivery worker source artifact hash mismatch: {source_type}")


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if isinstance(item, dict):
            status = str(item.get("status", "unknown"))
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    return {"ref": ref, "redacted": True} if ref else None


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"provider delivery worker secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if value is None:
        return True
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and _is_string_list(value):
        return True
    if (key.endswith("_root") or key.endswith("_hash")) and isinstance(value, str) and _is_sha256_ref(value):
        return True
    return False


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value)


def _is_sha256_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value.removeprefix("sha256:"))
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)
