from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .insurer_partner_service import verify_insurer_partner_service_attestation

INSURER_PARTNER_WORKER_SCHEMA = "trustai.insurer-partner-worker/0.1"
INSURER_PARTNER_WORKER_ENTRY_TYPE = "insurer.partner_worker_recorded"
INSURER_PARTNER_WORKER_MODES = {"local-reference", "scheduled-worker", "hosted-worker", "partner-api-worker", "production-design"}
INSURER_PARTNER_WORKER_OPERATION_KINDS = {
    "insurer_telemetry_delivery",
    "underwriting_quote_delivery",
    "policy_binding_workflow",
    "actuarial_product_publish",
    "consent_reconcile",
    "delivery_log_replay",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")
SUCCESSFUL_WORKFLOW_STATUSES = {"accepted", "bound", "completed", "not_applicable", "queued"}


@dataclass
class InsurerPartnerWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_insurer_partner_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("insurer partner worker receipt must contain an object")
    return value


def write_insurer_partner_worker_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_insurer_partner_worker_receipt(
    service_attestation: dict[str, Any],
    *,
    telemetry: dict[str, Any] | None = None,
    underwriting_quote: dict[str, Any] | None = None,
    actuarial_product: dict[str, Any] | None = None,
    actuarial_corpora: list[dict[str, Any]] | None = None,
    frontend_bundle_path: str | Path | None = None,
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
    checkpoint_hash: str | None = None,
    previous_cursor_ref: str | None = None,
    next_cursor_ref: str | None = None,
    attempt: int = 1,
    max_attempts: int = 3,
    queue_ref: str,
    queue_message_ref: str | None = None,
    destination_ref: str,
    delivery_log_ref: str,
    delivery_log_root: str,
    partner_event_log_ref: str | None = None,
    partner_event_log_root: str | None = None,
    policy_system_ref: str,
    policy_workflow_ref: str | None = None,
    policy_workflow_hash: str | None = None,
    policy_binding_ref: str | None = None,
    policy_binding_hash: str | None = None,
    workflow_status: str = "not_applicable",
    request_hash: str | None = None,
    response_status: int | None = None,
    response_hash: str | None = None,
    metrics_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    access_log_ref: str,
    access_log_root: str,
    credential_ref: str,
    partner_credential_ref: str,
    retention_until: str,
    evidence_refs: list[str] | None = None,
    started_at: str,
    completed_at: str | None = None,
    next_run_at: str | None = None,
    error_ref: str | None = None,
    now: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in INSURER_PARTNER_WORKER_MODES:
        raise ValueError(f"mode must be one of {sorted(INSURER_PARTNER_WORKER_MODES)}")
    if operation_kind not in INSURER_PARTNER_WORKER_OPERATION_KINDS:
        raise ValueError(f"operation_kind must be one of {sorted(INSURER_PARTNER_WORKER_OPERATION_KINDS)}")
    if not isinstance(service_attestation, dict):
        raise ValueError("service_attestation must be an object")
    for value, field in (
        (environment, "environment"),
        (worker_ref, "worker_ref"),
        (run_ref, "run_ref"),
        (actor_ref, "actor_ref"),
        (schedule_ref, "schedule_ref"),
        (lease_ref, "lease_ref"),
        (checkpoint_ref, "checkpoint_ref"),
        (queue_ref, "queue_ref"),
        (destination_ref, "destination_ref"),
        (delivery_log_ref, "delivery_log_ref"),
        (delivery_log_root, "delivery_log_root"),
        (policy_system_ref, "policy_system_ref"),
        (metrics_ref, "metrics_ref"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (access_log_ref, "access_log_ref"),
        (access_log_root, "access_log_root"),
        (credential_ref, "credential_ref"),
        (partner_credential_ref, "partner_credential_ref"),
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
    for field, value in (
        ("checkpoint_hash", checkpoint_hash),
        ("delivery_log_root", delivery_log_root),
        ("partner_event_log_root", partner_event_log_root),
        ("policy_workflow_hash", policy_workflow_hash),
        ("policy_binding_hash", policy_binding_hash),
        ("request_hash", request_hash),
        ("response_hash", response_hash),
        ("audit_log_root", audit_log_root),
        ("access_log_root", access_log_root),
    ):
        if value and not _is_sha256_ref(str(value)):
            raise ValueError(f"{field} must be a sha256 reference")
    if response_status is not None and (not isinstance(response_status, int) or response_status < 100 or response_status > 599):
        raise ValueError("response_status must be an HTTP status code")
    if workflow_status not in SUCCESSFUL_WORKFLOW_STATUSES and not error_ref:
        raise ValueError("workflow_status must be successful unless error_ref is supplied")

    service_result = verify_insurer_partner_service_attestation(
        service_attestation,
        telemetry,
        underwriting_quote,
        actuarial_product=actuarial_product,
        actuarial_corpora=actuarial_corpora,
        frontend_bundle_path=frontend_bundle_path,
        now=now,
        key=key,
    )
    if not service_result.ok:
        raise ValueError("invalid insurer partner service source: " + "; ".join(service_result.errors))

    source_artifacts = _source_artifacts(
        service_attestation=service_attestation,
        telemetry=telemetry,
        underwriting_quote=underwriting_quote,
        actuarial_product=actuarial_product,
        actuarial_corpora=actuarial_corpora or [],
    )
    service = _service_record(service_attestation)
    risk_transfer = _risk_transfer_record(service_attestation, telemetry, underwriting_quote)
    response_success = response_status is None or 200 <= response_status < 300
    workflow_success = workflow_status in SUCCESSFUL_WORKFLOW_STATUSES
    success = not error_ref and response_success and workflow_success
    body: dict[str, Any] = {
        "schema": INSURER_PARTNER_WORKER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": completed,
        "service": service,
        "risk_transfer": risk_transfer,
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
        "delivery": {
            "queue_ref": queue_ref,
            "queue_message_ref": queue_message_ref,
            "destination_ref": destination_ref,
            "delivery_log_ref": delivery_log_ref,
            "delivery_log_root": delivery_log_root,
            "partner_event_log_ref": partner_event_log_ref,
            "partner_event_log_root": partner_event_log_root,
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
        },
        "policy_system": {
            "policy_system_ref": policy_system_ref,
            "policy_workflow_ref": policy_workflow_ref,
            "policy_workflow_hash": policy_workflow_hash,
            "policy_binding_ref": policy_binding_ref,
            "policy_binding_hash": policy_binding_hash,
            "workflow_status": workflow_status,
        },
        "observability": {
            "metrics_ref": metrics_ref,
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "access_log_ref": access_log_ref,
            "access_log_root": access_log_root,
            "retention_until": retention_until,
            "evidence_refs": sorted(evidence_refs or []),
        },
        "credential": _redacted_ref(credential_ref),
        "partner_credential": _redacted_ref(partner_credential_ref),
        "source": _source_summary(source_artifacts),
        "source_artifacts": source_artifacts,
        "controls": _controls(
            mode=mode,
            service=service,
            risk_transfer=risk_transfer,
            schedule_ref=schedule_ref,
            lease_ref=lease_ref,
            checkpoint_ref=checkpoint_ref,
            checkpoint_hash=checkpoint_hash,
            delivery_log_root=delivery_log_root,
            partner_event_log_root=partner_event_log_root,
            policy_workflow_hash=policy_workflow_hash,
            policy_binding_hash=policy_binding_hash,
            audit_log_root=audit_log_root,
            access_log_root=access_log_root,
            response_status=response_status,
            credential_ref=credential_ref,
            partner_credential_ref=partner_credential_ref,
        ),
        "limitations": [
            "This receipt records one insurer partner delivery or policy-system worker run and the source service attestation hashes it processed.",
            "It stores scheduler, queue, delivery-log, partner event-log, policy workflow, audit/access-log, response hash, and redacted credential references, not raw insurer tokens, policy-system credentials, or customer PII.",
            "It proves continuously operated insurer integration workers only when paired with hosted-service, scheduling, monitoring, partner API, policy-system, and immutable log evidence.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [sign_value({"worker_operation_id": worker_operation_id, "insurer_partner_worker": body}, key)],
    }


def verify_insurer_partner_worker_receipt(
    receipt: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    telemetry: dict[str, Any] | None = None,
    underwriting_quote: dict[str, Any] | None = None,
    actuarial_product: dict[str, Any] | None = None,
    actuarial_corpora: list[dict[str, Any]] | None = None,
    frontend_bundle_path: str | Path | None = None,
    now: str | None = None,
    key: str | None = None,
) -> InsurerPartnerWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != INSURER_PARTNER_WORKER_SCHEMA:
        errors.append(f"unsupported insurer partner worker schema: {receipt.get('schema')}")
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append("worker_operation_id does not match canonical insurer partner worker body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("insurer partner worker receipt must include at least one signature")
    else:
        signed_value = {"worker_operation_id": receipt.get("worker_operation_id"), "insurer_partner_worker": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("insurer partner worker signature verification failed")

    try:
        recorded_at = parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"insurer partner worker recorded_at invalid: {exc}")
        recorded_at = None
    mode = receipt.get("mode")
    if mode not in INSURER_PARTNER_WORKER_MODES:
        errors.append("insurer partner worker mode is unsupported")
    elif mode not in {"hosted-worker", "partner-api-worker"}:
        warnings.append(f"insurer partner worker mode is {mode}; continuously hosted insurer partner worker operation is not claimed")

    _verify_service(receipt.get("service"), errors)
    _verify_risk_transfer(receipt.get("risk_transfer"), errors)
    _verify_worker(receipt.get("worker"), receipt.get("recorded_at"), errors)
    _verify_scheduler(receipt.get("scheduler"), errors)
    _verify_delivery(receipt.get("delivery"), errors)
    _verify_policy_system(receipt.get("policy_system"), errors)
    _verify_observability(receipt.get("observability"), recorded_at, now, errors)
    _verify_redacted_ref(receipt.get("credential"), "insurer partner worker credential", errors)
    _verify_redacted_ref(receipt.get("partner_credential"), "insurer partner worker partner_credential", errors)
    _verify_source(receipt.get("source"), errors)
    _check_no_secret_values(receipt, errors)
    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("insurer partner worker controls are required")
    if service_attestation is None:
        warnings.append("insurer partner service attestation artifact was not supplied; service hash was not replayed")
    else:
        _compare_source_hash(receipt, "insurer-partner-service-attestation", service_attestation, errors)
        service_hash = receipt.get("service", {}).get("attestation_hash") if isinstance(receipt.get("service"), dict) else None
        if service_hash != content_hash(service_attestation):
            errors.append("insurer partner worker service.attestation_hash does not match supplied service attestation")
        service_result = verify_insurer_partner_service_attestation(
            service_attestation,
            telemetry,
            underwriting_quote,
            actuarial_product=actuarial_product,
            actuarial_corpora=actuarial_corpora,
            frontend_bundle_path=frontend_bundle_path,
            now=now,
            key=key,
        )
        if not service_result.ok:
            errors.extend(f"insurer partner worker service source: {error}" for error in service_result.errors)
        warnings.extend(f"insurer partner worker service source: {warning}" for warning in service_result.warnings)

    for source_type, source_value in (
        ("insurer-risk-telemetry", telemetry),
        ("underwriting-quote", underwriting_quote),
        ("actuarial-product", actuarial_product),
    ):
        if source_value is not None:
            _compare_source_hash(receipt, source_type, source_value, errors)
    for corpus in actuarial_corpora or []:
        _compare_source_hash(receipt, "actuarial-corpus", corpus, errors)

    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    delivery = receipt.get("delivery", {}) if isinstance(receipt.get("delivery"), dict) else {}
    policy = receipt.get("policy_system", {}) if isinstance(receipt.get("policy_system"), dict) else {}
    response_status = delivery.get("response_status")
    response_success = response_status is None or (isinstance(response_status, int) and 200 <= response_status < 300)
    workflow_success = policy.get("workflow_status") in SUCCESSFUL_WORKFLOW_STATUSES
    expected_success = not worker.get("error_ref") and response_success and workflow_success
    if isinstance(worker.get("success"), bool) and worker.get("success") is not expected_success:
        errors.append("insurer partner worker success must match response status, workflow status, and error_ref")

    return InsurerPartnerWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_insurer_partner_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    telemetry: dict[str, Any] | None = None,
    underwriting_quote: dict[str, Any] | None = None,
    actuarial_product: dict[str, Any] | None = None,
    actuarial_corpora: list[dict[str, Any]] | None = None,
    frontend_bundle_path: str | Path | None = None,
    now: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_insurer_partner_worker_receipt(
        receipt,
        service_attestation=service_attestation,
        telemetry=telemetry,
        underwriting_quote=underwriting_quote,
        actuarial_product=actuarial_product,
        actuarial_corpora=actuarial_corpora,
        frontend_bundle_path=frontend_bundle_path,
        now=now,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid insurer partner worker receipt: " + "; ".join(result.errors))
    payload = {
        "worker_operation_id": receipt["worker_operation_id"],
        "worker_operation_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "service": receipt.get("service"),
        "risk_transfer": receipt.get("risk_transfer"),
        "worker": receipt.get("worker"),
        "scheduler": receipt.get("scheduler"),
        "delivery": receipt.get("delivery"),
        "policy_system": receipt.get("policy_system"),
        "observability": receipt.get("observability"),
        "source": receipt.get("source"),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(INSURER_PARTNER_WORKER_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("recorded_at"))


def _service_record(attestation: dict[str, Any]) -> dict[str, Any]:
    service = attestation.get("service", {}) if isinstance(attestation, dict) and isinstance(attestation.get("service"), dict) else {}
    partner = attestation.get("partner", {}) if isinstance(attestation, dict) and isinstance(attestation.get("partner"), dict) else {}
    return {
        "attestation_id": attestation.get("attestation_id") if isinstance(attestation, dict) else None,
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode") if isinstance(attestation, dict) else None,
        "environment": attestation.get("environment") if isinstance(attestation, dict) else None,
        "service_ref": service.get("service_ref"),
        "service_kind": service.get("service_kind"),
        "service_version": service.get("version"),
        "endpoint_url": service.get("endpoint_url"),
        "partner_api_endpoint": service.get("partner_api_endpoint"),
        "queue_ref": service.get("queue_ref"),
        "policy_system_ref": service.get("policy_system_ref"),
        "partner_contract_ref": partner.get("partner_contract_ref"),
    }


def _risk_transfer_record(attestation: dict[str, Any], telemetry: dict[str, Any] | None, underwriting_quote: dict[str, Any] | None) -> dict[str, Any]:
    risk = attestation.get("risk_transfer", {}) if isinstance(attestation, dict) and isinstance(attestation.get("risk_transfer"), dict) else {}
    partner = attestation.get("partner", {}) if isinstance(attestation, dict) and isinstance(attestation.get("partner"), dict) else {}
    return {
        "pack_id": risk.get("pack_id"),
        "contract_id": risk.get("contract_id"),
        "consent_id": risk.get("consent_id"),
        "consent_active": risk.get("consent_active"),
        "telemetry_hash": content_hash(telemetry) if isinstance(telemetry, dict) else risk.get("telemetry_hash"),
        "quote_id": underwriting_quote.get("quote_id") if isinstance(underwriting_quote, dict) else partner.get("quote_id"),
        "quote_ref": partner.get("quote_ref"),
        "underwriter": partner.get("underwriter"),
        "risk_score": risk.get("risk_score"),
        "risk_tier": risk.get("risk_tier"),
        "quoted_premium_usd": risk.get("quoted_premium_usd"),
        "discount_percent": risk.get("discount_percent"),
        "coverage_limit_usd": risk.get("coverage_limit_usd"),
    }

def _source_artifacts(
    *,
    service_attestation: dict[str, Any] | None,
    telemetry: dict[str, Any] | None,
    underwriting_quote: dict[str, Any] | None,
    actuarial_product: dict[str, Any] | None,
    actuarial_corpora: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for source_type, value in (
        ("insurer-partner-service-attestation", service_attestation),
        ("insurer-risk-telemetry", telemetry),
        ("underwriting-quote", underwriting_quote),
        ("actuarial-product", actuarial_product),
    ):
        if isinstance(value, dict):
            records.append({"type": source_type, "id": _source_id(value), "schema": value.get("schema"), "hash": content_hash(value)})
    for corpus in actuarial_corpora:
        if isinstance(corpus, dict):
            records.append({"type": "actuarial-corpus", "id": _source_id(corpus), "schema": corpus.get("schema"), "hash": content_hash(corpus)})
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
    for key_name in ("attestation_id", "quote_id", "product_id", "corpus_id", "pack_id", "consent_id"):
        if value.get(key_name):
            return value.get(key_name)
    if isinstance(value.get("consent"), dict) and value["consent"].get("consent_id"):
        return value["consent"]["consent_id"]
    return value.get("schema")


def _controls(
    *,
    mode: str,
    service: dict[str, Any],
    risk_transfer: dict[str, Any],
    schedule_ref: str,
    lease_ref: str,
    checkpoint_ref: str,
    checkpoint_hash: str | None,
    delivery_log_root: str,
    partner_event_log_root: str | None,
    policy_workflow_hash: str | None,
    policy_binding_hash: str | None,
    audit_log_root: str,
    access_log_root: str,
    response_status: int | None,
    credential_ref: str,
    partner_credential_ref: str,
) -> list[dict[str, str]]:
    return [
        {"id": "insurer-partner-service-source-bound", "status": "implemented" if service.get("attestation_hash") else "planned-production", "description": "Worker run is bound to a signed insurer partner service attestation by hash."},
        {"id": "consented-risk-and-quote-bound", "status": "implemented" if risk_transfer.get("consent_active") and risk_transfer.get("quote_id") else "planned-production", "description": "Worker run records the consented risk telemetry and underwriting quote identifiers it delivered."},
        {"id": "worker-scheduler-lease", "status": "implemented" if schedule_ref and lease_ref else "planned-production", "description": "Worker run records scheduler cadence and lease ownership metadata."},
        {"id": "worker-checkpoint-continuity", "status": "implemented" if checkpoint_ref and checkpoint_hash else "local-reference" if checkpoint_ref else "planned-production", "description": "Worker run records a checkpoint hash for replayable delivery continuity."},
        {"id": "delivery-and-audit-roots", "status": "implemented" if delivery_log_root and audit_log_root and access_log_root else "planned-production", "description": "Worker run binds delivery, audit, and access-log roots for partner delivery evidence."},
        {"id": "partner-event-log-binding", "status": "implemented" if partner_event_log_root else "local-reference", "description": "Worker run can bind a partner-owned event log root when supplied."},
        {"id": "policy-system-workflow-binding", "status": "implemented" if policy_workflow_hash or policy_binding_hash else "local-reference", "description": "Worker run can bind policy-system workflow and binding hashes."},
        {"id": "partner-response-binding", "status": "implemented" if response_status is not None else "local-reference", "description": "Worker run records a partner API or policy-system response status and optional response hash when available."},
        {"id": "redacted-worker-credentials", "status": "implemented" if credential_ref and partner_credential_ref else "planned-production", "description": "TrustAI and partner credential material is represented only by redacted references."},
        {"id": "hosted-insurer-worker-operation", "status": "implemented" if mode in {"hosted-worker", "partner-api-worker"} else "planned-production", "description": "Receipt claims hosted insurer partner worker operation only in hosted worker modes."},
    ]


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner worker service must be an object")
        return
    for field in ("attestation_id", "attestation_hash", "mode", "environment", "service_ref", "service_kind", "service_version", "endpoint_url", "partner_api_endpoint", "queue_ref", "policy_system_ref", "partner_contract_ref"):
        if value.get(field) in (None, ""):
            errors.append(f"insurer partner worker service.{field} is required")
    if not _is_sha256_ref(str(value.get("attestation_hash") or "")):
        errors.append("insurer partner worker service.attestation_hash must be a sha256 reference")


def _verify_risk_transfer(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner worker risk_transfer must be an object")
        return
    for field in ("pack_id", "contract_id", "consent_id", "telemetry_hash", "quote_id", "underwriter", "risk_tier"):
        if value.get(field) in (None, ""):
            errors.append(f"insurer partner worker risk_transfer.{field} is required")
    if value.get("consent_active") is not True:
        errors.append("insurer partner worker risk_transfer.consent_active must be true")
    if not _is_sha256_ref(str(value.get("telemetry_hash") or "")):
        errors.append("insurer partner worker risk_transfer.telemetry_hash must be a sha256 reference")


def _verify_worker(value: Any, recorded_at: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner worker worker must be an object")
        return
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at", "attempt", "max_attempts", "success"):
        if value.get(field) in (None, ""):
            errors.append(f"insurer partner worker worker.{field} is required")
    if value.get("operation_kind") not in INSURER_PARTNER_WORKER_OPERATION_KINDS:
        errors.append(f"insurer partner worker operation kind unsupported: {value.get('operation_kind')}")
    try:
        started = parse_rfc3339(str(value.get("started_at") or ""))
        completed = parse_rfc3339(str(value.get("completed_at") or ""))
        recorded = parse_rfc3339(str(recorded_at or ""))
        if completed < started:
            errors.append("insurer partner worker completed_at must be at or after started_at")
        if recorded != completed:
            errors.append("insurer partner worker recorded_at must equal worker.completed_at")
    except ValueError as exc:
        errors.append(f"insurer partner worker timestamp invalid: {exc}")
    attempt = value.get("attempt")
    max_attempts = value.get("max_attempts")
    if not isinstance(attempt, int) or attempt < 1:
        errors.append("insurer partner worker attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < (attempt if isinstance(attempt, int) else 1):
        errors.append("insurer partner worker max_attempts must be greater than or equal to attempt")
    if not isinstance(value.get("success"), bool):
        errors.append("insurer partner worker success must be a boolean")


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner worker scheduler must be an object")
        return
    for field in ("schedule_ref", "cadence_seconds", "lease_ref", "checkpoint_ref"):
        if value.get(field) in (None, ""):
            errors.append(f"insurer partner worker scheduler.{field} is required")
    cadence = value.get("cadence_seconds")
    if not isinstance(cadence, int) or cadence <= 0:
        errors.append("insurer partner worker scheduler.cadence_seconds must be a positive integer")
    if value.get("checkpoint_hash") and not _is_sha256_ref(str(value.get("checkpoint_hash"))):
        errors.append("insurer partner worker scheduler.checkpoint_hash must be a sha256 reference")
    if value.get("next_run_at"):
        try:
            parse_rfc3339(str(value.get("next_run_at")))
        except ValueError as exc:
            errors.append(f"insurer partner worker scheduler.next_run_at invalid: {exc}")


def _verify_delivery(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner worker delivery must be an object")
        return
    for field in ("queue_ref", "destination_ref", "delivery_log_ref", "delivery_log_root"):
        if value.get(field) in (None, ""):
            errors.append(f"insurer partner worker delivery.{field} is required")
    for field in ("delivery_log_root", "partner_event_log_root", "request_hash", "response_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"insurer partner worker delivery.{field} must be a sha256 reference")
    status = value.get("response_status")
    if status is not None and (not isinstance(status, int) or status < 100 or status > 599):
        errors.append("insurer partner worker delivery.response_status must be an HTTP status code")


def _verify_policy_system(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner worker policy_system must be an object")
        return
    for field in ("policy_system_ref", "workflow_status"):
        if value.get(field) in (None, ""):
            errors.append(f"insurer partner worker policy_system.{field} is required")
    for field in ("policy_workflow_hash", "policy_binding_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"insurer partner worker policy_system.{field} must be a sha256 reference")
    if value.get("workflow_status") not in SUCCESSFUL_WORKFLOW_STATUSES:
        errors.append(f"insurer partner worker policy_system.workflow_status unsupported: {value.get('workflow_status')}")


def _verify_observability(value: Any, recorded_at: Any, now: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner worker observability must be an object")
        return
    for field in ("metrics_ref", "audit_log_ref", "audit_log_root", "access_log_ref", "access_log_root", "retention_until"):
        if value.get(field) in (None, ""):
            errors.append(f"insurer partner worker observability.{field} is required")
    for field in ("audit_log_root", "access_log_root"):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"insurer partner worker observability.{field} must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if recorded_at and retention <= recorded_at:
            errors.append("insurer partner worker retention_until must be after recorded_at")
        if now and retention <= parse_rfc3339(now):
            errors.append("insurer partner worker retention has expired")
    except ValueError as exc:
        errors.append(f"insurer partner worker observability timestamp invalid: {exc}")
    refs = value.get("evidence_refs", [])
    if not isinstance(refs, list) or not all(isinstance(item, str) and item for item in refs):
        errors.append("insurer partner worker observability.evidence_refs must be a list of strings")


def _verify_source(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner worker source must be an object")
        return
    if not isinstance(value.get("source_count"), int) or value.get("source_count") < 3:
        errors.append("insurer partner worker source.source_count must be an integer >= 3")
    if not value.get("source_hash"):
        errors.append("insurer partner worker source.source_hash is required")
    required = value.get("required_types")
    if not isinstance(required, list):
        errors.append("insurer partner worker source.required_types must be a list")
    else:
        for item in ("insurer-partner-service-attestation", "insurer-risk-telemetry", "underwriting-quote"):
            if item not in required:
                errors.append(f"insurer partner worker source.required_types must include {item}")


def _compare_source_hash(receipt: dict[str, Any], source_type: str, source_value: dict[str, Any], errors: list[str]) -> None:
    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("insurer partner worker source_artifacts must be a list")
        return
    expected_hash = content_hash(source_value)
    matches = [artifact for artifact in artifacts if isinstance(artifact, dict) and artifact.get("type") == source_type]
    if not matches:
        errors.append(f"insurer partner worker source artifact missing: {source_type}")
        return
    if not any(artifact.get("hash") == expected_hash for artifact in matches):
        errors.append(f"insurer partner worker source artifact hash mismatch: {source_type}")


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
                    errors.append(f"insurer partner worker secret-like field must be redacted reference: {child_path}")
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
