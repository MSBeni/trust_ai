from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .provider_delivery_service import verify_provider_delivery_service_attestation
from .provider_delivery_worker import verify_provider_delivery_worker_receipt
from .provider_delivery_worker_bundle import verify_provider_delivery_worker_bundle

PROVIDER_DELIVERY_AUTHORITY_SCHEMA = "trustai.provider-delivery-production-authority-dossier/0.1"
PROVIDER_DELIVERY_AUTHORITY_ENTRY_TYPE = "provider.delivery_authority_recorded"
PROVIDER_DELIVERY_AUTHORITY_MODES = {"local-dossier", "provider-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {"id": "hosted-dispatch-worker-fleet", "title": "Continuously operated provider delivery dispatch worker fleets", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "production-provider-credentials", "title": "Production provider credentials under vault/KMS custody and rotation controls", "authority_kinds": ["kms-hsm", "provider-api", "customer"]},
    {"id": "live-provider-api-network-access", "title": "Live network egress to Slack/GitHub/GitLab provider APIs from operated infrastructure", "authority_kinds": ["provider-api", "hosted-service"]},
    {"id": "real-http-dispatch-artifacts", "title": "Real http-dispatch or recorded-response artifacts from external provider calls", "authority_kinds": ["provider-api", "hosted-service"]},
    {"id": "provider-owned-delivery-events", "title": "Provider-owned delivery, check, message, or event exports retrieved from provider APIs", "authority_kinds": ["provider-api"]},
    {"id": "scheduler-queue-lease-storage", "title": "Production scheduler, queue, DLQ, lease, checkpoint, and idempotency stores", "authority_kinds": ["provider-api", "hosted-service"]},
    {"id": "retry-dlq-idempotency-controls", "title": "Retry, dead-letter, deduplication, and idempotent dispatch controls", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "egress-rate-limit-request-signing", "title": "Tenant egress policy, provider rate-limit enforcement, and request signing controls", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "delivery-observability-audit", "title": "Production delivery logs, worker audit logs, metrics, alerts, and provider event roots", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "immutable-delivery-retention", "title": "Immutable provider delivery, worker, response, and audit retention", "authority_kinds": ["cloud-object-lock", "provider-api", "customer"]},
    {"id": "provider-operations-authority-binding", "title": "Provider operations authority or equivalent hosted callback/credential control evidence", "authority_kinds": ["hosted-service", "provider-api", "customer"]},
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class ProviderDeliveryAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_provider_delivery_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider delivery authority dossier must contain an object")
    return value


def write_provider_delivery_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_provider_delivery_authority_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 4)
    if len(parts) != 5:
        raise ValueError("authority evidence must be requirement_id,authority_kind,evidence_ref,evidence_hash,description[;key=value...]")
    requirement_id, authority_kind, evidence_ref, evidence_hash, description = [part.strip() for part in parts]
    description_parts = [part.strip() for part in description.split(";")]
    metadata: dict[str, Any] = {}
    for token in description_parts[1:]:
        if not token:
            continue
        if "=" not in token:
            raise ValueError("authority evidence metadata must be key=value")
        key, metadata_value = [part.strip() for part in token.split("=", 1)]
        if key not in {"issuer", "subject", "source_uri", "issued_at", "expires_at"}:
            raise ValueError(f"unsupported authority evidence metadata key: {key}")
        metadata[key] = metadata_value
    return {"requirement_id": requirement_id, "authority_kind": authority_kind, "evidence_ref": evidence_ref, "evidence_hash": evidence_hash, "description": description_parts[0], **metadata}


def build_provider_delivery_authority_dossier(
    service_attestation: dict[str, Any],
    *,
    worker_receipts: list[dict[str, Any]] | None = None,
    worker_bundles: list[dict[str, Any]] | None = None,
    delivery: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    payload_artifact_path: str | Path | None = None,
    provider_operations_service: dict[str, Any] | None = None,
    provider_response: dict[str, Any] | None = None,
    provider_audit_correlation: dict[str, Any] | None = None,
    provider_audit_log: Any | None = None,
    mode: str = "provider-dossier",
    environment: str | None = None,
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in PROVIDER_DELIVERY_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(PROVIDER_DELIVERY_AUTHORITY_MODES)}")
    for value, field in ((dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)
    receipts = list(worker_receipts or [])
    if not receipts:
        raise ValueError("provider delivery authority requires at least one worker receipt")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    service_result = verify_provider_delivery_service_attestation(
        service_attestation,
        delivery=delivery,
        payload=payload,
        payload_artifact_path=payload_artifact_path,
        provider_operations_service=provider_operations_service,
        key=key,
    )
    if not service_result.ok:
        raise ValueError("invalid provider delivery service source: " + "; ".join(service_result.errors))
    for receipt in receipts:
        worker_result = verify_provider_delivery_worker_receipt(
            receipt,
            service_attestation=service_attestation,
            delivery=delivery,
            payload=payload,
            payload_artifact_path=payload_artifact_path,
            provider_operations_service=provider_operations_service,
            provider_response=provider_response,
            provider_audit_correlation=provider_audit_correlation,
            provider_audit_log=provider_audit_log,
            key=key,
        )
        if not worker_result.ok:
            raise ValueError("invalid provider delivery worker source: " + "; ".join(worker_result.errors))
    bundles = list(worker_bundles or [])
    for bundle in bundles:
        bundle_result = verify_provider_delivery_worker_bundle(bundle, key=key)
        if not bundle_result.ok:
            raise ValueError("invalid provider delivery worker bundle source: " + "; ".join(bundle_result.errors))

    service_binding = _service_attestation_binding(service_attestation)
    worker_bindings = [_worker_receipt_binding(receipt) for receipt in receipts]
    worker_bundle_bindings = [_worker_bundle_binding(bundle) for bundle in bundles]
    link_errors = _worker_bundle_link_errors(worker_bundle_bindings, service_binding, worker_bindings)
    if link_errors:
        raise ValueError("invalid provider delivery worker bundle binding: " + "; ".join(link_errors))

    evidence_items = [_build_authority_evidence_item(item) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body: dict[str, Any] = {
        "schema": PROVIDER_DELIVERY_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment or service_attestation.get("environment") or "local",
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "service_attestation_binding": service_binding,
        "worker_receipt_bindings": worker_bindings,
        "worker_bundle_bindings": worker_bundle_bindings,
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, service_attestation, receipts, worker_bundle_bindings, evidence_items, summary),
        "limitations": [
            "This dossier binds verified provider delivery service and worker receipts to an explicit production-authority evidence checklist.",
            "It records authority references, hashes, freshness windows, and missing live-evidence categories for credentialed external Slack/GitHub/GitLab posting.",
            "It does not claim continuously operated production provider delivery unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    return {**body, "dossier_id": dossier_id, "signatures": [sign_value({"dossier_id": dossier_id, "provider_delivery_authority": body}, key)]}


def verify_provider_delivery_authority_dossier(
    dossier: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    worker_receipts: list[dict[str, Any]] | None = None,
    worker_bundles: list[dict[str, Any]] | None = None,
    delivery: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    payload_artifact_path: str | Path | None = None,
    provider_operations_service: dict[str, Any] | None = None,
    provider_response: dict[str, Any] | None = None,
    provider_audit_correlation: dict[str, Any] | None = None,
    provider_audit_log: Any | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> ProviderDeliveryAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != PROVIDER_DELIVERY_AUTHORITY_SCHEMA:
        errors.append(f"unsupported provider delivery authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical provider delivery authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider delivery authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "provider_delivery_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider delivery authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in PROVIDER_DELIVERY_AUTHORITY_MODES:
        errors.append("provider delivery authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"provider delivery authority mode is {mode}; live production delivery authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"provider delivery authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"provider delivery authority {field} is required")

    _verify_service_attestation_binding(
        dossier.get("service_attestation_binding"),
        service_attestation,
        {
            "delivery": delivery,
            "payload": payload,
            "payload_artifact_path": payload_artifact_path,
            "provider_operations_service": provider_operations_service,
        },
        key,
        errors,
        warnings,
    )
    _verify_worker_receipt_bindings(
        dossier.get("worker_receipt_bindings"),
        worker_receipts,
        service_attestation,
        {
            "delivery": delivery,
            "payload": payload,
            "payload_artifact_path": payload_artifact_path,
            "provider_operations_service": provider_operations_service,
            "provider_response": provider_response,
            "provider_audit_correlation": provider_audit_correlation,
            "provider_audit_log": provider_audit_log,
        },
        key,
        errors,
        warnings,
    )
    _verify_worker_bundle_bindings(
        dossier.get("worker_bundle_bindings"),
        worker_bundles,
        dossier.get("service_attestation_binding"),
        dossier.get("worker_receipt_bindings"),
        key,
        errors,
        warnings,
    )
    _verify_required_authority(dossier.get("required_production_authority"), errors)
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("provider delivery authority authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("provider delivery authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_counts[_verify_authority_evidence_item(item, errors, warnings, now=freshness_now, require_fresh=require_fresh)] += 1

    expected_summary = _summary([item for item in evidence if isinstance(item, dict)])
    if dossier.get("summary") != expected_summary:
        errors.append("provider delivery authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("provider delivery authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("provider delivery authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every provider delivery authority requirement to be covered")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("provider delivery authority controls are required")
    _check_no_secret_values(dossier, errors)
    return ProviderDeliveryAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_provider_delivery_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    service_attestation: dict[str, Any],
    worker_receipts: list[dict[str, Any]] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
    **sources: Any,
) -> dict[str, Any]:
    result = verify_provider_delivery_authority_dossier(
        dossier,
        service_attestation=service_attestation,
        worker_receipts=worker_receipts,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
        **sources,
    )
    if not result.ok:
        raise ValueError("invalid provider delivery authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "service_attestation_binding": dossier.get("service_attestation_binding"),
        "worker_receipt_bindings": dossier.get("worker_receipt_bindings"),
        "worker_bundle_bindings": dossier.get("worker_bundle_bindings"),
        "summary": dossier.get("summary"),
        "control_summary": _status_summary(dossier.get("controls", [])),
        "authority_evidence": [
            {"requirement_id": item.get("requirement_id"), "authority_kind": item.get("authority_kind"), "evidence_ref": item.get("evidence_ref"), "evidence_hash": item.get("evidence_hash"), "evidence_id": item.get("evidence_id"), "issued_at": item.get("issued_at"), "expires_at": item.get("expires_at")}
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(PROVIDER_DELIVERY_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _service_attestation_binding(attestation: dict[str, Any]) -> dict[str, Any]:
    source = attestation.get("source", {}) if isinstance(attestation.get("source"), dict) else {}
    service = attestation.get("service", {}) if isinstance(attestation.get("service"), dict) else {}
    dispatch = attestation.get("dispatch", {}) if isinstance(attestation.get("dispatch"), dict) else {}
    security = attestation.get("security", {}) if isinstance(attestation.get("security"), dict) else {}
    observability = attestation.get("observability", {}) if isinstance(attestation.get("observability"), dict) else {}
    actor = attestation.get("operation_actor", {}) if isinstance(attestation.get("operation_actor"), dict) else {}
    credential = actor.get("credential", {}) if isinstance(actor.get("credential"), dict) else {}
    provider_credential = dispatch.get("provider_credential", {}) if isinstance(dispatch.get("provider_credential"), dict) else {}
    return {
        "attestation_id": attestation.get("attestation_id"),
        "attestation_hash": content_hash(attestation),
        "attestation_schema": attestation.get("schema"),
        "attestation_mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "source_count": source.get("source_count"),
        "source_hash": source.get("source_hash"),
        "source_schemas": source.get("schemas"),
        "required_source_types": source.get("required_types"),
        "service_ref": service.get("service_ref"),
        "provider": service.get("provider"),
        "service_image_digest": service.get("service_image_digest"),
        "service_binary_hash": service.get("service_binary_hash"),
        "replicas_min": service.get("replicas_min"),
        "replicas_max": service.get("replicas_max"),
        "availability_zones": service.get("availability_zones"),
        "dispatch_worker_ref": dispatch.get("dispatch_worker_ref"),
        "queue_ref": dispatch.get("queue_ref"),
        "dead_letter_queue_ref": dispatch.get("dead_letter_queue_ref"),
        "idempotency_store_ref": dispatch.get("idempotency_store_ref"),
        "retry_policy_ref": dispatch.get("retry_policy_ref"),
        "outbound_proxy_ref": dispatch.get("outbound_proxy_ref"),
        "provider_endpoint_base": dispatch.get("provider_endpoint_base"),
        "provider_credential_ref": provider_credential.get("ref"),
        "source_delivery_id": dispatch.get("source_delivery_id"),
        "source_delivery_mode": dispatch.get("source_delivery_mode"),
        "source_target_url": dispatch.get("source_target_url"),
        "mtls_policy_ref": security.get("mtls_policy_ref"),
        "auth_policy_ref": security.get("auth_policy_ref"),
        "network_policy_ref": security.get("network_policy_ref"),
        "egress_policy_ref": security.get("egress_policy_ref"),
        "rate_limit_policy_ref": security.get("rate_limit_policy_ref"),
        "request_signing_policy_ref": security.get("request_signing_policy_ref"),
        "audit_log_ref": observability.get("audit_log_ref"),
        "audit_log_root": observability.get("audit_log_root"),
        "metrics_ref": observability.get("metrics_ref"),
        "alert_policy_ref": observability.get("alert_policy_ref"),
        "retention_until": observability.get("retention_until"),
        "actor_ref": actor.get("actor_ref"),
        "credential_ref": credential.get("ref"),
        "evidence_refs": actor.get("evidence_refs"),
    }


def _worker_receipt_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    service = receipt.get("service", {}) if isinstance(receipt.get("service"), dict) else {}
    source = receipt.get("source", {}) if isinstance(receipt.get("source"), dict) else {}
    source_delivery = receipt.get("source_delivery", {}) if isinstance(receipt.get("source_delivery"), dict) else {}
    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    scheduler = receipt.get("scheduler", {}) if isinstance(receipt.get("scheduler"), dict) else {}
    dispatch = receipt.get("dispatch", {}) if isinstance(receipt.get("dispatch"), dict) else {}
    observability = receipt.get("observability", {}) if isinstance(receipt.get("observability"), dict) else {}
    credential = receipt.get("credential", {}) if isinstance(receipt.get("credential"), dict) else {}
    provider_credential = receipt.get("provider_credential", {}) if isinstance(receipt.get("provider_credential"), dict) else {}
    return {
        "worker_operation_id": receipt.get("worker_operation_id"),
        "worker_operation_hash": content_hash(receipt),
        "receipt_schema": receipt.get("schema"),
        "receipt_mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "source_count": source.get("source_count"),
        "source_hash": source.get("source_hash"),
        "source_schemas": source.get("schemas"),
        "required_source_types": source.get("required_types"),
        "service_attestation_id": service.get("attestation_id"),
        "service_attestation_hash": service.get("attestation_hash"),
        "service_ref": service.get("service_ref"),
        "provider": service.get("provider"),
        "provider_endpoint_base": service.get("provider_endpoint_base"),
        "worker_ref": worker.get("worker_ref"),
        "run_ref": worker.get("run_ref"),
        "operation_kind": worker.get("operation_kind"),
        "actor_ref": worker.get("actor_ref"),
        "success": worker.get("success"),
        "started_at": worker.get("started_at"),
        "completed_at": worker.get("completed_at"),
        "schedule_ref": scheduler.get("schedule_ref"),
        "lease_ref": scheduler.get("lease_ref"),
        "checkpoint_ref": scheduler.get("checkpoint_ref"),
        "checkpoint_hash": scheduler.get("checkpoint_hash"),
        "queue_ref": dispatch.get("queue_ref"),
        "queue_message_ref": dispatch.get("queue_message_ref"),
        "dead_letter_queue_ref": dispatch.get("dead_letter_queue_ref"),
        "destination_ref": dispatch.get("destination_ref"),
        "idempotency_record_hash": dispatch.get("idempotency_record_hash"),
        "provider_request_ref": dispatch.get("provider_request_ref"),
        "request_hash": dispatch.get("request_hash"),
        "response_status": dispatch.get("response_status"),
        "response_hash": dispatch.get("response_hash"),
        "response_accepted": dispatch.get("response_accepted"),
        "rate_limit_bucket_ref": dispatch.get("rate_limit_bucket_ref"),
        "delivery_log_ref": observability.get("delivery_log_ref"),
        "delivery_log_root": observability.get("delivery_log_root"),
        "provider_event_log_ref": observability.get("provider_event_log_ref"),
        "provider_event_log_root": observability.get("provider_event_log_root"),
        "audit_log_ref": observability.get("audit_log_ref"),
        "audit_log_root": observability.get("audit_log_root"),
        "metrics_ref": observability.get("metrics_ref"),
        "retention_until": observability.get("retention_until"),
        "credential_ref": credential.get("ref"),
        "provider_credential_ref": provider_credential.get("ref"),
        "source_delivery_id": source_delivery.get("delivery_id"),
        "source_delivery_hash": source_delivery.get("delivery_hash"),
        "source_delivery_mode": source_delivery.get("mode"),
        "source_provider": source_delivery.get("provider"),
        "target_url": source_delivery.get("target_url"),
    }


def _verify_service_attestation_binding(binding: Any, service_attestation: dict[str, Any] | None, sources: dict[str, Any], key: str | None, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(binding, dict):
        errors.append("provider delivery authority service_attestation_binding must be an object")
        return
    for field in ("attestation_id", "attestation_hash", "attestation_schema", "attestation_mode", "environment", "attested_at", "source_count", "source_hash", "source_schemas", "required_source_types", "service_ref", "provider", "service_image_digest", "service_binary_hash", "replicas_min", "replicas_max", "availability_zones", "dispatch_worker_ref", "queue_ref", "dead_letter_queue_ref", "idempotency_store_ref", "retry_policy_ref", "outbound_proxy_ref", "provider_endpoint_base", "provider_credential_ref", "source_delivery_id", "source_delivery_mode", "source_target_url", "mtls_policy_ref", "auth_policy_ref", "network_policy_ref", "egress_policy_ref", "rate_limit_policy_ref", "request_signing_policy_ref", "audit_log_ref", "audit_log_root", "metrics_ref", "alert_policy_ref", "retention_until", "actor_ref", "credential_ref", "evidence_refs"):
        if binding.get(field) in (None, "", []):
            errors.append(f"provider delivery authority service_attestation_binding.{field} is required")
    if service_attestation is None:
        warnings.append("provider delivery authority service attestation was not supplied; provider delivery service source was not replayed")
        return
    expected = _service_attestation_binding(service_attestation)
    if binding != expected:
        errors.append("provider delivery authority service_attestation_binding does not match supplied service attestation")
    result = verify_provider_delivery_service_attestation(service_attestation, key=key, **sources)
    if not result.ok:
        errors.extend(f"provider delivery authority service source: {error}" for error in result.errors)
    warnings.extend(f"provider delivery authority service source: {warning}" for warning in result.warnings)


def _worker_bundle_binding(bundle: dict[str, Any]) -> dict[str, Any]:
    source = bundle.get("source", {}) if isinstance(bundle.get("source"), dict) else {}
    summary = bundle.get("summary", {}) if isinstance(bundle.get("summary"), dict) else {}
    return {
        "bundle_id": bundle.get("bundle_id"),
        "bundle_hash": content_hash(bundle),
        "bundle_schema": bundle.get("schema"),
        "bundle_mode": bundle.get("mode"),
        "environment": bundle.get("environment"),
        "generated_at": bundle.get("generated_at"),
        "reviewer_ref": bundle.get("reviewer_ref"),
        "bundle_ref": bundle.get("bundle_ref"),
        "worker_operation_id": source.get("worker_operation_id"),
        "worker_receipt_hash": source.get("worker_receipt_hash"),
        "service_attestation_id": source.get("service_attestation_id"),
        "service_attestation_hash": source.get("service_attestation_hash"),
        "delivery_id": source.get("delivery_id"),
        "delivery_hash": source.get("delivery_hash"),
        "source_artifact_count": summary.get("source_artifact_count"),
        "source_artifact_sha256_root": summary.get("source_artifact_sha256_root"),
        "source_artifact_content_root": summary.get("source_artifact_content_root"),
        "retained_payload_artifact_replayed": summary.get("retained_payload_artifact_replayed"),
        "provider_response_replayed": summary.get("provider_response_replayed"),
        "provider_audit_replayed": summary.get("provider_audit_replayed"),
    }


def _worker_bundle_link_errors(bundle_bindings: list[dict[str, Any]], service_binding: Any, worker_bindings: Any) -> list[str]:
    errors: list[str] = []
    service_hash = service_binding.get("attestation_hash") if isinstance(service_binding, dict) else None
    service_id = service_binding.get("attestation_id") if isinstance(service_binding, dict) else None
    worker_ids = {binding.get("worker_operation_id") for binding in worker_bindings if isinstance(binding, dict)} if isinstance(worker_bindings, list) else set()
    worker_hashes = {binding.get("worker_operation_hash") for binding in worker_bindings if isinstance(binding, dict)} if isinstance(worker_bindings, list) else set()
    for binding in bundle_bindings:
        if not isinstance(binding, dict):
            continue
        if service_hash and binding.get("service_attestation_hash") != service_hash:
            errors.append("provider delivery authority worker bundle does not reference supplied service attestation hash")
        if service_id and binding.get("service_attestation_id") != service_id:
            errors.append("provider delivery authority worker bundle does not reference supplied service attestation id")
        if worker_ids and binding.get("worker_operation_id") not in worker_ids:
            errors.append("provider delivery authority worker bundle does not reference a supplied worker receipt id")
        if worker_hashes and binding.get("worker_receipt_hash") not in worker_hashes:
            errors.append("provider delivery authority worker bundle does not reference a supplied worker receipt hash")
    return errors


def _verify_worker_bundle_bindings(bindings: Any, worker_bundles: list[dict[str, Any]] | None, service_binding: Any, worker_bindings: Any, key: str | None, errors: list[str], warnings: list[str]) -> None:
    if bindings is None:
        if worker_bundles:
            errors.append("provider delivery authority worker_bundle_bindings are required when worker bundles are supplied")
        return
    if not isinstance(bindings, list):
        errors.append("provider delivery authority worker_bundle_bindings must be a list")
        return
    for binding in bindings:
        if not isinstance(binding, dict):
            errors.append("provider delivery authority worker_bundle_binding must be an object")
            continue
        for field in ("bundle_id", "bundle_hash", "bundle_schema", "bundle_mode", "environment", "generated_at", "reviewer_ref", "bundle_ref", "worker_operation_id", "worker_receipt_hash", "service_attestation_id", "service_attestation_hash", "delivery_id", "delivery_hash", "source_artifact_count", "source_artifact_sha256_root", "source_artifact_content_root", "retained_payload_artifact_replayed", "provider_response_replayed", "provider_audit_replayed"):
            if binding.get(field) in (None, "", []):
                errors.append(f"provider delivery authority worker_bundle_binding.{field} is required")
    errors.extend(_worker_bundle_link_errors(bindings, service_binding, worker_bindings))
    if not worker_bundles:
        if bindings:
            warnings.append("provider delivery authority worker bundles were not supplied; worker bundle hashes were not replayed")
        return
    expected = [_worker_bundle_binding(bundle) for bundle in worker_bundles]
    if bindings != expected:
        errors.append("provider delivery authority worker_bundle_bindings do not match supplied worker bundles")
    for bundle in worker_bundles:
        result = verify_provider_delivery_worker_bundle(bundle, key=key)
        if not result.ok:
            errors.extend(f"provider delivery authority worker bundle source: {error}" for error in result.errors)
        warnings.extend(f"provider delivery authority worker bundle source: {warning}" for warning in result.warnings)


def _verify_worker_receipt_bindings(bindings: Any, worker_receipts: list[dict[str, Any]] | None, service_attestation: dict[str, Any] | None, sources: dict[str, Any], key: str | None, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(bindings, list) or not bindings:
        errors.append("provider delivery authority worker_receipt_bindings must include at least one worker receipt")
        bindings = []
    for binding in bindings:
        if not isinstance(binding, dict):
            errors.append("provider delivery authority worker_receipt_binding must be an object")
            continue
        for field in ("worker_operation_id", "worker_operation_hash", "receipt_schema", "receipt_mode", "environment", "recorded_at", "source_count", "source_hash", "source_schemas", "required_source_types", "service_attestation_id", "service_attestation_hash", "service_ref", "provider", "provider_endpoint_base", "worker_ref", "run_ref", "operation_kind", "actor_ref", "success", "started_at", "completed_at", "schedule_ref", "lease_ref", "checkpoint_ref", "checkpoint_hash", "queue_ref", "queue_message_ref", "dead_letter_queue_ref", "destination_ref", "idempotency_record_hash", "provider_request_ref", "request_hash", "rate_limit_bucket_ref", "delivery_log_ref", "delivery_log_root", "provider_event_log_ref", "provider_event_log_root", "audit_log_ref", "audit_log_root", "metrics_ref", "retention_until", "credential_ref", "provider_credential_ref", "source_delivery_id", "source_delivery_hash", "source_delivery_mode", "source_provider", "target_url"):
            if binding.get(field) in (None, "", []):
                errors.append(f"provider delivery authority worker_receipt_binding.{field} is required")
    if not worker_receipts:
        warnings.append("provider delivery authority worker receipts were not supplied; worker source hashes were not replayed")
        return
    expected = [_worker_receipt_binding(receipt) for receipt in worker_receipts]
    if bindings != expected:
        errors.append("provider delivery authority worker_receipt_bindings do not match supplied worker receipts")
    for receipt in worker_receipts:
        result = verify_provider_delivery_worker_receipt(
            receipt,
            service_attestation=service_attestation,
            delivery=sources.get("delivery"),
            payload=sources.get("payload"),
            payload_artifact_path=sources.get("payload_artifact_path"),
            provider_operations_service=sources.get("provider_operations_service"),
            provider_response=sources.get("provider_response"),
            provider_audit_correlation=sources.get("provider_audit_correlation"),
            provider_audit_log=sources.get("provider_audit_log"),
            key=key,
        )
        if not result.ok:
            errors.extend(f"provider delivery authority worker source: {error}" for error in result.errors)
        warnings.extend(f"provider delivery authority worker source: {warning}" for warning in result.warnings)
    if service_attestation is not None:
        service_hash = content_hash(service_attestation)
        service_id = service_attestation.get("attestation_id")
        for binding in bindings:
            if isinstance(binding, dict) and binding.get("service_attestation_hash") != service_hash:
                errors.append("provider delivery authority worker binding does not reference supplied service attestation hash")
            if isinstance(binding, dict) and binding.get("service_attestation_id") != service_id:
                errors.append("provider delivery authority worker binding does not reference supplied service attestation id")


def _build_authority_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unknown provider delivery production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in _requirement_authority_kinds(requirement_id):
        raise ValueError(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (evidence_hash, "evidence_hash"), (description, "description")):
        _require_text(value, field)
    _require_hash_ref(evidence_hash, "evidence_hash")
    for field in ("issued_at", "expires_at"):
        if item.get(field):
            parse_rfc3339(str(item[field]))
    body = {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description,
        "issuer": item.get("issuer"),
        "subject": item.get("subject"),
        "source_uri": item.get("source_uri"),
        "issued_at": item.get("issued_at"),
        "expires_at": item.get("expires_at"),
    }
    return {**body, "evidence_id": content_hash(body)}


def _verify_authority_evidence_item(item: dict[str, Any], errors: list[str], warnings: list[str], *, now: Any, require_fresh: bool) -> str:
    if item.get("evidence_id") != content_hash(without_keys(item, "evidence_id")):
        errors.append(f"provider delivery authority evidence_id does not match evidence body: {item.get('requirement_id')}")
    requirement_id = item.get("requirement_id")
    authority_kind = item.get("authority_kind")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        errors.append(f"unknown provider delivery production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    elif requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS and authority_kind not in _requirement_authority_kinds(str(requirement_id)):
        errors.append(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for field in ("evidence_ref", "evidence_hash", "description"):
        if not item.get(field):
            errors.append(f"provider delivery authority {field} is required: {requirement_id}")
    if item.get("evidence_hash") and not str(item.get("evidence_hash")).startswith("sha256:"):
        errors.append(f"provider delivery authority evidence_hash must start with sha256: {requirement_id}")

    issued_at = _parse_optional_timestamp(item, "issued_at", errors)
    expires_at = _parse_optional_timestamp(item, "expires_at", errors)
    freshness_status = "fresh"
    missing_fields = [field for field in ("issued_at", "expires_at") if not item.get(field)]
    if missing_fields:
        freshness_status = "missing"
        _freshness_problem(f"provider delivery authority freshness metadata missing for {requirement_id}: {', '.join(missing_fields)}", errors, warnings, require_fresh=require_fresh)
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        freshness_status = "stale"
        errors.append(f"provider delivery authority expires_at must be after issued_at: {requirement_id}")
    if now is not None and issued_at is not None and issued_at > now:
        freshness_status = "stale"
        _freshness_problem(f"provider delivery authority evidence is not yet issued for {requirement_id}: {item.get('issued_at')}", errors, warnings, require_fresh=require_fresh)
    if now is not None and expires_at is not None and expires_at <= now:
        freshness_status = "stale"
        _freshness_problem(f"provider delivery authority evidence expired for {requirement_id}: {item.get('expires_at')}", errors, warnings, require_fresh=require_fresh)
    return freshness_status


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("provider delivery authority required_production_authority does not match v0.1 requirements")


def _summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted({str(item.get("requirement_id")) for item in evidence if item.get("requirement_id") in set(PRODUCTION_AUTHORITY_REQUIREMENT_IDS)})
    missing = [requirement_id for requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS if requirement_id not in covered]
    return {
        "status": "complete" if not missing else "partial",
        "required_requirement_count": len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "evidence_count": len(evidence),
        "issued_at_count": sum(1 for item in evidence if item.get("issued_at")),
        "expires_at_count": sum(1 for item in evidence if item.get("expires_at")),
        "freshness_window_count": sum(1 for item in evidence if item.get("issued_at") and item.get("expires_at")),
        "covered_requirement_ids": covered,
        "missing_requirement_ids": missing,
    }


def _controls(mode: str, service_attestation: dict[str, Any], worker_receipts: list[dict[str, Any]], worker_bundle_bindings: list[dict[str, Any]], evidence: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"name": "service_attestation_replayed", "status": "passed", "detail": "The dossier builder replayed the provider delivery service attestation and supplied source evidence when available."},
        {"name": "worker_receipts_bound", "status": "passed" if service_attestation.get("attestation_id") and worker_receipts else "failed", "detail": "The dossier binds delivery worker operation IDs, service hashes, scheduler, queue, dispatch, response, log, and credential refs."},
        {"name": "worker_review_bundles_bound", "status": "passed" if worker_bundle_bindings else "deferred", "detail": "Optional worker review bundles bind offline source-byte replay, retained payload artifact replay, and safe third-party extraction to the authority dossier."},
        {"name": "authority_evidence_manifested", "status": "passed" if evidence else "deferred", "detail": "External provider delivery authority evidence references are hash-bound when supplied."},
        {"name": "freshness_windows_tracked", "status": "passed" if evidence and summary["freshness_window_count"] == len(evidence) else "deferred", "detail": "Issued/expires freshness windows are tracked for every supplied authority item when available."},
        {"name": "complete_live_authority", "status": "passed" if summary["missing_requirement_count"] == 0 else "deferred", "detail": "Every provider delivery production authority requirement must be covered before this can claim live production delivery authority."},
        {"name": "production_claim_limited", "status": "passed" if mode != "production-dossier" or summary["missing_requirement_count"] == 0 else "failed", "detail": "Non-production dossier modes explicitly avoid claiming live credentialed external provider posting."},
    ]


def _status_summary(controls: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        if not isinstance(control, dict):
            continue
        status = str(control.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _requirement_authority_kinds(requirement_id: str) -> set[str]:
    for requirement in PRODUCTION_AUTHORITY_REQUIREMENTS:
        if requirement["id"] == requirement_id:
            return set(requirement["authority_kinds"])
    return set()


def _freshness_reference(dossier: dict[str, Any], now: str | None, errors: list[str]) -> Any:
    reference = now or dossier.get("generated_at")
    if not reference:
        return None
    try:
        return parse_rfc3339(str(reference))
    except ValueError as exc:
        label = "now" if now else "generated_at"
        errors.append(f"provider delivery authority freshness {label} invalid: {exc}")
        return None


def _parse_optional_timestamp(item: dict[str, Any], field: str, errors: list[str]) -> Any:
    value = item.get(field)
    if not value:
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"provider delivery authority {field} invalid: {exc}")
        return None


def _freshness_problem(message: str, errors: list[str], warnings: list[str], *, require_fresh: bool) -> None:
    if require_fresh:
        errors.append(message)
    else:
        warnings.append(message)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"provider delivery authority {field} is required")
    return value


def _require_hash_ref(value: str, field: str) -> None:
    if not value.startswith("sha256:"):
        raise ValueError(f"provider delivery authority {field} must start with sha256:")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}"
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"provider delivery authority contains secret-like field {child_path}; store only redacted refs")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if value is None:
        return True
    if key in {"timestamp_token", "timestamp_tokens"}:
        return True
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        return True
    if (key.endswith("_root") or key.endswith("_hash")) and isinstance(value, str) and value.startswith("sha256:"):
        return True
    return False
