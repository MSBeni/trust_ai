from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .insurer_partner_service import verify_insurer_partner_service_attestation
from .insurer_partner_worker import verify_insurer_partner_worker_receipt

INSURER_PARTNER_AUTHORITY_SCHEMA = "trustai.insurer-partner-production-authority-dossier/0.1"
INSURER_PARTNER_AUTHORITY_ENTRY_TYPE = "insurer.partner_authority_recorded"
INSURER_PARTNER_AUTHORITY_MODES = {"local-dossier", "partner-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {"id": "credentialed-partner-api-calls", "title": "Credentialed partner API calls to the live insurer or underwriter endpoint", "authority_kinds": ["provider-api", "insurer", "hosted-service"]},
    {"id": "partner-owned-authentication-events", "title": "Partner-owned authentication, MFA, token, and account session events", "authority_kinds": ["identity-provider", "provider-api", "insurer"]},
    {"id": "externally-operated-insurer-worker-fleet", "title": "Continuously operated insurer integration worker fleet and hosted service runtime", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "live-underwriter-api-responses", "title": "Live underwriter quote, bind, or policy response artifacts from the partner API", "authority_kinds": ["provider-api", "insurer"]},
    {"id": "policy-system-workflow-execution", "title": "Production policy-system workflow execution and binding records", "authority_kinds": ["provider-api", "customer", "hosted-service"]},
    {"id": "immutable-partner-delivery-logs", "title": "Immutable partner delivery logs, event logs, response logs, and retention evidence", "authority_kinds": ["cloud-object-lock", "provider-api", "insurer", "customer"]},
    {"id": "production-scheduler-lease-storage", "title": "Production scheduler, queue, lease, checkpoint, cursor, and retry stores", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "partner-credential-vault-kms", "title": "TrustAI and partner credential custody, rotation, and KMS/vault enforcement", "authority_kinds": ["kms-hsm", "provider-api", "customer"]},
    {"id": "consent-pii-data-minimization-enforcement", "title": "Consent scope, data minimization, PII redaction, and request signing enforcement", "authority_kinds": ["hosted-service", "customer", "provider-api"]},
    {"id": "actuarial-risk-data-publication", "title": "Actuarial product or insurer risk telemetry publication accepted by the underwriter", "authority_kinds": ["insurer", "customer", "provider-api", "hosted-service"]},
    {"id": "insurer-observability-alerting", "title": "Production metrics, alert policy, audit/access roots, and incident response evidence", "authority_kinds": ["hosted-service", "provider-api"]},
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class InsurerPartnerAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_insurer_partner_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("insurer partner authority dossier must contain an object")
    return value


def write_insurer_partner_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_insurer_partner_authority_evidence_arg(value: str) -> dict[str, Any]:
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


def build_insurer_partner_authority_dossier(
    service_attestation: dict[str, Any],
    *,
    worker_receipts: list[dict[str, Any]] | None = None,
    telemetry: dict[str, Any] | None = None,
    underwriting_quote: dict[str, Any] | None = None,
    actuarial_product: dict[str, Any] | None = None,
    actuarial_corpora: list[dict[str, Any]] | None = None,
    frontend_bundle_path: str | Path | None = None,
    now: str | None = None,
    mode: str = "partner-dossier",
    environment: str | None = None,
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in INSURER_PARTNER_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(INSURER_PARTNER_AUTHORITY_MODES)}")
    for value, field in ((dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)
    receipts = list(worker_receipts or [])
    if not receipts:
        raise ValueError("insurer partner authority requires at least one worker receipt")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

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
    for receipt in receipts:
        worker_result = verify_insurer_partner_worker_receipt(
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
        if not worker_result.ok:
            raise ValueError("invalid insurer partner worker source: " + "; ".join(worker_result.errors))

    evidence_items = [_build_authority_evidence_item(item) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body: dict[str, Any] = {
        "schema": INSURER_PARTNER_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment or service_attestation.get("environment") or "local",
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "service_attestation_binding": _service_attestation_binding(service_attestation),
        "worker_receipt_bindings": [_worker_receipt_binding(receipt) for receipt in receipts],
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, service_attestation, receipts, evidence_items, summary),
        "limitations": [
            "This dossier binds verified insurer partner service and worker receipts to an explicit production-authority evidence checklist.",
            "It records authority references, hashes, freshness windows, and missing live-evidence categories for insurer partner API, policy-system, authentication, and delivery-log operation.",
            "It does not claim continuously operated production insurer partner authority unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    return {**body, "dossier_id": dossier_id, "signatures": [sign_value({"dossier_id": dossier_id, "insurer_partner_authority": body}, key)]}


def verify_insurer_partner_authority_dossier(
    dossier: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    worker_receipts: list[dict[str, Any]] | None = None,
    telemetry: dict[str, Any] | None = None,
    underwriting_quote: dict[str, Any] | None = None,
    actuarial_product: dict[str, Any] | None = None,
    actuarial_corpora: list[dict[str, Any]] | None = None,
    frontend_bundle_path: str | Path | None = None,
    source_now: str | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> InsurerPartnerAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != INSURER_PARTNER_AUTHORITY_SCHEMA:
        errors.append(f"unsupported insurer partner authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical insurer partner authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("insurer partner authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "insurer_partner_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("insurer partner authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in INSURER_PARTNER_AUTHORITY_MODES:
        errors.append("insurer partner authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"insurer partner authority mode is {mode}; live production insurer partner authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"insurer partner authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"insurer partner authority {field} is required")

    source_args = {
        "telemetry": telemetry,
        "underwriting_quote": underwriting_quote,
        "actuarial_product": actuarial_product,
        "actuarial_corpora": actuarial_corpora,
        "frontend_bundle_path": frontend_bundle_path,
        "now": source_now,
    }
    _verify_service_attestation_binding(dossier.get("service_attestation_binding"), service_attestation, source_args, key, errors, warnings)
    _verify_worker_receipt_bindings(dossier.get("worker_receipt_bindings"), worker_receipts, service_attestation, source_args, key, errors, warnings)
    _verify_required_authority(dossier.get("required_production_authority"), errors)
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("insurer partner authority authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("insurer partner authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_counts[_verify_authority_evidence_item(item, errors, warnings, now=freshness_now, require_fresh=require_fresh)] += 1

    expected_summary = _summary([item for item in evidence if isinstance(item, dict)])
    if dossier.get("summary") != expected_summary:
        errors.append("insurer partner authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("insurer partner authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("insurer partner authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every insurer partner authority requirement to be covered")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("insurer partner authority controls are required")
    _check_no_secret_values(dossier, errors)
    return InsurerPartnerAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_insurer_partner_authority_dossier(
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
    result = verify_insurer_partner_authority_dossier(
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
        raise ValueError("invalid insurer partner authority dossier: " + "; ".join(result.errors))
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
        "summary": dossier.get("summary"),
        "control_summary": _status_summary(dossier.get("controls", [])),
        "authority_evidence": [
            {"requirement_id": item.get("requirement_id"), "authority_kind": item.get("authority_kind"), "evidence_ref": item.get("evidence_ref"), "evidence_hash": item.get("evidence_hash"), "evidence_id": item.get("evidence_id"), "issued_at": item.get("issued_at"), "expires_at": item.get("expires_at")}
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(INSURER_PARTNER_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _service_attestation_binding(attestation: dict[str, Any]) -> dict[str, Any]:
    source = attestation.get("source", {}) if isinstance(attestation.get("source"), dict) else {}
    service = attestation.get("service", {}) if isinstance(attestation.get("service"), dict) else {}
    partner = attestation.get("partner", {}) if isinstance(attestation.get("partner"), dict) else {}
    risk = attestation.get("risk_transfer", {}) if isinstance(attestation.get("risk_transfer"), dict) else {}
    security = attestation.get("security", {}) if isinstance(attestation.get("security"), dict) else {}
    observability = attestation.get("observability", {}) if isinstance(attestation.get("observability"), dict) else {}
    actor = attestation.get("operation_actor", {}) if isinstance(attestation.get("operation_actor"), dict) else {}
    credential = actor.get("credential", {}) if isinstance(actor.get("credential"), dict) else {}
    partner_credential = actor.get("partner_credential", {}) if isinstance(actor.get("partner_credential"), dict) else {}
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
        "service_kind": service.get("service_kind"),
        "service_version": service.get("version"),
        "endpoint_url": service.get("endpoint_url"),
        "partner_api_endpoint": service.get("partner_api_endpoint"),
        "service_image_digest": service.get("service_image_digest"),
        "service_binary_hash": service.get("service_binary_hash"),
        "frontend_bundle_ref": service.get("frontend_bundle_ref"),
        "frontend_bundle_hash": service.get("frontend_bundle_hash"),
        "frontend_bundle_artifact_hash": service.get("frontend_bundle_artifact_hash"),
        "api_ref": service.get("api_ref"),
        "queue_ref": service.get("queue_ref"),
        "policy_system_ref": service.get("policy_system_ref"),
        "replicas_min": service.get("replicas_min"),
        "replicas_max": service.get("replicas_max"),
        "availability_zones": service.get("availability_zones"),
        "underwriter": partner.get("underwriter"),
        "quote_id": partner.get("quote_id"),
        "quote_ref": partner.get("quote_ref"),
        "quote_product": partner.get("quote_product"),
        "partner_contract_ref": partner.get("partner_contract_ref"),
        "partner_policy_system_ref": partner.get("policy_system_ref"),
        "actuarial_product_id": partner.get("actuarial_product_id"),
        "telemetry_hash": risk.get("telemetry_hash"),
        "telemetry_schema": risk.get("telemetry_schema"),
        "consent_id": risk.get("consent_id"),
        "consent_active": risk.get("consent_active"),
        "pack_id": risk.get("pack_id"),
        "contract_id": risk.get("contract_id"),
        "risk_score": risk.get("risk_score"),
        "risk_tier": risk.get("risk_tier"),
        "gate_outcome": risk.get("gate_outcome"),
        "quoted_premium_usd": risk.get("quoted_premium_usd"),
        "discount_percent": risk.get("discount_percent"),
        "coverage_limit_usd": risk.get("coverage_limit_usd"),
        "auth_provider_ref": security.get("auth_provider_ref"),
        "partner_auth_policy_ref": security.get("partner_auth_policy_ref"),
        "rbac_policy_ref": security.get("rbac_policy_ref"),
        "consent_policy_ref": security.get("consent_policy_ref"),
        "data_minimization_policy_ref": security.get("data_minimization_policy_ref"),
        "pii_redaction_policy_ref": security.get("pii_redaction_policy_ref"),
        "tenant_isolation_ref": security.get("tenant_isolation_ref"),
        "rate_limit_policy_ref": security.get("rate_limit_policy_ref"),
        "request_signing_ref": security.get("request_signing_ref"),
        "network_policy_ref": security.get("network_policy_ref"),
        "egress_policy_ref": security.get("egress_policy_ref"),
        "encryption_key_ref": security.get("encryption_key_ref"),
        "audit_log_ref": observability.get("audit_log_ref"),
        "audit_log_root": observability.get("audit_log_root"),
        "access_log_ref": observability.get("access_log_ref"),
        "access_log_root": observability.get("access_log_root"),
        "delivery_log_ref": observability.get("delivery_log_ref"),
        "delivery_log_root": observability.get("delivery_log_root"),
        "metrics_ref": observability.get("metrics_ref"),
        "alert_policy_ref": observability.get("alert_policy_ref"),
        "retention_until": observability.get("retention_until"),
        "actor_ref": actor.get("actor_ref"),
        "credential_ref": credential.get("ref"),
        "partner_credential_ref": partner_credential.get("ref"),
        "evidence_refs": actor.get("evidence_refs"),
    }


def _worker_receipt_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    source = receipt.get("source", {}) if isinstance(receipt.get("source"), dict) else {}
    service = receipt.get("service", {}) if isinstance(receipt.get("service"), dict) else {}
    risk = receipt.get("risk_transfer", {}) if isinstance(receipt.get("risk_transfer"), dict) else {}
    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    scheduler = receipt.get("scheduler", {}) if isinstance(receipt.get("scheduler"), dict) else {}
    delivery = receipt.get("delivery", {}) if isinstance(receipt.get("delivery"), dict) else {}
    policy = receipt.get("policy_system", {}) if isinstance(receipt.get("policy_system"), dict) else {}
    observability = receipt.get("observability", {}) if isinstance(receipt.get("observability"), dict) else {}
    credential = receipt.get("credential", {}) if isinstance(receipt.get("credential"), dict) else {}
    partner_credential = receipt.get("partner_credential", {}) if isinstance(receipt.get("partner_credential"), dict) else {}
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
        "service_kind": service.get("service_kind"),
        "service_version": service.get("service_version"),
        "endpoint_url": service.get("endpoint_url"),
        "partner_api_endpoint": service.get("partner_api_endpoint"),
        "partner_contract_ref": service.get("partner_contract_ref"),
        "policy_system_ref": service.get("policy_system_ref"),
        "queue_ref": service.get("queue_ref"),
        "pack_id": risk.get("pack_id"),
        "contract_id": risk.get("contract_id"),
        "consent_id": risk.get("consent_id"),
        "consent_active": risk.get("consent_active"),
        "telemetry_hash": risk.get("telemetry_hash"),
        "quote_id": risk.get("quote_id"),
        "quote_ref": risk.get("quote_ref"),
        "underwriter": risk.get("underwriter"),
        "risk_score": risk.get("risk_score"),
        "risk_tier": risk.get("risk_tier"),
        "quoted_premium_usd": risk.get("quoted_premium_usd"),
        "discount_percent": risk.get("discount_percent"),
        "coverage_limit_usd": risk.get("coverage_limit_usd"),
        "worker_ref": worker.get("worker_ref"),
        "run_ref": worker.get("run_ref"),
        "operation_kind": worker.get("operation_kind"),
        "actor_ref": worker.get("actor_ref"),
        "started_at": worker.get("started_at"),
        "completed_at": worker.get("completed_at"),
        "attempt": worker.get("attempt"),
        "max_attempts": worker.get("max_attempts"),
        "success": worker.get("success"),
        "schedule_ref": scheduler.get("schedule_ref"),
        "cadence_seconds": scheduler.get("cadence_seconds"),
        "lease_ref": scheduler.get("lease_ref"),
        "checkpoint_ref": scheduler.get("checkpoint_ref"),
        "checkpoint_hash": scheduler.get("checkpoint_hash"),
        "previous_cursor_ref": scheduler.get("previous_cursor_ref"),
        "next_cursor_ref": scheduler.get("next_cursor_ref"),
        "next_run_at": scheduler.get("next_run_at"),
        "delivery_queue_ref": delivery.get("queue_ref"),
        "queue_message_ref": delivery.get("queue_message_ref"),
        "destination_ref": delivery.get("destination_ref"),
        "delivery_log_ref": delivery.get("delivery_log_ref"),
        "delivery_log_root": delivery.get("delivery_log_root"),
        "partner_event_log_ref": delivery.get("partner_event_log_ref"),
        "partner_event_log_root": delivery.get("partner_event_log_root"),
        "request_hash": delivery.get("request_hash"),
        "response_status": delivery.get("response_status"),
        "response_hash": delivery.get("response_hash"),
        "worker_policy_system_ref": policy.get("policy_system_ref"),
        "policy_workflow_ref": policy.get("policy_workflow_ref"),
        "policy_workflow_hash": policy.get("policy_workflow_hash"),
        "policy_binding_ref": policy.get("policy_binding_ref"),
        "policy_binding_hash": policy.get("policy_binding_hash"),
        "workflow_status": policy.get("workflow_status"),
        "metrics_ref": observability.get("metrics_ref"),
        "audit_log_ref": observability.get("audit_log_ref"),
        "audit_log_root": observability.get("audit_log_root"),
        "access_log_ref": observability.get("access_log_ref"),
        "access_log_root": observability.get("access_log_root"),
        "retention_until": observability.get("retention_until"),
        "evidence_refs": observability.get("evidence_refs"),
        "credential_ref": credential.get("ref"),
        "partner_credential_ref": partner_credential.get("ref"),
    }


def _verify_service_attestation_binding(binding: Any, service_attestation: dict[str, Any] | None, sources: dict[str, Any], key: str | None, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(binding, dict):
        errors.append("insurer partner authority service_attestation_binding must be an object")
        return
    for field in (
        "attestation_id", "attestation_hash", "attestation_mode", "environment", "attested_at", "source_count", "source_hash", "service_ref", "service_kind", "service_version", "endpoint_url", "partner_api_endpoint", "service_image_digest", "service_binary_hash", "frontend_bundle_ref", "frontend_bundle_hash", "api_ref", "queue_ref", "policy_system_ref", "replicas_min", "replicas_max", "availability_zones", "underwriter", "quote_id", "quote_ref", "quote_product", "partner_contract_ref", "partner_policy_system_ref", "actuarial_product_id", "telemetry_hash", "telemetry_schema", "consent_id", "pack_id", "contract_id", "risk_score", "risk_tier", "gate_outcome", "quoted_premium_usd", "discount_percent", "coverage_limit_usd", "auth_provider_ref", "partner_auth_policy_ref", "rbac_policy_ref", "consent_policy_ref", "data_minimization_policy_ref", "pii_redaction_policy_ref", "tenant_isolation_ref", "rate_limit_policy_ref", "request_signing_ref", "network_policy_ref", "egress_policy_ref", "encryption_key_ref", "audit_log_root", "access_log_root", "delivery_log_root", "metrics_ref", "alert_policy_ref", "retention_until", "actor_ref", "credential_ref", "partner_credential_ref"
    ):
        if binding.get(field) in (None, "", []):
            errors.append(f"insurer partner authority service_attestation_binding.{field} is required")
    if service_attestation is None:
        warnings.append("insurer partner authority service attestation was not supplied; insurer partner service source was not replayed")
        return
    expected = _service_attestation_binding(service_attestation)
    if binding != expected:
        errors.append("insurer partner authority service_attestation_binding does not match supplied service attestation")
    result = verify_insurer_partner_service_attestation(service_attestation, key=key, **sources)
    if not result.ok:
        errors.extend(f"insurer partner authority service source: {error}" for error in result.errors)
    warnings.extend(f"insurer partner authority service source: {warning}" for warning in result.warnings)


def _verify_worker_receipt_bindings(bindings: Any, worker_receipts: list[dict[str, Any]] | None, service_attestation: dict[str, Any] | None, sources: dict[str, Any], key: str | None, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(bindings, list) or not bindings:
        errors.append("insurer partner authority worker_receipt_bindings must include at least one worker receipt")
        bindings = []
    for binding in bindings:
        if not isinstance(binding, dict):
            errors.append("insurer partner authority worker_receipt_binding must be an object")
            continue
        for field in (
            "worker_operation_id", "worker_operation_hash", "receipt_mode", "environment", "recorded_at", "source_count", "source_hash", "service_attestation_id", "service_attestation_hash", "service_ref", "service_kind", "service_version", "endpoint_url", "partner_api_endpoint", "partner_contract_ref", "policy_system_ref", "queue_ref", "pack_id", "contract_id", "consent_id", "telemetry_hash", "quote_id", "quote_ref", "underwriter", "risk_score", "risk_tier", "quoted_premium_usd", "discount_percent", "coverage_limit_usd", "worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at", "attempt", "max_attempts", "schedule_ref", "cadence_seconds", "lease_ref", "checkpoint_ref", "checkpoint_hash", "delivery_queue_ref", "queue_message_ref", "destination_ref", "delivery_log_ref", "delivery_log_root", "partner_event_log_ref", "partner_event_log_root", "request_hash", "response_status", "response_hash", "worker_policy_system_ref", "policy_workflow_ref", "policy_workflow_hash", "policy_binding_ref", "policy_binding_hash", "workflow_status", "metrics_ref", "audit_log_ref", "audit_log_root", "access_log_ref", "access_log_root", "retention_until", "credential_ref", "partner_credential_ref"
        ):
            if binding.get(field) in (None, "", []):
                errors.append(f"insurer partner authority worker_receipt_binding.{field} is required")
    if not worker_receipts:
        warnings.append("insurer partner authority worker receipts were not supplied; worker source hashes were not replayed")
        return
    expected = [_worker_receipt_binding(receipt) for receipt in worker_receipts]
    if bindings != expected:
        errors.append("insurer partner authority worker_receipt_bindings do not match supplied worker receipts")
    for receipt in worker_receipts:
        result = verify_insurer_partner_worker_receipt(receipt, service_attestation=service_attestation, key=key, **sources)
        if not result.ok:
            errors.extend(f"insurer partner authority worker source: {error}" for error in result.errors)
        warnings.extend(f"insurer partner authority worker source: {warning}" for warning in result.warnings)
    if service_attestation is not None:
        service_hash = content_hash(service_attestation)
        service_id = service_attestation.get("attestation_id")
        for binding in bindings:
            if isinstance(binding, dict) and binding.get("service_attestation_hash") != service_hash:
                errors.append("insurer partner authority worker binding does not reference supplied service attestation hash")
            if isinstance(binding, dict) and binding.get("service_attestation_id") != service_id:
                errors.append("insurer partner authority worker binding does not reference supplied service attestation id")


def _build_authority_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unknown insurer partner production authority requirement: {requirement_id}")
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
        errors.append(f"insurer partner authority evidence_id does not match evidence body: {item.get('requirement_id')}")
    requirement_id = item.get("requirement_id")
    authority_kind = item.get("authority_kind")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        errors.append(f"unknown insurer partner production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    elif requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS and authority_kind not in _requirement_authority_kinds(str(requirement_id)):
        errors.append(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for field in ("evidence_ref", "evidence_hash", "description"):
        if not item.get(field):
            errors.append(f"insurer partner authority {field} is required: {requirement_id}")
    if item.get("evidence_hash") and not str(item.get("evidence_hash")).startswith("sha256:"):
        errors.append(f"insurer partner authority evidence_hash must start with sha256: {requirement_id}")

    issued_at = _parse_optional_timestamp(item, "issued_at", errors)
    expires_at = _parse_optional_timestamp(item, "expires_at", errors)
    freshness_status = "fresh"
    missing_fields = [field for field in ("issued_at", "expires_at") if not item.get(field)]
    if missing_fields:
        freshness_status = "missing"
        _freshness_problem(f"insurer partner authority freshness metadata missing for {requirement_id}: {', '.join(missing_fields)}", errors, warnings, require_fresh=require_fresh)
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        freshness_status = "stale"
        errors.append(f"insurer partner authority expires_at must be after issued_at: {requirement_id}")
    if now is not None and issued_at is not None and issued_at > now:
        freshness_status = "stale"
        _freshness_problem(f"insurer partner authority evidence is not yet issued for {requirement_id}: {item.get('issued_at')}", errors, warnings, require_fresh=require_fresh)
    if now is not None and expires_at is not None and expires_at <= now:
        freshness_status = "stale"
        _freshness_problem(f"insurer partner authority evidence expired for {requirement_id}: {item.get('expires_at')}", errors, warnings, require_fresh=require_fresh)
    return freshness_status


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("insurer partner authority required_production_authority does not match v0.1 requirements")


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


def _controls(mode: str, service_attestation: dict[str, Any], worker_receipts: list[dict[str, Any]], evidence: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"name": "service_attestation_replayed", "status": "passed", "detail": "The dossier builder replayed the insurer partner service attestation and supplied source evidence when available."},
        {"name": "worker_receipts_bound", "status": "passed" if service_attestation.get("attestation_id") and worker_receipts else "failed", "detail": "The dossier binds insurer partner worker operation IDs, service hashes, scheduler, queue, delivery, policy, response, log, and credential refs."},
        {"name": "authority_evidence_manifested", "status": "passed" if evidence else "deferred", "detail": "External insurer partner authority evidence references are hash-bound when supplied."},
        {"name": "freshness_windows_tracked", "status": "passed" if evidence and summary["freshness_window_count"] == len(evidence) else "deferred", "detail": "Issued/expires freshness windows are tracked for every supplied authority item when available."},
        {"name": "complete_live_authority", "status": "passed" if summary["missing_requirement_count"] == 0 else "deferred", "detail": "Every insurer partner production authority requirement must be covered before this can claim live production insurer integration authority."},
        {"name": "production_claim_limited", "status": "passed" if mode != "production-dossier" or summary["missing_requirement_count"] == 0 else "failed", "detail": "Non-production dossier modes explicitly avoid claiming live credentialed insurer partner or policy-system operation."},
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
        errors.append(f"insurer partner authority freshness {label} invalid: {exc}")
        return None


def _parse_optional_timestamp(item: dict[str, Any], field: str, errors: list[str]) -> Any:
    value = item.get(field)
    if not value:
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"insurer partner authority {field} invalid: {exc}")
        return None


def _freshness_problem(message: str, errors: list[str], warnings: list[str], *, require_fresh: bool) -> None:
    if require_fresh:
        errors.append(message)
    else:
        warnings.append(message)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"insurer partner authority {field} is required")
    return value


def _require_hash_ref(value: str, field: str) -> None:
    if not value.startswith("sha256:"):
        raise ValueError(f"insurer partner authority {field} must start with sha256:")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}"
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"insurer partner authority contains secret-like field {child_path}; store only redacted refs")
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
