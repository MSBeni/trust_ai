from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .delivery import verify_provider_delivery
from .provider_operations_service import verify_provider_operations_service_attestation

PROVIDER_DELIVERY_SERVICE_SCHEMA = "trustai.provider-delivery-service-attestation/0.1"
PROVIDER_DELIVERY_SERVICE_ENTRY_TYPE = "provider.delivery_service_attested"
PROVIDER_DELIVERY_SERVICE_MODES = {"local-reference", "provider-delivery-attested", "production-design"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ProviderDeliveryServiceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_provider_delivery_service_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider delivery service attestation must contain an object")
    return value


def write_provider_delivery_service_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_provider_delivery_service_attestation(
    *,
    delivery: dict[str, Any],
    payload: dict[str, Any] | None = None,
    payload_artifact_path: str | Path | None = None,
    provider_operations_service: dict[str, Any] | None = None,
    mode: str = "provider-delivery-attested",
    environment: str = "local",
    service_ref: str,
    service_version: str,
    service_image: str,
    service_image_digest: str,
    service_binary_hash: str,
    replicas_min: int,
    replicas_max: int,
    availability_zones: list[str] | None = None,
    dispatch_worker_ref: str,
    queue_ref: str,
    dead_letter_queue_ref: str,
    idempotency_store_ref: str,
    retry_policy_ref: str,
    outbound_proxy_ref: str,
    provider_endpoint_base: str,
    provider_credential_ref: str,
    mtls_policy_ref: str,
    auth_policy_ref: str,
    network_policy_ref: str,
    egress_policy_ref: str,
    rate_limit_policy_ref: str,
    request_signing_policy_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    metrics_ref: str,
    alert_policy_ref: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in PROVIDER_DELIVERY_SERVICE_MODES:
        raise ValueError(f"mode must be one of {sorted(PROVIDER_DELIVERY_SERVICE_MODES)}")
    source_result = _verify_sources(delivery=delivery, payload=payload, payload_artifact_path=payload_artifact_path, provider_operations_service=provider_operations_service, key=key)
    if not source_result.ok:
        raise ValueError("invalid provider delivery service source evidence: " + "; ".join(source_result.errors))

    timestamp = attested_at or utc_now()
    parse_rfc3339(timestamp)
    retention = parse_rfc3339(retention_until)
    if retention <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after attested_at")

    for field, value in {
        "service_ref": service_ref,
        "service_version": service_version,
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "dispatch_worker_ref": dispatch_worker_ref,
        "queue_ref": queue_ref,
        "dead_letter_queue_ref": dead_letter_queue_ref,
        "idempotency_store_ref": idempotency_store_ref,
        "retry_policy_ref": retry_policy_ref,
        "outbound_proxy_ref": outbound_proxy_ref,
        "provider_endpoint_base": provider_endpoint_base,
        "provider_credential_ref": provider_credential_ref,
        "mtls_policy_ref": mtls_policy_ref,
        "auth_policy_ref": auth_policy_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "request_signing_policy_ref": request_signing_policy_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
    }.items():
        _require_text(value, field)

    delivery_credential = delivery.get("credential") if isinstance(delivery.get("credential"), dict) else {}
    if delivery_credential.get("ref") != provider_credential_ref:
        raise ValueError("provider_credential_ref must match delivery credential ref")

    service = {
        "service_ref": service_ref,
        "version": service_version,
        "provider": delivery.get("provider"),
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "replicas_min": replicas_min,
        "replicas_max": replicas_max,
        "availability_zones": sorted(availability_zones or []),
    }
    dispatch = {
        "dispatch_worker_ref": dispatch_worker_ref,
        "queue_ref": queue_ref,
        "dead_letter_queue_ref": dead_letter_queue_ref,
        "idempotency_store_ref": idempotency_store_ref,
        "retry_policy_ref": retry_policy_ref,
        "outbound_proxy_ref": outbound_proxy_ref,
        "provider_endpoint_base": provider_endpoint_base.rstrip("/"),
        "provider_credential": _redacted_ref(provider_credential_ref),
        "source_delivery_id": delivery.get("delivery_id"),
        "source_delivery_mode": delivery.get("mode"),
        "source_target_url": delivery.get("target_url"),
    }
    security = {
        "mtls_policy_ref": mtls_policy_ref,
        "auth_policy_ref": auth_policy_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "request_signing_policy_ref": request_signing_policy_ref,
    }
    observability = {
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
        "retention_until": retention_until,
    }
    operation_actor = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    source_artifacts = _source_artifacts(delivery=delivery, payload=payload, provider_operations_service=provider_operations_service)
    body: dict[str, Any] = {
        "schema": PROVIDER_DELIVERY_SERVICE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": _source_summary(source_artifacts),
        "service": service,
        "dispatch": dispatch,
        "security": security,
        "observability": observability,
        "operation_actor": operation_actor,
        "source_artifacts": source_artifacts,
        "controls": _controls(service, dispatch, security, observability),
        "limitations": [
            "This attestation binds provider delivery receipts to dispatch service hardening evidence.",
            "It stores redacted credential references and hashes, not provider API tokens or request secrets.",
            "It does not prove successful credentialed external posting unless the source delivery receipt records a provider response or HTTP dispatch.",
            "Production deployments should pair this attestation with live provider delivery receipts, provider operations service evidence, managed queues, egress controls, and audit-log exports.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "provider_delivery_service": body}, key)],
    }


def verify_provider_delivery_service_attestation(
    attestation: dict[str, Any],
    *,
    delivery: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    payload_artifact_path: str | Path | None = None,
    provider_operations_service: dict[str, Any] | None = None,
    key: str | None = None,
) -> ProviderDeliveryServiceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != PROVIDER_DELIVERY_SERVICE_SCHEMA:
        errors.append(f"unsupported provider delivery service attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    if attestation.get("attestation_id") != content_hash(body):
        errors.append("attestation_id does not match canonical provider delivery service attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider delivery service attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "provider_delivery_service": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider delivery service attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"provider delivery service attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in PROVIDER_DELIVERY_SERVICE_MODES:
        errors.append("provider delivery service mode is unsupported")
    elif mode != "provider-delivery-attested":
        warnings.append(f"provider delivery service mode is {mode}; live dispatch operation is not fully claimed")

    _verify_service(attestation.get("service"), errors)
    _verify_dispatch(attestation.get("dispatch"), errors, warnings)
    _verify_required_object(attestation.get("security"), "security", errors)
    _verify_observability(attestation.get("observability"), attested, errors)
    _verify_actor(attestation.get("operation_actor"), errors)

    controls = attestation.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("provider delivery service controls are required")

    source_artifacts = attestation.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or len(source_artifacts) < 1:
        errors.append("provider delivery service source_artifacts must include a provider delivery receipt")
    supplied_sources = _source_artifacts(delivery=delivery, payload=payload, provider_operations_service=provider_operations_service)
    if supplied_sources:
        if source_artifacts != supplied_sources:
            errors.append("provider delivery service source_artifacts do not match supplied source artifacts")
        if attestation.get("source") != _source_summary(supplied_sources):
            errors.append("provider delivery service source summary does not match supplied source artifacts")
        source_result = _verify_sources(delivery=delivery, payload=payload, payload_artifact_path=payload_artifact_path, provider_operations_service=provider_operations_service, key=key)
        if not source_result.ok:
            errors.extend(f"provider delivery service source invalid: {error}" for error in source_result.errors)
        warnings.extend(f"provider delivery service source: {warning}" for warning in source_result.warnings)
    else:
        warnings.append("provider delivery service source artifacts were not supplied; delivery hashes were not replayed")

    _check_no_secret_values(attestation, errors)
    return ProviderDeliveryServiceVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_delivery_service_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    **sources: Any,
) -> dict[str, Any]:
    key = sources.pop("key", None)
    result = verify_provider_delivery_service_attestation(attestation, key=key, **sources)
    if not result.ok:
        raise ValueError("invalid provider delivery service attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "source": attestation.get("source"),
        "service": attestation.get("service"),
        "dispatch": attestation.get("dispatch"),
        "security": attestation.get("security"),
        "observability": attestation.get("observability"),
        "operation_actor": attestation.get("operation_actor"),
        "source_artifacts": attestation.get("source_artifacts"),
        "control_summary": _status_summary(attestation.get("controls", [])),
    }
    return chain.append(PROVIDER_DELIVERY_SERVICE_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _verify_sources(
    *,
    delivery: dict[str, Any] | None,
    payload: dict[str, Any] | None,
    payload_artifact_path: str | Path | None,
    provider_operations_service: dict[str, Any] | None,
    key: str | None,
) -> ProviderDeliveryServiceVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(delivery, dict):
        errors.append("delivery source is required")
        return ProviderDeliveryServiceVerification(False, errors, warnings)

    delivery_result = verify_provider_delivery(delivery, payload, payload_artifact_path=payload_artifact_path, key=key)
    if not delivery_result.ok:
        errors.extend(f"delivery: {error}" for error in delivery_result.errors)
    warnings.extend(f"delivery: {warning}" for warning in delivery_result.warnings)
    if delivery.get("mode") == "dry-run":
        warnings.append("delivery source is dry-run; successful external provider posting is not claimed")

    if provider_operations_service is not None:
        operations_result = verify_provider_operations_service_attestation(provider_operations_service, key=key)
        if not operations_result.ok:
            errors.extend(f"provider operations service: {error}" for error in operations_result.errors)
        warnings.extend(f"provider operations service: {warning}" for warning in operations_result.warnings)
        provider = provider_operations_service.get("service", {}).get("provider")
        if provider and delivery.get("provider") and provider != delivery.get("provider"):
            errors.append("provider operations service provider does not match delivery provider")
    else:
        warnings.append("provider operations service attestation was not supplied")
    return ProviderDeliveryServiceVerification(not errors, errors, warnings)


def _source_artifacts(**sources: dict[str, Any] | None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name, value in sources.items():
        if isinstance(value, dict):
            records.append({"type": name.replace("_", "-"), "id": _source_id(value), "schema": value.get("schema"), "hash": content_hash(value)})
    return records


def _source_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_count": len(records),
        "source_hash": content_hash(records),
        "schemas": sorted({str(record.get("schema")) for record in records if record.get("schema")}),
        "required_types": sorted(record["type"] for record in records),
    }


def _source_id(value: dict[str, Any]) -> Any:
    for key in ("delivery_id", "payload_hash", "attestation_id"):
        if value.get(key):
            return value.get(key)
    return value.get("schema")


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider delivery service service must be an object")
        return
    for field in ("service_ref", "version", "provider", "service_image", "service_image_digest", "service_binary_hash"):
        if not value.get(field):
            errors.append(f"provider delivery service service.{field} is required")
    for field in ("service_image_digest", "service_binary_hash"):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"provider delivery service service.{field} must be a sha256 reference")
    replicas_min = value.get("replicas_min")
    replicas_max = value.get("replicas_max")
    if not isinstance(replicas_min, int) or replicas_min < 2:
        errors.append("provider delivery service service.replicas_min must be an integer >= 2")
    if not isinstance(replicas_max, int) or not isinstance(replicas_min, int) or replicas_max < replicas_min:
        errors.append("provider delivery service service.replicas_max must be >= replicas_min")
    if not isinstance(value.get("availability_zones"), list) or len(value.get("availability_zones")) < 2:
        errors.append("provider delivery service service.availability_zones must include at least two zones")


def _verify_dispatch(value: Any, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider delivery service dispatch must be an object")
        return
    for field in (
        "dispatch_worker_ref",
        "queue_ref",
        "dead_letter_queue_ref",
        "idempotency_store_ref",
        "retry_policy_ref",
        "outbound_proxy_ref",
        "provider_endpoint_base",
        "source_delivery_id",
        "source_delivery_mode",
        "source_target_url",
    ):
        if not value.get(field):
            errors.append(f"provider delivery service dispatch.{field} is required")
    _verify_redacted_ref(value.get("provider_credential"), "provider delivery service dispatch.provider_credential", errors)
    if value.get("source_delivery_mode") == "dry-run":
        warnings.append("provider delivery service source delivery is dry-run; live external post is not claimed")


def _verify_required_object(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"provider delivery service {name} must be an object")
        return
    for field, child in value.items():
        if not child:
            errors.append(f"provider delivery service {name}.{field} is required")


def _verify_observability(value: Any, attested: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider delivery service observability must be an object")
        return
    for field in ("audit_log_ref", "audit_log_root", "metrics_ref", "alert_policy_ref", "retention_until"):
        if not value.get(field):
            errors.append(f"provider delivery service observability.{field} is required")
    if not _is_sha256_ref(str(value.get("audit_log_root") or "")):
        errors.append("provider delivery service observability.audit_log_root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("provider delivery service observability.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"provider delivery service observability.retention_until invalid: {exc}")


def _verify_actor(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider delivery service operation_actor must be an object")
        return
    if not value.get("actor_ref"):
        errors.append("provider delivery service operation_actor.actor_ref is required")
    _verify_redacted_ref(value.get("credential"), "provider delivery service operation_actor.credential", errors)


def _controls(service: dict[str, Any], dispatch: dict[str, Any], security: dict[str, Any], observability: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"id": "provider-delivery-service-identity", "status": "service-attested" if service.get("service_image_digest") and service.get("service_binary_hash") else "planned-production", "description": "Provider delivery service image, binary hash, provider, replica floor, and multi-zone evidence are bound."},
        {"id": "provider-delivery-source-binding", "status": "service-attested" if dispatch.get("source_delivery_id") and dispatch.get("provider_endpoint_base") else "planned-production", "description": "Source delivery receipt, provider endpoint, and redacted provider credential are bound."},
        {"id": "provider-delivery-queue-retry-dlq", "status": "service-attested" if dispatch.get("queue_ref") and dispatch.get("dead_letter_queue_ref") and dispatch.get("retry_policy_ref") else "planned-production", "description": "Dispatch queue, retry policy, and dead-letter queue evidence are bound."},
        {"id": "provider-delivery-idempotent-egress", "status": "service-attested" if dispatch.get("idempotency_store_ref") and security.get("egress_policy_ref") and dispatch.get("outbound_proxy_ref") else "planned-production", "description": "Idempotency, outbound proxy, and egress controls are bound."},
        {"id": "provider-delivery-auth-rate-limit", "status": "service-attested" if security.get("auth_policy_ref") and security.get("rate_limit_policy_ref") and security.get("request_signing_policy_ref") else "planned-production", "description": "Authentication, rate-limit, and request signing policy evidence are bound."},
        {"id": "provider-delivery-audit-retention", "status": "service-attested" if observability.get("audit_log_ref") and observability.get("audit_log_root") else "planned-production", "description": "Dispatch audit-log root, metrics, alerting, and retention evidence are bound."},
    ]


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
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                if not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"provider delivery service secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _is_sha256_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value[7:])
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())
