from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .actuarial import verify_actuarial_corpus, verify_actuarial_product
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .underwriting_quote import INSURER_TELEMETRY_SCHEMA, verify_underwriting_quote

INSURER_PARTNER_SERVICE_SCHEMA = "trustai.insurer-partner-service-attestation/0.1"
INSURER_PARTNER_SERVICE_ENTRY_TYPE = "insurer.partner_service_attested"
INSURER_PARTNER_SERVICE_MODES = {"local-reference", "partner-service-attested", "production-design"}
INSURER_PARTNER_KINDS = {"insurer-api", "insurer-portal", "underwriting-integration", "actuarial-data-product"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class InsurerPartnerServiceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_insurer_partner_service_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("insurer partner service attestation must contain an object")
    return value


def write_insurer_partner_service_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_insurer_partner_service_attestation(
    telemetry: dict[str, Any],
    underwriting_quote: dict[str, Any],
    *,
    actuarial_product: dict[str, Any] | None = None,
    actuarial_corpora: list[dict[str, Any]] | None = None,
    mode: str = "partner-service-attested",
    environment: str = "local",
    service_kind: str = "underwriting-integration",
    service_ref: str,
    service_version: str,
    endpoint_url: str,
    partner_api_endpoint: str,
    service_image: str,
    service_image_digest: str,
    service_binary_hash: str,
    frontend_bundle_ref: str,
    frontend_bundle_hash: str,
    api_ref: str,
    queue_ref: str,
    policy_system_ref: str,
    partner_contract_ref: str,
    auth_provider_ref: str,
    partner_auth_policy_ref: str,
    rbac_policy_ref: str,
    consent_policy_ref: str,
    data_minimization_policy_ref: str,
    pii_redaction_policy_ref: str,
    tenant_isolation_ref: str,
    rate_limit_policy_ref: str,
    request_signing_ref: str,
    network_policy_ref: str,
    egress_policy_ref: str,
    encryption_key_ref: str,
    replicas_min: int,
    replicas_max: int,
    availability_zones: list[str] | None,
    audit_log_ref: str,
    audit_log_root: str,
    access_log_ref: str,
    access_log_root: str,
    delivery_log_ref: str,
    delivery_log_root: str,
    metrics_ref: str,
    alert_policy_ref: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    partner_credential_ref: str,
    evidence_refs: list[str] | None = None,
    now: str | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in INSURER_PARTNER_SERVICE_MODES:
        raise ValueError(f"mode must be one of {sorted(INSURER_PARTNER_SERVICE_MODES)}")
    if service_kind not in INSURER_PARTNER_KINDS:
        raise ValueError(f"service_kind must be one of {sorted(INSURER_PARTNER_KINDS)}")

    quote_result = verify_underwriting_quote(underwriting_quote, telemetry=telemetry, now=now, key=key)
    if not quote_result.ok:
        raise ValueError("invalid underwriting quote source: " + "; ".join(quote_result.errors))

    corpora = actuarial_corpora or []
    if actuarial_product is not None:
        product_result = verify_actuarial_product(actuarial_product, corpora=corpora or None, key=key)
        if not product_result.ok:
            raise ValueError("invalid actuarial product source: " + "; ".join(product_result.errors))
    for corpus in corpora:
        corpus_result = verify_actuarial_corpus(corpus)
        if not corpus_result.ok:
            raise ValueError("invalid actuarial corpus source: " + "; ".join(corpus_result.errors))

    timestamp = attested_at or utc_now()
    attested = parse_rfc3339(timestamp)
    retention = parse_rfc3339(retention_until)
    if retention <= attested:
        raise ValueError("retention_until must be after attested_at")

    for field, value in {
        "environment": environment,
        "service_ref": service_ref,
        "service_version": service_version,
        "endpoint_url": endpoint_url,
        "partner_api_endpoint": partner_api_endpoint,
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "frontend_bundle_ref": frontend_bundle_ref,
        "frontend_bundle_hash": frontend_bundle_hash,
        "api_ref": api_ref,
        "queue_ref": queue_ref,
        "policy_system_ref": policy_system_ref,
        "partner_contract_ref": partner_contract_ref,
        "auth_provider_ref": auth_provider_ref,
        "partner_auth_policy_ref": partner_auth_policy_ref,
        "rbac_policy_ref": rbac_policy_ref,
        "consent_policy_ref": consent_policy_ref,
        "data_minimization_policy_ref": data_minimization_policy_ref,
        "pii_redaction_policy_ref": pii_redaction_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "request_signing_ref": request_signing_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "encryption_key_ref": encryption_key_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "access_log_ref": access_log_ref,
        "access_log_root": access_log_root,
        "delivery_log_ref": delivery_log_ref,
        "delivery_log_root": delivery_log_root,
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
        "partner_credential_ref": partner_credential_ref,
    }.items():
        _require_text(value, field)

    source_artifacts = _source_artifacts(
        telemetry=telemetry,
        underwriting_quote=underwriting_quote,
        actuarial_product=actuarial_product,
        actuarial_corpora=corpora,
    )
    service = {
        "service_ref": service_ref,
        "version": service_version,
        "service_kind": service_kind,
        "endpoint_url": endpoint_url,
        "partner_api_endpoint": partner_api_endpoint,
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "frontend_bundle_ref": frontend_bundle_ref,
        "frontend_bundle_hash": frontend_bundle_hash,
        "api_ref": api_ref,
        "queue_ref": queue_ref,
        "policy_system_ref": policy_system_ref,
        "replicas_min": replicas_min,
        "replicas_max": replicas_max,
        "availability_zones": sorted(availability_zones or []),
    }
    partner = {
        "underwriter": underwriting_quote.get("underwriter", {}).get("name"),
        "quote_id": underwriting_quote.get("quote_id"),
        "quote_ref": underwriting_quote.get("quote", {}).get("quote_ref"),
        "quote_product": underwriting_quote.get("quote", {}).get("product"),
        "partner_contract_ref": partner_contract_ref,
        "policy_system_ref": policy_system_ref,
        "actuarial_product_id": actuarial_product.get("product_id") if actuarial_product else None,
    }
    risk_transfer = {
        "telemetry_hash": content_hash(telemetry),
        "telemetry_schema": telemetry.get("schema"),
        "consent_id": telemetry.get("consent", {}).get("consent_id"),
        "consent_active": telemetry.get("consent", {}).get("status", {}).get("active"),
        "pack_id": telemetry.get("pack_id"),
        "contract_id": telemetry.get("contract_id"),
        "risk_score": telemetry.get("risk_score"),
        "risk_tier": telemetry.get("risk_tier"),
        "gate_outcome": telemetry.get("gate_outcome"),
        "quoted_premium_usd": underwriting_quote.get("quote", {}).get("quoted_premium_usd"),
        "discount_percent": underwriting_quote.get("quote", {}).get("discount_percent"),
        "coverage_limit_usd": underwriting_quote.get("quote", {}).get("coverage_limit_usd"),
    }
    security = {
        "auth_provider_ref": auth_provider_ref,
        "partner_auth_policy_ref": partner_auth_policy_ref,
        "rbac_policy_ref": rbac_policy_ref,
        "consent_policy_ref": consent_policy_ref,
        "data_minimization_policy_ref": data_minimization_policy_ref,
        "pii_redaction_policy_ref": pii_redaction_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "request_signing_ref": request_signing_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "encryption_key_ref": encryption_key_ref,
    }
    observability = {
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "access_log_ref": access_log_ref,
        "access_log_root": access_log_root,
        "delivery_log_ref": delivery_log_ref,
        "delivery_log_root": delivery_log_root,
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
        "retention_until": retention_until,
    }
    operation_actor = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "partner_credential": _redacted_ref(partner_credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    body: dict[str, Any] = {
        "schema": INSURER_PARTNER_SERVICE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": _source_summary(source_artifacts),
        "service": service,
        "partner": partner,
        "risk_transfer": risk_transfer,
        "security": security,
        "observability": observability,
        "operation_actor": operation_actor,
        "source_artifacts": source_artifacts,
        "controls": _controls(service, partner, risk_transfer, security, observability),
        "limitations": [
            "This attestation binds consented insurer telemetry and underwriting quote evidence to insurer partner service hardening evidence.",
            "It records service image, endpoint, partner API, frontend bundle, partner authentication, consent/data-minimization, request-signing, delivery, policy-system, audit, access-log, metrics, alerting, actor, and redacted credential evidence.",
            "It stores redacted credential references and artifact hashes, not raw insurer tokens, policy-system credentials, customer PII, or private underwriting data.",
            "Production deployments should replace local/reference insurer endpoints with credentialed partner authentication, live underwriter API responses, policy-system workflow identifiers, and immutable partner delivery logs.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "insurer_partner_service": body}, key)],
    }


def verify_insurer_partner_service_attestation(
    attestation: dict[str, Any],
    telemetry: dict[str, Any] | None = None,
    underwriting_quote: dict[str, Any] | None = None,
    *,
    actuarial_product: dict[str, Any] | None = None,
    actuarial_corpora: list[dict[str, Any]] | None = None,
    now: str | None = None,
    key: str | None = None,
) -> InsurerPartnerServiceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != INSURER_PARTNER_SERVICE_SCHEMA:
        errors.append(f"unsupported insurer partner service attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical insurer partner service attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("insurer partner service attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "insurer_partner_service": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("insurer partner service attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"insurer partner service attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in INSURER_PARTNER_SERVICE_MODES:
        errors.append("insurer partner service mode is unsupported")
    elif mode != "partner-service-attested":
        warnings.append(f"insurer partner service mode is {mode}; live insurer partner operation is not fully claimed")

    _verify_source(attestation.get("source"), errors)
    _verify_service(attestation.get("service"), errors)
    _verify_partner(attestation.get("partner"), errors)
    _verify_risk_transfer(attestation.get("risk_transfer"), errors)
    _verify_required_object(attestation.get("security"), "security", errors)
    _verify_observability(attestation.get("observability"), attested, errors)
    _verify_actor(attestation.get("operation_actor"), errors)
    _check_no_secret_values(attestation, errors)

    corpora = actuarial_corpora or []
    supplied_records = _source_artifacts(
        telemetry=telemetry,
        underwriting_quote=underwriting_quote,
        actuarial_product=actuarial_product,
        actuarial_corpora=corpora,
    )
    source_artifacts = attestation.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("insurer partner service source_artifacts are required")
    elif supplied_records:
        if source_artifacts != supplied_records:
            errors.append("insurer partner service source_artifacts do not match supplied source artifacts")
        if attestation.get("source") != _source_summary(supplied_records):
            errors.append("insurer partner service source summary does not match supplied source artifacts")

    if telemetry is not None:
        _verify_telemetry(telemetry, errors)
        _verify_risk_transfer_matches_source(attestation.get("risk_transfer"), telemetry, underwriting_quote, errors)
    else:
        warnings.append("insurer telemetry source was not supplied; service source hashes were not replayed")

    if underwriting_quote is not None:
        quote_result = verify_underwriting_quote(underwriting_quote, telemetry=telemetry, now=now, key=key)
        errors.extend(f"underwriting quote source: {error}" for error in quote_result.errors)
        warnings.extend(f"underwriting quote source: {warning}" for warning in quote_result.warnings)
        _verify_partner_matches_quote(attestation.get("partner"), underwriting_quote, errors)
    else:
        warnings.append("underwriting quote source was not supplied; quote binding was not replayed")

    for corpus in corpora:
        corpus_result = verify_actuarial_corpus(corpus)
        errors.extend(f"actuarial corpus source {corpus.get('corpus_id')}: {error}" for error in corpus_result.errors)
        warnings.extend(f"actuarial corpus source {corpus.get('corpus_id')}: {warning}" for warning in corpus_result.warnings)
    if actuarial_product is not None:
        product_result = verify_actuarial_product(actuarial_product, corpora=corpora or None, key=key)
        errors.extend(f"actuarial product source: {error}" for error in product_result.errors)
        warnings.extend(f"actuarial product source: {warning}" for warning in product_result.warnings)
        if attestation.get("partner", {}).get("actuarial_product_id") != actuarial_product.get("product_id"):
            errors.append("insurer partner service partner.actuarial_product_id does not match actuarial product source")

    return InsurerPartnerServiceVerification(ok=not errors, errors=errors, warnings=warnings)


def append_insurer_partner_service_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    telemetry: dict[str, Any] | None = None,
    underwriting_quote: dict[str, Any] | None = None,
    *,
    actuarial_product: dict[str, Any] | None = None,
    actuarial_corpora: list[dict[str, Any]] | None = None,
    now: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_insurer_partner_service_attestation(
        attestation,
        telemetry,
        underwriting_quote,
        actuarial_product=actuarial_product,
        actuarial_corpora=actuarial_corpora,
        now=now,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid insurer partner service attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "service": attestation.get("service"),
        "partner": attestation.get("partner"),
        "risk_transfer": attestation.get("risk_transfer"),
        "source": attestation.get("source"),
        "controls": attestation.get("controls", []),
        "control_status_summary": _status_summary(attestation.get("controls", [])),
        "limitations": attestation.get("limitations", []),
    }
    return chain.append(INSURER_PARTNER_SERVICE_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _source_artifacts(
    *,
    telemetry: dict[str, Any] | None = None,
    underwriting_quote: dict[str, Any] | None = None,
    actuarial_product: dict[str, Any] | None = None,
    actuarial_corpora: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name, value in (
        ("insurer-risk-telemetry", telemetry),
        ("underwriting-quote", underwriting_quote),
        ("actuarial-product", actuarial_product),
    ):
        if isinstance(value, dict):
            records.append({"type": name, "id": _source_id(value), "schema": value.get("schema"), "hash": content_hash(value)})
    for corpus in actuarial_corpora or []:
        if isinstance(corpus, dict):
            records.append({"type": "actuarial-corpus", "id": _source_id(corpus), "schema": corpus.get("schema"), "hash": content_hash(corpus)})
    return records


def _source_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_count": len(records),
        "source_hash": content_hash(records),
        "schemas": sorted({str(record.get("schema")) for record in records if record.get("schema")}),
        "required_types": sorted(record["type"] for record in records),
    }


def _source_id(value: dict[str, Any]) -> Any:
    for key_name in ("quote_id", "product_id", "corpus_id", "pack_id", "consent_id"):
        if value.get(key_name):
            return value.get(key_name)
    if isinstance(value.get("consent"), dict) and value["consent"].get("consent_id"):
        return value["consent"]["consent_id"]
    return value.get("schema")


def _verify_source(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner service source must be an object")
        return
    if not isinstance(value.get("source_count"), int) or value.get("source_count") < 2:
        errors.append("insurer partner service source.source_count must be an integer >= 2")
    if not value.get("source_hash"):
        errors.append("insurer partner service source.source_hash is required")
    required = value.get("required_types")
    if not isinstance(required, list):
        errors.append("insurer partner service source.required_types must be a list")
    else:
        for item in ("insurer-risk-telemetry", "underwriting-quote"):
            if item not in required:
                errors.append(f"insurer partner service source.required_types must include {item}")


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner service service must be an object")
        return
    for field in (
        "service_ref",
        "version",
        "service_kind",
        "endpoint_url",
        "partner_api_endpoint",
        "service_image",
        "service_image_digest",
        "service_binary_hash",
        "frontend_bundle_ref",
        "frontend_bundle_hash",
        "api_ref",
        "queue_ref",
        "policy_system_ref",
    ):
        if not value.get(field):
            errors.append(f"insurer partner service service.{field} is required")
    if value.get("service_kind") not in INSURER_PARTNER_KINDS:
        errors.append("insurer partner service service.service_kind is unsupported")
    for field in ("endpoint_url", "partner_api_endpoint"):
        parsed = urlparse(str(value.get(field) or ""))
        if parsed.scheme != "https" or not parsed.netloc:
            errors.append(f"insurer partner service service.{field} must use HTTPS")
    for field in ("service_image_digest", "service_binary_hash", "frontend_bundle_hash"):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"insurer partner service service.{field} must be a sha256 reference")
    replicas_min = value.get("replicas_min")
    replicas_max = value.get("replicas_max")
    if not isinstance(replicas_min, int) or replicas_min < 2:
        errors.append("insurer partner service service.replicas_min must be an integer >= 2")
    if not isinstance(replicas_max, int) or not isinstance(replicas_min, int) or replicas_max < replicas_min:
        errors.append("insurer partner service service.replicas_max must be >= replicas_min")
    if not isinstance(value.get("availability_zones"), list) or len(value.get("availability_zones")) < 2:
        errors.append("insurer partner service service.availability_zones must include at least two zones")


def _verify_partner(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner service partner must be an object")
        return
    for field in ("underwriter", "quote_id", "quote_ref", "quote_product", "partner_contract_ref", "policy_system_ref"):
        if not value.get(field):
            errors.append(f"insurer partner service partner.{field} is required")


def _verify_risk_transfer(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner service risk_transfer must be an object")
        return
    for field in ("telemetry_hash", "telemetry_schema", "consent_id", "pack_id", "contract_id", "risk_tier", "gate_outcome"):
        if not value.get(field):
            errors.append(f"insurer partner service risk_transfer.{field} is required")
    if value.get("telemetry_schema") != INSURER_TELEMETRY_SCHEMA:
        errors.append(f"unsupported risk telemetry schema: {value.get('telemetry_schema')}")
    if value.get("consent_active") is not True:
        errors.append("insurer partner service risk_transfer.consent_active must be true")
    try:
        risk_score = float(value.get("risk_score"))
        if risk_score < 0 or risk_score > 100:
            errors.append("insurer partner service risk_transfer.risk_score must be between 0 and 100")
    except (TypeError, ValueError):
        errors.append("insurer partner service risk_transfer.risk_score must be numeric")
    for field in ("quoted_premium_usd", "discount_percent", "coverage_limit_usd"):
        try:
            amount = float(value.get(field))
            if amount < 0:
                errors.append(f"insurer partner service risk_transfer.{field} must be non-negative")
        except (TypeError, ValueError):
            errors.append(f"insurer partner service risk_transfer.{field} must be numeric")


def _verify_required_object(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"insurer partner service {name} must be an object")
        return
    for field, child in value.items():
        if not child:
            errors.append(f"insurer partner service {name}.{field} is required")


def _verify_observability(value: Any, attested: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner service observability must be an object")
        return
    for field in ("audit_log_ref", "audit_log_root", "access_log_ref", "access_log_root", "delivery_log_ref", "delivery_log_root", "metrics_ref", "alert_policy_ref", "retention_until"):
        if not value.get(field):
            errors.append(f"insurer partner service observability.{field} is required")
    for field in ("audit_log_root", "access_log_root", "delivery_log_root"):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"insurer partner service observability.{field} must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("insurer partner service observability.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"insurer partner service observability.retention_until invalid: {exc}")


def _verify_actor(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("insurer partner service operation_actor must be an object")
        return
    if not value.get("actor_ref"):
        errors.append("insurer partner service operation_actor.actor_ref is required")
    _verify_redacted_ref(value.get("credential"), "insurer partner service operation_actor.credential", errors)
    _verify_redacted_ref(value.get("partner_credential"), "insurer partner service operation_actor.partner_credential", errors)


def _verify_telemetry(telemetry: dict[str, Any], errors: list[str]) -> None:
    if telemetry.get("schema") != INSURER_TELEMETRY_SCHEMA:
        errors.append(f"unsupported insurer telemetry schema: {telemetry.get('schema')}")
    if telemetry.get("consent", {}).get("status", {}).get("active") is not True:
        errors.append("insurer telemetry consent is not active")
    if not telemetry.get("pack_id"):
        errors.append("insurer telemetry missing pack_id")
    if not telemetry.get("contract_id"):
        errors.append("insurer telemetry missing contract_id")


def _verify_risk_transfer_matches_source(value: Any, telemetry: dict[str, Any], quote: dict[str, Any] | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        return
    expected = {
        "telemetry_hash": content_hash(telemetry),
        "telemetry_schema": telemetry.get("schema"),
        "consent_id": telemetry.get("consent", {}).get("consent_id"),
        "consent_active": telemetry.get("consent", {}).get("status", {}).get("active"),
        "pack_id": telemetry.get("pack_id"),
        "contract_id": telemetry.get("contract_id"),
        "risk_score": telemetry.get("risk_score"),
        "risk_tier": telemetry.get("risk_tier"),
        "gate_outcome": telemetry.get("gate_outcome"),
    }
    if isinstance(quote, dict):
        expected.update(
            {
                "quoted_premium_usd": quote.get("quote", {}).get("quoted_premium_usd"),
                "discount_percent": quote.get("quote", {}).get("discount_percent"),
                "coverage_limit_usd": quote.get("quote", {}).get("coverage_limit_usd"),
            }
        )
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            errors.append(f"insurer partner service risk_transfer.{field} does not match source evidence")


def _verify_partner_matches_quote(value: Any, quote: dict[str, Any], errors: list[str]) -> None:
    if not isinstance(value, dict):
        return
    expected = {
        "underwriter": quote.get("underwriter", {}).get("name"),
        "quote_id": quote.get("quote_id"),
        "quote_ref": quote.get("quote", {}).get("quote_ref"),
        "quote_product": quote.get("quote", {}).get("product"),
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            errors.append(f"insurer partner service partner.{field} does not match underwriting quote source")


def _controls(
    service: dict[str, Any],
    partner: dict[str, Any],
    risk_transfer: dict[str, Any],
    security: dict[str, Any],
    observability: dict[str, Any],
) -> list[dict[str, str]]:
    return [
        {"id": "insurer-service-identity", "status": "service-attested" if service.get("service_image_digest") and service.get("service_binary_hash") else "planned-production", "description": "Insurer partner service image, binary hash, endpoint, replica floor, and multi-zone evidence are bound."},
        {"id": "insurer-partner-api-binding", "status": "service-attested" if service.get("partner_api_endpoint") and partner.get("partner_contract_ref") else "planned-production", "description": "Partner API endpoint, partner contract, and policy-system references are bound."},
        {"id": "consented-risk-telemetry-binding", "status": "service-attested" if risk_transfer.get("consent_active") and risk_transfer.get("telemetry_hash") else "planned-production", "description": "Active consented insurer telemetry and canonical telemetry hash are bound."},
        {"id": "underwriting-quote-binding", "status": "service-attested" if partner.get("quote_id") and risk_transfer.get("quoted_premium_usd") is not None else "planned-production", "description": "Signed underwriting quote, quoted premium, discount, and coverage terms are bound."},
        {"id": "partner-auth-data-minimization", "status": "service-attested" if security.get("partner_auth_policy_ref") and security.get("consent_policy_ref") and security.get("data_minimization_policy_ref") else "planned-production", "description": "Partner authentication, consent scope, data minimization, PII redaction, and RBAC controls are bound."},
        {"id": "partner-delivery-observability", "status": "service-attested" if observability.get("delivery_log_root") and observability.get("audit_log_root") else "planned-production", "description": "Delivery log root, audit root, access root, metrics, alerting, and retention evidence are bound."},
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
                    errors.append(f"insurer partner service secret-like field must be redacted reference: {child_path}")
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
