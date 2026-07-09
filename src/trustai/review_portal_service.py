from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .regulator import verify_regulator_disclosure
from .regulator_acceptance import verify_regulator_acceptance
from .supervised_access import verify_supervised_access_receipt
from .verifier import verify_proof_pack

REVIEW_PORTAL_SERVICE_SCHEMA = "trustai.review-portal-service-attestation/0.1"
REVIEW_PORTAL_SERVICE_ENTRY_TYPE = "review_portal.service_attested"
REVIEW_PORTAL_SERVICE_MODES = {"local-reference", "portal-service-attested", "production-design"}
REVIEW_PORTAL_KINDS = {"auditor", "regulator", "third-party-review"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ReviewPortalServiceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_review_portal_service_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("review portal service attestation must contain an object")
    return value


def write_review_portal_service_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_review_portal_service_attestation(
    supervised_access_receipt: dict[str, Any],
    *,
    proof_pack: dict[str, Any] | None = None,
    proof_pack_path: str | Path | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    disclosure_path: str | Path | None = None,
    view_path: str | Path | None = None,
    frontend_bundle_path: str | Path | None = None,
    regulator_acceptance: dict[str, Any] | None = None,
    eu_ai_act_document: dict[str, Any] | None = None,
    mode: str = "portal-service-attested",
    environment: str = "local",
    portal_kind: str = "regulator",
    service_ref: str,
    service_version: str,
    endpoint_url: str,
    service_image: str,
    service_image_digest: str,
    service_binary_hash: str,
    frontend_bundle_ref: str,
    frontend_bundle_hash: str,
    api_ref: str,
    session_store_ref: str,
    auth_provider_ref: str,
    auth_policy_ref: str,
    rbac_policy_ref: str,
    session_policy_ref: str,
    selective_disclosure_policy_ref: str,
    tenant_isolation_ref: str,
    rate_limit_policy_ref: str,
    network_policy_ref: str,
    egress_policy_ref: str,
    content_security_policy_ref: str,
    encryption_key_ref: str,
    replicas_min: int,
    replicas_max: int,
    availability_zones: list[str] | None,
    audit_log_ref: str,
    audit_log_root: str,
    access_log_ref: str,
    access_log_root: str,
    metrics_ref: str,
    alert_policy_ref: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in REVIEW_PORTAL_SERVICE_MODES:
        raise ValueError(f"mode must be one of {sorted(REVIEW_PORTAL_SERVICE_MODES)}")
    if portal_kind not in REVIEW_PORTAL_KINDS:
        raise ValueError(f"portal_kind must be one of {sorted(REVIEW_PORTAL_KINDS)}")

    access_result = verify_supervised_access_receipt(
        supervised_access_receipt,
        proof_pack=proof_pack,
        proof_pack_path=proof_pack_path,
        disclosure=regulator_disclosure,
        disclosure_path=disclosure_path,
        view_path=view_path,
        key=key,
    )
    if not access_result.ok:
        raise ValueError("invalid supervised access receipt: " + "; ".join(access_result.errors))

    if regulator_acceptance is not None:
        acceptance_result = verify_regulator_acceptance(
            regulator_acceptance,
            proof_pack=proof_pack,
            regulator_disclosure=regulator_disclosure,
            eu_ai_act_document=eu_ai_act_document,
            supervised_access_receipt=supervised_access_receipt,
            supervised_view_path=view_path,
            key=key,
        )
        if not acceptance_result.ok:
            raise ValueError("invalid regulator acceptance: " + "; ".join(acceptance_result.errors))

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
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "frontend_bundle_ref": frontend_bundle_ref,
        "frontend_bundle_hash": frontend_bundle_hash,
        "api_ref": api_ref,
        "session_store_ref": session_store_ref,
        "auth_provider_ref": auth_provider_ref,
        "auth_policy_ref": auth_policy_ref,
        "rbac_policy_ref": rbac_policy_ref,
        "session_policy_ref": session_policy_ref,
        "selective_disclosure_policy_ref": selective_disclosure_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "content_security_policy_ref": content_security_policy_ref,
        "encryption_key_ref": encryption_key_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "access_log_ref": access_log_ref,
        "access_log_root": access_log_root,
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
    }.items():
        _require_text(value, field)

    source_artifacts = _source_artifacts(
        supervised_access_receipt=supervised_access_receipt,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        regulator_acceptance=regulator_acceptance,
        eu_ai_act_document=eu_ai_act_document,
    )
    if view_path is not None:
        source_artifacts.append(_view_artifact(view_path))
    frontend_bundle_artifact = None
    if frontend_bundle_path is not None:
        frontend_bundle_artifact = _frontend_bundle_artifact(frontend_bundle_path)
        if _normalize_sha256_ref(frontend_bundle_hash) != frontend_bundle_artifact["hash"]:
            raise ValueError("frontend_bundle_hash does not match supplied frontend bundle")
        source_artifacts.append(frontend_bundle_artifact)

    audience = supervised_access_receipt.get("audience", {}) if isinstance(supervised_access_receipt, dict) else {}
    reviewer = supervised_access_receipt.get("reviewer", {}) if isinstance(supervised_access_receipt, dict) else {}
    service = {
        "service_ref": service_ref,
        "version": service_version,
        "portal_kind": portal_kind,
        "endpoint_url": endpoint_url,
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "frontend_bundle_ref": frontend_bundle_ref,
        "frontend_bundle_hash": frontend_bundle_hash,
        "frontend_bundle_artifact_hash": frontend_bundle_artifact["hash"] if frontend_bundle_artifact else None,
        "api_ref": api_ref,
        "replicas_min": replicas_min,
        "replicas_max": replicas_max,
        "availability_zones": sorted(availability_zones or []),
    }
    access = {
        "supervised_access_receipt_id": supervised_access_receipt.get("receipt_id"),
        "session_id": supervised_access_receipt.get("session_id"),
        "audience_type": audience.get("type"),
        "audience_purpose": audience.get("purpose"),
        "reviewer_subject_ref": reviewer.get("subject_ref"),
        "reviewer_organization": reviewer.get("organization"),
        "reviewer_role": reviewer.get("role"),
        "artifact_count": len(supervised_access_receipt.get("artifacts", [])),
        "source_view_path": str(view_path) if view_path is not None else None,
    }
    security = {
        "auth_provider_ref": auth_provider_ref,
        "auth_policy_ref": auth_policy_ref,
        "rbac_policy_ref": rbac_policy_ref,
        "session_policy_ref": session_policy_ref,
        "selective_disclosure_policy_ref": selective_disclosure_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "content_security_policy_ref": content_security_policy_ref,
        "encryption_key_ref": encryption_key_ref,
    }
    observability = {
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "access_log_ref": access_log_ref,
        "access_log_root": access_log_root,
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
        "retention_until": retention_until,
    }
    operation_actor = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    body: dict[str, Any] = {
        "schema": REVIEW_PORTAL_SERVICE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": _source_summary(source_artifacts),
        "service": service,
        "access": access,
        "security": security,
        "observability": observability,
        "operation_actor": operation_actor,
        "source_artifacts": source_artifacts,
        "controls": _controls(service, access, security, observability),
        "limitations": [
            "This attestation binds supervised-access review evidence to hosted portal service hardening evidence.",
            "It records portal image and frontend bundle hashes, endpoint, auth, RBAC, session, selective-disclosure, network, audit, access-log, metrics, alerting, actor, and redacted credential evidence.",
            "It stores redacted credential references and artifact hashes, not raw portal credentials, user sessions, or disclosed private data.",
            "Production deployments should replace local/static view evidence with live portal sessions, identity-provider authentication events, immutable access logs, and hosted regulator or auditor UI operations.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "review_portal_service": body}, key)],
    }


def verify_review_portal_service_attestation(
    attestation: dict[str, Any],
    supervised_access_receipt: dict[str, Any] | None = None,
    *,
    proof_pack: dict[str, Any] | None = None,
    proof_pack_path: str | Path | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    disclosure_path: str | Path | None = None,
    view_path: str | Path | None = None,
    frontend_bundle_path: str | Path | None = None,
    regulator_acceptance: dict[str, Any] | None = None,
    eu_ai_act_document: dict[str, Any] | None = None,
    key: str | None = None,
) -> ReviewPortalServiceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != REVIEW_PORTAL_SERVICE_SCHEMA:
        errors.append(f"unsupported review portal service attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical review portal service attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("review portal service attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "review_portal_service": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("review portal service attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"review portal service attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in REVIEW_PORTAL_SERVICE_MODES:
        errors.append("review portal service mode is unsupported")
    elif mode != "portal-service-attested":
        warnings.append(f"review portal service mode is {mode}; live hosted portal operation is not fully claimed")

    _verify_source(attestation.get("source"), errors)
    _verify_service(attestation.get("service"), errors)
    _verify_access(attestation.get("access"), errors)
    _verify_required_object(attestation.get("security"), "security", errors)
    _verify_observability(attestation.get("observability"), attested, errors)
    _verify_actor(attestation.get("operation_actor"), errors)
    _check_no_secret_values(attestation, errors)

    supplied_records = _source_artifacts(
        supervised_access_receipt=supervised_access_receipt,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        regulator_acceptance=regulator_acceptance,
        eu_ai_act_document=eu_ai_act_document,
    )
    if view_path is not None:
        supplied_records.append(_view_artifact(view_path))
    if frontend_bundle_path is not None:
        try:
            frontend_bundle_artifact = _frontend_bundle_artifact(frontend_bundle_path)
        except OSError as exc:
            errors.append(f"review portal service frontend bundle source could not be read: {exc}")
        else:
            supplied_records.append(frontend_bundle_artifact)
            service = attestation.get("service")
            expected_hash = service.get("frontend_bundle_hash") if isinstance(service, dict) else None
            if _normalize_sha256_ref(str(expected_hash or "")) != frontend_bundle_artifact["hash"]:
                errors.append("review portal service service.frontend_bundle_hash does not match supplied frontend bundle")
            artifact_hash = service.get("frontend_bundle_artifact_hash") if isinstance(service, dict) else None
            if artifact_hash is not None and artifact_hash != frontend_bundle_artifact["hash"]:
                errors.append("review portal service service.frontend_bundle_artifact_hash does not match supplied frontend bundle")
    else:
        warnings.append("frontend bundle source was not supplied; bundle hash was not replayed")
    source_artifacts = attestation.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("review portal service source_artifacts are required")
    elif supplied_records:
        if source_artifacts != supplied_records:
            errors.append("review portal service source_artifacts do not match supplied source artifacts")
        if attestation.get("source") != _source_summary(supplied_records):
            errors.append("review portal service source summary does not match supplied source artifacts")

    if supervised_access_receipt is not None:
        access_result = verify_supervised_access_receipt(
            supervised_access_receipt,
            proof_pack=proof_pack,
            proof_pack_path=proof_pack_path,
            disclosure=regulator_disclosure,
            disclosure_path=disclosure_path,
            view_path=view_path,
            key=key,
        )
        errors.extend(f"supervised access source: {error}" for error in access_result.errors)
        warnings.extend(f"supervised access source: {warning}" for warning in access_result.warnings)
        _verify_access_matches_source(attestation.get("access"), supervised_access_receipt, errors)
    else:
        warnings.append("supervised access source was not supplied; portal source hashes were not replayed")

    if proof_pack is not None:
        pack_result = verify_proof_pack(proof_pack, key=key)
        errors.extend(f"proof pack source: {error}" for error in pack_result.errors)
        warnings.extend(f"proof pack source: {warning}" for warning in pack_result.warnings)
    if regulator_disclosure is not None:
        disclosure_result = verify_regulator_disclosure(regulator_disclosure, key=key)
        errors.extend(f"regulator disclosure source: {error}" for error in disclosure_result.errors)
        warnings.extend(f"regulator disclosure source: {warning}" for warning in disclosure_result.warnings)
    if regulator_acceptance is not None:
        acceptance_result = verify_regulator_acceptance(
            regulator_acceptance,
            proof_pack=proof_pack,
            regulator_disclosure=regulator_disclosure,
            eu_ai_act_document=eu_ai_act_document,
            supervised_access_receipt=supervised_access_receipt,
            supervised_view_path=view_path,
            key=key,
        )
        errors.extend(f"regulator acceptance source: {error}" for error in acceptance_result.errors)
        warnings.extend(f"regulator acceptance source: {warning}" for warning in acceptance_result.warnings)

    return ReviewPortalServiceVerification(ok=not errors, errors=errors, warnings=warnings)


def append_review_portal_service_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    supervised_access_receipt: dict[str, Any] | None = None,
    *,
    proof_pack: dict[str, Any] | None = None,
    proof_pack_path: str | Path | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    disclosure_path: str | Path | None = None,
    view_path: str | Path | None = None,
    frontend_bundle_path: str | Path | None = None,
    regulator_acceptance: dict[str, Any] | None = None,
    eu_ai_act_document: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_review_portal_service_attestation(
        attestation,
        supervised_access_receipt,
        proof_pack=proof_pack,
        proof_pack_path=proof_pack_path,
        regulator_disclosure=regulator_disclosure,
        disclosure_path=disclosure_path,
        view_path=view_path,
        frontend_bundle_path=frontend_bundle_path,
        regulator_acceptance=regulator_acceptance,
        eu_ai_act_document=eu_ai_act_document,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid review portal service attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "service": attestation.get("service"),
        "access": attestation.get("access"),
        "source": attestation.get("source"),
        "controls": attestation.get("controls", []),
        "control_status_summary": _status_summary(attestation.get("controls", [])),
        "limitations": attestation.get("limitations", []),
    }
    return chain.append(REVIEW_PORTAL_SERVICE_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _source_artifacts(**sources: dict[str, Any] | None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name, value in sources.items():
        if isinstance(value, dict):
            records.append({"type": name.replace("_", "-"), "id": _source_id(value), "schema": value.get("schema"), "hash": content_hash(value)})
    return records


def _view_artifact(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    data = source.read_bytes()
    return {
        "type": "static-view",
        "id": str(path),
        "schema": "text/html",
        "hash": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _frontend_bundle_artifact(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    data = source.read_bytes()
    suffix = source.suffix.lower()
    if suffix == ".js":
        schema = "application/javascript"
    elif suffix == ".css":
        schema = "text/css"
    elif suffix in {".html", ".htm"}:
        schema = "text/html"
    else:
        schema = "application/octet-stream"
    return {
        "type": "frontend-bundle",
        "id": str(path),
        "schema": schema,
        "hash": _sha256_ref(data),
        "size_bytes": len(data),
    }


def _source_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_count": len(records),
        "source_hash": content_hash(records),
        "schemas": sorted({str(record.get("schema")) for record in records if record.get("schema")}),
        "required_types": sorted(record["type"] for record in records),
    }


def _source_id(value: dict[str, Any]) -> Any:
    for key_name in ("receipt_id", "pack_id", "disclosure_id", "acceptance_id", "document_id"):
        if value.get(key_name):
            return value.get(key_name)
    return value.get("schema")


def _verify_source(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("review portal service source must be an object")
        return
    if not isinstance(value.get("source_count"), int) or value.get("source_count") < 1:
        errors.append("review portal service source.source_count must be an integer >= 1")
    if not value.get("source_hash"):
        errors.append("review portal service source.source_hash is required")
    required = value.get("required_types")
    if not isinstance(required, list) or "supervised-access-receipt" not in required:
        errors.append("review portal service source.required_types must include supervised-access-receipt")


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("review portal service service must be an object")
        return
    for field in (
        "service_ref",
        "version",
        "portal_kind",
        "endpoint_url",
        "service_image",
        "service_image_digest",
        "service_binary_hash",
        "frontend_bundle_ref",
        "frontend_bundle_hash",
        "api_ref",
    ):
        if not value.get(field):
            errors.append(f"review portal service service.{field} is required")
    if value.get("portal_kind") not in REVIEW_PORTAL_KINDS:
        errors.append("review portal service service.portal_kind is unsupported")
    parsed = urlparse(str(value.get("endpoint_url") or ""))
    if parsed.scheme != "https" or not parsed.netloc:
        errors.append("review portal service service.endpoint_url must use HTTPS")
    for field in ("service_image_digest", "service_binary_hash", "frontend_bundle_hash"):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"review portal service service.{field} must be a sha256 reference")
    replicas_min = value.get("replicas_min")
    replicas_max = value.get("replicas_max")
    if not isinstance(replicas_min, int) or replicas_min < 2:
        errors.append("review portal service service.replicas_min must be an integer >= 2")
    if not isinstance(replicas_max, int) or not isinstance(replicas_min, int) or replicas_max < replicas_min:
        errors.append("review portal service service.replicas_max must be >= replicas_min")
    if not isinstance(value.get("availability_zones"), list) or len(value.get("availability_zones")) < 2:
        errors.append("review portal service service.availability_zones must include at least two zones")


def _verify_access(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("review portal service access must be an object")
        return
    for field in ("supervised_access_receipt_id", "session_id", "audience_type", "reviewer_subject_ref", "reviewer_organization", "reviewer_role"):
        if not value.get(field):
            errors.append(f"review portal service access.{field} is required")
    if not isinstance(value.get("artifact_count"), int) or value.get("artifact_count") < 1:
        errors.append("review portal service access.artifact_count must be an integer >= 1")


def _verify_access_matches_source(value: Any, receipt: dict[str, Any], errors: list[str]) -> None:
    if not isinstance(value, dict):
        return
    audience = receipt.get("audience", {}) if isinstance(receipt, dict) else {}
    reviewer = receipt.get("reviewer", {}) if isinstance(receipt, dict) else {}
    expected = {
        "supervised_access_receipt_id": receipt.get("receipt_id"),
        "session_id": receipt.get("session_id"),
        "audience_type": audience.get("type"),
        "audience_purpose": audience.get("purpose"),
        "reviewer_subject_ref": reviewer.get("subject_ref"),
        "reviewer_organization": reviewer.get("organization"),
        "reviewer_role": reviewer.get("role"),
        "artifact_count": len(receipt.get("artifacts", [])),
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            errors.append(f"review portal service access.{field} does not match supervised access source")


def _verify_required_object(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"review portal service {name} must be an object")
        return
    for field, child in value.items():
        if not child:
            errors.append(f"review portal service {name}.{field} is required")


def _verify_observability(value: Any, attested: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("review portal service observability must be an object")
        return
    for field in ("audit_log_ref", "audit_log_root", "access_log_ref", "access_log_root", "metrics_ref", "alert_policy_ref", "retention_until"):
        if not value.get(field):
            errors.append(f"review portal service observability.{field} is required")
    for field in ("audit_log_root", "access_log_root"):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"review portal service observability.{field} must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("review portal service observability.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"review portal service observability.retention_until invalid: {exc}")


def _verify_actor(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("review portal service operation_actor must be an object")
        return
    if not value.get("actor_ref"):
        errors.append("review portal service operation_actor.actor_ref is required")
    _verify_redacted_ref(value.get("credential"), "review portal service operation_actor.credential", errors)


def _controls(service: dict[str, Any], access: dict[str, Any], security: dict[str, Any], observability: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"id": "review-portal-service-identity", "status": "service-attested" if service.get("service_image_digest") and service.get("service_binary_hash") else "planned-production", "description": "Portal service image, binary hash, endpoint, replica floor, and multi-zone evidence are bound."},
        {"id": "review-portal-frontend-integrity", "status": "service-attested" if service.get("frontend_bundle_hash") and service.get("api_ref") else "planned-production", "description": "Portal frontend bundle hash and API reference are bound."},
        {"id": "review-portal-supervised-access-binding", "status": "service-attested" if access.get("supervised_access_receipt_id") and access.get("session_id") else "planned-production", "description": "Portal session is bound to signed supervised-access receipt evidence."},
        {"id": "review-portal-auth-session-rbac", "status": "service-attested" if security.get("auth_provider_ref") and security.get("session_policy_ref") and security.get("rbac_policy_ref") else "planned-production", "description": "Auth provider, session policy, and RBAC controls are bound."},
        {"id": "review-portal-selective-disclosure-tenant-isolation", "status": "service-attested" if security.get("selective_disclosure_policy_ref") and security.get("tenant_isolation_ref") else "planned-production", "description": "Selective disclosure and tenant isolation controls are bound."},
        {"id": "review-portal-audit-access-retention", "status": "service-attested" if observability.get("audit_log_root") and observability.get("access_log_root") else "planned-production", "description": "Portal audit-log root, access-log root, metrics, alerting, and retention evidence are bound."},
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
                    errors.append(f"review portal service secret-like field must be redacted reference: {child_path}")
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


def _sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _normalize_sha256_ref(value: str) -> str:
    if value.startswith("sha256:"):
        return value
    return "sha256:" + value
