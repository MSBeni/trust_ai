from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .policy_backend_enforcement import POLICY_BACKEND_ENGINES, verify_policy_backend_enforcement_receipt

POLICY_BACKEND_SERVICE_SCHEMA = "trustai.policy-backend-service-attestation/0.1"
POLICY_BACKEND_SERVICE_ENTRY_TYPE = "policy_backend.service_attested"
POLICY_BACKEND_SERVICE_MODES = {"local-reference", "backend-service-attested", "production-design"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class PolicyBackendServiceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_policy_backend_service_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("policy backend service attestation must contain an object")
    return value


def write_policy_backend_service_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_policy_backend_service_attestation(
    enforcement_receipt: dict[str, Any],
    *,
    policy_pack: dict[str, Any] | None = None,
    action: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    policy_export: dict[str, Any] | None = None,
    policy_engine_receipt: dict[str, Any] | None = None,
    mode: str = "backend-service-attested",
    environment: str = "local",
    service_ref: str,
    service_version: str,
    engine: str,
    backend_ref: str,
    endpoint_url: str,
    service_image: str,
    service_image_digest: str,
    service_binary_hash: str,
    bundle_ref: str | None = None,
    bundle_hash: str | None = None,
    replicas_min: int,
    replicas_max: int,
    availability_zones: list[str] | None = None,
    mtls_policy_ref: str,
    auth_policy_ref: str,
    tenant_isolation_ref: str,
    policy_sync_ref: str,
    admission_policy_ref: str,
    rate_limit_policy_ref: str,
    circuit_breaker_ref: str,
    cache_store_ref: str,
    network_policy_ref: str,
    egress_policy_ref: str,
    decision_log_ref: str,
    decision_log_root: str,
    decision_log_retention_days: int,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in POLICY_BACKEND_SERVICE_MODES:
        raise ValueError(f"mode must be one of {sorted(POLICY_BACKEND_SERVICE_MODES)}")
    if engine not in POLICY_BACKEND_ENGINES:
        raise ValueError(f"engine must be one of {sorted(POLICY_BACKEND_ENGINES)}")

    enforcement_result = verify_policy_backend_enforcement_receipt(
        enforcement_receipt,
        policy_pack,
        action,
        proof_pack,
        decision,
        policy_export=policy_export,
        policy_engine_receipt=policy_engine_receipt,
        key=key,
    )
    if not enforcement_result.ok:
        raise ValueError("invalid policy backend enforcement receipt: " + "; ".join(enforcement_result.errors))

    backend = enforcement_receipt.get("backend", {}) if isinstance(enforcement_receipt, dict) else {}
    bundle_ref = bundle_ref or backend.get("bundle_ref")
    bundle_hash = bundle_hash or backend.get("bundle_hash")

    timestamp = attested_at or utc_now()
    parse_rfc3339(timestamp)
    retention = parse_rfc3339(retention_until)
    if retention <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after attested_at")

    for field, value in {
        "service_ref": service_ref,
        "service_version": service_version,
        "engine": engine,
        "backend_ref": backend_ref,
        "endpoint_url": endpoint_url,
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "bundle_ref": bundle_ref,
        "bundle_hash": bundle_hash,
        "mtls_policy_ref": mtls_policy_ref,
        "auth_policy_ref": auth_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "policy_sync_ref": policy_sync_ref,
        "admission_policy_ref": admission_policy_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "circuit_breaker_ref": circuit_breaker_ref,
        "cache_store_ref": cache_store_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "decision_log_ref": decision_log_ref,
        "decision_log_root": decision_log_root,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
    }.items():
        _require_text(value, field)

    service = {
        "service_ref": service_ref,
        "version": service_version,
        "engine": engine,
        "backend_ref": backend_ref,
        "endpoint_url": endpoint_url,
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "bundle_ref": bundle_ref,
        "bundle_hash": bundle_hash,
        "replicas_min": replicas_min,
        "replicas_max": replicas_max,
        "availability_zones": sorted(availability_zones or []),
    }
    security = {
        "mtls_policy_ref": mtls_policy_ref,
        "auth_policy_ref": auth_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "policy_sync_ref": policy_sync_ref,
        "admission_policy_ref": admission_policy_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "circuit_breaker_ref": circuit_breaker_ref,
        "cache_store_ref": cache_store_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
    }
    operation = {
        "decision_log_ref": decision_log_ref,
        "decision_log_root": decision_log_root,
        "decision_log_retention_days": decision_log_retention_days,
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    audit_log = {
        "audit_log_ref": audit_log_ref,
        "root": audit_log_root,
        "retention_until": retention_until,
    }
    body: dict[str, Any] = {
        "schema": POLICY_BACKEND_SERVICE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": _source_record(enforcement_receipt, policy_engine_receipt),
        "enforcement": _enforcement_record(enforcement_receipt),
        "service": service,
        "security": security,
        "operation": operation,
        "audit_log": audit_log,
        "source_artifacts": _source_artifacts(enforcement_receipt, policy_export, policy_engine_receipt),
        "controls": _controls(service, security, operation, audit_log),
        "limitations": [
            "This attestation binds hosted OPA/Cedar enforcement receipts to operated policy backend service hardening evidence.",
            "It records service image digests, bundle hashes, mTLS/authn/z, tenant isolation, policy sync, rate limits, decision logging, cache, network policy, audit roots, actor, and redacted credential evidence.",
            "It stores redacted credential references and hashes, not raw backend credentials or raw policy decision payloads.",
            "Production deployments should replace local references with continuously operated OPA/Cedar service, vault, KMS, logging, and monitoring evidence.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "policy_backend_service": body}, key)],
    }


def verify_policy_backend_service_attestation(
    attestation: dict[str, Any],
    enforcement_receipt: dict[str, Any] | None = None,
    *,
    policy_pack: dict[str, Any] | None = None,
    action: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    policy_export: dict[str, Any] | None = None,
    policy_engine_receipt: dict[str, Any] | None = None,
    key: str | None = None,
) -> PolicyBackendServiceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != POLICY_BACKEND_SERVICE_SCHEMA:
        errors.append(f"unsupported policy backend service attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical policy backend service attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("policy backend service attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "policy_backend_service": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("policy backend service attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"policy backend service attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in POLICY_BACKEND_SERVICE_MODES:
        errors.append("policy backend service mode is unsupported")
    elif mode != "backend-service-attested":
        warnings.append(f"policy backend service mode is {mode}; live backend operation is not fully claimed")

    _verify_source(attestation.get("source"), errors)
    _verify_enforcement(attestation.get("enforcement"), errors)
    _verify_service(attestation.get("service"), errors)
    _verify_security(attestation.get("security"), errors)
    _verify_operation(attestation.get("operation"), errors)
    _verify_audit_log(attestation.get("audit_log"), attested, errors)

    controls = attestation.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("policy backend service controls are required")

    source_artifacts = attestation.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("policy backend service source_artifacts must contain at least an enforcement receipt")

    supplied_sources = _source_artifacts(enforcement_receipt, policy_export, policy_engine_receipt)
    if supplied_sources:
        if source_artifacts != supplied_sources:
            errors.append("policy backend service source_artifacts do not match supplied source artifacts")
        expected_source = _source_record(enforcement_receipt, policy_engine_receipt)
        if attestation.get("source") != expected_source:
            errors.append("policy backend service source record does not match supplied artifacts")
    else:
        warnings.append("policy backend service source artifacts were not supplied; enforcement hash was not replayed")

    if enforcement_receipt is not None:
        enforcement_result = verify_policy_backend_enforcement_receipt(
            enforcement_receipt,
            policy_pack,
            action,
            proof_pack,
            decision,
            policy_export=policy_export,
            policy_engine_receipt=policy_engine_receipt,
            key=key,
        )
        if not enforcement_result.ok:
            errors.extend(f"policy backend enforcement invalid: {error}" for error in enforcement_result.errors)
        warnings.extend(f"policy backend enforcement: {warning}" for warning in enforcement_result.warnings)
        _check_service_matches_enforcement(attestation.get("service"), enforcement_receipt, errors)

    _check_no_secret_values(attestation, errors)
    return PolicyBackendServiceVerification(ok=not errors, errors=errors, warnings=warnings)


def append_policy_backend_service_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    enforcement_receipt: dict[str, Any] | None = None,
    *,
    policy_pack: dict[str, Any] | None = None,
    action: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    policy_export: dict[str, Any] | None = None,
    policy_engine_receipt: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_policy_backend_service_attestation(
        attestation,
        enforcement_receipt,
        policy_pack=policy_pack,
        action=action,
        proof_pack=proof_pack,
        decision=decision,
        policy_export=policy_export,
        policy_engine_receipt=policy_engine_receipt,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid policy backend service attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "source": attestation.get("source"),
        "enforcement": attestation.get("enforcement"),
        "service": attestation.get("service"),
        "security": attestation.get("security"),
        "operation": attestation.get("operation"),
        "audit_log": attestation.get("audit_log"),
        "source_artifacts": attestation.get("source_artifacts"),
        "control_summary": _status_summary(attestation.get("controls", [])),
    }
    return chain.append(POLICY_BACKEND_SERVICE_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _source_record(enforcement_receipt: dict[str, Any] | None, policy_engine_receipt: dict[str, Any] | None) -> dict[str, Any]:
    backend = enforcement_receipt.get("backend", {}) if isinstance(enforcement_receipt, dict) else {}
    return {
        "enforcement_id": enforcement_receipt.get("enforcement_id") if isinstance(enforcement_receipt, dict) else None,
        "enforcement_hash": content_hash(enforcement_receipt) if isinstance(enforcement_receipt, dict) else None,
        "enforcement_mode": enforcement_receipt.get("mode") if isinstance(enforcement_receipt, dict) else None,
        "enforcement_environment": enforcement_receipt.get("environment") if isinstance(enforcement_receipt, dict) else None,
        "engine": backend.get("engine") if isinstance(backend, dict) else None,
        "backend_ref": backend.get("backend_ref") if isinstance(backend, dict) else None,
        "endpoint_url": backend.get("endpoint_url") if isinstance(backend, dict) else None,
        "bundle_ref": backend.get("bundle_ref") if isinstance(backend, dict) else None,
        "bundle_hash": backend.get("bundle_hash") if isinstance(backend, dict) else None,
        "policy_engine_receipt_id": policy_engine_receipt.get("receipt_id") if isinstance(policy_engine_receipt, dict) else None,
        "policy_engine_receipt_hash": content_hash(policy_engine_receipt) if isinstance(policy_engine_receipt, dict) else None,
    }


def _enforcement_record(enforcement_receipt: dict[str, Any]) -> dict[str, Any]:
    backend = enforcement_receipt.get("backend", {}) if isinstance(enforcement_receipt.get("backend"), dict) else {}
    decision = enforcement_receipt.get("decision", {}) if isinstance(enforcement_receipt.get("decision"), dict) else {}
    return {
        "enforcement_id": enforcement_receipt.get("enforcement_id"),
        "enforcement_hash": content_hash(enforcement_receipt),
        "mode": enforcement_receipt.get("mode"),
        "environment": enforcement_receipt.get("environment"),
        "enforced_at": enforcement_receipt.get("enforced_at"),
        "engine": backend.get("engine"),
        "backend_ref": backend.get("backend_ref"),
        "endpoint_url": backend.get("endpoint_url"),
        "bundle_ref": backend.get("bundle_ref"),
        "bundle_hash": backend.get("bundle_hash"),
        "decision_hash": decision.get("hash"),
        "decision_outcome": decision.get("outcome"),
        "decision_passed": decision.get("passed"),
    }


def _source_artifacts(
    enforcement_receipt: dict[str, Any] | None,
    policy_export: dict[str, Any] | None,
    policy_engine_receipt: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    if isinstance(enforcement_receipt, dict):
        artifacts.append(
            {
                "type": "policy-backend-enforcement",
                "id": enforcement_receipt.get("enforcement_id"),
                "schema": enforcement_receipt.get("schema"),
                "hash": content_hash(enforcement_receipt),
            }
        )
    if isinstance(policy_export, dict):
        artifacts.append(
            {
                "type": "policy-export",
                "id": policy_export.get("policy_pack_id"),
                "schema": policy_export.get("schema"),
                "hash": content_hash(policy_export),
            }
        )
    if isinstance(policy_engine_receipt, dict):
        artifacts.append(
            {
                "type": "policy-engine-receipt",
                "id": policy_engine_receipt.get("receipt_id"),
                "schema": policy_engine_receipt.get("schema"),
                "hash": content_hash(policy_engine_receipt),
            }
        )
    return artifacts


def _verify_source(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend service source must be an object")
        return
    for field in ("enforcement_id", "enforcement_hash", "enforcement_mode", "enforcement_environment", "engine", "backend_ref", "endpoint_url", "bundle_ref", "bundle_hash"):
        if not value.get(field):
            errors.append(f"policy backend service source.{field} is required")


def _verify_enforcement(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend service enforcement must be an object")
        return
    for field in ("enforcement_id", "enforcement_hash", "mode", "environment", "enforced_at", "engine", "backend_ref", "endpoint_url", "bundle_ref", "bundle_hash", "decision_hash"):
        if not value.get(field):
            errors.append(f"policy backend service enforcement.{field} is required")
    if value.get("engine") not in POLICY_BACKEND_ENGINES:
        errors.append("policy backend service enforcement.engine is unsupported")
    if not _is_https_url(str(value.get("endpoint_url") or "")):
        errors.append("policy backend service enforcement.endpoint_url must use HTTPS")
    for field in ("bundle_hash",):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"policy backend service enforcement.{field} must be a sha256 reference")


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend service service must be an object")
        return
    for field in ("service_ref", "version", "engine", "backend_ref", "endpoint_url", "service_image", "service_image_digest", "service_binary_hash", "bundle_ref", "bundle_hash"):
        if not value.get(field):
            errors.append(f"policy backend service service.{field} is required")
    if value.get("engine") not in POLICY_BACKEND_ENGINES:
        errors.append("policy backend service service.engine is unsupported")
    if not _is_https_url(str(value.get("endpoint_url") or "")):
        errors.append("policy backend service service.endpoint_url must use HTTPS")
    for field in ("service_image_digest", "service_binary_hash", "bundle_hash"):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"policy backend service service.{field} must be a sha256 reference")
    replicas_min = value.get("replicas_min")
    replicas_max = value.get("replicas_max")
    if not isinstance(replicas_min, int) or replicas_min < 2:
        errors.append("policy backend service service.replicas_min must be an integer >= 2")
    if not isinstance(replicas_max, int) or not isinstance(replicas_min, int) or replicas_max < replicas_min:
        errors.append("policy backend service service.replicas_max must be >= replicas_min")
    if not isinstance(value.get("availability_zones"), list) or len(value.get("availability_zones")) < 2:
        errors.append("policy backend service service.availability_zones must include at least two zones")


def _verify_security(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend service security must be an object")
        return
    for field in (
        "mtls_policy_ref",
        "auth_policy_ref",
        "tenant_isolation_ref",
        "policy_sync_ref",
        "admission_policy_ref",
        "rate_limit_policy_ref",
        "circuit_breaker_ref",
        "cache_store_ref",
        "network_policy_ref",
        "egress_policy_ref",
    ):
        if not value.get(field):
            errors.append(f"policy backend service security.{field} is required")


def _verify_operation(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend service operation must be an object")
        return
    for field in ("decision_log_ref", "decision_log_root", "actor_ref"):
        if not value.get(field):
            errors.append(f"policy backend service operation.{field} is required")
    if not _is_sha256_ref(str(value.get("decision_log_root") or "")):
        errors.append("policy backend service operation.decision_log_root must be a sha256 reference")
    if not isinstance(value.get("decision_log_retention_days"), int) or value.get("decision_log_retention_days") < 30:
        errors.append("policy backend service operation.decision_log_retention_days must be an integer >= 30")
    _verify_redacted_ref(value.get("credential"), "policy backend service operation.credential", errors)


def _verify_audit_log(value: Any, attested: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("policy backend service audit_log must be an object")
        return
    for field in ("audit_log_ref", "root", "retention_until"):
        if not value.get(field):
            errors.append(f"policy backend service audit_log.{field} is required")
    if not _is_sha256_ref(str(value.get("root") or "")):
        errors.append("policy backend service audit_log.root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("policy backend service audit_log.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"policy backend service audit_log.retention_until invalid: {exc}")


def _check_service_matches_enforcement(service: Any, enforcement_receipt: dict[str, Any], errors: list[str]) -> None:
    if not isinstance(service, dict):
        return
    backend = enforcement_receipt.get("backend", {}) if isinstance(enforcement_receipt.get("backend"), dict) else {}
    for service_field, backend_field in (
        ("engine", "engine"),
        ("backend_ref", "backend_ref"),
        ("endpoint_url", "endpoint_url"),
        ("bundle_ref", "bundle_ref"),
        ("bundle_hash", "bundle_hash"),
    ):
        if service.get(service_field) != backend.get(backend_field):
            errors.append(f"policy backend service service.{service_field} does not match enforcement backend.{backend_field}")


def _controls(service: dict[str, Any], security: dict[str, Any], operation: dict[str, Any], audit_log: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "id": "policy-backend-service-identity",
            "status": "service-attested" if service.get("service_image_digest") and service.get("bundle_hash") else "planned-production",
            "description": "OPA/Cedar service image, binary hash, endpoint, and policy bundle hash are bound.",
        },
        {
            "id": "policy-backend-ha",
            "status": "service-attested" if service.get("replicas_min", 0) >= 2 and len(service.get("availability_zones", [])) >= 2 else "planned-production",
            "description": "Replica floor and multi-zone availability evidence are bound.",
        },
        {
            "id": "policy-backend-authz",
            "status": "service-attested" if security.get("mtls_policy_ref") and security.get("auth_policy_ref") and security.get("tenant_isolation_ref") else "planned-production",
            "description": "mTLS, authorization, tenant isolation, policy sync, and admission controls are bound.",
        },
        {
            "id": "policy-backend-resilience",
            "status": "service-attested" if security.get("rate_limit_policy_ref") and security.get("circuit_breaker_ref") and security.get("cache_store_ref") else "planned-production",
            "description": "Rate limit, circuit breaker, and cache/idempotency store evidence are bound.",
        },
        {
            "id": "policy-backend-decision-log",
            "status": "service-attested" if operation.get("decision_log_ref") and operation.get("decision_log_root") else "planned-production",
            "description": "Decision log root, retention, actor, and redacted credential evidence are bound.",
        },
        {
            "id": "policy-backend-audit-retention",
            "status": "service-attested" if audit_log.get("audit_log_ref") and audit_log.get("root") else "planned-production",
            "description": "Audit log root and retention evidence are bound.",
        },
    ]


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "unknown"))
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


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
                    errors.append(f"policy backend service secret-like field must be redacted reference: {child_path}")
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


def _is_https_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)