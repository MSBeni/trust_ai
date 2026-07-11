from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .policy_backend_provider_bundle import verify_policy_backend_provider_bundle
from .policy_backend_service_bundle import verify_policy_backend_service_bundle

POLICY_BACKEND_AUTHORITY_SCHEMA = "trustai.policy-backend-production-authority-dossier/0.1"
POLICY_BACKEND_AUTHORITY_ENTRY_TYPE = "policy_backend.production_authority_recorded"
POLICY_BACKEND_AUTHORITY_MODES = {"local-dossier", "provider-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {
        "id": "opa-cedar-backend-fleet",
        "title": "Continuously operated OPA/Cedar backend fleets",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "scheduler-queue-lease",
        "title": "Production scheduler, queue, lease, checkpoint, and cursor provider exports",
        "authority_kinds": ["provider-api", "hosted-service"],
    },
    {
        "id": "decision-log-retention",
        "title": "Provider-backed decision log retention and replay windows",
        "authority_kinds": ["provider-api", "cloud-object-lock", "hosted-service"],
    },
    {
        "id": "audit-log-retention",
        "title": "Immutable audit log retention and custody",
        "authority_kinds": ["provider-api", "cloud-object-lock", "customer"],
    },
    {
        "id": "credential-custody",
        "title": "Redacted credential custody and vault access evidence",
        "authority_kinds": ["kms-hsm", "provider-api", "customer"],
    },
    {
        "id": "kms-hsm-key-control",
        "title": "KMS/HSM key control, signer policy, and denied-operation logs",
        "authority_kinds": ["kms-hsm", "provider-api"],
    },
    {
        "id": "network-mtls-authz",
        "title": "Network, mTLS, authentication, and authorization enforcement",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "tenant-isolation",
        "title": "Tenant isolation and production namespace boundaries",
        "authority_kinds": ["hosted-service", "provider-api", "customer"],
    },
    {
        "id": "policy-bundle-supply-chain",
        "title": "Policy bundle supply-chain provenance and deployment admission",
        "authority_kinds": ["ci-run", "provider-api", "hosted-service"],
    },
    {
        "id": "incident-drift-monitoring",
        "title": "Incident, drift, rate-limit, and circuit-breaker monitoring",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "provider-export-freshness",
        "title": "Provider export freshness, cursors, and replay recency",
        "authority_kinds": ["provider-api", "hosted-service"],
    },
    {
        "id": "immutable-worm-retention",
        "title": "Immutable WORM/object-lock retention for backend evidence",
        "authority_kinds": ["cloud-object-lock", "provider-api", "customer"],
    },
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]

PROVIDER_BUNDLE_BINDING_REQUIRED_FIELDS = (
    "bundle_id",
    "bundle_hash",
    "bundle_schema",
    "bundle_mode",
    "environment",
    "generated_at",
    "reviewer_ref",
    "bundle_ref",
    "provider_receipt_id",
    "provider_receipt_hash",
    "provider",
    "provider_export_hash",
    "provider_export_ref",
    "worker_operation_id",
    "worker_operation_hash",
    "service_attestation_id",
    "enforcement_id",
    "backend_ref",
    "engine",
    "endpoint_url",
    "decision_hash",
    "decision_log_root",
    "audit_log_root",
    "source_artifact_count",
    "source_artifact_sha256_root",
    "source_artifact_content_root",
    "provider_record_root_count",
    "provider_record_roots",
    "policy_engine_receipt_replayed",
)

SERVICE_BUNDLE_BINDING_REQUIRED_FIELDS = (
    "bundle_id",
    "bundle_hash",
    "bundle_schema",
    "bundle_mode",
    "environment",
    "generated_at",
    "reviewer_ref",
    "bundle_ref",
    "service_attestation_id",
    "service_attestation_hash",
    "service_ref",
    "service_version",
    "enforcement_id",
    "enforcement_hash",
    "engine",
    "backend_ref",
    "endpoint_url",
    "policy_bundle_ref",
    "policy_bundle_hash",
    "policy_pack_id",
    "policy_pack_version",
    "decision_hash",
    "decision_outcome",
    "decision_passed",
    "decision_log_root",
    "audit_log_root",
    "source_artifact_count",
    "source_artifact_sha256_root",
    "source_artifact_content_root",
    "policy_engine_receipt_replayed",
    "service_control_summary",
    "enforcement_control_summary",
)

@dataclass
class PolicyBackendAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_policy_backend_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("policy backend authority dossier must contain an object")
    return value


def write_policy_backend_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_policy_backend_authority_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 4)
    if len(parts) != 5:
        raise ValueError(
            "authority evidence must be requirement_id,authority_kind,evidence_ref,evidence_hash,description[;key=value...]"
        )
    requirement_id, authority_kind, evidence_ref, evidence_hash, description = [part.strip() for part in parts]
    description_parts = [part.strip() for part in description.split(";")]
    metadata: dict[str, Any] = {}
    allowed_metadata = {"issuer", "subject", "source_uri", "issued_at", "expires_at"}
    for token in description_parts[1:]:
        if not token:
            continue
        if "=" not in token:
            raise ValueError("authority evidence metadata must be key=value")
        key, metadata_value = [part.strip() for part in token.split("=", 1)]
        if key not in allowed_metadata:
            raise ValueError(f"unsupported authority evidence metadata key: {key}")
        metadata[key] = metadata_value
    return {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description_parts[0],
        **metadata,
    }


def build_policy_backend_authority_dossier(
    provider_bundle: dict[str, Any],
    *,
    service_bundles: list[dict[str, Any]] | None = None,
    mode: str = "provider-dossier",
    environment: str | None = None,
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in POLICY_BACKEND_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(POLICY_BACKEND_AUTHORITY_MODES)}")
    for value, field in (
        (dossier_ref, "dossier_ref"),
        (authority_ref, "authority_ref"),
        (producer_ref, "producer_ref"),
    ):
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    bundle_result = verify_policy_backend_provider_bundle(provider_bundle, key=key)
    if not bundle_result.ok:
        raise ValueError("invalid policy backend provider bundle source: " + "; ".join(bundle_result.errors))
    bundles = list(service_bundles or [])
    for bundle in bundles:
        service_result = verify_policy_backend_service_bundle(bundle, key=key)
        if not service_result.ok:
            raise ValueError("invalid policy backend service bundle source: " + "; ".join(service_result.errors))

    provider_binding = _provider_bundle_binding(provider_bundle)
    service_bundle_bindings = [_service_bundle_binding(bundle) for bundle in bundles]
    link_errors = _service_bundle_link_errors(service_bundle_bindings, provider_binding)
    if link_errors:
        raise ValueError("policy backend service bundle source linkage failed: " + "; ".join(link_errors))
    source_context = _authority_evidence_source_context(provider_binding, service_bundle_bindings)
    evidence_items = [_build_authority_evidence_item(item, source_context) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body: dict[str, Any] = {
        "schema": POLICY_BACKEND_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment or provider_bundle.get("environment") or "local",
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "provider_bundle_binding": provider_binding,
        "service_bundle_bindings": service_bundle_bindings,
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, provider_binding, service_bundle_bindings, evidence_items, summary),
        "limitations": [
            "This dossier binds a verified policy backend provider export bundle to an explicit production-authority evidence checklist.",
            "Optional service review bundles are independently verified, linked to the same OPA/Cedar backend and enforcement identity, and bind their own decision and audit roots.",
            "It records authority references, hashes, freshness windows, and missing live-evidence categories; it does not fetch provider APIs itself.",
            "It does not claim continuously operated production OPA/Cedar infrastructure unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    return {
        **body,
        "dossier_id": dossier_id,
        "signatures": [sign_value({"dossier_id": dossier_id, "policy_backend_authority": body}, key)],
    }


def verify_policy_backend_authority_dossier(
    dossier: dict[str, Any],
    *,
    provider_bundle: dict[str, Any] | None = None,
    service_bundles: list[dict[str, Any]] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> PolicyBackendAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != POLICY_BACKEND_AUTHORITY_SCHEMA:
        errors.append(f"unsupported policy backend authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    expected_id = content_hash(body)
    if dossier.get("dossier_id") != expected_id:
        errors.append("dossier_id does not match canonical policy backend authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("policy backend authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "policy_backend_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("policy backend authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in POLICY_BACKEND_AUTHORITY_MODES:
        errors.append("policy backend authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"policy backend authority mode is {mode}; live production authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"policy backend authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"policy backend authority {field} is required")

    _verify_provider_bundle_binding(dossier.get("provider_bundle_binding"), provider_bundle, key, errors, warnings)
    _verify_service_bundle_bindings(
        dossier.get("service_bundle_bindings"),
        service_bundles,
        dossier.get("provider_bundle_binding"),
        key,
        errors,
        warnings,
    )
    _verify_required_authority(dossier.get("required_production_authority"), errors)
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("policy backend authority authority_evidence must be a list")
        evidence = []
    evidence_source_context = _authority_evidence_source_context(
        dossier.get("provider_bundle_binding") if isinstance(dossier.get("provider_bundle_binding"), dict) else {},
        dossier.get("service_bundle_bindings") if isinstance(dossier.get("service_bundle_bindings"), list) else [],
    )
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("policy backend authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_status = _verify_authority_evidence_item(
            item,
            errors,
            warnings,
            now=freshness_now,
            require_fresh=require_fresh,
            source_context=evidence_source_context,
        )
        freshness_counts[freshness_status] += 1

    evidence_dicts = [item for item in evidence if isinstance(item, dict)]
    expected_summary = _summary(evidence_dicts)
    if dossier.get("summary") != expected_summary:
        errors.append("policy backend authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("policy backend authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("policy backend authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every policy backend authority requirement to be covered")
    provider_binding_for_controls = dossier.get("provider_bundle_binding") if isinstance(dossier.get("provider_bundle_binding"), dict) else {}
    service_bindings_for_controls = [
        binding
        for binding in (dossier.get("service_bundle_bindings") if isinstance(dossier.get("service_bundle_bindings"), list) else [])
        if isinstance(binding, dict)
    ]
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("policy backend authority controls are required")
    elif dossier.get("controls") != _controls(str(mode), provider_binding_for_controls, service_bindings_for_controls, evidence_dicts, expected_summary):
        errors.append("policy backend authority controls do not match dossier body")
    _check_no_secret_values(dossier, errors)
    return PolicyBackendAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_policy_backend_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    provider_bundle: dict[str, Any],
    service_bundles: list[dict[str, Any]] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_policy_backend_authority_dossier(
        dossier,
        provider_bundle=provider_bundle,
        service_bundles=service_bundles,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid policy backend authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "provider_bundle_binding": dossier.get("provider_bundle_binding"),
        "service_bundle_bindings": dossier.get("service_bundle_bindings"),
        "summary": dossier.get("summary"),
        "control_summary": _status_summary(dossier.get("controls", [])),
        "authority_evidence": [
            {
                "requirement_id": item.get("requirement_id"),
                "authority_kind": item.get("authority_kind"),
                "evidence_ref": item.get("evidence_ref"),
                "evidence_hash": item.get("evidence_hash"),
                "evidence_id": item.get("evidence_id"),
                "issued_at": item.get("issued_at"),
                "expires_at": item.get("expires_at"),
                "source_context": item.get("source_context"),
            }
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(POLICY_BACKEND_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _provider_bundle_binding(bundle: dict[str, Any]) -> dict[str, Any]:
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
        "provider_receipt_id": source.get("provider_receipt_id"),
        "provider_receipt_hash": source.get("provider_receipt_hash"),
        "provider": source.get("provider"),
        "provider_export_hash": source.get("provider_export_hash"),
        "provider_export_ref": source.get("provider_export_ref"),
        "worker_operation_id": source.get("worker_operation_id"),
        "worker_operation_hash": source.get("worker_operation_hash"),
        "service_attestation_id": source.get("service_attestation_id"),
        "enforcement_id": source.get("enforcement_id"),
        "backend_ref": source.get("backend_ref"),
        "engine": source.get("engine"),
        "endpoint_url": source.get("endpoint_url"),
        "decision_hash": source.get("decision_hash"),
        "decision_log_root": source.get("decision_log_root"),
        "audit_log_root": source.get("audit_log_root"),
        "source_artifact_count": summary.get("source_artifact_count"),
        "source_artifact_sha256_root": summary.get("source_artifact_sha256_root"),
        "source_artifact_content_root": summary.get("source_artifact_content_root"),
        "provider_record_root_count": summary.get("provider_record_root_count"),
        "provider_record_roots": summary.get("provider_record_roots"),
        "policy_engine_receipt_replayed": summary.get("policy_engine_receipt_replayed"),
    }


def _service_bundle_binding(bundle: dict[str, Any]) -> dict[str, Any]:
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
        "service_attestation_id": source.get("service_attestation_id"),
        "service_attestation_hash": source.get("service_attestation_hash"),
        "service_ref": source.get("service_ref"),
        "service_version": source.get("service_version"),
        "enforcement_id": source.get("enforcement_id"),
        "enforcement_hash": source.get("enforcement_hash"),
        "engine": source.get("engine"),
        "backend_ref": source.get("backend_ref"),
        "endpoint_url": source.get("endpoint_url"),
        "policy_bundle_ref": source.get("bundle_ref"),
        "policy_bundle_hash": source.get("bundle_hash"),
        "policy_pack_id": source.get("policy_pack_id"),
        "policy_pack_version": source.get("policy_pack_version"),
        "runtime_action_id": source.get("runtime_action_id"),
        "runtime_action_type": source.get("runtime_action_type"),
        "decision_hash": source.get("decision_hash"),
        "decision_outcome": source.get("decision_outcome"),
        "decision_passed": source.get("decision_passed"),
        "decision_log_root": source.get("decision_log_root"),
        "audit_log_root": source.get("audit_log_root"),
        "source_artifact_count": summary.get("source_artifact_count"),
        "source_artifact_sha256_root": summary.get("source_artifact_sha256_root"),
        "source_artifact_content_root": summary.get("source_artifact_content_root"),
        "policy_engine_receipt_replayed": summary.get("policy_engine_receipt_replayed"),
        "service_control_summary": summary.get("service_control_summary"),
        "enforcement_control_summary": summary.get("enforcement_control_summary"),
    }


def _service_bundle_link_errors(service_bindings: list[dict[str, Any]], provider_binding: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not service_bindings:
        return errors
    checks = (
        ("service_attestation_id", "service attestation id"),
        ("enforcement_id", "enforcement id"),
        ("backend_ref", "backend ref"),
        ("engine", "engine"),
        ("endpoint_url", "endpoint url"),
        ("decision_hash", "decision hash"),
    )
    for binding in service_bindings:
        label = binding.get("bundle_id") or "<unknown>"
        for field, description in checks:
            expected = provider_binding.get(field)
            actual = binding.get(field)
            if expected and actual and expected != actual:
                errors.append(f"service bundle {label} {description} does not match provider bundle")
    return errors


def _verify_provider_bundle_binding(
    binding: Any,
    provider_bundle: dict[str, Any] | None,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if not isinstance(binding, dict):
        errors.append("policy backend authority provider_bundle_binding must be an object")
        return
    for field in PROVIDER_BUNDLE_BINDING_REQUIRED_FIELDS:
        if binding.get(field) in (None, "", []):
            errors.append(f"policy backend authority provider_bundle_binding.{field} is required")
    if provider_bundle is None:
        errors.append("policy backend authority provider bundle is required for verification")
        return
    expected = _provider_bundle_binding(provider_bundle)
    if binding != expected:
        errors.append("policy backend authority provider_bundle_binding does not match supplied provider bundle")
    result = verify_policy_backend_provider_bundle(provider_bundle, key=key)
    if not result.ok:
        errors.extend(f"policy backend authority provider bundle source: {error}" for error in result.errors)
    warnings.extend(f"policy backend authority provider bundle source: {warning}" for warning in result.warnings)


def _verify_service_bundle_bindings(
    bindings: Any,
    service_bundles: list[dict[str, Any]] | None,
    provider_binding: Any,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if bindings is None:
        if service_bundles:
            errors.append("policy backend authority service_bundle_bindings are required when service bundles are supplied")
        return
    if not isinstance(bindings, list):
        errors.append("policy backend authority service_bundle_bindings must be a list")
        return
    for binding in bindings:
        if not isinstance(binding, dict):
            errors.append("policy backend authority service bundle binding must be an object")
            continue
        for field in SERVICE_BUNDLE_BINDING_REQUIRED_FIELDS:
            if binding.get(field) in (None, "", []):
                errors.append(f"policy backend authority service_bundle_bindings.{field} is required")
    if isinstance(provider_binding, dict):
        valid_bindings = [binding for binding in bindings if isinstance(binding, dict)]
        errors.extend(_service_bundle_link_errors(valid_bindings, provider_binding))
    if not service_bundles:
        if bindings:
            warnings.append("policy backend authority service bundle bindings were present but no service bundle sources were supplied")
        return
    expected = [_service_bundle_binding(bundle) for bundle in service_bundles]
    if bindings != expected:
        errors.append("policy backend authority service_bundle_bindings do not match supplied service bundles")
    for bundle in service_bundles:
        result = verify_policy_backend_service_bundle(bundle, key=key)
        if not result.ok:
            errors.extend(f"policy backend authority service bundle source: {error}" for error in result.errors)
        warnings.extend(f"policy backend authority service bundle source: {warning}" for warning in result.warnings)


def _build_authority_evidence_item(item: dict[str, Any], source_context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unknown policy backend production authority requirement: {requirement_id}")
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
        "source_context": source_context,
    }
    return {**body, "evidence_id": content_hash(body)}


def _verify_authority_evidence_item(
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    now: Any,
    require_fresh: bool,
    source_context: dict[str, Any],
) -> str:
    if item.get("evidence_id") != content_hash(without_keys(item, "evidence_id")):
        errors.append(f"policy backend authority evidence_id does not match evidence body: {item.get('requirement_id')}")
    requirement_id = item.get("requirement_id")
    authority_kind = item.get("authority_kind")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        errors.append(f"unknown policy backend production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    elif requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS and authority_kind not in _requirement_authority_kinds(str(requirement_id)):
        errors.append(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for field in ("evidence_ref", "evidence_hash", "description"):
        if not item.get(field):
            errors.append(f"policy backend authority {field} is required: {requirement_id}")
    if item.get("evidence_hash") and not str(item.get("evidence_hash")).startswith("sha256:"):
        errors.append(f"policy backend authority evidence_hash must start with sha256: {requirement_id}")
    if not isinstance(item.get("source_context"), dict):
        errors.append(f"policy backend authority source_context is required: {requirement_id}")
    elif item.get("source_context") != source_context:
        errors.append(f"policy backend authority source_context does not match source bindings: {requirement_id}")

    issued_at = _parse_optional_timestamp(item, "issued_at", errors)
    expires_at = _parse_optional_timestamp(item, "expires_at", errors)
    freshness_status = "fresh"
    missing_fields = [field for field in ("issued_at", "expires_at") if not item.get(field)]
    if missing_fields:
        freshness_status = "missing"
        _freshness_problem(
            f"policy backend authority freshness metadata missing for {requirement_id}: {', '.join(missing_fields)}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        freshness_status = "stale"
        errors.append(f"policy backend authority expires_at must be after issued_at: {requirement_id}")
    if now is not None and issued_at is not None and issued_at > now:
        freshness_status = "stale"
        _freshness_problem(
            f"policy backend authority evidence is not yet issued for {requirement_id}: {item.get('issued_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if now is not None and expires_at is not None and expires_at <= now:
        freshness_status = "stale"
        _freshness_problem(
            f"policy backend authority evidence expired for {requirement_id}: {item.get('expires_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    return freshness_status


def _authority_evidence_source_context(provider_binding: dict[str, Any], service_bundle_bindings: list[Any]) -> dict[str, Any]:
    service_bindings = [binding for binding in service_bundle_bindings if isinstance(binding, dict)]
    service_contexts = [
        {
            "bundle_id": binding.get("bundle_id"),
            "bundle_hash": binding.get("bundle_hash"),
            "service_attestation_id": binding.get("service_attestation_id"),
            "service_attestation_hash": binding.get("service_attestation_hash"),
            "service_ref": binding.get("service_ref"),
            "service_version": binding.get("service_version"),
            "enforcement_id": binding.get("enforcement_id"),
            "enforcement_hash": binding.get("enforcement_hash"),
            "engine": binding.get("engine"),
            "backend_ref": binding.get("backend_ref"),
            "endpoint_url": binding.get("endpoint_url"),
            "policy_bundle_hash": binding.get("policy_bundle_hash"),
            "policy_pack_id": binding.get("policy_pack_id"),
            "policy_pack_version": binding.get("policy_pack_version"),
            "runtime_action_id": binding.get("runtime_action_id"),
            "decision_hash": binding.get("decision_hash"),
            "decision_log_root": binding.get("decision_log_root"),
            "audit_log_root": binding.get("audit_log_root"),
            "source_artifact_sha256_root": binding.get("source_artifact_sha256_root"),
            "policy_engine_receipt_replayed": binding.get("policy_engine_receipt_replayed"),
        }
        for binding in service_bindings
    ]
    return {
        "provider_bundle_id": provider_binding.get("bundle_id"),
        "provider_bundle_hash": provider_binding.get("bundle_hash"),
        "provider_receipt_id": provider_binding.get("provider_receipt_id"),
        "provider_receipt_hash": provider_binding.get("provider_receipt_hash"),
        "provider": provider_binding.get("provider"),
        "provider_export_ref": provider_binding.get("provider_export_ref"),
        "provider_export_hash": provider_binding.get("provider_export_hash"),
        "worker_operation_id": provider_binding.get("worker_operation_id"),
        "worker_operation_hash": provider_binding.get("worker_operation_hash"),
        "service_attestation_id": provider_binding.get("service_attestation_id"),
        "enforcement_id": provider_binding.get("enforcement_id"),
        "engine": provider_binding.get("engine"),
        "backend_ref": provider_binding.get("backend_ref"),
        "endpoint_url": provider_binding.get("endpoint_url"),
        "decision_hash": provider_binding.get("decision_hash"),
        "decision_log_root": provider_binding.get("decision_log_root"),
        "audit_log_root": provider_binding.get("audit_log_root"),
        "source_artifact_sha256_root": provider_binding.get("source_artifact_sha256_root"),
        "provider_record_roots": provider_binding.get("provider_record_roots"),
        "policy_engine_receipt_replayed": provider_binding.get("policy_engine_receipt_replayed"),
        "service_bundle_count": len(service_contexts),
        "service_bundle_hashes": sorted({str(binding.get("bundle_hash")) for binding in service_bindings if binding.get("bundle_hash")}),
        "service_bundles_hash": content_hash(service_contexts),
        "service_bundles": service_contexts,
    }


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("policy backend authority required_production_authority does not match v0.1 requirements")


def _summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted(
        {
            str(item.get("requirement_id"))
            for item in evidence
            if item.get("requirement_id") in set(PRODUCTION_AUTHORITY_REQUIREMENT_IDS)
        }
    )
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


def _controls(
    mode: str,
    provider_binding: dict[str, Any],
    service_bundle_bindings: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    summary: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        {
            "name": "provider_bundle_replayed",
            "status": "passed",
            "detail": "The dossier builder replayed the policy backend provider export bundle and its embedded sources.",
        },
        {
            "name": "provider_bundle_bound",
            "status": "passed" if provider_binding.get("bundle_id") else "failed",
            "detail": "The dossier binds the provider bundle ID, bundle hash, provider receipt hash, record roots, and artifact roots.",
        },
        {
            "name": "service_review_bundles_bound",
            "status": "passed" if service_bundle_bindings else "deferred",
            "detail": "Optional service review bundles bind offline source-byte replay, OPA/Cedar service attestation, enforcement identity, decision roots, and audit roots to the authority dossier.",
        },
        {
            "name": "authority_evidence_manifested",
            "status": "passed" if evidence else "deferred",
            "detail": "External authority evidence references are hash-bound when supplied.",
        },
        {
            "name": "freshness_windows_tracked",
            "status": "passed" if evidence and summary["freshness_window_count"] == len(evidence) else "deferred",
            "detail": "Issued/expires freshness windows are tracked for every supplied authority item when available.",
        },
        {
            "name": "complete_live_authority",
            "status": "passed" if summary["missing_requirement_count"] == 0 else "deferred",
            "detail": "Every production authority requirement must be covered before this can claim production OPA/Cedar backend authority.",
        },
        {
            "name": "production_claim_limited",
            "status": "passed" if mode != "production-dossier" or summary["missing_requirement_count"] == 0 else "failed",
            "detail": "Non-production dossier modes explicitly avoid claiming live production operation.",
        },
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
        errors.append(f"policy backend authority freshness {label} invalid: {exc}")
        return None


def _parse_optional_timestamp(item: dict[str, Any], field: str, errors: list[str]) -> Any:
    value = item.get(field)
    if not value:
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"policy backend authority {field} invalid: {exc}")
        return None


def _freshness_problem(message: str, errors: list[str], warnings: list[str], *, require_fresh: bool) -> None:
    if require_fresh:
        errors.append(message)
    else:
        warnings.append(message)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"policy backend authority {field} is required")
    return value


def _require_hash_ref(value: str, field: str) -> None:
    if not value.startswith("sha256:"):
        raise ValueError(f"policy backend authority {field} must start with sha256:")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}"
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"policy backend authority contains secret-like field {child_path}; store only redacted refs")
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
