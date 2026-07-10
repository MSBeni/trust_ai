from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .provider_operations_service import verify_provider_operations_service_attestation

PROVIDER_OPERATIONS_AUTHORITY_SCHEMA = "trustai.provider-operations-production-authority-dossier/0.1"
PROVIDER_OPERATIONS_AUTHORITY_ENTRY_TYPE = "provider.operations_authority_recorded"
PROVIDER_OPERATIONS_AUTHORITY_MODES = {"local-dossier", "provider-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {
        "id": "hosted-callback-worker-fleet",
        "title": "Continuously operated provider callback, OAuth, audit, and lifecycle worker fleets",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "live-public-ingress",
        "title": "Live TrustAI-operated public ingress, DNS, TLS, WAF, and provider webhook endpoints",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "provider-owned-vault-kms",
        "title": "Live provider-owned vault/KMS calls behind credential custody receipts",
        "authority_kinds": ["kms-hsm", "provider-api"],
    },
    {
        "id": "managed-ha-callback-storage",
        "title": "Managed Postgres/HA callback request storage operations and failover evidence",
        "authority_kinds": ["provider-api", "hosted-service"],
    },
    {
        "id": "provider-audit-infrastructure",
        "title": "Production-operated provider audit stream, worker, and immutable audit infrastructure",
        "authority_kinds": ["provider-api", "cloud-object-lock", "hosted-service"],
    },
    {
        "id": "credentialed-external-provider-calls",
        "title": "Credentialed external Slack/GitHub/GitLab provider calls and provider-owned event replay",
        "authority_kinds": ["provider-api", "hosted-service"],
    },
    {
        "id": "webhook-signature-replay-dedup",
        "title": "Webhook signature validation, replay windows, deduplication, and retry controls",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "oauth-app-lifecycle",
        "title": "OAuth/app installation lifecycle operations and app credential custody",
        "authority_kinds": ["identity-provider", "provider-api", "hosted-service"],
    },
    {
        "id": "scheduler-lease-checkpoint",
        "title": "Production scheduler, lease, checkpoint, queue, and cursor provider exports",
        "authority_kinds": ["provider-api", "hosted-service"],
    },
    {
        "id": "network-egress-rate-limit",
        "title": "Tenant network, egress, request signing, and provider rate-limit enforcement",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "immutable-callback-retention",
        "title": "Immutable callback, delivery, lifecycle, credential, and provider audit retention",
        "authority_kinds": ["cloud-object-lock", "provider-api", "customer"],
    },
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class ProviderOperationsAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_provider_operations_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider operations authority dossier must contain an object")
    return value


def write_provider_operations_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_provider_operations_authority_evidence_arg(value: str) -> dict[str, Any]:
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


def build_provider_operations_authority_dossier(
    service_attestation: dict[str, Any],
    *,
    provider_installation: dict[str, Any] | None = None,
    provider_ingress: dict[str, Any] | None = None,
    callback_storage: dict[str, Any] | None = None,
    lifecycle: dict[str, Any] | None = None,
    lifecycle_operation: dict[str, Any] | None = None,
    audit_lifecycle_operation: dict[str, Any] | None = None,
    audit_worker: dict[str, Any] | None = None,
    credential_custody: dict[str, Any] | None = None,
    callback_store: dict[str, Any] | None = None,
    audit_stream: dict[str, Any] | None = None,
    audit_correlation: dict[str, Any] | None = None,
    callback_store_db_path: str | Path | None = None,
    mode: str = "provider-dossier",
    environment: str | None = None,
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in PROVIDER_OPERATIONS_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(PROVIDER_OPERATIONS_AUTHORITY_MODES)}")
    for value, field in (
        (dossier_ref, "dossier_ref"),
        (authority_ref, "authority_ref"),
        (producer_ref, "producer_ref"),
    ):
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    source_result = verify_provider_operations_service_attestation(
        service_attestation,
        provider_installation=provider_installation,
        provider_ingress=provider_ingress,
        callback_storage=callback_storage,
        lifecycle=lifecycle,
        lifecycle_operation=lifecycle_operation,
        audit_lifecycle_operation=audit_lifecycle_operation,
        audit_worker=audit_worker,
        credential_custody=credential_custody,
        callback_store=callback_store,
        audit_stream=audit_stream,
        audit_correlation=audit_correlation,
        callback_store_db_path=callback_store_db_path,
        key=key,
    )
    if not source_result.ok:
        raise ValueError("invalid provider operations service source: " + "; ".join(source_result.errors))

    evidence_items = [_build_authority_evidence_item(item) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body: dict[str, Any] = {
        "schema": PROVIDER_OPERATIONS_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment or service_attestation.get("environment") or "local",
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "service_attestation_binding": _service_attestation_binding(service_attestation),
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, service_attestation, evidence_items, summary),
        "limitations": [
            "This dossier binds a verified provider operations service attestation to an explicit production-authority evidence checklist.",
            "It records authority references, hashes, freshness windows, and missing live-evidence categories for provider-hosted callbacks and external provider operations.",
            "It does not claim continuously operated production Slack/GitHub/GitLab callback infrastructure unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    return {
        **body,
        "dossier_id": dossier_id,
        "signatures": [sign_value({"dossier_id": dossier_id, "provider_operations_authority": body}, key)],
    }


def verify_provider_operations_authority_dossier(
    dossier: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    provider_installation: dict[str, Any] | None = None,
    provider_ingress: dict[str, Any] | None = None,
    callback_storage: dict[str, Any] | None = None,
    lifecycle: dict[str, Any] | None = None,
    lifecycle_operation: dict[str, Any] | None = None,
    audit_lifecycle_operation: dict[str, Any] | None = None,
    audit_worker: dict[str, Any] | None = None,
    credential_custody: dict[str, Any] | None = None,
    callback_store: dict[str, Any] | None = None,
    audit_stream: dict[str, Any] | None = None,
    audit_correlation: dict[str, Any] | None = None,
    callback_store_db_path: str | Path | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> ProviderOperationsAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != PROVIDER_OPERATIONS_AUTHORITY_SCHEMA:
        errors.append(f"unsupported provider operations authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    expected_id = content_hash(body)
    if dossier.get("dossier_id") != expected_id:
        errors.append("dossier_id does not match canonical provider operations authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider operations authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "provider_operations_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider operations authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in PROVIDER_OPERATIONS_AUTHORITY_MODES:
        errors.append("provider operations authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"provider operations authority mode is {mode}; live production authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"provider operations authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"provider operations authority {field} is required")

    _verify_service_attestation_binding(
        dossier.get("service_attestation_binding"),
        service_attestation,
        {
            "provider_installation": provider_installation,
            "provider_ingress": provider_ingress,
            "callback_storage": callback_storage,
            "lifecycle": lifecycle,
            "lifecycle_operation": lifecycle_operation,
            "audit_lifecycle_operation": audit_lifecycle_operation,
            "audit_worker": audit_worker,
            "credential_custody": credential_custody,
            "callback_store": callback_store,
            "audit_stream": audit_stream,
            "audit_correlation": audit_correlation,
            "callback_store_db_path": callback_store_db_path,
        },
        key,
        errors,
        warnings,
    )
    _verify_required_authority(dossier.get("required_production_authority"), errors)
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("provider operations authority authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("provider operations authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_status = _verify_authority_evidence_item(
            item,
            errors,
            warnings,
            now=freshness_now,
            require_fresh=require_fresh,
        )
        freshness_counts[freshness_status] += 1

    expected_summary = _summary([item for item in evidence if isinstance(item, dict)])
    if dossier.get("summary") != expected_summary:
        errors.append("provider operations authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("provider operations authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("provider operations authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every provider operations authority requirement to be covered")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("provider operations authority controls are required")
    _check_no_secret_values(dossier, errors)
    return ProviderOperationsAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_provider_operations_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    service_attestation: dict[str, Any],
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
    **sources: Any,
) -> dict[str, Any]:
    result = verify_provider_operations_authority_dossier(
        dossier,
        service_attestation=service_attestation,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
        **sources,
    )
    if not result.ok:
        raise ValueError("invalid provider operations authority dossier: " + "; ".join(result.errors))
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
            }
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(PROVIDER_OPERATIONS_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _service_attestation_binding(attestation: dict[str, Any]) -> dict[str, Any]:
    source = attestation.get("source", {}) if isinstance(attestation.get("source"), dict) else {}
    service = attestation.get("service", {}) if isinstance(attestation.get("service"), dict) else {}
    operations = attestation.get("operations", {}) if isinstance(attestation.get("operations"), dict) else {}
    security = attestation.get("security", {}) if isinstance(attestation.get("security"), dict) else {}
    audit_log = attestation.get("audit_log", {}) if isinstance(attestation.get("audit_log"), dict) else {}
    actor = attestation.get("operation_actor", {}) if isinstance(attestation.get("operation_actor"), dict) else {}
    credential = actor.get("credential", {}) if isinstance(actor.get("credential"), dict) else {}
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
        "public_ingress_ref": operations.get("public_ingress_ref"),
        "oauth_worker_ref": operations.get("oauth_worker_ref"),
        "callback_worker_ref": operations.get("callback_worker_ref"),
        "audit_worker_ref": operations.get("audit_worker_ref"),
        "storage_ref": operations.get("storage_ref"),
        "vault_ref": operations.get("vault_ref"),
        "kms_key_ref": operations.get("kms_key_ref"),
        "scheduler_ref": operations.get("scheduler_ref"),
        "lease_ref": operations.get("lease_ref"),
        "checkpoint_ref": operations.get("checkpoint_ref"),
        "external_call_policy_ref": operations.get("external_call_policy_ref"),
        "mtls_policy_ref": security.get("mtls_policy_ref"),
        "auth_policy_ref": security.get("auth_policy_ref"),
        "webhook_signature_policy_ref": security.get("webhook_signature_policy_ref"),
        "replay_window_ref": security.get("replay_window_ref"),
        "dedup_store_ref": security.get("dedup_store_ref"),
        "rate_limit_policy_ref": security.get("rate_limit_policy_ref"),
        "network_policy_ref": security.get("network_policy_ref"),
        "egress_policy_ref": security.get("egress_policy_ref"),
        "audit_log_ref": audit_log.get("audit_log_ref"),
        "audit_log_root": audit_log.get("root"),
        "retention_until": audit_log.get("retention_until"),
        "actor_ref": actor.get("actor_ref"),
        "credential_ref": credential.get("ref"),
        "evidence_refs": actor.get("evidence_refs"),
    }


def _verify_service_attestation_binding(
    binding: Any,
    service_attestation: dict[str, Any] | None,
    sources: dict[str, Any],
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if not isinstance(binding, dict):
        errors.append("provider operations authority service_attestation_binding must be an object")
        return
    for field in (
        "attestation_id",
        "attestation_hash",
        "attestation_mode",
        "environment",
        "attested_at",
        "source_count",
        "source_hash",
        "service_ref",
        "provider",
        "service_image_digest",
        "service_binary_hash",
        "replicas_min",
        "replicas_max",
        "availability_zones",
        "public_ingress_ref",
        "oauth_worker_ref",
        "callback_worker_ref",
        "audit_worker_ref",
        "storage_ref",
        "vault_ref",
        "kms_key_ref",
        "scheduler_ref",
        "lease_ref",
        "checkpoint_ref",
        "external_call_policy_ref",
        "webhook_signature_policy_ref",
        "replay_window_ref",
        "dedup_store_ref",
        "audit_log_root",
        "retention_until",
        "actor_ref",
        "credential_ref",
    ):
        if binding.get(field) in (None, "", []):
            errors.append(f"provider operations authority service_attestation_binding.{field} is required")
    if service_attestation is None:
        warnings.append("provider operations authority service attestation was not supplied; provider operations source was not replayed")
        return
    expected = _service_attestation_binding(service_attestation)
    if binding != expected:
        errors.append("provider operations authority service_attestation_binding does not match supplied service attestation")
    result = verify_provider_operations_service_attestation(service_attestation, key=key, **sources)
    if not result.ok:
        errors.extend(f"provider operations authority service source: {error}" for error in result.errors)
    warnings.extend(f"provider operations authority service source: {warning}" for warning in result.warnings)


def _build_authority_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unknown provider operations production authority requirement: {requirement_id}")
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


def _verify_authority_evidence_item(
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    now: Any,
    require_fresh: bool,
) -> str:
    if item.get("evidence_id") != content_hash(without_keys(item, "evidence_id")):
        errors.append(f"provider operations authority evidence_id does not match evidence body: {item.get('requirement_id')}")
    requirement_id = item.get("requirement_id")
    authority_kind = item.get("authority_kind")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        errors.append(f"unknown provider operations production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    elif requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS and authority_kind not in _requirement_authority_kinds(str(requirement_id)):
        errors.append(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for field in ("evidence_ref", "evidence_hash", "description"):
        if not item.get(field):
            errors.append(f"provider operations authority {field} is required: {requirement_id}")
    if item.get("evidence_hash") and not str(item.get("evidence_hash")).startswith("sha256:"):
        errors.append(f"provider operations authority evidence_hash must start with sha256: {requirement_id}")

    issued_at = _parse_optional_timestamp(item, "issued_at", errors)
    expires_at = _parse_optional_timestamp(item, "expires_at", errors)
    freshness_status = "fresh"
    missing_fields = [field for field in ("issued_at", "expires_at") if not item.get(field)]
    if missing_fields:
        freshness_status = "missing"
        _freshness_problem(
            f"provider operations authority freshness metadata missing for {requirement_id}: {', '.join(missing_fields)}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        freshness_status = "stale"
        errors.append(f"provider operations authority expires_at must be after issued_at: {requirement_id}")
    if now is not None and issued_at is not None and issued_at > now:
        freshness_status = "stale"
        _freshness_problem(
            f"provider operations authority evidence is not yet issued for {requirement_id}: {item.get('issued_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if now is not None and expires_at is not None and expires_at <= now:
        freshness_status = "stale"
        _freshness_problem(
            f"provider operations authority evidence expired for {requirement_id}: {item.get('expires_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    return freshness_status


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("provider operations authority required_production_authority does not match v0.1 requirements")


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


def _controls(mode: str, service_attestation: dict[str, Any], evidence: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": "service_attestation_replayed",
            "status": "passed",
            "detail": "The dossier builder replayed the provider operations service attestation and supplied source evidence.",
        },
        {
            "name": "service_attestation_bound",
            "status": "passed" if service_attestation.get("attestation_id") else "failed",
            "detail": "The dossier binds the service attestation ID, attestation hash, source hash, service controls, and callback operation refs.",
        },
        {
            "name": "authority_evidence_manifested",
            "status": "passed" if evidence else "deferred",
            "detail": "External provider operations authority evidence references are hash-bound when supplied.",
        },
        {
            "name": "freshness_windows_tracked",
            "status": "passed" if evidence and summary["freshness_window_count"] == len(evidence) else "deferred",
            "detail": "Issued/expires freshness windows are tracked for every supplied authority item when available.",
        },
        {
            "name": "complete_live_authority",
            "status": "passed" if summary["missing_requirement_count"] == 0 else "deferred",
            "detail": "Every provider operations production authority requirement must be covered before this can claim live production authority.",
        },
        {
            "name": "production_claim_limited",
            "status": "passed" if mode != "production-dossier" or summary["missing_requirement_count"] == 0 else "failed",
            "detail": "Non-production dossier modes explicitly avoid claiming live production callback operation.",
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
        errors.append(f"provider operations authority freshness {label} invalid: {exc}")
        return None


def _parse_optional_timestamp(item: dict[str, Any], field: str, errors: list[str]) -> Any:
    value = item.get(field)
    if not value:
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"provider operations authority {field} invalid: {exc}")
        return None


def _freshness_problem(message: str, errors: list[str], warnings: list[str], *, require_fresh: bool) -> None:
    if require_fresh:
        errors.append(message)
    else:
        warnings.append(message)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"provider operations authority {field} is required")
    return value


def _require_hash_ref(value: str, field: str) -> None:
    if not value.startswith("sha256:"):
        raise ValueError(f"provider operations authority {field} must start with sha256:")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}"
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"provider operations authority contains secret-like field {child_path}; store only redacted refs")
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
