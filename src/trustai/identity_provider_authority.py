from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .identity_provider_lifecycle_worker import verify_identity_provider_lifecycle_worker_receipt

IDENTITY_PROVIDER_AUTHORITY_SCHEMA = "trustai.identity-provider-production-authority-dossier/0.1"
IDENTITY_PROVIDER_AUTHORITY_ENTRY_TYPE = "identity.provider_authority_recorded"
IDENTITY_PROVIDER_AUTHORITY_MODES = {"local-dossier", "provider-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {"id": "live-identity-provider-event-streams", "title": "Live Okta, Entra, ServiceNow, or equivalent identity-provider event streams", "authority_kinds": ["identity-provider", "provider-api"]},
    {"id": "token-session-propagation", "title": "Token, session, and account propagation records for governed agents", "authority_kinds": ["identity-provider", "provider-api"]},
    {"id": "account-app-lifecycle-apis", "title": "Account, app assignment, SCIM sync, token revocation, and session revocation lifecycle API exports", "authority_kinds": ["identity-provider", "provider-api"]},
    {"id": "provider-system-log-retention", "title": "Provider-native system-log retention, cursor, and replay exports", "authority_kinds": ["identity-provider", "provider-api", "cloud-object-lock"]},
    {"id": "immutable-identity-audit-logs", "title": "Immutable identity-provider lifecycle worker and provider audit logs", "authority_kinds": ["identity-provider", "cloud-object-lock", "customer"]},
    {"id": "credential-custody-and-kms", "title": "Identity-provider lifecycle credential custody and KMS/HSM enforcement evidence", "authority_kinds": ["kms-hsm", "identity-provider", "provider-api"]},
    {"id": "scheduler-queue-lease-checkpoint", "title": "Production scheduler, queue, lease, checkpoint, cursor, and dead-letter provider exports", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "identity-inventory-reconciliation", "title": "Agent inventory reconciliation against identity-provider records and trust-network identity receipts", "authority_kinds": ["identity-provider", "provider-api", "customer"]},
    {"id": "propagation-response-replay", "title": "Retained request/response replay for lifecycle propagation operations", "authority_kinds": ["identity-provider", "provider-api", "customer"]},
    {"id": "tenant-network-and-access-controls", "title": "Tenant network, admin access, breakglass, and rate-limit controls for identity lifecycle workers", "authority_kinds": ["hosted-service", "provider-api", "identity-provider"]},
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class IdentityProviderAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_identity_provider_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("identity provider authority dossier must contain an object")
    return value


def write_identity_provider_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_identity_provider_authority_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 4)
    if len(parts) != 5:
        raise ValueError("authority evidence must be requirement_id,authority_kind,evidence_ref,evidence_hash,description[;key=value...]")
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


def _worker_sources_kwargs(
    *,
    lifecycle_operation_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_provider_session_receipt: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    identity_payload_path: str | Path | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "lifecycle_operation_receipt": lifecycle_operation_receipt,
        "identity_provider_attestation": identity_provider_attestation,
        "identity_provider_session_receipt": identity_provider_session_receipt,
        "identity_payload": identity_payload,
        "identity_payload_path": identity_payload_path,
        "vendor_identity_receipt": vendor_identity_receipt,
        "proof_packs": proof_packs,
        "trust_network_manifest": trust_network_manifest,
    }


def build_identity_provider_authority_dossier(
    worker_receipt: dict[str, Any],
    *,
    lifecycle_operation_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_provider_session_receipt: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    identity_payload_path: str | Path | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    mode: str = "provider-dossier",
    environment: str | None = None,
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in IDENTITY_PROVIDER_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(IDENTITY_PROVIDER_AUTHORITY_MODES)}")
    for value, field in ((dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    source_kwargs = _worker_sources_kwargs(
        lifecycle_operation_receipt=lifecycle_operation_receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_provider_session_receipt=identity_provider_session_receipt,
        identity_payload=identity_payload,
        identity_payload_path=identity_payload_path,
        vendor_identity_receipt=vendor_identity_receipt,
        proof_packs=proof_packs,
        trust_network_manifest=trust_network_manifest,
    )
    source_result = verify_identity_provider_lifecycle_worker_receipt(worker_receipt, key=key, **source_kwargs)
    if not source_result.ok:
        raise ValueError("invalid identity provider lifecycle worker source: " + "; ".join(source_result.errors))
    evidence_items = [_build_authority_evidence_item(item) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body: dict[str, Any] = {
        "schema": IDENTITY_PROVIDER_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment or worker_receipt.get("environment") or "local",
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "worker_binding": _worker_binding(worker_receipt),
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, worker_receipt, evidence_items, summary),
        "limitations": [
            "This dossier binds a verified identity-provider lifecycle worker receipt to an explicit production-authority evidence checklist.",
            "It records authority references, hashes, freshness windows, and missing live-evidence categories for identity-provider event streams and lifecycle propagation.",
            "It does not claim continuously operated production identity-provider authority unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    return {**body, "dossier_id": dossier_id, "signatures": [sign_value({"dossier_id": dossier_id, "identity_provider_authority": body}, key)]}

def verify_identity_provider_authority_dossier(
    dossier: dict[str, Any],
    *,
    worker_receipt: dict[str, Any] | None = None,
    lifecycle_operation_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_provider_session_receipt: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    identity_payload_path: str | Path | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> IdentityProviderAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != IDENTITY_PROVIDER_AUTHORITY_SCHEMA:
        errors.append(f"unsupported identity provider authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    expected_id = content_hash(body)
    if dossier.get("dossier_id") != expected_id:
        errors.append("dossier_id does not match canonical identity provider authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("identity provider authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "identity_provider_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("identity provider authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in IDENTITY_PROVIDER_AUTHORITY_MODES:
        errors.append("identity provider authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"identity provider authority mode is {mode}; live production identity-provider authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"identity provider authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"identity provider authority {field} is required")

    source_kwargs = _worker_sources_kwargs(
        lifecycle_operation_receipt=lifecycle_operation_receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_provider_session_receipt=identity_provider_session_receipt,
        identity_payload=identity_payload,
        identity_payload_path=identity_payload_path,
        vendor_identity_receipt=vendor_identity_receipt,
        proof_packs=proof_packs,
        trust_network_manifest=trust_network_manifest,
    )
    _verify_worker_binding(dossier.get("worker_binding"), worker_receipt, source_kwargs, key, errors, warnings)
    _verify_required_authority(dossier.get("required_production_authority"), errors)
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("identity provider authority authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("identity provider authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_status = _verify_authority_evidence_item(item, errors, warnings, now=freshness_now, require_fresh=require_fresh)
        freshness_counts[freshness_status] += 1

    expected_summary = _summary([item for item in evidence if isinstance(item, dict)])
    if dossier.get("summary") != expected_summary:
        errors.append("identity provider authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("identity provider authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("identity provider authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every identity provider authority requirement to be covered")
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("production-dossier mode requires every identity provider authority evidence item to be fresh")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("identity provider authority controls are required")
    elif dossier.get("controls") != _controls(str(mode), worker_receipt or {}, [item for item in evidence if isinstance(item, dict)], expected_summary):
        errors.append("identity provider authority controls do not match dossier body")
    _check_no_secret_values(dossier, errors)

    return IdentityProviderAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_identity_provider_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    worker_receipt: dict[str, Any],
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
    **sources: Any,
) -> dict[str, Any]:
    result = verify_identity_provider_authority_dossier(
        dossier,
        worker_receipt=worker_receipt,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
        **sources,
    )
    if not result.ok:
        raise ValueError("invalid identity provider authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "worker_binding": dossier.get("worker_binding"),
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
    return chain.append(IDENTITY_PROVIDER_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _worker_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    source_operation = receipt.get("source_operation", {}) if isinstance(receipt.get("source_operation"), dict) else {}
    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    scheduler = receipt.get("scheduler", {}) if isinstance(receipt.get("scheduler"), dict) else {}
    propagation = receipt.get("propagation", {}) if isinstance(receipt.get("propagation"), dict) else {}
    observability = receipt.get("observability", {}) if isinstance(receipt.get("observability"), dict) else {}
    credential = receipt.get("credential", {}) if isinstance(receipt.get("credential"), dict) else {}
    return {
        "worker_operation_id": receipt.get("worker_operation_id"),
        "worker_receipt_hash": content_hash(receipt),
        "worker_schema": receipt.get("schema"),
        "worker_mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "provider": receipt.get("provider"),
        "source_operation_id": source_operation.get("operation_id"),
        "source_operation_hash": source_operation.get("operation_hash"),
        "identity_id": source_operation.get("identity_id"),
        "identity_record_hash": source_operation.get("identity_record_hash"),
        "operation_kind": worker.get("operation_kind"),
        "worker_ref": worker.get("worker_ref"),
        "run_ref": worker.get("run_ref"),
        "worker_success": worker.get("success"),
        "schedule_ref": scheduler.get("schedule_ref"),
        "lease_ref": scheduler.get("lease_ref"),
        "checkpoint_ref": scheduler.get("checkpoint_ref"),
        "checkpoint_hash": scheduler.get("checkpoint_hash"),
        "queue_ref": propagation.get("queue_ref"),
        "queue_message_ref": propagation.get("queue_message_ref"),
        "destination_ref": propagation.get("destination_ref"),
        "propagation_log_ref": propagation.get("propagation_log_ref"),
        "propagation_log_root": propagation.get("propagation_log_root"),
        "account_state_log_root": propagation.get("account_state_log_root"),
        "session_revocation_log_root": propagation.get("session_revocation_log_root"),
        "token_revocation_log_root": propagation.get("token_revocation_log_root"),
        "request_hash": propagation.get("request_hash"),
        "response_status": propagation.get("response_status"),
        "response_hash": propagation.get("response_hash"),
        "metrics_ref": observability.get("metrics_ref"),
        "audit_log_ref": observability.get("audit_log_ref"),
        "audit_log_root": observability.get("audit_log_root"),
        "retention_until": observability.get("retention_until"),
        "credential_ref": credential.get("ref"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }

def _verify_worker_binding(
    binding: Any,
    worker_receipt: dict[str, Any] | None,
    sources: dict[str, Any],
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if not isinstance(binding, dict):
        errors.append("identity provider authority worker_binding must be an object")
        return
    for field in (
        "worker_operation_id",
        "worker_receipt_hash",
        "worker_mode",
        "environment",
        "recorded_at",
        "provider",
        "source_operation_id",
        "source_operation_hash",
        "identity_id",
        "identity_record_hash",
        "operation_kind",
        "worker_ref",
        "run_ref",
        "worker_success",
        "schedule_ref",
        "lease_ref",
        "checkpoint_ref",
        "queue_ref",
        "destination_ref",
        "propagation_log_ref",
        "propagation_log_root",
        "audit_log_root",
        "retention_until",
        "credential_ref",
    ):
        if binding.get(field) in (None, "", []):
            errors.append(f"identity provider authority worker_binding.{field} is required")
    if worker_receipt is None:
        warnings.append("identity provider authority worker receipt was not supplied; identity lifecycle worker source was not replayed")
        return
    expected = _worker_binding(worker_receipt)
    if binding != expected:
        errors.append("identity provider authority worker_binding does not match supplied lifecycle worker receipt")
    result = verify_identity_provider_lifecycle_worker_receipt(worker_receipt, key=key, **sources)
    if not result.ok:
        errors.extend(f"identity provider authority worker source: {error}" for error in result.errors)
    warnings.extend(f"identity provider authority worker source: {warning}" for warning in result.warnings)


def _build_authority_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unknown identity provider production authority requirement: {requirement_id}")
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
        errors.append(f"identity provider authority evidence_id does not match evidence body: {item.get('requirement_id')}")
    requirement_id = item.get("requirement_id")
    authority_kind = item.get("authority_kind")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        errors.append(f"unknown identity provider production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    elif requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS and authority_kind not in _requirement_authority_kinds(str(requirement_id)):
        errors.append(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for field in ("evidence_ref", "evidence_hash", "description"):
        if not item.get(field):
            errors.append(f"identity provider authority {field} is required: {requirement_id}")
    if item.get("evidence_hash") and not str(item.get("evidence_hash")).startswith("sha256:"):
        errors.append(f"identity provider authority evidence_hash must start with sha256: {requirement_id}")

    issued_at = _parse_optional_timestamp(item, "issued_at", errors)
    expires_at = _parse_optional_timestamp(item, "expires_at", errors)
    freshness_status = "fresh"
    missing_fields = [field for field in ("issued_at", "expires_at") if not item.get(field)]
    if missing_fields:
        freshness_status = "missing"
        _freshness_problem(
            f"identity provider authority freshness metadata missing for {requirement_id}: {', '.join(missing_fields)}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        freshness_status = "stale"
        errors.append(f"identity provider authority expires_at must be after issued_at: {requirement_id}")
    if now is not None and issued_at is not None and issued_at > now:
        freshness_status = "stale"
        _freshness_problem(
            f"identity provider authority evidence is not yet issued for {requirement_id}: {item.get('issued_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if now is not None and expires_at is not None and expires_at <= now:
        freshness_status = "stale"
        _freshness_problem(
            f"identity provider authority evidence expired for {requirement_id}: {item.get('expires_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    return freshness_status


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("identity provider authority required_production_authority does not match v0.1 requirements")


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


def _controls(mode: str, worker_receipt: dict[str, Any], evidence: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"name": "lifecycle_worker_replayed", "status": "passed", "detail": "The dossier builder replayed the identity-provider lifecycle worker receipt and supplied source evidence."},
        {"name": "lifecycle_worker_bound", "status": "passed" if worker_receipt.get("worker_operation_id") else "failed", "detail": "The dossier binds the worker operation ID, receipt hash, source operation, scheduler, propagation, and audit roots."},
        {"name": "authority_evidence_manifested", "status": "passed" if evidence else "deferred", "detail": "External identity-provider authority evidence references are hash-bound when supplied."},
        {"name": "freshness_windows_tracked", "status": "passed" if evidence and summary["freshness_window_count"] == len(evidence) else "deferred", "detail": "Issued/expires freshness windows are tracked for every supplied authority item when available."},
        {"name": "complete_live_authority", "status": "passed" if summary["missing_requirement_count"] == 0 else "deferred", "detail": "Every identity-provider production authority requirement must be covered before this can claim live production authority."},
        {"name": "production_claim_limited", "status": "passed" if mode != "production-dossier" or summary["missing_requirement_count"] == 0 else "failed", "detail": "Non-production dossier modes explicitly avoid claiming live identity-provider authority."},
    ]


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls if isinstance(controls, list) else []:
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
        errors.append(f"identity provider authority freshness {label} invalid: {exc}")
        return None


def _parse_optional_timestamp(item: dict[str, Any], field: str, errors: list[str]) -> Any:
    value = item.get(field)
    if not value:
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"identity provider authority {field} invalid: {exc}")
        return None


def _freshness_problem(message: str, errors: list[str], warnings: list[str], *, require_fresh: bool) -> None:
    if require_fresh:
        errors.append(message)
    else:
        warnings.append(message)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"identity provider authority {field} is required")
    return value


def _require_hash_ref(value: str, field: str) -> None:
    if not value.startswith("sha256:"):
        raise ValueError(f"identity provider authority {field} must start with sha256:")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}"
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"identity provider authority contains secret-like field {child_path}; store only redacted refs")
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
