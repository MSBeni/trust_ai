from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approval_callback import verify_approval_callback
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .provider_delivery_authority import verify_provider_delivery_authority_dossier
from .provider_operations_authority import verify_provider_operations_authority_dossier
from .provider_webhook import verify_provider_webhook_receipt

PROVIDER_APPROVAL_AUTHORITY_SCHEMA = "trustai.provider-approval-production-authority-dossier/0.1"
PROVIDER_APPROVAL_AUTHORITY_ENTRY_TYPE = "provider.approval_authority_recorded"
PROVIDER_APPROVAL_AUTHORITY_MODES = {"local-dossier", "provider-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {"id": "hosted-approval-callback-ingress", "title": "Continuously operated Slack approval callback ingress and worker fleet", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "slack-interaction-signature-replay", "title": "Slack interaction signature replay, timestamp window, and action binding", "authority_kinds": ["provider-api", "identity-provider", "hosted-service"]},
    {"id": "github-gitlab-webhook-signature-replay", "title": "GitHub/GitLab webhook signature replay, delivery identity, and deduplication", "authority_kinds": ["provider-api", "hosted-service"]},
    {"id": "pending-request-storage-and-dedup", "title": "Pending approval request storage, replay protection, and deduplication controls", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "provider-delivery-authority", "title": "Provider delivery production authority for check runs, Slack messages, or GitLab statuses", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "provider-operations-authority", "title": "Provider operations production authority for callbacks, ingress, credentials, and audit workers", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "production-provider-credentials", "title": "Production provider credentials under vault/KMS custody and rotation controls", "authority_kinds": ["kms-hsm", "provider-api", "customer"]},
    {"id": "immutable-approval-audit-logs", "title": "Immutable approval, callback, webhook, delivery, and provider audit logs", "authority_kinds": ["cloud-object-lock", "provider-api", "customer"]},
    {"id": "scheduler-queue-retry-idempotency", "title": "Approval/delivery scheduler, queue, retry, DLQ, and idempotency exports", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "tenant-network-egress-controls", "title": "Tenant isolation, network egress, provider rate-limit, and request signing controls", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "reviewer-identity-and-rbac", "title": "Reviewer identity, role binding, team membership, and RBAC evidence", "authority_kinds": ["identity-provider", "provider-api", "customer"]},
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class ProviderApprovalAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_provider_approval_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider approval authority dossier must contain an object")
    return value


def write_provider_approval_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_provider_approval_authority_evidence_arg(value: str) -> dict[str, Any]:
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


def build_provider_approval_authority_dossier(
    approval_request: dict[str, Any],
    approval_callback: dict[str, Any],
    *,
    webhook_receipts: list[dict[str, Any]] | None = None,
    provider_delivery_authority: dict[str, Any] | None = None,
    provider_operations_authority: dict[str, Any] | None = None,
    mode: str = "provider-dossier",
    environment: str | None = None,
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in PROVIDER_APPROVAL_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(PROVIDER_APPROVAL_AUTHORITY_MODES)}")
    for value, field in ((dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)
    callback_result = verify_approval_callback(approval_request, approval_callback, key=key)
    if not callback_result.ok:
        raise ValueError("invalid approval callback source: " + "; ".join(callback_result.errors))
    webhooks = list(webhook_receipts or [])
    for receipt in webhooks:
        webhook_result = verify_provider_webhook_receipt(receipt, key=key)
        if not webhook_result.ok:
            raise ValueError("invalid provider webhook source: " + "; ".join(webhook_result.errors))
    if provider_delivery_authority is not None:
        delivery_result = verify_provider_delivery_authority_dossier(provider_delivery_authority, key=key)
        if not delivery_result.ok:
            raise ValueError("invalid provider delivery authority source: " + "; ".join(delivery_result.errors))
    if provider_operations_authority is not None:
        operations_result = verify_provider_operations_authority_dossier(provider_operations_authority, key=key)
        if not operations_result.ok:
            raise ValueError("invalid provider operations authority source: " + "; ".join(operations_result.errors))

    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    evidence_items = [_build_authority_evidence_item(item) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    binding = _source_binding(approval_request, approval_callback, webhooks, provider_delivery_authority, provider_operations_authority)
    body: dict[str, Any] = {
        "schema": PROVIDER_APPROVAL_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment or "local",
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "source_binding": binding,
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, binding, evidence_items, summary),
        "limitations": [
            "This dossier binds signed approval callbacks, provider webhook receipts, and provider delivery/operations authority dossiers to a CI/CD approval production-authority checklist.",
            "It records authority references, hashes, freshness windows, and missing live-evidence categories for credentialed Slack/GitHub/GitLab approval operations.",
            "It does not claim continuously operated production CI/CD approval authority unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    signed_value = {"dossier_id": dossier_id, "provider_approval_authority": body}
    return {**body, "dossier_id": dossier_id, "signatures": [sign_value(signed_value, key)]}


def verify_provider_approval_authority_dossier(
    dossier: dict[str, Any],
    *,
    approval_request: dict[str, Any] | None = None,
    approval_callback: dict[str, Any] | None = None,
    webhook_receipts: list[dict[str, Any]] | None = None,
    provider_delivery_authority: dict[str, Any] | None = None,
    provider_operations_authority: dict[str, Any] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> ProviderApprovalAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != PROVIDER_APPROVAL_AUTHORITY_SCHEMA:
        errors.append(f"unsupported provider approval authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical provider approval authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider approval authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "provider_approval_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider approval authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in PROVIDER_APPROVAL_AUTHORITY_MODES:
        errors.append("provider approval authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"provider approval authority mode is {mode}; live production approval authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"provider approval authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"provider approval authority {field} is required")

    _verify_source_binding(
        dossier.get("source_binding"),
        approval_request,
        approval_callback,
        webhook_receipts,
        provider_delivery_authority,
        provider_operations_authority,
        errors,
        warnings,
        key=key,
    )
    _verify_required_authority(dossier.get("required_production_authority"), errors)
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("provider approval authority authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("provider approval authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_counts[_verify_authority_evidence_item(item, errors, warnings, now=freshness_now, require_fresh=require_fresh)] += 1

    evidence_dicts = [item for item in evidence if isinstance(item, dict)]
    expected_summary = _summary(evidence_dicts)
    if dossier.get("summary") != expected_summary:
        errors.append("provider approval authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("provider approval authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("provider approval authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every provider approval authority requirement to be covered")
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("production-dossier mode requires every provider approval authority evidence item to be fresh")
    binding_for_controls = dossier.get("source_binding") if isinstance(dossier.get("source_binding"), dict) else {}
    if mode == "production-dossier" and not _source_binding_complete(binding_for_controls):
        errors.append("production-dossier mode requires callback, webhook, provider delivery authority, and provider operations authority bindings")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("provider approval authority controls are required")
    elif dossier.get("controls") != _controls(str(mode), binding_for_controls, evidence_dicts, expected_summary):
        errors.append("provider approval authority controls do not match dossier body")
    _check_no_secret_values(dossier, errors)

    return ProviderApprovalAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_provider_approval_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    approval_request: dict[str, Any],
    approval_callback: dict[str, Any],
    webhook_receipts: list[dict[str, Any]] | None = None,
    provider_delivery_authority: dict[str, Any] | None = None,
    provider_operations_authority: dict[str, Any] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_approval_authority_dossier(
        dossier,
        approval_request=approval_request,
        approval_callback=approval_callback,
        webhook_receipts=webhook_receipts,
        provider_delivery_authority=provider_delivery_authority,
        provider_operations_authority=provider_operations_authority,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid provider approval authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "source_binding": dossier.get("source_binding"),
        "summary": dossier.get("summary"),
        "control_summary": _status_summary(dossier.get("controls", [])),
        "authority_evidence": [
            {"requirement_id": item.get("requirement_id"), "authority_kind": item.get("authority_kind"), "evidence_ref": item.get("evidence_ref"), "evidence_hash": item.get("evidence_hash"), "evidence_id": item.get("evidence_id"), "issued_at": item.get("issued_at"), "expires_at": item.get("expires_at")}
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(PROVIDER_APPROVAL_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _source_binding(
    approval_request: dict[str, Any],
    approval_callback: dict[str, Any],
    webhook_receipts: list[dict[str, Any]],
    provider_delivery_authority: dict[str, Any] | None,
    provider_operations_authority: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "approval_request": _approval_request_binding(approval_request),
        "approval_callback": _approval_callback_binding(approval_callback),
        "webhook_receipts": [_webhook_binding(receipt) for receipt in webhook_receipts],
        "provider_delivery_authority": _authority_dossier_binding(provider_delivery_authority, "provider-delivery-authority") if provider_delivery_authority else None,
        "provider_operations_authority": _authority_dossier_binding(provider_operations_authority, "provider-operations-authority") if provider_operations_authority else None,
    }


def _approval_request_binding(request: dict[str, Any]) -> dict[str, Any]:
    body = request.get("request", {}).get("body", {}) if isinstance(request.get("request"), dict) and isinstance(request.get("request", {}).get("body"), dict) else {}
    return {
        "approval_request_id": request.get("approval_request_id"),
        "approval_request_hash": content_hash(request),
        "provider": request.get("provider", "slack"),
        "pack_id": request.get("pack_id"),
        "contract_id": request.get("contract_id"),
        "contract_hash": request.get("contract_hash"),
        "channel": request.get("channel"),
        "requested_roles": sorted(str(role) for role in request.get("requested_roles", [])),
        "callback_url_hash": content_hash(request.get("callback_url")) if request.get("callback_url") else None,
        "body_hash": content_hash(body),
        "expires_at": request.get("expires_at"),
    }


def _approval_callback_binding(callback: dict[str, Any]) -> dict[str, Any]:
    return {
        "callback_id": callback.get("callback_id"),
        "callback_hash": content_hash(callback),
        "provider": callback.get("provider"),
        "approval_request_id": callback.get("approval_request_id"),
        "request_payload_hash": callback.get("request_payload_hash"),
        "pack_id": callback.get("pack_id"),
        "contract_id": callback.get("contract_id"),
        "contract_hash": callback.get("contract_hash"),
        "role": callback.get("role"),
        "action_id": callback.get("action_id"),
        "action_value_hash": content_hash(callback.get("action_value")) if callback.get("action_value") else None,
        "approver_hash": content_hash(callback.get("approver")) if callback.get("approver") else None,
        "external_user_id_hash": content_hash(callback.get("external_user_id")) if callback.get("external_user_id") else None,
        "team_id": callback.get("team_id"),
        "approved_at": callback.get("approved_at"),
    }


def _webhook_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    payload = receipt.get("payload", {}) if isinstance(receipt.get("payload"), dict) else {}
    webhook = receipt.get("webhook", {}) if isinstance(receipt.get("webhook"), dict) else {}
    verification = receipt.get("verification", {}) if isinstance(receipt.get("verification"), dict) else {}
    return {
        "receipt_id": receipt.get("receipt_id"),
        "receipt_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "received_at": receipt.get("received_at"),
        "event": webhook.get("event"),
        "delivery_id": webhook.get("delivery_id"),
        "payload_sha256": payload.get("sha256"),
        "payload_size_bytes": payload.get("size_bytes"),
        "provider_signature_verified": verification.get("provider_signature_verified"),
        "verification_method": verification.get("method"),
        "verification_header": verification.get("header"),
        "verification_value_hash": verification.get("value_hash"),
    }


def _authority_dossier_binding(dossier: dict[str, Any], source_type: str) -> dict[str, Any]:
    return {
        "source_type": source_type,
        "dossier_id": dossier.get("dossier_id"),
        "dossier_hash": content_hash(dossier),
        "schema": dossier.get("schema"),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "summary": dossier.get("summary"),
        "authority_ref": dossier.get("authority_ref"),
    }


def _verify_source_binding(
    binding: Any,
    approval_request: dict[str, Any] | None,
    approval_callback: dict[str, Any] | None,
    webhook_receipts: list[dict[str, Any]] | None,
    provider_delivery_authority: dict[str, Any] | None,
    provider_operations_authority: dict[str, Any] | None,
    errors: list[str],
    warnings: list[str],
    *,
    key: str | None,
) -> None:
    if not isinstance(binding, dict):
        errors.append("provider approval authority source_binding is required")
        return
    if not isinstance(binding.get("approval_request"), dict):
        errors.append("provider approval authority source_binding.approval_request is required")
    if not isinstance(binding.get("approval_callback"), dict):
        errors.append("provider approval authority source_binding.approval_callback is required")
    if not isinstance(binding.get("webhook_receipts"), list):
        errors.append("provider approval authority source_binding.webhook_receipts must be a list")
    _verify_binding_completeness(binding, errors)
    if approval_request is None or approval_callback is None:
        warnings.append("provider approval authority approval source not supplied; approval binding hashes were not replayed")
        return
    callback_result = verify_approval_callback(approval_request, approval_callback, key=key)
    errors.extend(f"provider approval authority callback source: {error}" for error in callback_result.errors)
    warnings.extend(f"provider approval authority callback source: {warning}" for warning in callback_result.warnings)
    webhooks = list(webhook_receipts or [])
    if webhook_receipts is None:
        warnings.append("provider approval authority webhook receipts not supplied; webhook binding hashes were not replayed")
    for receipt in webhooks:
        webhook_result = verify_provider_webhook_receipt(receipt, key=key)
        errors.extend(f"provider approval authority webhook source: {error}" for error in webhook_result.errors)
        warnings.extend(f"provider approval authority webhook source: {warning}" for warning in webhook_result.warnings)
    if provider_delivery_authority is not None:
        delivery_result = verify_provider_delivery_authority_dossier(provider_delivery_authority, key=key)
        errors.extend(f"provider approval authority provider delivery source: {error}" for error in delivery_result.errors)
        warnings.extend(f"provider approval authority provider delivery source: {warning}" for warning in delivery_result.warnings)
    if provider_operations_authority is not None:
        operations_result = verify_provider_operations_authority_dossier(provider_operations_authority, key=key)
        errors.extend(f"provider approval authority provider operations source: {error}" for error in operations_result.errors)
        warnings.extend(f"provider approval authority provider operations source: {warning}" for warning in operations_result.warnings)
    expected = _source_binding(approval_request, approval_callback, webhooks, provider_delivery_authority, provider_operations_authority)
    if binding != expected:
        errors.append("provider approval authority source_binding does not match supplied source artifacts")


def _verify_binding_completeness(binding: dict[str, Any], errors: list[str]) -> None:
    request = binding.get("approval_request") if isinstance(binding.get("approval_request"), dict) else {}
    callback = binding.get("approval_callback") if isinstance(binding.get("approval_callback"), dict) else {}
    for field in (
        "approval_request_id",
        "approval_request_hash",
        "provider",
        "pack_id",
        "contract_id",
        "contract_hash",
        "channel",
        "requested_roles",
        "callback_url_hash",
        "body_hash",
    ):
        if request.get(field) in (None, "", []):
            errors.append(f"provider approval authority source_binding.approval_request.{field} is required")
    for field in (
        "callback_id",
        "callback_hash",
        "provider",
        "approval_request_id",
        "request_payload_hash",
        "pack_id",
        "contract_id",
        "contract_hash",
        "role",
        "action_id",
        "action_value_hash",
        "approver_hash",
        "external_user_id_hash",
        "team_id",
        "approved_at",
    ):
        if callback.get(field) in (None, "", []):
            errors.append(f"provider approval authority source_binding.approval_callback.{field} is required")
    webhooks = binding.get("webhook_receipts")
    if isinstance(webhooks, list):
        for index, webhook in enumerate(webhooks):
            if not isinstance(webhook, dict):
                errors.append(f"provider approval authority source_binding.webhook_receipts[{index}] must be an object")
                continue
            for field in (
                "receipt_id",
                "receipt_hash",
                "provider",
                "received_at",
                "event",
                "delivery_id",
                "payload_sha256",
                "payload_size_bytes",
                "provider_signature_verified",
                "verification_method",
                "verification_header",
                "verification_value_hash",
            ):
                if webhook.get(field) in (None, "", []):
                    errors.append(f"provider approval authority source_binding.webhook_receipts[{index}].{field} is required")
    for key in ("provider_delivery_authority", "provider_operations_authority"):
        authority = binding.get(key)
        if authority is None:
            continue
        if not isinstance(authority, dict):
            errors.append(f"provider approval authority source_binding.{key} must be an object")
            continue
        for field in ("source_type", "dossier_id", "dossier_hash", "schema", "mode", "environment", "generated_at", "summary", "authority_ref"):
            if authority.get(field) in (None, "", []):
                errors.append(f"provider approval authority source_binding.{key}.{field} is required")


def _source_binding_complete(binding: dict[str, Any]) -> bool:
    errors: list[str] = []
    _verify_binding_completeness(binding, errors)
    return bool(
        not errors
        and isinstance(binding.get("approval_request"), dict)
        and isinstance(binding.get("approval_callback"), dict)
        and binding.get("webhook_receipts")
        and isinstance(binding.get("provider_delivery_authority"), dict)
        and isinstance(binding.get("provider_operations_authority"), dict)
    )


def _build_authority_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unsupported provider approval authority requirement: {requirement_id}")
    requirement = next(req for req in PRODUCTION_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in requirement["authority_kinds"]:
        raise ValueError(f"authority kind {authority_kind} is not valid for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (evidence_hash, "evidence_hash"), (description, "description")):
        _require_text(value, field)
    built = {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description,
    }
    for field in ("issuer", "subject", "source_uri", "issued_at", "expires_at"):
        if item.get(field):
            built[field] = str(item[field])
    for field in ("issued_at", "expires_at"):
        if built.get(field):
            parse_rfc3339(str(built[field]))
    if built.get("issued_at") and built.get("expires_at") and parse_rfc3339(str(built["issued_at"])) > parse_rfc3339(str(built["expires_at"])):
        raise ValueError("authority evidence issued_at must not be after expires_at")
    built["evidence_id"] = content_hash(built)
    return built


def _verify_authority_evidence_item(
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    now,
    require_fresh: bool,
) -> str:
    try:
        expected = _build_authority_evidence_item(item)
    except ValueError as exc:
        errors.append(f"invalid provider approval authority evidence: {exc}")
        return "missing"
    if item != expected:
        errors.append("provider approval authority evidence_id does not match evidence body")
    issued_at = item.get("issued_at")
    expires_at = item.get("expires_at")
    if not issued_at or not expires_at:
        if require_fresh:
            errors.append(f"provider approval authority evidence {item.get('requirement_id')} freshness metadata missing")
        return "missing"
    issued = parse_rfc3339(str(issued_at))
    expires = parse_rfc3339(str(expires_at))
    if issued > expires:
        errors.append(f"provider approval authority evidence {item.get('requirement_id')} issued_at is after expires_at")
        return "stale"
    if now < issued or now > expires:
        message = f"provider approval authority evidence {item.get('requirement_id')} is outside its freshness window"
        if require_fresh:
            errors.append(message)
        else:
            warnings.append(message)
        return "stale"
    return "fresh"


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("provider approval authority required_production_authority does not match the required checklist")


def _summary(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted({item.get("requirement_id") for item in evidence_items if item.get("requirement_id")})
    missing = [req_id for req_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS if req_id not in covered]
    return {
        "required_requirement_count": len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "covered_requirement_ids": covered,
        "missing_requirement_ids": missing,
        "authority_evidence_count": len(evidence_items),
    }


def _controls(mode: str, binding: dict[str, Any], evidence_items: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    freshness = _freshness_summary(evidence_items)
    missing = summary.get("missing_requirement_count", 0)
    webhook_count = len(binding.get("webhook_receipts") or []) if isinstance(binding.get("webhook_receipts"), list) else 0
    callback_bound = isinstance(binding.get("approval_callback"), dict) and bool(binding.get("approval_callback", {}).get("callback_id"))
    authority_bound = isinstance(binding.get("provider_delivery_authority"), dict) and isinstance(binding.get("provider_operations_authority"), dict)
    production_ready = mode == "production-dossier" and callback_bound and webhook_count > 0 and authority_bound and not missing and freshness["missing"] == 0
    return [
        {
            "id": "approval-callback-bound",
            "status": "passed" if callback_bound else "failed",
            "detail": "Dossier binds the signed approval callback, approval request hash, role/action binding, approver hash, and callback timestamp.",
        },
        {
            "id": "provider-webhook-receipts-bound",
            "status": "passed" if webhook_count > 0 else "deferred",
            "detail": f"{webhook_count} provider webhook receipts are hash-bound to the approval authority dossier.",
        },
        {
            "id": "provider-authority-dossiers-bound",
            "status": "passed" if authority_bound else "deferred",
            "detail": "Provider delivery and provider operations production authority dossiers are both hash-bound when available.",
        },
        {
            "id": "authority-evidence-checklist-covered",
            "status": "passed" if not missing else "deferred",
            "detail": f"{summary.get('covered_requirement_count', 0)}/{summary.get('required_requirement_count', 0)} provider approval production authority categories are covered.",
        },
        {
            "id": "freshness-windows-tracked",
            "status": "passed" if evidence_items and freshness["missing"] == 0 else "deferred",
            "detail": f"windowed={freshness['windowed']} missing_freshness={freshness['missing']}",
        },
        {
            "id": "production-mode-gated",
            "status": "passed" if production_ready else "deferred",
            "detail": "Production CI/CD approval authority is claimed only when approval, webhook, delivery, operations, and every authority category are covered with timestamped evidence windows.",
        },
        {
            "id": "raw-secret-exclusion",
            "status": "passed",
            "detail": "Dossier stores hashes and redacted references instead of raw Slack, GitHub, GitLab, or provider credentials.",
        },
    ]


def _freshness_summary(evidence_items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"windowed": 0, "missing": 0}
    for item in evidence_items:
        if item.get("issued_at") and item.get("expires_at"):
            counts["windowed"] += 1
        else:
            counts["missing"] += 1
    return counts


def _freshness_reference(dossier: dict[str, Any], now: str | None, errors: list[str]):
    value = now or dossier.get("generated_at") or utc_now()
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"freshness reference time invalid: {exc}")
        return parse_rfc3339(utc_now())


def _status_summary(controls: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        status = str(control.get("status", "unknown")) if isinstance(control, dict) else "unknown"
        summary[status] = summary.get(status, 0) + 1
    return summary


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            nested_path = f"{path}.{key_text}"
            if any(marker in key_text.lower() for marker in SECRET_KEY_MARKERS) and not _allowed_secret_reference_key(key_text):
                if isinstance(nested, str) and not _is_redacted_reference(nested):
                    errors.append(f"raw secret-like value is not allowed at {nested_path}")
            _check_no_secret_values(nested, errors, nested_path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _check_no_secret_values(nested, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str) -> bool:
    lowered = key.lower()
    return lowered.endswith(("_ref", "_hash", "_root", "_id")) or lowered in {"production-provider-credentials"}


def _is_redacted_reference(value: str) -> bool:
    return value.startswith(("env:", "vault:", "kms:", "secret-ref:", "sha256:", "hash:"))


def _require_text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")
