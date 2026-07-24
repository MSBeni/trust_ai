from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .trust_network_service import verify_trust_network_service_attestation
from .trust_network_worker import verify_trust_network_worker_receipt
from .trust_network_worker_bundle import verify_trust_network_worker_bundle

TRUST_NETWORK_AUTHORITY_SCHEMA = "trustai.trust-network-production-authority-dossier/0.1"
TRUST_NETWORK_AUTHORITY_ENTRY_TYPE = "trust_network.authority_recorded"
TRUST_NETWORK_AUTHORITY_MODES = {"local-dossier", "network-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {"id": "hosted-registry-marketplace-worker-fleet", "title": "Continuously operated hosted registry and marketplace worker fleets", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "production-scheduler-lease-storage", "title": "Production scheduler, queue, lease, checkpoint, cursor, entitlement, and subscription stores", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "live-identity-provider-event-streams", "title": "Live provider-owned identity-provider session, token, account, and app event streams", "authority_kinds": ["identity-provider", "provider-api"]},
    {"id": "identity-provider-lifecycle-worker-authority", "title": "Externally operated identity-provider lifecycle worker authority beyond local lifecycle receipts", "authority_kinds": ["identity-provider", "provider-api", "hosted-service"]},
    {"id": "immutable-account-session-token-logs", "title": "Immutable provider-owned account, session, token, and propagation logs", "authority_kinds": ["identity-provider", "provider-api", "cloud-object-lock", "customer"]},
    {"id": "registry-publication-status-propagation", "title": "Hosted trust-network registry publication, suspension, revocation, and status propagation authority", "authority_kinds": ["hosted-service", "provider-api", "customer"]},
    {"id": "marketplace-entitlement-distribution-exports", "title": "Hosted marketplace catalog, entitlement, subscription, and distribution exports", "authority_kinds": ["hosted-service", "provider-api", "customer"]},
    {"id": "provider-owned-invoice-payout-tax-custody", "title": "Provider-owned invoice, payout, revenue-share, and tax-custody exports", "authority_kinds": ["provider-api", "customer", "cloud-object-lock"]},
    {"id": "revocation-cache-invalidation-propagation", "title": "Production revocation propagation and cache-invalidation evidence", "authority_kinds": ["hosted-service", "provider-api", "identity-provider"]},
    {"id": "live-external-provider-callbacks", "title": "Live external provider callbacks for identity, procurement, registry, marketplace, and settlement operations", "authority_kinds": ["provider-api", "identity-provider", "hosted-service"]},
    {"id": "hosted-registry-marketplace-observability", "title": "Hosted registry, marketplace, worker, access, publication, and audit observability with immutable roots", "authority_kinds": ["hosted-service", "provider-api", "cloud-object-lock"]},
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]

SERVICE_ATTESTATION_BINDING_REQUIRED_FIELDS = (
    "attestation_id",
    "attestation_hash",
    "attestation_schema",
    "attestation_mode",
    "environment",
    "attested_at",
    "source_count",
    "source_hash",
    "source_schemas",
    "required_source_types",
    "service_ref",
    "service_kind",
    "service_version",
    "registry_endpoint",
    "marketplace_endpoint",
    "service_image_digest",
    "service_binary_hash",
    "frontend_bundle_ref",
    "frontend_bundle_hash",
    "api_ref",
    "registry_store_ref",
    "search_index_ref",
    "entitlement_store_ref",
    "subscription_queue_ref",
    "replicas_min",
    "replicas_max",
    "availability_zones",
    "registration_id",
    "registration_ref",
    "registration_status",
    "effective_status",
    "vendor_name",
    "buyer",
    "identity_provider",
    "identity_id",
    "procurement_contract_ref",
    "catalog_id",
    "distribution_id",
    "target",
    "subscriber",
    "auth_provider_ref",
    "identity_federation_policy_ref",
    "procurement_sync_policy_ref",
    "entitlement_policy_ref",
    "revocation_policy_ref",
    "cache_invalidation_policy_ref",
    "request_signing_ref",
    "network_policy_ref",
    "encryption_key_ref",
    "registry_audit_log_root",
    "marketplace_audit_log_root",
    "access_log_root",
    "publication_log_root",
    "metrics_ref",
    "alert_policy_ref",
    "retention_until",
    "actor_ref",
    "credential_ref",
    "marketplace_credential_ref",
    "evidence_refs",
)

WORKER_RECEIPT_BINDING_REQUIRED_FIELDS = (
    "worker_operation_id",
    "worker_operation_hash",
    "receipt_schema",
    "receipt_mode",
    "environment",
    "recorded_at",
    "source_count",
    "source_hash",
    "source_schemas",
    "required_source_types",
    "service_attestation_id",
    "service_attestation_hash",
    "service_ref",
    "service_kind",
    "service_version",
    "registry_endpoint",
    "marketplace_endpoint",
    "worker_ref",
    "run_ref",
    "operation_kind",
    "actor_ref",
    "started_at",
    "completed_at",
    "schedule_ref",
    "lease_ref",
    "checkpoint_ref",
    "checkpoint_hash",
    "previous_cursor_ref",
    "next_cursor_ref",
    "queue_ref",
    "queue_message_ref",
    "destination_ref",
    "publication_log_ref",
    "publication_log_root",
    "cache_invalidation_ref",
    "external_callback_ref",
    "request_hash",
    "response_status",
    "response_hash",
    "provider_invoice_log_ref",
    "provider_invoice_log_hash",
    "provider_payout_log_ref",
    "provider_payout_log_hash",
    "provider_tax_custody_ref",
    "provider_tax_document_hash",
    "registration_id",
    "registration_status",
    "effective_status",
    "catalog_id",
    "distribution_id",
    "governance_id",
    "settlement_id",
    "entitlement_decision",
    "invoice_ref",
    "payout_ref",
    "metrics_ref",
    "audit_log_ref",
    "audit_log_root",
    "credential_ref",
    "evidence_refs",
)

WORKER_BUNDLE_BINDING_REQUIRED_FIELDS = (
    "bundle_id",
    "bundle_hash",
    "bundle_schema",
    "bundle_mode",
    "environment",
    "generated_at",
    "reviewer_ref",
    "bundle_ref",
    "worker_operation_id",
    "worker_receipt_hash",
    "service_attestation_id",
    "service_attestation_hash",
    "service_ref",
    "registration_id",
    "registration_hash",
    "registration_ref",
    "registration_status",
    "run_ref",
    "operation_kind",
    "destination_ref",
    "response_status",
    "publication_log_root",
    "catalog_id",
    "catalog_hash",
    "distribution_id",
    "distribution_hash",
    "settlement_id",
    "settlement_hash",
    "source_artifact_count",
    "source_artifact_sha256_root",
    "source_artifact_content_root",
    "proof_pack_count",
    "marketplace_asset_count",
    "frontend_bundle_replayed",
    "marketplace_settlement_replayed",
    "worker_control_summary",
)

@dataclass
class TrustNetworkAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_trust_network_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("trust-network authority dossier must contain an object")
    return value


def write_trust_network_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_trust_network_authority_evidence_arg(value: str) -> dict[str, Any]:
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


def build_trust_network_authority_dossier(
    service_attestation: dict[str, Any],
    *,
    worker_receipts: list[dict[str, Any]] | None = None,
    worker_bundles: list[dict[str, Any]] | None = None,
    registry_receipt: dict[str, Any] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    procurement_receipt: dict[str, Any] | None = None,
    procurement_integration_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    registry_status_receipt: dict[str, Any] | None = None,
    marketplace_catalog: dict[str, Any] | None = None,
    marketplace_distribution: dict[str, Any] | None = None,
    frontend_bundle_path: str | Path | None = None,
    marketplace_author_governance: dict[str, Any] | None = None,
    marketplace_settlement: dict[str, Any] | None = None,
    root: str | Path = ".",
    source_now: str | None = None,
    mode: str = "network-dossier",
    environment: str | None = None,
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in TRUST_NETWORK_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(TRUST_NETWORK_AUTHORITY_MODES)}")
    for value, field in ((dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)
    receipts = list(worker_receipts or [])
    if not receipts:
        raise ValueError("trust-network authority requires at least one worker receipt")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    service_args = _service_source_args(
        registry_receipt=registry_receipt,
        trust_network_manifest=trust_network_manifest,
        vendor_identity_receipt=vendor_identity_receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_payload=identity_payload,
        procurement_receipt=procurement_receipt,
        procurement_integration_receipt=procurement_integration_receipt,
        proof_packs=proof_packs,
        registry_status_receipt=registry_status_receipt,
        marketplace_catalog=marketplace_catalog,
        marketplace_distribution=marketplace_distribution,
        frontend_bundle_path=frontend_bundle_path,
        root=root,
        now=source_now,
        key=key,
    )
    service_result = verify_trust_network_service_attestation(service_attestation, **service_args)
    if not service_result.ok:
        raise ValueError("invalid trust-network service source: " + "; ".join(service_result.errors))

    worker_args = _worker_source_args(
        service_attestation=service_attestation,
        registry_receipt=registry_receipt,
        trust_network_manifest=trust_network_manifest,
        vendor_identity_receipt=vendor_identity_receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_payload=identity_payload,
        procurement_receipt=procurement_receipt,
        procurement_integration_receipt=procurement_integration_receipt,
        proof_packs=proof_packs,
        registry_status_receipt=registry_status_receipt,
        marketplace_catalog=marketplace_catalog,
        marketplace_distribution=marketplace_distribution,
        frontend_bundle_path=frontend_bundle_path,
        marketplace_author_governance=marketplace_author_governance,
        marketplace_settlement=marketplace_settlement,
        root=root,
        key=key,
    )
    for receipt in receipts:
        worker_result = verify_trust_network_worker_receipt(receipt, **worker_args)
        if not worker_result.ok:
            raise ValueError("invalid trust-network worker source: " + "; ".join(worker_result.errors))
    bundles = list(worker_bundles or [])
    for bundle in bundles:
        bundle_result = verify_trust_network_worker_bundle(bundle, key=key)
        if not bundle_result.ok:
            raise ValueError("invalid trust-network worker bundle source: " + "; ".join(bundle_result.errors))

    service_binding = _service_attestation_binding(service_attestation)
    worker_bindings = [_worker_receipt_binding(receipt) for receipt in receipts]
    worker_bundle_bindings = [_worker_bundle_binding(bundle) for bundle in bundles]
    link_errors = _worker_bundle_link_errors(worker_bundle_bindings, service_binding, worker_bindings)
    if link_errors:
        raise ValueError("invalid trust-network worker bundle binding: " + "; ".join(link_errors))

    source_context = _authority_evidence_source_context(service_binding, worker_bindings, worker_bundle_bindings)
    evidence_items = [_build_authority_evidence_item(item, source_context) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body: dict[str, Any] = {
        "schema": TRUST_NETWORK_AUTHORITY_SCHEMA,
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
        "controls": _controls(mode, service_binding, worker_bindings, worker_bundle_bindings, evidence_items, summary),
        "limitations": [
            "This dossier binds verified trust-network service and worker receipts to an explicit production-authority evidence checklist.",
            "It records authority references, hashes, freshness windows, and missing live-evidence categories for hosted registry, marketplace, identity-provider, procurement, settlement, callback, and revocation operation.",
            "It does not claim continuously operated production trust-network authority unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    return {**body, "dossier_id": dossier_id, "signatures": [sign_value({"dossier_id": dossier_id, "trust_network_authority": body}, key)]}

def verify_trust_network_authority_dossier(
    dossier: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    worker_receipts: list[dict[str, Any]] | None = None,
    worker_bundles: list[dict[str, Any]] | None = None,
    registry_receipt: dict[str, Any] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    procurement_receipt: dict[str, Any] | None = None,
    procurement_integration_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    registry_status_receipt: dict[str, Any] | None = None,
    marketplace_catalog: dict[str, Any] | None = None,
    marketplace_distribution: dict[str, Any] | None = None,
    frontend_bundle_path: str | Path | None = None,
    marketplace_author_governance: dict[str, Any] | None = None,
    marketplace_settlement: dict[str, Any] | None = None,
    root: str | Path = ".",
    source_now: str | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> TrustNetworkAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != TRUST_NETWORK_AUTHORITY_SCHEMA:
        errors.append(f"unsupported trust-network authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical trust-network authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("trust-network authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "trust_network_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("trust-network authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in TRUST_NETWORK_AUTHORITY_MODES:
        errors.append("trust-network authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"trust-network authority mode is {mode}; live production trust-network authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"trust-network authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"trust-network authority {field} is required")

    service_args = _service_source_args(
        registry_receipt=registry_receipt,
        trust_network_manifest=trust_network_manifest,
        vendor_identity_receipt=vendor_identity_receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_payload=identity_payload,
        procurement_receipt=procurement_receipt,
        procurement_integration_receipt=procurement_integration_receipt,
        proof_packs=proof_packs,
        registry_status_receipt=registry_status_receipt,
        marketplace_catalog=marketplace_catalog,
        marketplace_distribution=marketplace_distribution,
        frontend_bundle_path=frontend_bundle_path,
        root=root,
        now=source_now,
        key=key,
    )
    worker_args = _worker_source_args(
        service_attestation=service_attestation,
        registry_receipt=registry_receipt,
        trust_network_manifest=trust_network_manifest,
        vendor_identity_receipt=vendor_identity_receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_payload=identity_payload,
        procurement_receipt=procurement_receipt,
        procurement_integration_receipt=procurement_integration_receipt,
        proof_packs=proof_packs,
        registry_status_receipt=registry_status_receipt,
        marketplace_catalog=marketplace_catalog,
        marketplace_distribution=marketplace_distribution,
        frontend_bundle_path=frontend_bundle_path,
        marketplace_author_governance=marketplace_author_governance,
        marketplace_settlement=marketplace_settlement,
        root=root,
        key=key,
    )
    _verify_service_attestation_binding(dossier.get("service_attestation_binding"), service_attestation, service_args, errors, warnings)
    _verify_worker_receipt_bindings(dossier.get("worker_receipt_bindings"), worker_receipts, worker_args, errors, warnings)
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
        errors.append("trust-network authority authority_evidence must be a list")
        evidence = []
    evidence_source_context = _authority_evidence_source_context(
        dossier.get("service_attestation_binding") if isinstance(dossier.get("service_attestation_binding"), dict) else {},
        dossier.get("worker_receipt_bindings") if isinstance(dossier.get("worker_receipt_bindings"), list) else [],
        dossier.get("worker_bundle_bindings") if isinstance(dossier.get("worker_bundle_bindings"), list) else [],
    )
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("trust-network authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_counts[
            _verify_authority_evidence_item(
                item,
                errors,
                warnings,
                now=freshness_now,
                require_fresh=require_fresh,
                source_context=evidence_source_context,
            )
        ] += 1

    expected_summary = _summary([item for item in evidence if isinstance(item, dict)])
    if dossier.get("summary") != expected_summary:
        errors.append("trust-network authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("trust-network authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("trust-network authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every trust-network authority requirement to be covered")
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("production-dossier mode requires every trust-network authority evidence item to be fresh")
    service_binding_for_controls = dossier.get("service_attestation_binding") if isinstance(dossier.get("service_attestation_binding"), dict) else {}
    worker_bindings_for_controls = dossier.get("worker_receipt_bindings") if isinstance(dossier.get("worker_receipt_bindings"), list) else []
    worker_bundle_bindings_for_controls = dossier.get("worker_bundle_bindings") if isinstance(dossier.get("worker_bundle_bindings"), list) else []
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("trust-network authority controls are required")
    elif dossier.get("controls") != _controls(
        str(mode),
        service_binding_for_controls,
        worker_bindings_for_controls,
        worker_bundle_bindings_for_controls,
        [item for item in evidence if isinstance(item, dict)],
        expected_summary,
    ):
        errors.append("trust-network authority controls do not match dossier body")
    _check_no_secret_values(dossier, errors)
    return TrustNetworkAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )

def append_trust_network_authority_dossier(
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
    result = verify_trust_network_authority_dossier(
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
        raise ValueError("invalid trust-network authority dossier: " + "; ".join(result.errors))
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
            {"requirement_id": item.get("requirement_id"), "authority_kind": item.get("authority_kind"), "evidence_ref": item.get("evidence_ref"), "evidence_hash": item.get("evidence_hash"), "evidence_id": item.get("evidence_id"), "issued_at": item.get("issued_at"), "expires_at": item.get("expires_at"), "source_context": item.get("source_context")}
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(TRUST_NETWORK_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _service_source_args(**kwargs: Any) -> dict[str, Any]:
    return {
        "registry_receipt": kwargs.get("registry_receipt"),
        "trust_network_manifest": kwargs.get("trust_network_manifest"),
        "vendor_identity_receipt": kwargs.get("vendor_identity_receipt"),
        "identity_provider_attestation": kwargs.get("identity_provider_attestation"),
        "identity_payload": kwargs.get("identity_payload"),
        "procurement_receipt": kwargs.get("procurement_receipt"),
        "procurement_integration_receipt": kwargs.get("procurement_integration_receipt"),
        "proof_packs": kwargs.get("proof_packs"),
        "registry_status_receipt": kwargs.get("registry_status_receipt"),
        "marketplace_catalog": kwargs.get("marketplace_catalog"),
        "marketplace_distribution": kwargs.get("marketplace_distribution"),
        "frontend_bundle_path": kwargs.get("frontend_bundle_path"),
        "root": kwargs.get("root", "."),
        "now": kwargs.get("now"),
        "key": kwargs.get("key"),
    }


def _worker_source_args(**kwargs: Any) -> dict[str, Any]:
    return {
        "service_attestation": kwargs.get("service_attestation"),
        "registry_receipt": kwargs.get("registry_receipt"),
        "trust_network_manifest": kwargs.get("trust_network_manifest"),
        "vendor_identity_receipt": kwargs.get("vendor_identity_receipt"),
        "identity_provider_attestation": kwargs.get("identity_provider_attestation"),
        "identity_payload": kwargs.get("identity_payload"),
        "procurement_receipt": kwargs.get("procurement_receipt"),
        "procurement_integration_receipt": kwargs.get("procurement_integration_receipt"),
        "proof_packs": kwargs.get("proof_packs"),
        "registry_status_receipt": kwargs.get("registry_status_receipt"),
        "marketplace_catalog": kwargs.get("marketplace_catalog"),
        "marketplace_distribution": kwargs.get("marketplace_distribution"),
        "frontend_bundle_path": kwargs.get("frontend_bundle_path"),
        "marketplace_author_governance": kwargs.get("marketplace_author_governance"),
        "marketplace_settlement": kwargs.get("marketplace_settlement"),
        "root": kwargs.get("root", "."),
        "key": kwargs.get("key"),
    }

def _service_attestation_binding(attestation: dict[str, Any]) -> dict[str, Any]:
    source = attestation.get("source", {}) if isinstance(attestation.get("source"), dict) else {}
    service = attestation.get("service", {}) if isinstance(attestation.get("service"), dict) else {}
    registry = attestation.get("registry", {}) if isinstance(attestation.get("registry"), dict) else {}
    marketplace = attestation.get("marketplace", {}) if isinstance(attestation.get("marketplace"), dict) else {}
    security = attestation.get("security", {}) if isinstance(attestation.get("security"), dict) else {}
    observability = attestation.get("observability", {}) if isinstance(attestation.get("observability"), dict) else {}
    actor = attestation.get("operation_actor", {}) if isinstance(attestation.get("operation_actor"), dict) else {}
    credential = actor.get("credential", {}) if isinstance(actor.get("credential"), dict) else {}
    marketplace_credential = actor.get("marketplace_credential", {}) if isinstance(actor.get("marketplace_credential"), dict) else {}
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
        "registry_endpoint": service.get("registry_endpoint"),
        "marketplace_endpoint": service.get("marketplace_endpoint"),
        "service_image_digest": service.get("service_image_digest"),
        "service_binary_hash": service.get("service_binary_hash"),
        "frontend_bundle_ref": service.get("frontend_bundle_ref"),
        "frontend_bundle_hash": service.get("frontend_bundle_hash"),
        "api_ref": service.get("api_ref"),
        "registry_store_ref": service.get("registry_store_ref"),
        "search_index_ref": service.get("search_index_ref"),
        "entitlement_store_ref": service.get("entitlement_store_ref"),
        "subscription_queue_ref": service.get("subscription_queue_ref"),
        "replicas_min": service.get("replicas_min"),
        "replicas_max": service.get("replicas_max"),
        "availability_zones": service.get("availability_zones"),
        "registration_id": registry.get("registration_id"),
        "registration_ref": registry.get("registration_ref"),
        "registration_status": registry.get("registration_status"),
        "effective_status": registry.get("effective_status"),
        "vendor_name": registry.get("vendor_name"),
        "buyer": registry.get("buyer"),
        "identity_provider": registry.get("identity_provider"),
        "identity_id": registry.get("identity_id"),
        "procurement_contract_ref": registry.get("procurement_contract_ref"),
        "catalog_id": marketplace.get("catalog_id"),
        "distribution_id": marketplace.get("distribution_id"),
        "target": marketplace.get("target"),
        "subscriber": marketplace.get("subscriber"),
        "auth_provider_ref": security.get("auth_provider_ref"),
        "identity_federation_policy_ref": security.get("identity_federation_policy_ref"),
        "procurement_sync_policy_ref": security.get("procurement_sync_policy_ref"),
        "entitlement_policy_ref": security.get("entitlement_policy_ref"),
        "revocation_policy_ref": security.get("revocation_policy_ref"),
        "cache_invalidation_policy_ref": security.get("cache_invalidation_policy_ref"),
        "request_signing_ref": security.get("request_signing_ref"),
        "network_policy_ref": security.get("network_policy_ref"),
        "encryption_key_ref": security.get("encryption_key_ref"),
        "registry_audit_log_root": observability.get("registry_audit_log_root"),
        "marketplace_audit_log_root": observability.get("marketplace_audit_log_root"),
        "access_log_root": observability.get("access_log_root"),
        "publication_log_root": observability.get("publication_log_root"),
        "metrics_ref": observability.get("metrics_ref"),
        "alert_policy_ref": observability.get("alert_policy_ref"),
        "retention_until": observability.get("retention_until"),
        "actor_ref": actor.get("actor_ref"),
        "credential_ref": credential.get("ref"),
        "marketplace_credential_ref": marketplace_credential.get("ref"),
        "evidence_refs": actor.get("evidence_refs"),
    }

def _worker_receipt_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    source = receipt.get("source", {}) if isinstance(receipt.get("source"), dict) else {}
    service = receipt.get("service", {}) if isinstance(receipt.get("service"), dict) else {}
    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    scheduler = receipt.get("scheduler", {}) if isinstance(receipt.get("scheduler"), dict) else {}
    propagation = receipt.get("propagation", {}) if isinstance(receipt.get("propagation"), dict) else {}
    provider_logs = propagation.get("provider_logs", {}) if isinstance(propagation.get("provider_logs"), dict) else {}
    registry = receipt.get("registry", {}) if isinstance(receipt.get("registry"), dict) else {}
    marketplace = receipt.get("marketplace", {}) if isinstance(receipt.get("marketplace"), dict) else {}
    observability = receipt.get("observability", {}) if isinstance(receipt.get("observability"), dict) else {}
    credential = receipt.get("credential", {}) if isinstance(receipt.get("credential"), dict) else {}
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
        "registry_endpoint": service.get("registry_endpoint"),
        "marketplace_endpoint": service.get("marketplace_endpoint"),
        "worker_ref": worker.get("worker_ref"),
        "run_ref": worker.get("run_ref"),
        "operation_kind": worker.get("operation_kind"),
        "actor_ref": worker.get("actor_ref"),
        "started_at": worker.get("started_at"),
        "completed_at": worker.get("completed_at"),
        "schedule_ref": scheduler.get("schedule_ref"),
        "lease_ref": scheduler.get("lease_ref"),
        "checkpoint_ref": scheduler.get("checkpoint_ref"),
        "checkpoint_hash": scheduler.get("checkpoint_hash"),
        "previous_cursor_ref": scheduler.get("previous_cursor_ref"),
        "next_cursor_ref": scheduler.get("next_cursor_ref"),
        "queue_ref": propagation.get("queue_ref"),
        "queue_message_ref": propagation.get("queue_message_ref"),
        "destination_ref": propagation.get("destination_ref"),
        "publication_log_ref": propagation.get("publication_log_ref"),
        "publication_log_root": propagation.get("publication_log_root"),
        "cache_invalidation_ref": propagation.get("cache_invalidation_ref"),
        "external_callback_ref": propagation.get("external_callback_ref"),
        "request_hash": propagation.get("request_hash"),
        "response_status": propagation.get("response_status"),
        "response_hash": propagation.get("response_hash"),
        "provider_invoice_log_ref": provider_logs.get("invoice_log_ref"),
        "provider_invoice_log_hash": provider_logs.get("invoice_log_hash"),
        "provider_payout_log_ref": provider_logs.get("payout_log_ref"),
        "provider_payout_log_hash": provider_logs.get("payout_log_hash"),
        "provider_tax_custody_ref": provider_logs.get("tax_custody_ref"),
        "provider_tax_document_hash": provider_logs.get("tax_document_hash"),
        "registration_id": registry.get("registration_id"),
        "registration_status": registry.get("registration_status"),
        "effective_status": registry.get("effective_status"),
        "catalog_id": marketplace.get("catalog_id"),
        "distribution_id": marketplace.get("distribution_id"),
        "governance_id": marketplace.get("governance_id"),
        "settlement_id": marketplace.get("settlement_id"),
        "entitlement_decision": marketplace.get("entitlement_decision"),
        "invoice_ref": marketplace.get("invoice_ref"),
        "payout_ref": marketplace.get("payout_ref"),
        "metrics_ref": observability.get("metrics_ref"),
        "audit_log_ref": observability.get("audit_log_ref"),
        "audit_log_root": observability.get("audit_log_root"),
        "credential_ref": credential.get("ref"),
        "evidence_refs": observability.get("evidence_refs"),
    }

def _verify_service_attestation_binding(binding: Any, service_attestation: dict[str, Any] | None, source_args: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    if not isinstance(binding, dict):
        errors.append("trust-network authority service_attestation_binding must be an object")
        return
    _verify_binding_required_fields(
        binding,
        SERVICE_ATTESTATION_BINDING_REQUIRED_FIELDS,
        "trust-network authority service_attestation_binding",
        errors,
    )
    if service_attestation is None:
        warnings.append("trust-network authority service attestation artifact was not supplied; service hash was not replayed")
        return
    expected = _service_attestation_binding(service_attestation)
    if binding != expected:
        errors.append("trust-network authority service_attestation_binding does not match supplied service attestation")
    result = verify_trust_network_service_attestation(service_attestation, **source_args)
    if not result.ok:
        errors.extend(f"trust-network authority service source: {error}" for error in result.errors)
    warnings.extend(f"trust-network authority service source: {warning}" for warning in result.warnings)


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
        "service_ref": source.get("service_ref"),
        "registration_id": source.get("registration_id"),
        "registration_hash": source.get("registration_hash"),
        "registration_ref": source.get("registration_ref"),
        "registration_status": source.get("registration_status"),
        "run_ref": source.get("run_ref"),
        "operation_kind": source.get("operation_kind"),
        "destination_ref": source.get("destination_ref"),
        "response_status": source.get("response_status"),
        "publication_log_root": source.get("publication_log_root"),
        "catalog_id": source.get("catalog_id"),
        "catalog_hash": source.get("catalog_hash"),
        "distribution_id": source.get("distribution_id"),
        "distribution_hash": source.get("distribution_hash"),
        "settlement_id": source.get("settlement_id"),
        "settlement_hash": source.get("settlement_hash"),
        "source_artifact_count": summary.get("source_artifact_count"),
        "source_artifact_sha256_root": summary.get("source_artifact_sha256_root"),
        "source_artifact_content_root": summary.get("source_artifact_content_root"),
        "proof_pack_count": summary.get("proof_pack_count"),
        "marketplace_asset_count": summary.get("marketplace_asset_count"),
        "frontend_bundle_replayed": summary.get("frontend_bundle_replayed"),
        "marketplace_settlement_replayed": summary.get("marketplace_settlement_replayed"),
        "worker_control_summary": summary.get("worker_control_summary"),
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
            errors.append("trust-network authority worker bundle does not reference supplied service attestation hash")
        if service_id and binding.get("service_attestation_id") != service_id:
            errors.append("trust-network authority worker bundle does not reference supplied service attestation id")
        if worker_ids and binding.get("worker_operation_id") not in worker_ids:
            errors.append("trust-network authority worker bundle does not reference a supplied worker receipt id")
        if worker_hashes and binding.get("worker_receipt_hash") not in worker_hashes:
            errors.append("trust-network authority worker bundle does not reference a supplied worker receipt hash")
    return errors


def _verify_worker_bundle_bindings(bindings: Any, worker_bundles: list[dict[str, Any]] | None, service_binding: Any, worker_bindings: Any, key: str | None, errors: list[str], warnings: list[str]) -> None:
    if bindings is None:
        if worker_bundles:
            errors.append("trust-network authority worker_bundle_bindings are required when worker bundles are supplied")
        return
    if not isinstance(bindings, list):
        errors.append("trust-network authority worker_bundle_bindings must be a list")
        return
    for binding in bindings:
        if not isinstance(binding, dict):
            errors.append("trust-network authority worker_bundle_binding must be an object")
            continue
        _verify_binding_required_fields(
            binding,
            WORKER_BUNDLE_BINDING_REQUIRED_FIELDS,
            "trust-network authority worker_bundle_binding",
            errors,
        )
    errors.extend(_worker_bundle_link_errors(bindings, service_binding, worker_bindings))
    if not worker_bundles:
        if bindings:
            warnings.append("trust-network authority worker bundles were not supplied; worker bundle hashes were not replayed")
        return
    expected = [_worker_bundle_binding(bundle) for bundle in worker_bundles]
    if bindings != expected:
        errors.append("trust-network authority worker_bundle_bindings do not match supplied worker bundles")
    for bundle in worker_bundles:
        result = verify_trust_network_worker_bundle(bundle, key=key)
        if not result.ok:
            errors.extend(f"trust-network authority worker bundle source: {error}" for error in result.errors)
        warnings.extend(f"trust-network authority worker bundle source: {warning}" for warning in result.warnings)

def _verify_worker_receipt_bindings(bindings: Any, worker_receipts: list[dict[str, Any]] | None, source_args: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    if not isinstance(bindings, list) or not bindings:
        errors.append("trust-network authority worker_receipt_bindings must be a non-empty list")
        return
    for binding in bindings:
        if not isinstance(binding, dict):
            errors.append("trust-network authority worker receipt binding must be an object")
            continue
        _verify_binding_required_fields(
            binding,
            WORKER_RECEIPT_BINDING_REQUIRED_FIELDS,
            "trust-network authority worker_receipt_binding",
            errors,
        )
    receipts = list(worker_receipts or [])
    if not receipts:
        warnings.append("trust-network authority worker receipt artifacts were not supplied; worker hashes were not replayed")
        return
    if len(bindings) != len(receipts):
        errors.append("trust-network authority worker receipt binding count does not match supplied worker receipts")
        return
    expected_by_hash = {content_hash(receipt): _worker_receipt_binding(receipt) for receipt in receipts}
    for binding in bindings:
        if not isinstance(binding, dict):
            errors.append("trust-network authority worker receipt binding must be an object")
            continue
        expected = expected_by_hash.get(binding.get("worker_operation_hash"))
        if expected is None:
            errors.append(f"trust-network authority worker receipt binding is not backed by supplied receipt: {binding.get('worker_operation_id')}")
            continue
        if binding != expected:
            errors.append(f"trust-network authority worker receipt binding does not match supplied worker receipt: {binding.get('worker_operation_id')}")
    for receipt in receipts:
        result = verify_trust_network_worker_receipt(receipt, **source_args)
        if not result.ok:
            errors.extend(f"trust-network authority worker source: {error}" for error in result.errors)
        warnings.extend(f"trust-network authority worker source: {warning}" for warning in result.warnings)

def _verify_binding_required_fields(binding: dict[str, Any], fields: tuple[str, ...], label: str, errors: list[str]) -> None:
    for field in fields:
        if binding.get(field) in (None, "", []):
            errors.append(f"{label}.{field} is required")

def _build_authority_evidence_item(item: dict[str, Any], source_context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unknown trust-network production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in _requirement_authority_kinds(requirement_id):
        raise ValueError(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (evidence_hash, "evidence_hash"), (description, "description")):
        _require_text(value, field)
    evidence_hash = _normalize_sha256_ref(evidence_hash, "evidence_hash")
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
        errors.append(f"trust-network authority evidence_id does not match evidence body: {item.get('requirement_id')}")
    requirement_id = item.get("requirement_id")
    authority_kind = item.get("authority_kind")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        errors.append(f"unknown trust-network production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    elif requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS and authority_kind not in _requirement_authority_kinds(str(requirement_id)):
        errors.append(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for field in ("evidence_ref", "evidence_hash", "description"):
        if not item.get(field):
            errors.append(f"trust-network authority {field} is required: {requirement_id}")
    if item.get("evidence_hash"):
        try:
            normalized_hash = _normalize_sha256_ref(str(item.get("evidence_hash")), "evidence_hash")
        except ValueError as exc:
            errors.append(f"invalid trust-network authority evidence: {exc}")
            return "missing"
        if item.get("evidence_hash") != normalized_hash:
            errors.append(f"trust-network authority evidence_hash is not canonical lowercase sha256: {requirement_id}")
    if not isinstance(item.get("source_context"), dict):
        errors.append(f"trust-network authority source_context is required: {requirement_id}")
    elif item.get("source_context") != source_context:
        errors.append(f"trust-network authority source_context does not match source bindings: {requirement_id}")

    issued_at = _parse_optional_timestamp(item, "issued_at", errors)
    expires_at = _parse_optional_timestamp(item, "expires_at", errors)
    freshness_status = "fresh"
    missing_fields = [field for field in ("issued_at", "expires_at") if not item.get(field)]
    if missing_fields:
        freshness_status = "missing"
        _freshness_problem(f"trust-network authority freshness metadata missing for {requirement_id}: {', '.join(missing_fields)}", errors, warnings, require_fresh=require_fresh)
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        freshness_status = "stale"
        errors.append(f"trust-network authority expires_at must be after issued_at: {requirement_id}")
    if now is not None and issued_at is not None and issued_at > now:
        freshness_status = "stale"
        _freshness_problem(f"trust-network authority evidence is not yet issued for {requirement_id}: {item.get('issued_at')}", errors, warnings, require_fresh=require_fresh)
    if now is not None and expires_at is not None and expires_at <= now:
        freshness_status = "stale"
        _freshness_problem(f"trust-network authority evidence expired for {requirement_id}: {item.get('expires_at')}", errors, warnings, require_fresh=require_fresh)
    return freshness_status


def _authority_evidence_source_context(
    service_binding: dict[str, Any],
    worker_bindings: list[Any],
    worker_bundle_bindings: list[Any],
) -> dict[str, Any]:
    valid_workers = [binding for binding in worker_bindings if isinstance(binding, dict)]
    valid_bundles = [binding for binding in worker_bundle_bindings if isinstance(binding, dict)]
    return {
        "service_attestation_id": service_binding.get("attestation_id"),
        "service_attestation_hash": service_binding.get("attestation_hash"),
        "environment": service_binding.get("environment"),
        "service_ref": service_binding.get("service_ref"),
        "service_kind": service_binding.get("service_kind"),
        "service_version": service_binding.get("service_version"),
        "registry_endpoint": service_binding.get("registry_endpoint"),
        "marketplace_endpoint": service_binding.get("marketplace_endpoint"),
        "frontend_bundle_hash": service_binding.get("frontend_bundle_hash"),
        "registry_store_ref": service_binding.get("registry_store_ref"),
        "entitlement_store_ref": service_binding.get("entitlement_store_ref"),
        "subscription_queue_ref": service_binding.get("subscription_queue_ref"),
        "registration_id": service_binding.get("registration_id"),
        "registration_status": service_binding.get("registration_status"),
        "effective_status": service_binding.get("effective_status"),
        "catalog_id": service_binding.get("catalog_id"),
        "distribution_id": service_binding.get("distribution_id"),
        "auth_provider_ref": service_binding.get("auth_provider_ref"),
        "identity_federation_policy_ref": service_binding.get("identity_federation_policy_ref"),
        "procurement_sync_policy_ref": service_binding.get("procurement_sync_policy_ref"),
        "entitlement_policy_ref": service_binding.get("entitlement_policy_ref"),
        "revocation_policy_ref": service_binding.get("revocation_policy_ref"),
        "cache_invalidation_policy_ref": service_binding.get("cache_invalidation_policy_ref"),
        "request_signing_ref": service_binding.get("request_signing_ref"),
        "network_policy_ref": service_binding.get("network_policy_ref"),
        "registry_audit_log_root": service_binding.get("registry_audit_log_root"),
        "marketplace_audit_log_root": service_binding.get("marketplace_audit_log_root"),
        "access_log_root": service_binding.get("access_log_root"),
        "publication_log_root": service_binding.get("publication_log_root"),
        "metrics_ref": service_binding.get("metrics_ref"),
        "retention_until": service_binding.get("retention_until"),
        "actor_ref": service_binding.get("actor_ref"),
        "credential_ref": service_binding.get("credential_ref"),
        "marketplace_credential_ref": service_binding.get("marketplace_credential_ref"),
        "service_source_hash": service_binding.get("source_hash"),
        "service_evidence_refs": service_binding.get("evidence_refs"),
        "worker_operation_ids": _sorted_present(binding.get("worker_operation_id") for binding in valid_workers),
        "worker_operation_hashes": _sorted_present(binding.get("worker_operation_hash") for binding in valid_workers),
        "worker_run_refs": _sorted_present(binding.get("run_ref") for binding in valid_workers),
        "worker_operation_kinds": _sorted_present(binding.get("operation_kind") for binding in valid_workers),
        "worker_schedule_refs": _sorted_present(binding.get("schedule_ref") for binding in valid_workers),
        "worker_lease_refs": _sorted_present(binding.get("lease_ref") for binding in valid_workers),
        "worker_checkpoint_refs": _sorted_present(binding.get("checkpoint_ref") for binding in valid_workers),
        "worker_queue_refs": _sorted_present(binding.get("queue_ref") for binding in valid_workers),
        "worker_queue_message_refs": _sorted_present(binding.get("queue_message_ref") for binding in valid_workers),
        "worker_destination_refs": _sorted_present(binding.get("destination_ref") for binding in valid_workers),
        "worker_publication_log_roots": _sorted_present(binding.get("publication_log_root") for binding in valid_workers),
        "worker_cache_invalidation_refs": _sorted_present(binding.get("cache_invalidation_ref") for binding in valid_workers),
        "worker_external_callback_refs": _sorted_present(binding.get("external_callback_ref") for binding in valid_workers),
        "worker_request_hashes": _sorted_present(binding.get("request_hash") for binding in valid_workers),
        "worker_response_hashes": _sorted_present(binding.get("response_hash") for binding in valid_workers),
        "worker_provider_invoice_log_hashes": _sorted_present(binding.get("provider_invoice_log_hash") for binding in valid_workers),
        "worker_provider_payout_log_hashes": _sorted_present(binding.get("provider_payout_log_hash") for binding in valid_workers),
        "worker_provider_tax_document_hashes": _sorted_present(binding.get("provider_tax_document_hash") for binding in valid_workers),
        "worker_audit_log_roots": _sorted_present(binding.get("audit_log_root") for binding in valid_workers),
        "worker_evidence_refs": _sorted_present(ref for binding in valid_workers for ref in (binding.get("evidence_refs") or []) if isinstance(binding.get("evidence_refs"), list)),
        "worker_bundle_ids": _sorted_present(binding.get("bundle_id") for binding in valid_bundles),
        "worker_bundle_hashes": _sorted_present(binding.get("bundle_hash") for binding in valid_bundles),
        "worker_bundle_source_roots": _sorted_present(binding.get("source_artifact_sha256_root") for binding in valid_bundles),
        "worker_bundle_content_roots": _sorted_present(binding.get("source_artifact_content_root") for binding in valid_bundles),
        "worker_bundle_frontend_replayed": _sorted_present(binding.get("frontend_bundle_replayed") for binding in valid_bundles),
        "worker_bundle_settlement_replayed": _sorted_present(binding.get("marketplace_settlement_replayed") for binding in valid_bundles),
    }


def _sorted_present(values: Any) -> list[Any]:
    return sorted(value for value in values if value not in (None, "", []))


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("trust-network authority required_production_authority does not match v0.1 requirements")


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


def _controls(mode: str, service_binding: dict[str, Any], worker_bindings: list[Any], worker_bundle_bindings: list[Any], evidence: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"name": "service_attestation_replayed", "status": "passed", "detail": "The dossier builder replayed the trust-network service attestation and supplied source evidence when available."},
        {"name": "worker_receipts_bound", "status": "passed" if service_binding.get("attestation_id") and worker_bindings else "failed", "detail": "The dossier binds trust-network worker operation IDs, service hashes, scheduler, queue, marketplace, settlement, propagation, provider-log, response, audit, and credential refs."},
        {"name": "worker_review_bundles_bound", "status": "passed" if worker_bundle_bindings else "deferred", "detail": "Optional worker review bundles bind offline source-byte replay, marketplace asset replay, frontend bundle replay, and procurement review evidence to the authority dossier."},
        {"name": "authority_evidence_manifested", "status": "passed" if evidence else "deferred", "detail": "External trust-network authority evidence references are hash-bound when supplied."},
        {"name": "freshness_windows_tracked", "status": "passed" if evidence and summary["freshness_window_count"] == len(evidence) else "deferred", "detail": "Issued/expires freshness windows are tracked for every supplied authority item when available."},
        {"name": "complete_live_authority", "status": "passed" if summary["missing_requirement_count"] == 0 else "deferred", "detail": "Every trust-network production authority requirement must be covered before this can claim live hosted cross-org trust-network authority."},
        {"name": "production_claim_limited", "status": "passed" if mode != "production-dossier" or summary["missing_requirement_count"] == 0 else "failed", "detail": "Non-production dossier modes explicitly avoid claiming live hosted registry, marketplace, identity-provider, lifecycle, settlement, callback, and revocation operation."},
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
        errors.append(f"trust-network authority freshness {label} invalid: {exc}")
        return None


def _parse_optional_timestamp(item: dict[str, Any], field: str, errors: list[str]) -> Any:
    value = item.get(field)
    if not value:
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"trust-network authority {field} invalid: {exc}")
        return None


def _freshness_problem(message: str, errors: list[str], warnings: list[str], *, require_fresh: bool) -> None:
    if require_fresh:
        errors.append(message)
    else:
        warnings.append(message)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"trust-network authority {field} is required")
    return value


def _normalize_sha256_ref(value: str | None, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")
    if not value.startswith("sha256:"):
        raise ValueError(f"{field} must start with sha256:")
    hexdigest = value.removeprefix("sha256:")
    if len(hexdigest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in hexdigest):
        raise ValueError(f"{field} must contain a 64-character sha256 digest")
    return "sha256:" + hexdigest.lower()


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}"
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"trust-network authority contains secret-like field {child_path}; store only redacted refs")
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
