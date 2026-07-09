from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .marketplace import verify_marketplace_catalog, verify_marketplace_distribution
from .trust_network_registry import verify_trust_network_registry_receipt
from .trust_network_registry_status import verify_trust_network_registry_status_receipt

TRUST_NETWORK_SERVICE_SCHEMA = "trustai.trust-network-service-attestation/0.1"
TRUST_NETWORK_SERVICE_ENTRY_TYPE = "trust_network.service_attested"
TRUST_NETWORK_SERVICE_MODES = {"local-reference", "hosted-service-attested", "production-design"}
TRUST_NETWORK_SERVICE_KINDS = {"registry", "marketplace", "registry-marketplace", "procurement-federation"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class TrustNetworkServiceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_trust_network_service_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("trust-network service attestation must contain an object")
    return value


def write_trust_network_service_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_trust_network_service_attestation(
    registry_receipt: dict[str, Any],
    *,
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
    root: str | Path = ".",
    mode: str = "hosted-service-attested",
    environment: str = "local",
    service_kind: str = "registry-marketplace",
    service_ref: str,
    service_version: str,
    registry_endpoint: str,
    marketplace_endpoint: str,
    service_image: str,
    service_image_digest: str,
    service_binary_hash: str,
    frontend_bundle_ref: str,
    frontend_bundle_hash: str,
    api_ref: str,
    registry_store_ref: str,
    search_index_ref: str,
    entitlement_store_ref: str,
    subscription_queue_ref: str,
    auth_provider_ref: str,
    vendor_auth_policy_ref: str,
    buyer_auth_policy_ref: str,
    subscriber_auth_policy_ref: str,
    rbac_policy_ref: str,
    identity_federation_policy_ref: str,
    procurement_sync_policy_ref: str,
    entitlement_policy_ref: str,
    catalog_review_policy_ref: str,
    revocation_policy_ref: str,
    cache_invalidation_policy_ref: str,
    tenant_isolation_ref: str,
    rate_limit_policy_ref: str,
    request_signing_ref: str,
    network_policy_ref: str,
    egress_policy_ref: str,
    encryption_key_ref: str,
    replicas_min: int,
    replicas_max: int,
    availability_zones: list[str] | None,
    registry_audit_log_ref: str,
    registry_audit_log_root: str,
    marketplace_audit_log_ref: str,
    marketplace_audit_log_root: str,
    access_log_ref: str,
    access_log_root: str,
    publication_log_ref: str,
    publication_log_root: str,
    metrics_ref: str,
    alert_policy_ref: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    marketplace_credential_ref: str,
    evidence_refs: list[str] | None = None,
    now: str | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in TRUST_NETWORK_SERVICE_MODES:
        raise ValueError(f"mode must be one of {sorted(TRUST_NETWORK_SERVICE_MODES)}")
    if service_kind not in TRUST_NETWORK_SERVICE_KINDS:
        raise ValueError(f"service_kind must be one of {sorted(TRUST_NETWORK_SERVICE_KINDS)}")
    if (marketplace_catalog is None) != (marketplace_distribution is None):
        raise ValueError("marketplace_catalog and marketplace_distribution must be supplied together")
    if service_kind in {"marketplace", "registry-marketplace"} and marketplace_catalog is None:
        raise ValueError("marketplace_catalog and marketplace_distribution are required for marketplace service attestations")

    registry_result = verify_trust_network_registry_receipt(
        registry_receipt,
        trust_network_manifest=trust_network_manifest,
        vendor_identity_receipt=vendor_identity_receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_payload=identity_payload,
        procurement_receipt=procurement_receipt,
        procurement_integration_receipt=procurement_integration_receipt,
        proof_packs=proof_packs,
        key=key,
        now=now,
    )
    if not registry_result.ok:
        raise ValueError("invalid trust-network registry source: " + "; ".join(registry_result.errors))

    if registry_status_receipt is not None:
        status_result = verify_trust_network_registry_status_receipt(
            registry_status_receipt,
            registry_receipt=registry_receipt,
            trust_network_manifest=trust_network_manifest,
            vendor_identity_receipt=vendor_identity_receipt,
            identity_provider_attestation=identity_provider_attestation,
            identity_payload=identity_payload,
            procurement_receipt=procurement_receipt,
            procurement_integration_receipt=procurement_integration_receipt,
            proof_packs=proof_packs,
            key=key,
            now=now,
        )
        if not status_result.ok:
            raise ValueError("invalid trust-network registry status source: " + "; ".join(status_result.errors))

    if marketplace_catalog is not None:
        catalog_result = verify_marketplace_catalog(marketplace_catalog, root=root)
        if not catalog_result.ok:
            raise ValueError("invalid marketplace catalog source: " + "; ".join(catalog_result.errors))
        distribution_result = verify_marketplace_distribution(
            marketplace_distribution or {},
            catalog=marketplace_catalog,
            root=root,
            key=key,
        )
        if not distribution_result.ok:
            raise ValueError("invalid marketplace distribution source: " + "; ".join(distribution_result.errors))

    timestamp = attested_at or utc_now()
    attested = parse_rfc3339(timestamp)
    retention = parse_rfc3339(retention_until)
    if retention <= attested:
        raise ValueError("retention_until must be after attested_at")

    for field, value in {
        "environment": environment,
        "service_ref": service_ref,
        "service_version": service_version,
        "registry_endpoint": registry_endpoint,
        "marketplace_endpoint": marketplace_endpoint,
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "frontend_bundle_ref": frontend_bundle_ref,
        "frontend_bundle_hash": frontend_bundle_hash,
        "api_ref": api_ref,
        "registry_store_ref": registry_store_ref,
        "search_index_ref": search_index_ref,
        "entitlement_store_ref": entitlement_store_ref,
        "subscription_queue_ref": subscription_queue_ref,
        "auth_provider_ref": auth_provider_ref,
        "vendor_auth_policy_ref": vendor_auth_policy_ref,
        "buyer_auth_policy_ref": buyer_auth_policy_ref,
        "subscriber_auth_policy_ref": subscriber_auth_policy_ref,
        "rbac_policy_ref": rbac_policy_ref,
        "identity_federation_policy_ref": identity_federation_policy_ref,
        "procurement_sync_policy_ref": procurement_sync_policy_ref,
        "entitlement_policy_ref": entitlement_policy_ref,
        "catalog_review_policy_ref": catalog_review_policy_ref,
        "revocation_policy_ref": revocation_policy_ref,
        "cache_invalidation_policy_ref": cache_invalidation_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "request_signing_ref": request_signing_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "encryption_key_ref": encryption_key_ref,
        "registry_audit_log_ref": registry_audit_log_ref,
        "registry_audit_log_root": registry_audit_log_root,
        "marketplace_audit_log_ref": marketplace_audit_log_ref,
        "marketplace_audit_log_root": marketplace_audit_log_root,
        "access_log_ref": access_log_ref,
        "access_log_root": access_log_root,
        "publication_log_ref": publication_log_ref,
        "publication_log_root": publication_log_root,
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
        "marketplace_credential_ref": marketplace_credential_ref,
    }.items():
        _require_text(value, field)

    source_artifacts = _source_artifacts(
        registry_receipt=registry_receipt,
        registry_status_receipt=registry_status_receipt,
        marketplace_catalog=marketplace_catalog,
        marketplace_distribution=marketplace_distribution,
    )
    service = {
        "service_ref": service_ref,
        "version": service_version,
        "service_kind": service_kind,
        "registry_endpoint": registry_endpoint,
        "marketplace_endpoint": marketplace_endpoint,
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "frontend_bundle_ref": frontend_bundle_ref,
        "frontend_bundle_hash": frontend_bundle_hash,
        "api_ref": api_ref,
        "registry_store_ref": registry_store_ref,
        "search_index_ref": search_index_ref,
        "entitlement_store_ref": entitlement_store_ref,
        "subscription_queue_ref": subscription_queue_ref,
        "replicas_min": replicas_min,
        "replicas_max": replicas_max,
        "availability_zones": sorted(availability_zones or []),
    }
    registry = _registry_record(registry_receipt, registry_status_receipt)
    marketplace = _marketplace_record(marketplace_catalog, marketplace_distribution)
    security = {
        "auth_provider_ref": auth_provider_ref,
        "vendor_auth_policy_ref": vendor_auth_policy_ref,
        "buyer_auth_policy_ref": buyer_auth_policy_ref,
        "subscriber_auth_policy_ref": subscriber_auth_policy_ref,
        "rbac_policy_ref": rbac_policy_ref,
        "identity_federation_policy_ref": identity_federation_policy_ref,
        "procurement_sync_policy_ref": procurement_sync_policy_ref,
        "entitlement_policy_ref": entitlement_policy_ref,
        "catalog_review_policy_ref": catalog_review_policy_ref,
        "revocation_policy_ref": revocation_policy_ref,
        "cache_invalidation_policy_ref": cache_invalidation_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "request_signing_ref": request_signing_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "encryption_key_ref": encryption_key_ref,
    }
    observability = {
        "registry_audit_log_ref": registry_audit_log_ref,
        "registry_audit_log_root": registry_audit_log_root,
        "marketplace_audit_log_ref": marketplace_audit_log_ref,
        "marketplace_audit_log_root": marketplace_audit_log_root,
        "access_log_ref": access_log_ref,
        "access_log_root": access_log_root,
        "publication_log_ref": publication_log_ref,
        "publication_log_root": publication_log_root,
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
        "retention_until": retention_until,
    }
    operation_actor = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "marketplace_credential": _redacted_ref(marketplace_credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    body: dict[str, Any] = {
        "schema": TRUST_NETWORK_SERVICE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": _source_summary(source_artifacts),
        "service": service,
        "registry": registry,
        "marketplace": marketplace,
        "security": security,
        "observability": observability,
        "operation_actor": operation_actor,
        "source_artifacts": source_artifacts,
        "controls": _controls(service, registry, marketplace, security, observability),
        "limitations": [
            "This attestation binds trust-network registry and marketplace source receipts to hosted service hardening evidence.",
            "It records service image, endpoint, frontend bundle, API, registry store, search, entitlement, subscription queue, identity federation, procurement sync, revocation, audit, access-log, publication-log, metrics, alerting, actor, and redacted credential evidence.",
            "It stores redacted credential references and artifact hashes, not raw IdP tokens, procurement credentials, marketplace credentials, vendor private data, or customer proof-pack payloads.",
            "Production deployments should replace local/reference endpoints with authenticated hosted trust-network and marketplace operations, live vendor identity-provider callbacks, immutable registry propagation logs, marketplace entitlement logs, and signed status-distribution receipts.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "trust_network_service": body}, key)],
    }


def verify_trust_network_service_attestation(
    attestation: dict[str, Any],
    registry_receipt: dict[str, Any] | None = None,
    *,
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
    root: str | Path = ".",
    now: str | None = None,
    key: str | None = None,
) -> TrustNetworkServiceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != TRUST_NETWORK_SERVICE_SCHEMA:
        errors.append(f"unsupported trust-network service attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical trust-network service attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("trust-network service attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "trust_network_service": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("trust-network service attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"trust-network service attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in TRUST_NETWORK_SERVICE_MODES:
        errors.append("trust-network service mode is unsupported")
    elif mode != "hosted-service-attested":
        warnings.append(f"trust-network service mode is {mode}; hosted trust-network operation is not fully claimed")

    service_kind = _verify_service(attestation.get("service"), errors)
    _verify_source(attestation.get("source"), service_kind, errors)
    _verify_registry(attestation.get("registry"), service_kind, errors)
    _verify_marketplace(attestation.get("marketplace"), service_kind, errors)
    _verify_required_object(attestation.get("security"), "security", errors)
    _verify_observability(attestation.get("observability"), attested, errors)
    _verify_actor(attestation.get("operation_actor"), errors)
    _check_no_secret_values(attestation, errors)

    source_artifacts = attestation.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("trust-network service source_artifacts are required")
        source_artifacts = []

    supplied_records = _source_artifacts(
        registry_receipt=registry_receipt,
        registry_status_receipt=registry_status_receipt,
        marketplace_catalog=marketplace_catalog,
        marketplace_distribution=marketplace_distribution,
    )
    if supplied_records and source_artifacts:
        for expected in supplied_records:
            actual = _artifact_by_type(source_artifacts, str(expected.get("type")))
            if actual != expected:
                errors.append(f"trust-network service source artifact mismatch for {expected.get('type')}")
        if len(supplied_records) == len(source_artifacts) and attestation.get("source") != _source_summary(supplied_records):
            errors.append("trust-network service source summary does not match supplied source artifacts")

    if registry_receipt is None:
        warnings.append("trust-network registry source was not supplied; registry service binding was not replayed")
    else:
        registry_result = verify_trust_network_registry_receipt(
            registry_receipt,
            trust_network_manifest=trust_network_manifest,
            vendor_identity_receipt=vendor_identity_receipt,
            identity_provider_attestation=identity_provider_attestation,
            identity_payload=identity_payload,
            procurement_receipt=procurement_receipt,
            procurement_integration_receipt=procurement_integration_receipt,
            proof_packs=proof_packs,
            key=key,
            now=now,
        )
        errors.extend(f"trust-network registry source: {error}" for error in registry_result.errors)
        warnings.extend(f"trust-network registry source: {warning}" for warning in registry_result.warnings)
        _verify_registry_matches_source(attestation.get("registry"), registry_receipt, registry_status_receipt, errors)

    if registry_status_receipt is None:
        if isinstance(attestation.get("registry"), dict) and attestation["registry"].get("status_id"):
            warnings.append("trust-network registry status source was not supplied; status propagation binding was not replayed")
    else:
        status_result = verify_trust_network_registry_status_receipt(
            registry_status_receipt,
            registry_receipt=registry_receipt,
            trust_network_manifest=trust_network_manifest,
            vendor_identity_receipt=vendor_identity_receipt,
            identity_provider_attestation=identity_provider_attestation,
            identity_payload=identity_payload,
            procurement_receipt=procurement_receipt,
            procurement_integration_receipt=procurement_integration_receipt,
            proof_packs=proof_packs,
            key=key,
            now=now,
        )
        errors.extend(f"trust-network registry status source: {error}" for error in status_result.errors)
        warnings.extend(f"trust-network registry status source: {warning}" for warning in status_result.warnings)

    if marketplace_catalog is None:
        if service_kind in {"marketplace", "registry-marketplace"}:
            warnings.append("marketplace catalog source was not supplied; marketplace service binding was not replayed")
    else:
        catalog_result = verify_marketplace_catalog(marketplace_catalog, root=root)
        errors.extend(f"marketplace catalog source: {error}" for error in catalog_result.errors)
        warnings.extend(f"marketplace catalog source: {warning}" for warning in catalog_result.warnings)

    if marketplace_distribution is None:
        if service_kind in {"marketplace", "registry-marketplace"}:
            warnings.append("marketplace distribution source was not supplied; marketplace delivery binding was not replayed")
    else:
        distribution_result = verify_marketplace_distribution(
            marketplace_distribution,
            catalog=marketplace_catalog,
            root=root,
            key=key,
        )
        errors.extend(f"marketplace distribution source: {error}" for error in distribution_result.errors)
        warnings.extend(f"marketplace distribution source: {warning}" for warning in distribution_result.warnings)
        _verify_marketplace_matches_source(attestation.get("marketplace"), marketplace_catalog, marketplace_distribution, errors)

    return TrustNetworkServiceVerification(ok=not errors, errors=errors, warnings=warnings)


def append_trust_network_service_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    registry_receipt: dict[str, Any] | None = None,
    *,
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
    root: str | Path = ".",
    now: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_trust_network_service_attestation(
        attestation,
        registry_receipt,
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
        root=root,
        now=now,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid trust-network service attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "service": attestation.get("service"),
        "registry": attestation.get("registry"),
        "marketplace": attestation.get("marketplace"),
        "source": attestation.get("source"),
        "controls": attestation.get("controls", []),
        "control_status_summary": _status_summary(attestation.get("controls", [])),
        "limitations": attestation.get("limitations", []),
    }
    return chain.append(TRUST_NETWORK_SERVICE_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _source_artifacts(
    *,
    registry_receipt: dict[str, Any] | None = None,
    registry_status_receipt: dict[str, Any] | None = None,
    marketplace_catalog: dict[str, Any] | None = None,
    marketplace_distribution: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name, value in (
        ("trust-network-registry", registry_receipt),
        ("trust-network-registry-status", registry_status_receipt),
        ("marketplace-catalog", marketplace_catalog),
        ("marketplace-distribution", marketplace_distribution),
    ):
        if isinstance(value, dict):
            records.append({"type": name, "id": _source_id(value), "schema": value.get("schema"), "hash": content_hash(value)})
    return records


def _source_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_count": len(records),
        "source_hash": content_hash(records),
        "schemas": sorted({str(record.get("schema")) for record in records if record.get("schema")}),
        "required_types": sorted(record["type"] for record in records),
    }


def _source_id(value: dict[str, Any]) -> Any:
    for key_name in ("registration_id", "status_id", "catalog_id", "distribution_id", "manifest_id", "receipt_id"):
        if value.get(key_name):
            return value.get(key_name)
    return value.get("schema")


def _registry_record(registry_receipt: dict[str, Any], status_receipt: dict[str, Any] | None) -> dict[str, Any]:
    registration = registry_receipt.get("registration", {})
    registry = registry_receipt.get("registry", {})
    vendor = registry_receipt.get("vendor", {})
    network = registry_receipt.get("trust_network", {})
    status_update = status_receipt.get("status_update", {}) if isinstance(status_receipt, dict) else {}
    return {
        "registration_id": registry_receipt.get("registration_id"),
        "registration_hash": content_hash(registry_receipt),
        "registration_ref": registration.get("registration_ref"),
        "registration_status": registration.get("status"),
        "effective_status": status_update.get("new_status") or registration.get("status"),
        "status_id": status_receipt.get("status_id") if isinstance(status_receipt, dict) else None,
        "status_hash": content_hash(status_receipt) if isinstance(status_receipt, dict) else None,
        "status_reason_code": status_update.get("reason_code"),
        "visibility": registration.get("visibility"),
        "registry_name": registry.get("name"),
        "registry_endpoint": registry.get("endpoint"),
        "namespace": registry.get("namespace"),
        "vendor_name": vendor.get("name"),
        "vendor_subject_ref": vendor.get("subject_ref"),
        "identity_provider": vendor.get("identity_provider"),
        "identity_id": vendor.get("identity_id"),
        "trust_network_manifest_id": network.get("manifest_id"),
        "buyer": network.get("buyer"),
        "procurement_contract_ref": registry_receipt.get("procurement", {}).get("contract_ref"),
        "procurement_integration_id": registry_receipt.get("procurement", {}).get("integration_id"),
    }


def _marketplace_record(catalog: dict[str, Any] | None, distribution: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(catalog, dict) or not isinstance(distribution, dict):
        return {
            "catalog_id": None,
            "distribution_id": None,
            "asset_count": 0,
        }
    channel = distribution.get("channel", {})
    subscriber = distribution.get("subscriber", {})
    return {
        "catalog_id": catalog.get("catalog_id"),
        "catalog_hash": content_hash(catalog),
        "catalog_status": catalog.get("status"),
        "publisher": catalog.get("publisher"),
        "asset_count": len(catalog.get("assets", [])) if isinstance(catalog.get("assets"), list) else 0,
        "asset_ids": sorted(asset.get("asset_id") for asset in catalog.get("assets", []) if isinstance(asset, dict) and asset.get("asset_id")),
        "distribution_id": distribution.get("distribution_id"),
        "distribution_hash": content_hash(distribution),
        "distribution_ref": distribution.get("distribution_ref"),
        "mode": distribution.get("mode"),
        "channel_type": channel.get("type") if isinstance(channel, dict) else None,
        "target": channel.get("target") if isinstance(channel, dict) else None,
        "subscriber": subscriber.get("organization") if isinstance(subscriber, dict) else None,
        "subscriber_ref": subscriber.get("subject_ref") if isinstance(subscriber, dict) else None,
        "distributed_asset_count": len(distribution.get("assets", [])) if isinstance(distribution.get("assets"), list) else 0,
    }


def _verify_source(value: Any, service_kind: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("trust-network service source must be an object")
        return
    if not isinstance(value.get("source_count"), int) or value.get("source_count") < 1:
        errors.append("trust-network service source.source_count must be an integer >= 1")
    if not value.get("source_hash"):
        errors.append("trust-network service source.source_hash is required")
    required = value.get("required_types")
    if not isinstance(required, list):
        errors.append("trust-network service source.required_types must be a list")
        return
    if "trust-network-registry" not in required:
        errors.append("trust-network service source.required_types must include trust-network-registry")
    if service_kind in {"marketplace", "registry-marketplace"}:
        for item in ("marketplace-catalog", "marketplace-distribution"):
            if item not in required:
                errors.append(f"trust-network service source.required_types must include {item}")


def _verify_service(value: Any, errors: list[str]) -> str | None:
    if not isinstance(value, dict):
        errors.append("trust-network service service must be an object")
        return None
    for field in (
        "service_ref",
        "version",
        "service_kind",
        "registry_endpoint",
        "marketplace_endpoint",
        "service_image",
        "service_image_digest",
        "service_binary_hash",
        "frontend_bundle_ref",
        "frontend_bundle_hash",
        "api_ref",
        "registry_store_ref",
        "search_index_ref",
        "entitlement_store_ref",
        "subscription_queue_ref",
    ):
        if not value.get(field):
            errors.append(f"trust-network service service.{field} is required")
    service_kind = value.get("service_kind")
    if service_kind not in TRUST_NETWORK_SERVICE_KINDS:
        errors.append("trust-network service service.service_kind is unsupported")
    for field in ("registry_endpoint", "marketplace_endpoint"):
        parsed = urlparse(str(value.get(field) or ""))
        if parsed.scheme != "https" or not parsed.netloc:
            errors.append(f"trust-network service service.{field} must use HTTPS")
    for field in ("service_image_digest", "service_binary_hash", "frontend_bundle_hash"):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"trust-network service service.{field} must be a sha256 reference")
    replicas_min = value.get("replicas_min")
    replicas_max = value.get("replicas_max")
    if not isinstance(replicas_min, int) or replicas_min < 2:
        errors.append("trust-network service service.replicas_min must be an integer >= 2")
    if not isinstance(replicas_max, int) or not isinstance(replicas_min, int) or replicas_max < replicas_min:
        errors.append("trust-network service service.replicas_max must be >= replicas_min")
    if not isinstance(value.get("availability_zones"), list) or len(value.get("availability_zones")) < 2:
        errors.append("trust-network service service.availability_zones must include at least two zones")
    return str(service_kind) if service_kind else None


def _verify_registry(value: Any, service_kind: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("trust-network service registry must be an object")
        return
    for field in ("registration_id", "registration_hash", "registration_ref", "registration_status", "effective_status", "registry_name", "registry_endpoint", "namespace", "vendor_name", "vendor_subject_ref", "trust_network_manifest_id"):
        if not value.get(field):
            errors.append(f"trust-network service registry.{field} is required")
    if service_kind in {"registry", "registry-marketplace", "procurement-federation"} and not value.get("procurement_integration_id"):
        errors.append("trust-network service registry.procurement_integration_id is required")
    if value.get("registration_status") not in {"active", "suspended", "revoked"}:
        errors.append("trust-network service registry.registration_status is unsupported")
    if value.get("effective_status") not in {"active", "suspended", "revoked"}:
        errors.append("trust-network service registry.effective_status is unsupported")


def _verify_marketplace(value: Any, service_kind: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("trust-network service marketplace must be an object")
        return
    if service_kind in {"marketplace", "registry-marketplace"}:
        for field in ("catalog_id", "catalog_hash", "catalog_status", "publisher", "distribution_id", "distribution_hash", "distribution_ref", "channel_type", "target", "subscriber"):
            if not value.get(field):
                errors.append(f"trust-network service marketplace.{field} is required")
        if not isinstance(value.get("asset_count"), int) or value.get("asset_count") < 1:
            errors.append("trust-network service marketplace.asset_count must be an integer >= 1")
        if not isinstance(value.get("distributed_asset_count"), int) or value.get("distributed_asset_count") < 1:
            errors.append("trust-network service marketplace.distributed_asset_count must be an integer >= 1")
    for field in ("catalog_hash", "distribution_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"trust-network service marketplace.{field} must be a sha256 reference or canonical hash")


def _verify_required_object(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"trust-network service {name} must be an object")
        return
    for field, child in value.items():
        if not child:
            errors.append(f"trust-network service {name}.{field} is required")


def _verify_observability(value: Any, attested: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("trust-network service observability must be an object")
        return
    for field in ("registry_audit_log_ref", "registry_audit_log_root", "marketplace_audit_log_ref", "marketplace_audit_log_root", "access_log_ref", "access_log_root", "publication_log_ref", "publication_log_root", "metrics_ref", "alert_policy_ref", "retention_until"):
        if not value.get(field):
            errors.append(f"trust-network service observability.{field} is required")
    for field in ("registry_audit_log_root", "marketplace_audit_log_root", "access_log_root", "publication_log_root"):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"trust-network service observability.{field} must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("trust-network service observability.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"trust-network service observability.retention_until invalid: {exc}")


def _verify_actor(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("trust-network service operation_actor must be an object")
        return
    if not value.get("actor_ref"):
        errors.append("trust-network service operation_actor.actor_ref is required")
    _verify_redacted_ref(value.get("credential"), "trust-network service operation_actor.credential", errors)
    _verify_redacted_ref(value.get("marketplace_credential"), "trust-network service operation_actor.marketplace_credential", errors)


def _verify_registry_matches_source(value: Any, registry_receipt: dict[str, Any], status_receipt: dict[str, Any] | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        return
    expected = _registry_record(registry_receipt, status_receipt)
    for field, expected_value in expected.items():
        if expected_value is not None and value.get(field) != expected_value:
            errors.append(f"trust-network service registry.{field} does not match source evidence")


def _verify_marketplace_matches_source(value: Any, catalog: dict[str, Any] | None, distribution: dict[str, Any], errors: list[str]) -> None:
    if not isinstance(value, dict) or not isinstance(catalog, dict):
        return
    expected = _marketplace_record(catalog, distribution)
    for field, expected_value in expected.items():
        if expected_value is not None and value.get(field) != expected_value:
            errors.append(f"trust-network service marketplace.{field} does not match source evidence")


def _controls(
    service: dict[str, Any],
    registry: dict[str, Any],
    marketplace: dict[str, Any],
    security: dict[str, Any],
    observability: dict[str, Any],
) -> list[dict[str, str]]:
    return [
        {"id": "hosted-trust-network-service-identity", "status": "service-attested" if service.get("service_image_digest") and service.get("service_binary_hash") else "planned-production", "description": "Hosted trust-network service image, binary hash, endpoints, replica floor, and multi-zone evidence are bound."},
        {"id": "hosted-registry-publication-binding", "status": "service-attested" if registry.get("registration_id") and registry.get("registration_hash") else "planned-production", "description": "Signed registry publication receipt, registration reference, vendor, buyer, namespace, and source manifest binding are bound."},
        {"id": "vendor-identity-federation", "status": "service-attested" if security.get("identity_federation_policy_ref") and registry.get("identity_provider") else "planned-production", "description": "Vendor identity-provider binding and hosted identity federation policy evidence are bound."},
        {"id": "procurement-entitlement-sync", "status": "service-attested" if registry.get("procurement_integration_id") and security.get("procurement_sync_policy_ref") and security.get("entitlement_policy_ref") else "planned-production", "description": "Procurement integration, entitlement store, subscriber authorization, and sync policy evidence are bound."},
        {"id": "marketplace-catalog-distribution-binding", "status": "service-attested" if marketplace.get("catalog_id") and marketplace.get("distribution_id") else "planned-production", "description": "Marketplace catalog, selected assets, subscriber, distribution receipt, target, and entitlement delivery evidence are bound."},
        {"id": "revocation-status-propagation", "status": "service-attested" if registry.get("status_id") and security.get("revocation_policy_ref") and security.get("cache_invalidation_policy_ref") else "planned-production", "description": "Registry status-change, revocation policy, cache invalidation, and propagation evidence are bound."},
        {"id": "hosted-trust-network-observability", "status": "service-attested" if observability.get("registry_audit_log_root") and observability.get("marketplace_audit_log_root") and observability.get("publication_log_root") else "planned-production", "description": "Registry audit root, marketplace audit root, access root, publication root, metrics, alerting, and retention evidence are bound."},
    ]


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if isinstance(item, dict):
            status = str(item.get("status", "unknown"))
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _artifact_by_type(records: list[Any], artifact_type: str) -> dict[str, Any] | None:
    for record in records:
        if isinstance(record, dict) and record.get("type") == artifact_type:
            return record
    return None


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
                    errors.append(f"trust-network service secret-like field must be redacted reference: {child_path}")
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
