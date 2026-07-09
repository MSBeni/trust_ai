from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .marketplace import verify_marketplace_catalog, verify_marketplace_distribution
from .marketplace_author import verify_marketplace_author_governance
from .marketplace_settlement import verify_marketplace_settlement
from .trust_network_service import verify_trust_network_service_attestation

TRUST_NETWORK_WORKER_SCHEMA = "trustai.trust-network-worker/0.1"
TRUST_NETWORK_WORKER_ENTRY_TYPE = "trust_network.worker_recorded"
TRUST_NETWORK_WORKER_MODES = {"local-reference", "scheduled-worker", "hosted-worker", "production-design"}
TRUST_NETWORK_WORKER_OPERATION_KINDS = {
    "registry_publish",
    "registry_status_propagation",
    "marketplace_catalog_sync",
    "marketplace_entitlement_reconcile",
    "marketplace_settlement_reconcile",
    "registry_marketplace_reconcile",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class TrustNetworkWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_trust_network_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("trust-network worker receipt must contain an object")
    return value


def write_trust_network_worker_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_trust_network_worker_receipt(
    service_attestation: dict[str, Any],
    *,
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
    marketplace_author_governance: dict[str, Any] | None = None,
    marketplace_settlement: dict[str, Any] | None = None,
    root: str | Path = ".",
    mode: str = "scheduled-worker",
    environment: str = "local",
    worker_ref: str,
    run_ref: str,
    operation_kind: str,
    actor_ref: str,
    schedule_ref: str,
    cadence_seconds: int,
    lease_ref: str,
    checkpoint_ref: str,
    checkpoint_hash: str | None = None,
    previous_cursor_ref: str | None = None,
    next_cursor_ref: str | None = None,
    attempt: int = 1,
    max_attempts: int = 3,
    queue_ref: str,
    queue_message_ref: str | None = None,
    destination_ref: str,
    publication_log_ref: str,
    publication_log_root: str,
    cache_invalidation_ref: str | None = None,
    external_callback_ref: str | None = None,
    provider_invoice_log_ref: str | None = None,
    provider_invoice_log_hash: str | None = None,
    provider_payout_log_ref: str | None = None,
    provider_payout_log_hash: str | None = None,
    provider_tax_custody_ref: str | None = None,
    provider_tax_document_hash: str | None = None,
    request_hash: str | None = None,
    response_status: int | None = None,
    response_hash: str | None = None,
    metrics_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    started_at: str,
    completed_at: str | None = None,
    next_run_at: str | None = None,
    error_ref: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in TRUST_NETWORK_WORKER_MODES:
        raise ValueError(f"mode must be one of {sorted(TRUST_NETWORK_WORKER_MODES)}")
    if operation_kind not in TRUST_NETWORK_WORKER_OPERATION_KINDS:
        raise ValueError(f"operation_kind must be one of {sorted(TRUST_NETWORK_WORKER_OPERATION_KINDS)}")
    if not isinstance(service_attestation, dict):
        raise ValueError("service_attestation must be an object")
    for value, field in (
        (worker_ref, "worker_ref"),
        (run_ref, "run_ref"),
        (actor_ref, "actor_ref"),
        (schedule_ref, "schedule_ref"),
        (lease_ref, "lease_ref"),
        (checkpoint_ref, "checkpoint_ref"),
        (queue_ref, "queue_ref"),
        (destination_ref, "destination_ref"),
        (publication_log_ref, "publication_log_ref"),
        (publication_log_root, "publication_log_root"),
        (metrics_ref, "metrics_ref"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (credential_ref, "credential_ref"),
        (started_at, "started_at"),
    ):
        _require_text(value, field)
    completed = completed_at or utc_now()
    started = parse_rfc3339(started_at)
    finished = parse_rfc3339(completed)
    if finished < started:
        raise ValueError("completed_at must be at or after started_at")
    if next_run_at:
        parse_rfc3339(next_run_at)
    if not isinstance(cadence_seconds, int) or cadence_seconds <= 0:
        raise ValueError("cadence_seconds must be a positive integer")
    if not isinstance(attempt, int) or attempt < 1:
        raise ValueError("attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < attempt:
        raise ValueError("max_attempts must be greater than or equal to attempt")
    for field, value in (
        ("checkpoint_hash", checkpoint_hash),
        ("publication_log_root", publication_log_root),
        ("provider_invoice_log_hash", provider_invoice_log_hash),
        ("provider_payout_log_hash", provider_payout_log_hash),
        ("provider_tax_document_hash", provider_tax_document_hash),
        ("request_hash", request_hash),
        ("response_hash", response_hash),
        ("audit_log_root", audit_log_root),
    ):
        if value and not _is_sha256_ref(str(value)):
            raise ValueError(f"{field} must be a sha256 reference")
    if response_status is not None and (not isinstance(response_status, int) or response_status < 100 or response_status > 599):
        raise ValueError("response_status must be an HTTP status code")

    service_result = None
    if registry_receipt is not None:
        service_result = verify_trust_network_service_attestation(
            service_attestation,
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
            key=key,
        )
        if not service_result.ok:
            raise ValueError("invalid trust-network service source: " + "; ".join(service_result.errors))
    if marketplace_catalog is not None:
        catalog_result = verify_marketplace_catalog(marketplace_catalog, root=root)
        if not catalog_result.ok:
            raise ValueError("invalid marketplace catalog source: " + "; ".join(catalog_result.errors))
    if marketplace_distribution is not None:
        distribution_result = verify_marketplace_distribution(
            marketplace_distribution,
            catalog=marketplace_catalog,
            root=root,
            key=key,
        )
        if not distribution_result.ok:
            raise ValueError("invalid marketplace distribution source: " + "; ".join(distribution_result.errors))
    if marketplace_author_governance is not None:
        author_result = verify_marketplace_author_governance(
            marketplace_author_governance,
            catalog=marketplace_catalog,
            distribution=marketplace_distribution,
            root=root,
            key=key,
        )
        if not author_result.ok:
            raise ValueError("invalid marketplace author source: " + "; ".join(author_result.errors))
    if marketplace_settlement is not None:
        settlement_result = verify_marketplace_settlement(
            marketplace_settlement,
            author_governance=marketplace_author_governance,
            catalog=marketplace_catalog,
            distribution=marketplace_distribution,
            root=root,
            key=key,
        )
        if not settlement_result.ok:
            raise ValueError("invalid marketplace settlement source: " + "; ".join(settlement_result.errors))

    source_artifacts = _source_artifacts(
        service_attestation=service_attestation,
        registry_receipt=registry_receipt,
        registry_status_receipt=registry_status_receipt,
        marketplace_catalog=marketplace_catalog,
        marketplace_distribution=marketplace_distribution,
        marketplace_author_governance=marketplace_author_governance,
        marketplace_settlement=marketplace_settlement,
    )
    success = not error_ref and (response_status is None or 200 <= response_status < 300)
    service = _service_record(service_attestation)
    registry = _registry_record(registry_receipt, registry_status_receipt)
    marketplace = _marketplace_record(
        marketplace_catalog,
        marketplace_distribution,
        marketplace_author_governance,
        marketplace_settlement,
    )
    provider_logs = {
        "invoice_log_ref": provider_invoice_log_ref,
        "invoice_log_hash": provider_invoice_log_hash,
        "payout_log_ref": provider_payout_log_ref,
        "payout_log_hash": provider_payout_log_hash,
        "tax_custody_ref": provider_tax_custody_ref,
        "tax_document_hash": provider_tax_document_hash,
    }
    body: dict[str, Any] = {
        "schema": TRUST_NETWORK_WORKER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": completed,
        "service": service,
        "registry": registry,
        "marketplace": marketplace,
        "worker": {
            "worker_ref": worker_ref,
            "run_ref": run_ref,
            "operation_kind": operation_kind,
            "actor_ref": actor_ref,
            "started_at": started_at,
            "completed_at": completed,
            "attempt": attempt,
            "max_attempts": max_attempts,
            "success": success,
            "error_ref": error_ref,
        },
        "scheduler": {
            "schedule_ref": schedule_ref,
            "cadence_seconds": cadence_seconds,
            "lease_ref": lease_ref,
            "checkpoint_ref": checkpoint_ref,
            "checkpoint_hash": checkpoint_hash,
            "previous_cursor_ref": previous_cursor_ref,
            "next_cursor_ref": next_cursor_ref,
            "next_run_at": next_run_at,
        },
        "propagation": {
            "queue_ref": queue_ref,
            "queue_message_ref": queue_message_ref,
            "destination_ref": destination_ref,
            "publication_log_ref": publication_log_ref,
            "publication_log_root": publication_log_root,
            "cache_invalidation_ref": cache_invalidation_ref,
            "external_callback_ref": external_callback_ref,
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
            "provider_logs": provider_logs,
        },
        "source": _source_summary(source_artifacts),
        "credential": _redacted_ref(credential_ref),
        "observability": {
            "metrics_ref": metrics_ref,
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "evidence_refs": sorted(evidence_refs or []),
        },
        "controls": _controls(
            mode=mode,
            operation_kind=operation_kind,
            service=service,
            registry=registry,
            marketplace=marketplace,
            source_artifacts=source_artifacts,
            schedule_ref=schedule_ref,
            lease_ref=lease_ref,
            checkpoint_ref=checkpoint_ref,
            checkpoint_hash=checkpoint_hash,
            publication_log_root=publication_log_root,
            audit_log_root=audit_log_root,
            provider_logs=provider_logs,
            credential_ref=credential_ref,
            response_status=response_status,
        ),
        "limitations": [
            "This receipt records one trust-network registry or marketplace worker run and the source receipt hashes it processed.",
            "It stores queue, lease, checkpoint, audit-log, provider-log hash, and redacted credential references, not raw marketplace credentials or provider response bodies.",
            "It proves continuously operated hosted workers only when paired with hosted-service, scheduling, monitoring, live provider callback, and immutable log evidence.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [sign_value({"worker_operation_id": worker_operation_id, "trust_network_worker": body}, key)],
    }


def verify_trust_network_worker_receipt(
    receipt: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
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
    marketplace_author_governance: dict[str, Any] | None = None,
    marketplace_settlement: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> TrustNetworkWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != TRUST_NETWORK_WORKER_SCHEMA:
        errors.append(f"unsupported trust-network worker schema: {receipt.get('schema')}")
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append("worker_operation_id does not match canonical trust-network worker body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("trust-network worker receipt must include at least one signature")
    else:
        signed_value = {"worker_operation_id": receipt.get("worker_operation_id"), "trust_network_worker": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("trust-network worker signature verification failed")

    try:
        parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"trust-network worker recorded_at invalid: {exc}")
    mode = receipt.get("mode")
    if mode not in TRUST_NETWORK_WORKER_MODES:
        errors.append("trust-network worker mode is unsupported")
    elif mode != "hosted-worker":
        warnings.append(f"trust-network worker mode is {mode}; continuously hosted worker operation is not claimed")

    operation_kind = _verify_worker(receipt.get("worker"), errors)
    _verify_scheduler(receipt.get("scheduler"), errors)
    _verify_propagation(receipt.get("propagation"), errors)
    _verify_service(receipt.get("service"), errors)
    _verify_registry(receipt.get("registry"), operation_kind, errors)
    _verify_marketplace(receipt.get("marketplace"), operation_kind, errors)
    _verify_redacted_ref(receipt.get("credential"), "trust-network worker credential", errors)
    _verify_observability(receipt.get("observability"), errors)
    _check_no_secret_values(receipt, errors)

    if service_attestation is None:
        warnings.append("trust-network worker service attestation artifact was not supplied; service hash was not replayed")
    else:
        _compare_source_hash(receipt, "trust-network-service-attestation", service_attestation, errors)
        service_hash = receipt.get("service", {}).get("attestation_hash") if isinstance(receipt.get("service"), dict) else None
        if service_hash != content_hash(service_attestation):
            errors.append("trust-network worker service.attestation_hash does not match supplied service attestation")
        if registry_receipt is not None:
            service_result = verify_trust_network_service_attestation(
                service_attestation,
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
                key=key,
            )
            if not service_result.ok:
                errors.extend(f"trust-network worker service source: {error}" for error in service_result.errors)
            warnings.extend(f"trust-network worker service source: {warning}" for warning in service_result.warnings)
        else:
            warnings.append("trust-network worker registry source was not supplied; service source receipt was not deep-verified")

    for source_type, source_value in (
        ("trust-network-registry", registry_receipt),
        ("trust-network-registry-status", registry_status_receipt),
        ("marketplace-catalog", marketplace_catalog),
        ("marketplace-distribution", marketplace_distribution),
        ("marketplace-author-governance", marketplace_author_governance),
        ("marketplace-settlement", marketplace_settlement),
    ):
        if source_value is not None:
            _compare_source_hash(receipt, source_type, source_value, errors)

    if marketplace_catalog is not None:
        catalog_result = verify_marketplace_catalog(marketplace_catalog, root=root)
        if not catalog_result.ok:
            errors.extend(f"trust-network worker marketplace catalog source: {error}" for error in catalog_result.errors)
    if marketplace_distribution is not None:
        distribution_result = verify_marketplace_distribution(marketplace_distribution, catalog=marketplace_catalog, root=root, key=key)
        if not distribution_result.ok:
            errors.extend(f"trust-network worker marketplace distribution source: {error}" for error in distribution_result.errors)
    if marketplace_author_governance is not None:
        author_result = verify_marketplace_author_governance(
            marketplace_author_governance,
            catalog=marketplace_catalog,
            distribution=marketplace_distribution,
            root=root,
            key=key,
        )
        if not author_result.ok:
            errors.extend(f"trust-network worker marketplace author source: {error}" for error in author_result.errors)
    if marketplace_settlement is not None:
        settlement_result = verify_marketplace_settlement(
            marketplace_settlement,
            author_governance=marketplace_author_governance,
            catalog=marketplace_catalog,
            distribution=marketplace_distribution,
            root=root,
            key=key,
        )
        if not settlement_result.ok:
            errors.extend(f"trust-network worker marketplace settlement source: {error}" for error in settlement_result.errors)

    if operation_kind == "marketplace_settlement_reconcile" and marketplace_settlement is None:
        warnings.append("trust-network worker settlement source artifact was not supplied; settlement hash was not replayed")
    if operation_kind and operation_kind.startswith("marketplace") and marketplace_catalog is None:
        warnings.append("trust-network worker marketplace source artifacts were not supplied; marketplace hashes were not replayed")
    return TrustNetworkWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_trust_network_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
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
    marketplace_author_governance: dict[str, Any] | None = None,
    marketplace_settlement: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_trust_network_worker_receipt(
        receipt,
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
        marketplace_author_governance=marketplace_author_governance,
        marketplace_settlement=marketplace_settlement,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid trust-network worker receipt: " + "; ".join(result.errors))
    payload = {
        "worker_operation_id": receipt["worker_operation_id"],
        "worker_operation_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "service": receipt.get("service"),
        "registry": receipt.get("registry"),
        "marketplace": receipt.get("marketplace"),
        "worker": receipt.get("worker"),
        "scheduler": receipt.get("scheduler"),
        "propagation": receipt.get("propagation"),
        "source": receipt.get("source"),
        "credential": receipt.get("credential"),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(TRUST_NETWORK_WORKER_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("recorded_at"))


def _service_record(attestation: dict[str, Any]) -> dict[str, Any]:
    service = attestation.get("service", {}) if isinstance(attestation, dict) else {}
    return {
        "attestation_id": attestation.get("attestation_id"),
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "service_ref": service.get("service_ref") if isinstance(service, dict) else None,
        "service_kind": service.get("service_kind") if isinstance(service, dict) else None,
        "service_version": service.get("version") if isinstance(service, dict) else None,
        "registry_endpoint": service.get("registry_endpoint") if isinstance(service, dict) else None,
        "marketplace_endpoint": service.get("marketplace_endpoint") if isinstance(service, dict) else None,
    }


def _registry_record(registry: dict[str, Any] | None, status: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(registry, dict):
        return {"registration_id": None, "registration_hash": None, "status_id": None, "status_hash": None}
    registration = registry.get("registration", {}) if isinstance(registry.get("registration"), dict) else {}
    status_update = status.get("status_update", {}) if isinstance(status, dict) and isinstance(status.get("status_update"), dict) else {}
    return {
        "registration_id": registry.get("registration_id"),
        "registration_hash": content_hash(registry),
        "registration_ref": registration.get("registration_ref"),
        "registration_status": registration.get("status"),
        "effective_status": status_update.get("new_status") or registration.get("status"),
        "status_id": status.get("status_id") if isinstance(status, dict) else None,
        "status_hash": content_hash(status) if isinstance(status, dict) else None,
        "status_reason_code": status_update.get("reason_code"),
    }


def _marketplace_record(
    catalog: dict[str, Any] | None,
    distribution: dict[str, Any] | None,
    author: dict[str, Any] | None,
    settlement: dict[str, Any] | None,
) -> dict[str, Any]:
    marketplace: dict[str, Any] = {
        "catalog_id": catalog.get("catalog_id") if isinstance(catalog, dict) else None,
        "catalog_hash": content_hash(catalog) if isinstance(catalog, dict) else None,
        "distribution_id": distribution.get("distribution_id") if isinstance(distribution, dict) else None,
        "distribution_hash": content_hash(distribution) if isinstance(distribution, dict) else None,
        "asset_count": len(catalog.get("assets", [])) if isinstance(catalog, dict) and isinstance(catalog.get("assets"), list) else 0,
        "governance_id": author.get("governance_id") if isinstance(author, dict) else None,
        "governance_hash": content_hash(author) if isinstance(author, dict) else None,
        "settlement_id": settlement.get("settlement_id") if isinstance(settlement, dict) else None,
        "settlement_hash": content_hash(settlement) if isinstance(settlement, dict) else None,
    }
    if isinstance(settlement, dict):
        invoice = settlement.get("invoice", {}) if isinstance(settlement.get("invoice"), dict) else {}
        payout = settlement.get("payout", {}) if isinstance(settlement.get("payout"), dict) else {}
        entitlement = settlement.get("entitlement", {}) if isinstance(settlement.get("entitlement"), dict) else {}
        marketplace.update(
            {
                "subscriber_ref": entitlement.get("subscriber_ref"),
                "entitlement_decision": entitlement.get("decision"),
                "invoice_ref": invoice.get("invoice_ref"),
                "invoice_status": invoice.get("status"),
                "payout_ref": payout.get("payout_ref"),
                "payout_status": payout.get("status"),
            }
        )
    return marketplace


def _source_artifacts(
    *,
    service_attestation: dict[str, Any] | None,
    registry_receipt: dict[str, Any] | None,
    registry_status_receipt: dict[str, Any] | None,
    marketplace_catalog: dict[str, Any] | None,
    marketplace_distribution: dict[str, Any] | None,
    marketplace_author_governance: dict[str, Any] | None,
    marketplace_settlement: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for source_type, value in (
        ("trust-network-service-attestation", service_attestation),
        ("trust-network-registry", registry_receipt),
        ("trust-network-registry-status", registry_status_receipt),
        ("marketplace-catalog", marketplace_catalog),
        ("marketplace-distribution", marketplace_distribution),
        ("marketplace-author-governance", marketplace_author_governance),
        ("marketplace-settlement", marketplace_settlement),
    ):
        if isinstance(value, dict):
            records.append({"type": source_type, "id": _source_id(value), "schema": value.get("schema"), "hash": content_hash(value)})
    return records


def _source_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_count": len(records),
        "source_hash": content_hash(records),
        "schemas": sorted({str(record.get("schema")) for record in records if record.get("schema")}),
        "required_types": sorted(record["type"] for record in records),
        "artifacts": records,
    }


def _source_id(value: dict[str, Any]) -> Any:
    for key_name in (
        "attestation_id",
        "registration_id",
        "status_id",
        "catalog_id",
        "distribution_id",
        "governance_id",
        "settlement_id",
        "manifest_id",
        "receipt_id",
    ):
        if value.get(key_name):
            return value.get(key_name)
    return value.get("schema")


def _controls(
    *,
    mode: str,
    operation_kind: str,
    service: dict[str, Any],
    registry: dict[str, Any],
    marketplace: dict[str, Any],
    source_artifacts: list[dict[str, Any]],
    schedule_ref: str,
    lease_ref: str,
    checkpoint_ref: str,
    checkpoint_hash: str | None,
    publication_log_root: str,
    audit_log_root: str,
    provider_logs: dict[str, Any],
    credential_ref: str,
    response_status: int | None,
) -> list[dict[str, Any]]:
    types = {record.get("type") for record in source_artifacts}
    return [
        {
            "id": "trust-network-service-source-bound",
            "status": "implemented" if service.get("attestation_hash") and "trust-network-service-attestation" in types else "planned-production",
            "description": "Worker run is bound to a signed trust-network service attestation by hash.",
        },
        {
            "id": "registry-source-bound",
            "status": "implemented" if registry.get("registration_hash") else "planned-production",
            "description": "Worker run records the registry publication and optional status-change receipt hashes it processed.",
        },
        {
            "id": "marketplace-source-bound",
            "status": "implemented" if marketplace.get("catalog_hash") and marketplace.get("distribution_hash") else "not-applicable" if operation_kind.startswith("registry") else "planned-production",
            "description": "Marketplace worker work is bound to catalog and distribution receipt hashes.",
        },
        {
            "id": "marketplace-author-bound",
            "status": "implemented" if marketplace.get("governance_hash") else "not-applicable" if not operation_kind.startswith("marketplace") else "planned-production",
            "description": "Marketplace worker work can bind third-party author governance evidence.",
        },
        {
            "id": "marketplace-settlement-bound",
            "status": "implemented" if marketplace.get("settlement_hash") else "not-applicable" if operation_kind != "marketplace_settlement_reconcile" else "planned-production",
            "description": "Settlement reconciliation work is bound to a signed marketplace settlement receipt.",
        },
        {
            "id": "worker-scheduler-lease",
            "status": "implemented" if schedule_ref and lease_ref else "planned-production",
            "description": "Worker run records scheduler cadence and lease ownership metadata.",
        },
        {
            "id": "worker-checkpoint-continuity",
            "status": "implemented" if checkpoint_ref and checkpoint_hash else "local-reference" if checkpoint_ref else "planned-production",
            "description": "Worker run records a checkpoint hash for replayable propagation continuity.",
        },
        {
            "id": "publication-and-audit-roots",
            "status": "implemented" if publication_log_root and audit_log_root else "planned-production",
            "description": "Worker run binds publication and audit-log roots for propagation evidence.",
        },
        {
            "id": "provider-owned-ledger-bindings",
            "status": "implemented" if _has_provider_logs(provider_logs) else "planned-production",
            "description": "Worker run can bind provider-owned invoice, payout, or tax-custody logs by hash.",
        },
        {
            "id": "provider-response-binding",
            "status": "implemented" if response_status is not None else "local-reference",
            "description": "Worker run records a provider or internal service response status and optional response hash when available.",
        },
        {
            "id": "redacted-worker-credential",
            "status": "implemented" if credential_ref else "planned-production",
            "description": "Worker credential material is represented only by a redacted reference.",
        },
        {
            "id": "hosted-worker-operation",
            "status": "implemented" if mode == "hosted-worker" else "planned-production",
            "description": "Receipt claims continuously hosted worker operation only in hosted-worker mode.",
        },
    ]


def _verify_worker(value: Any, errors: list[str]) -> str | None:
    if not isinstance(value, dict):
        errors.append("trust-network worker worker must be an object")
        return None
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at", "attempt", "max_attempts", "success"):
        if value.get(field) in (None, ""):
            errors.append(f"trust-network worker worker.{field} is required")
    operation_kind = value.get("operation_kind")
    if operation_kind not in TRUST_NETWORK_WORKER_OPERATION_KINDS:
        errors.append(f"trust-network worker operation kind unsupported: {operation_kind}")
        operation_kind = None
    try:
        started = parse_rfc3339(str(value.get("started_at") or ""))
        completed = parse_rfc3339(str(value.get("completed_at") or ""))
        if completed < started:
            errors.append("trust-network worker completed_at must be at or after started_at")
    except ValueError as exc:
        errors.append(f"trust-network worker timestamp invalid: {exc}")
    attempt = value.get("attempt")
    max_attempts = value.get("max_attempts")
    if not isinstance(attempt, int) or attempt < 1:
        errors.append("trust-network worker attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < (attempt if isinstance(attempt, int) else 1):
        errors.append("trust-network worker max_attempts must be greater than or equal to attempt")
    if not isinstance(value.get("success"), bool):
        errors.append("trust-network worker success must be a boolean")
    return operation_kind


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("trust-network worker scheduler must be an object")
        return
    for field in ("schedule_ref", "cadence_seconds", "lease_ref", "checkpoint_ref"):
        if value.get(field) in (None, ""):
            errors.append(f"trust-network worker scheduler.{field} is required")
    cadence = value.get("cadence_seconds")
    if not isinstance(cadence, int) or cadence <= 0:
        errors.append("trust-network worker scheduler.cadence_seconds must be a positive integer")
    if value.get("checkpoint_hash") and not _is_sha256_ref(str(value.get("checkpoint_hash"))):
        errors.append("trust-network worker scheduler.checkpoint_hash must be a sha256 reference")
    if value.get("next_run_at"):
        try:
            parse_rfc3339(str(value.get("next_run_at")))
        except ValueError as exc:
            errors.append(f"trust-network worker scheduler.next_run_at invalid: {exc}")


def _verify_propagation(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("trust-network worker propagation must be an object")
        return
    for field in ("queue_ref", "destination_ref", "publication_log_ref", "publication_log_root"):
        if not value.get(field):
            errors.append(f"trust-network worker propagation.{field} is required")
    for field in ("publication_log_root", "request_hash", "response_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"trust-network worker propagation.{field} must be a sha256 reference")
    response_status = value.get("response_status")
    if response_status is not None and (not isinstance(response_status, int) or response_status < 100 or response_status > 599):
        errors.append("trust-network worker propagation.response_status must be an HTTP status code")
    provider_logs = value.get("provider_logs", {})
    if not isinstance(provider_logs, dict):
        errors.append("trust-network worker propagation.provider_logs must be an object")
        return
    for field in ("invoice_log_hash", "payout_log_hash", "tax_document_hash"):
        if provider_logs.get(field) and not _is_sha256_ref(str(provider_logs.get(field))):
            errors.append(f"trust-network worker propagation.provider_logs.{field} must be a sha256 reference")


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("trust-network worker service must be an object")
        return
    for field in ("attestation_id", "attestation_hash", "service_ref", "service_kind", "service_version"):
        if not value.get(field):
            errors.append(f"trust-network worker service.{field} is required")
    if value.get("attestation_hash") and not _is_sha256_ref(str(value.get("attestation_hash"))):
        errors.append("trust-network worker service.attestation_hash must be a sha256 reference")


def _verify_registry(value: Any, operation_kind: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("trust-network worker registry must be an object")
        return
    if operation_kind and operation_kind.startswith("registry") and not value.get("registration_hash"):
        errors.append("trust-network worker registry.registration_hash is required for registry operations")
    if value.get("registration_hash") and not _is_sha256_ref(str(value.get("registration_hash"))):
        errors.append("trust-network worker registry.registration_hash must be a sha256 reference")
    if value.get("status_hash") and not _is_sha256_ref(str(value.get("status_hash"))):
        errors.append("trust-network worker registry.status_hash must be a sha256 reference")


def _verify_marketplace(value: Any, operation_kind: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("trust-network worker marketplace must be an object")
        return
    if operation_kind and operation_kind.startswith("marketplace") and not value.get("catalog_hash"):
        errors.append("trust-network worker marketplace.catalog_hash is required for marketplace operations")
    if operation_kind == "marketplace_settlement_reconcile" and not value.get("settlement_hash"):
        errors.append("trust-network worker marketplace.settlement_hash is required for settlement reconciliation operations")
    for field in ("catalog_hash", "distribution_hash", "governance_hash", "settlement_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"trust-network worker marketplace.{field} must be a sha256 reference")


def _verify_observability(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("trust-network worker observability must be an object")
        return
    for field in ("metrics_ref", "audit_log_ref", "audit_log_root"):
        if not value.get(field):
            errors.append(f"trust-network worker observability.{field} is required")
    if value.get("audit_log_root") and not _is_sha256_ref(str(value.get("audit_log_root"))):
        errors.append("trust-network worker observability.audit_log_root must be a sha256 reference")
    if not isinstance(value.get("evidence_refs", []), list):
        errors.append("trust-network worker observability.evidence_refs must be a list")


def _compare_source_hash(receipt: dict[str, Any], source_type: str, source_value: dict[str, Any], errors: list[str]) -> None:
    source = receipt.get("source", {})
    artifacts = source.get("artifacts", []) if isinstance(source, dict) else []
    if not isinstance(artifacts, list):
        errors.append("trust-network worker source.artifacts must be a list")
        return
    matches = [item for item in artifacts if isinstance(item, dict) and item.get("type") == source_type]
    if not matches:
        errors.append(f"trust-network worker source missing artifact type: {source_type}")
        return
    expected_hash = content_hash(source_value)
    if not any(item.get("hash") == expected_hash for item in matches):
        errors.append(f"trust-network worker source hash mismatch for {source_type}")


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return summary


def _has_provider_logs(value: dict[str, Any]) -> bool:
    return any(value.get(field) for field in ("invoice_log_hash", "payout_log_hash", "tax_document_hash"))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    return {"ref": ref, "redacted": True} if ref else None


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _is_sha256_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value[7:])
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                if not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"trust-network worker secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")
