from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .trust_network_registry import REGISTRY_STATUSES, verify_trust_network_registry_receipt

TRUST_NETWORK_REGISTRY_STATUS_SCHEMA = "trustai.trust-network-registry-status/0.1"
TRUST_NETWORK_REGISTRY_STATUS_ENTRY_TYPE = "trust_network.registry.status_changed"


@dataclass
class TrustNetworkRegistryStatusVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    previous_status: str | None = None
    new_status: str | None = None


def build_trust_network_registry_status_receipt(
    registry_receipt: dict[str, Any],
    *,
    new_status: str,
    reason: str,
    actor_ref: str,
    actor_role: str = "registry-operator",
    reason_code: str | None = None,
    decided_at: str | None = None,
    effective_at: str | None = None,
    dispute_ref: str | None = None,
    dispute_window_until: str | None = None,
    evidence_refs: list[str] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    procurement_receipt: dict[str, Any] | None = None,
    procurement_integration_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if new_status not in REGISTRY_STATUSES:
        raise ValueError("new_status must be active, suspended, or revoked")
    _require_text(reason, "reason")
    _require_text(actor_ref, "actor_ref")
    _require_text(actor_role, "actor_role")
    decided = decided_at or utc_now()
    effective = effective_at or decided
    parse_rfc3339(decided)
    parse_rfc3339(effective)
    if dispute_window_until:
        _validate_window(effective, dispute_window_until)

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
    )
    if not registry_result.ok:
        raise ValueError("invalid trust-network registry receipt: " + "; ".join(registry_result.errors))
    previous_status = registry_receipt.get("registration", {}).get("status")
    if new_status == previous_status:
        raise ValueError("new_status must differ from registry receipt status")

    target = _target_record(registry_receipt)
    status_update = {
        "previous_status": previous_status,
        "new_status": new_status,
        "reason": reason,
        "reason_code": reason_code,
        "decided_at": decided,
        "effective_at": effective,
        "actor": {
            "ref": actor_ref,
            "role": actor_role,
            "attestation_mode": "local-reference",
            "production_replacement": "authenticated hosted registry operator, buyer, vendor, or dispute-system event",
        },
        "dispute": {
            "dispute_ref": dispute_ref,
            "window_until": dispute_window_until,
            "evidence_refs": sorted(set(evidence_refs or [])),
        },
        "status_payload_hash": content_hash(
            {
                "registration_id": registry_receipt.get("registration_id"),
                "previous_status": previous_status,
                "new_status": new_status,
                "reason": reason,
                "reason_code": reason_code,
                "effective_at": effective,
            }
        ),
    }
    body = {
        "schema": TRUST_NETWORK_REGISTRY_STATUS_SCHEMA,
        "decided_at": decided,
        "effective_at": effective,
        "target_registration": target,
        "status_update": status_update,
        "source_artifacts": [_registry_artifact(registry_receipt)],
        "controls": _controls_for(new_status, bool(dispute_ref or dispute_window_until or evidence_refs)),
        "limitations": [
            "This receipt records a local-reference trust-network registry status change.",
            "It binds the status change to a signed registry publication receipt by canonical hash.",
            "It does not claim hosted registry propagation, authenticated operator workflow, or external dispute adjudication.",
            "Production deployments should replace this local receipt with an authenticated hosted registry status event and propagation audit.",
        ],
    }
    status_id = content_hash(body)
    return {
        **body,
        "status_id": status_id,
        "signatures": [sign_value({"status_id": status_id, "status": body}, key)],
    }


def verify_trust_network_registry_status_receipt(
    receipt: dict[str, Any],
    *,
    registry_receipt: dict[str, Any] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    procurement_receipt: dict[str, Any] | None = None,
    procurement_integration_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> TrustNetworkRegistryStatusVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != TRUST_NETWORK_REGISTRY_STATUS_SCHEMA:
        errors.append(f"unsupported trust-network registry status schema: {receipt.get('schema')}")
    body = without_keys(receipt, "status_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("status_id") != expected_id:
        errors.append("status_id does not match canonical trust-network registry status body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("trust-network registry status receipt missing signature")
    else:
        signed_value = {"status_id": receipt.get("status_id"), "status": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("trust-network registry status receipt signature invalid")

    _verify_times(receipt, now, errors)
    update = receipt.get("status_update", {})
    if not isinstance(update, dict):
        errors.append("trust-network registry status_update must be an object")
        update = {}
    previous_status = update.get("previous_status")
    new_status = update.get("new_status")
    if previous_status not in REGISTRY_STATUSES:
        errors.append("trust-network registry previous_status must be active, suspended, or revoked")
    if new_status not in REGISTRY_STATUSES:
        errors.append("trust-network registry new_status must be active, suspended, or revoked")
    if previous_status == new_status:
        errors.append("trust-network registry status change must change status")
    if not update.get("reason"):
        errors.append("trust-network registry status reason is required")
    actor = update.get("actor", {})
    if not isinstance(actor, dict) or not actor.get("ref") or not actor.get("role"):
        errors.append("trust-network registry status actor ref and role are required")
    dispute = update.get("dispute", {})
    if not isinstance(dispute, dict):
        errors.append("trust-network registry status dispute must be an object")
        dispute = {}
    if dispute.get("window_until"):
        try:
            _validate_window(str(receipt.get("effective_at")), str(dispute.get("window_until")))
        except ValueError as exc:
            errors.append(str(exc))

    target = receipt.get("target_registration", {})
    if not isinstance(target, dict) or not target.get("registration_id") or not target.get("registration_ref"):
        errors.append("trust-network registry target registration_id and registration_ref are required")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        errors.append("trust-network registry status receipt must include exactly one registry source artifact")
        artifacts = []
    artifact = artifacts[0] if artifacts and isinstance(artifacts[0], dict) else None
    if artifact and artifact.get("name") != "trust_network_registry_receipt":
        errors.append("trust-network registry status source artifact must be trust_network_registry_receipt")

    if registry_receipt is None:
        warnings.append("trust-network registry receipt source not supplied; verified status binding only")
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
        )
        if not registry_result.ok:
            errors.extend(f"source trust-network registry receipt invalid: {error}" for error in registry_result.errors)
        warnings.extend(f"source trust-network registry warning: {warning}" for warning in registry_result.warnings)
        _compare_artifact(artifact, _registry_artifact(registry_receipt), errors)
        expected_target = _target_record(registry_receipt)
        if target != expected_target:
            errors.append("trust-network registry status target does not match source registry receipt")
        source_status = registry_receipt.get("registration", {}).get("status")
        if previous_status != source_status:
            errors.append("trust-network registry status previous_status does not match source registry receipt")

    expected_payload_hash = content_hash(
        {
            "registration_id": target.get("registration_id"),
            "previous_status": previous_status,
            "new_status": new_status,
            "reason": update.get("reason"),
            "reason_code": update.get("reason_code"),
            "effective_at": receipt.get("effective_at"),
        }
    )
    if update.get("status_payload_hash") != expected_payload_hash:
        errors.append("trust-network registry status payload hash does not match status update")

    return TrustNetworkRegistryStatusVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        previous_status=previous_status,
        new_status=new_status,
    )


def append_trust_network_registry_status_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    registry_receipt: dict[str, Any] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    procurement_receipt: dict[str, Any] | None = None,
    procurement_integration_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_trust_network_registry_status_receipt(
        receipt,
        registry_receipt=registry_receipt,
        trust_network_manifest=trust_network_manifest,
        vendor_identity_receipt=vendor_identity_receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_payload=identity_payload,
        procurement_receipt=procurement_receipt,
        procurement_integration_receipt=procurement_integration_receipt,
        proof_packs=proof_packs,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid trust-network registry status receipt: " + "; ".join(result.errors))
    payload = {
        "status_id": receipt["status_id"],
        "status_hash": content_hash(receipt),
        "target_registration": receipt.get("target_registration"),
        "status_update": {
            "previous_status": receipt.get("status_update", {}).get("previous_status"),
            "new_status": receipt.get("status_update", {}).get("new_status"),
            "reason_code": receipt.get("status_update", {}).get("reason_code"),
            "effective_at": receipt.get("effective_at"),
            "actor": receipt.get("status_update", {}).get("actor"),
            "status_payload_hash": receipt.get("status_update", {}).get("status_payload_hash"),
        },
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(TRUST_NETWORK_REGISTRY_STATUS_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("decided_at"))


def load_trust_network_registry_status_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("trust-network registry status receipt must contain an object")
    return value


def write_trust_network_registry_status_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _target_record(registry_receipt: dict[str, Any]) -> dict[str, Any]:
    registration = registry_receipt.get("registration", {})
    registry = registry_receipt.get("registry", {})
    vendor = registry_receipt.get("vendor", {})
    network = registry_receipt.get("trust_network", {})
    return {
        "registration_id": registry_receipt.get("registration_id"),
        "content_hash": content_hash(registry_receipt),
        "registration_ref": registration.get("registration_ref"),
        "current_status": registration.get("status"),
        "visibility": registration.get("visibility"),
        "registry": {
            "name": registry.get("name"),
            "endpoint": registry.get("endpoint"),
            "namespace": registry.get("namespace"),
        },
        "vendor": {
            "name": vendor.get("name"),
            "subject_ref": vendor.get("subject_ref"),
            "identity_provider": vendor.get("identity_provider"),
            "identity_id": vendor.get("identity_id"),
        },
        "trust_network": {
            "manifest_id": network.get("manifest_id"),
            "buyer": network.get("buyer"),
        },
    }


def _registry_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    registration = receipt.get("registration", {})
    vendor = receipt.get("vendor", {})
    return {
        "name": "trust_network_registry_receipt",
        "artifact_type": "trustai.trust-network-registry",
        "content_hash": content_hash(receipt),
        "registration_id": receipt.get("registration_id"),
        "registration_ref": registration.get("registration_ref"),
        "status": registration.get("status"),
        "vendor": vendor.get("name"),
    }


def _controls_for(new_status: str, has_dispute_evidence: bool) -> list[dict[str, str]]:
    return [
        {
            "id": "registry-status-binding",
            "status": "implemented-reference",
            "description": "Receipt binds a status change to a signed registry publication receipt by canonical hash.",
        },
        {
            "id": "status-propagation-audit",
            "status": "planned-production",
            "description": "Production registries should prove propagation to hosted registry indexes, subscribers, and procurement integrations.",
        },
        {
            "id": "dispute-workflow-binding",
            "status": "implemented-reference" if has_dispute_evidence else "planned-production",
            "description": "Receipt can bind dispute references, evidence references, and appeal windows for suspended or revoked registrations.",
        },
        {
            "id": "revocation-enforcement",
            "status": "planned-production" if new_status == "revoked" else "not-applicable",
            "description": "Production registries should enforce revoked registrations through authenticated lookup and cache invalidation.",
        },
    ]


def _verify_times(receipt: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        decided = parse_rfc3339(str(receipt.get("decided_at")))
        effective = parse_rfc3339(str(receipt.get("effective_at")))
        if effective < decided:
            errors.append("trust-network registry status effective_at must be at or after decided_at")
        if now and parse_rfc3339(now) < decided:
            errors.append("trust-network registry status decision is in the future")
    except ValueError as exc:
        errors.append(f"invalid trust-network registry status time field: {exc}")


def _validate_window(effective_at: Any, window_until: Any) -> None:
    effective = parse_rfc3339(str(effective_at))
    until = parse_rfc3339(str(window_until))
    if until <= effective:
        raise ValueError("trust-network registry dispute window must be after effective_at")


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"trust-network registry status missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "registration_id": artifact.get("registration_id"),
    }


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
