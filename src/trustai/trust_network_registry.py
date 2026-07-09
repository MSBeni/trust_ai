from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .identity_provider_attestation import verify_identity_provider_attestation
from .procurement_clause import verify_procurement_clause_receipt
from .procurement_integration import verify_procurement_integration_receipt
from .trust_network import verify_trust_network_manifest
from .vendor_identity import verify_vendor_identity_receipt

TRUST_NETWORK_REGISTRY_SCHEMA = "trustai.trust-network-registry/0.1"
TRUST_NETWORK_REGISTRY_ENTRY_TYPE = "trust_network.registry.published"

REGISTRY_STATUSES = {"active", "suspended", "revoked"}
REGISTRY_VISIBILITIES = {"private", "buyer-vendor", "public"}


@dataclass
class TrustNetworkRegistryVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    status: str | None = None


def build_trust_network_registry_receipt(
    trust_network_manifest: dict[str, Any],
    vendor_identity_receipt: dict[str, Any],
    *,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    procurement_receipt: dict[str, Any] | None = None,
    procurement_integration_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    registry_name: str = "local-trust-network-registry",
    registry_endpoint: str = "local-registry",
    namespace: str = "local",
    registration_ref: str | None = None,
    status: str = "active",
    visibility: str = "buyer-vendor",
    terms_ref: str | None = None,
    revocation_endpoint: str | None = None,
    published_at: str | None = None,
    expires_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _require_text(registry_name, "registry_name")
    _require_text(registry_endpoint, "registry_endpoint")
    _require_text(namespace, "namespace")
    if status not in REGISTRY_STATUSES:
        raise ValueError("status must be active, suspended, or revoked")
    if visibility not in REGISTRY_VISIBILITIES:
        raise ValueError("visibility must be private, buyer-vendor, or public")
    published = published_at or utc_now()
    parse_rfc3339(published)
    if expires_at:
        _validate_expiry(published, expires_at)

    manifest_result = verify_trust_network_manifest(
        trust_network_manifest,
        proof_packs=proof_packs,
        key=key,
    )
    if not manifest_result.ok:
        raise ValueError("invalid trust-network manifest: " + "; ".join(manifest_result.errors))

    vendor_result = verify_vendor_identity_receipt(
        vendor_identity_receipt,
        proof_packs=proof_packs,
        trust_network_manifest=trust_network_manifest,
        key=key,
    )
    if not vendor_result.ok:
        raise ValueError("invalid vendor identity receipt: " + "; ".join(vendor_result.errors))
    _validate_vendor_network_binding(trust_network_manifest, vendor_identity_receipt)

    if identity_provider_attestation is not None:
        identity_result = verify_identity_provider_attestation(
            identity_provider_attestation,
            identity_payload=identity_payload,
            vendor_identity_receipt=vendor_identity_receipt,
            proof_packs=proof_packs,
            trust_network_manifest=trust_network_manifest,
            key=key,
        )
        if not identity_result.ok:
            raise ValueError("invalid identity provider attestation: " + "; ".join(identity_result.errors))
        _validate_identity_binding(identity_provider_attestation, vendor_identity_receipt, trust_network_manifest)

    if procurement_receipt is not None:
        procurement_result = verify_procurement_clause_receipt(
            procurement_receipt,
            trust_network_manifest=trust_network_manifest,
            proof_packs=proof_packs,
            key=key,
        )
        if not procurement_result.ok:
            raise ValueError("invalid procurement clause receipt: " + "; ".join(procurement_result.errors))
        _validate_procurement_binding(procurement_receipt, trust_network_manifest)

    if procurement_integration_receipt is not None:
        if procurement_receipt is None:
            raise ValueError("procurement_receipt is required when procurement_integration_receipt is supplied")
        integration_result = verify_procurement_integration_receipt(
            procurement_integration_receipt,
            procurement_receipt=procurement_receipt,
            vendor_identity_receipt=vendor_identity_receipt,
            trust_network_manifest=trust_network_manifest,
            proof_packs=proof_packs,
            key=key,
        )
        if not integration_result.ok:
            raise ValueError("invalid procurement integration receipt: " + "; ".join(integration_result.errors))

    source_artifacts = _source_artifacts(
        trust_network_manifest,
        vendor_identity_receipt,
        identity_provider_attestation,
        procurement_receipt,
        procurement_integration_receipt,
    )
    registry_payload = _registry_payload(
        trust_network_manifest,
        vendor_identity_receipt,
        identity_provider_attestation,
        procurement_receipt,
        procurement_integration_receipt,
    )
    ref = registration_ref or content_hash(
        {
            "registry_name": registry_name,
            "namespace": namespace,
            "manifest_id": trust_network_manifest.get("manifest_id"),
            "vendor_identity_receipt_id": vendor_identity_receipt.get("receipt_id"),
        }
    )[:32]
    body = {
        "schema": TRUST_NETWORK_REGISTRY_SCHEMA,
        "published_at": published,
        "expires_at": expires_at,
        "registry": {
            "name": registry_name,
            "endpoint": registry_endpoint.rstrip("/"),
            "namespace": namespace,
            "attestation_mode": "local-reference",
            "production_replacement": "authenticated hosted trust-network registry publication event",
        },
        "registration": {
            "registration_ref": ref,
            "status": status,
            "visibility": visibility,
            "terms_ref": terms_ref,
            "revocation_endpoint": revocation_endpoint,
            "idempotency_key": content_hash(
                {
                    "registration_ref": ref,
                    "manifest_id": trust_network_manifest.get("manifest_id"),
                    "vendor_identity_receipt_id": vendor_identity_receipt.get("receipt_id"),
                    "registry_endpoint": registry_endpoint.rstrip("/"),
                }
            )[:32],
        },
        "vendor": _vendor_record(vendor_identity_receipt),
        "trust_network": _trust_network_record(trust_network_manifest),
        "proof_packs": _proof_pack_refs(vendor_identity_receipt),
        "identity_provider": _identity_record(identity_provider_attestation),
        "procurement": _procurement_record(procurement_receipt, procurement_integration_receipt),
        "registry_payload": registry_payload,
        "source_artifacts": source_artifacts,
        "controls": _controls_for(
            registry_endpoint=registry_endpoint,
            has_identity_attestation=identity_provider_attestation is not None,
            has_procurement=procurement_receipt is not None,
            has_procurement_integration=procurement_integration_receipt is not None,
        ),
        "limitations": [
            "This receipt records a local-reference trust-network registry publication.",
            "It binds the trust-network manifest, vendor identity, optional identity-provider attestation, and procurement receipts by canonical hash.",
            "It does not claim live hosted registry authentication, cross-org account enrollment, or production identity-provider callbacks.",
            "Production deployments should replace this local receipt with an authenticated hosted trust-network registry event.",
        ],
    }
    registration_id = content_hash(body)
    return {
        **body,
        "registration_id": registration_id,
        "signatures": [sign_value({"registration_id": registration_id, "registration": body}, key)],
    }


def verify_trust_network_registry_receipt(
    receipt: dict[str, Any],
    *,
    trust_network_manifest: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    procurement_receipt: dict[str, Any] | None = None,
    procurement_integration_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> TrustNetworkRegistryVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != TRUST_NETWORK_REGISTRY_SCHEMA:
        errors.append(f"unsupported trust-network registry schema: {receipt.get('schema')}")
    body = without_keys(receipt, "registration_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("registration_id") != expected_id:
        errors.append("registration_id does not match canonical trust-network registry body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("trust-network registry receipt missing signature")
    else:
        signed_value = {"registration_id": receipt.get("registration_id"), "registration": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("trust-network registry receipt signature invalid")

    _verify_times(receipt, now, errors)
    registry = receipt.get("registry", {})
    if not isinstance(registry, dict) or not registry.get("name") or not registry.get("endpoint") or not registry.get("namespace"):
        errors.append("trust-network registry name, endpoint, and namespace are required")
    registration = receipt.get("registration", {})
    if not isinstance(registration, dict):
        errors.append("trust-network registry registration must be an object")
        registration = {}
    if not registration.get("registration_ref") or not registration.get("idempotency_key"):
        errors.append("trust-network registry registration_ref and idempotency_key are required")
    status = registration.get("status")
    if status not in REGISTRY_STATUSES:
        errors.append("trust-network registry status must be active, suspended, or revoked")
    if registration.get("visibility") not in REGISTRY_VISIBILITIES:
        errors.append("trust-network registry visibility must be private, buyer-vendor, or public")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) < 2:
        errors.append("trust-network registry must include trust-network and vendor identity source artifacts")
        artifacts = []

    if trust_network_manifest is None:
        warnings.append("trust-network manifest source not supplied; verified registry binding only")
    else:
        manifest_result = verify_trust_network_manifest(
            trust_network_manifest,
            proof_packs=proof_packs,
            key=key,
        )
        if not manifest_result.ok:
            errors.extend(f"source trust-network manifest invalid: {error}" for error in manifest_result.errors)
        warnings.extend(f"source trust-network manifest warning: {warning}" for warning in manifest_result.warnings)
        _compare_artifact(_artifact_by_name(artifacts, "trust_network_manifest"), _trust_network_artifact(trust_network_manifest), errors)
        if receipt.get("trust_network") != _trust_network_record(trust_network_manifest):
            errors.append("trust-network registry manifest binding does not match source manifest")

    if vendor_identity_receipt is None:
        warnings.append("vendor identity receipt source not supplied; verified registry binding only")
    else:
        vendor_result = verify_vendor_identity_receipt(
            vendor_identity_receipt,
            proof_packs=proof_packs,
            trust_network_manifest=trust_network_manifest,
            key=key,
        )
        if not vendor_result.ok:
            errors.extend(f"source vendor identity receipt invalid: {error}" for error in vendor_result.errors)
        warnings.extend(f"source vendor identity warning: {warning}" for warning in vendor_result.warnings)
        _compare_artifact(_artifact_by_name(artifacts, "vendor_identity_receipt"), _vendor_artifact(vendor_identity_receipt), errors)
        if receipt.get("vendor") != _vendor_record(vendor_identity_receipt):
            errors.append("trust-network registry vendor binding does not match source vendor identity")
        if receipt.get("proof_packs") != _proof_pack_refs(vendor_identity_receipt):
            errors.append("trust-network registry proof-pack refs do not match source vendor identity")

    if trust_network_manifest is not None and vendor_identity_receipt is not None:
        try:
            _validate_vendor_network_binding(trust_network_manifest, vendor_identity_receipt)
        except ValueError as exc:
            errors.append(str(exc))

    if identity_provider_attestation is None:
        if _artifact_by_name(artifacts, "identity_provider_attestation") is not None:
            warnings.append("identity provider attestation source not supplied; verified registry binding only")
    else:
        identity_result = verify_identity_provider_attestation(
            identity_provider_attestation,
            identity_payload=identity_payload,
            vendor_identity_receipt=vendor_identity_receipt,
            proof_packs=proof_packs,
            trust_network_manifest=trust_network_manifest,
            key=key,
        )
        if not identity_result.ok:
            errors.extend(f"source identity provider attestation invalid: {error}" for error in identity_result.errors)
        warnings.extend(f"source identity provider warning: {warning}" for warning in identity_result.warnings)
        _compare_artifact(
            _artifact_by_name(artifacts, "identity_provider_attestation"),
            _identity_artifact(identity_provider_attestation),
            errors,
        )
        if receipt.get("identity_provider") != _identity_record(identity_provider_attestation):
            errors.append("trust-network registry identity-provider binding does not match source attestation")
        if vendor_identity_receipt is not None and trust_network_manifest is not None:
            try:
                _validate_identity_binding(identity_provider_attestation, vendor_identity_receipt, trust_network_manifest)
            except ValueError as exc:
                errors.append(str(exc))

    if procurement_receipt is None:
        if _artifact_by_name(artifacts, "procurement_clause_receipt") is not None:
            warnings.append("procurement clause receipt source not supplied; verified registry binding only")
    else:
        procurement_result = verify_procurement_clause_receipt(
            procurement_receipt,
            trust_network_manifest=trust_network_manifest,
            proof_packs=proof_packs,
            key=key,
        )
        if not procurement_result.ok:
            errors.extend(f"source procurement clause receipt invalid: {error}" for error in procurement_result.errors)
        warnings.extend(f"source procurement clause warning: {warning}" for warning in procurement_result.warnings)
        _compare_artifact(
            _artifact_by_name(artifacts, "procurement_clause_receipt"),
            _procurement_artifact(procurement_receipt),
            errors,
        )
        if trust_network_manifest is not None:
            try:
                _validate_procurement_binding(procurement_receipt, trust_network_manifest)
            except ValueError as exc:
                errors.append(str(exc))

    if procurement_integration_receipt is None:
        if _artifact_by_name(artifacts, "procurement_integration_receipt") is not None:
            warnings.append("procurement integration receipt source not supplied; verified registry binding only")
    else:
        integration_result = verify_procurement_integration_receipt(
            procurement_integration_receipt,
            procurement_receipt=procurement_receipt,
            vendor_identity_receipt=vendor_identity_receipt,
            trust_network_manifest=trust_network_manifest,
            proof_packs=proof_packs,
            key=key,
        )
        if not integration_result.ok:
            errors.extend(f"source procurement integration receipt invalid: {error}" for error in integration_result.errors)
        warnings.extend(f"source procurement integration warning: {warning}" for warning in integration_result.warnings)
        _compare_artifact(
            _artifact_by_name(artifacts, "procurement_integration_receipt"),
            _integration_artifact(procurement_integration_receipt),
            errors,
        )

    if procurement_receipt is not None or procurement_integration_receipt is not None:
        expected_procurement = _procurement_record(procurement_receipt, procurement_integration_receipt)
        if receipt.get("procurement") != expected_procurement:
            errors.append("trust-network registry procurement binding does not match source receipts")

    if trust_network_manifest is not None and vendor_identity_receipt is not None:
        expected_payload = _registry_payload(
            trust_network_manifest,
            vendor_identity_receipt,
            identity_provider_attestation,
            procurement_receipt,
            procurement_integration_receipt,
        )
        if receipt.get("registry_payload") != expected_payload:
            errors.append("trust-network registry payload does not match supplied source artifacts")

    return TrustNetworkRegistryVerification(ok=not errors, errors=errors, warnings=warnings, status=status)


def append_trust_network_registry_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    trust_network_manifest: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    procurement_receipt: dict[str, Any] | None = None,
    procurement_integration_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_trust_network_registry_receipt(
        receipt,
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
        raise ValueError("invalid trust-network registry receipt: " + "; ".join(result.errors))
    payload = {
        "registration_id": receipt["registration_id"],
        "registration_hash": content_hash(receipt),
        "registry": receipt.get("registry"),
        "registration": receipt.get("registration"),
        "vendor": receipt.get("vendor"),
        "trust_network": receipt.get("trust_network"),
        "identity_provider": receipt.get("identity_provider"),
        "procurement": _procurement_ref(receipt.get("procurement")),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(TRUST_NETWORK_REGISTRY_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("published_at"))


def load_trust_network_registry_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("trust-network registry receipt must contain an object")
    return value


def write_trust_network_registry_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _registry_payload(
    manifest: dict[str, Any],
    vendor_receipt: dict[str, Any],
    identity_attestation: dict[str, Any] | None,
    procurement_receipt: dict[str, Any] | None,
    integration_receipt: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema": "trustai.trust-network-registry-payload/0.1",
        "manifest_id": manifest.get("manifest_id"),
        "vendor_identity_receipt_id": vendor_receipt.get("receipt_id"),
        "identity_provider_attestation_id": (identity_attestation or {}).get("attestation_id"),
        "procurement_clause_receipt_id": (procurement_receipt or {}).get("receipt_id"),
        "procurement_integration_id": (integration_receipt or {}).get("integration_id"),
        "buyer": manifest.get("buyer"),
        "vendor": _vendor_record(vendor_receipt),
        "trust_network": _trust_network_record(manifest),
        "proof_pack_ids": [record.get("pack_id") for record in vendor_receipt.get("proof_packs", []) if isinstance(record, dict)],
        "accepted": bool((vendor_receipt.get("trust_network") or {}).get("accepted", False)),
    }


def _source_artifacts(
    manifest: dict[str, Any],
    vendor_receipt: dict[str, Any],
    identity_attestation: dict[str, Any] | None,
    procurement_receipt: dict[str, Any] | None,
    integration_receipt: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    artifacts = [_trust_network_artifact(manifest), _vendor_artifact(vendor_receipt)]
    if identity_attestation is not None:
        artifacts.append(_identity_artifact(identity_attestation))
    if procurement_receipt is not None:
        artifacts.append(_procurement_artifact(procurement_receipt))
    if integration_receipt is not None:
        artifacts.append(_integration_artifact(integration_receipt))
    return artifacts


def _trust_network_record(manifest: dict[str, Any]) -> dict[str, Any]:
    clause = manifest.get("procurement_clause", {})
    summary = manifest.get("network_summary", {})
    return {
        "manifest_id": manifest.get("manifest_id"),
        "content_hash": content_hash(manifest),
        "buyer": manifest.get("buyer"),
        "clause_hash": content_hash(clause),
        "clause_name": clause.get("name"),
        "vendor_count": summary.get("vendor_count"),
        "accepted_vendor_count": summary.get("accepted_vendor_count"),
        "required_frameworks": clause.get("required_frameworks", []),
        "accepted_risk_classes": clause.get("accepted_risk_classes", []),
    }


def _vendor_record(receipt: dict[str, Any]) -> dict[str, Any]:
    vendor = receipt.get("vendor", {})
    network = receipt.get("trust_network") or {}
    return {
        "receipt_id": receipt.get("receipt_id"),
        "content_hash": content_hash(receipt),
        "name": vendor.get("name"),
        "legal_name": vendor.get("legal_name"),
        "subject_ref": vendor.get("subject_ref"),
        "domain": vendor.get("domain"),
        "identity_provider": vendor.get("identity_provider"),
        "identity_id": vendor.get("identity_id"),
        "trust_network_manifest_id": network.get("manifest_id"),
        "accepted_in_network": bool(network.get("accepted", False)),
        "proof_pack_count": len([record for record in receipt.get("proof_packs", []) if isinstance(record, dict)]),
    }


def _proof_pack_refs(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "pack_id": record.get("pack_id"),
            "content_hash": record.get("content_hash"),
            "contract_id": record.get("contract_id"),
            "gate_outcome": record.get("gate_outcome"),
            "agent": record.get("agent"),
        }
        for record in receipt.get("proof_packs", [])
        if isinstance(record, dict)
    ]


def _identity_record(attestation: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(attestation, dict):
        return None
    authentication = attestation.get("authentication", {})
    subject = attestation.get("subject", {})
    binding = attestation.get("vendor_binding") or {}
    return {
        "attestation_id": attestation.get("attestation_id"),
        "content_hash": content_hash(attestation),
        "provider": authentication.get("provider"),
        "tenant_ref": authentication.get("tenant_ref"),
        "method": authentication.get("method"),
        "subject_ref": subject.get("subject_ref"),
        "identity_id": subject.get("identity_id"),
        "identity_record_hash": subject.get("identity_record_hash"),
        "vendor_identity_receipt_id": binding.get("receipt_id"),
        "trust_network_manifest_id": binding.get("trust_network_manifest_id"),
        "provider_identity_matches_vendor": binding.get("provider_identity_matches_vendor"),
    }


def _procurement_record(
    procurement_receipt: dict[str, Any] | None,
    integration_receipt: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(procurement_receipt, dict) and not isinstance(integration_receipt, dict):
        return None
    contract = (procurement_receipt or {}).get("contract", {})
    requirements = (procurement_receipt or {}).get("requirements", {})
    request = (integration_receipt or {}).get("request", {})
    system = (integration_receipt or {}).get("procurement_system", {})
    return {
        "clause_receipt_id": (procurement_receipt or {}).get("receipt_id"),
        "clause_content_hash": content_hash(procurement_receipt) if procurement_receipt is not None else None,
        "contract_ref": contract.get("contract_ref"),
        "trust_network_manifest_id": requirements.get("trust_network_manifest_id"),
        "integration_id": (integration_receipt or {}).get("integration_id"),
        "integration_content_hash": content_hash(integration_receipt) if integration_receipt is not None else None,
        "mode": (integration_receipt or {}).get("mode"),
        "procurement_system": system.get("name"),
        "request_target_url": request.get("target_url"),
        "request_body_hash": request.get("body_hash"),
    }


def _trust_network_artifact(manifest: dict[str, Any]) -> dict[str, Any]:
    summary = manifest.get("network_summary", {})
    return {
        "name": "trust_network_manifest",
        "artifact_type": "trustai.trust-network-manifest",
        "content_hash": content_hash(manifest),
        "manifest_id": manifest.get("manifest_id"),
        "buyer": manifest.get("buyer"),
        "vendor_count": summary.get("vendor_count"),
        "accepted_vendor_count": summary.get("accepted_vendor_count"),
    }


def _vendor_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    vendor = receipt.get("vendor", {})
    network = receipt.get("trust_network") or {}
    return {
        "name": "vendor_identity_receipt",
        "artifact_type": "trustai.vendor-identity",
        "content_hash": content_hash(receipt),
        "receipt_id": receipt.get("receipt_id"),
        "vendor": vendor.get("name"),
        "subject_ref": vendor.get("subject_ref"),
        "trust_network_manifest_id": network.get("manifest_id"),
        "accepted_in_network": bool(network.get("accepted", False)),
    }


def _identity_artifact(attestation: dict[str, Any]) -> dict[str, Any]:
    authentication = attestation.get("authentication", {})
    subject = attestation.get("subject", {})
    binding = attestation.get("vendor_binding") or {}
    return {
        "name": "identity_provider_attestation",
        "artifact_type": "trustai.identity-provider-attestation",
        "content_hash": content_hash(attestation),
        "attestation_id": attestation.get("attestation_id"),
        "provider": authentication.get("provider"),
        "identity_id": subject.get("identity_id"),
        "subject_ref": subject.get("subject_ref"),
        "vendor_identity_receipt_id": binding.get("receipt_id"),
        "trust_network_manifest_id": binding.get("trust_network_manifest_id"),
    }


def _procurement_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    buyer = receipt.get("buyer", {})
    contract = receipt.get("contract", {})
    requirements = receipt.get("requirements", {})
    return {
        "name": "procurement_clause_receipt",
        "artifact_type": "trustai.procurement-clause",
        "content_hash": content_hash(receipt),
        "receipt_id": receipt.get("receipt_id"),
        "buyer": buyer.get("name"),
        "contract_ref": contract.get("contract_ref"),
        "trust_network_manifest_id": requirements.get("trust_network_manifest_id"),
    }


def _integration_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    system = receipt.get("procurement_system", {})
    artifacts = receipt.get("source_artifacts", [])
    return {
        "name": "procurement_integration_receipt",
        "artifact_type": "trustai.procurement-integration",
        "content_hash": content_hash(receipt),
        "integration_id": receipt.get("integration_id"),
        "mode": receipt.get("mode"),
        "procurement_system": system.get("name"),
        "procurement_clause_receipt_id": _artifact_by_name(artifacts, "procurement_clause_receipt").get("receipt_id")
        if _artifact_by_name(artifacts, "procurement_clause_receipt")
        else None,
        "vendor_identity_receipt_id": _artifact_by_name(artifacts, "vendor_identity_receipt").get("receipt_id")
        if _artifact_by_name(artifacts, "vendor_identity_receipt")
        else None,
        "trust_network_manifest_id": _artifact_by_name(artifacts, "trust_network_manifest").get("manifest_id")
        if _artifact_by_name(artifacts, "trust_network_manifest")
        else None,
    }


def _controls_for(
    *,
    registry_endpoint: str,
    has_identity_attestation: bool,
    has_procurement: bool,
    has_procurement_integration: bool,
) -> list[dict[str, str]]:
    hosted_status = "planned-production" if registry_endpoint == "local-registry" else "local-reference"
    return [
        {
            "id": "registry-publication-binding",
            "status": "implemented-reference",
            "description": "Receipt binds registry publication metadata to source trust-network and vendor evidence hashes.",
        },
        {
            "id": "source-artifact-deep-verification",
            "status": "implemented-reference",
            "description": "Verifier can deep-check supplied source manifest, identity, procurement, and proof-pack artifacts.",
        },
        {
            "id": "identity-provider-attestation-binding",
            "status": "implemented-reference" if has_identity_attestation else "planned-production",
            "description": "Registry publication can bind a recorded provider identity attestation for the vendor agent.",
        },
        {
            "id": "procurement-registration-binding",
            "status": "implemented-reference" if has_procurement else "planned-production",
            "description": "Registry publication can bind buyer procurement clause adoption evidence.",
        },
        {
            "id": "procurement-platform-integration",
            "status": "implemented-reference" if has_procurement_integration else "planned-production",
            "description": "Registry publication can bind procurement-system payload evidence or provider response receipts.",
        },
        {
            "id": "hosted-registry-authentication",
            "status": hosted_status,
            "description": "Production deployments should publish through an authenticated hosted cross-org trust-network registry.",
        },
    ]


def _validate_vendor_network_binding(manifest: dict[str, Any], vendor_receipt: dict[str, Any]) -> None:
    network = vendor_receipt.get("trust_network") or {}
    if not network.get("accepted"):
        raise ValueError("vendor identity receipt must include accepted trust-network binding")
    if network.get("manifest_id") != manifest.get("manifest_id"):
        raise ValueError("vendor identity receipt must reference the supplied trust-network manifest")
    vendor = vendor_receipt.get("vendor", {}).get("name")
    pack_ids = {record.get("pack_id") for record in vendor_receipt.get("proof_packs", []) if isinstance(record, dict)}
    accepted_submissions = [
        submission
        for submission in manifest.get("submissions", [])
        if isinstance(submission, dict)
        and submission.get("vendor") == vendor
        and submission.get("accepted")
        and submission.get("proof_pack", {}).get("pack_id") in pack_ids
    ]
    if len(accepted_submissions) != len(pack_ids):
        raise ValueError("trust-network manifest must include accepted submissions for all vendor identity proof packs")


def _validate_identity_binding(
    attestation: dict[str, Any],
    vendor_receipt: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    binding = attestation.get("vendor_binding") or {}
    if binding.get("receipt_id") != vendor_receipt.get("receipt_id"):
        raise ValueError("identity provider attestation must reference the supplied vendor identity receipt")
    if binding.get("trust_network_manifest_id") != manifest.get("manifest_id"):
        raise ValueError("identity provider attestation must reference the supplied trust-network manifest")
    if binding.get("provider_identity_matches_vendor") is not True:
        raise ValueError("identity provider attestation must match the vendor identity provider reference")


def _validate_procurement_binding(receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
    if receipt.get("requirements", {}).get("trust_network_manifest_id") != manifest.get("manifest_id"):
        raise ValueError("procurement clause receipt must reference the supplied trust-network manifest")
    if receipt.get("requirements", {}).get("accepted_vendor_count", 0) < 1:
        raise ValueError("procurement clause receipt must include at least one accepted vendor")


def _verify_times(receipt: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        published = parse_rfc3339(str(receipt.get("published_at")))
        expires_at = receipt.get("expires_at")
        if expires_at:
            expires = parse_rfc3339(str(expires_at))
            if expires <= published:
                errors.append("trust-network registry expires_at must be after published_at")
            if now and parse_rfc3339(now) > expires:
                errors.append("trust-network registry receipt is expired")
    except ValueError as exc:
        errors.append(f"invalid trust-network registry time field: {exc}")


def _validate_expiry(published_at: Any, expires_at: Any) -> None:
    published = parse_rfc3339(str(published_at))
    expires = parse_rfc3339(str(expires_at))
    if expires <= published:
        raise ValueError("trust-network registry expires_at must be after published_at")


def _artifact_by_name(artifacts: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"trust-network registry missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "receipt_id": artifact.get("receipt_id"),
        "attestation_id": artifact.get("attestation_id"),
        "integration_id": artifact.get("integration_id"),
        "manifest_id": artifact.get("manifest_id"),
    }


def _procurement_ref(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(record, dict):
        return None
    return {
        "clause_receipt_id": record.get("clause_receipt_id"),
        "contract_ref": record.get("contract_ref"),
        "integration_id": record.get("integration_id"),
        "mode": record.get("mode"),
        "procurement_system": record.get("procurement_system"),
        "request_body_hash": record.get("request_body_hash"),
    }


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
