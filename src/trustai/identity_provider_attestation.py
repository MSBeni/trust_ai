from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .identity import SUPPORTED_IDENTITY_PROVIDERS, identity_payload_to_inventory
from .vendor_identity import verify_vendor_identity_receipt

IDENTITY_PROVIDER_ATTESTATION_SCHEMA = "trustai.identity-provider-attestation/0.1"
IDENTITY_PROVIDER_ATTESTATION_ENTRY_TYPE = "identity.provider.attested"


@dataclass
class IdentityProviderAttestationVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_identity_provider_attestation(
    identity_payload: dict[str, Any],
    *,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    provider: str | None = None,
    identity_id: str | None = None,
    agent_name: str | None = None,
    subject_ref: str | None = None,
    issuer: str = "trustai-local",
    tenant_ref: str | None = None,
    authentication_method: str = "recorded-export",
    issued_at: str | None = None,
    expires_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _require_text(issuer, "issuer")
    _require_text(authentication_method, "authentication_method")
    issued = issued_at or utc_now()
    parse_rfc3339(issued)
    if expires_at:
        _validate_expiry(issued, expires_at)

    inventory = identity_payload_to_inventory(identity_payload)
    subject = _select_subject(
        inventory,
        provider=provider,
        identity_id=identity_id or _vendor_identity_id(vendor_identity_receipt),
        agent_name=agent_name or _vendor_agent_name(vendor_identity_receipt),
    )
    if subject["identity_provider"] not in SUPPORTED_IDENTITY_PROVIDERS:
        raise ValueError(f"unsupported identity provider: {subject['identity_provider']}")

    vendor_binding = None
    if vendor_identity_receipt is not None:
        result = verify_vendor_identity_receipt(
            vendor_identity_receipt,
            proof_packs=proof_packs,
            trust_network_manifest=trust_network_manifest,
            key=key,
        )
        if not result.ok:
            raise ValueError("invalid vendor identity receipt: " + "; ".join(result.errors))
        vendor_binding = _vendor_binding(vendor_identity_receipt, subject)

    body = {
        "schema": IDENTITY_PROVIDER_ATTESTATION_SCHEMA,
        "issued_at": issued,
        "expires_at": expires_at,
        "issuer": issuer,
        "authentication": {
            "method": authentication_method,
            "provider": subject["identity_provider"],
            "tenant_ref": tenant_ref,
            "observed_at": inventory.get("observed_at"),
            "source": inventory.get("source"),
            "attestation_mode": "local-recorded-export",
            "production_replacement": "provider-authenticated token introspection, SCIM/Graph/Okta API event, or signed identity registry event",
        },
        "source_payload": {
            "content_hash": content_hash(identity_payload),
            "inventory_hash": content_hash(inventory),
            "record_count": len(inventory.get("agents", [])),
            "providers": sorted({agent.get("identity_provider") for agent in inventory.get("agents", []) if agent.get("identity_provider")}),
        },
        "subject": {
            "subject_ref": subject_ref or (vendor_identity_receipt or {}).get("vendor", {}).get("subject_ref"),
            "identity_provider": subject["identity_provider"],
            "identity_id": subject["identity_id"],
            "identity_record_hash": subject["identity_record_hash"],
            "agent": _agent_summary(subject),
        },
        "vendor_binding": vendor_binding,
        "controls": _controls_for(authentication_method, vendor_binding is not None),
        "limitations": [
            "This receipt verifies a recorded identity-provider export and binds it to TrustAI vendor/proof evidence.",
            "It does not claim live identity-provider authentication, provider-signed response validation, or legal entity validation outside the supplied references.",
            "Production deployments should replace this local receipt with a provider-authenticated API event or signed identity registry assertion.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "attestation": body}, key)],
    }


def verify_identity_provider_attestation(
    attestation: dict[str, Any],
    *,
    identity_payload: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> IdentityProviderAttestationVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != IDENTITY_PROVIDER_ATTESTATION_SCHEMA:
        errors.append(f"unsupported identity provider attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical identity provider attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("identity provider attestation missing signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "attestation": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("identity provider attestation signature invalid")

    _verify_times(attestation, now, errors)
    authentication = attestation.get("authentication", {})
    provider = authentication.get("provider") if isinstance(authentication, dict) else None
    if provider not in SUPPORTED_IDENTITY_PROVIDERS:
        errors.append(f"unsupported identity provider: {provider}")
    if not isinstance(authentication, dict) or not authentication.get("method") or not authentication.get("observed_at"):
        errors.append("identity provider authentication method and observed_at are required")
    else:
        try:
            parse_rfc3339(str(authentication.get("observed_at")))
        except ValueError as exc:
            errors.append(f"invalid identity provider observed_at: {exc}")

    subject = attestation.get("subject", {})
    if not isinstance(subject, dict) or not subject.get("identity_provider") or not subject.get("identity_id"):
        errors.append("identity provider attestation subject identity_provider and identity_id are required")

    selected_subject: dict[str, Any] | None = None
    if identity_payload is None:
        warnings.append("identity provider payload source not supplied; verified attestation binding only")
    else:
        try:
            inventory = identity_payload_to_inventory(identity_payload)
            expected_payload = {
                "content_hash": content_hash(identity_payload),
                "inventory_hash": content_hash(inventory),
                "record_count": len(inventory.get("agents", [])),
                "providers": sorted(
                    {agent.get("identity_provider") for agent in inventory.get("agents", []) if agent.get("identity_provider")}
                ),
            }
            if attestation.get("source_payload") != expected_payload:
                errors.append("identity provider source payload binding does not match supplied payload")
            selected = _select_subject(
                inventory,
                provider=subject.get("identity_provider"),
                identity_id=subject.get("identity_id"),
            )
            selected_subject = selected
            if subject.get("identity_record_hash") != selected.get("identity_record_hash"):
                errors.append("identity provider subject identity_record_hash does not match supplied payload")
            if subject.get("agent") != _agent_summary(selected):
                errors.append("identity provider subject agent summary does not match supplied payload")
        except ValueError as exc:
            errors.append(f"identity provider payload invalid: {exc}")

    vendor_binding = attestation.get("vendor_binding")
    if vendor_binding:
        if vendor_identity_receipt is None:
            warnings.append("vendor identity receipt source not supplied; verified identity provider binding only")
        else:
            result = verify_vendor_identity_receipt(
                vendor_identity_receipt,
                proof_packs=proof_packs,
                trust_network_manifest=trust_network_manifest,
                key=key,
            )
            if not result.ok:
                errors.extend(f"source vendor identity receipt invalid: {error}" for error in result.errors)
            warnings.extend(f"source vendor identity warning: {warning}" for warning in result.warnings)
            expected_binding = _vendor_binding(vendor_identity_receipt, selected_subject or _subject_from_attestation(subject))
            if vendor_binding != expected_binding:
                errors.append("vendor identity binding does not match source receipt and subject")
    elif vendor_identity_receipt is not None:
        warnings.append("vendor identity receipt source supplied but attestation has no vendor binding")

    return IdentityProviderAttestationVerification(ok=not errors, errors=errors, warnings=warnings)


def append_identity_provider_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    *,
    identity_payload: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_identity_provider_attestation(
        attestation,
        identity_payload=identity_payload,
        vendor_identity_receipt=vendor_identity_receipt,
        proof_packs=proof_packs,
        trust_network_manifest=trust_network_manifest,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid identity provider attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "authentication": attestation.get("authentication"),
        "subject": attestation.get("subject"),
        "vendor_binding": _vendor_binding_ref(attestation.get("vendor_binding")),
        "source_payload": attestation.get("source_payload"),
        "limitations": attestation.get("limitations", []),
    }
    return chain.append(
        IDENTITY_PROVIDER_ATTESTATION_ENTRY_TYPE,
        payload,
        key=key,
        timestamp=attestation.get("issued_at"),
    )


def load_identity_provider_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("identity provider attestation must contain an object")
    return value


def write_identity_provider_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def _select_subject(
    inventory: dict[str, Any],
    *,
    provider: str | None = None,
    identity_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    agents = [agent for agent in inventory.get("agents", []) if isinstance(agent, dict)]
    if provider:
        provider = _normalize_provider(provider)
        agents = [agent for agent in agents if agent.get("identity_provider") == provider]
    if identity_id:
        agents = [agent for agent in agents if agent.get("identity_id") == identity_id]
    if agent_name:
        agents = [agent for agent in agents if agent.get("name") == agent_name]
    if not agents:
        raise ValueError("identity provider payload did not contain the requested subject")
    if len(agents) > 1:
        raise ValueError("identity provider subject selection is ambiguous")
    return agents[0]


def _vendor_binding(receipt: dict[str, Any], subject: dict[str, Any]) -> dict[str, Any]:
    vendor = receipt.get("vendor", {})
    matching_pack_agents = [
        pack.get("pack_id")
        for pack in receipt.get("proof_packs", [])
        if isinstance(pack, dict) and _agent_matches_subject(pack.get("agent", {}), subject)
    ]
    return {
        "receipt_id": receipt.get("receipt_id"),
        "content_hash": content_hash(receipt),
        "vendor": {
            "name": vendor.get("name"),
            "legal_name": vendor.get("legal_name"),
            "subject_ref": vendor.get("subject_ref"),
            "identity_provider": vendor.get("identity_provider"),
            "identity_id": vendor.get("identity_id"),
        },
        "provider_identity_matches_vendor": (
            vendor.get("identity_provider") == subject.get("identity_provider")
            and vendor.get("identity_id") == subject.get("identity_id")
        ),
        "matching_proof_pack_ids": matching_pack_agents,
        "trust_network_manifest_id": (receipt.get("trust_network") or {}).get("manifest_id"),
    }


def _agent_matches_subject(agent: dict[str, Any], subject: dict[str, Any]) -> bool:
    return (
        agent.get("name") == subject.get("name")
        and agent.get("version") == subject.get("version")
        and agent.get("risk_class") == subject.get("risk_class")
    )


def _agent_summary(agent: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": agent.get("name"),
        "version": agent.get("version"),
        "owner": agent.get("owner"),
        "risk_class": agent.get("risk_class"),
        "environment": agent.get("environment"),
        "governed": agent.get("governed"),
        "contract_id": agent.get("contract_id"),
    }


def _subject_from_attestation(subject: dict[str, Any]) -> dict[str, Any]:
    agent = subject.get("agent", {}) if isinstance(subject, dict) else {}
    return {
        "identity_provider": subject.get("identity_provider"),
        "identity_id": subject.get("identity_id"),
        "identity_record_hash": subject.get("identity_record_hash"),
        "name": agent.get("name"),
        "version": agent.get("version"),
        "owner": agent.get("owner"),
        "risk_class": agent.get("risk_class"),
        "environment": agent.get("environment"),
        "governed": agent.get("governed"),
        "contract_id": agent.get("contract_id"),
    }

def _vendor_binding_ref(binding: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(binding, dict):
        return None
    return {
        "receipt_id": binding.get("receipt_id"),
        "content_hash": binding.get("content_hash"),
        "vendor": binding.get("vendor"),
        "provider_identity_matches_vendor": binding.get("provider_identity_matches_vendor"),
        "matching_proof_pack_ids": binding.get("matching_proof_pack_ids", []),
        "trust_network_manifest_id": binding.get("trust_network_manifest_id"),
    }


def _vendor_identity_id(receipt: dict[str, Any] | None) -> str | None:
    if not isinstance(receipt, dict):
        return None
    value = receipt.get("vendor", {}).get("identity_id")
    return str(value) if value else None


def _vendor_agent_name(receipt: dict[str, Any] | None) -> str | None:
    if not isinstance(receipt, dict):
        return None
    for pack in receipt.get("proof_packs", []):
        if isinstance(pack, dict) and pack.get("agent", {}).get("name"):
            return str(pack["agent"]["name"])
    return None


def _normalize_provider(provider: str) -> str:
    normalized = provider.lower().replace("azure_ad", "entra").replace("microsoft_entra", "entra")
    if normalized not in SUPPORTED_IDENTITY_PROVIDERS:
        raise ValueError(f"unsupported identity provider: {provider}")
    return normalized


def _controls_for(authentication_method: str, has_vendor_binding: bool) -> list[dict[str, str]]:
    return [
        {
            "id": "identity-provider-export-binding",
            "status": "implemented-reference",
            "description": "Receipt binds a recorded identity-provider export by canonical hash and normalized inventory hash.",
        },
        {
            "id": "vendor-proof-evidence-binding",
            "status": "implemented-reference" if has_vendor_binding else "not-applicable",
            "description": "Optional vendor binding links provider identity to TrustAI vendor identity and proof-pack evidence.",
        },
        {
            "id": "live-identity-provider-authentication",
            "status": "planned-production" if authentication_method == "recorded-export" else "local-reference",
            "description": "Production deployments should verify provider-authenticated API responses or signed identity events.",
        },
    ]


def _verify_times(attestation: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        issued = parse_rfc3339(str(attestation.get("issued_at")))
        expires_at = attestation.get("expires_at")
        if expires_at:
            expires = parse_rfc3339(str(expires_at))
            if expires <= issued:
                errors.append("identity provider attestation expires_at must be after issued_at")
            if now and parse_rfc3339(now) > expires:
                errors.append("identity provider attestation is expired")
    except ValueError as exc:
        errors.append(f"invalid identity provider attestation time field: {exc}")


def _validate_expiry(issued_at: Any, expires_at: Any) -> None:
    issued = parse_rfc3339(str(issued_at))
    expires = parse_rfc3339(str(expires_at))
    if expires <= issued:
        raise ValueError("identity provider attestation expires_at must be after issued_at")


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
