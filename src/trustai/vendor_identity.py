from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .trust_network import verify_trust_network_manifest
from .verifier import verify_proof_pack

VENDOR_IDENTITY_SCHEMA = "trustai.vendor-identity/0.1"
VENDOR_IDENTITY_ENTRY_TYPE = "vendor.identity.attested"


@dataclass
class VendorIdentityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    proof_pack_count: int = 0
    accepted_in_network: bool = False


def build_vendor_identity_receipt(
    proof_packs: list[dict[str, Any]],
    *,
    vendor: str,
    legal_name: str,
    subject_ref: str,
    domain: str | None = None,
    identity_provider: str | None = None,
    identity_id: str | None = None,
    issuer: str = "trustai-local",
    issued_at: str | None = None,
    expires_at: str | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if not proof_packs:
        raise ValueError("at least one proof pack is required")
    _require_text(vendor, "vendor")
    _require_text(legal_name, "legal_name")
    _require_text(subject_ref, "subject_ref")
    _require_text(issuer, "issuer")

    issued = issued_at or utc_now()
    parse_rfc3339(issued)
    if expires_at:
        _validate_expiry(issued, expires_at)

    pack_records = []
    for pack in proof_packs:
        result = verify_proof_pack(pack, key=key)
        if not result.ok:
            raise ValueError("invalid source proof pack: " + "; ".join(result.errors))
        pack_records.append(_proof_pack_record(pack))

    network_record = None
    if trust_network_manifest is not None:
        manifest_result = verify_trust_network_manifest(
            trust_network_manifest,
            proof_packs=proof_packs,
            key=key,
        )
        if not manifest_result.ok:
            raise ValueError("invalid source trust-network manifest: " + "; ".join(manifest_result.errors))
        network_record = _trust_network_record(trust_network_manifest, vendor, _pack_ids(pack_records))

    body = {
        "schema": VENDOR_IDENTITY_SCHEMA,
        "issued_at": issued,
        "expires_at": expires_at,
        "issuer": issuer,
        "vendor": {
            "name": vendor,
            "legal_name": legal_name,
            "subject_ref": subject_ref,
            "domain": domain,
            "identity_provider": identity_provider,
            "identity_id": identity_id,
            "attestation_mode": "local-reference",
            "production_replacement": "vendor-authenticated identity provider, procurement platform, or registry event",
        },
        "proof_packs": pack_records,
        "trust_network": network_record,
        "controls": _controls_for(identity_provider, trust_network_manifest is not None),
        "limitations": [
            "This receipt binds a local vendor identity reference to TrustAI proof-pack evidence.",
            "It does not claim live identity-provider authentication, external registry enrollment, or legal entity validation outside the supplied references.",
            "Production deployments should replace this local receipt with a vendor-authenticated identity provider, procurement platform, or trust-network registry event.",
        ],
    }
    receipt_id = content_hash(body)
    return {
        **body,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "receipt": body}, key)],
    }


def verify_vendor_identity_receipt(
    receipt: dict[str, Any],
    *,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> VendorIdentityVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != VENDOR_IDENTITY_SCHEMA:
        errors.append(f"unsupported vendor identity schema: {receipt.get('schema')}")

    body = without_keys(receipt, "receipt_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("receipt_id") != expected_id:
        errors.append("receipt_id does not match canonical vendor identity body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("vendor identity receipt missing signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "receipt": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("vendor identity receipt signature invalid")

    vendor = receipt.get("vendor", {})
    for field in ("name", "legal_name", "subject_ref", "attestation_mode"):
        if not isinstance(vendor, dict) or not vendor.get(field):
            errors.append(f"vendor identity {field} missing")

    _verify_times(receipt, now, errors)

    records = receipt.get("proof_packs", [])
    if not isinstance(records, list) or not records:
        errors.append("vendor identity receipt must include at least one proof-pack binding")
        records = []

    pack_ids = _pack_ids(records)
    if len(pack_ids) != len(set(pack_ids)):
        errors.append("vendor identity receipt includes duplicate proof-pack ids")

    if proof_packs is None:
        for pack_id in pack_ids:
            warnings.append(f"source proof pack not supplied for deep verification: {pack_id}")
    else:
        pack_by_id = _source_pack_map(proof_packs, errors)
        for record in records:
            if not isinstance(record, dict):
                errors.append("proof-pack binding must be an object")
                continue
            pack_id = record.get("pack_id")
            pack = pack_by_id.get(pack_id)
            if pack is None:
                errors.append(f"source proof pack not supplied: {pack_id}")
                continue
            _verify_pack_binding(record, pack, errors, warnings, key)

    accepted_in_network = False
    network_record = receipt.get("trust_network")
    if network_record:
        if trust_network_manifest is None:
            warnings.append("trust-network manifest source not supplied; verified vendor identity binding only")
            accepted_in_network = bool(network_record.get("accepted"))
        else:
            manifest_result = verify_trust_network_manifest(
                trust_network_manifest,
                proof_packs=proof_packs,
                key=key,
            )
            if not manifest_result.ok:
                errors.extend(f"source trust-network manifest invalid: {error}" for error in manifest_result.errors)
            warnings.extend(f"source trust-network manifest warning: {warning}" for warning in manifest_result.warnings)
            try:
                expected_network = _trust_network_record(trust_network_manifest, vendor.get("name"), pack_ids)
            except ValueError as exc:
                errors.append(str(exc))
                expected_network = None
            if expected_network is not None and network_record != expected_network:
                errors.append("trust-network binding does not match source manifest")
            accepted_in_network = bool(expected_network and expected_network.get("accepted"))
    elif trust_network_manifest is not None:
        warnings.append("source trust-network manifest supplied but receipt has no trust-network binding")

    return VendorIdentityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        proof_pack_count=len(records),
        accepted_in_network=accepted_in_network,
    )


def append_vendor_identity_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    proof_packs: list[dict[str, Any]] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_vendor_identity_receipt(
        receipt,
        proof_packs=proof_packs,
        trust_network_manifest=trust_network_manifest,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid vendor identity receipt: " + "; ".join(result.errors))
    payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "vendor": receipt.get("vendor"),
        "proof_packs": [_proof_pack_ref(record) for record in receipt.get("proof_packs", [])],
        "trust_network": _trust_network_ref(receipt.get("trust_network")),
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(VENDOR_IDENTITY_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("issued_at"))


def load_vendor_identity_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("vendor identity receipt must contain an object")
    return value


def write_vendor_identity_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _proof_pack_record(pack: dict[str, Any]) -> dict[str, Any]:
    decision = pack.get("gate_decision", {})
    agent = decision.get("agent", {})
    tree = pack.get("chain", {}).get("tree", {})
    return {
        "pack_id": pack.get("pack_id"),
        "content_hash": content_hash(pack),
        "issued_at": pack.get("issued_at"),
        "contract_id": decision.get("contract_id"),
        "contract_hash": decision.get("contract_hash") or pack.get("contract", {}).get("hash"),
        "gate_outcome": decision.get("outcome"),
        "agent": {
            "name": agent.get("name"),
            "version": agent.get("version"),
            "framework": agent.get("framework"),
            "risk_class": agent.get("risk_class"),
        },
        "chain": {
            "root": tree.get("root"),
            "size": tree.get("size"),
        },
    }


def _trust_network_record(manifest: dict[str, Any], vendor: str | None, pack_ids: list[str]) -> dict[str, Any]:
    vendor_name = vendor or ""
    submissions = [
        submission
        for submission in manifest.get("submissions", [])
        if isinstance(submission, dict)
        and submission.get("vendor") == vendor_name
        and submission.get("proof_pack", {}).get("pack_id") in pack_ids
    ]
    represented = {submission.get("proof_pack", {}).get("pack_id") for submission in submissions}
    missing = [pack_id for pack_id in pack_ids if pack_id not in represented]
    if missing or not submissions:
        raise ValueError("trust-network manifest does not include accepted vendor submission for all receipt proof packs")
    if not all(submission.get("accepted") for submission in submissions):
        raise ValueError("trust-network manifest includes rejected vendor submission")

    clause = manifest.get("procurement_clause", {})
    return {
        "manifest_id": manifest.get("manifest_id"),
        "content_hash": content_hash(manifest),
        "buyer": manifest.get("buyer"),
        "accepted": True,
        "procurement_clause": {
            "name": clause.get("name"),
            "clause_hash": content_hash(clause),
            "required_gate_outcome": clause.get("required_gate_outcome"),
            "required_frameworks": clause.get("required_frameworks", []),
            "accepted_risk_classes": clause.get("accepted_risk_classes", []),
        },
        "submissions": [
            {
                "vendor": submission.get("vendor"),
                "submission_id": submission.get("submission_id"),
                "pack_id": submission.get("proof_pack", {}).get("pack_id"),
                "accepted": submission.get("accepted"),
                "requirement_results": submission.get("requirement_results", []),
            }
            for submission in submissions
        ],
    }


def _verify_pack_binding(
    record: dict[str, Any],
    pack: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    key: str | None,
) -> None:
    expected = _proof_pack_record(pack)
    if record != expected:
        if record.get("content_hash") != expected.get("content_hash"):
            errors.append(f"proof pack source hash mismatch: {record.get('pack_id')}")
        for field in ("pack_id", "contract_id", "contract_hash", "gate_outcome", "issued_at"):
            if record.get(field) != expected.get(field):
                errors.append(f"proof pack binding {field} mismatch: {record.get('pack_id')}")
        if record.get("agent") != expected.get("agent"):
            errors.append(f"proof pack binding agent mismatch: {record.get('pack_id')}")
        if record.get("chain") != expected.get("chain"):
            errors.append(f"proof pack binding chain mismatch: {record.get('pack_id')}")
    result = verify_proof_pack(pack, key=key)
    if not result.ok:
        errors.extend(f"source proof pack invalid: {error}" for error in result.errors)
    warnings.extend(f"source proof pack warning: {warning}" for warning in result.warnings)


def _source_pack_map(packs: list[dict[str, Any]], errors: list[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for pack in packs:
        pack_id = pack.get("pack_id")
        if not pack_id:
            errors.append("source proof pack missing pack_id")
            continue
        if pack_id in result:
            errors.append(f"duplicate source proof pack id: {pack_id}")
            continue
        result[pack_id] = pack
    return result


def _pack_ids(records: list[dict[str, Any]]) -> list[str]:
    return [str(record.get("pack_id")) for record in records if isinstance(record, dict) and record.get("pack_id")]


def _proof_pack_ref(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "pack_id": record.get("pack_id"),
        "content_hash": record.get("content_hash"),
        "contract_id": record.get("contract_id"),
        "gate_outcome": record.get("gate_outcome"),
        "agent": record.get("agent"),
    }


def _trust_network_ref(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(record, dict):
        return None
    return {
        "manifest_id": record.get("manifest_id"),
        "content_hash": record.get("content_hash"),
        "buyer": record.get("buyer"),
        "accepted": record.get("accepted"),
        "submissions": [
            {
                "submission_id": submission.get("submission_id"),
                "pack_id": submission.get("pack_id"),
                "accepted": submission.get("accepted"),
            }
            for submission in record.get("submissions", [])
            if isinstance(submission, dict)
        ],
    }


def _controls_for(identity_provider: str | None, has_trust_network: bool) -> list[dict[str, str]]:
    return [
        {
            "id": "vendor-identity-binding",
            "status": "implemented-reference",
            "description": "Receipt binds vendor legal identity references to source proof-pack hashes.",
        },
        {
            "id": "proof-pack-deep-verification",
            "status": "implemented-reference",
            "description": "Verifier can deep-check source proof packs when supplied.",
        },
        {
            "id": "trust-network-acceptance-binding",
            "status": "implemented-reference" if has_trust_network else "not-applicable",
            "description": "Optional trust-network binding proves the vendor submission was accepted by buyer requirements.",
        },
        {
            "id": "identity-provider-authentication",
            "status": "planned-production" if not identity_provider else "local-reference",
            "description": "Production deployments should authenticate vendor identity through an external identity provider or registry.",
        },
    ]


def _verify_times(receipt: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        issued_at = receipt.get("issued_at")
        issued = parse_rfc3339(str(issued_at))
        expires_at = receipt.get("expires_at")
        if expires_at:
            expires = parse_rfc3339(str(expires_at))
            if expires <= issued:
                errors.append("vendor identity expires_at must be after issued_at")
            if now and parse_rfc3339(now) > expires:
                errors.append("vendor identity receipt is expired")
    except ValueError as exc:
        errors.append(f"invalid vendor identity time field: {exc}")


def _validate_expiry(issued_at: Any, expires_at: Any) -> None:
    issued = parse_rfc3339(str(issued_at))
    expires = parse_rfc3339(str(expires_at))
    if expires <= issued:
        raise ValueError("vendor identity expires_at must be after issued_at")


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
