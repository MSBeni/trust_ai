from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import CHAIN_SPEC_VERSION, EvidenceChain
from .crypto import sign_value, verify_value
from .keyring import KEYRING_SCHEMA, validate_keyring, verify_chain_with_keyring
from .verifier import verify_proof_pack

TRUST_AUTHORITY_RECEIPT_SCHEMA = "trustai.trust-authority-receipt/0.1"
TRUST_AUTHORITY_ENTRY_TYPE = "trust_authority.attested"


@dataclass
class TrustAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_trust_authority_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("trust authority receipt must contain an object")
    return value


def build_trust_authority_receipt(
    chain: EvidenceChain,
    keyring: dict[str, Any],
    *,
    proof_pack: dict[str, Any] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    validate_keyring(keyring)
    chain_result = verify_chain_with_keyring(chain, keyring)
    if not chain_result.ok:
        raise ValueError("chain failed keyring verification: " + "; ".join(chain_result.errors))

    proof_result = None
    if proof_pack is not None:
        proof_result = verify_proof_pack(proof_pack, keyring=keyring)
        if not proof_result.ok:
            raise ValueError("proof pack failed keyring verification: " + "; ".join(proof_result.errors))

    body: dict[str, Any] = {
        "schema": TRUST_AUTHORITY_RECEIPT_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "authority": {
            "mode": "local-reference",
            "evidence_signing_provider": "local-kms",
            "artifact_signing_provider": "local-dev",
            "timestamp_authority_provider": "local-tsa",
            "production_replacement": "customer-controlled KMS/HSM signing and independent RFC 3161 timestamp authority",
        },
        "chain": _chain_ref(chain),
        "keyring": _keyring_ref(keyring),
        "providers": _provider_summary(chain, keyring, proof_pack),
        "verification": {
            "chain": {
                "ok": True,
                "error_count": 0,
                "verified_entry_count": len(chain.entries),
            },
            "proof_pack": _proof_verification_summary(proof_pack, proof_result),
        },
        "limitations": [
            "This local receipt binds the verification shape for KMS/HSM and TSA-backed deployments.",
            "It does not claim live cloud KMS/HSM signing or an independent RFC 3161 timestamp authority.",
            "Key material is redacted from the receipt; the full keyring is supplied separately for offline verification.",
        ],
    }
    if proof_pack is not None:
        body["proof_pack"] = _proof_pack_ref(proof_pack)

    receipt_id = content_hash(body)
    return {
        **body,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "receipt": body}, key)],
    }


def verify_trust_authority_receipt(
    receipt: dict[str, Any],
    *,
    chain: EvidenceChain | None = None,
    keyring: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    key: str | None = None,
) -> TrustAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != TRUST_AUTHORITY_RECEIPT_SCHEMA:
        errors.append(f"unsupported trust authority receipt schema: {receipt.get('schema')}")
    body = without_keys(receipt, "receipt_id", "signatures")
    expected_receipt_id = content_hash(body)
    if receipt.get("receipt_id") != expected_receipt_id:
        errors.append("receipt_id does not match canonical receipt body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("trust authority receipt must include at least one signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "receipt": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("trust authority receipt signature verification failed")

    verification = receipt.get("verification", {})
    if not isinstance(verification, dict):
        errors.append("trust authority receipt verification summary must be an object")
        verification = {}
    if verification.get("chain", {}).get("ok") is not True:
        errors.append("trust authority receipt does not claim a passing chain verification")

    if keyring is None:
        warnings.append("keyring not supplied for deep trust authority verification")
    else:
        try:
            validate_keyring(keyring)
        except ValueError as exc:
            errors.append(f"keyring invalid: {exc}")
        keyring_ref = receipt.get("keyring", {})
        expected_keyring_ref = _keyring_ref(keyring)
        for field in ("schema", "tenant_id", "content_hash", "keys", "rotation_count"):
            if keyring_ref.get(field) != expected_keyring_ref.get(field):
                errors.append(f"receipt keyring {field} does not match supplied keyring")

    if chain is None:
        warnings.append("evidence chain not supplied for deep trust authority verification")
    elif keyring is None:
        errors.append("keyring is required to verify supplied evidence chain")
    else:
        chain_result = verify_chain_with_keyring(chain, keyring)
        if not chain_result.ok:
            errors.extend(f"chain invalid: {error}" for error in chain_result.errors)
        expected_chain_ref = _chain_ref(chain)
        receipt_chain = receipt.get("chain", {})
        for field in ("tenant_id", "content_hash", "tree", "entry_count", "first_entry_id", "last_entry_id", "entry_type_counts"):
            if receipt_chain.get(field) != expected_chain_ref.get(field):
                errors.append(f"receipt chain {field} does not match supplied chain")

    receipt_has_pack = "proof_pack" in receipt
    if proof_pack is None:
        if receipt_has_pack:
            warnings.append("proof pack not supplied for deep trust authority verification")
    elif keyring is None:
        errors.append("keyring is required to verify supplied proof pack")
    else:
        proof_result = verify_proof_pack(proof_pack, keyring=keyring)
        if not proof_result.ok:
            errors.extend(f"proof pack invalid: {error}" for error in proof_result.errors)
        expected_pack_ref = _proof_pack_ref(proof_pack)
        receipt_pack = receipt.get("proof_pack", {})
        for field in ("pack_id", "content_hash", "contract_hash", "chain_tree", "signature_refs"):
            if receipt_pack.get(field) != expected_pack_ref.get(field):
                errors.append(f"receipt proof_pack {field} does not match supplied proof pack")

    if chain is not None and keyring is not None:
        expected_provider_summary = _provider_summary(chain, keyring, proof_pack if proof_pack is not None else None)
        if receipt.get("providers") != expected_provider_summary:
            errors.append("receipt provider summary does not match supplied artifacts")

    authority = receipt.get("authority", {})
    if authority.get("mode") != "local-reference":
        warnings.append(f"trust authority receipt mode is {authority.get('mode')}")
    if authority.get("evidence_signing_provider") != "local-kms":
        warnings.append("receipt evidence signing provider is not local-kms")
    if authority.get("timestamp_authority_provider") != "local-tsa":
        warnings.append("receipt timestamp authority provider is not local-tsa")

    return TrustAuthorityVerification(ok=not errors, errors=errors, warnings=warnings)


def append_trust_authority_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    source_chain: EvidenceChain | None = None,
    keyring: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_trust_authority_receipt(
        receipt,
        chain=source_chain,
        keyring=keyring,
        proof_pack=proof_pack,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid trust authority receipt: " + "; ".join(result.errors))
    payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "authority": receipt.get("authority"),
        "chain": receipt.get("chain"),
        "keyring": {
            "schema": receipt.get("keyring", {}).get("schema"),
            "tenant_id": receipt.get("keyring", {}).get("tenant_id"),
            "content_hash": receipt.get("keyring", {}).get("content_hash"),
            "rotation_count": receipt.get("keyring", {}).get("rotation_count"),
        },
        "proof_pack": receipt.get("proof_pack"),
        "providers": receipt.get("providers"),
        "verification": receipt.get("verification"),
    }
    return chain.append(TRUST_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("generated_at"))


def write_trust_authority_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _chain_document(chain: EvidenceChain) -> dict[str, Any]:
    return {
        "spec_version": CHAIN_SPEC_VERSION,
        "tenant_id": chain.tenant_id,
        "tree": chain.tree(),
        "entries": chain.entries,
    }


def _chain_ref(chain: EvidenceChain) -> dict[str, Any]:
    entry_counts = Counter(entry.get("entry_type", "") for entry in chain.entries)
    return {
        "tenant_id": chain.tenant_id,
        "content_hash": content_hash(_chain_document(chain)),
        "tree": chain.tree(),
        "entry_count": len(chain.entries),
        "first_entry_id": chain.entries[0]["entry_id"] if chain.entries else None,
        "last_entry_id": chain.entries[-1]["entry_id"] if chain.entries else None,
        "entry_type_counts": dict(sorted(entry_counts.items())),
    }


def _keyring_ref(keyring: dict[str, Any]) -> dict[str, Any]:
    validate_keyring(keyring)
    return {
        "schema": keyring.get("schema"),
        "tenant_id": keyring.get("tenant_id"),
        "content_hash": content_hash(keyring),
        "keys": _redacted_keys(keyring),
        "rotation_count": len(keyring.get("rotations", [])),
    }


def _redacted_keys(keyring: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for key in keyring.get("keys", []):
        records.append(
            {
                item: key.get(item)
                for item in ("key_id", "provider", "alg", "status", "usages", "activated_at", "retired_at")
                if key.get(item) is not None
            }
        )
    return sorted(records, key=lambda item: (item.get("provider", ""), item.get("key_id", "")))


def _proof_pack_ref(proof_pack: dict[str, Any]) -> dict[str, Any]:
    signatures = proof_pack.get("signatures", [])
    return {
        "pack_id": proof_pack.get("pack_id"),
        "content_hash": content_hash(proof_pack),
        "contract_hash": proof_pack.get("contract", {}).get("hash"),
        "chain_tree": proof_pack.get("chain", {}).get("tree"),
        "gate_outcome": proof_pack.get("gate_decision", {}).get("outcome"),
        "signature_refs": _signature_refs(signatures),
    }


def _proof_verification_summary(
    proof_pack: dict[str, Any] | None,
    proof_result: Any | None,
) -> dict[str, Any]:
    if proof_pack is None:
        return {"included": False, "ok": None}
    return {
        "included": True,
        "ok": bool(proof_result and proof_result.ok),
        "warning_count": len(proof_result.warnings if proof_result else []),
        "decision": proof_result.decision if proof_result else None,
    }


def _provider_summary(
    chain: EvidenceChain,
    keyring: dict[str, Any],
    proof_pack: dict[str, Any] | None,
) -> dict[str, Any]:
    entry_signatures = Counter()
    timestamp_tokens = Counter()
    timestamp_signatures = Counter()
    for entry in chain.entries:
        signature = entry.get("signature", {})
        if isinstance(signature, dict):
            entry_signatures[_provider_key(signature)] += 1
        token = entry.get("timestamp_token", {})
        if isinstance(token, dict):
            timestamp_tokens[str(token.get("tsa_id", ""))] += 1
            token_signature = token.get("signature", {})
            if isinstance(token_signature, dict):
                timestamp_signatures[_provider_key(token_signature)] += 1

    keyring_keys = Counter()
    for key in keyring.get("keys", []):
        usages = key.get("usages", [])
        usage_label = ",".join(sorted(usages)) if isinstance(usages, list) else str(usages)
        keyring_keys[f"{key.get('provider')}:{key.get('key_id')}:{key.get('status', 'active')}:{usage_label}"] += 1

    pack_signatures = Counter()
    if proof_pack is not None:
        for signature in proof_pack.get("signatures", []):
            if isinstance(signature, dict):
                pack_signatures[_provider_key(signature)] += 1

    return {
        "chain_entry_signatures": dict(sorted(entry_signatures.items())),
        "timestamp_tokens": dict(sorted(timestamp_tokens.items())),
        "timestamp_token_signatures": dict(sorted(timestamp_signatures.items())),
        "proof_pack_signatures": dict(sorted(pack_signatures.items())),
        "keyring_keys": dict(sorted(keyring_keys.items())),
    }


def _provider_key(signature: dict[str, Any]) -> str:
    return f"{signature.get('provider')}:{signature.get('key_id')}:{signature.get('alg')}"


def _signature_refs(signatures: list[Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for signature in signatures:
        if isinstance(signature, dict):
            refs.append(
                {
                    "schema": signature.get("schema"),
                    "alg": signature.get("alg"),
                    "provider": signature.get("provider"),
                    "key_id": signature.get("key_id"),
                }
            )
    return refs
