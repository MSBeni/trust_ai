from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .trust_network import verify_trust_network_manifest

PROCUREMENT_CLAUSE_SCHEMA = "trustai.procurement-clause/0.1"
PROCUREMENT_CLAUSE_ENTRY_TYPE = "procurement.clause.recorded"


@dataclass
class ProcurementClauseVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_procurement_clause_receipt(
    trust_network_manifest: dict[str, Any],
    *,
    contract_ref: str,
    approver_ref: str,
    buyer: str | None = None,
    legal_entity: str | None = None,
    procurement_system: str = "local-reference",
    effective_at: str,
    expires_at: str | None = None,
    issued_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    issued = issued_at or utc_now()
    _require_text(contract_ref, "contract_ref")
    _require_text(approver_ref, "approver_ref")
    _require_text(procurement_system, "procurement_system")
    parse_rfc3339(issued)
    parse_rfc3339(effective_at)
    if expires_at:
        _validate_expiry(effective_at, expires_at)

    manifest_buyer = trust_network_manifest.get("buyer") or "local-buyer"
    buyer_name = buyer or manifest_buyer
    _require_text(buyer_name, "buyer")
    clause = trust_network_manifest.get("procurement_clause", {})
    clause_hash = content_hash(clause)
    source_artifact = _manifest_record(trust_network_manifest)
    body = {
        "schema": PROCUREMENT_CLAUSE_SCHEMA,
        "issued_at": issued,
        "buyer": {
            "name": buyer_name,
            "legal_entity": legal_entity,
            "approver_ref": approver_ref,
            "procurement_system": procurement_system,
            "attestation_mode": "local-reference",
            "production_replacement": "buyer procurement platform approval or contract-management system event",
        },
        "contract": {
            "contract_ref": contract_ref,
            "effective_at": effective_at,
            "expires_at": expires_at,
            "clause_name": clause.get("name"),
            "clause_hash": clause_hash,
            "clause_text": clause.get("text"),
        },
        "requirements": {
            "trust_network_manifest_id": trust_network_manifest.get("manifest_id"),
            "vendor_count": trust_network_manifest.get("network_summary", {}).get("vendor_count"),
            "accepted_vendor_count": trust_network_manifest.get("network_summary", {}).get("accepted_vendor_count"),
            "required_gate_outcome": clause.get("required_gate_outcome"),
            "required_frameworks": clause.get("required_frameworks", []),
            "accepted_risk_classes": clause.get("accepted_risk_classes", []),
        },
        "source_artifacts": [source_artifact],
        "controls": _controls_for(procurement_system),
        "limitations": [
            "This receipt verifies a local buyer procurement-clause acknowledgement over a TrustAI trust-network manifest.",
            "It does not claim live procurement-platform integration, external buyer authentication, or binding legal acceptance outside the recorded contract reference.",
            "Production deployments should replace this local receipt with a buyer-authenticated procurement or contract-management system event.",
        ],
    }
    receipt_id = content_hash(body)
    return {
        **body,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "receipt": body}, key)],
    }


def verify_procurement_clause_receipt(
    receipt: dict[str, Any],
    *,
    trust_network_manifest: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> ProcurementClauseVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != PROCUREMENT_CLAUSE_SCHEMA:
        errors.append(f"unsupported procurement clause schema: {receipt.get('schema')}")

    body = without_keys(receipt, "receipt_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("receipt_id") != expected_id:
        errors.append("receipt_id does not match canonical procurement clause body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("procurement clause receipt missing signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "receipt": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("procurement clause receipt signature invalid")

    buyer = receipt.get("buyer", {})
    for field in ("name", "approver_ref", "procurement_system"):
        if not buyer.get(field):
            errors.append(f"procurement clause buyer {field} missing")

    contract = receipt.get("contract", {})
    for field in ("contract_ref", "effective_at", "clause_name", "clause_hash", "clause_text"):
        if not contract.get(field):
            errors.append(f"procurement clause contract {field} missing")
    try:
        parse_rfc3339(str(receipt.get("issued_at")))
        parse_rfc3339(str(contract.get("effective_at")))
        if contract.get("expires_at"):
            _validate_expiry(contract.get("effective_at"), contract.get("expires_at"))
    except ValueError as exc:
        errors.append(f"invalid procurement clause time field: {exc}")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        errors.append("procurement clause receipt must include exactly one trust-network source artifact")
        artifacts = []
    artifact = artifacts[0] if artifacts and isinstance(artifacts[0], dict) else None
    if artifact and artifact.get("name") != "trust_network_manifest":
        errors.append("procurement clause source artifact must be trust_network_manifest")

    requirements = receipt.get("requirements", {})
    if requirements.get("accepted_vendor_count", 0) < 1:
        errors.append("procurement clause receipt requires at least one accepted vendor")

    if trust_network_manifest is None:
        if artifact is not None:
            warnings.append("trust-network manifest source not supplied; verified procurement clause binding only")
    else:
        expected = _manifest_record(trust_network_manifest)
        _compare_artifact(artifact, expected, errors)
        manifest_result = verify_trust_network_manifest(
            trust_network_manifest,
            proof_packs=proof_packs,
            key=key,
        )
        if not manifest_result.ok:
            errors.extend(f"source trust-network manifest invalid: {error}" for error in manifest_result.errors)
        warnings.extend(f"source trust-network manifest warning: {warning}" for warning in manifest_result.warnings)
        clause = trust_network_manifest.get("procurement_clause", {})
        if contract.get("clause_hash") != content_hash(clause):
            errors.append("procurement clause hash does not match source manifest clause")
        if requirements != _requirements_record(trust_network_manifest):
            errors.append("procurement clause requirements do not match source manifest")
        manifest_buyer = trust_network_manifest.get("buyer")
        if manifest_buyer and buyer.get("name") != manifest_buyer:
            errors.append("procurement clause buyer does not match trust-network manifest buyer")

    return ProcurementClauseVerification(ok=not errors, errors=errors, warnings=warnings)


def append_procurement_clause_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_procurement_clause_receipt(receipt, key=key)
    if not result.ok:
        raise ValueError("invalid procurement clause receipt: " + "; ".join(result.errors))
    payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "buyer": receipt.get("buyer"),
        "contract": receipt.get("contract"),
        "requirements": receipt.get("requirements"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(PROCUREMENT_CLAUSE_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("issued_at"))


def load_procurement_clause_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("procurement clause receipt must contain an object")
    return value


def write_procurement_clause_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _manifest_record(manifest: dict[str, Any]) -> dict[str, Any]:
    clause = manifest.get("procurement_clause", {})
    summary = manifest.get("network_summary", {})
    return {
        "name": "trust_network_manifest",
        "artifact_type": "trustai.trust-network-manifest",
        "content_hash": content_hash(manifest),
        "manifest_id": manifest.get("manifest_id"),
        "buyer": manifest.get("buyer"),
        "clause_hash": content_hash(clause),
        "clause_name": clause.get("name"),
        "vendor_count": summary.get("vendor_count"),
        "accepted_vendor_count": summary.get("accepted_vendor_count"),
    }


def _requirements_record(manifest: dict[str, Any]) -> dict[str, Any]:
    clause = manifest.get("procurement_clause", {})
    summary = manifest.get("network_summary", {})
    return {
        "trust_network_manifest_id": manifest.get("manifest_id"),
        "vendor_count": summary.get("vendor_count"),
        "accepted_vendor_count": summary.get("accepted_vendor_count"),
        "required_gate_outcome": clause.get("required_gate_outcome"),
        "required_frameworks": clause.get("required_frameworks", []),
        "accepted_risk_classes": clause.get("accepted_risk_classes", []),
    }


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "manifest_id": artifact.get("manifest_id"),
        "clause_hash": artifact.get("clause_hash"),
    }


def _compare_artifact(
    actual: dict[str, Any] | None,
    expected: dict[str, Any],
    errors: list[str],
) -> None:
    if actual is None:
        errors.append(f"procurement clause receipt missing artifact: {expected['name']}")
        return
    for field in (
        "name",
        "artifact_type",
        "content_hash",
        "manifest_id",
        "buyer",
        "clause_hash",
        "clause_name",
        "vendor_count",
        "accepted_vendor_count",
    ):
        if expected.get(field) != actual.get(field):
            errors.append(f"artifact {expected['name']} {field} mismatch")


def _controls_for(procurement_system: str) -> list[dict[str, str]]:
    return [
        {
            "id": "trust-network-manifest-binding",
            "status": "implemented-reference",
            "description": "Receipt binds the trust-network manifest and procurement clause by canonical hash.",
        },
        {
            "id": "buyer-approval-reference",
            "status": "local-reference",
            "description": "Receipt records buyer, approver reference, contract reference, and procurement system reference.",
        },
        {
            "id": "source-proof-pack-verification",
            "status": "implemented-reference",
            "description": "Verifier can deep-check the trust-network manifest and all supplied vendor proof packs.",
        },
        {
            "id": "procurement-platform-integration",
            "status": "planned-production" if procurement_system == "local-reference" else "local-reference",
            "description": "Production deployments should record this receipt from a buyer contract or procurement system.",
        },
    ]


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")


def _validate_expiry(effective_at: Any, expires_at: Any) -> None:
    effective = parse_rfc3339(str(effective_at))
    expires = parse_rfc3339(str(expires_at))
    if expires <= effective:
        raise ValueError("procurement clause expires_at must be after effective_at")
