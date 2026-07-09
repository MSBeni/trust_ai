from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .procurement_clause import verify_procurement_clause_receipt
from .vendor_identity import verify_vendor_identity_receipt

PROCUREMENT_INTEGRATION_SCHEMA = "trustai.procurement-integration/0.1"
PROCUREMENT_INTEGRATION_ENTRY_TYPE = "procurement.integration.recorded"
PROCUREMENT_PAYLOAD_SCHEMA = "trustai.procurement-system-payload/0.1"


@dataclass
class ProcurementIntegrationVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_procurement_integration_receipt(
    procurement_receipt: dict[str, Any],
    vendor_identity_receipt: dict[str, Any],
    *,
    trust_network_manifest: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    procurement_system: str = "local-procurement",
    endpoint_base: str = "local-procurement",
    credential_ref: str = "local-reference",
    mode: str = "dry-run",
    request_method: str = "POST",
    request_path: str = "/trustai/vendor-proof-pack-acceptances",
    integration_ref: str | None = None,
    delivered_at: str | None = None,
    response_status: int | None = None,
    response_body: Any | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _require_text(procurement_system, "procurement_system")
    _require_text(endpoint_base, "endpoint_base")
    _require_text(credential_ref, "credential_ref")
    _require_text(request_method, "request_method")
    _require_text(request_path, "request_path")
    if mode not in {"dry-run", "recorded-response"}:
        raise ValueError("mode must be dry-run or recorded-response")
    delivered = delivered_at or utc_now()
    parse_rfc3339(delivered)

    procurement_result = verify_procurement_clause_receipt(
        procurement_receipt,
        trust_network_manifest=trust_network_manifest,
        proof_packs=proof_packs,
        key=key,
    )
    if not procurement_result.ok:
        raise ValueError("invalid procurement clause receipt: " + "; ".join(procurement_result.errors))
    vendor_result = verify_vendor_identity_receipt(
        vendor_identity_receipt,
        proof_packs=proof_packs,
        trust_network_manifest=trust_network_manifest,
        key=key,
    )
    if not vendor_result.ok:
        raise ValueError("invalid vendor identity receipt: " + "; ".join(vendor_result.errors))
    _validate_source_consistency(procurement_receipt, vendor_identity_receipt)

    request_body = _request_body(procurement_receipt, vendor_identity_receipt, trust_network_manifest)
    request_body_hash = content_hash(request_body)
    target_url = _target_url(endpoint_base, request_path)
    body: dict[str, Any] = {
        "schema": PROCUREMENT_INTEGRATION_SCHEMA,
        "mode": mode,
        "delivered_at": delivered,
        "procurement_system": {
            "name": procurement_system,
            "endpoint_base": endpoint_base.rstrip("/"),
            "credential": {"ref": credential_ref, "redacted": True},
            "integration_ref": integration_ref,
            "attestation_mode": "local-reference",
            "production_replacement": "authenticated procurement-platform dispatch event and provider response",
        },
        "request": {
            "method": request_method.upper(),
            "path": request_path,
            "target_url": target_url,
            "body": request_body,
            "body_hash": request_body_hash,
            "idempotency_key": content_hash(
                {
                    "procurement_receipt_id": procurement_receipt.get("receipt_id"),
                    "vendor_identity_receipt_id": vendor_identity_receipt.get("receipt_id"),
                    "target_url": target_url,
                }
            )[:32],
        },
        "source_artifacts": _source_artifacts(procurement_receipt, vendor_identity_receipt, trust_network_manifest),
        "controls": _controls_for(mode),
        "limitations": [
            "This receipt records a local-reference procurement integration payload and optional recorded response.",
            "It does not claim live Coupa, SAP Ariba, ServiceNow, or contract-management system dispatch unless a production provider response is supplied.",
            "Production deployments should replace this local receipt with an authenticated procurement-platform event and immutable provider response.",
        ],
    }
    if mode == "recorded-response":
        if response_status is None:
            raise ValueError("response_status is required for recorded-response mode")
        body["response"] = {
            "status": response_status,
            "body_hash": content_hash(response_body),
            "accepted": 200 <= response_status < 300,
        }
    integration_id = content_hash(body)
    return {
        **body,
        "integration_id": integration_id,
        "signatures": [sign_value({"integration_id": integration_id, "integration": body}, key)],
    }


def verify_procurement_integration_receipt(
    receipt: dict[str, Any],
    *,
    procurement_receipt: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> ProcurementIntegrationVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != PROCUREMENT_INTEGRATION_SCHEMA:
        errors.append(f"unsupported procurement integration schema: {receipt.get('schema')}")
    body = without_keys(receipt, "integration_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("integration_id") != expected_id:
        errors.append("integration_id does not match canonical procurement integration body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("procurement integration receipt missing signature")
    else:
        signed_value = {"integration_id": receipt.get("integration_id"), "integration": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("procurement integration receipt signature invalid")

    try:
        parse_rfc3339(str(receipt.get("delivered_at")))
    except ValueError as exc:
        errors.append(f"invalid procurement integration delivered_at: {exc}")

    if receipt.get("mode") not in {"dry-run", "recorded-response"}:
        errors.append("procurement integration mode must be dry-run or recorded-response")
    if receipt.get("mode") == "dry-run":
        warnings.append("procurement integration is a dry-run receipt; no procurement provider response is claimed")
    else:
        response = receipt.get("response", {})
        if not isinstance(response, dict) or response.get("status") is None or not response.get("body_hash"):
            errors.append("recorded-response procurement integration must include response status and body_hash")

    system = receipt.get("procurement_system", {})
    credential = system.get("credential", {}) if isinstance(system, dict) else {}
    if not isinstance(system, dict) or not system.get("name") or not system.get("endpoint_base"):
        errors.append("procurement integration system name and endpoint_base are required")
    if not isinstance(credential, dict) or not credential.get("ref") or credential.get("redacted") is not True:
        errors.append("procurement integration credential reference must be redacted")

    request = receipt.get("request", {})
    if not isinstance(request, dict):
        errors.append("procurement integration request must be an object")
        request = {}
    request_body = request.get("body")
    if not isinstance(request_body, dict):
        errors.append("procurement integration request body must be an object")
    elif request.get("body_hash") != content_hash(request_body):
        errors.append("procurement integration request body_hash does not match body")
    if not request.get("method") or not request.get("path") or not request.get("target_url"):
        errors.append("procurement integration request method, path, and target_url are required")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) < 2:
        errors.append("procurement integration must include procurement and vendor identity source artifacts")
        artifacts = []

    if procurement_receipt is None:
        warnings.append("procurement clause receipt source not supplied; verified integration binding only")
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
        _compare_artifact(_artifact_by_name(artifacts, "procurement_clause_receipt"), _procurement_artifact(procurement_receipt), errors)

    if vendor_identity_receipt is None:
        warnings.append("vendor identity receipt source not supplied; verified integration binding only")
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

    if procurement_receipt is not None and vendor_identity_receipt is not None:
        try:
            _validate_source_consistency(procurement_receipt, vendor_identity_receipt)
        except ValueError as exc:
            errors.append(str(exc))
        expected_body = _request_body(procurement_receipt, vendor_identity_receipt, trust_network_manifest)
        if request_body != expected_body:
            errors.append("procurement integration request body does not match source receipts")

    if trust_network_manifest is not None:
        _compare_artifact(
            _artifact_by_name(artifacts, "trust_network_manifest"),
            _trust_network_artifact(trust_network_manifest),
            errors,
        )

    return ProcurementIntegrationVerification(ok=not errors, errors=errors, warnings=warnings)


def append_procurement_integration_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    procurement_receipt: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    trust_network_manifest: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_procurement_integration_receipt(
        receipt,
        procurement_receipt=procurement_receipt,
        vendor_identity_receipt=vendor_identity_receipt,
        trust_network_manifest=trust_network_manifest,
        proof_packs=proof_packs,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid procurement integration receipt: " + "; ".join(result.errors))
    payload = {
        "integration_id": receipt["integration_id"],
        "integration_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "procurement_system": receipt.get("procurement_system"),
        "request": {
            "method": receipt.get("request", {}).get("method"),
            "path": receipt.get("request", {}).get("path"),
            "target_url": receipt.get("request", {}).get("target_url"),
            "body_hash": receipt.get("request", {}).get("body_hash"),
            "idempotency_key": receipt.get("request", {}).get("idempotency_key"),
        },
        "response": receipt.get("response"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(PROCUREMENT_INTEGRATION_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("delivered_at"))


def load_procurement_integration_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("procurement integration receipt must contain an object")
    return value


def write_procurement_integration_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _request_body(
    procurement_receipt: dict[str, Any],
    vendor_identity_receipt: dict[str, Any],
    trust_network_manifest: dict[str, Any] | None,
) -> dict[str, Any]:
    vendor = vendor_identity_receipt.get("vendor", {})
    proof_packs = vendor_identity_receipt.get("proof_packs", [])
    network = vendor_identity_receipt.get("trust_network") or {}
    return {
        "schema": PROCUREMENT_PAYLOAD_SCHEMA,
        "buyer": procurement_receipt.get("buyer"),
        "contract": procurement_receipt.get("contract"),
        "requirements": procurement_receipt.get("requirements"),
        "vendor": {
            "name": vendor.get("name"),
            "legal_name": vendor.get("legal_name"),
            "subject_ref": vendor.get("subject_ref"),
            "domain": vendor.get("domain"),
            "identity_provider": vendor.get("identity_provider"),
            "identity_id": vendor.get("identity_id"),
        },
        "proof_packs": [
            {
                "pack_id": pack.get("pack_id"),
                "content_hash": pack.get("content_hash"),
                "contract_id": pack.get("contract_id"),
                "gate_outcome": pack.get("gate_outcome"),
                "agent": pack.get("agent"),
            }
            for pack in proof_packs
            if isinstance(pack, dict)
        ],
        "trust_network": {
            "manifest_id": network.get("manifest_id") or (trust_network_manifest or {}).get("manifest_id"),
            "content_hash": network.get("content_hash") or (content_hash(trust_network_manifest) if trust_network_manifest else None),
            "buyer": network.get("buyer") or (trust_network_manifest or {}).get("buyer"),
            "accepted": bool(network.get("accepted", False)),
        },
        "source_receipts": {
            "procurement_clause_receipt_id": procurement_receipt.get("receipt_id"),
            "vendor_identity_receipt_id": vendor_identity_receipt.get("receipt_id"),
        },
        "decision": {
            "accepted": bool(network.get("accepted", False)) and procurement_receipt.get("requirements", {}).get("accepted_vendor_count", 0) >= 1,
            "reason": "Vendor proof-pack evidence satisfies buyer procurement clause and vendor identity binding.",
        },
    }


def _source_artifacts(
    procurement_receipt: dict[str, Any],
    vendor_identity_receipt: dict[str, Any],
    trust_network_manifest: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    artifacts = [_procurement_artifact(procurement_receipt), _vendor_artifact(vendor_identity_receipt)]
    if trust_network_manifest is not None:
        artifacts.append(_trust_network_artifact(trust_network_manifest))
    return artifacts


def _procurement_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "procurement_clause_receipt",
        "artifact_type": "trustai.procurement-clause",
        "content_hash": content_hash(receipt),
        "receipt_id": receipt.get("receipt_id"),
        "buyer": receipt.get("buyer", {}).get("name"),
        "contract_ref": receipt.get("contract", {}).get("contract_ref"),
        "trust_network_manifest_id": receipt.get("requirements", {}).get("trust_network_manifest_id"),
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


def _trust_network_artifact(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "trust_network_manifest",
        "artifact_type": "trustai.trust-network-manifest",
        "content_hash": content_hash(manifest),
        "manifest_id": manifest.get("manifest_id"),
        "buyer": manifest.get("buyer"),
        "accepted_vendor_count": manifest.get("network_summary", {}).get("accepted_vendor_count"),
    }


def _validate_source_consistency(procurement_receipt: dict[str, Any], vendor_identity_receipt: dict[str, Any]) -> None:
    procurement_manifest_id = procurement_receipt.get("requirements", {}).get("trust_network_manifest_id")
    vendor_manifest_id = (vendor_identity_receipt.get("trust_network") or {}).get("manifest_id")
    if procurement_manifest_id and vendor_manifest_id and procurement_manifest_id != vendor_manifest_id:
        raise ValueError("procurement clause and vendor identity receipts reference different trust-network manifests")
    if not (vendor_identity_receipt.get("trust_network") or {}).get("accepted"):
        raise ValueError("vendor identity receipt must be accepted in a trust-network binding")
    if procurement_receipt.get("requirements", {}).get("accepted_vendor_count", 0) < 1:
        raise ValueError("procurement clause receipt must include at least one accepted vendor")


def _controls_for(mode: str) -> list[dict[str, str]]:
    return [
        {
            "id": "source-receipt-binding",
            "status": "implemented-reference",
            "description": "Receipt binds procurement clause and vendor identity receipts by canonical hash.",
        },
        {
            "id": "procurement-payload-hash",
            "status": "implemented-reference",
            "description": "Receipt records the exact procurement-system request body and canonical body hash.",
        },
        {
            "id": "procurement-provider-response",
            "status": "implemented-reference" if mode == "recorded-response" else "planned-production",
            "description": "Production integrations should include an authenticated provider response or durable platform event.",
        },
    ]


def _artifact_by_name(artifacts: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"procurement integration missing source artifact: {expected['name']}")
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
        "manifest_id": artifact.get("manifest_id"),
    }


def _target_url(endpoint_base: str, path: str) -> str:
    if endpoint_base == "local-procurement":
        return f"local-procurement:{path}"
    return f"{endpoint_base.rstrip('/')}{path}"


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
