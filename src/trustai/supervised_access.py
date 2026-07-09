from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .insurer import build_insurer_telemetry
from .regulator import verify_regulator_disclosure
from .verifier import verify_proof_pack

SUPERVISED_ACCESS_SCHEMA = "trustai.supervised-access/0.1"
SUPERVISED_ACCESS_ENTRY_TYPE = "supervised.access.granted"

AUDIENCE_TYPES = {"auditor", "regulator", "insurer", "procurement"}


@dataclass
class SupervisedAccessVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_supervised_access_receipt(
    proof_pack: dict[str, Any],
    *,
    subject_ref: str,
    organization: str,
    role: str,
    audience_type: str = "regulator",
    purpose: str = "supervised proof-pack review",
    expires_at: str,
    proof_pack_path: str | Path | None = None,
    disclosure: dict[str, Any] | None = None,
    disclosure_path: str | Path | None = None,
    view_path: str | Path | None = None,
    insurer_telemetry: dict[str, Any] | None = None,
    insurer_telemetry_path: str | Path | None = None,
    issued_at: str | None = None,
    auth_context: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    issued = issued_at or utc_now()
    _validate_time_window(issued, expires_at)
    audience = _audience(audience_type, purpose)
    reviewer = _reviewer(subject_ref, organization, role, auth_context)
    artifacts = [_proof_pack_record(proof_pack, proof_pack_path)]
    if disclosure is not None:
        artifacts.append(_disclosure_record(disclosure, disclosure_path))
    if view_path is not None:
        artifacts.append(_view_record(view_path))
    if insurer_telemetry is not None:
        artifacts.append(_insurer_record(insurer_telemetry, insurer_telemetry_path))
    session_id = content_hash(
        {
            "audience": audience,
            "reviewer": reviewer,
            "expires_at": expires_at,
            "artifact_refs": [_artifact_ref(artifact) for artifact in artifacts],
        }
    )
    body = {
        "schema": SUPERVISED_ACCESS_SCHEMA,
        "session_id": session_id,
        "issued_at": issued,
        "expires_at": expires_at,
        "audience": audience,
        "reviewer": reviewer,
        "scope": _scope_for(audience_type, artifacts),
        "artifacts": artifacts,
        "controls": _controls_for(audience_type, artifacts),
        "limitations": [
            "This receipt verifies a local supervised-access grant over signed evidence artifacts.",
            "It does not claim a hosted React portal, live identity-provider login, or production partner authentication service.",
            "Production deployments should replace reviewer references and local view hashes with credentialed portal sessions and auditable authentication events.",
        ],
    }
    receipt_id = content_hash(body)
    return {
        **body,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "receipt": body}, key)],
    }


def verify_supervised_access_receipt(
    receipt: dict[str, Any],
    *,
    proof_pack: dict[str, Any] | None = None,
    proof_pack_path: str | Path | None = None,
    disclosure: dict[str, Any] | None = None,
    disclosure_path: str | Path | None = None,
    view_path: str | Path | None = None,
    insurer_telemetry: dict[str, Any] | None = None,
    insurer_telemetry_path: str | Path | None = None,
    now: str | None = None,
    key: str | None = None,
) -> SupervisedAccessVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != SUPERVISED_ACCESS_SCHEMA:
        errors.append(f"unsupported supervised access schema: {receipt.get('schema')}")

    body = without_keys(receipt, "receipt_id", "signatures")
    expected_receipt_id = content_hash(body)
    if receipt.get("receipt_id") != expected_receipt_id:
        errors.append("receipt_id does not match canonical receipt body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("supervised access receipt missing signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "receipt": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("supervised access receipt signature invalid")

    audience = receipt.get("audience", {})
    audience_type = audience.get("type")
    if audience_type not in AUDIENCE_TYPES:
        errors.append(f"unsupported supervised access audience type: {audience_type}")
    if not audience.get("purpose"):
        errors.append("supervised access audience purpose missing")

    reviewer = receipt.get("reviewer", {})
    for field in ("subject_ref", "organization", "role"):
        if not reviewer.get(field):
            errors.append(f"supervised access reviewer {field} missing")

    issued_at = receipt.get("issued_at")
    expires_at = receipt.get("expires_at")
    try:
        issued_dt, expires_dt = _validate_time_window(issued_at, expires_at)
        if now and parse_rfc3339(now) > expires_dt:
            warnings.append("supervised access receipt is expired at verification time")
    except ValueError as exc:
        errors.append(str(exc))
        issued_dt = expires_dt = None

    artifacts = receipt.get("artifacts", [])
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("supervised access receipt must include artifacts")
        artifacts = []
    artifact_by_name = {artifact.get("name"): artifact for artifact in artifacts if isinstance(artifact, dict)}
    if "proof_pack" not in artifact_by_name:
        errors.append("supervised access receipt must include proof_pack artifact")
    if audience_type == "regulator" and "regulator_disclosure" not in artifact_by_name:
        errors.append("regulator supervised access requires a regulator_disclosure artifact")
    if audience_type == "insurer" and "insurer_telemetry" not in artifact_by_name:
        errors.append("insurer supervised access requires an insurer_telemetry artifact")

    _verify_supplied_proof_pack(
        artifact_by_name.get("proof_pack"),
        proof_pack,
        proof_pack_path,
        errors,
        warnings,
        key,
    )
    _verify_supplied_disclosure(
        artifact_by_name.get("regulator_disclosure"),
        disclosure,
        disclosure_path,
        errors,
        warnings,
        key,
    )
    _verify_supplied_view(artifact_by_name.get("static_view"), view_path, errors, warnings)
    _verify_supplied_insurer(
        artifact_by_name.get("insurer_telemetry"),
        insurer_telemetry,
        insurer_telemetry_path,
        errors,
        warnings,
    )

    expected_session_id = content_hash(
        {
            "audience": audience,
            "reviewer": reviewer,
            "expires_at": expires_at,
            "artifact_refs": [_artifact_ref(artifact) for artifact in artifacts if isinstance(artifact, dict)],
        }
    )
    if receipt.get("session_id") != expected_session_id:
        errors.append("session_id does not match audience, reviewer, expiry, and artifact references")

    if issued_dt and expires_dt and expires_dt <= issued_dt:
        errors.append("supervised access expires_at must be after issued_at")

    return SupervisedAccessVerification(ok=not errors, errors=errors, warnings=warnings)


def append_supervised_access_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_supervised_access_receipt(receipt, key=key)
    if not result.ok:
        raise ValueError("invalid supervised access receipt: " + "; ".join(result.errors))
    payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "session_id": receipt.get("session_id"),
        "audience": receipt.get("audience"),
        "reviewer": receipt.get("reviewer"),
        "expires_at": receipt.get("expires_at"),
        "artifact_count": len(receipt.get("artifacts", [])),
        "artifact_refs": [_artifact_ref(artifact) for artifact in receipt.get("artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(SUPERVISED_ACCESS_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("issued_at"))


def load_supervised_access_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("supervised access receipt must contain an object")
    return value


def write_supervised_access_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _audience(audience_type: str, purpose: str) -> dict[str, str]:
    if audience_type not in AUDIENCE_TYPES:
        raise ValueError(f"unsupported supervised access audience type: {audience_type}")
    if not purpose:
        raise ValueError("purpose is required")
    return {"type": audience_type, "purpose": purpose}


def _reviewer(
    subject_ref: str,
    organization: str,
    role: str,
    auth_context: dict[str, Any] | None,
) -> dict[str, Any]:
    for field_name, value in (
        ("subject_ref", subject_ref),
        ("organization", organization),
        ("role", role),
    ):
        if not value:
            raise ValueError(f"reviewer {field_name} is required")
    return {
        "subject_ref": subject_ref,
        "organization": organization,
        "role": role,
        "auth_context": auth_context
        or {
            "mode": "local-reference",
            "credential_binding": "subject-ref-only",
            "production_replacement": "OIDC/SAML-backed portal session with immutable access logs",
        },
    }


def _validate_time_window(issued_at: Any, expires_at: Any) -> tuple[Any, Any]:
    if not issued_at:
        raise ValueError("issued_at is required")
    if not expires_at:
        raise ValueError("expires_at is required")
    issued_dt = parse_rfc3339(str(issued_at))
    expires_dt = parse_rfc3339(str(expires_at))
    if expires_dt <= issued_dt:
        raise ValueError("expires_at must be after issued_at")
    return issued_dt, expires_dt


def _scope_for(audience_type: str, artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "mode": "selective-disclosure",
        "audience_type": audience_type,
        "artifact_names": [artifact["name"] for artifact in artifacts],
        "network_required": False,
        "write_access": False,
    }


def _controls_for(audience_type: str, artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
    controls = [
        {
            "id": "artifact-hash-binding",
            "status": "implemented-reference",
            "description": "Receipt binds every disclosed artifact by canonical hash or raw SHA-256.",
        },
        {
            "id": "reviewer-identity-reference",
            "status": "local-reference",
            "description": "Receipt records reviewer subject, organization, and role for local supervised review.",
        },
        {
            "id": "expiry-window",
            "status": "implemented-reference",
            "description": "Receipt requires issued_at and expires_at and verifies the time window.",
        },
        {
            "id": "hosted-portal-auth",
            "status": "planned-production",
            "description": "Replace local reviewer references with OIDC/SAML-backed portal sessions.",
        },
    ]
    if audience_type == "regulator":
        controls.append(
            {
                "id": "regulator-disclosure-binding",
                "status": "implemented-reference",
                "description": "Regulator access requires a signed selective-disclosure artifact.",
            }
        )
    if audience_type == "insurer":
        controls.append(
            {
                "id": "insurer-consent-binding",
                "status": "implemented-reference",
                "description": "Insurer access requires consented insurer telemetry with active consent status.",
            }
        )
    if any(artifact.get("name") == "static_view" for artifact in artifacts):
        controls.append(
            {
                "id": "static-view-binding",
                "status": "implemented-reference",
                "description": "Rendered local HTML view is bound by raw SHA-256.",
            }
        )
    return controls


def _proof_pack_record(proof_pack: dict[str, Any], path: str | Path | None = None) -> dict[str, Any]:
    decision = proof_pack.get("gate_decision", {})
    return {
        "name": "proof_pack",
        "artifact_type": "trustai.proof-pack",
        "path": str(path) if path else None,
        "content_hash": content_hash(proof_pack),
        "pack_id": proof_pack.get("pack_id"),
        "contract_id": decision.get("contract_id"),
        "agent": decision.get("agent", {}),
        "gate_outcome": decision.get("outcome"),
    }


def _disclosure_record(disclosure: dict[str, Any], path: str | Path | None = None) -> dict[str, Any]:
    return {
        "name": "regulator_disclosure",
        "artifact_type": "trustai.regulator-disclosure",
        "path": str(path) if path else None,
        "content_hash": content_hash(disclosure),
        "disclosure_id": disclosure.get("disclosure_id"),
        "audience": disclosure.get("audience"),
        "purpose": disclosure.get("purpose"),
        "disclosed_entry_count": disclosure.get("selection", {}).get("disclosed_entry_count"),
    }


def _view_record(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    data = source.read_bytes()
    return {
        "name": "static_view",
        "artifact_type": "text/html",
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _insurer_record(telemetry: dict[str, Any], path: str | Path | None = None) -> dict[str, Any]:
    consent = telemetry.get("consent", {})
    return {
        "name": "insurer_telemetry",
        "artifact_type": "trustai.insurer-risk-telemetry",
        "path": str(path) if path else None,
        "content_hash": content_hash(telemetry),
        "consent_id": consent.get("consent_id"),
        "consent_active": consent.get("status", {}).get("active"),
        "risk_tier": telemetry.get("risk_tier"),
        "risk_score": telemetry.get("risk_score"),
    }


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "sha256": artifact.get("sha256"),
        "pack_id": artifact.get("pack_id"),
        "disclosure_id": artifact.get("disclosure_id"),
        "consent_id": artifact.get("consent_id"),
    }


def _verify_supplied_proof_pack(
    artifact: dict[str, Any] | None,
    proof_pack: dict[str, Any] | None,
    path: str | Path | None,
    errors: list[str],
    warnings: list[str],
    key: str | None,
) -> None:
    if proof_pack is None:
        if artifact is not None:
            warnings.append("proof pack source not supplied; verified receipt binding only")
        return
    expected = _proof_pack_record(proof_pack, path)
    _compare_artifact(artifact, expected, errors)
    result = verify_proof_pack(proof_pack, key=key)
    if not result.ok:
        errors.extend(f"source proof pack invalid: {error}" for error in result.errors)
    warnings.extend(f"source proof pack warning: {warning}" for warning in result.warnings)


def _verify_supplied_disclosure(
    artifact: dict[str, Any] | None,
    disclosure: dict[str, Any] | None,
    path: str | Path | None,
    errors: list[str],
    warnings: list[str],
    key: str | None,
) -> None:
    if disclosure is None:
        if artifact is not None:
            warnings.append("regulator disclosure source not supplied; verified receipt binding only")
        return
    expected = _disclosure_record(disclosure, path)
    _compare_artifact(artifact, expected, errors)
    result = verify_regulator_disclosure(disclosure, key=key)
    if not result.ok:
        errors.extend(f"source regulator disclosure invalid: {error}" for error in result.errors)
    warnings.extend(f"source regulator disclosure warning: {warning}" for warning in result.warnings)


def _verify_supplied_view(
    artifact: dict[str, Any] | None,
    path: str | Path | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if path is None:
        if artifact is not None:
            warnings.append("static view source not supplied; verified receipt binding only")
        return
    expected = _view_record(path)
    _compare_artifact(artifact, expected, errors)


def _verify_supplied_insurer(
    artifact: dict[str, Any] | None,
    telemetry: dict[str, Any] | None,
    path: str | Path | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if telemetry is None:
        if artifact is not None:
            warnings.append("insurer telemetry source not supplied; verified receipt binding only")
        return
    expected = _insurer_record(telemetry, path)
    _compare_artifact(artifact, expected, errors)
    if telemetry.get("schema") != "trustai.insurer-risk-telemetry/0.1":
        errors.append(f"unsupported insurer telemetry schema: {telemetry.get('schema')}")
    if telemetry.get("consent", {}).get("status", {}).get("active") is not True:
        errors.append("insurer telemetry consent status is not active")


def _compare_artifact(
    actual: dict[str, Any] | None,
    expected: dict[str, Any],
    errors: list[str],
) -> None:
    if actual is None:
        errors.append(f"receipt missing artifact: {expected['name']}")
        return
    for field in ("name", "artifact_type", "content_hash", "sha256", "size_bytes", "pack_id", "disclosure_id", "consent_id"):
        if field in expected and expected.get(field) != actual.get(field):
            errors.append(f"artifact {expected['name']} {field} mismatch")
