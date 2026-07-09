from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .certification import verify_auditor_certification_kit
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

AUDITOR_ACCREDITATION_SCHEMA = "trustai.auditor-accreditation/0.1"
AUDITOR_ACCREDITATION_ENTRY_TYPE = "auditor.accreditation.issued"

ACCREDITATION_STATUSES = {"active", "suspended", "revoked"}


@dataclass
class AuditorAccreditationVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    status: str | None = None


def build_auditor_accreditation_receipt(
    certification_kit: dict[str, Any],
    *,
    auditor_name: str,
    auditor_ref: str,
    auditor_organization: str,
    auditor_role: str = "external-auditor",
    accreditation_body: str = "trustai-local-accreditation-program",
    program_ref: str = "trustai-auditor-program-v0.1",
    credential_id: str | None = None,
    status: str = "active",
    score_percent: int = 100,
    scope: str | None = None,
    issued_at: str | None = None,
    expires_at: str | None = None,
    renewal_due_at: str | None = None,
    proctor_ref: str | None = None,
    evidence_refs: list[str] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    _require_text(auditor_name, "auditor_name")
    _require_text(auditor_ref, "auditor_ref")
    _require_text(auditor_organization, "auditor_organization")
    _require_text(auditor_role, "auditor_role")
    _require_text(accreditation_body, "accreditation_body")
    _require_text(program_ref, "program_ref")
    if status not in ACCREDITATION_STATUSES:
        raise ValueError("status must be active, suspended, or revoked")
    issued = issued_at or utc_now()
    parse_rfc3339(issued)
    if expires_at:
        _validate_after("expires_at", issued, expires_at)
    if renewal_due_at:
        _validate_after("renewal_due_at", issued, renewal_due_at)

    kit_result = verify_auditor_certification_kit(
        certification_kit,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        standards_package=standards_package,
        root=root,
        key=key,
    )
    if not kit_result["ok"]:
        raise ValueError("invalid auditor certification kit: " + "; ".join(kit_result["errors"]))

    minimum_score = certification_kit.get("rubric", {}).get("minimum_score_percent")
    if not isinstance(minimum_score, int):
        raise ValueError("certification kit missing integer minimum score")
    if score_percent < minimum_score:
        raise ValueError("score_percent must satisfy certification kit minimum score")

    credential = credential_id or content_hash(
        {
            "auditor_ref": auditor_ref,
            "auditor_organization": auditor_organization,
            "kit_id": certification_kit.get("kit_id"),
            "program_ref": program_ref,
        }
    )[:32]
    body = {
        "schema": AUDITOR_ACCREDITATION_SCHEMA,
        "issued_at": issued,
        "expires_at": expires_at,
        "accreditation_body": {
            "name": accreditation_body,
            "program_ref": program_ref,
            "attestation_mode": "local-reference",
            "production_replacement": "independent auditor accreditation program, proctored exam, and public credential registry",
        },
        "auditor": {
            "name": auditor_name,
            "organization": auditor_organization,
            "subject_ref": auditor_ref,
            "role": auditor_role,
        },
        "credential": {
            "credential_id": credential,
            "status": status,
            "scope": scope or certification_kit.get("rubric", {}).get("certification_scope"),
            "score_percent": score_percent,
            "minimum_score_percent": minimum_score,
            "issued_at": issued,
            "expires_at": expires_at,
            "renewal_due_at": renewal_due_at,
            "proctor_ref": proctor_ref,
            "evidence_refs": sorted(set(evidence_refs or [])),
        },
        "source_artifacts": [_kit_artifact(certification_kit)],
        "controls": _controls_for(status, bool(proctor_ref), bool(evidence_refs)),
        "limitations": [
            "This receipt records a local-reference auditor accreditation over a TrustAI certification kit.",
            "It binds the credential to the kit, auditor subject, score, scope, and source artifact hashes.",
            "It does not claim independent proctoring, public credential registry publication, or external standards-body governance.",
            "Production deployments should replace this local receipt with an independent accreditation program and public revocation registry.",
        ],
    }
    accreditation_id = content_hash(body)
    return {
        **body,
        "accreditation_id": accreditation_id,
        "signatures": [sign_value({"accreditation_id": accreditation_id, "accreditation": body}, key)],
    }


def verify_auditor_accreditation_receipt(
    receipt: dict[str, Any],
    *,
    certification_kit: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    now: str | None = None,
) -> AuditorAccreditationVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != AUDITOR_ACCREDITATION_SCHEMA:
        errors.append(f"unsupported auditor accreditation schema: {receipt.get('schema')}")
    body = without_keys(receipt, "accreditation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("accreditation_id") != expected_id:
        errors.append("accreditation_id does not match canonical auditor accreditation body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("auditor accreditation receipt missing signature")
    else:
        signed_value = {"accreditation_id": receipt.get("accreditation_id"), "accreditation": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("auditor accreditation receipt signature invalid")

    _verify_times(receipt, now, errors)
    body_record = receipt.get("accreditation_body", {})
    if not isinstance(body_record, dict) or not body_record.get("name") or not body_record.get("program_ref"):
        errors.append("auditor accreditation body name and program_ref are required")
    auditor = receipt.get("auditor", {})
    if not isinstance(auditor, dict) or not auditor.get("name") or not auditor.get("organization") or not auditor.get("subject_ref"):
        errors.append("auditor accreditation auditor name, organization, and subject_ref are required")
    credential = receipt.get("credential", {})
    if not isinstance(credential, dict):
        errors.append("auditor accreditation credential must be an object")
        credential = {}
    status = credential.get("status")
    if status not in ACCREDITATION_STATUSES:
        errors.append("auditor accreditation status must be active, suspended, or revoked")
    if not credential.get("credential_id") or not credential.get("scope"):
        errors.append("auditor accreditation credential_id and scope are required")
    if not isinstance(credential.get("score_percent"), int) or not isinstance(credential.get("minimum_score_percent"), int):
        errors.append("auditor accreditation score_percent and minimum_score_percent must be integers")
    elif credential.get("score_percent") < credential.get("minimum_score_percent"):
        errors.append("auditor accreditation score does not satisfy minimum score")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        errors.append("auditor accreditation must include exactly one certification-kit source artifact")
        artifacts = []
    artifact = artifacts[0] if artifacts and isinstance(artifacts[0], dict) else None

    if certification_kit is None:
        warnings.append("auditor certification kit source not supplied; verified accreditation binding only")
    else:
        kit_result = verify_auditor_certification_kit(
            certification_kit,
            proof_pack=proof_pack,
            regulator_disclosure=regulator_disclosure,
            standards_package=standards_package,
            root=root,
            key=key,
        )
        if not kit_result["ok"]:
            errors.extend(f"source auditor certification kit invalid: {error}" for error in kit_result["errors"])
        warnings.extend(f"source auditor certification kit warning: {warning}" for warning in kit_result["warnings"])
        _compare_artifact(artifact, _kit_artifact(certification_kit), errors)
        expected_minimum = certification_kit.get("rubric", {}).get("minimum_score_percent")
        if credential.get("minimum_score_percent") != expected_minimum:
            errors.append("auditor accreditation minimum score does not match certification kit rubric")
        expected_scope = certification_kit.get("rubric", {}).get("certification_scope")
        if credential.get("scope") != expected_scope:
            warnings.append("auditor accreditation scope differs from certification kit default scope")

    return AuditorAccreditationVerification(ok=not errors, errors=errors, warnings=warnings, status=status)


def append_auditor_accreditation_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    certification_kit: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_auditor_accreditation_receipt(
        receipt,
        certification_kit=certification_kit,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        standards_package=standards_package,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid auditor accreditation receipt: " + "; ".join(result.errors))
    payload = {
        "accreditation_id": receipt["accreditation_id"],
        "accreditation_hash": content_hash(receipt),
        "accreditation_body": receipt.get("accreditation_body"),
        "auditor": receipt.get("auditor"),
        "credential": receipt.get("credential"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(AUDITOR_ACCREDITATION_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("issued_at"))


def load_auditor_accreditation_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("auditor accreditation receipt must contain an object")
    return value


def write_auditor_accreditation_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _kit_artifact(kit: dict[str, Any]) -> dict[str, Any]:
    rubric = kit.get("rubric", {})
    return {
        "name": "auditor_certification_kit",
        "artifact_type": "trustai.auditor-certification-kit",
        "content_hash": content_hash(kit),
        "kit_id": kit.get("kit_id"),
        "program_version": kit.get("program_version"),
        "minimum_score_percent": rubric.get("minimum_score_percent"),
        "required_module_count": len(rubric.get("required_module_ids", [])),
        "required_exercise_count": len(rubric.get("required_exercise_ids", [])),
    }


def _controls_for(status: str, has_proctor: bool, has_evidence_refs: bool) -> list[dict[str, str]]:
    return [
        {
            "id": "certification-kit-binding",
            "status": "implemented-reference",
            "description": "Receipt binds accreditation to a verified auditor certification kit by canonical hash.",
        },
        {
            "id": "auditor-identity-binding",
            "status": "local-reference",
            "description": "Receipt records auditor subject reference, organization, role, and credential id.",
        },
        {
            "id": "proctored-exam-evidence",
            "status": "local-reference" if has_proctor else "planned-production",
            "description": "Production accreditation should bind an authenticated proctoring or exam-delivery event.",
        },
        {
            "id": "credential-registry",
            "status": "planned-production" if status == "active" else "not-applicable",
            "description": "Production accreditation should publish active credentials to a public or partner-verifiable registry.",
        },
        {
            "id": "revocation-and-renewal-governance",
            "status": "local-reference" if has_evidence_refs else "planned-production",
            "description": "Production accreditation should record renewal, suspension, and revocation evidence.",
        },
    ]


def _verify_times(receipt: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        issued = parse_rfc3339(str(receipt.get("issued_at")))
        credential = receipt.get("credential", {}) if isinstance(receipt.get("credential"), dict) else {}
        expires_at = receipt.get("expires_at")
        if expires_at:
            expires = parse_rfc3339(str(expires_at))
            if expires <= issued:
                errors.append("auditor accreditation expires_at must be after issued_at")
            if now and parse_rfc3339(now) > expires:
                errors.append("auditor accreditation receipt is expired")
        if credential.get("renewal_due_at"):
            renewal = parse_rfc3339(str(credential.get("renewal_due_at")))
            if renewal <= issued:
                errors.append("auditor accreditation renewal_due_at must be after issued_at")
    except ValueError as exc:
        errors.append(f"invalid auditor accreditation time field: {exc}")


def _validate_after(field_name: str, issued_at: Any, value: Any) -> None:
    issued = parse_rfc3339(str(issued_at))
    parsed = parse_rfc3339(str(value))
    if parsed <= issued:
        raise ValueError(f"auditor accreditation {field_name} must be after issued_at")


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"auditor accreditation missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "kit_id": artifact.get("kit_id"),
    }


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
