from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .certification import verify_auditor_certification_kit
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .standards import verify_standards_submission

AUDITOR_PROGRAM_GOVERNANCE_SCHEMA = "trustai.auditor-program-governance/0.1"
AUDITOR_PROGRAM_GOVERNANCE_ENTRY_TYPE = "auditor.program.governance.published"

PROGRAM_STATUSES = {"draft", "active", "suspended", "retired"}
GOVERNANCE_MODES = {"local-reference", "independent-board", "standards-body-sponsored", "industry-consortium"}


@dataclass
class AuditorProgramGovernanceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    status: str | None = None


def build_auditor_program_governance_receipt(
    certification_kit: dict[str, Any],
    *,
    standards_package: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    root: str | Path = ".",
    program_name: str = "TrustAI Auditor Program",
    program_ref: str = "TRUSTAI-AUDITOR-0.1",
    accreditation_body: str = "TrustAI Auditor Program",
    governance_body: str = "trustai-local-auditor-program-board",
    governance_ref: str | None = None,
    governance_mode: str = "local-reference",
    status: str = "active",
    version: str | None = None,
    operator_ref: str = "trustai-local",
    board_members: list[str] | None = None,
    independence_policy_ref: str | None = None,
    proctoring_policy_ref: str | None = None,
    revocation_policy_ref: str | None = None,
    renewal_policy_ref: str | None = None,
    appeals_policy_ref: str | None = None,
    registry_ref: str | None = None,
    evidence_refs: list[str] | None = None,
    issued_at: str | None = None,
    effective_at: str | None = None,
    expires_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _require_text(program_name, "program_name")
    _require_text(program_ref, "program_ref")
    _require_text(accreditation_body, "accreditation_body")
    _require_text(governance_body, "governance_body")
    _require_text(operator_ref, "operator_ref")
    if status not in PROGRAM_STATUSES:
        raise ValueError("status must be draft, active, suspended, or retired")
    if governance_mode not in GOVERNANCE_MODES:
        raise ValueError("governance_mode must be local-reference, independent-board, standards-body-sponsored, or industry-consortium")

    issued = issued_at or utc_now()
    effective = effective_at or issued
    parse_rfc3339(issued)
    parse_rfc3339(effective)
    if parse_rfc3339(effective) < parse_rfc3339(issued):
        raise ValueError("auditor program effective_at must be at or after issued_at")
    if expires_at:
        _validate_after("expires_at", effective, expires_at)

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
    if standards_package is not None:
        standards_result = verify_standards_submission(standards_package, root=root)
        if not standards_result.ok:
            raise ValueError("invalid standards package: " + "; ".join(standards_result.errors))

    program_version = version or str(certification_kit.get("program_version") or "unknown")
    governance = {
        "governance_body": governance_body,
        "governance_ref": governance_ref
        or content_hash(
            {
                "program_ref": program_ref,
                "version": program_version,
                "governance_body": governance_body,
            }
        )[:32],
        "governance_mode": governance_mode,
        "operator_ref": operator_ref,
        "board_members": sorted(set(board_members or ["trustai-local-governance-board"])),
        "policies": {
            "independence_policy_ref": independence_policy_ref,
            "proctoring_policy_ref": proctoring_policy_ref,
            "revocation_policy_ref": revocation_policy_ref,
            "renewal_policy_ref": renewal_policy_ref,
            "appeals_policy_ref": appeals_policy_ref,
            "registry_ref": registry_ref,
        },
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    program = {
        "name": program_name,
        "program_ref": program_ref,
        "version": program_version,
        "status": status,
        "accreditation_body": accreditation_body,
        "attestation_mode": "local-reference",
        "production_replacement": "independent auditor accreditation program governance, board minutes, proctored exam provider, public registry, and appeal workflow",
    }
    source_artifacts = [_kit_artifact(certification_kit)]
    if standards_package is not None:
        source_artifacts.append(_standards_artifact(standards_package))
    body = {
        "schema": AUDITOR_PROGRAM_GOVERNANCE_SCHEMA,
        "issued_at": issued,
        "effective_at": effective,
        "expires_at": expires_at,
        "program": program,
        "governance": governance,
        "source_artifacts": source_artifacts,
        "governance_payload_hash": content_hash(
            {
                "program": program,
                "governance": governance,
                "source_artifacts": source_artifacts,
            }
        ),
        "controls": _controls_for(governance_mode, governance["policies"], bool(governance["board_members"])),
        "limitations": [
            "This receipt records local-reference governance for the TrustAI auditor accreditation program.",
            "It binds governance metadata, board/operator references, policy references, certification kit evidence, and standards package evidence by canonical hash.",
            "It does not claim independent accreditation authority, external proctoring, public credential registry operation, or standards-body sponsorship.",
            "Production deployments should replace this local receipt with independent program governance records, board approvals, proctoring provider attestations, and public registry operations.",
        ],
    }
    program_id = content_hash(body)
    return {
        **body,
        "program_id": program_id,
        "signatures": [sign_value({"program_id": program_id, "governance": body}, key)],
    }


def verify_auditor_program_governance_receipt(
    receipt: dict[str, Any],
    *,
    certification_kit: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    now: str | None = None,
) -> AuditorProgramGovernanceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != AUDITOR_PROGRAM_GOVERNANCE_SCHEMA:
        errors.append(f"unsupported auditor program governance schema: {receipt.get('schema')}")
    body = without_keys(receipt, "program_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("program_id") != expected_id:
        errors.append("program_id does not match canonical auditor program governance body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("auditor program governance receipt missing signature")
    else:
        signed_value = {"program_id": receipt.get("program_id"), "governance": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("auditor program governance receipt signature invalid")

    _verify_times(receipt, now, errors)
    program = receipt.get("program", {})
    if not isinstance(program, dict) or not program.get("name") or not program.get("program_ref") or not program.get("version"):
        errors.append("auditor program name, program_ref, and version are required")
        program = {}
    status = program.get("status")
    if status not in PROGRAM_STATUSES:
        errors.append("auditor program status must be draft, active, suspended, or retired")
    governance = receipt.get("governance", {})
    if not isinstance(governance, dict):
        errors.append("auditor program governance must be an object")
        governance = {}
    if not governance.get("governance_body") or not governance.get("governance_ref") or not governance.get("operator_ref"):
        errors.append("auditor program governance_body, governance_ref, and operator_ref are required")
    if governance.get("governance_mode") not in GOVERNANCE_MODES:
        errors.append("auditor program governance_mode is unsupported")
    board_members = governance.get("board_members", [])
    if not isinstance(board_members, list) or not all(isinstance(member, str) and member for member in board_members):
        errors.append("auditor program board_members must be non-empty strings")
    elif not board_members:
        errors.append("auditor program must include at least one board member or governance actor")
    policies = governance.get("policies", {})
    if not isinstance(policies, dict):
        errors.append("auditor program policies must be an object")
        policies = {}

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("auditor program governance receipt must include source artifacts")
        artifacts = []
    kit_artifact = _artifact_by_name(artifacts, "auditor_certification_kit")
    if kit_artifact is None:
        errors.append("auditor program governance receipt must include auditor_certification_kit source artifact")

    if certification_kit is None:
        warnings.append("auditor certification kit source not supplied; verified governance binding only")
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
        _compare_artifact(kit_artifact, _kit_artifact(certification_kit), errors)
        if program.get("version") != certification_kit.get("program_version"):
            errors.append("auditor program governance version does not match certification kit program_version")

    standards_artifact = _artifact_by_name(artifacts, "standards_package")
    if standards_package is None:
        if standards_artifact is not None:
            warnings.append("standards package source not supplied; verified governance standards binding only")
    else:
        standards_result = verify_standards_submission(standards_package, root=root)
        if not standards_result.ok:
            errors.extend(f"source standards package invalid: {error}" for error in standards_result.errors)
        warnings.extend(f"source standards package warning: {warning}" for warning in standards_result.warnings)
        _compare_artifact(standards_artifact, _standards_artifact(standards_package), errors)

    expected_payload_hash = content_hash(
        {
            "program": program,
            "governance": governance,
            "source_artifacts": artifacts,
        }
    )
    if receipt.get("governance_payload_hash") != expected_payload_hash:
        errors.append("auditor program governance payload hash does not match program and governance records")

    return AuditorProgramGovernanceVerification(ok=not errors, errors=errors, warnings=warnings, status=status)


def append_auditor_program_governance_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    certification_kit: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_auditor_program_governance_receipt(
        receipt,
        certification_kit=certification_kit,
        standards_package=standards_package,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid auditor program governance receipt: " + "; ".join(result.errors))
    payload = {
        "program_id": receipt["program_id"],
        "program_hash": content_hash(receipt),
        "program": receipt.get("program"),
        "governance": {
            "governance_body": receipt.get("governance", {}).get("governance_body"),
            "governance_ref": receipt.get("governance", {}).get("governance_ref"),
            "governance_mode": receipt.get("governance", {}).get("governance_mode"),
            "operator_ref": receipt.get("governance", {}).get("operator_ref"),
            "board_members": receipt.get("governance", {}).get("board_members", []),
            "policies": receipt.get("governance", {}).get("policies", {}),
        },
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(AUDITOR_PROGRAM_GOVERNANCE_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("issued_at"))


def load_auditor_program_governance_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("auditor program governance receipt must contain an object")
    return value


def write_auditor_program_governance_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
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


def _standards_artifact(package: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "standards_package",
        "artifact_type": "trustai.standards-submission",
        "content_hash": content_hash(package),
        "package_id": package.get("package_id"),
        "spec_count": len(package.get("specs", [])),
        "target_body": package.get("target_body"),
    }


def _controls_for(governance_mode: str, policies: dict[str, Any], has_board: bool) -> list[dict[str, str]]:
    return [
        {
            "id": "certification-kit-governance-binding",
            "status": "implemented-reference",
            "description": "Program governance binds to a verified auditor certification kit by canonical hash.",
        },
        {
            "id": "independent-governance-board",
            "status": "local-reference" if has_board else "planned-production",
            "description": "Program governance records board or governance actor references for accreditation oversight.",
        },
        {
            "id": "independence-and-conflict-policy",
            "status": "local-reference" if policies.get("independence_policy_ref") else "planned-production",
            "description": "Production accreditation should bind auditor independence and conflict-of-interest policy evidence.",
        },
        {
            "id": "proctored-exam-policy",
            "status": "local-reference" if policies.get("proctoring_policy_ref") else "planned-production",
            "description": "Production accreditation should bind proctoring provider, exam security, and retake policy references.",
        },
        {
            "id": "renewal-revocation-appeals",
            "status": "local-reference"
            if policies.get("renewal_policy_ref") and policies.get("revocation_policy_ref") and policies.get("appeals_policy_ref")
            else "planned-production",
            "description": "Production accreditation should bind renewal, suspension, revocation, and appeal governance.",
        },
        {
            "id": "credential-registry-operation",
            "status": "local-reference" if policies.get("registry_ref") else "planned-production",
            "description": "Production accreditation should operate a public or partner-verifiable credential registry.",
        },
        {
            "id": "external-sponsorship",
            "status": "planned-production" if governance_mode == "local-reference" else "local-reference",
            "description": "Production programs should be independently governed, standards-body sponsored, or industry-consortium sponsored.",
        },
    ]


def _verify_times(receipt: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        issued = parse_rfc3339(str(receipt.get("issued_at")))
        effective = parse_rfc3339(str(receipt.get("effective_at")))
        if effective < issued:
            errors.append("auditor program effective_at must be at or after issued_at")
        expires_at = receipt.get("expires_at")
        if expires_at:
            expires = parse_rfc3339(str(expires_at))
            if expires <= effective:
                errors.append("auditor program expires_at must be after effective_at")
            if now and parse_rfc3339(now) > expires:
                errors.append("auditor program governance receipt is expired")
    except ValueError as exc:
        errors.append(f"invalid auditor program governance time field: {exc}")


def _validate_after(field_name: str, effective_at: Any, value: Any) -> None:
    effective = parse_rfc3339(str(effective_at))
    parsed = parse_rfc3339(str(value))
    if parsed <= effective:
        raise ValueError(f"auditor program {field_name} must be after effective_at")


def _artifact_by_name(artifacts: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"auditor program governance missing source artifact: {expected['name']}")
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
        "package_id": artifact.get("package_id"),
    }


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
