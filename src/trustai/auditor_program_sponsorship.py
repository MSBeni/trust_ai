from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .auditor_program_governance import verify_auditor_program_governance_receipt
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .standards_body_ballot import verify_standards_body_ballot_receipt

AUDITOR_PROGRAM_SPONSORSHIP_SCHEMA = "trustai.auditor-program-sponsorship/0.1"
AUDITOR_PROGRAM_SPONSORSHIP_ENTRY_TYPE = "auditor.program.sponsorship.published"

SPONSORSHIP_MODES = {"standards-body-sponsored", "industry-consortium", "independent-board", "local-reference"}
SPONSORSHIP_STATUSES = {"active", "suspended", "retired"}


@dataclass
class AuditorProgramSponsorshipVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    status: str | None = None
    sponsorship_mode: str | None = None


def build_auditor_program_sponsorship_receipt(
    governance_receipt: dict[str, Any],
    ballot_receipt: dict[str, Any],
    *,
    certification_kit: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    sponsor_body: str | None = None,
    sponsor_ref: str | None = None,
    sponsorship_ref: str | None = None,
    sponsorship_mode: str = "standards-body-sponsored",
    status: str = "active",
    scope: list[str] | None = None,
    terms_ref: str | None = None,
    charter_ref: str | None = None,
    oversight_refs: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    issued_at: str | None = None,
    effective_at: str | None = None,
    expires_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if sponsorship_mode not in SPONSORSHIP_MODES:
        raise ValueError("sponsorship_mode must be standards-body-sponsored, industry-consortium, independent-board, or local-reference")
    if status not in SPONSORSHIP_STATUSES:
        raise ValueError("status must be active, suspended, or retired")

    governance_result = verify_auditor_program_governance_receipt(
        governance_receipt,
        certification_kit=certification_kit,
        standards_package=standards_package,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        root=root,
        key=key,
    )
    if not governance_result.ok:
        raise ValueError("invalid auditor program governance receipt: " + "; ".join(governance_result.errors))
    ballot_result = verify_standards_body_ballot_receipt(
        ballot_receipt,
        submission_receipt=submission_receipt,
        status_receipt=status_receipt,
        standards_package=standards_package,
        verifier_release=verifier_release,
        conformance_report=conformance_report,
        root=root,
        key=key,
    )
    if not ballot_result.ok:
        raise ValueError("invalid standards-body ballot receipt: " + "; ".join(ballot_result.errors))
    if ballot_result.outcome != "accepted":
        raise ValueError("auditor program sponsorship requires an accepted standards-body ballot")

    issued = issued_at or utc_now()
    effective = effective_at or issued
    parse_rfc3339(issued)
    parse_rfc3339(effective)
    if parse_rfc3339(effective) < parse_rfc3339(issued):
        raise ValueError("auditor program sponsorship effective_at must be at or after issued_at")
    if expires_at:
        _validate_after("expires_at", effective, expires_at)

    program = _program_record(governance_receipt)
    ballot_body = ballot_receipt.get("target_submission", {}).get("standards_body", {})
    body_name = sponsor_body or ballot_body.get("name") or governance_receipt.get("governance", {}).get("governance_body")
    _require_text(body_name, "sponsor_body")
    sponsor = {
        "sponsor_body": body_name,
        "sponsor_ref": sponsor_ref
        or content_hash(
            {
                "sponsor_body": body_name,
                "program_ref": program.get("program_ref"),
                "ballot_id": ballot_receipt.get("ballot_id"),
            }
        )[:32],
        "sponsorship_ref": sponsorship_ref
        or content_hash(
            {
                "sponsor_body": body_name,
                "program_id": program.get("program_id"),
                "mode": sponsorship_mode,
                "effective_at": effective,
            }
        )[:32],
        "sponsorship_mode": sponsorship_mode,
        "status": status,
        "scope": sorted(set(scope or ["auditor-training", "auditor-accreditation", "verifier-competency-review"])),
        "terms_ref": terms_ref,
        "charter_ref": charter_ref,
        "oversight_refs": sorted(set(oversight_refs or [])),
        "evidence_refs": sorted(set(evidence_refs or [])),
        "production_replacement": "sponsor-signed accreditation program charter, board authorization, public sponsorship page, and renewal workflow",
    }
    source_artifacts = [_governance_artifact(governance_receipt), _ballot_artifact(ballot_receipt)]
    body = {
        "schema": AUDITOR_PROGRAM_SPONSORSHIP_SCHEMA,
        "issued_at": issued,
        "effective_at": effective,
        "expires_at": expires_at,
        "program": program,
        "sponsor": sponsor,
        "source_artifacts": source_artifacts,
        "sponsorship_payload_hash": content_hash(
            {
                "program": program,
                "sponsor": sponsor,
                "source_artifacts": source_artifacts,
            }
        ),
        "controls": _controls_for(sponsorship_mode, bool(sponsor.get("sponsor_ref")), bool(terms_ref or charter_ref), bool(expires_at)),
        "limitations": [
            "This receipt records local-reference sponsorship evidence for an auditor accreditation program.",
            "It binds the sponsorship to a signed auditor program governance receipt and an accepted standards-body ballot by canonical hash.",
            "It does not claim an externally operated accreditation authority unless signed or countersigned by the named sponsor.",
            "Production deployments should replace this local receipt with sponsor-signed program charters, public sponsorship records, and renewal governance.",
        ],
    }
    sponsorship_id = content_hash(body)
    return {
        **body,
        "sponsorship_id": sponsorship_id,
        "signatures": [sign_value({"sponsorship_id": sponsorship_id, "sponsorship": body}, key)],
    }


def verify_auditor_program_sponsorship_receipt(
    receipt: dict[str, Any],
    *,
    governance_receipt: dict[str, Any] | None = None,
    ballot_receipt: dict[str, Any] | None = None,
    certification_kit: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    now: str | None = None,
) -> AuditorProgramSponsorshipVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != AUDITOR_PROGRAM_SPONSORSHIP_SCHEMA:
        errors.append(f"unsupported auditor program sponsorship schema: {receipt.get('schema')}")
    body = without_keys(receipt, "sponsorship_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("sponsorship_id") != expected_id:
        errors.append("sponsorship_id does not match canonical auditor program sponsorship body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("auditor program sponsorship receipt missing signature")
    else:
        signed_value = {"sponsorship_id": receipt.get("sponsorship_id"), "sponsorship": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("auditor program sponsorship receipt signature invalid")

    _verify_times(receipt, now, errors)
    program = receipt.get("program", {})
    if not isinstance(program, dict) or not program.get("program_id") or not program.get("program_ref") or not program.get("version"):
        errors.append("auditor program sponsorship program_id, program_ref, and version are required")
        program = {}
    sponsor = receipt.get("sponsor", {})
    if not isinstance(sponsor, dict):
        errors.append("auditor program sponsorship sponsor must be an object")
        sponsor = {}
    if not sponsor.get("sponsor_body") or not sponsor.get("sponsor_ref") or not sponsor.get("sponsorship_ref"):
        errors.append("auditor program sponsorship sponsor_body, sponsor_ref, and sponsorship_ref are required")
    sponsorship_mode = sponsor.get("sponsorship_mode")
    if sponsorship_mode not in SPONSORSHIP_MODES:
        errors.append("auditor program sponsorship mode is unsupported")
    status = sponsor.get("status")
    if status not in SPONSORSHIP_STATUSES:
        errors.append("auditor program sponsorship status is unsupported")
    scope = sponsor.get("scope", [])
    if not isinstance(scope, list) or not all(isinstance(item, str) and item for item in scope):
        errors.append("auditor program sponsorship scope must be non-empty strings")
    elif not scope:
        errors.append("auditor program sponsorship scope must include at least one scope item")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        errors.append("auditor program sponsorship receipt must include governance and ballot source artifacts")
        artifacts = []
    governance_artifact = _artifact_by_name(artifacts, "auditor_program_governance_receipt")
    ballot_artifact = _artifact_by_name(artifacts, "standards_body_ballot_receipt")
    if governance_artifact is None:
        errors.append("auditor program sponsorship missing auditor_program_governance_receipt source artifact")
    if ballot_artifact is None:
        errors.append("auditor program sponsorship missing standards_body_ballot_receipt source artifact")

    if governance_receipt is None:
        warnings.append("auditor program governance source not supplied; verified sponsorship binding only")
    else:
        governance_result = verify_auditor_program_governance_receipt(
            governance_receipt,
            certification_kit=certification_kit,
            standards_package=standards_package,
            proof_pack=proof_pack,
            regulator_disclosure=regulator_disclosure,
            root=root,
            key=key,
        )
        if not governance_result.ok:
            errors.extend(f"source auditor program governance receipt invalid: {error}" for error in governance_result.errors)
        warnings.extend(f"source auditor program governance warning: {warning}" for warning in governance_result.warnings)
        _compare_artifact(governance_artifact, _governance_artifact(governance_receipt), errors)
        if program != _program_record(governance_receipt):
            errors.append("auditor program sponsorship program record does not match source governance receipt")

    if ballot_receipt is None:
        warnings.append("standards-body ballot source not supplied; verified sponsorship binding only")
    else:
        ballot_result = verify_standards_body_ballot_receipt(
            ballot_receipt,
            submission_receipt=submission_receipt,
            status_receipt=status_receipt,
            standards_package=standards_package,
            verifier_release=verifier_release,
            conformance_report=conformance_report,
            root=root,
            key=key,
        )
        if not ballot_result.ok:
            errors.extend(f"source standards-body ballot receipt invalid: {error}" for error in ballot_result.errors)
        warnings.extend(f"source standards-body ballot warning: {warning}" for warning in ballot_result.warnings)
        _compare_artifact(ballot_artifact, _ballot_artifact(ballot_receipt), errors)
        if ballot_result.outcome != "accepted":
            errors.append("auditor program sponsorship requires an accepted standards-body ballot")
        ballot_body = ballot_receipt.get("target_submission", {}).get("standards_body", {}).get("name")
        if sponsorship_mode == "standards-body-sponsored" and ballot_body and sponsor.get("sponsor_body") != ballot_body:
            errors.append("auditor program sponsorship sponsor_body must match accepted standards-body ballot body")

    expected_payload_hash = content_hash(
        {
            "program": program,
            "sponsor": sponsor,
            "source_artifacts": artifacts,
        }
    )
    if receipt.get("sponsorship_payload_hash") != expected_payload_hash:
        errors.append("auditor program sponsorship payload hash does not match program and sponsor records")

    return AuditorProgramSponsorshipVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        status=status if isinstance(status, str) else None,
        sponsorship_mode=sponsorship_mode if isinstance(sponsorship_mode, str) else None,
    )


def append_auditor_program_sponsorship_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    governance_receipt: dict[str, Any] | None = None,
    ballot_receipt: dict[str, Any] | None = None,
    certification_kit: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_auditor_program_sponsorship_receipt(
        receipt,
        governance_receipt=governance_receipt,
        ballot_receipt=ballot_receipt,
        certification_kit=certification_kit,
        standards_package=standards_package,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        submission_receipt=submission_receipt,
        status_receipt=status_receipt,
        verifier_release=verifier_release,
        conformance_report=conformance_report,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid auditor program sponsorship receipt: " + "; ".join(result.errors))
    payload = {
        "sponsorship_id": receipt["sponsorship_id"],
        "sponsorship_hash": content_hash(receipt),
        "program": receipt.get("program"),
        "sponsor": receipt.get("sponsor"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(AUDITOR_PROGRAM_SPONSORSHIP_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("issued_at"))


def load_auditor_program_sponsorship_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("auditor program sponsorship receipt must contain an object")
    return value


def write_auditor_program_sponsorship_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _program_record(governance_receipt: dict[str, Any]) -> dict[str, Any]:
    program = governance_receipt.get("program", {})
    governance = governance_receipt.get("governance", {})
    return {
        "program_id": governance_receipt.get("program_id"),
        "content_hash": content_hash(governance_receipt),
        "name": program.get("name"),
        "program_ref": program.get("program_ref"),
        "version": program.get("version"),
        "status": program.get("status"),
        "accreditation_body": program.get("accreditation_body"),
        "governance_body": governance.get("governance_body"),
        "governance_ref": governance.get("governance_ref"),
        "governance_mode": governance.get("governance_mode"),
    }


def _governance_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    program = receipt.get("program", {})
    governance = receipt.get("governance", {})
    return {
        "name": "auditor_program_governance_receipt",
        "artifact_type": "trustai.auditor-program-governance",
        "content_hash": content_hash(receipt),
        "program_id": receipt.get("program_id"),
        "program_ref": program.get("program_ref"),
        "governance_mode": governance.get("governance_mode"),
    }


def _ballot_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    ballot = receipt.get("ballot", {})
    decision = receipt.get("decision", {})
    return {
        "name": "standards_body_ballot_receipt",
        "artifact_type": "trustai.standards-body-ballot",
        "content_hash": content_hash(receipt),
        "ballot_id": receipt.get("ballot_id"),
        "ballot_ref": ballot.get("ballot_ref"),
        "outcome": decision.get("outcome"),
    }


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "program_id": artifact.get("program_id"),
        "ballot_id": artifact.get("ballot_id"),
    }


def _artifact_by_name(artifacts: list[Any], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"auditor program sponsorship missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _controls_for(sponsorship_mode: str, has_sponsor_ref: bool, has_terms_or_charter: bool, has_expiry: bool) -> list[dict[str, str]]:
    return [
        {
            "id": "program-governance-binding",
            "status": "implemented-reference",
            "description": "Sponsorship receipt binds to a signed auditor program governance receipt by canonical hash.",
        },
        {
            "id": "accepted-standards-ballot-binding",
            "status": "implemented-reference",
            "description": "Sponsorship receipt binds to an accepted standards-body ballot receipt by canonical hash.",
        },
        {
            "id": "sponsor-identity-reference",
            "status": "local-reference" if has_sponsor_ref else "planned-production",
            "description": "Production sponsorship should bind a sponsor-controlled identity, docket, or public page.",
        },
        {
            "id": "program-charter-and-terms",
            "status": "local-reference" if has_terms_or_charter else "planned-production",
            "description": "Production sponsorship should bind charter terms, scope, and renewal obligations.",
        },
        {
            "id": "external-operation-mode",
            "status": "planned-production" if sponsorship_mode == "local-reference" else "local-reference",
            "description": "Production accreditation programs should be operated by a standards body, industry consortium, or independent board.",
        },
        {
            "id": "renewal-and-expiry-governance",
            "status": "local-reference" if has_expiry else "planned-production",
            "description": "Production sponsorship should define expiry, renewal, suspension, and retirement governance.",
        },
    ]


def _verify_times(receipt: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        issued = parse_rfc3339(str(receipt.get("issued_at")))
        effective = parse_rfc3339(str(receipt.get("effective_at")))
        if effective < issued:
            errors.append("auditor program sponsorship effective_at must be at or after issued_at")
        expires_at = receipt.get("expires_at")
        if expires_at:
            expires = parse_rfc3339(str(expires_at))
            if expires <= effective:
                errors.append("auditor program sponsorship expires_at must be after effective_at")
            if now and parse_rfc3339(now) > expires:
                errors.append("auditor program sponsorship receipt is expired")
    except ValueError as exc:
        errors.append(f"invalid auditor program sponsorship time field: {exc}")


def _validate_after(field_name: str, effective_at: Any, value: Any) -> None:
    effective = parse_rfc3339(str(effective_at))
    parsed = parse_rfc3339(str(value))
    if parsed <= effective:
        raise ValueError(f"auditor program sponsorship {field_name} must be after effective_at")


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
