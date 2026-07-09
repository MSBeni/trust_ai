from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .eu_ai_act import verify_eu_ai_act_document
from .regulator import verify_regulator_disclosure
from .supervised_access import verify_supervised_access_receipt
from .verifier import verify_proof_pack

REGULATOR_ACCEPTANCE_SCHEMA = "trustai.regulator-acceptance/0.1"
REGULATOR_ACCEPTANCE_ENTRY_TYPE = "regulator.acceptance.recorded"

ACCEPTANCE_OUTCOMES = {
    "accepted",
    "accepted_with_observations",
    "accepted_with_conditions",
    "needs_remediation",
    "rejected",
}
ACCEPTED_OUTCOMES = {"accepted", "accepted_with_observations", "accepted_with_conditions"}


@dataclass
class RegulatorAcceptanceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_regulator_acceptance(
    proof_pack: dict[str, Any],
    regulator_disclosure: dict[str, Any],
    eu_ai_act_document: dict[str, Any],
    *,
    regulator: str,
    authority_ref: str,
    reviewer_ref: str,
    decision: str = "accepted",
    examination_ref: str = "local-supervisory-review",
    purpose: str = "EU AI Act supervised review acceptance",
    accepted_at: str | None = None,
    review_period_start: str | None = None,
    review_period_end: str | None = None,
    observations: list[str] | None = None,
    conditions: list[str] | None = None,
    supervised_access_receipt: dict[str, Any] | None = None,
    supervised_view_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    issued_at = accepted_at or utc_now()
    _require_text(regulator, "regulator")
    _require_text(authority_ref, "authority_ref")
    _require_text(reviewer_ref, "reviewer_ref")
    _require_text(examination_ref, "examination_ref")
    _require_text(purpose, "purpose")
    _validate_decision(decision)
    _validate_review_period(review_period_start, review_period_end)
    parse_rfc3339(issued_at)

    source_artifacts = [
        _proof_pack_record(proof_pack),
        _disclosure_record(regulator_disclosure),
        _eu_ai_act_record(eu_ai_act_document),
    ]
    if supervised_access_receipt is not None:
        source_artifacts.append(_supervised_access_record(supervised_access_receipt))

    body = {
        "schema": REGULATOR_ACCEPTANCE_SCHEMA,
        "issued_at": issued_at,
        "regulator": {
            "name": regulator,
            "authority_ref": authority_ref,
            "reviewer_ref": reviewer_ref,
            "attestation_mode": "local-reference",
            "production_replacement": "credentialed regulator portal acknowledgement or authority-signed examination letter",
        },
        "decision": {
            "outcome": decision,
            "accepted": decision in ACCEPTED_OUTCOMES,
            "examination_ref": examination_ref,
            "observations": list(observations or []),
            "conditions": list(conditions or []),
        },
        "review_scope": {
            "purpose": purpose,
            "framework": "EU AI Act high-risk technical documentation",
            "review_period": {
                "start": review_period_start,
                "end": review_period_end,
            },
            "source_artifact_names": [artifact["name"] for artifact in source_artifacts],
            "offline_verification_required": True,
        },
        "source_artifacts": source_artifacts,
        "controls": _controls_for(decision, supervised_access_receipt is not None),
        "limitations": [
            "This receipt verifies a local regulator acceptance acknowledgement over signed TrustAI evidence artifacts.",
            "It does not claim a production regulator portal, binding legal determination, or live authority identity proof.",
            "Production deployments should replace this local receipt with an authority-signed acknowledgement or credentialed supervisory portal event.",
        ],
    }
    acceptance_id = content_hash(body)
    return {
        **body,
        "acceptance_id": acceptance_id,
        "signatures": [sign_value({"acceptance_id": acceptance_id, "acceptance": body}, key)],
    }


def verify_regulator_acceptance(
    acceptance: dict[str, Any],
    *,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    eu_ai_act_document: dict[str, Any] | None = None,
    supervised_access_receipt: dict[str, Any] | None = None,
    supervised_view_path: str | Path | None = None,
    key: str | None = None,
) -> RegulatorAcceptanceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if acceptance.get("schema") != REGULATOR_ACCEPTANCE_SCHEMA:
        errors.append(f"unsupported regulator acceptance schema: {acceptance.get('schema')}")

    body = without_keys(acceptance, "acceptance_id", "signatures")
    expected_id = content_hash(body)
    if acceptance.get("acceptance_id") != expected_id:
        errors.append("acceptance_id does not match canonical acceptance body")

    signatures = acceptance.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("regulator acceptance missing signature")
    else:
        signed_value = {"acceptance_id": acceptance.get("acceptance_id"), "acceptance": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("regulator acceptance signature invalid")

    try:
        parse_rfc3339(str(acceptance.get("issued_at")))
    except ValueError as exc:
        errors.append(f"invalid regulator acceptance issued_at: {exc}")

    regulator = acceptance.get("regulator", {})
    for field in ("name", "authority_ref", "reviewer_ref"):
        if not regulator.get(field):
            errors.append(f"regulator acceptance regulator {field} missing")

    decision = acceptance.get("decision", {})
    outcome = decision.get("outcome")
    if outcome not in ACCEPTANCE_OUTCOMES:
        errors.append(f"unsupported regulator acceptance outcome: {outcome}")
    elif outcome not in ACCEPTED_OUTCOMES:
        warnings.append("regulator acceptance decision is not an accepted outcome")
    if decision.get("accepted") != (outcome in ACCEPTED_OUTCOMES):
        errors.append("regulator acceptance accepted flag does not match outcome")
    for field in ("observations", "conditions"):
        if not isinstance(decision.get(field), list):
            errors.append(f"regulator acceptance decision {field} must be a list")
    if not decision.get("examination_ref"):
        errors.append("regulator acceptance examination_ref missing")

    scope = acceptance.get("review_scope", {})
    if not scope.get("purpose"):
        errors.append("regulator acceptance review purpose missing")
    period = scope.get("review_period", {})
    try:
        _validate_review_period(period.get("start"), period.get("end"))
    except ValueError as exc:
        errors.append(str(exc))

    artifacts = acceptance.get("source_artifacts", [])
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("regulator acceptance must include source_artifacts")
        artifacts = []
    artifact_by_name = {artifact.get("name"): artifact for artifact in artifacts if isinstance(artifact, dict)}
    for name in ("proof_pack", "regulator_disclosure", "eu_ai_act_document"):
        if name not in artifact_by_name:
            errors.append(f"regulator acceptance missing source artifact: {name}")

    _verify_supplied_proof_pack(artifact_by_name.get("proof_pack"), proof_pack, errors, warnings, key)
    _verify_supplied_disclosure(
        artifact_by_name.get("regulator_disclosure"),
        regulator_disclosure,
        errors,
        warnings,
        key,
    )
    _verify_supplied_eu_ai_act(
        artifact_by_name.get("eu_ai_act_document"),
        eu_ai_act_document,
        proof_pack,
        regulator_disclosure,
        errors,
        warnings,
        key,
    )
    _verify_supplied_supervised_access(
        artifact_by_name.get("supervised_access"),
        supervised_access_receipt,
        proof_pack,
        regulator_disclosure,
        supervised_view_path,
        errors,
        warnings,
        key,
    )

    expected_names = [artifact.get("name") for artifact in artifacts if isinstance(artifact, dict)]
    if scope.get("source_artifact_names") != expected_names:
        errors.append("review_scope source_artifact_names does not match source_artifacts")

    return RegulatorAcceptanceVerification(ok=not errors, errors=errors, warnings=warnings)


def append_regulator_acceptance(
    chain: EvidenceChain,
    acceptance: dict[str, Any],
    *,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_regulator_acceptance(acceptance, key=key)
    if not result.ok:
        raise ValueError("invalid regulator acceptance: " + "; ".join(result.errors))
    payload = {
        "acceptance_id": acceptance["acceptance_id"],
        "acceptance_hash": content_hash(acceptance),
        "regulator": acceptance.get("regulator"),
        "decision": acceptance.get("decision"),
        "review_scope": acceptance.get("review_scope"),
        "source_refs": [_artifact_ref(artifact) for artifact in acceptance.get("source_artifacts", [])],
        "limitations": acceptance.get("limitations", []),
    }
    return chain.append(REGULATOR_ACCEPTANCE_ENTRY_TYPE, payload, key=key, timestamp=acceptance.get("issued_at"))


def load_regulator_acceptance(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("regulator acceptance must contain an object")
    return value


def write_regulator_acceptance(path: str | Path, acceptance: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(acceptance, indent=2, sort_keys=True), encoding="utf-8")


def _require_text(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")


def _validate_decision(decision: str) -> None:
    if decision not in ACCEPTANCE_OUTCOMES:
        raise ValueError(f"unsupported regulator acceptance outcome: {decision}")


def _validate_review_period(start: Any, end: Any) -> None:
    if start is None and end is None:
        return
    if not start or not end:
        raise ValueError("regulator acceptance review period requires start and end")
    start_dt = parse_rfc3339(str(start))
    end_dt = parse_rfc3339(str(end))
    if end_dt < start_dt:
        raise ValueError("regulator acceptance review period end is before start")


def _controls_for(decision: str, has_supervised_access: bool) -> list[dict[str, str]]:
    controls = [
        {
            "id": "source-artifact-binding",
            "status": "implemented-reference",
            "description": "Acceptance binds proof pack, disclosure, and EU AI Act document by canonical hash.",
        },
        {
            "id": "authority-attestation-reference",
            "status": "local-reference",
            "description": "Receipt records regulator, authority reference, reviewer reference, and examination reference.",
        },
        {
            "id": "accepted-outcome-classification",
            "status": "implemented-reference",
            "description": "Receipt separates accepted outcomes from remediation or rejection outcomes.",
        },
        {
            "id": "credentialed-supervisor-portal",
            "status": "planned-production",
            "description": "Replace local attestation with authority-authenticated portal or signed examination-letter evidence.",
        },
    ]
    if has_supervised_access:
        controls.append(
            {
                "id": "supervised-access-binding",
                "status": "implemented-reference",
                "description": "Acceptance binds the supervised-access receipt used for review.",
            }
        )
    if decision == "accepted_with_conditions":
        controls.append(
            {
                "id": "condition-tracking",
                "status": "local-reference",
                "description": "Acceptance records conditions for downstream remediation tracking.",
            }
        )
    return controls


def _proof_pack_record(proof_pack: dict[str, Any]) -> dict[str, Any]:
    decision = proof_pack.get("gate_decision", {})
    return {
        "name": "proof_pack",
        "artifact_type": "trustai.proof-pack",
        "content_hash": content_hash(proof_pack),
        "pack_id": proof_pack.get("pack_id"),
        "contract_id": decision.get("contract_id"),
        "agent": decision.get("agent", {}),
        "gate_outcome": decision.get("outcome"),
    }


def _disclosure_record(disclosure: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "regulator_disclosure",
        "artifact_type": "trustai.regulator-disclosure",
        "content_hash": content_hash(disclosure),
        "disclosure_id": disclosure.get("disclosure_id"),
        "audience": disclosure.get("audience"),
        "purpose": disclosure.get("purpose"),
        "disclosed_entry_count": disclosure.get("selection", {}).get("disclosed_entry_count"),
    }


def _eu_ai_act_record(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "eu_ai_act_document",
        "artifact_type": "trustai.eu-ai-act-technical-documentation",
        "content_hash": content_hash(document),
        "document_id": document.get("document_id"),
        "regulatory_basis": document.get("regulatory_basis"),
        "section_count": len(document.get("sections", [])),
    }


def _supervised_access_record(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "supervised_access",
        "artifact_type": "trustai.supervised-access",
        "content_hash": content_hash(receipt),
        "receipt_id": receipt.get("receipt_id"),
        "session_id": receipt.get("session_id"),
        "audience": receipt.get("audience"),
        "reviewer": receipt.get("reviewer"),
    }


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "pack_id": artifact.get("pack_id"),
        "disclosure_id": artifact.get("disclosure_id"),
        "document_id": artifact.get("document_id"),
        "receipt_id": artifact.get("receipt_id"),
    }


def _verify_supplied_proof_pack(
    artifact: dict[str, Any] | None,
    proof_pack: dict[str, Any] | None,
    errors: list[str],
    warnings: list[str],
    key: str | None,
) -> None:
    if proof_pack is None:
        if artifact is not None:
            warnings.append("proof pack source not supplied; verified regulator acceptance binding only")
        return
    expected = _proof_pack_record(proof_pack)
    _compare_artifact(artifact, expected, errors)
    result = verify_proof_pack(proof_pack, key=key)
    if not result.ok:
        errors.extend(f"source proof pack invalid: {error}" for error in result.errors)
    warnings.extend(f"source proof pack warning: {warning}" for warning in result.warnings)


def _verify_supplied_disclosure(
    artifact: dict[str, Any] | None,
    disclosure: dict[str, Any] | None,
    errors: list[str],
    warnings: list[str],
    key: str | None,
) -> None:
    if disclosure is None:
        if artifact is not None:
            warnings.append("regulator disclosure source not supplied; verified regulator acceptance binding only")
        return
    expected = _disclosure_record(disclosure)
    _compare_artifact(artifact, expected, errors)
    result = verify_regulator_disclosure(disclosure, key=key)
    if not result.ok:
        errors.extend(f"source regulator disclosure invalid: {error}" for error in result.errors)
    warnings.extend(f"source regulator disclosure warning: {warning}" for warning in result.warnings)


def _verify_supplied_eu_ai_act(
    artifact: dict[str, Any] | None,
    document: dict[str, Any] | None,
    proof_pack: dict[str, Any] | None,
    disclosure: dict[str, Any] | None,
    errors: list[str],
    warnings: list[str],
    key: str | None,
) -> None:
    if document is None:
        if artifact is not None:
            warnings.append("EU AI Act document source not supplied; verified regulator acceptance binding only")
        return
    expected = _eu_ai_act_record(document)
    _compare_artifact(artifact, expected, errors)
    result = verify_eu_ai_act_document(document, proof_pack=proof_pack, regulator_disclosure=disclosure, key=key)
    if not result.ok:
        errors.extend(f"source EU AI Act document invalid: {error}" for error in result.errors)
    warnings.extend(f"source EU AI Act document warning: {warning}" for warning in result.warnings)


def _verify_supplied_supervised_access(
    artifact: dict[str, Any] | None,
    receipt: dict[str, Any] | None,
    proof_pack: dict[str, Any] | None,
    disclosure: dict[str, Any] | None,
    view_path: str | Path | None,
    errors: list[str],
    warnings: list[str],
    key: str | None,
) -> None:
    if receipt is None:
        if artifact is not None:
            warnings.append("supervised access source not supplied; verified regulator acceptance binding only")
        return
    expected = _supervised_access_record(receipt)
    _compare_artifact(artifact, expected, errors)
    result = verify_supervised_access_receipt(
        receipt,
        proof_pack=proof_pack,
        disclosure=disclosure,
        view_path=view_path,
        key=key,
    )
    if not result.ok:
        errors.extend(f"source supervised access receipt invalid: {error}" for error in result.errors)
    warnings.extend(f"source supervised access receipt warning: {warning}" for warning in result.warnings)


def _compare_artifact(
    actual: dict[str, Any] | None,
    expected: dict[str, Any],
    errors: list[str],
) -> None:
    if actual is None:
        errors.append(f"regulator acceptance missing source artifact: {expected['name']}")
        return
    fields = (
        "name",
        "artifact_type",
        "content_hash",
        "pack_id",
        "contract_id",
        "gate_outcome",
        "disclosure_id",
        "document_id",
        "receipt_id",
        "session_id",
        "section_count",
    )
    for field in fields:
        if field in expected and expected.get(field) != actual.get(field):
            errors.append(f"artifact {expected['name']} {field} mismatch")
