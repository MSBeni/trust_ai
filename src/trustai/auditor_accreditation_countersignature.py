from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .auditor_accreditation import verify_auditor_accreditation_receipt
from .auditor_program_sponsorship import verify_auditor_program_sponsorship_receipt
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

AUDITOR_ACCREDITATION_COUNTERSIGNATURE_SCHEMA = "trustai.auditor-accreditation-countersignature/0.1"
AUDITOR_ACCREDITATION_COUNTERSIGNATURE_ENTRY_TYPE = "auditor.accreditation.countersigned"

COUNTERSIGNATURE_MODES = {"local-reference", "sponsor-countersigned", "recorded-response"}
COUNTERSIGNATURE_OPERATIONS = {"issue", "renew", "suspend", "revoke", "reinstate"}
OPERATION_STATUS = {
    "issue": "active",
    "renew": "active",
    "reinstate": "active",
    "suspend": "suspended",
    "revoke": "revoked",
}


@dataclass
class AuditorAccreditationCountersignatureVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    operation: str | None = None
    mode: str | None = None


def build_auditor_accreditation_countersignature_receipt(
    accreditation_receipt: dict[str, Any],
    sponsorship_receipt: dict[str, Any],
    *,
    certification_kit: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    governance_receipt: dict[str, Any] | None = None,
    ballot_receipt: dict[str, Any] | None = None,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    operation: str = "issue",
    mode: str = "sponsor-countersigned",
    countersignature_ref: str | None = None,
    operation_ref: str | None = None,
    sponsor_actor_ref: str | None = None,
    sponsor_actor_role: str = "sponsor-authorized-representative",
    authority_ref: str | None = None,
    terms_ref: str | None = None,
    evidence_refs: list[str] | None = None,
    signed_at: str | None = None,
    effective_at: str | None = None,
    expires_at: str | None = None,
    response_status: int | None = None,
    response_body: Any | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if operation not in COUNTERSIGNATURE_OPERATIONS:
        raise ValueError("operation must be issue, renew, suspend, revoke, or reinstate")
    if mode not in COUNTERSIGNATURE_MODES:
        raise ValueError("mode must be local-reference, sponsor-countersigned, or recorded-response")
    if mode == "sponsor-countersigned" and not sponsor_actor_ref:
        raise ValueError("sponsor-countersigned mode requires sponsor_actor_ref")
    if mode == "recorded-response" and response_status is None:
        raise ValueError("recorded-response mode requires response_status")

    accreditation_result = verify_auditor_accreditation_receipt(
        accreditation_receipt,
        certification_kit=certification_kit,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        standards_package=standards_package,
        root=root,
        key=key,
    )
    if not accreditation_result.ok:
        raise ValueError("invalid auditor accreditation receipt: " + "; ".join(accreditation_result.errors))

    sponsorship_result = verify_auditor_program_sponsorship_receipt(
        sponsorship_receipt,
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
    if not sponsorship_result.ok:
        raise ValueError("invalid auditor program sponsorship receipt: " + "; ".join(sponsorship_result.errors))
    if sponsorship_result.status != "active":
        raise ValueError("auditor accreditation countersignature requires an active sponsorship")

    _validate_operation_status(operation, accreditation_receipt)
    _validate_program_binding(accreditation_receipt, sponsorship_receipt)

    signed = signed_at or utc_now()
    effective = effective_at or signed
    parse_rfc3339(signed)
    parse_rfc3339(effective)
    if parse_rfc3339(effective) < parse_rfc3339(signed):
        raise ValueError("auditor accreditation countersignature effective_at must be at or after signed_at")
    if expires_at:
        _validate_after("expires_at", effective, expires_at)

    accreditation = _accreditation_record(accreditation_receipt)
    sponsorship = _sponsorship_record(sponsorship_receipt)
    ref = countersignature_ref or content_hash(
        {
            "accreditation_id": accreditation.get("accreditation_id"),
            "sponsorship_id": sponsorship.get("sponsorship_id"),
            "operation": operation,
            "effective_at": effective,
        }
    )[:32]
    operation_record = {
        "operation": operation,
        "operation_ref": operation_ref or content_hash({"countersignature_ref": ref, "operation": operation})[:32],
        "credential_status": accreditation.get("credential", {}).get("status"),
        "signed_at": signed,
        "effective_at": effective,
        "expires_at": expires_at,
    }
    sponsor = {
        "sponsor_body": sponsorship.get("sponsor", {}).get("sponsor_body"),
        "sponsor_ref": sponsorship.get("sponsor", {}).get("sponsor_ref"),
        "sponsorship_ref": sponsorship.get("sponsor", {}).get("sponsorship_ref"),
        "sponsorship_mode": sponsorship.get("sponsor", {}).get("sponsorship_mode"),
        "scope": sponsorship.get("sponsor", {}).get("scope"),
    }
    countersignature = {
        "countersignature_ref": ref,
        "mode": mode,
        "terms_ref": terms_ref,
        "actor": {
            "ref": sponsor_actor_ref,
            "role": sponsor_actor_role,
            "authority_ref": authority_ref,
            "attestation_mode": "local-reference" if mode == "local-reference" else mode,
            "production_replacement": "sponsor-controlled signing identity, public authorization record, and revocation workflow",
        },
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    source_artifacts = [_accreditation_artifact(accreditation_receipt), _sponsorship_artifact(sponsorship_receipt)]
    body: dict[str, Any] = {
        "schema": AUDITOR_ACCREDITATION_COUNTERSIGNATURE_SCHEMA,
        "signed_at": signed,
        "effective_at": effective,
        "expires_at": expires_at,
        "operation": operation_record,
        "accreditation": accreditation,
        "sponsorship": sponsorship,
        "sponsor": sponsor,
        "countersignature": countersignature,
        "source_artifacts": source_artifacts,
        "countersignature_payload_hash": content_hash(
            {
                "operation": operation_record,
                "accreditation": accreditation,
                "sponsorship": sponsorship,
                "sponsor": sponsor,
                "countersignature": countersignature,
                "source_artifacts": source_artifacts,
            }
        ),
        "controls": _controls_for(mode, bool(sponsor_actor_ref), bool(terms_ref), bool(response_status), bool(evidence_refs)),
        "limitations": [
            "This receipt records local-reference sponsor countersignature evidence for an auditor accreditation operation.",
            "It binds the countersignature to a signed auditor accreditation receipt and an active auditor program sponsorship receipt by canonical hash.",
            "It does not claim a sponsor-controlled production signing ceremony unless backed by sponsor-controlled keys, authority records, and immutable provider response evidence.",
            "Production deployments should replace this local receipt with sponsor-owned signing keys, public authorization records, and accreditation operation workflow evidence.",
        ],
    }
    if response_status is not None:
        body["response"] = {
            "status": response_status,
            "body_hash": content_hash(response_body),
            "accepted": 200 <= response_status < 300,
        }
    countersignature_id = content_hash(body)
    return {
        **body,
        "countersignature_id": countersignature_id,
        "signatures": [sign_value({"countersignature_id": countersignature_id, "countersignature": body}, key)],
    }


def verify_auditor_accreditation_countersignature_receipt(
    receipt: dict[str, Any],
    *,
    accreditation_receipt: dict[str, Any] | None = None,
    sponsorship_receipt: dict[str, Any] | None = None,
    certification_kit: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    governance_receipt: dict[str, Any] | None = None,
    ballot_receipt: dict[str, Any] | None = None,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    now: str | None = None,
) -> AuditorAccreditationCountersignatureVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != AUDITOR_ACCREDITATION_COUNTERSIGNATURE_SCHEMA:
        errors.append(f"unsupported auditor accreditation countersignature schema: {receipt.get('schema')}")
    body = without_keys(receipt, "countersignature_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("countersignature_id") != expected_id:
        errors.append("countersignature_id does not match canonical auditor accreditation countersignature body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("auditor accreditation countersignature receipt missing signature")
    else:
        signed_value = {"countersignature_id": receipt.get("countersignature_id"), "countersignature": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("auditor accreditation countersignature receipt signature invalid")

    _verify_times(receipt, now, errors)
    operation = receipt.get("operation", {})
    if not isinstance(operation, dict):
        errors.append("auditor accreditation countersignature operation must be an object")
        operation = {}
    operation_name = operation.get("operation")
    if operation_name not in COUNTERSIGNATURE_OPERATIONS:
        errors.append("auditor accreditation countersignature operation is unsupported")
    if not operation.get("operation_ref") or not operation.get("credential_status"):
        errors.append("auditor accreditation countersignature operation_ref and credential_status are required")
    elif operation_name in OPERATION_STATUS and operation.get("credential_status") != OPERATION_STATUS[operation_name]:
        errors.append("auditor accreditation countersignature operation does not match credential status")

    accreditation = receipt.get("accreditation", {})
    if not isinstance(accreditation, dict) or not accreditation.get("accreditation_id"):
        errors.append("auditor accreditation countersignature accreditation record is required")
        accreditation = {}
    sponsorship = receipt.get("sponsorship", {})
    if not isinstance(sponsorship, dict) or not sponsorship.get("sponsorship_id"):
        errors.append("auditor accreditation countersignature sponsorship record is required")
        sponsorship = {}
    sponsor = receipt.get("sponsor", {})
    if not isinstance(sponsor, dict) or not sponsor.get("sponsor_body") or not sponsor.get("sponsor_ref"):
        errors.append("auditor accreditation countersignature sponsor_body and sponsor_ref are required")
        sponsor = {}
    if sponsor.get("scope") and "auditor-accreditation" not in sponsor.get("scope", []):
        errors.append("auditor accreditation countersignature requires sponsorship scope auditor-accreditation")

    countersignature = receipt.get("countersignature", {})
    if not isinstance(countersignature, dict):
        errors.append("auditor accreditation countersignature must be an object")
        countersignature = {}
    mode = countersignature.get("mode")
    if mode not in COUNTERSIGNATURE_MODES:
        errors.append("auditor accreditation countersignature mode is unsupported")
    if not countersignature.get("countersignature_ref"):
        errors.append("auditor accreditation countersignature_ref is required")
    actor = countersignature.get("actor", {})
    if not isinstance(actor, dict):
        errors.append("auditor accreditation countersignature actor must be an object")
        actor = {}
    if mode == "sponsor-countersigned" and not actor.get("ref"):
        errors.append("sponsor-countersigned accreditation requires sponsor actor ref")
    if mode == "local-reference":
        warnings.append("auditor accreditation countersignature is local-reference; no sponsor-controlled signing ceremony is claimed")

    response = receipt.get("response")
    if mode == "recorded-response":
        if not isinstance(response, dict) or response.get("status") is None or not response.get("body_hash"):
            errors.append("recorded-response accreditation countersignature must include response status and body_hash")
    elif response is not None and not isinstance(response, dict):
        errors.append("auditor accreditation countersignature response must be an object when supplied")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        errors.append("auditor accreditation countersignature must include accreditation and sponsorship source artifacts")
        artifacts = []
    accreditation_artifact = _artifact_by_name(artifacts, "auditor_accreditation_receipt")
    sponsorship_artifact = _artifact_by_name(artifacts, "auditor_program_sponsorship_receipt")
    if accreditation_artifact is None:
        errors.append("auditor accreditation countersignature missing auditor_accreditation_receipt source artifact")
    if sponsorship_artifact is None:
        errors.append("auditor accreditation countersignature missing auditor_program_sponsorship_receipt source artifact")

    if accreditation_receipt is None:
        warnings.append("auditor accreditation source not supplied; verified countersignature binding only")
    else:
        accreditation_result = verify_auditor_accreditation_receipt(
            accreditation_receipt,
            certification_kit=certification_kit,
            proof_pack=proof_pack,
            regulator_disclosure=regulator_disclosure,
            standards_package=standards_package,
            root=root,
            key=key,
            now=now,
        )
        if not accreditation_result.ok:
            errors.extend(f"source auditor accreditation receipt invalid: {error}" for error in accreditation_result.errors)
        warnings.extend(f"source auditor accreditation warning: {warning}" for warning in accreditation_result.warnings)
        _compare_artifact(accreditation_artifact, _accreditation_artifact(accreditation_receipt), errors)
        if accreditation != _accreditation_record(accreditation_receipt):
            errors.append("auditor accreditation countersignature accreditation record does not match source receipt")
        try:
            _validate_operation_status(str(operation_name), accreditation_receipt)
        except ValueError as exc:
            errors.append(str(exc))

    if sponsorship_receipt is None:
        warnings.append("auditor program sponsorship source not supplied; verified countersignature binding only")
    else:
        sponsorship_result = verify_auditor_program_sponsorship_receipt(
            sponsorship_receipt,
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
            now=now,
        )
        if not sponsorship_result.ok:
            errors.extend(f"source auditor program sponsorship receipt invalid: {error}" for error in sponsorship_result.errors)
        warnings.extend(f"source auditor program sponsorship warning: {warning}" for warning in sponsorship_result.warnings)
        if sponsorship_result.status != "active":
            errors.append("auditor accreditation countersignature requires an active sponsorship")
        _compare_artifact(sponsorship_artifact, _sponsorship_artifact(sponsorship_receipt), errors)
        if sponsorship != _sponsorship_record(sponsorship_receipt):
            errors.append("auditor accreditation countersignature sponsorship record does not match source receipt")
        expected_sponsor = {
            "sponsor_body": sponsorship_receipt.get("sponsor", {}).get("sponsor_body"),
            "sponsor_ref": sponsorship_receipt.get("sponsor", {}).get("sponsor_ref"),
            "sponsorship_ref": sponsorship_receipt.get("sponsor", {}).get("sponsorship_ref"),
            "sponsorship_mode": sponsorship_receipt.get("sponsor", {}).get("sponsorship_mode"),
            "scope": sponsorship_receipt.get("sponsor", {}).get("scope"),
        }
        if sponsor != expected_sponsor:
            errors.append("auditor accreditation countersignature sponsor record does not match source sponsorship")

    if accreditation_receipt is not None and sponsorship_receipt is not None:
        try:
            _validate_program_binding(accreditation_receipt, sponsorship_receipt)
        except ValueError as exc:
            errors.append(str(exc))

    expected_payload_hash = content_hash(
        {
            "operation": operation,
            "accreditation": accreditation,
            "sponsorship": sponsorship,
            "sponsor": sponsor,
            "countersignature": countersignature,
            "source_artifacts": artifacts,
        }
    )
    if receipt.get("countersignature_payload_hash") != expected_payload_hash:
        errors.append("auditor accreditation countersignature payload hash does not match records")

    return AuditorAccreditationCountersignatureVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        operation=operation_name if isinstance(operation_name, str) else None,
        mode=mode if isinstance(mode, str) else None,
    )


def append_auditor_accreditation_countersignature_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    accreditation_receipt: dict[str, Any] | None = None,
    sponsorship_receipt: dict[str, Any] | None = None,
    certification_kit: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    governance_receipt: dict[str, Any] | None = None,
    ballot_receipt: dict[str, Any] | None = None,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_auditor_accreditation_countersignature_receipt(
        receipt,
        accreditation_receipt=accreditation_receipt,
        sponsorship_receipt=sponsorship_receipt,
        certification_kit=certification_kit,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        standards_package=standards_package,
        governance_receipt=governance_receipt,
        ballot_receipt=ballot_receipt,
        submission_receipt=submission_receipt,
        status_receipt=status_receipt,
        verifier_release=verifier_release,
        conformance_report=conformance_report,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid auditor accreditation countersignature receipt: " + "; ".join(result.errors))
    payload = {
        "countersignature_id": receipt["countersignature_id"],
        "countersignature_hash": content_hash(receipt),
        "operation": receipt.get("operation"),
        "accreditation": receipt.get("accreditation"),
        "sponsorship": receipt.get("sponsorship"),
        "sponsor": receipt.get("sponsor"),
        "countersignature": receipt.get("countersignature"),
        "response": receipt.get("response"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(AUDITOR_ACCREDITATION_COUNTERSIGNATURE_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("signed_at"))


def load_auditor_accreditation_countersignature_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("auditor accreditation countersignature receipt must contain an object")
    return value


def write_auditor_accreditation_countersignature_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _accreditation_record(receipt: dict[str, Any]) -> dict[str, Any]:
    body = receipt.get("accreditation_body", {})
    auditor = receipt.get("auditor", {})
    credential = receipt.get("credential", {})
    return {
        "accreditation_id": receipt.get("accreditation_id"),
        "content_hash": content_hash(receipt),
        "accreditation_body": {
            "name": body.get("name"),
            "program_ref": body.get("program_ref"),
        },
        "auditor": {
            "subject_ref": auditor.get("subject_ref"),
            "organization": auditor.get("organization"),
            "role": auditor.get("role"),
        },
        "credential": {
            "credential_id": credential.get("credential_id"),
            "status": credential.get("status"),
            "scope": credential.get("scope"),
            "issued_at": credential.get("issued_at") or receipt.get("issued_at"),
            "expires_at": credential.get("expires_at") or receipt.get("expires_at"),
            "renewal_due_at": credential.get("renewal_due_at"),
        },
    }


def _sponsorship_record(receipt: dict[str, Any]) -> dict[str, Any]:
    program = receipt.get("program", {})
    sponsor = receipt.get("sponsor", {})
    return {
        "sponsorship_id": receipt.get("sponsorship_id"),
        "content_hash": content_hash(receipt),
        "program": {
            "program_id": program.get("program_id"),
            "program_ref": program.get("program_ref"),
            "accreditation_body": program.get("accreditation_body"),
            "governance_mode": program.get("governance_mode"),
        },
        "sponsor": {
            "sponsor_body": sponsor.get("sponsor_body"),
            "sponsor_ref": sponsor.get("sponsor_ref"),
            "sponsorship_ref": sponsor.get("sponsorship_ref"),
            "sponsorship_mode": sponsor.get("sponsorship_mode"),
            "status": sponsor.get("status"),
            "scope": sponsor.get("scope"),
        },
        "effective_at": receipt.get("effective_at"),
        "expires_at": receipt.get("expires_at"),
    }


def _accreditation_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    credential = receipt.get("credential", {})
    body = receipt.get("accreditation_body", {})
    return {
        "name": "auditor_accreditation_receipt",
        "artifact_type": "trustai.auditor-accreditation",
        "content_hash": content_hash(receipt),
        "accreditation_id": receipt.get("accreditation_id"),
        "credential_id": credential.get("credential_id"),
        "status": credential.get("status"),
        "program_ref": body.get("program_ref"),
    }


def _sponsorship_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    sponsor = receipt.get("sponsor", {})
    program = receipt.get("program", {})
    return {
        "name": "auditor_program_sponsorship_receipt",
        "artifact_type": "trustai.auditor-program-sponsorship",
        "content_hash": content_hash(receipt),
        "sponsorship_id": receipt.get("sponsorship_id"),
        "program_ref": program.get("program_ref"),
        "sponsorship_mode": sponsor.get("sponsorship_mode"),
        "status": sponsor.get("status"),
    }


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "accreditation_id": artifact.get("accreditation_id"),
        "sponsorship_id": artifact.get("sponsorship_id"),
    }


def _artifact_by_name(artifacts: list[Any], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"auditor accreditation countersignature missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _validate_operation_status(operation: str, accreditation_receipt: dict[str, Any]) -> None:
    expected_status = OPERATION_STATUS.get(operation)
    credential = accreditation_receipt.get("credential", {})
    status = credential.get("status") if isinstance(credential, dict) else None
    if expected_status and status != expected_status:
        raise ValueError(f"auditor accreditation countersignature operation {operation} requires credential status {expected_status}")


def _validate_program_binding(accreditation_receipt: dict[str, Any], sponsorship_receipt: dict[str, Any]) -> None:
    accreditation_body = accreditation_receipt.get("accreditation_body", {})
    program = sponsorship_receipt.get("program", {})
    if accreditation_body.get("program_ref") != program.get("program_ref"):
        raise ValueError("auditor accreditation countersignature program_ref must match active sponsorship program_ref")
    if accreditation_body.get("name") != program.get("accreditation_body"):
        raise ValueError("auditor accreditation countersignature accreditation body must match active sponsorship program")
    sponsor = sponsorship_receipt.get("sponsor", {})
    scope = sponsor.get("scope", []) if isinstance(sponsor, dict) else []
    if "auditor-accreditation" not in scope:
        raise ValueError("auditor accreditation countersignature requires sponsorship scope auditor-accreditation")


def _controls_for(mode: str, has_actor: bool, has_terms: bool, has_response: bool, has_evidence: bool) -> list[dict[str, str]]:
    return [
        {
            "id": "active-sponsorship-binding",
            "status": "implemented-reference",
            "description": "Receipt binds accreditation countersignature to an active auditor program sponsorship receipt by canonical hash.",
        },
        {
            "id": "accreditation-operation-binding",
            "status": "implemented-reference",
            "description": "Receipt binds a specific accreditation operation to a signed auditor accreditation receipt and credential status.",
        },
        {
            "id": "sponsor-actor-authorization",
            "status": "local-reference" if has_actor else "planned-production",
            "description": "Production countersignatures should bind a sponsor-controlled signing identity or authorized service account.",
        },
        {
            "id": "sponsor-terms-binding",
            "status": "local-reference" if has_terms else "planned-production",
            "description": "Production countersignatures should bind the sponsor terms, charter, or accreditation-operation authorization policy.",
        },
        {
            "id": "countersignature-provider-response",
            "status": "recorded-response" if has_response else ("local-reference" if mode == "sponsor-countersigned" else "planned-production"),
            "description": "Production countersignatures should preserve immutable response evidence from the sponsor signing workflow.",
        },
        {
            "id": "operation-evidence",
            "status": "local-reference" if has_evidence else "planned-production",
            "description": "Production accreditation operations should bind review tickets, board minutes, or signing ceremony evidence.",
        },
    ]


def _verify_times(receipt: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        signed = parse_rfc3339(str(receipt.get("signed_at")))
        effective = parse_rfc3339(str(receipt.get("effective_at")))
        if effective < signed:
            errors.append("auditor accreditation countersignature effective_at must be at or after signed_at")
        if now and parse_rfc3339(now) < signed:
            errors.append("auditor accreditation countersignature is in the future")
        expires_at = receipt.get("expires_at")
        if expires_at:
            expires = parse_rfc3339(str(expires_at))
            if expires <= effective:
                errors.append("auditor accreditation countersignature expires_at must be after effective_at")
            if now and parse_rfc3339(now) > expires:
                errors.append("auditor accreditation countersignature receipt is expired")
    except ValueError as exc:
        errors.append(f"invalid auditor accreditation countersignature time field: {exc}")


def _validate_after(field_name: str, effective_at: Any, value: Any) -> None:
    effective = parse_rfc3339(str(effective_at))
    parsed = parse_rfc3339(str(value))
    if parsed <= effective:
        raise ValueError(f"auditor accreditation countersignature {field_name} must be after effective_at")
