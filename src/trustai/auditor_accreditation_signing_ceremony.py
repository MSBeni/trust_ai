from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .auditor_accreditation_countersignature import verify_auditor_accreditation_countersignature_receipt
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

AUDITOR_ACCREDITATION_SIGNING_CEREMONY_SCHEMA = "trustai.auditor-accreditation-signing-ceremony/0.1"
AUDITOR_ACCREDITATION_SIGNING_CEREMONY_ENTRY_TYPE = "auditor.accreditation.signing_ceremony.recorded"

SIGNING_CEREMONY_MODES = {"local-reference", "sponsor-controlled", "recorded-response"}


@dataclass
class AuditorAccreditationSigningCeremonyVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    ceremony_id: str | None = None
    mode: str | None = None


def build_auditor_accreditation_signing_ceremony_receipt(
    countersignature_receipt: dict[str, Any],
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
    mode: str = "sponsor-controlled",
    ceremony_ref: str | None = None,
    signing_system: str = "local-sponsor-signing-system",
    signing_endpoint: str = "local-sponsor-signing-system",
    key_provider: str = "local-sponsor-hsm",
    key_ref: str | None = None,
    key_algorithm: str = "HMAC-SHA256",
    public_key_ref: str | None = None,
    credential_ref: str = "local-reference",
    sponsor_operator_ref: str | None = None,
    sponsor_operator_role: str = "sponsor-signing-operator",
    approver_refs: list[str] | None = None,
    witness_refs: list[str] | None = None,
    quorum_required: int = 1,
    authority_ref: str | None = None,
    policy_ref: str | None = None,
    rotation_ref: str | None = None,
    revocation_ref: str | None = None,
    evidence_refs: list[str] | None = None,
    ceremony_at: str | None = None,
    response_status: int | None = None,
    response_body: Any | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in SIGNING_CEREMONY_MODES:
        raise ValueError("mode must be local-reference, sponsor-controlled, or recorded-response")
    _require_text(signing_system, "signing_system")
    _require_text(signing_endpoint, "signing_endpoint")
    _require_text(key_provider, "key_provider")
    _require_text(key_algorithm, "key_algorithm")
    _require_text(credential_ref, "credential_ref")
    approvers = sorted(set(approver_refs or []))
    witnesses = sorted(set(witness_refs or []))
    if quorum_required < 1:
        raise ValueError("quorum_required must be at least 1")
    if mode in {"sponsor-controlled", "recorded-response"}:
        _require_text(key_ref, "key_ref")
        _require_text(sponsor_operator_ref, "sponsor_operator_ref")
        _require_text(authority_ref, "authority_ref")
        _require_text(policy_ref, "policy_ref")
        if len(approvers) < quorum_required:
            raise ValueError("approver_refs must satisfy quorum_required")
    if mode == "recorded-response" and response_status is None:
        raise ValueError("recorded-response mode requires response_status")

    countersignature_result = verify_auditor_accreditation_countersignature_receipt(
        countersignature_receipt,
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
    if not countersignature_result.ok:
        raise ValueError("invalid auditor accreditation countersignature receipt: " + "; ".join(countersignature_result.errors))
    if mode in {"sponsor-controlled", "recorded-response"} and countersignature_result.mode != "sponsor-countersigned":
        raise ValueError("sponsor-controlled signing ceremony requires a sponsor-countersigned accreditation countersignature")

    occurred = ceremony_at or utc_now()
    _validate_times(str(countersignature_receipt.get("signed_at")), occurred)
    source = _countersignature_record(countersignature_receipt)
    ref = ceremony_ref or content_hash(
        {
            "countersignature_id": source.get("countersignature_id"),
            "key_ref": key_ref,
            "occurred_at": occurred,
        }
    )[:32]
    ceremony = {
        "ceremony_ref": ref,
        "mode": mode,
        "occurred_at": occurred,
        "authority_ref": authority_ref,
        "policy_ref": policy_ref,
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    signing_key = {
        "provider": key_provider,
        "key_ref": key_ref,
        "algorithm": key_algorithm,
        "public_key_ref": public_key_ref,
        "rotation_ref": rotation_ref,
        "revocation_ref": revocation_ref,
    }
    signing_service = {
        "name": signing_system,
        "endpoint": signing_endpoint,
        "credential": {"ref": credential_ref, "redacted": True},
        "attestation_mode": _attestation_mode(mode),
        "production_replacement": "sponsor-owned HSM/KMS signing ceremony with immutable audit log, revocation state, and public key publication",
    }
    participants = {
        "operator": {
            "ref": sponsor_operator_ref,
            "role": sponsor_operator_role,
        },
        "approver_refs": approvers,
        "witness_refs": witnesses,
        "quorum_required": quorum_required,
        "quorum_met": len(approvers) >= quorum_required,
    }
    source_artifacts = [_countersignature_artifact(countersignature_receipt)]
    body: dict[str, Any] = {
        "schema": AUDITOR_ACCREDITATION_SIGNING_CEREMONY_SCHEMA,
        "mode": mode,
        "ceremony_at": occurred,
        "source": source,
        "ceremony": ceremony,
        "signing_service": signing_service,
        "signing_key": signing_key,
        "participants": participants,
        "source_artifacts": source_artifacts,
        "ceremony_payload_hash": content_hash(
            {
                "source": source,
                "ceremony": ceremony,
                "signing_service": signing_service,
                "signing_key": signing_key,
                "participants": participants,
                "source_artifacts": source_artifacts,
            }
        ),
        "controls": _controls_for(mode, bool(key_ref), bool(sponsor_operator_ref), participants["quorum_met"], bool(response_status), bool(witnesses)),
        "limitations": [
            "This receipt records local-reference sponsor signing ceremony evidence for an auditor accreditation countersignature.",
            "It binds a verified sponsor-countersigned accreditation operation to key metadata, quorum, witness, policy, authority, and optional provider response hashes.",
            "It does not claim production HSM/KMS enforcement unless backed by sponsor-owned keys, immutable audit logs, public key material, and revocation evidence.",
            "Production deployments should replace local key references with sponsor-owned signing ceremonies and externally verifiable key lifecycle records.",
        ],
    }
    if response_status is not None:
        body["response"] = {
            "status": response_status,
            "body_hash": content_hash(response_body),
            "accepted": 200 <= response_status < 300,
        }
    ceremony_id = content_hash(body)
    return {
        **body,
        "ceremony_id": ceremony_id,
        "signatures": [sign_value({"ceremony_id": ceremony_id, "signing_ceremony": body}, key)],
    }


def verify_auditor_accreditation_signing_ceremony_receipt(
    receipt: dict[str, Any],
    *,
    countersignature_receipt: dict[str, Any] | None = None,
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
) -> AuditorAccreditationSigningCeremonyVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != AUDITOR_ACCREDITATION_SIGNING_CEREMONY_SCHEMA:
        errors.append(f"unsupported auditor accreditation signing ceremony schema: {receipt.get('schema')}")
    body = without_keys(receipt, "ceremony_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("ceremony_id") != expected_id:
        errors.append("ceremony_id does not match canonical auditor accreditation signing ceremony body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("auditor accreditation signing ceremony receipt missing signature")
    else:
        signed_value = {"ceremony_id": receipt.get("ceremony_id"), "signing_ceremony": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("auditor accreditation signing ceremony receipt signature invalid")

    mode = receipt.get("mode")
    if mode not in SIGNING_CEREMONY_MODES:
        errors.append("auditor accreditation signing ceremony mode is unsupported")
    if mode == "local-reference":
        warnings.append("auditor accreditation signing ceremony is local-reference; no sponsor-owned signing ceremony is claimed")

    try:
        ceremony_at = str(receipt.get("ceremony_at"))
        source_signed_at = str((receipt.get("source") or {}).get("signed_at"))
        _validate_times(source_signed_at, ceremony_at)
        if now and parse_rfc3339(now) < parse_rfc3339(ceremony_at):
            errors.append("auditor accreditation signing ceremony is in the future")
    except ValueError as exc:
        errors.append(f"invalid auditor accreditation signing ceremony time field: {exc}")

    source = receipt.get("source", {})
    if not isinstance(source, dict) or not source.get("countersignature_id") or not source.get("content_hash"):
        errors.append("auditor accreditation signing ceremony source countersignature_id and content_hash are required")
        source = {}
    if mode in {"sponsor-controlled", "recorded-response"} and source.get("mode") != "sponsor-countersigned":
        errors.append("sponsor-controlled signing ceremony requires sponsor-countersigned source countersignature")

    ceremony = receipt.get("ceremony", {})
    if not isinstance(ceremony, dict) or not ceremony.get("ceremony_ref"):
        errors.append("auditor accreditation signing ceremony_ref is required")
        ceremony = {}
    if mode in {"sponsor-controlled", "recorded-response"}:
        if not ceremony.get("authority_ref"):
            errors.append("sponsor-controlled signing ceremony requires authority_ref")
        if not ceremony.get("policy_ref"):
            errors.append("sponsor-controlled signing ceremony requires policy_ref")

    signing_service = receipt.get("signing_service", {})
    if not isinstance(signing_service, dict) or not signing_service.get("name") or not signing_service.get("endpoint"):
        errors.append("auditor accreditation signing ceremony signing service name and endpoint are required")
        signing_service = {}
    credential = signing_service.get("credential", {}) if isinstance(signing_service, dict) else {}
    if not isinstance(credential, dict) or not credential.get("ref") or credential.get("redacted") is not True:
        errors.append("auditor accreditation signing ceremony credential reference must be redacted")

    signing_key = receipt.get("signing_key", {})
    if not isinstance(signing_key, dict) or not signing_key.get("provider") or not signing_key.get("algorithm"):
        errors.append("auditor accreditation signing ceremony signing key provider and algorithm are required")
        signing_key = {}
    if mode in {"sponsor-controlled", "recorded-response"} and not signing_key.get("key_ref"):
        errors.append("sponsor-controlled signing ceremony requires key_ref")

    participants = receipt.get("participants", {})
    if not isinstance(participants, dict):
        errors.append("auditor accreditation signing ceremony participants must be an object")
        participants = {}
    operator = participants.get("operator", {}) if isinstance(participants, dict) else {}
    approvers = participants.get("approver_refs", []) if isinstance(participants, dict) else []
    quorum_required = participants.get("quorum_required") if isinstance(participants, dict) else None
    if mode in {"sponsor-controlled", "recorded-response"}:
        if not isinstance(operator, dict) or not operator.get("ref"):
            errors.append("sponsor-controlled signing ceremony requires sponsor operator ref")
        if not isinstance(approvers, list) or not isinstance(quorum_required, int) or len(approvers) < quorum_required:
            errors.append("sponsor-controlled signing ceremony approvers must satisfy quorum_required")
        if participants.get("quorum_met") is not True:
            errors.append("sponsor-controlled signing ceremony quorum_met must be true")

    response = receipt.get("response")
    if mode == "recorded-response":
        if not isinstance(response, dict) or response.get("status") is None or not response.get("body_hash"):
            errors.append("recorded-response signing ceremony must include response status and body_hash")
        elif not response.get("accepted"):
            errors.append("recorded-response signing ceremony requires an accepted provider response")
    elif response is not None and not isinstance(response, dict):
        errors.append("auditor accreditation signing ceremony response must be an object when supplied")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        errors.append("auditor accreditation signing ceremony must include exactly one countersignature source artifact")
        artifacts = []
    countersignature_artifact = _artifact_by_name(artifacts, "auditor_accreditation_countersignature_receipt")
    if countersignature_artifact is None:
        errors.append("auditor accreditation signing ceremony missing countersignature source artifact")

    if countersignature_receipt is None:
        warnings.append("auditor accreditation countersignature source not supplied; verified signing ceremony binding only")
    else:
        countersignature_result = verify_auditor_accreditation_countersignature_receipt(
            countersignature_receipt,
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
            now=now,
        )
        if not countersignature_result.ok:
            errors.extend(f"source auditor accreditation countersignature receipt invalid: {error}" for error in countersignature_result.errors)
        warnings.extend(f"source auditor accreditation countersignature warning: {warning}" for warning in countersignature_result.warnings)
        _compare_artifact(countersignature_artifact, _countersignature_artifact(countersignature_receipt), errors)
        if source != _countersignature_record(countersignature_receipt):
            errors.append("auditor accreditation signing ceremony source record does not match countersignature receipt")
        if mode in {"sponsor-controlled", "recorded-response"} and countersignature_result.mode != "sponsor-countersigned":
            errors.append("sponsor-controlled signing ceremony requires a sponsor-countersigned source receipt")

    expected_payload_hash = content_hash(
        {
            "source": source,
            "ceremony": ceremony,
            "signing_service": signing_service,
            "signing_key": signing_key,
            "participants": participants,
            "source_artifacts": artifacts,
        }
    )
    if receipt.get("ceremony_payload_hash") != expected_payload_hash:
        errors.append("auditor accreditation signing ceremony payload hash does not match records")

    return AuditorAccreditationSigningCeremonyVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        ceremony_id=receipt.get("ceremony_id") if isinstance(receipt.get("ceremony_id"), str) else None,
        mode=mode if isinstance(mode, str) else None,
    )


def append_auditor_accreditation_signing_ceremony_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    countersignature_receipt: dict[str, Any] | None = None,
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
    result = verify_auditor_accreditation_signing_ceremony_receipt(
        receipt,
        countersignature_receipt=countersignature_receipt,
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
        raise ValueError("invalid auditor accreditation signing ceremony receipt: " + "; ".join(result.errors))
    payload = {
        "ceremony_id": receipt["ceremony_id"],
        "ceremony_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "source": receipt.get("source"),
        "ceremony": receipt.get("ceremony"),
        "signing_service": receipt.get("signing_service"),
        "signing_key": receipt.get("signing_key"),
        "participants": receipt.get("participants"),
        "response": receipt.get("response"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(AUDITOR_ACCREDITATION_SIGNING_CEREMONY_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("ceremony_at"))


def load_auditor_accreditation_signing_ceremony_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("auditor accreditation signing ceremony receipt must contain an object")
    return value


def write_auditor_accreditation_signing_ceremony_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _countersignature_record(receipt: dict[str, Any]) -> dict[str, Any]:
    accreditation = receipt.get("accreditation", {})
    sponsorship = receipt.get("sponsorship", {})
    countersignature = receipt.get("countersignature", {})
    operation = receipt.get("operation", {})
    sponsor = receipt.get("sponsor", {})
    return {
        "countersignature_id": receipt.get("countersignature_id"),
        "content_hash": content_hash(receipt),
        "mode": countersignature.get("mode"),
        "signed_at": receipt.get("signed_at"),
        "effective_at": receipt.get("effective_at"),
        "operation": {
            "operation": operation.get("operation"),
            "operation_ref": operation.get("operation_ref"),
            "credential_status": operation.get("credential_status"),
        },
        "countersignature": {
            "countersignature_ref": countersignature.get("countersignature_ref"),
            "actor_ref": (countersignature.get("actor") or {}).get("ref") if isinstance(countersignature.get("actor"), dict) else None,
            "actor_role": (countersignature.get("actor") or {}).get("role") if isinstance(countersignature.get("actor"), dict) else None,
        },
        "accreditation": {
            "accreditation_id": accreditation.get("accreditation_id"),
            "credential_id": (accreditation.get("credential") or {}).get("credential_id") if isinstance(accreditation.get("credential"), dict) else None,
            "credential_status": (accreditation.get("credential") or {}).get("status") if isinstance(accreditation.get("credential"), dict) else None,
        },
        "sponsorship": {
            "sponsorship_id": sponsorship.get("sponsorship_id"),
            "sponsor_ref": sponsor.get("sponsor_ref"),
            "sponsorship_ref": sponsor.get("sponsorship_ref"),
        },
    }


def _countersignature_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    countersignature = receipt.get("countersignature", {})
    operation = receipt.get("operation", {})
    return {
        "name": "auditor_accreditation_countersignature_receipt",
        "artifact_type": "trustai.auditor-accreditation-countersignature",
        "content_hash": content_hash(receipt),
        "countersignature_id": receipt.get("countersignature_id"),
        "countersignature_ref": countersignature.get("countersignature_ref") if isinstance(countersignature, dict) else None,
        "operation": operation.get("operation") if isinstance(operation, dict) else None,
    }


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "countersignature_id": artifact.get("countersignature_id"),
        "countersignature_ref": artifact.get("countersignature_ref"),
    }


def _artifact_by_name(artifacts: list[Any], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"auditor accreditation signing ceremony missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _attestation_mode(mode: str) -> str:
    if mode == "sponsor-controlled":
        return "sponsor-controlled"
    if mode == "recorded-response":
        return "recorded-response"
    return "local-reference"


def _controls_for(
    mode: str,
    has_key_ref: bool,
    has_operator_ref: bool,
    quorum_met: bool,
    has_response: bool,
    has_witnesses: bool,
) -> list[dict[str, str]]:
    return [
        {
            "id": "countersignature-binding",
            "status": "implemented-reference",
            "description": "Signing ceremony binds to a verified auditor accreditation countersignature by canonical hash.",
        },
        {
            "id": "sponsor-controlled-key",
            "status": "sponsor-controlled" if has_key_ref and mode != "local-reference" else "planned-production",
            "description": "Production ceremonies should bind sponsor-owned signing keys, public key references, and key lifecycle evidence.",
        },
        {
            "id": "authorized-sponsor-operator",
            "status": "authenticated-reference" if has_operator_ref else "planned-production",
            "description": "Ceremony records the sponsor operator responsible for the accreditation signing operation.",
        },
        {
            "id": "quorum-approval",
            "status": "implemented-reference" if quorum_met else "planned-production",
            "description": "Ceremony records approver quorum for sponsor-controlled accreditation signing.",
        },
        {
            "id": "witness-evidence",
            "status": "implemented-reference" if has_witnesses else "planned-production",
            "description": "Production ceremonies should bind independent witness or audit-log references.",
        },
        {
            "id": "provider-response-capture",
            "status": "recorded-response" if has_response else "planned-production",
            "description": "Recorded-response ceremonies preserve provider response hashes from the signing backend.",
        },
    ]


def _validate_times(source_signed_at: str, ceremony_at: str) -> None:
    source_time = parse_rfc3339(source_signed_at)
    ceremony_time = parse_rfc3339(ceremony_at)
    if ceremony_time < source_time:
        raise ValueError("auditor accreditation signing ceremony ceremony_at must be at or after countersignature signed_at")


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
