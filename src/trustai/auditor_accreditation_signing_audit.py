from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .auditor_accreditation_signing_ceremony import verify_auditor_accreditation_signing_ceremony_receipt
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

AUDITOR_ACCREDITATION_SIGNING_AUDIT_SCHEMA = "trustai.auditor-accreditation-signing-audit/0.1"
AUDITOR_ACCREDITATION_SIGNING_AUDIT_ENTRY_TYPE = "auditor.accreditation.signing_audit.recorded"

SIGNING_AUDIT_MODES = {"local-reference", "public-key-published", "immutable-audit-log", "provider-anchored"}


@dataclass
class AuditorAccreditationSigningAuditVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    audit_id: str | None = None
    mode: str | None = None


def build_auditor_accreditation_signing_audit_receipt(
    signing_ceremony_receipt: dict[str, Any],
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
    mode: str = "provider-anchored",
    audit_ref: str | None = None,
    publisher: str = "local-signing-audit-publisher",
    publication_endpoint: str = "local-signing-audit-publisher",
    credential_ref: str = "local-reference",
    actor_ref: str | None = None,
    key_ref: str | None = None,
    public_key_ref: str | None = None,
    public_key_fingerprint: str | None = None,
    key_status: str = "active",
    publication_ref: str | None = None,
    rotation_ref: str | None = None,
    revocation_ref: str | None = None,
    audit_log_ref: str | None = None,
    audit_log_root: str | None = None,
    audit_log_size: int | None = None,
    audit_log_algorithm: str = "SHA-256",
    audit_log_entry_ref: str | None = None,
    audit_log_export_ref: str | None = None,
    retention_until: str | None = None,
    witness_refs: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    published_at: str | None = None,
    response_status: int | None = None,
    response_body: Any | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in SIGNING_AUDIT_MODES:
        raise ValueError("mode must be local-reference, public-key-published, immutable-audit-log, or provider-anchored")
    _require_text(publisher, "publisher")
    _require_text(publication_endpoint, "publication_endpoint")
    _require_text(credential_ref, "credential_ref")
    if mode in {"public-key-published", "provider-anchored"}:
        _require_text(public_key_ref, "public_key_ref")
        _require_text(public_key_fingerprint, "public_key_fingerprint")
    if mode in {"immutable-audit-log", "provider-anchored"}:
        _require_text(audit_log_ref, "audit_log_ref")
        _require_text(audit_log_root, "audit_log_root")
        if audit_log_size is None or audit_log_size < 1:
            raise ValueError("audit_log_size must be at least 1 for immutable-audit-log or provider-anchored mode")
    if mode == "provider-anchored":
        _require_text(actor_ref, "actor_ref")
        if response_status is None:
            raise ValueError("provider-anchored mode requires response_status")

    source_result = verify_auditor_accreditation_signing_ceremony_receipt(
        signing_ceremony_receipt,
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
    if not source_result.ok:
        raise ValueError("invalid auditor accreditation signing ceremony receipt: " + "; ".join(source_result.errors))
    if mode != "local-reference" and source_result.mode not in {"sponsor-controlled", "recorded-response"}:
        raise ValueError("signing audit requires a sponsor-controlled or recorded-response signing ceremony source")

    published = published_at or utc_now()
    _validate_times(str(signing_ceremony_receipt.get("ceremony_at")), published)
    if retention_until:
        _validate_retention(published, retention_until)

    source = _ceremony_record(signing_ceremony_receipt)
    resolved_key_ref = key_ref or source.get("signing_key", {}).get("key_ref")
    if mode != "local-reference" and resolved_key_ref != source.get("signing_key", {}).get("key_ref"):
        raise ValueError("signing audit key_ref must match source signing ceremony key_ref")
    resolved_audit_ref = audit_ref or content_hash(
        {
            "ceremony_id": source.get("ceremony_id"),
            "key_ref": resolved_key_ref,
            "public_key_ref": public_key_ref,
            "audit_log_root": audit_log_root,
            "published_at": published,
        }
    )[:32]
    publisher_record = {
        "name": publisher,
        "endpoint": publication_endpoint,
        "credential": {"ref": credential_ref, "redacted": True},
        "actor_ref": actor_ref,
        "attestation_mode": _attestation_mode(mode),
        "production_replacement": "sponsor-owned HSM/KMS publication workflow with public key transparency record and immutable signing audit log",
    }
    key_publication = {
        "publication_ref": publication_ref or resolved_audit_ref,
        "key_ref": resolved_key_ref,
        "public_key_ref": public_key_ref,
        "fingerprint": public_key_fingerprint,
        "status": key_status,
        "rotation_ref": rotation_ref,
        "revocation_ref": revocation_ref,
        "published_at": published,
    }
    audit_log = {
        "audit_log_ref": audit_log_ref,
        "root": audit_log_root,
        "size": audit_log_size,
        "algorithm": audit_log_algorithm,
        "entry_ref": audit_log_entry_ref,
        "export_ref": audit_log_export_ref,
        "retention_until": retention_until,
        "witness_refs": sorted(set(witness_refs or [])),
    }
    source_artifacts = [_ceremony_artifact(signing_ceremony_receipt)]
    audit = {
        "audit_ref": resolved_audit_ref,
        "mode": mode,
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    body: dict[str, Any] = {
        "schema": AUDITOR_ACCREDITATION_SIGNING_AUDIT_SCHEMA,
        "mode": mode,
        "published_at": published,
        "source": source,
        "publisher": publisher_record,
        "key_publication": key_publication,
        "audit_log": audit_log,
        "audit": audit,
        "source_artifacts": source_artifacts,
        "audit_payload_hash": content_hash(
            {
                "source": source,
                "publisher": publisher_record,
                "key_publication": key_publication,
                "audit_log": audit_log,
                "audit": audit,
                "source_artifacts": source_artifacts,
            }
        ),
        "controls": _controls_for(mode, bool(public_key_ref), bool(audit_log_root), bool(actor_ref), bool(response_status), bool(witness_refs)),
        "limitations": [
            "This receipt records local-reference key publication and immutable signing audit evidence for an auditor accreditation signing ceremony.",
            "It binds the signing ceremony to public key metadata, key status, audit log root, retention metadata, witness references, and optional provider response hashes.",
            "It does not claim production HSM/KMS enforcement unless backed by sponsor-owned key custody, transparency publication, and immutable audit-log infrastructure.",
            "Production deployments should replace local references with sponsor-owned HSM/KMS audit exports, public key transparency records, and externally retained audit logs.",
        ],
    }
    if response_status is not None:
        body["response"] = {
            "status": response_status,
            "body_hash": content_hash(response_body),
            "accepted": 200 <= response_status < 300,
        }
    audit_id = content_hash(body)
    return {
        **body,
        "audit_id": audit_id,
        "signatures": [sign_value({"audit_id": audit_id, "signing_audit": body}, key)],
    }


def verify_auditor_accreditation_signing_audit_receipt(
    receipt: dict[str, Any],
    *,
    signing_ceremony_receipt: dict[str, Any] | None = None,
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
) -> AuditorAccreditationSigningAuditVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != AUDITOR_ACCREDITATION_SIGNING_AUDIT_SCHEMA:
        errors.append(f"unsupported auditor accreditation signing audit schema: {receipt.get('schema')}")
    body = without_keys(receipt, "audit_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("audit_id") != expected_id:
        errors.append("audit_id does not match canonical auditor accreditation signing audit body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("auditor accreditation signing audit receipt missing signature")
    else:
        signed_value = {"audit_id": receipt.get("audit_id"), "signing_audit": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("auditor accreditation signing audit receipt signature invalid")

    mode = receipt.get("mode")
    if mode not in SIGNING_AUDIT_MODES:
        errors.append("auditor accreditation signing audit mode is unsupported")
    if mode == "local-reference":
        warnings.append("auditor accreditation signing audit is local-reference; no public key publication or immutable audit log is claimed")

    try:
        published_at = str(receipt.get("published_at"))
        ceremony_at = str((receipt.get("source") or {}).get("ceremony_at"))
        _validate_times(ceremony_at, published_at)
        if now and parse_rfc3339(now) < parse_rfc3339(published_at):
            errors.append("auditor accreditation signing audit is in the future")
    except ValueError as exc:
        errors.append(f"invalid auditor accreditation signing audit time field: {exc}")

    source = receipt.get("source", {})
    if not isinstance(source, dict) or not source.get("ceremony_id") or not source.get("content_hash"):
        errors.append("auditor accreditation signing audit source ceremony_id and content_hash are required")
        source = {}
    if mode != "local-reference" and source.get("mode") not in {"sponsor-controlled", "recorded-response"}:
        errors.append("signing audit requires a sponsor-controlled or recorded-response signing ceremony source")

    publisher = receipt.get("publisher", {})
    if not isinstance(publisher, dict) or not publisher.get("name") or not publisher.get("endpoint"):
        errors.append("auditor accreditation signing audit publisher name and endpoint are required")
        publisher = {}
    credential = publisher.get("credential", {}) if isinstance(publisher, dict) else {}
    if not isinstance(credential, dict) or not credential.get("ref") or credential.get("redacted") is not True:
        errors.append("auditor accreditation signing audit credential reference must be redacted")
    if mode == "provider-anchored" and not publisher.get("actor_ref"):
        errors.append("provider-anchored signing audit requires actor_ref")

    key_publication = receipt.get("key_publication", {})
    if not isinstance(key_publication, dict):
        errors.append("auditor accreditation signing audit key_publication must be an object")
        key_publication = {}
    if mode in {"public-key-published", "provider-anchored"}:
        if not key_publication.get("public_key_ref") or not key_publication.get("fingerprint"):
            errors.append("public-key-published and provider-anchored signing audits require public_key_ref and fingerprint")
        if key_publication.get("status") != "active":
            errors.append("auditor accreditation signing audit key status must be active")
    if source.get("signing_key", {}).get("key_ref") and key_publication.get("key_ref") != source.get("signing_key", {}).get("key_ref"):
        errors.append("auditor accreditation signing audit key_ref does not match source signing ceremony")

    audit_log = receipt.get("audit_log", {})
    if not isinstance(audit_log, dict):
        errors.append("auditor accreditation signing audit audit_log must be an object")
        audit_log = {}
    if mode in {"immutable-audit-log", "provider-anchored"}:
        if not audit_log.get("audit_log_ref") or not audit_log.get("root"):
            errors.append("immutable-audit-log and provider-anchored signing audits require audit_log_ref and root")
        if not isinstance(audit_log.get("size"), int) or audit_log.get("size") < 1:
            errors.append("immutable-audit-log and provider-anchored signing audits require positive audit log size")
        if not audit_log.get("algorithm"):
            errors.append("auditor accreditation signing audit audit log algorithm is required")
        if audit_log.get("retention_until"):
            try:
                _validate_retention(str(receipt.get("published_at")), str(audit_log.get("retention_until")))
            except ValueError as exc:
                errors.append(str(exc))

    audit = receipt.get("audit", {})
    if not isinstance(audit, dict) or not audit.get("audit_ref"):
        errors.append("auditor accreditation signing audit audit_ref is required")
        audit = {}

    response = receipt.get("response")
    if mode == "provider-anchored":
        if not isinstance(response, dict) or response.get("status") is None or not response.get("body_hash"):
            errors.append("provider-anchored signing audit must include provider response status and body_hash")
        elif not response.get("accepted"):
            errors.append("provider-anchored signing audit requires an accepted provider response")
    elif response is not None and not isinstance(response, dict):
        errors.append("auditor accreditation signing audit response must be an object when supplied")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        errors.append("auditor accreditation signing audit must include exactly one signing ceremony source artifact")
        artifacts = []
    ceremony_artifact = _artifact_by_name(artifacts, "auditor_accreditation_signing_ceremony_receipt")
    if ceremony_artifact is None:
        errors.append("auditor accreditation signing audit missing signing ceremony source artifact")

    if signing_ceremony_receipt is None:
        warnings.append("auditor accreditation signing ceremony source not supplied; verified signing audit binding only")
    else:
        source_result = verify_auditor_accreditation_signing_ceremony_receipt(
            signing_ceremony_receipt,
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
            now=now,
        )
        if not source_result.ok:
            errors.extend(f"source auditor accreditation signing ceremony receipt invalid: {error}" for error in source_result.errors)
        warnings.extend(f"source auditor accreditation signing ceremony warning: {warning}" for warning in source_result.warnings)
        _compare_artifact(ceremony_artifact, _ceremony_artifact(signing_ceremony_receipt), errors)
        if source != _ceremony_record(signing_ceremony_receipt):
            errors.append("auditor accreditation signing audit source record does not match signing ceremony receipt")
        if mode != "local-reference" and source_result.mode not in {"sponsor-controlled", "recorded-response"}:
            errors.append("signing audit requires a sponsor-controlled or recorded-response source receipt")

    expected_payload_hash = content_hash(
        {
            "source": source,
            "publisher": publisher,
            "key_publication": key_publication,
            "audit_log": audit_log,
            "audit": audit,
            "source_artifacts": artifacts,
        }
    )
    if receipt.get("audit_payload_hash") != expected_payload_hash:
        errors.append("auditor accreditation signing audit payload hash does not match records")

    return AuditorAccreditationSigningAuditVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        audit_id=receipt.get("audit_id") if isinstance(receipt.get("audit_id"), str) else None,
        mode=mode if isinstance(mode, str) else None,
    )


def append_auditor_accreditation_signing_audit_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    signing_ceremony_receipt: dict[str, Any] | None = None,
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
    result = verify_auditor_accreditation_signing_audit_receipt(
        receipt,
        signing_ceremony_receipt=signing_ceremony_receipt,
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
        raise ValueError("invalid auditor accreditation signing audit receipt: " + "; ".join(result.errors))
    payload = {
        "audit_id": receipt["audit_id"],
        "audit_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "source": receipt.get("source"),
        "publisher": receipt.get("publisher"),
        "key_publication": receipt.get("key_publication"),
        "audit_log": receipt.get("audit_log"),
        "audit": receipt.get("audit"),
        "response": receipt.get("response"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(AUDITOR_ACCREDITATION_SIGNING_AUDIT_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("published_at"))


def load_auditor_accreditation_signing_audit_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("auditor accreditation signing audit receipt must contain an object")
    return value


def write_auditor_accreditation_signing_audit_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _ceremony_record(receipt: dict[str, Any]) -> dict[str, Any]:
    ceremony = receipt.get("ceremony", {})
    signing_service = receipt.get("signing_service", {})
    signing_key = receipt.get("signing_key", {})
    participants = receipt.get("participants", {})
    source = receipt.get("source", {})
    return {
        "ceremony_id": receipt.get("ceremony_id"),
        "content_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "ceremony_at": receipt.get("ceremony_at"),
        "ceremony": {
            "ceremony_ref": ceremony.get("ceremony_ref"),
            "authority_ref": ceremony.get("authority_ref"),
            "policy_ref": ceremony.get("policy_ref"),
        },
        "signing_service": {
            "name": signing_service.get("name"),
            "endpoint": signing_service.get("endpoint"),
        },
        "signing_key": {
            "provider": signing_key.get("provider"),
            "key_ref": signing_key.get("key_ref"),
            "algorithm": signing_key.get("algorithm"),
            "public_key_ref": signing_key.get("public_key_ref"),
            "rotation_ref": signing_key.get("rotation_ref"),
            "revocation_ref": signing_key.get("revocation_ref"),
        },
        "participants": {
            "operator_ref": (participants.get("operator") or {}).get("ref") if isinstance(participants.get("operator"), dict) else None,
            "approver_refs": participants.get("approver_refs"),
            "witness_refs": participants.get("witness_refs"),
            "quorum_required": participants.get("quorum_required"),
            "quorum_met": participants.get("quorum_met"),
        },
        "source_countersignature": {
            "countersignature_id": source.get("countersignature_id"),
            "operation": (source.get("operation") or {}).get("operation") if isinstance(source.get("operation"), dict) else None,
        },
    }


def _ceremony_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    ceremony = receipt.get("ceremony", {})
    return {
        "name": "auditor_accreditation_signing_ceremony_receipt",
        "artifact_type": "trustai.auditor-accreditation-signing-ceremony",
        "content_hash": content_hash(receipt),
        "ceremony_id": receipt.get("ceremony_id"),
        "ceremony_ref": ceremony.get("ceremony_ref") if isinstance(ceremony, dict) else None,
        "mode": receipt.get("mode"),
    }


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "ceremony_id": artifact.get("ceremony_id"),
        "ceremony_ref": artifact.get("ceremony_ref"),
    }


def _artifact_by_name(artifacts: list[Any], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"auditor accreditation signing audit missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _attestation_mode(mode: str) -> str:
    if mode == "provider-anchored":
        return "provider-anchored"
    if mode == "immutable-audit-log":
        return "immutable-audit-log"
    if mode == "public-key-published":
        return "public-key-published"
    return "local-reference"


def _controls_for(
    mode: str,
    has_public_key: bool,
    has_audit_root: bool,
    has_actor: bool,
    has_response: bool,
    has_witnesses: bool,
) -> list[dict[str, str]]:
    return [
        {
            "id": "signing-ceremony-binding",
            "status": "implemented-reference",
            "description": "Signing audit binds to a verified auditor accreditation signing ceremony by canonical hash.",
        },
        {
            "id": "public-key-publication",
            "status": "published-reference" if has_public_key else "planned-production",
            "description": "Receipt records public key reference, key fingerprint, key status, and rotation/revocation references.",
        },
        {
            "id": "immutable-signing-audit-log",
            "status": "implemented-reference" if has_audit_root else "planned-production",
            "description": "Receipt records immutable audit log root, size, algorithm, entry reference, and retention metadata.",
        },
        {
            "id": "authorized-publication-actor",
            "status": "authenticated-reference" if has_actor else "planned-production",
            "description": "Provider-anchored publication binds the audit to an authenticated sponsor actor.",
        },
        {
            "id": "provider-response-capture",
            "status": "recorded-response" if has_response else "planned-production",
            "description": "Provider-anchored publication preserves the publication provider response hash.",
        },
        {
            "id": "audit-witness-evidence",
            "status": "implemented-reference" if has_witnesses else "planned-production",
            "description": "Receipt records witness references for the key publication and signing audit log.",
        },
    ]


def _validate_times(source_ceremony_at: str, published_at: str) -> None:
    source_time = parse_rfc3339(source_ceremony_at)
    published_time = parse_rfc3339(published_at)
    if published_time < source_time:
        raise ValueError("auditor accreditation signing audit published_at must be at or after signing ceremony time")


def _validate_retention(published_at: str, retention_until: str) -> None:
    published_time = parse_rfc3339(published_at)
    retention_time = parse_rfc3339(retention_until)
    if retention_time <= published_time:
        raise ValueError("auditor accreditation signing audit retention_until must be after published_at")


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
