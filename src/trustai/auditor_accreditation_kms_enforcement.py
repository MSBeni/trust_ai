from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .auditor_accreditation_signing_audit import verify_auditor_accreditation_signing_audit_receipt
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_SCHEMA = "trustai.auditor-accreditation-kms-enforcement/0.1"
AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_ENTRY_TYPE = "auditor.accreditation.kms_enforcement.recorded"

KMS_ENFORCEMENT_MODES = {"local-reference", "policy-bound", "hsm-attested", "provider-enforced"}


@dataclass
class AuditorAccreditationKmsEnforcementVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    enforcement_id: str | None = None
    mode: str | None = None


def build_auditor_accreditation_kms_enforcement_receipt(
    signing_audit_receipt: dict[str, Any],
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
    mode: str = "provider-enforced",
    enforcement_ref: str | None = None,
    provider: str = "local-sponsor-kms",
    provider_endpoint: str = "local-sponsor-kms",
    credential_ref: str = "local-reference",
    actor_ref: str | None = None,
    key_ref: str | None = None,
    key_provider: str | None = None,
    key_algorithm: str | None = None,
    key_status: str = "active",
    attestation_ref: str | None = None,
    attestation_hash: str | None = None,
    key_policy_ref: str | None = None,
    key_policy_hash: str | None = None,
    allowed_actor_refs: list[str] | None = None,
    key_usage: list[str] | None = None,
    denied_operation_refs: list[str] | None = None,
    quorum_required: int = 1,
    quorum_approver_refs: list[str] | None = None,
    rotation_ref: str | None = None,
    revocation_ref: str | None = None,
    audit_log_ref: str | None = None,
    audit_log_root: str | None = None,
    audit_log_size: int | None = None,
    audit_log_algorithm: str | None = None,
    evidence_refs: list[str] | None = None,
    enforced_at: str | None = None,
    response_status: int | None = None,
    response_body: Any | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in KMS_ENFORCEMENT_MODES:
        raise ValueError("mode must be local-reference, policy-bound, hsm-attested, or provider-enforced")
    _require_text(provider, "provider")
    _require_text(provider_endpoint, "provider_endpoint")
    _require_text(credential_ref, "credential_ref")
    if quorum_required < 1:
        raise ValueError("quorum_required must be at least 1")

    source_result = verify_auditor_accreditation_signing_audit_receipt(
        signing_audit_receipt,
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
    if not source_result.ok:
        raise ValueError("invalid auditor accreditation signing audit receipt: " + "; ".join(source_result.errors))
    if mode != "local-reference" and source_result.mode != "provider-anchored":
        raise ValueError("KMS enforcement requires a provider-anchored signing audit source")

    source = _signing_audit_record(signing_audit_receipt)
    source_key = source.get("key_publication", {}).get("key_ref")
    resolved_key_ref = key_ref or source_key
    if mode != "local-reference" and resolved_key_ref != source_key:
        raise ValueError("KMS enforcement key_ref must match source signing audit key_ref")
    if mode in {"hsm-attested", "provider-enforced"}:
        _require_text(attestation_ref, "attestation_ref")
        _require_text(attestation_hash, "attestation_hash")
        _require_text(key_policy_ref, "key_policy_ref")
        _require_text(key_policy_hash, "key_policy_hash")
        _require_text(source.get("key_publication", {}).get("public_key_ref"), "source public_key_ref")
        _require_text(source.get("key_publication", {}).get("fingerprint"), "source public key fingerprint")
        _require_text(source.get("audit_log", {}).get("audit_log_ref") or audit_log_ref, "audit_log_ref")
        _require_text(source.get("audit_log", {}).get("root") or audit_log_root, "audit_log_root")
    if mode in {"policy-bound", "hsm-attested", "provider-enforced"}:
        _require_text(key_policy_ref, "key_policy_ref")
        _require_text(key_policy_hash, "key_policy_hash")
        if len(quorum_approver_refs or []) < quorum_required:
            raise ValueError("quorum_approver_refs must satisfy quorum_required")
    if mode == "provider-enforced":
        _require_text(actor_ref, "actor_ref")
        if response_status is None:
            raise ValueError("provider-enforced mode requires response_status")

    occurred = enforced_at or utc_now()
    _validate_times(str(signing_audit_receipt.get("published_at")), occurred)
    usage = sorted(set(key_usage or ["sign", "verify"]))
    allowed_actors = sorted(set(allowed_actor_refs or ([actor_ref] if actor_ref else [])))
    if actor_ref and actor_ref not in allowed_actors:
        allowed_actors.append(actor_ref)
        allowed_actors.sort()
    approvers = sorted(set(quorum_approver_refs or []))
    audit_log_source = source.get("audit_log", {})
    audit_log = {
        "audit_log_ref": audit_log_ref or audit_log_source.get("audit_log_ref"),
        "root": audit_log_root or audit_log_source.get("root"),
        "size": audit_log_size or audit_log_source.get("size"),
        "algorithm": audit_log_algorithm or audit_log_source.get("algorithm"),
        "source_entry_ref": audit_log_source.get("entry_ref"),
        "source_export_ref": audit_log_source.get("export_ref"),
    }
    ref = enforcement_ref or content_hash(
        {
            "audit_id": source.get("audit_id"),
            "key_ref": resolved_key_ref,
            "attestation_ref": attestation_ref,
            "key_policy_ref": key_policy_ref,
            "enforced_at": occurred,
        }
    )[:32]
    enforcement_service = {
        "provider": provider,
        "endpoint": provider_endpoint,
        "credential": {"ref": credential_ref, "redacted": True},
        "actor_ref": actor_ref,
        "attestation_mode": _attestation_mode(mode),
        "production_replacement": "sponsor-owned HSM/KMS enforcement workflow with exported key policy, HSM attestation, public key publication, and immutable audit logs",
    }
    key_custody = {
        "provider": key_provider or source.get("source_signing_key", {}).get("provider"),
        "key_ref": resolved_key_ref,
        "algorithm": key_algorithm or source.get("source_signing_key", {}).get("algorithm"),
        "status": key_status,
        "ownership": "sponsor-owned" if mode != "local-reference" else "local-reference",
        "public_key_ref": source.get("key_publication", {}).get("public_key_ref"),
        "public_key_fingerprint": source.get("key_publication", {}).get("fingerprint"),
        "attestation_ref": attestation_ref,
        "attestation_hash": attestation_hash,
        "rotation_ref": rotation_ref or source.get("key_publication", {}).get("rotation_ref"),
        "revocation_ref": revocation_ref or source.get("key_publication", {}).get("revocation_ref"),
    }
    key_policy = {
        "policy_ref": key_policy_ref,
        "policy_hash": key_policy_hash,
        "allowed_actor_refs": allowed_actors,
        "key_usage": usage,
        "denied_operation_refs": sorted(set(denied_operation_refs or [])),
        "quorum_required": quorum_required,
        "quorum_approver_refs": approvers,
        "quorum_met": len(approvers) >= quorum_required,
    }
    enforcement = {
        "enforcement_ref": ref,
        "mode": mode,
        "enforced_at": occurred,
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    source_artifacts = [_signing_audit_artifact(signing_audit_receipt)]
    body: dict[str, Any] = {
        "schema": AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_SCHEMA,
        "mode": mode,
        "enforced_at": occurred,
        "source": source,
        "enforcement": enforcement,
        "enforcement_service": enforcement_service,
        "key_custody": key_custody,
        "key_policy": key_policy,
        "audit_log": audit_log,
        "source_artifacts": source_artifacts,
        "enforcement_payload_hash": content_hash(
            {
                "source": source,
                "enforcement": enforcement,
                "enforcement_service": enforcement_service,
                "key_custody": key_custody,
                "key_policy": key_policy,
                "audit_log": audit_log,
                "source_artifacts": source_artifacts,
            }
        ),
        "controls": _controls_for(mode, bool(attestation_ref), bool(key_policy_ref), key_policy["quorum_met"], bool(audit_log.get("root")), bool(response_status)),
        "limitations": [
            "This receipt records local-reference sponsor-owned KMS/HSM enforcement evidence for an auditor accreditation signing audit.",
            "It binds key custody, HSM attestation, key policy, actor authorization, quorum, public key publication, rotation/revocation, and immutable audit-log root evidence to a verified signing audit.",
            "It does not prove live cloud KMS/HSM enforcement unless backed by provider exports, sponsor-controlled key custody, and externally retained audit logs.",
            "Production deployments should replace local references with cloud KMS/HSM attestation exports, key policy documents, and independent transparency/audit records.",
        ],
    }
    if response_status is not None:
        body["response"] = {
            "status": response_status,
            "body_hash": content_hash(response_body),
            "accepted": 200 <= response_status < 300,
        }
    enforcement_id = content_hash(body)
    return {
        **body,
        "enforcement_id": enforcement_id,
        "signatures": [sign_value({"enforcement_id": enforcement_id, "kms_enforcement": body}, key)],
    }


def verify_auditor_accreditation_kms_enforcement_receipt(
    receipt: dict[str, Any],
    *,
    signing_audit_receipt: dict[str, Any] | None = None,
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
) -> AuditorAccreditationKmsEnforcementVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_SCHEMA:
        errors.append(f"unsupported auditor accreditation KMS enforcement schema: {receipt.get('schema')}")
    body = without_keys(receipt, "enforcement_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("enforcement_id") != expected_id:
        errors.append("enforcement_id does not match canonical auditor accreditation KMS enforcement body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("auditor accreditation KMS enforcement receipt missing signature")
    else:
        signed_value = {"enforcement_id": receipt.get("enforcement_id"), "kms_enforcement": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("auditor accreditation KMS enforcement receipt signature invalid")

    mode = receipt.get("mode")
    if mode not in KMS_ENFORCEMENT_MODES:
        errors.append("auditor accreditation KMS enforcement mode is unsupported")
    if mode == "local-reference":
        warnings.append("auditor accreditation KMS enforcement is local-reference; no sponsor-owned HSM/KMS enforcement is claimed")

    try:
        enforced_at = str(receipt.get("enforced_at"))
        source_published_at = str((receipt.get("source") or {}).get("published_at"))
        _validate_times(source_published_at, enforced_at)
        if now and parse_rfc3339(now) < parse_rfc3339(enforced_at):
            errors.append("auditor accreditation KMS enforcement is in the future")
    except ValueError as exc:
        errors.append(f"invalid auditor accreditation KMS enforcement time field: {exc}")

    source = receipt.get("source", {})
    if not isinstance(source, dict) or not source.get("audit_id") or not source.get("content_hash"):
        errors.append("auditor accreditation KMS enforcement source audit_id and content_hash are required")
        source = {}
    if mode != "local-reference" and source.get("mode") != "provider-anchored":
        errors.append("KMS enforcement requires a provider-anchored signing audit source")

    enforcement = receipt.get("enforcement", {})
    if not isinstance(enforcement, dict) or not enforcement.get("enforcement_ref"):
        errors.append("auditor accreditation KMS enforcement_ref is required")
        enforcement = {}

    enforcement_service = receipt.get("enforcement_service", {})
    if not isinstance(enforcement_service, dict) or not enforcement_service.get("provider") or not enforcement_service.get("endpoint"):
        errors.append("auditor accreditation KMS enforcement service provider and endpoint are required")
        enforcement_service = {}
    credential = enforcement_service.get("credential", {}) if isinstance(enforcement_service, dict) else {}
    if not isinstance(credential, dict) or not credential.get("ref") or credential.get("redacted") is not True:
        errors.append("auditor accreditation KMS enforcement credential reference must be redacted")
    if mode == "provider-enforced" and not enforcement_service.get("actor_ref"):
        errors.append("provider-enforced KMS enforcement requires actor_ref")

    key_custody = receipt.get("key_custody", {})
    if not isinstance(key_custody, dict):
        errors.append("auditor accreditation KMS enforcement key_custody must be an object")
        key_custody = {}
    source_key_publication = source.get("key_publication", {}) if isinstance(source, dict) else {}
    if key_custody.get("key_ref") != source_key_publication.get("key_ref"):
        errors.append("auditor accreditation KMS enforcement key_ref does not match signing audit source")
    if mode != "local-reference" and key_custody.get("status") != "active":
        errors.append("auditor accreditation KMS enforcement key status must be active")
    if mode in {"hsm-attested", "provider-enforced"}:
        if not key_custody.get("attestation_ref") or not key_custody.get("attestation_hash"):
            errors.append("hsm-attested and provider-enforced KMS enforcement require attestation_ref and attestation_hash")
        if key_custody.get("public_key_ref") != source_key_publication.get("public_key_ref"):
            errors.append("auditor accreditation KMS enforcement public_key_ref does not match signing audit source")
        if key_custody.get("public_key_fingerprint") != source_key_publication.get("fingerprint"):
            errors.append("auditor accreditation KMS enforcement public key fingerprint does not match signing audit source")

    key_policy = receipt.get("key_policy", {})
    if not isinstance(key_policy, dict):
        errors.append("auditor accreditation KMS enforcement key_policy must be an object")
        key_policy = {}
    if mode in {"policy-bound", "hsm-attested", "provider-enforced"}:
        if not key_policy.get("policy_ref") or not key_policy.get("policy_hash"):
            errors.append("policy-bound KMS enforcement requires key policy ref and hash")
        key_usage = key_policy.get("key_usage")
        if not isinstance(key_usage, list) or "sign" not in key_usage:
            errors.append("auditor accreditation KMS enforcement key policy must allow signing usage")
        allowed_actors = key_policy.get("allowed_actor_refs")
        if not isinstance(allowed_actors, list) or not allowed_actors:
            errors.append("auditor accreditation KMS enforcement key policy requires allowed_actor_refs")
        actor_ref = enforcement_service.get("actor_ref")
        if actor_ref and actor_ref not in allowed_actors:
            errors.append("auditor accreditation KMS enforcement actor_ref must be allowed by key policy")
        quorum_required = key_policy.get("quorum_required")
        approvers = key_policy.get("quorum_approver_refs")
        if not isinstance(quorum_required, int) or not isinstance(approvers, list) or len(approvers) < quorum_required:
            errors.append("auditor accreditation KMS enforcement approvers must satisfy quorum_required")
        if key_policy.get("quorum_met") is not True:
            errors.append("auditor accreditation KMS enforcement quorum_met must be true")

    audit_log = receipt.get("audit_log", {})
    if not isinstance(audit_log, dict):
        errors.append("auditor accreditation KMS enforcement audit_log must be an object")
        audit_log = {}
    source_audit_log = source.get("audit_log", {}) if isinstance(source, dict) else {}
    if mode in {"hsm-attested", "provider-enforced"}:
        if not audit_log.get("audit_log_ref") or not audit_log.get("root"):
            errors.append("hsm-attested and provider-enforced KMS enforcement require audit_log_ref and root")
        if audit_log.get("audit_log_ref") != source_audit_log.get("audit_log_ref"):
            errors.append("auditor accreditation KMS enforcement audit_log_ref does not match signing audit source")
        if audit_log.get("root") != source_audit_log.get("root"):
            errors.append("auditor accreditation KMS enforcement audit log root does not match signing audit source")
        if not isinstance(audit_log.get("size"), int) or audit_log.get("size") < 1:
            errors.append("auditor accreditation KMS enforcement requires positive audit log size")

    response = receipt.get("response")
    if mode == "provider-enforced":
        if not isinstance(response, dict) or response.get("status") is None or not response.get("body_hash"):
            errors.append("provider-enforced KMS enforcement must include provider response status and body_hash")
        elif not response.get("accepted"):
            errors.append("provider-enforced KMS enforcement requires an accepted provider response")
    elif response is not None and not isinstance(response, dict):
        errors.append("auditor accreditation KMS enforcement response must be an object when supplied")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        errors.append("auditor accreditation KMS enforcement must include exactly one signing audit source artifact")
        artifacts = []
    audit_artifact = _artifact_by_name(artifacts, "auditor_accreditation_signing_audit_receipt")
    if audit_artifact is None:
        errors.append("auditor accreditation KMS enforcement missing signing audit source artifact")

    if signing_audit_receipt is None:
        warnings.append("auditor accreditation signing audit source not supplied; verified KMS enforcement binding only")
    else:
        source_result = verify_auditor_accreditation_signing_audit_receipt(
            signing_audit_receipt,
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
            now=now,
        )
        if not source_result.ok:
            errors.extend(f"source auditor accreditation signing audit receipt invalid: {error}" for error in source_result.errors)
        warnings.extend(f"source auditor accreditation signing audit warning: {warning}" for warning in source_result.warnings)
        _compare_artifact(audit_artifact, _signing_audit_artifact(signing_audit_receipt), errors)
        if source != _signing_audit_record(signing_audit_receipt):
            errors.append("auditor accreditation KMS enforcement source record does not match signing audit receipt")
        if mode != "local-reference" and source_result.mode != "provider-anchored":
            errors.append("KMS enforcement requires a provider-anchored signing audit source receipt")

    expected_payload_hash = content_hash(
        {
            "source": source,
            "enforcement": enforcement,
            "enforcement_service": enforcement_service,
            "key_custody": key_custody,
            "key_policy": key_policy,
            "audit_log": audit_log,
            "source_artifacts": artifacts,
        }
    )
    if receipt.get("enforcement_payload_hash") != expected_payload_hash:
        errors.append("auditor accreditation KMS enforcement payload hash does not match records")

    return AuditorAccreditationKmsEnforcementVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        enforcement_id=receipt.get("enforcement_id") if isinstance(receipt.get("enforcement_id"), str) else None,
        mode=mode if isinstance(mode, str) else None,
    )


def append_auditor_accreditation_kms_enforcement_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    signing_audit_receipt: dict[str, Any] | None = None,
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
    result = verify_auditor_accreditation_kms_enforcement_receipt(
        receipt,
        signing_audit_receipt=signing_audit_receipt,
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
        raise ValueError("invalid auditor accreditation KMS enforcement receipt: " + "; ".join(result.errors))
    payload = {
        "enforcement_id": receipt["enforcement_id"],
        "enforcement_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "source": receipt.get("source"),
        "enforcement": receipt.get("enforcement"),
        "enforcement_service": receipt.get("enforcement_service"),
        "key_custody": receipt.get("key_custody"),
        "key_policy": receipt.get("key_policy"),
        "audit_log": receipt.get("audit_log"),
        "response": receipt.get("response"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("enforced_at"))


def load_auditor_accreditation_kms_enforcement_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("auditor accreditation KMS enforcement receipt must contain an object")
    return value


def write_auditor_accreditation_kms_enforcement_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _signing_audit_record(receipt: dict[str, Any]) -> dict[str, Any]:
    audit = receipt.get("audit", {})
    key_publication = receipt.get("key_publication", {})
    audit_log = receipt.get("audit_log", {})
    source = receipt.get("source", {})
    return {
        "audit_id": receipt.get("audit_id"),
        "content_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "published_at": receipt.get("published_at"),
        "audit": {
            "audit_ref": audit.get("audit_ref") if isinstance(audit, dict) else None,
        },
        "key_publication": {
            "key_ref": key_publication.get("key_ref") if isinstance(key_publication, dict) else None,
            "public_key_ref": key_publication.get("public_key_ref") if isinstance(key_publication, dict) else None,
            "fingerprint": key_publication.get("fingerprint") if isinstance(key_publication, dict) else None,
            "status": key_publication.get("status") if isinstance(key_publication, dict) else None,
            "rotation_ref": key_publication.get("rotation_ref") if isinstance(key_publication, dict) else None,
            "revocation_ref": key_publication.get("revocation_ref") if isinstance(key_publication, dict) else None,
        },
        "audit_log": {
            "audit_log_ref": audit_log.get("audit_log_ref") if isinstance(audit_log, dict) else None,
            "root": audit_log.get("root") if isinstance(audit_log, dict) else None,
            "size": audit_log.get("size") if isinstance(audit_log, dict) else None,
            "algorithm": audit_log.get("algorithm") if isinstance(audit_log, dict) else None,
            "entry_ref": audit_log.get("entry_ref") if isinstance(audit_log, dict) else None,
            "export_ref": audit_log.get("export_ref") if isinstance(audit_log, dict) else None,
        },
        "source_signing_key": {
            "provider": (source.get("signing_key") or {}).get("provider") if isinstance(source.get("signing_key"), dict) else None,
            "key_ref": (source.get("signing_key") or {}).get("key_ref") if isinstance(source.get("signing_key"), dict) else None,
            "algorithm": (source.get("signing_key") or {}).get("algorithm") if isinstance(source.get("signing_key"), dict) else None,
        },
    }


def _signing_audit_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    audit = receipt.get("audit", {})
    return {
        "name": "auditor_accreditation_signing_audit_receipt",
        "artifact_type": "trustai.auditor-accreditation-signing-audit",
        "content_hash": content_hash(receipt),
        "audit_id": receipt.get("audit_id"),
        "audit_ref": audit.get("audit_ref") if isinstance(audit, dict) else None,
        "mode": receipt.get("mode"),
    }


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "audit_id": artifact.get("audit_id"),
        "audit_ref": artifact.get("audit_ref"),
    }


def _artifact_by_name(artifacts: list[Any], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"auditor accreditation KMS enforcement missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _attestation_mode(mode: str) -> str:
    if mode == "provider-enforced":
        return "provider-enforced"
    if mode == "hsm-attested":
        return "hsm-attested"
    if mode == "policy-bound":
        return "policy-bound"
    return "local-reference"


def _controls_for(
    mode: str,
    has_attestation: bool,
    has_policy: bool,
    quorum_met: bool,
    has_audit_log: bool,
    has_response: bool,
) -> list[dict[str, str]]:
    return [
        {
            "id": "signing-audit-binding",
            "status": "implemented-reference",
            "description": "KMS enforcement receipt binds to a verified auditor accreditation signing audit by canonical hash.",
        },
        {
            "id": "sponsor-key-custody",
            "status": "attested-reference" if has_attestation else "planned-production",
            "description": "Receipt records sponsor-owned HSM/KMS attestation reference and attestation hash.",
        },
        {
            "id": "key-policy-enforcement",
            "status": "policy-bound" if has_policy else "planned-production",
            "description": "Receipt records key policy hash, allowed actors, usage scope, denied operations, and quorum controls.",
        },
        {
            "id": "dual-control-quorum",
            "status": "implemented-reference" if quorum_met else "planned-production",
            "description": "Receipt verifies that recorded approvers satisfy the required signing quorum.",
        },
        {
            "id": "immutable-kms-audit-log",
            "status": "implemented-reference" if has_audit_log else "planned-production",
            "description": "Receipt binds the enforcement record to the source signing audit immutable log root and size.",
        },
        {
            "id": "provider-enforcement-response",
            "status": "recorded-response" if has_response else ("not-applicable" if mode != "provider-enforced" else "planned-production"),
            "description": "Provider-enforced mode preserves the KMS/HSM provider response hash.",
        },
    ]


def _validate_times(source_published_at: str, enforced_at: str) -> None:
    source_time = parse_rfc3339(source_published_at)
    enforcement_time = parse_rfc3339(enforced_at)
    if enforcement_time < source_time:
        raise ValueError("auditor accreditation KMS enforcement enforced_at must be at or after signing audit publication time")


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
