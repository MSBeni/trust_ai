from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .trust_authority_provider import verify_trust_authority_provider_attestation

TRUST_AUTHORITY_KMS_ENFORCEMENT_SCHEMA = "trustai.trust-authority-kms-enforcement/0.1"
TRUST_AUTHORITY_KMS_ENFORCEMENT_ENTRY_TYPE = "trust_authority.kms_enforcement.recorded"
TRUST_AUTHORITY_KMS_ENFORCEMENT_MODES = {"local-reference", "policy-bound", "hsm-attested", "provider-enforced"}


@dataclass
class TrustAuthorityKmsEnforcementVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    enforcement_id: str | None = None
    mode: str | None = None


def build_trust_authority_kms_enforcement_receipt(
    provider_attestation: dict[str, Any],
    trust_authority_receipt: dict[str, Any] | None = None,
    source_chain: Any | None = None,
    keyring: dict[str, Any] | None = None,
    *,
    proof_pack: dict[str, Any] | None = None,
    mode: str = "provider-enforced",
    enforcement_ref: str | None = None,
    provider: str = "local-trust-authority-kms",
    provider_endpoint: str = "local-reference",
    credential_ref: str = "local-reference",
    actor_ref: str | None = None,
    key_ref: str | None = None,
    key_provider: str | None = None,
    key_algorithm: str | None = None,
    key_status: str = "active",
    hsm_attestation_ref: str | None = None,
    hsm_attestation_hash: str | None = None,
    key_policy_ref: str | None = None,
    key_policy_hash: str | None = None,
    timestamp_policy_ref: str | None = None,
    timestamp_policy_hash: str | None = None,
    timestamp_attestation_ref: str | None = None,
    timestamp_attestation_hash: str | None = None,
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
    if mode not in TRUST_AUTHORITY_KMS_ENFORCEMENT_MODES:
        raise ValueError(f"mode must be one of {sorted(TRUST_AUTHORITY_KMS_ENFORCEMENT_MODES)}")
    _require_text(provider, "provider")
    _require_text(provider_endpoint, "provider_endpoint")
    _require_text(credential_ref, "credential_ref")
    if quorum_required < 1:
        raise ValueError("quorum_required must be at least 1")

    source_result = verify_trust_authority_provider_attestation(
        provider_attestation,
        trust_authority_receipt,
        source_chain,
        keyring,
        proof_pack=proof_pack,
        key=key,
    )
    if not source_result.ok:
        raise ValueError("invalid trust authority provider attestation: " + "; ".join(source_result.errors))
    if mode != "local-reference" and provider_attestation.get("mode") != "provider-attested":
        raise ValueError("KMS enforcement requires a provider-attested trust authority provider source")

    source = _provider_attestation_record(provider_attestation)
    source_kms = source.get("kms", {})
    source_tsa = source.get("timestamp_authority", {})
    resolved_key_ref = key_ref or source_kms.get("key_ref")
    if mode != "local-reference" and resolved_key_ref != source_kms.get("key_ref"):
        raise ValueError("KMS enforcement key_ref must match source trust authority provider KMS key_ref")
    resolved_key_policy_ref = key_policy_ref or source_kms.get("key_policy_ref")
    resolved_key_policy_hash = key_policy_hash or source_kms.get("key_policy_hash")
    resolved_timestamp_policy_ref = timestamp_policy_ref or source_tsa.get("timestamp_policy_ref")
    resolved_timestamp_policy_hash = timestamp_policy_hash or source_tsa.get("timestamp_policy_hash")

    if source_kms.get("key_policy_hash") and resolved_key_policy_hash != source_kms.get("key_policy_hash"):
        raise ValueError("KMS enforcement key_policy_hash must match source trust authority provider key policy hash")
    if source_tsa.get("timestamp_policy_hash") and resolved_timestamp_policy_hash != source_tsa.get("timestamp_policy_hash"):
        raise ValueError("KMS enforcement timestamp_policy_hash must match source trust authority provider timestamp policy hash")
    if mode in {"hsm-attested", "provider-enforced"}:
        _require_text(hsm_attestation_ref, "hsm_attestation_ref")
        _require_text(hsm_attestation_hash, "hsm_attestation_hash")
        _require_text(source_tsa.get("certificate_chain_hash"), "source TSA certificate_chain_hash")
    if mode in {"policy-bound", "hsm-attested", "provider-enforced"}:
        _require_text(resolved_key_policy_ref, "key_policy_ref")
        _require_text(resolved_key_policy_hash, "key_policy_hash")
        _require_text(resolved_timestamp_policy_ref, "timestamp_policy_ref")
        _require_text(resolved_timestamp_policy_hash, "timestamp_policy_hash")
        if len(quorum_approver_refs or []) < quorum_required:
            raise ValueError("quorum_approver_refs must satisfy quorum_required")
    if mode == "provider-enforced":
        _require_text(actor_ref, "actor_ref")
        if response_status is None:
            raise ValueError("provider-enforced mode requires response_status")

    occurred = enforced_at or utc_now()
    _validate_times(str(provider_attestation.get("attested_at")), occurred)
    usage = sorted(set(key_usage or ["sign", "timestamp", "verify"]))
    allowed_actors = sorted(set(allowed_actor_refs or ([actor_ref] if actor_ref else [])))
    if actor_ref and actor_ref not in allowed_actors:
        allowed_actors.append(actor_ref)
        allowed_actors.sort()
    approvers = sorted(set(quorum_approver_refs or []))
    source_audit = source.get("audit_log", {})
    audit_log = {
        "audit_log_ref": audit_log_ref or source_audit.get("audit_log_ref"),
        "root": audit_log_root or source_audit.get("root"),
        "retention_until": source_audit.get("retention_until"),
        "size": audit_log_size,
        "algorithm": audit_log_algorithm or "sha256-merkle-root",
    }
    ref = enforcement_ref or content_hash({"attestation_id": source.get("attestation_id"), "key_ref": resolved_key_ref, "hsm_attestation_ref": hsm_attestation_ref, "key_policy_ref": resolved_key_policy_ref, "timestamp_policy_ref": resolved_timestamp_policy_ref, "enforced_at": occurred})[:32]
    enforcement = {"enforcement_ref": ref, "mode": mode, "enforced_at": occurred, "evidence_refs": sorted(set(evidence_refs or []))}
    enforcement_service = {"provider": provider, "endpoint": provider_endpoint, "credential": {"ref": credential_ref, "redacted": True}, "actor_ref": actor_ref, "attestation_mode": _attestation_mode(mode), "production_replacement": "customer-controlled KMS/HSM and RFC 3161 TSA enforcement workflow with exported key policy, HSM attestation, TSA certificate-chain evidence, and immutable provider audit logs"}
    key_custody = {"provider": key_provider or source_kms.get("provider"), "key_ref": resolved_key_ref, "algorithm": key_algorithm or source_kms.get("key_algorithm"), "status": key_status, "ownership": "customer-controlled" if mode != "local-reference" else "local-reference", "hsm_attestation_ref": hsm_attestation_ref, "hsm_attestation_hash": hsm_attestation_hash, "rotation_ref": rotation_ref, "revocation_ref": revocation_ref}
    timestamp_authority = {"provider": source_tsa.get("provider"), "endpoint": source_tsa.get("endpoint"), "certificate_chain_hash": source_tsa.get("certificate_chain_hash"), "timestamp_policy_ref": resolved_timestamp_policy_ref, "timestamp_policy_hash": resolved_timestamp_policy_hash, "timestamp_attestation_ref": timestamp_attestation_ref, "timestamp_attestation_hash": timestamp_attestation_hash}
    key_policy = {"policy_ref": resolved_key_policy_ref, "policy_hash": resolved_key_policy_hash, "allowed_actor_refs": allowed_actors, "key_usage": usage, "denied_operation_refs": sorted(set(denied_operation_refs or [])), "quorum_required": quorum_required, "quorum_approver_refs": approvers, "quorum_met": len(approvers) >= quorum_required}
    source_artifacts = [_provider_attestation_artifact(provider_attestation)]
    body: dict[str, Any] = {"schema": TRUST_AUTHORITY_KMS_ENFORCEMENT_SCHEMA, "mode": mode, "enforced_at": occurred, "source": source, "enforcement": enforcement, "enforcement_service": enforcement_service, "key_custody": key_custody, "timestamp_authority": timestamp_authority, "key_policy": key_policy, "audit_log": audit_log, "source_artifacts": source_artifacts, "enforcement_payload_hash": content_hash({"source": source, "enforcement": enforcement, "enforcement_service": enforcement_service, "key_custody": key_custody, "timestamp_authority": timestamp_authority, "key_policy": key_policy, "audit_log": audit_log, "source_artifacts": source_artifacts}), "controls": _controls_for(mode, bool(hsm_attestation_ref and hsm_attestation_hash), bool(resolved_key_policy_ref and resolved_key_policy_hash), bool(resolved_timestamp_policy_ref and resolved_timestamp_policy_hash), key_policy["quorum_met"], bool(audit_log.get("root")), bool(response_status)), "limitations": ["This receipt records local-reference KMS/HSM and TSA policy enforcement evidence for a trust-authority provider attestation.", "It binds key custody, HSM attestation, key and timestamp policy hashes, actor authorization, quorum, audit-log roots, and provider response hashes to a verified trust-authority provider attestation.", "It does not prove live cloud KMS/HSM or RFC 3161 TSA enforcement unless backed by provider exports, customer-controlled key custody, and externally retained audit logs.", "Production deployments should replace local references with cloud KMS/HSM attestation exports, key policy documents, TSA policy exports, and independent transparency/audit records."]}
    if response_status is not None:
        body["response"] = {"status": response_status, "body_hash": content_hash(response_body), "accepted": 200 <= response_status < 300}
    enforcement_id = content_hash(body)
    return {**body, "enforcement_id": enforcement_id, "signatures": [sign_value({"enforcement_id": enforcement_id, "trust_authority_kms_enforcement": body}, key)]}

def verify_trust_authority_kms_enforcement_receipt(
    receipt: dict[str, Any],
    *,
    provider_attestation: dict[str, Any] | None = None,
    trust_authority_receipt: dict[str, Any] | None = None,
    source_chain: Any | None = None,
    keyring: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> TrustAuthorityKmsEnforcementVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != TRUST_AUTHORITY_KMS_ENFORCEMENT_SCHEMA:
        errors.append(f"unsupported trust authority KMS enforcement schema: {receipt.get('schema')}")
    body = without_keys(receipt, "enforcement_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("enforcement_id") != expected_id:
        errors.append("enforcement_id does not match canonical trust authority KMS enforcement body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("trust authority KMS enforcement receipt missing signature")
    else:
        signed_value = {"enforcement_id": receipt.get("enforcement_id"), "trust_authority_kms_enforcement": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("trust authority KMS enforcement receipt signature invalid")

    mode = receipt.get("mode")
    if mode not in TRUST_AUTHORITY_KMS_ENFORCEMENT_MODES:
        errors.append("trust authority KMS enforcement mode is unsupported")
    if mode == "local-reference":
        warnings.append("trust authority KMS enforcement is local-reference; no customer-controlled KMS/HSM enforcement is claimed")

    try:
        enforced_at = str(receipt.get("enforced_at"))
        source_attested_at = str((receipt.get("source") or {}).get("attested_at"))
        _validate_times(source_attested_at, enforced_at)
        if now and parse_rfc3339(now) < parse_rfc3339(enforced_at):
            errors.append("trust authority KMS enforcement is in the future")
    except ValueError as exc:
        errors.append(f"invalid trust authority KMS enforcement time field: {exc}")

    source = receipt.get("source", {})
    if not isinstance(source, dict) or not source.get("attestation_id") or not source.get("content_hash"):
        errors.append("trust authority KMS enforcement source attestation_id and content_hash are required")
        source = {}
    if mode != "local-reference" and source.get("mode") != "provider-attested":
        errors.append("KMS enforcement requires a provider-attested trust authority provider source")

    enforcement = receipt.get("enforcement", {})
    if not isinstance(enforcement, dict) or not enforcement.get("enforcement_ref"):
        errors.append("trust authority KMS enforcement_ref is required")
        enforcement = {}

    enforcement_service = receipt.get("enforcement_service", {})
    if not isinstance(enforcement_service, dict) or not enforcement_service.get("provider") or not enforcement_service.get("endpoint"):
        errors.append("trust authority KMS enforcement service provider and endpoint are required")
        enforcement_service = {}
    endpoint = str(enforcement_service.get("endpoint") or "")
    if mode == "provider-enforced" and not _is_https(endpoint):
        errors.append("provider-enforced trust authority KMS endpoint must use HTTPS")
    credential = enforcement_service.get("credential", {}) if isinstance(enforcement_service, dict) else {}
    if not isinstance(credential, dict) or not credential.get("ref") or credential.get("redacted") is not True:
        errors.append("trust authority KMS enforcement credential reference must be redacted")
    if mode == "provider-enforced" and not enforcement_service.get("actor_ref"):
        errors.append("provider-enforced trust authority KMS enforcement requires actor_ref")

    key_custody = receipt.get("key_custody", {})
    if not isinstance(key_custody, dict):
        errors.append("trust authority KMS enforcement key_custody must be an object")
        key_custody = {}
    source_kms = source.get("kms", {}) if isinstance(source, dict) else {}
    if key_custody.get("key_ref") != source_kms.get("key_ref"):
        errors.append("trust authority KMS enforcement key_ref does not match provider attestation KMS source")
    if mode != "local-reference" and key_custody.get("status") != "active":
        errors.append("trust authority KMS enforcement key status must be active")
    if mode in {"hsm-attested", "provider-enforced"}:
        if not key_custody.get("hsm_attestation_ref") or not key_custody.get("hsm_attestation_hash"):
            errors.append("hsm-attested and provider-enforced trust authority KMS enforcement require HSM attestation ref and hash")
        if not _is_hash_ref(str(key_custody.get("hsm_attestation_hash") or "")):
            errors.append("trust authority KMS HSM attestation hash must be a sha256 reference")

    timestamp_authority = receipt.get("timestamp_authority", {})
    if not isinstance(timestamp_authority, dict):
        errors.append("trust authority KMS enforcement timestamp_authority must be an object")
        timestamp_authority = {}
    source_tsa = source.get("timestamp_authority", {}) if isinstance(source, dict) else {}
    for field in ("provider", "endpoint", "certificate_chain_hash"):
        if timestamp_authority.get(field) != source_tsa.get(field):
            errors.append(f"trust authority KMS timestamp_authority.{field} does not match provider attestation source")
    if not _is_hash_ref(str(timestamp_authority.get("certificate_chain_hash") or "")):
        errors.append("trust authority KMS timestamp_authority.certificate_chain_hash must be a sha256 reference")
    if mode in {"policy-bound", "hsm-attested", "provider-enforced"}:
        if not timestamp_authority.get("timestamp_policy_ref") or not timestamp_authority.get("timestamp_policy_hash"):
            errors.append("trust authority KMS enforcement requires timestamp policy ref and hash")
        if not _is_hash_ref(str(timestamp_authority.get("timestamp_policy_hash") or "")):
            errors.append("trust authority KMS timestamp policy hash must be a sha256 reference")
        if source_tsa.get("timestamp_policy_hash") and timestamp_authority.get("timestamp_policy_hash") != source_tsa.get("timestamp_policy_hash"):
            errors.append("trust authority KMS timestamp policy hash does not match provider attestation source")

    key_policy = receipt.get("key_policy", {})
    if not isinstance(key_policy, dict):
        errors.append("trust authority KMS enforcement key_policy must be an object")
        key_policy = {}
    if mode in {"policy-bound", "hsm-attested", "provider-enforced"}:
        if not key_policy.get("policy_ref") or not key_policy.get("policy_hash"):
            errors.append("policy-bound trust authority KMS enforcement requires key policy ref and hash")
        if not _is_hash_ref(str(key_policy.get("policy_hash") or "")):
            errors.append("trust authority KMS key policy hash must be a sha256 reference")
        if source_kms.get("key_policy_hash") and key_policy.get("policy_hash") != source_kms.get("key_policy_hash"):
            errors.append("trust authority KMS key policy hash does not match provider attestation source")
        key_usage = key_policy.get("key_usage")
        if not isinstance(key_usage, list) or "sign" not in key_usage or "timestamp" not in key_usage:
            errors.append("trust authority KMS key policy must allow signing and timestamp usage")
        allowed_actors = key_policy.get("allowed_actor_refs")
        if not isinstance(allowed_actors, list) or not allowed_actors:
            errors.append("trust authority KMS key policy requires allowed_actor_refs")
        actor_ref = enforcement_service.get("actor_ref")
        if actor_ref and actor_ref not in allowed_actors:
            errors.append("trust authority KMS actor_ref must be allowed by key policy")
        quorum_required = key_policy.get("quorum_required")
        approvers = key_policy.get("quorum_approver_refs")
        if not isinstance(quorum_required, int) or not isinstance(approvers, list) or len(approvers) < quorum_required:
            errors.append("trust authority KMS approvers must satisfy quorum_required")
        if key_policy.get("quorum_met") is not True:
            errors.append("trust authority KMS quorum_met must be true")
    audit_log = receipt.get("audit_log", {})
    if not isinstance(audit_log, dict):
        errors.append("trust authority KMS enforcement audit_log must be an object")
        audit_log = {}
    source_audit = source.get("audit_log", {}) if isinstance(source, dict) else {}
    if mode in {"hsm-attested", "provider-enforced"}:
        if not audit_log.get("audit_log_ref") or not audit_log.get("root"):
            errors.append("hsm-attested and provider-enforced trust authority KMS enforcement require audit_log_ref and root")
        if audit_log.get("audit_log_ref") != source_audit.get("audit_log_ref"):
            errors.append("trust authority KMS enforcement audit_log_ref does not match provider attestation source")
        if audit_log.get("root") != source_audit.get("root"):
            errors.append("trust authority KMS enforcement audit log root does not match provider attestation source")
        if not isinstance(audit_log.get("size"), int) or audit_log.get("size") < 1:
            errors.append("trust authority KMS enforcement requires positive audit log size")

    response = receipt.get("response")
    if mode == "provider-enforced":
        if not isinstance(response, dict) or response.get("status") is None or not response.get("body_hash"):
            errors.append("provider-enforced trust authority KMS enforcement must include provider response status and body_hash")
        elif not response.get("accepted"):
            errors.append("provider-enforced trust authority KMS enforcement requires an accepted provider response")
    elif response is not None and not isinstance(response, dict):
        errors.append("trust authority KMS enforcement response must be an object when supplied")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        errors.append("trust authority KMS enforcement must include exactly one provider attestation source artifact")
        artifacts = []
    provider_artifact = _artifact_by_name(artifacts, "trust_authority_provider_attestation")
    if provider_artifact is None:
        errors.append("trust authority KMS enforcement missing provider attestation source artifact")

    if provider_attestation is None:
        warnings.append("trust authority provider attestation source not supplied; verified KMS enforcement binding only")
    else:
        source_result = verify_trust_authority_provider_attestation(
            provider_attestation,
            trust_authority_receipt,
            source_chain,
            keyring,
            proof_pack=proof_pack,
            key=key,
        )
        if not source_result.ok:
            errors.extend(f"source trust authority provider attestation invalid: {error}" for error in source_result.errors)
        warnings.extend(f"source trust authority provider warning: {warning}" for warning in source_result.warnings)
        _compare_artifact(provider_artifact, _provider_attestation_artifact(provider_attestation), errors)
        if source != _provider_attestation_record(provider_attestation):
            errors.append("trust authority KMS enforcement source record does not match provider attestation")
        if mode != "local-reference" and provider_attestation.get("mode") != "provider-attested":
            errors.append("KMS enforcement requires a provider-attested trust authority provider source")

    expected_payload_hash = content_hash({"source": source, "enforcement": enforcement, "enforcement_service": enforcement_service, "key_custody": key_custody, "timestamp_authority": timestamp_authority, "key_policy": key_policy, "audit_log": audit_log, "source_artifacts": artifacts})
    if receipt.get("enforcement_payload_hash") != expected_payload_hash:
        errors.append("trust authority KMS enforcement payload hash does not match records")

    return TrustAuthorityKmsEnforcementVerification(ok=not errors, errors=errors, warnings=warnings, enforcement_id=receipt.get("enforcement_id") if isinstance(receipt.get("enforcement_id"), str) else None, mode=mode if isinstance(mode, str) else None)


def append_trust_authority_kms_enforcement_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    provider_attestation: dict[str, Any] | None = None,
    trust_authority_receipt: dict[str, Any] | None = None,
    source_chain: Any | None = None,
    keyring: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_trust_authority_kms_enforcement_receipt(receipt, provider_attestation=provider_attestation, trust_authority_receipt=trust_authority_receipt, source_chain=source_chain, keyring=keyring, proof_pack=proof_pack, key=key)
    if not result.ok:
        raise ValueError("invalid trust authority KMS enforcement receipt: " + "; ".join(result.errors))
    payload = {
        "enforcement_id": receipt["enforcement_id"],
        "enforcement_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "source": receipt.get("source"),
        "enforcement": receipt.get("enforcement"),
        "enforcement_service": receipt.get("enforcement_service"),
        "key_custody": receipt.get("key_custody"),
        "timestamp_authority": receipt.get("timestamp_authority"),
        "key_policy": receipt.get("key_policy"),
        "audit_log": receipt.get("audit_log"),
        "response": receipt.get("response"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(TRUST_AUTHORITY_KMS_ENFORCEMENT_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("enforced_at"))


def load_trust_authority_kms_enforcement_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("trust authority KMS enforcement receipt must contain an object")
    return value


def write_trust_authority_kms_enforcement_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")

def _provider_attestation_record(attestation: dict[str, Any]) -> dict[str, Any]:
    source = attestation.get("source", {})
    kms = attestation.get("kms", {})
    tsa = attestation.get("timestamp_authority", {})
    operation = attestation.get("operation", {})
    audit = attestation.get("audit_log", {})
    return {
        "attestation_id": attestation.get("attestation_id"),
        "content_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "trust_authority_receipt_id": source.get("trust_authority_receipt_id") if isinstance(source, dict) else None,
        "source_chain_root": source.get("source_chain_root") if isinstance(source, dict) else None,
        "keyring_hash": source.get("keyring_hash") if isinstance(source, dict) else None,
        "kms": {
            "provider": kms.get("provider") if isinstance(kms, dict) else None,
            "endpoint": kms.get("endpoint") if isinstance(kms, dict) else None,
            "key_ref": kms.get("key_ref") if isinstance(kms, dict) else None,
            "key_algorithm": kms.get("key_algorithm") if isinstance(kms, dict) else None,
            "request_hash": kms.get("request_hash") if isinstance(kms, dict) else None,
            "response_status": kms.get("response_status") if isinstance(kms, dict) else None,
            "response_hash": kms.get("response_hash") if isinstance(kms, dict) else None,
            "key_policy_ref": kms.get("key_policy_ref") if isinstance(kms, dict) else None,
            "key_policy_hash": kms.get("key_policy_hash") if isinstance(kms, dict) else None,
        },
        "timestamp_authority": {
            "provider": tsa.get("provider") if isinstance(tsa, dict) else None,
            "endpoint": tsa.get("endpoint") if isinstance(tsa, dict) else None,
            "request_hash": tsa.get("request_hash") if isinstance(tsa, dict) else None,
            "response_status": tsa.get("response_status") if isinstance(tsa, dict) else None,
            "response_hash": tsa.get("response_hash") if isinstance(tsa, dict) else None,
            "certificate_chain_hash": tsa.get("certificate_chain_hash") if isinstance(tsa, dict) else None,
            "timestamp_policy_ref": tsa.get("timestamp_policy_ref") if isinstance(tsa, dict) else None,
            "timestamp_policy_hash": tsa.get("timestamp_policy_hash") if isinstance(tsa, dict) else None,
        },
        "operation_actor_ref": operation.get("actor_ref") if isinstance(operation, dict) else None,
        "audit_log": {
            "audit_log_ref": audit.get("audit_log_ref") if isinstance(audit, dict) else None,
            "root": audit.get("root") if isinstance(audit, dict) else None,
            "retention_until": audit.get("retention_until") if isinstance(audit, dict) else None,
        },
    }


def _provider_attestation_artifact(attestation: dict[str, Any]) -> dict[str, Any]:
    return {"name": "trust_authority_provider_attestation", "artifact_type": "trustai.trust-authority-provider-attestation", "content_hash": content_hash(attestation), "attestation_id": attestation.get("attestation_id"), "mode": attestation.get("mode")}


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {"name": artifact.get("name"), "artifact_type": artifact.get("artifact_type"), "content_hash": artifact.get("content_hash"), "attestation_id": artifact.get("attestation_id")}


def _artifact_by_name(artifacts: list[Any], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"trust authority KMS enforcement missing source artifact: {expected['name']}")
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


def _controls_for(mode: str, has_hsm_attestation: bool, has_key_policy: bool, has_timestamp_policy: bool, quorum_met: bool, has_audit_log: bool, has_response: bool) -> list[dict[str, str]]:
    return [
        {"id": "provider-attestation-binding", "status": "implemented-reference", "description": "KMS enforcement receipt binds to a verified trust-authority provider attestation by canonical hash."},
        {"id": "customer-controlled-key-custody", "status": "attested-reference" if has_hsm_attestation else "planned-production", "description": "Receipt records customer-controlled HSM/KMS attestation reference and attestation hash."},
        {"id": "key-policy-enforcement", "status": "policy-bound" if has_key_policy else "planned-production", "description": "Receipt records key policy hash, allowed actors, usage scope, denied operations, and quorum controls."},
        {"id": "timestamp-policy-enforcement", "status": "policy-bound" if has_timestamp_policy else "planned-production", "description": "Receipt records timestamp policy hash and binds it to the source timestamp-authority evidence."},
        {"id": "dual-control-quorum", "status": "implemented-reference" if quorum_met else "planned-production", "description": "Receipt verifies that recorded approvers satisfy the required signing/timestamping quorum."},
        {"id": "immutable-provider-audit-log", "status": "implemented-reference" if has_audit_log else "planned-production", "description": "Receipt binds the enforcement record to the provider attestation audit-log root and retention deadline."},
        {"id": "provider-enforcement-response", "status": "recorded-response" if has_response else ("not-applicable" if mode != "provider-enforced" else "planned-production"), "description": "Provider-enforced mode preserves the KMS/HSM enforcement provider response hash."},
    ]


def _validate_times(source_attested_at: str, enforced_at: str) -> None:
    source_time = parse_rfc3339(source_attested_at)
    enforcement_time = parse_rfc3339(enforced_at)
    if enforcement_time < source_time:
        raise ValueError("trust authority KMS enforcement enforced_at must be at or after provider attestation time")


def _valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def _is_https(value: str | None) -> bool:
    return bool(value and _valid_url(value) and urlparse(value).scheme.lower() == "https")


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value.removeprefix("sha256:"))
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")