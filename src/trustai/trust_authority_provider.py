from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import CHAIN_SPEC_VERSION, EvidenceChain
from .crypto import sign_value, verify_value
from .keyring import validate_keyring
from .trust_authority import verify_trust_authority_receipt

TRUST_AUTHORITY_PROVIDER_SCHEMA = "trustai.trust-authority-provider-attestation/0.1"
TRUST_AUTHORITY_PROVIDER_ENTRY_TYPE = "trust_authority.provider_attested"

TRUST_AUTHORITY_PROVIDER_MODES = {"local-reference", "provider-attested", "production-design"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class TrustAuthorityProviderVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_trust_authority_provider_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("trust authority provider attestation must contain an object")
    return value


def write_trust_authority_provider_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_trust_authority_provider_attestation(
    trust_authority_receipt: dict[str, Any],
    source_chain: EvidenceChain,
    keyring: dict[str, Any],
    *,
    proof_pack: dict[str, Any] | None = None,
    mode: str = "provider-attested",
    environment: str = "local",
    kms_provider: str,
    kms_endpoint: str,
    kms_key_ref: str,
    kms_key_algorithm: str = "HMAC-SHA256",
    kms_request_hash: str,
    kms_response_status: int,
    kms_response_hash: str,
    tsa_provider: str,
    tsa_endpoint: str,
    tsa_request_hash: str,
    tsa_response_status: int,
    tsa_response_hash: str,
    tsa_certificate_chain_hash: str,
    actor_ref: str,
    credential_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    key_policy_ref: str | None = None,
    key_policy_hash: str | None = None,
    timestamp_policy_ref: str | None = None,
    timestamp_policy_hash: str | None = None,
    kms_request_path: str | Path | None = None,
    kms_response_path: str | Path | None = None,
    tsa_request_path: str | Path | None = None,
    tsa_response_path: str | Path | None = None,
    tsa_certificate_chain_path: str | Path | None = None,
    evidence_refs: list[str] | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in TRUST_AUTHORITY_PROVIDER_MODES:
        raise ValueError(f"mode must be one of {sorted(TRUST_AUTHORITY_PROVIDER_MODES)}")
    _require_text(kms_provider, "kms_provider")
    _require_text(kms_endpoint, "kms_endpoint")
    _require_text(kms_key_ref, "kms_key_ref")
    _require_text(kms_request_hash, "kms_request_hash")
    _require_text(kms_response_hash, "kms_response_hash")
    _require_text(tsa_provider, "tsa_provider")
    _require_text(tsa_endpoint, "tsa_endpoint")
    _require_text(tsa_request_hash, "tsa_request_hash")
    _require_text(tsa_response_hash, "tsa_response_hash")
    _require_text(tsa_certificate_chain_hash, "tsa_certificate_chain_hash")
    _require_text(actor_ref, "actor_ref")
    _require_text(credential_ref, "credential_ref")
    _require_text(audit_log_ref, "audit_log_ref")
    _require_text(audit_log_root, "audit_log_root")
    _require_text(retention_until, "retention_until")
    if not isinstance(kms_response_status, int) or not isinstance(tsa_response_status, int):
        raise ValueError("response statuses must be integers")
    validate_keyring(keyring)
    source_result = verify_trust_authority_receipt(
        trust_authority_receipt,
        chain=source_chain,
        keyring=keyring,
        proof_pack=proof_pack,
        key=key,
    )
    if not source_result.ok:
        raise ValueError("invalid trust authority receipt: " + "; ".join(source_result.errors))
    timestamp = attested_at or utc_now()
    parse_rfc3339(timestamp)
    retention = parse_rfc3339(retention_until)
    if retention <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after attested_at")

    source = _trust_authority_source_record(trust_authority_receipt)
    kms = {
        "provider": kms_provider,
        "endpoint": kms_endpoint,
        "key_ref": kms_key_ref,
        "key_algorithm": kms_key_algorithm,
        "request_hash": kms_request_hash,
        "response_status": kms_response_status,
        "response_hash": kms_response_hash,
        "accepted": 200 <= kms_response_status < 300,
        "key_policy_ref": key_policy_ref,
        "key_policy_hash": key_policy_hash,
    }
    tsa = {
        "provider": tsa_provider,
        "endpoint": tsa_endpoint,
        "request_hash": tsa_request_hash,
        "response_status": tsa_response_status,
        "response_hash": tsa_response_hash,
        "accepted": 200 <= tsa_response_status < 300,
        "certificate_chain_hash": tsa_certificate_chain_hash,
        "timestamp_policy_ref": timestamp_policy_ref,
        "timestamp_policy_hash": timestamp_policy_hash,
    }
    audit = {
        "audit_log_ref": audit_log_ref,
        "root": audit_log_root,
        "retention_until": retention_until,
    }
    operation = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    source_artifacts = _source_artifacts(
        trust_authority_receipt=trust_authority_receipt,
        source_chain=source_chain,
        keyring=keyring,
        proof_pack=proof_pack,
    )
    provider_artifacts = _provider_artifacts(
        kms_request_path=kms_request_path,
        kms_response_path=kms_response_path,
        tsa_request_path=tsa_request_path,
        tsa_response_path=tsa_response_path,
        tsa_certificate_chain_path=tsa_certificate_chain_path,
    )
    _validate_provider_artifacts(kms, tsa, provider_artifacts)
    body: dict[str, Any] = {
        "schema": TRUST_AUTHORITY_PROVIDER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": source,
        "kms": kms,
        "timestamp_authority": tsa,
        "operation": operation,
        "audit_log": audit,
        "source_artifacts": source_artifacts,
        "provider_artifacts": provider_artifacts,
        "controls": _controls(
            mode=mode,
            kms_endpoint=kms_endpoint,
            kms_request_hash=kms_request_hash,
            kms_response_hash=kms_response_hash,
            kms_response_status=kms_response_status,
            tsa_endpoint=tsa_endpoint,
            tsa_request_hash=tsa_request_hash,
            tsa_response_hash=tsa_response_hash,
            tsa_response_status=tsa_response_status,
            tsa_certificate_chain_hash=tsa_certificate_chain_hash,
            key_policy_hash=key_policy_hash,
            timestamp_policy_hash=timestamp_policy_hash,
            audit_log_root=audit_log_root,
            provider_artifact_count=len(provider_artifacts),
            credential_ref=credential_ref,
        ),
        "limitations": [
            "This attestation binds a verified TrustAI trust-authority receipt to recorded KMS/HSM and RFC 3161 TSA provider evidence.",
            "It records provider endpoints, request hashes, response hashes, certificate-chain hashes, audit-log roots, and redacted credential references.",
            "When provider artifact paths are supplied, it also binds retained KMS/TSA request, response, and certificate-chain bytes by hash and size.",
            "It does not contain raw provider credentials, private keys, timestamp response bytes, or signing response bodies.",
            "Production deployments should preserve provider-native request/response bodies in WORM storage when retention policy requires replay beyond hashes.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "trust_authority_provider": body}, key)],
    }


def verify_trust_authority_provider_attestation(
    attestation: dict[str, Any],
    trust_authority_receipt: dict[str, Any] | None = None,
    source_chain: EvidenceChain | None = None,
    keyring: dict[str, Any] | None = None,
    *,
    proof_pack: dict[str, Any] | None = None,
    kms_request_path: str | Path | None = None,
    kms_response_path: str | Path | None = None,
    tsa_request_path: str | Path | None = None,
    tsa_response_path: str | Path | None = None,
    tsa_certificate_chain_path: str | Path | None = None,
    key: str | None = None,
) -> TrustAuthorityProviderVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != TRUST_AUTHORITY_PROVIDER_SCHEMA:
        errors.append(f"unsupported trust authority provider attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical trust authority provider attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("trust authority provider attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "trust_authority_provider": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("trust authority provider attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"trust authority provider attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in TRUST_AUTHORITY_PROVIDER_MODES:
        errors.append("trust authority provider mode is unsupported")
    elif mode != "provider-attested":
        warnings.append(f"trust authority provider mode is {mode}; live KMS/TSA provider operation is not fully claimed")

    source = attestation.get("source", {})
    if not isinstance(source, dict):
        errors.append("trust authority provider source must be an object")
        source = {}
    for field in ("trust_authority_receipt_id", "trust_authority_receipt_hash", "source_chain_hash", "keyring_hash"):
        if not source.get(field):
            errors.append(f"trust authority provider source.{field} is required")

    kms = attestation.get("kms", {})
    if not isinstance(kms, dict):
        errors.append("trust authority provider kms must be an object")
        kms = {}
    _verify_endpoint_record(kms, "trust authority provider kms", errors)
    if not kms.get("key_ref"):
        errors.append("trust authority provider kms.key_ref is required")
    if not kms.get("key_algorithm"):
        errors.append("trust authority provider kms.key_algorithm is required")
    if kms.get("key_policy_hash") and not _is_hash_ref(str(kms.get("key_policy_hash"))):
        errors.append("trust authority provider kms.key_policy_hash must be a sha256 reference")

    tsa = attestation.get("timestamp_authority", {})
    if not isinstance(tsa, dict):
        errors.append("trust authority provider timestamp_authority must be an object")
        tsa = {}
    _verify_endpoint_record(tsa, "trust authority provider timestamp_authority", errors)
    if not _is_hash_ref(str(tsa.get("certificate_chain_hash") or "")):
        errors.append("trust authority provider timestamp_authority.certificate_chain_hash must be a sha256 reference")
    if tsa.get("timestamp_policy_hash") and not _is_hash_ref(str(tsa.get("timestamp_policy_hash"))):
        errors.append("trust authority provider timestamp_authority.timestamp_policy_hash must be a sha256 reference")

    operation = attestation.get("operation", {})
    if not isinstance(operation, dict):
        errors.append("trust authority provider operation must be an object")
        operation = {}
    if not operation.get("actor_ref"):
        errors.append("trust authority provider operation.actor_ref is required")
    _verify_redacted_ref(operation.get("credential"), "trust authority provider operation.credential", errors)

    audit = attestation.get("audit_log", {})
    if not isinstance(audit, dict):
        errors.append("trust authority provider audit_log must be an object")
        audit = {}
    for field in ("audit_log_ref", "root", "retention_until"):
        if not audit.get(field):
            errors.append(f"trust authority provider audit_log.{field} is required")
    if not _is_hash_ref(str(audit.get("root") or "")):
        errors.append("trust authority provider audit_log.root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(audit.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("trust authority provider audit_log.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"trust authority provider audit_log.retention_until invalid: {exc}")

    source_artifacts = attestation.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("trust authority provider source_artifacts must contain at least one source")
        source_artifacts = []
    provider_artifacts = attestation.get("provider_artifacts", [])
    if not isinstance(provider_artifacts, list):
        errors.append("trust authority provider provider_artifacts must be a list")
        provider_artifacts = []
    _verify_provider_artifact_records(provider_artifacts, kms, tsa, errors)
    supplied_sources = _source_artifacts(
        trust_authority_receipt=trust_authority_receipt,
        source_chain=source_chain,
        keyring=keyring,
        proof_pack=proof_pack,
    )
    if supplied_sources:
        if source_artifacts != supplied_sources:
            errors.append("trust authority provider source_artifacts do not match supplied source artifacts")
        if trust_authority_receipt is not None:
            expected_source = _trust_authority_source_record(trust_authority_receipt)
            if source != expected_source:
                errors.append("trust authority provider source record does not match supplied trust authority receipt")
        if trust_authority_receipt is not None and source_chain is not None and keyring is not None:
            result = verify_trust_authority_receipt(
                trust_authority_receipt,
                chain=source_chain,
                keyring=keyring,
                proof_pack=proof_pack,
                key=key,
            )
            if not result.ok:
                errors.extend(f"trust authority provider source invalid: {error}" for error in result.errors)
            warnings.extend(f"trust authority provider source warning: {warning}" for warning in result.warnings)
    else:
        warnings.append("trust authority provider source artifacts were not supplied; source hashes were not replayed")

    try:
        supplied_provider_artifacts = _provider_artifacts(
            kms_request_path=kms_request_path,
            kms_response_path=kms_response_path,
            tsa_request_path=tsa_request_path,
            tsa_response_path=tsa_response_path,
            tsa_certificate_chain_path=tsa_certificate_chain_path,
        )
    except OSError as exc:
        errors.append(f"trust authority provider artifact source could not be read: {exc}")
        supplied_provider_artifacts = []
    if supplied_provider_artifacts:
        if provider_artifacts != supplied_provider_artifacts:
            errors.append("trust authority provider provider_artifacts do not match supplied provider artifacts")
        _verify_provider_artifact_records(supplied_provider_artifacts, kms, tsa, errors)
    elif not provider_artifacts:
        warnings.append("trust authority provider KMS/TSA artifact paths were not supplied; provider request/response hashes were not replayed")

    controls = attestation.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("trust authority provider controls are required")
    _check_no_secret_values(attestation, errors)

    return TrustAuthorityProviderVerification(ok=not errors, errors=errors, warnings=warnings)


def append_trust_authority_provider_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    trust_authority_receipt: dict[str, Any] | None = None,
    source_chain: EvidenceChain | None = None,
    keyring: dict[str, Any] | None = None,
    *,
    proof_pack: dict[str, Any] | None = None,
    kms_request_path: str | Path | None = None,
    kms_response_path: str | Path | None = None,
    tsa_request_path: str | Path | None = None,
    tsa_response_path: str | Path | None = None,
    tsa_certificate_chain_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_trust_authority_provider_attestation(
        attestation,
        trust_authority_receipt,
        source_chain,
        keyring,
        proof_pack=proof_pack,
        kms_request_path=kms_request_path,
        kms_response_path=kms_response_path,
        tsa_request_path=tsa_request_path,
        tsa_response_path=tsa_response_path,
        tsa_certificate_chain_path=tsa_certificate_chain_path,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid trust authority provider attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "source": attestation.get("source"),
        "kms": attestation.get("kms"),
        "timestamp_authority": attestation.get("timestamp_authority"),
        "operation": attestation.get("operation"),
        "audit_log": attestation.get("audit_log"),
        "source_artifacts": attestation.get("source_artifacts"),
        "provider_artifacts": attestation.get("provider_artifacts", []),
        "control_summary": _status_summary(attestation.get("controls", [])),
    }
    return chain.append(TRUST_AUTHORITY_PROVIDER_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _trust_authority_source_record(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "trust_authority_receipt_id": receipt.get("receipt_id"),
        "trust_authority_receipt_hash": content_hash(receipt),
        "source_chain_hash": receipt.get("chain", {}).get("content_hash") if isinstance(receipt.get("chain"), dict) else None,
        "source_chain_root": receipt.get("chain", {}).get("tree", {}).get("root") if isinstance(receipt.get("chain"), dict) else None,
        "keyring_hash": receipt.get("keyring", {}).get("content_hash") if isinstance(receipt.get("keyring"), dict) else None,
        "proof_pack_hash": receipt.get("proof_pack", {}).get("content_hash") if isinstance(receipt.get("proof_pack"), dict) else None,
        "providers": receipt.get("providers"),
    }


def _source_artifacts(
    *,
    trust_authority_receipt: dict[str, Any] | None,
    source_chain: EvidenceChain | None,
    keyring: dict[str, Any] | None,
    proof_pack: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if trust_authority_receipt is not None:
        records.append(
            {
                "source_type": "trust_authority_receipt",
                "source_id": trust_authority_receipt.get("receipt_id"),
                "source_hash": content_hash(trust_authority_receipt),
            }
        )
    if source_chain is not None:
        records.append(
            {
                "source_type": "evidence_chain",
                "source_id": source_chain.tenant_id,
                "source_hash": content_hash(_chain_document(source_chain)),
                "tree_root": source_chain.tree().get("root"),
                "entry_count": len(source_chain.entries),
            }
        )
    if keyring is not None:
        records.append(
            {
                "source_type": "keyring",
                "source_id": keyring.get("tenant_id"),
                "source_hash": content_hash(keyring),
                "key_count": len(keyring.get("keys", [])) if isinstance(keyring.get("keys"), list) else 0,
            }
        )
    if proof_pack is not None:
        records.append(
            {
                "source_type": "proof_pack",
                "source_id": proof_pack.get("pack_id"),
                "source_hash": content_hash(proof_pack),
            }
        )
    return records


def _provider_artifacts(
    *,
    kms_request_path: str | Path | None = None,
    kms_response_path: str | Path | None = None,
    tsa_request_path: str | Path | None = None,
    tsa_response_path: str | Path | None = None,
    tsa_certificate_chain_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for artifact_type, path in (
        ("kms_request", kms_request_path),
        ("kms_response", kms_response_path),
        ("tsa_request", tsa_request_path),
        ("tsa_response", tsa_response_path),
        ("tsa_certificate_chain", tsa_certificate_chain_path),
    ):
        if path is None:
            continue
        source = Path(path)
        data = source.read_bytes()
        records.append(
            {
                "artifact_type": artifact_type,
                "path": str(path).replace("\\", "/"),
                "hash": _sha256_ref(data),
                "size_bytes": len(data),
                "media_type": _artifact_media_type(source),
            }
        )
    return records


def _validate_provider_artifacts(kms: dict[str, Any], tsa: dict[str, Any], records: list[dict[str, Any]]) -> None:
    errors: list[str] = []
    _verify_provider_artifact_records(records, kms, tsa, errors)
    if errors:
        raise ValueError("invalid trust authority provider artifacts: " + "; ".join(errors))


def _verify_provider_artifact_records(records: list[Any], kms: dict[str, Any], tsa: dict[str, Any], errors: list[str]) -> None:
    expected_hashes = {
        "kms_request": kms.get("request_hash"),
        "kms_response": kms.get("response_hash"),
        "tsa_request": tsa.get("request_hash"),
        "tsa_response": tsa.get("response_hash"),
        "tsa_certificate_chain": tsa.get("certificate_chain_hash"),
    }
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            errors.append("trust authority provider provider_artifacts entries must be objects")
            continue
        artifact_type = str(record.get("artifact_type") or "")
        if artifact_type not in expected_hashes:
            errors.append(f"trust authority provider provider_artifacts artifact_type unsupported: {artifact_type}")
            continue
        if artifact_type in seen:
            errors.append(f"trust authority provider provider_artifacts duplicate artifact_type: {artifact_type}")
        seen.add(artifact_type)
        for field in ("path", "hash", "size_bytes"):
            if record.get(field) in (None, ""):
                errors.append(f"trust authority provider provider_artifacts {artifact_type}.{field} is required")
        if not isinstance(record.get("size_bytes"), int) or record.get("size_bytes") < 0:
            errors.append(f"trust authority provider provider_artifacts {artifact_type}.size_bytes must be a non-negative integer")
        artifact_hash = str(record.get("hash") or "")
        if not _is_hash_ref(artifact_hash):
            errors.append(f"trust authority provider provider_artifacts {artifact_type}.hash must be a sha256 reference")
        expected_hash = str(expected_hashes.get(artifact_type) or "")
        if expected_hash and _normalize_hash_ref(expected_hash) != _normalize_hash_ref(artifact_hash):
            errors.append(f"trust authority provider {artifact_type} artifact hash does not match recorded provider hash")


def _artifact_media_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix in {".pem", ".crt", ".cer"}:
        return "application/pem-certificate-chain"
    if suffix in {".tsr", ".der"}:
        return "application/octet-stream"
    return "application/octet-stream"


def _sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _normalize_hash_ref(value: str) -> str:
    if value.startswith("sha256:"):
        return value
    return "sha256:" + value


def _chain_document(chain: EvidenceChain) -> dict[str, Any]:
    return {
        "spec_version": CHAIN_SPEC_VERSION,
        "tenant_id": chain.tenant_id,
        "tree": chain.tree(),
        "entries": chain.entries,
    }


def _verify_endpoint_record(record: dict[str, Any], label: str, errors: list[str]) -> None:
    for field in ("provider", "endpoint", "request_hash", "response_hash"):
        if not record.get(field):
            errors.append(f"{label}.{field} is required")
    endpoint = str(record.get("endpoint") or "")
    if not _valid_url(endpoint):
        errors.append(f"{label}.endpoint must be an absolute URL")
    elif not _is_https(endpoint):
        errors.append(f"{label}.endpoint must use HTTPS")
    for field in ("request_hash", "response_hash"):
        if not _is_hash_ref(str(record.get(field) or "")):
            errors.append(f"{label}.{field} must be a sha256 reference")
    status = record.get("response_status")
    if not isinstance(status, int) or status < 100 or status > 599:
        errors.append(f"{label}.response_status must be an HTTP status code")
    elif record.get("accepted") is not (200 <= status < 300):
        errors.append(f"{label}.accepted must match response_status")


def _controls(
    *,
    mode: str,
    kms_endpoint: str,
    kms_request_hash: str,
    kms_response_hash: str,
    kms_response_status: int,
    tsa_endpoint: str,
    tsa_request_hash: str,
    tsa_response_hash: str,
    tsa_response_status: int,
    tsa_certificate_chain_hash: str,
    key_policy_hash: str | None,
    timestamp_policy_hash: str | None,
    audit_log_root: str,
    provider_artifact_count: int,
    credential_ref: str,
) -> list[dict[str, Any]]:
    return [
        {
            "id": "kms-provider-operation",
            "status": "implemented"
            if mode == "provider-attested" and _is_https(kms_endpoint) and _is_hash_ref(kms_request_hash) and _is_hash_ref(kms_response_hash) and 200 <= kms_response_status < 300
            else "planned-production",
            "description": "KMS/HSM signing operation endpoint, request hash, response status, and response hash are recorded.",
        },
        {
            "id": "independent-tsa-operation",
            "status": "implemented"
            if mode == "provider-attested" and _is_https(tsa_endpoint) and _is_hash_ref(tsa_request_hash) and _is_hash_ref(tsa_response_hash) and 200 <= tsa_response_status < 300
            else "planned-production",
            "description": "RFC 3161 TSA endpoint, request hash, response status, and response hash are recorded.",
        },
        {
            "id": "tsa-certificate-chain",
            "status": "implemented" if _is_hash_ref(tsa_certificate_chain_hash) else "planned-production",
            "description": "Timestamp-authority certificate-chain hash is bound into the attestation.",
        },
        {
            "id": "provider-key-policy",
            "status": "implemented" if key_policy_hash and _is_hash_ref(key_policy_hash) else "planned-production",
            "description": "KMS/HSM key policy hash is bound when supplied.",
        },
        {
            "id": "timestamp-policy",
            "status": "implemented" if timestamp_policy_hash and _is_hash_ref(timestamp_policy_hash) else "planned-production",
            "description": "Timestamp policy hash is bound when supplied.",
        },
        {
            "id": "immutable-provider-audit-log",
            "status": "implemented" if _is_hash_ref(audit_log_root) else "planned-production",
            "description": "Provider audit-log root and retention deadline are recorded.",
        },
        {
            "id": "provider-artifact-replay",
            "status": "implemented" if provider_artifact_count >= 5 else "local-reference" if provider_artifact_count else "planned-production",
            "description": "KMS/TSA request, response, and certificate-chain artifacts are replay-bound when supplied.",
        },
        {
            "id": "redacted-provider-credential",
            "status": "implemented" if credential_ref else "planned-production",
            "description": "KMS/TSA provider credentials are represented only by redacted references.",
        },
    ]


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def _is_https(value: str | None) -> bool:
    return bool(value and urlparse(value).scheme.lower() == "https")


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value.removeprefix("sha256:"))
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _require_text(value: str | None, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _check_no_secret_values(value: Any, errors: list[str], *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _exempt_trust_authority_evidence_path(child_path):
                    pass
                elif _allowed_secret_reference_key(normalized, item):
                    pass
                elif not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"trust authority provider secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        return True
    return False


def _exempt_trust_authority_evidence_path(path: str) -> bool:
    return path in {
        "source.providers.timestamp_tokens",
        "source.providers.timestamp_token_signatures",
    }