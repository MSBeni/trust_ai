from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .provider_audit_worker import verify_provider_audit_worker_receipt
from .provider_installation import verify_provider_installation_manifest
from .provider_lifecycle import verify_provider_lifecycle_manifest
from .provider_lifecycle_operation import verify_provider_lifecycle_operation_receipt

PROVIDER_CREDENTIAL_CUSTODY_SCHEMA = "trustai.provider-credential-custody/0.1"
PROVIDER_CREDENTIAL_CUSTODY_ENTRY_TYPE = "provider_credential.custody_recorded"

CUSTODY_MODES = {"local-reference", "vault-policy", "kms-attested", "provider-managed-vault", "production-design"}
CREDENTIAL_KINDS = {
    "app_private_key",
    "webhook_secret",
    "oauth_client_secret",
    "access_token",
    "refresh_token",
    "audit_log_token",
    "provider_api_token",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ProviderCredentialCustodyVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_provider_credential_custody_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider credential custody receipt must contain an object")
    return value


def write_provider_credential_custody_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_provider_credential_custody_receipt(
    *,
    credential_ref: str,
    credential_kind: str,
    custody_ref: str,
    vault_ref: str,
    kms_provider: str,
    kms_endpoint: str,
    key_ref: str,
    key_algorithm: str,
    policy_ref: str,
    policy_hash: str,
    rotation_ref: str,
    revocation_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    actor_ref: str,
    allowed_actor_refs: list[str],
    denied_operation_refs: list[str] | None = None,
    quorum_required: int = 1,
    quorum_approver_refs: list[str] | None = None,
    provider_installation: dict[str, Any] | None = None,
    lifecycle_manifest: dict[str, Any] | None = None,
    lifecycle_operation: dict[str, Any] | None = None,
    audit_worker: dict[str, Any] | None = None,
    attestation_ref: str | None = None,
    attestation_hash: str | None = None,
    access_grant_ref: str | None = None,
    evidence_refs: list[str] | None = None,
    response_status: int | None = None,
    response_hash: str | None = None,
    mode: str = "vault-policy",
    environment: str = "local",
    issued_at: str | None = None,
    expires_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in CUSTODY_MODES:
        raise ValueError("mode must be local-reference, vault-policy, kms-attested, provider-managed-vault, or production-design")
    if credential_kind not in CREDENTIAL_KINDS:
        raise ValueError("credential_kind is unsupported")
    for value, field in (
        (credential_ref, "credential_ref"),
        (custody_ref, "custody_ref"),
        (vault_ref, "vault_ref"),
        (kms_provider, "kms_provider"),
        (kms_endpoint, "kms_endpoint"),
        (key_ref, "key_ref"),
        (key_algorithm, "key_algorithm"),
        (policy_ref, "policy_ref"),
        (policy_hash, "policy_hash"),
        (rotation_ref, "rotation_ref"),
        (revocation_ref, "revocation_ref"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (retention_until, "retention_until"),
        (actor_ref, "actor_ref"),
    ):
        _require_text(value, field)
    if not allowed_actor_refs:
        raise ValueError("allowed_actor_refs must contain at least one actor")
    if actor_ref not in allowed_actor_refs:
        raise ValueError("actor_ref must be included in allowed_actor_refs")
    if quorum_required < 1:
        raise ValueError("quorum_required must be at least 1")
    approvers = sorted(set(quorum_approver_refs or []))
    if len(approvers) < quorum_required:
        raise ValueError("quorum_approver_refs must satisfy quorum_required")
    issued = issued_at or utc_now()
    parse_rfc3339(issued)
    retention = parse_rfc3339(retention_until)
    if retention <= parse_rfc3339(issued):
        raise ValueError("retention_until must be after issued_at")
    if expires_at and parse_rfc3339(expires_at) <= parse_rfc3339(issued):
        raise ValueError("expires_at must be after issued_at")
    if mode in {"kms-attested", "provider-managed-vault"}:
        _require_text(attestation_ref, "attestation_ref")
        _require_text(attestation_hash, "attestation_hash")
        if response_status is None:
            raise ValueError(f"{mode} mode requires response_status")
        if response_hash is None:
            raise ValueError(f"{mode} mode requires response_hash")

    source_records = _source_records(
        provider_installation=provider_installation,
        lifecycle_manifest=lifecycle_manifest,
        lifecycle_operation=lifecycle_operation,
        audit_worker=audit_worker,
    )
    if not source_records:
        raise ValueError("at least one provider credential source artifact is required")
    provider = _derive_provider(source_records)
    source_credential_refs = sorted({ref for source in source_records for ref in source.get("credential_refs", [])})
    if credential_ref not in source_credential_refs:
        raise ValueError("credential_ref must be present in at least one source artifact credential reference")

    credential = {"ref": credential_ref, "kind": credential_kind, "redacted": True}
    custody = {
        "custody_ref": custody_ref,
        "mode": mode,
        "environment": environment,
        "issued_at": issued,
        "expires_at": expires_at,
        "retention_until": retention_until,
        "access_grant_ref": access_grant_ref,
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    vault = {
        "vault_ref": vault_ref,
        "provider": kms_provider,
        "endpoint": kms_endpoint,
        "key_ref": key_ref,
        "key_algorithm": key_algorithm,
        "attestation_ref": attestation_ref,
        "attestation_hash": attestation_hash,
        "rotation_ref": rotation_ref,
        "revocation_ref": revocation_ref,
    }
    policy = {
        "policy_ref": policy_ref,
        "policy_hash": policy_hash,
        "allowed_actor_refs": sorted(set(allowed_actor_refs)),
        "actor_ref": actor_ref,
        "denied_operation_refs": sorted(set(denied_operation_refs or [])),
        "quorum_required": quorum_required,
        "quorum_approver_refs": approvers,
        "quorum_met": len(approvers) >= quorum_required,
    }
    audit_log = {
        "audit_log_ref": audit_log_ref,
        "root": audit_log_root,
        "retention_until": retention_until,
    }
    body: dict[str, Any] = {
        "schema": PROVIDER_CREDENTIAL_CUSTODY_SCHEMA,
        "mode": mode,
        "environment": environment,
        "issued_at": issued,
        "provider": provider,
        "credential": credential,
        "custody": custody,
        "vault": vault,
        "policy": policy,
        "audit_log": audit_log,
        "source_artifacts": source_records,
        "source_credential_refs": source_credential_refs,
        "controls": _controls(
            mode=mode,
            credential_ref=credential_ref,
            vault_ref=vault_ref,
            kms_endpoint=kms_endpoint,
            policy_hash=policy_hash,
            attestation_ref=attestation_ref,
            rotation_ref=rotation_ref,
            revocation_ref=revocation_ref,
            audit_log_root=audit_log_root,
            quorum_met=policy["quorum_met"],
            response_status=response_status,
        ),
        "limitations": [
            "This receipt records provider credential custody evidence with redacted credential references, vault/KMS metadata, key policy, rotation, revocation, quorum, and audit-log root bindings.",
            "It does not reveal provider tokens, webhook secrets, private keys, client secrets, or raw vault response bodies.",
            "It does not prove production credential custody unless mode is kms-attested or provider-managed-vault and paired with provider exports, deployment, monitoring, and independent audit-log evidence.",
        ],
    }
    if response_status is not None:
        body["response"] = {
            "status": response_status,
            "response_hash": response_hash,
            "accepted": 200 <= response_status < 300,
        }
    custody_id = content_hash(body)
    return {
        **body,
        "custody_id": custody_id,
        "signatures": [sign_value({"custody_id": custody_id, "provider_credential_custody": body}, key)],
    }


def verify_provider_credential_custody_receipt(
    receipt: dict[str, Any],
    *,
    provider_installation: dict[str, Any] | None = None,
    lifecycle_manifest: dict[str, Any] | None = None,
    lifecycle_operation: dict[str, Any] | None = None,
    audit_worker: dict[str, Any] | None = None,
    provider_ingress_manifest: dict[str, Any] | None = None,
    callback_storage_manifest: dict[str, Any] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> ProviderCredentialCustodyVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != PROVIDER_CREDENTIAL_CUSTODY_SCHEMA:
        errors.append(f"unsupported provider credential custody schema: {receipt.get('schema')}")
    body = without_keys(receipt, "custody_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("custody_id") != expected_id:
        errors.append("custody_id does not match canonical provider credential custody body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider credential custody receipt must include at least one signature")
    else:
        signed_value = {"custody_id": receipt.get("custody_id"), "provider_credential_custody": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider credential custody signature verification failed")

    mode = receipt.get("mode")
    if mode not in CUSTODY_MODES:
        errors.append("provider credential custody mode is unsupported")
    elif mode not in {"kms-attested", "provider-managed-vault"}:
        warnings.append(f"provider credential custody mode is {mode}; production provider credential custody is not claimed")
    provider = _normalize_provider(receipt.get("provider"))
    if not provider:
        errors.append("provider credential custody provider is required")

    try:
        issued = parse_rfc3339(str(receipt.get("issued_at") or ""))
    except ValueError as exc:
        errors.append(f"provider credential custody issued_at invalid: {exc}")
        issued = None

    credential = receipt.get("credential", {})
    if not isinstance(credential, dict):
        errors.append("provider credential custody credential must be an object")
        credential = {}
    _verify_redacted_ref(credential, "provider credential custody credential", errors)
    if credential.get("kind") not in CREDENTIAL_KINDS:
        errors.append(f"provider credential custody credential kind unsupported: {credential.get('kind')}")
    credential_ref = str(credential.get("ref") or "")

    custody = receipt.get("custody", {})
    if not isinstance(custody, dict):
        errors.append("provider credential custody custody must be an object")
        custody = {}
    for field in ("custody_ref", "mode", "environment", "issued_at", "retention_until"):
        if not custody.get(field):
            errors.append(f"provider credential custody custody.{field} is required")
    if custody.get("mode") != mode:
        errors.append("provider credential custody custody.mode must match receipt mode")
    if custody.get("issued_at") != receipt.get("issued_at"):
        errors.append("provider credential custody custody.issued_at must match receipt issued_at")
    try:
        retention = parse_rfc3339(str(custody.get("retention_until") or ""))
        if issued and retention <= issued:
            errors.append("provider credential custody retention_until must be after issued_at")
    except ValueError as exc:
        errors.append(f"provider credential custody retention_until invalid: {exc}")
    expires_at = custody.get("expires_at")
    if expires_at:
        try:
            expires = parse_rfc3339(str(expires_at))
            if issued and expires <= issued:
                errors.append("provider credential custody expires_at must be after issued_at")
            if now and expires <= parse_rfc3339(now):
                errors.append("provider credential custody has expired")
        except ValueError as exc:
            errors.append(f"provider credential custody expires_at invalid: {exc}")

    vault = receipt.get("vault", {})
    if not isinstance(vault, dict):
        errors.append("provider credential custody vault must be an object")
        vault = {}
    for field in ("vault_ref", "provider", "endpoint", "key_ref", "key_algorithm", "rotation_ref", "revocation_ref"):
        if not vault.get(field):
            errors.append(f"provider credential custody vault.{field} is required")
    endpoint = str(vault.get("endpoint") or "")
    if not _valid_url(endpoint):
        errors.append("provider credential custody vault.endpoint must be an absolute URL")
    elif mode in {"kms-attested", "provider-managed-vault"} and not _is_https(endpoint):
        errors.append("provider credential custody vault.endpoint must use HTTPS in attested modes")
    if mode in {"kms-attested", "provider-managed-vault"}:
        if not vault.get("attestation_ref"):
            errors.append("provider credential custody vault.attestation_ref is required in attested modes")
        if not _is_hash_ref(str(vault.get("attestation_hash") or "")):
            errors.append("provider credential custody vault.attestation_hash must be a sha256 reference in attested modes")

    policy = receipt.get("policy", {})
    if not isinstance(policy, dict):
        errors.append("provider credential custody policy must be an object")
        policy = {}
    for field in ("policy_ref", "policy_hash", "allowed_actor_refs", "actor_ref", "quorum_required", "quorum_approver_refs"):
        if policy.get(field) in (None, ""):
            errors.append(f"provider credential custody policy.{field} is required")
    if not _is_hash_ref(str(policy.get("policy_hash") or "")):
        errors.append("provider credential custody policy.policy_hash must be a sha256 reference")
    allowed_actor_refs = policy.get("allowed_actor_refs", [])
    if not _is_string_list(allowed_actor_refs) or not allowed_actor_refs:
        errors.append("provider credential custody policy.allowed_actor_refs must be a non-empty string array")
    elif policy.get("actor_ref") not in allowed_actor_refs:
        errors.append("provider credential custody policy.actor_ref must be included in allowed_actor_refs")
    quorum_required = policy.get("quorum_required")
    approvers = policy.get("quorum_approver_refs", [])
    if not isinstance(quorum_required, int) or quorum_required < 1:
        errors.append("provider credential custody policy.quorum_required must be a positive integer")
    if not _is_string_list(approvers):
        errors.append("provider credential custody policy.quorum_approver_refs must be a string array")
    elif isinstance(quorum_required, int) and len(approvers) < quorum_required:
        errors.append("provider credential custody policy.quorum_approver_refs must satisfy quorum_required")
    if policy.get("quorum_met") is not True:
        errors.append("provider credential custody policy.quorum_met must be true")

    audit_log = receipt.get("audit_log", {})
    if not isinstance(audit_log, dict):
        errors.append("provider credential custody audit_log must be an object")
        audit_log = {}
    for field in ("audit_log_ref", "root", "retention_until"):
        if not audit_log.get(field):
            errors.append(f"provider credential custody audit_log.{field} is required")
    if not _is_hash_ref(str(audit_log.get("root") or "")):
        errors.append("provider credential custody audit_log.root must be a sha256 reference")

    response = receipt.get("response")
    if mode in {"kms-attested", "provider-managed-vault"} and not isinstance(response, dict):
        errors.append("provider credential custody response is required in attested modes")
    if isinstance(response, dict):
        status = response.get("status")
        if not isinstance(status, int) or status < 100 or status > 599:
            errors.append("provider credential custody response.status must be an HTTP status code")
        elif response.get("accepted") is not (200 <= status < 300):
            errors.append("provider credential custody response.accepted must match status")
        if not _is_hash_ref(str(response.get("response_hash") or "")):
            errors.append("provider credential custody response.response_hash must be a sha256 reference")

    source_artifacts = receipt.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("provider credential custody source_artifacts must contain at least one source")
        source_artifacts = []
    for source in source_artifacts:
        if not isinstance(source, dict):
            errors.append("provider credential custody source artifact records must be objects")
            continue
        if source.get("provider") != provider:
            errors.append("provider credential custody source provider does not match receipt provider")
    supplied_sources = _source_records(
        provider_installation=provider_installation,
        lifecycle_manifest=lifecycle_manifest,
        lifecycle_operation=lifecycle_operation,
        audit_worker=audit_worker,
    )
    if supplied_sources:
        if source_artifacts != supplied_sources:
            errors.append("provider credential custody source_artifacts do not match supplied source artifacts")
        _verify_supplied_sources(
            provider_installation=provider_installation,
            lifecycle_manifest=lifecycle_manifest,
            lifecycle_operation=lifecycle_operation,
            audit_worker=audit_worker,
            provider_ingress_manifest=provider_ingress_manifest,
            callback_storage_manifest=callback_storage_manifest,
            key=key,
            errors=errors,
            warnings=warnings,
        )
    else:
        warnings.append("provider credential custody source artifacts were not supplied; source hashes were not replayed")
    source_credential_refs = receipt.get("source_credential_refs", [])
    if not _is_string_list(source_credential_refs) or not source_credential_refs:
        errors.append("provider credential custody source_credential_refs must be a non-empty string array")
    elif credential_ref not in source_credential_refs:
        errors.append("provider credential custody credential ref is not present in source_credential_refs")
    if supplied_sources:
        expected_refs = sorted({ref for source in supplied_sources for ref in source.get("credential_refs", [])})
        if source_credential_refs != expected_refs:
            errors.append("provider credential custody source_credential_refs do not match supplied source artifacts")

    controls = receipt.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("provider credential custody controls are required")
    _check_no_secret_values(receipt, errors)

    return ProviderCredentialCustodyVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_credential_custody_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    provider_installation: dict[str, Any] | None = None,
    lifecycle_manifest: dict[str, Any] | None = None,
    lifecycle_operation: dict[str, Any] | None = None,
    audit_worker: dict[str, Any] | None = None,
    provider_ingress_manifest: dict[str, Any] | None = None,
    callback_storage_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_credential_custody_receipt(
        receipt,
        provider_installation=provider_installation,
        lifecycle_manifest=lifecycle_manifest,
        lifecycle_operation=lifecycle_operation,
        audit_worker=audit_worker,
        provider_ingress_manifest=provider_ingress_manifest,
        callback_storage_manifest=callback_storage_manifest,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid provider credential custody receipt: " + "; ".join(result.errors))
    payload = {
        "custody_id": receipt["custody_id"],
        "custody_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "issued_at": receipt.get("issued_at"),
        "credential": receipt.get("credential"),
        "custody": receipt.get("custody"),
        "vault": receipt.get("vault"),
        "policy": receipt.get("policy"),
        "audit_log": receipt.get("audit_log"),
        "source_artifacts": receipt.get("source_artifacts"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(PROVIDER_CREDENTIAL_CUSTODY_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("issued_at"))


def _source_records(
    *,
    provider_installation: dict[str, Any] | None,
    lifecycle_manifest: dict[str, Any] | None,
    lifecycle_operation: dict[str, Any] | None,
    audit_worker: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if provider_installation is not None:
        webhook = provider_installation.get("webhook", {}) if isinstance(provider_installation.get("webhook"), dict) else {}
        credential_refs = _redacted_refs(provider_installation.get("credential"), webhook.get("secret"))
        records.append(
            {
                "source_type": "provider_installation",
                "source_id": provider_installation.get("manifest_id"),
                "source_hash": content_hash(provider_installation),
                "provider": provider_installation.get("provider"),
                "credential_refs": credential_refs,
            }
        )
    if lifecycle_manifest is not None:
        lifecycle = lifecycle_manifest.get("lifecycle", {}) if isinstance(lifecycle_manifest.get("lifecycle"), dict) else {}
        oauth = lifecycle_manifest.get("oauth", {}) if isinstance(lifecycle_manifest.get("oauth"), dict) else {}
        records.append(
            {
                "source_type": "provider_lifecycle",
                "source_id": lifecycle_manifest.get("lifecycle_manifest_id"),
                "source_hash": content_hash(lifecycle_manifest),
                "provider": lifecycle.get("provider"),
                "credential_refs": _redacted_refs(oauth.get("token_store")),
            }
        )
    if lifecycle_operation is not None:
        operation = lifecycle_operation.get("operation", {}) if isinstance(lifecycle_operation.get("operation"), dict) else {}
        records.append(
            {
                "source_type": "provider_lifecycle_operation",
                "source_id": lifecycle_operation.get("operation_receipt_id"),
                "source_hash": content_hash(lifecycle_operation),
                "provider": lifecycle_operation.get("provider"),
                "operation_kind": operation.get("kind"),
                "operation_ref": operation.get("operation_ref"),
                "credential_refs": _redacted_refs(lifecycle_operation.get("credential"), lifecycle_operation.get("token_store")),
            }
        )
    if audit_worker is not None:
        worker = audit_worker.get("worker", {}) if isinstance(audit_worker.get("worker"), dict) else {}
        records.append(
            {
                "source_type": "provider_audit_worker",
                "source_id": audit_worker.get("worker_operation_id"),
                "source_hash": content_hash(audit_worker),
                "provider": audit_worker.get("provider"),
                "operation_kind": worker.get("operation_kind"),
                "worker_ref": worker.get("worker_ref"),
                "credential_refs": _redacted_refs(audit_worker.get("credential")),
            }
        )
    return records


def _verify_supplied_sources(
    *,
    provider_installation: dict[str, Any] | None,
    lifecycle_manifest: dict[str, Any] | None,
    lifecycle_operation: dict[str, Any] | None,
    audit_worker: dict[str, Any] | None,
    provider_ingress_manifest: dict[str, Any] | None,
    callback_storage_manifest: dict[str, Any] | None,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if provider_installation is not None:
        result = verify_provider_installation_manifest(provider_installation, key=key)
        if not result.ok:
            errors.extend(f"provider credential custody installation invalid: {error}" for error in result.errors)
        warnings.extend(f"provider credential custody installation warning: {warning}" for warning in result.warnings)
    if lifecycle_manifest is not None:
        result = verify_provider_lifecycle_manifest(lifecycle_manifest, provider_installation=provider_installation, provider_ingress_manifest=provider_ingress_manifest, callback_storage_manifest=callback_storage_manifest, key=key)
        if not result.ok:
            errors.extend(f"provider credential custody lifecycle invalid: {error}" for error in result.errors)
        warnings.extend(f"provider credential custody lifecycle warning: {warning}" for warning in result.warnings)
    if lifecycle_operation is not None:
        result = verify_provider_lifecycle_operation_receipt(lifecycle_operation, lifecycle_manifest=lifecycle_manifest, key=key)
        if not result.ok:
            errors.extend(f"provider credential custody lifecycle operation invalid: {error}" for error in result.errors)
        warnings.extend(f"provider credential custody lifecycle operation warning: {warning}" for warning in result.warnings)
    if audit_worker is not None:
        result = verify_provider_audit_worker_receipt(audit_worker, lifecycle_manifest=lifecycle_manifest, lifecycle_operation=lifecycle_operation, key=key)
        if not result.ok:
            errors.extend(f"provider credential custody audit worker invalid: {error}" for error in result.errors)
        warnings.extend(f"provider credential custody audit worker warning: {warning}" for warning in result.warnings)


def _controls(
    *,
    mode: str,
    credential_ref: str,
    vault_ref: str,
    kms_endpoint: str,
    policy_hash: str,
    attestation_ref: str | None,
    rotation_ref: str,
    revocation_ref: str,
    audit_log_root: str,
    quorum_met: bool,
    response_status: int | None,
) -> list[dict[str, Any]]:
    return [
        {
            "id": "redacted-provider-credential-custody",
            "status": "implemented" if credential_ref else "planned-production",
            "description": "Provider credential material is represented only by a redacted credential reference.",
        },
        {
            "id": "vault-kms-binding",
            "status": "implemented" if vault_ref and _valid_url(kms_endpoint) else "planned-production",
            "description": "Credential custody is bound to a vault/KMS reference and endpoint.",
        },
        {
            "id": "credential-policy-hash",
            "status": "implemented" if _is_hash_ref(policy_hash) else "planned-production",
            "description": "Credential access policy is bound by immutable hash.",
        },
        {
            "id": "attested-custody",
            "status": "implemented" if mode in {"kms-attested", "provider-managed-vault"} and attestation_ref else "planned-production",
            "description": "Credential custody can bind an HSM/KMS or provider vault attestation.",
        },
        {
            "id": "rotation-and-revocation",
            "status": "implemented" if rotation_ref and revocation_ref else "planned-production",
            "description": "Credential custody records rotation and revocation references.",
        },
        {
            "id": "custody-audit-log-root",
            "status": "implemented" if _is_hash_ref(audit_log_root) else "planned-production",
            "description": "Credential custody audit trail is bound to an immutable audit-log root.",
        },
        {
            "id": "custody-quorum",
            "status": "implemented" if quorum_met else "planned-production",
            "description": "Credential custody records approver quorum for privileged operations.",
        },
        {
            "id": "provider-custody-response",
            "status": "implemented" if response_status is not None and 200 <= response_status < 300 else "local-reference",
            "description": "Attested modes can bind a provider vault/KMS response hash.",
        },
    ]


def _redacted_refs(*values: Any) -> list[str]:
    refs: list[str] = []
    for value in values:
        if isinstance(value, dict) and value.get("redacted") is True and value.get("ref"):
            refs.append(str(value["ref"]))
    return sorted(set(refs))


def _derive_provider(records: list[dict[str, Any]]) -> str:
    providers = {_normalize_provider(record.get("provider")) for record in records}
    providers.discard(None)
    if not providers:
        raise ValueError("provider credential custody provider could not be derived from source artifacts")
    if len(providers) > 1:
        raise ValueError("provider credential custody source providers must match")
    return str(providers.pop())


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


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


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value)


def _require_text(value: str | None, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _normalize_provider(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized or None


def _check_no_secret_values(value: Any, errors: list[str], *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, item):
                    pass
                elif normalized == "credential_kind":
                    pass
                elif not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"provider credential custody secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and _is_string_list(value):
        return True
    return False
