from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .deployment import verify_deployment_manifest
from .object_store import WORMStore

BYOC_OPERATOR_SCHEMA = "trustai.byoc-operator-attestation/0.1"
BYOC_OPERATOR_ENTRY_TYPE = "deployment.byoc_operator_attested"
BYOC_OPERATOR_MODES = {"local-reference", "byoc-operator-attested", "airgap-operator-design", "production-design"}
OBJECT_LOCK_MODES = {"local-reference", "s3-object-lock-compliance", "gcs-bucket-lock", "azure-immutability-policy"}
RETENTION_MODES = {"compliance", "governance", "local-reference"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class BYOCOperatorVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_byoc_operator_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("BYOC operator attestation must contain an object")
    return value


def write_byoc_operator_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_byoc_operator_attestation(
    deployment_manifest: dict[str, Any],
    worm_receipt: dict[str, Any],
    *,
    legal_hold: dict[str, Any] | None = None,
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
    mode: str = "byoc-operator-attested",
    environment: str = "local",
    operator_ref: str,
    operator_version: str,
    operator_image: str,
    operator_image_digest: str,
    namespace: str,
    service_account_ref: str,
    reconciler_ref: str,
    upgrade_policy_ref: str,
    rollback_policy_ref: str,
    tenant_id: str,
    customer_account_ref: str,
    data_plane_ref: str,
    control_plane_ref: str | None = None,
    keyring_ref: str,
    object_lock_provider: str,
    object_lock_mode: str = "s3-object-lock-compliance",
    object_lock_bucket: str,
    object_lock_region: str,
    retention_mode: str = "compliance",
    default_retention_days: int = 2555,
    object_lock_enabled: bool = True,
    versioning_enabled: bool = True,
    legal_hold_required: bool = True,
    backup_policy_ref: str,
    backup_schedule: str,
    restore_test_ref: str,
    restore_test_at: str,
    rpo_minutes: int,
    rto_minutes: int,
    ingress_mode: str,
    egress_policy_ref: str,
    private_endpoint: bool = True,
    allowed_egress_refs: list[str] | None = None,
    airgap_bundle_ref: str | None = None,
    airgap_bundle_hash: str | None = None,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in BYOC_OPERATOR_MODES:
        raise ValueError(f"mode must be one of {sorted(BYOC_OPERATOR_MODES)}")
    if object_lock_mode not in OBJECT_LOCK_MODES:
        raise ValueError(f"object_lock_mode must be one of {sorted(OBJECT_LOCK_MODES)}")
    if retention_mode not in RETENTION_MODES:
        raise ValueError(f"retention_mode must be one of {sorted(RETENTION_MODES)}")

    deploy_result = verify_deployment_manifest(deployment_manifest, root=root)
    if not deploy_result.ok:
        raise ValueError("invalid deployment manifest: " + "; ".join(deploy_result.errors))

    timestamp = attested_at or utc_now()
    parse_rfc3339(timestamp)
    parse_rfc3339(restore_test_at)
    audit_retention = parse_rfc3339(retention_until)
    if audit_retention <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after attested_at")

    worm_audit = WORMStore(store).audit_receipt(worm_receipt, now=timestamp, legal_hold=legal_hold)
    if not worm_audit.ok:
        raise ValueError("invalid WORM receipt or legal hold: " + "; ".join(worm_audit.errors))
    if legal_hold_required and not worm_audit.legal_hold_active:
        raise ValueError("legal_hold_required requires a verified active legal hold")
    if not worm_audit.retention_active and not worm_audit.legal_hold_active:
        raise ValueError("WORM retention must be active or protected by legal hold")

    for field, value in {
        "operator_ref": operator_ref,
        "operator_version": operator_version,
        "operator_image": operator_image,
        "operator_image_digest": operator_image_digest,
        "namespace": namespace,
        "service_account_ref": service_account_ref,
        "reconciler_ref": reconciler_ref,
        "upgrade_policy_ref": upgrade_policy_ref,
        "rollback_policy_ref": rollback_policy_ref,
        "tenant_id": tenant_id,
        "customer_account_ref": customer_account_ref,
        "data_plane_ref": data_plane_ref,
        "keyring_ref": keyring_ref,
        "object_lock_provider": object_lock_provider,
        "object_lock_bucket": object_lock_bucket,
        "object_lock_region": object_lock_region,
        "backup_policy_ref": backup_policy_ref,
        "backup_schedule": backup_schedule,
        "restore_test_ref": restore_test_ref,
        "ingress_mode": ingress_mode,
        "egress_policy_ref": egress_policy_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
    }.items():
        _require_text(value, field)

    deployment = _deployment_record(deployment_manifest)
    object_lock = {
        "provider": object_lock_provider,
        "mode": object_lock_mode,
        "bucket_ref": object_lock_bucket,
        "region": object_lock_region,
        "object_lock_enabled": object_lock_enabled,
        "versioning_enabled": versioning_enabled,
        "retention_mode": retention_mode,
        "default_retention_days": default_retention_days,
        "retention_until": worm_receipt.get("retention_until"),
        "legal_hold_required": legal_hold_required,
        "worm_receipt": _worm_receipt_record(worm_receipt),
        "legal_hold": _legal_hold_record(legal_hold),
    }
    operator = {
        "operator_ref": operator_ref,
        "version": operator_version,
        "image": operator_image,
        "image_digest": operator_image_digest,
        "namespace": namespace,
        "service_account_ref": service_account_ref,
        "reconciler_ref": reconciler_ref,
        "upgrade_policy_ref": upgrade_policy_ref,
        "rollback_policy_ref": rollback_policy_ref,
    }
    tenancy = {
        "tenant_id": tenant_id,
        "customer_account_ref": customer_account_ref,
        "data_plane_ref": data_plane_ref,
        "control_plane_ref": control_plane_ref,
        "keyring_ref": keyring_ref,
    }
    backup = {
        "backup_policy_ref": backup_policy_ref,
        "schedule": backup_schedule,
        "restore_test_ref": restore_test_ref,
        "restore_test_at": restore_test_at,
        "rpo_minutes": rpo_minutes,
        "rto_minutes": rto_minutes,
    }
    network = {
        "ingress_mode": ingress_mode,
        "egress_policy_ref": egress_policy_ref,
        "private_endpoint": private_endpoint,
        "allowed_egress_refs": sorted(allowed_egress_refs or []),
        "airgap_bundle_ref": airgap_bundle_ref,
        "airgap_bundle_hash": airgap_bundle_hash,
    }
    audit_log = {
        "audit_log_ref": audit_log_ref,
        "root": audit_log_root,
        "retention_until": retention_until,
    }
    operation = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    source = _source_record(deployment_manifest, worm_receipt, legal_hold)
    body: dict[str, Any] = {
        "schema": BYOC_OPERATOR_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": source,
        "deployment": deployment,
        "operator": operator,
        "tenancy": tenancy,
        "object_lock": object_lock,
        "backup": backup,
        "network": network,
        "operation": operation,
        "audit_log": audit_log,
        "source_artifacts": _source_artifacts(deployment_manifest, worm_receipt, legal_hold),
        "controls": _controls(
            mode=mode,
            object_lock=object_lock,
            backup=backup,
            network=network,
            legal_hold_active=worm_audit.legal_hold_active,
        ),
        "limitations": [
            "This attestation binds the BYOC/self-hosted deployment manifest to WORM retention and operator evidence.",
            "It records Object Lock, legal hold, backup/restore, tenant, keyring, network, and operator controls without storing raw credentials.",
            "Local-reference evidence does not prove live cloud Object Lock or a continuously operated production operator.",
            "Production deployments should preserve provider-native Object Lock, backup, audit-log, and operator reconciliation exports.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "byoc_operator": body}, key)],
    }


def verify_byoc_operator_attestation(
    attestation: dict[str, Any],
    deployment_manifest: dict[str, Any] | None = None,
    worm_receipt: dict[str, Any] | None = None,
    *,
    legal_hold: dict[str, Any] | None = None,
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
    key: str | None = None,
) -> BYOCOperatorVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != BYOC_OPERATOR_SCHEMA:
        errors.append(f"unsupported BYOC operator attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical BYOC operator attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("BYOC operator attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "byoc_operator": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("BYOC operator attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"BYOC operator attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in BYOC_OPERATOR_MODES:
        errors.append("BYOC operator mode is unsupported")
    elif mode != "byoc-operator-attested":
        warnings.append(f"BYOC operator mode is {mode}; live production operator enforcement is not fully claimed")

    _verify_source_record(attestation.get("source"), errors)
    _verify_deployment_record(attestation.get("deployment"), errors)
    _verify_operator_record(attestation.get("operator"), errors)
    _verify_tenancy_record(attestation.get("tenancy"), errors)
    _verify_object_lock_record(attestation.get("object_lock"), errors)
    _verify_backup_record(attestation.get("backup"), errors)
    _verify_network_record(attestation.get("network"), errors, warnings)
    _verify_operation_record(attestation.get("operation"), errors)
    _verify_audit_log(attestation.get("audit_log"), attested, errors)

    controls = attestation.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("BYOC operator controls are required")

    source_artifacts = attestation.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("BYOC operator source_artifacts must contain deployment and WORM sources")
        source_artifacts = []

    supplied_sources = _source_artifacts(deployment_manifest, worm_receipt, legal_hold)
    if supplied_sources:
        if source_artifacts != supplied_sources:
            errors.append("BYOC operator source_artifacts do not match supplied source artifacts")
        expected_source = _source_record(deployment_manifest, worm_receipt, legal_hold)
        if attestation.get("source") != expected_source:
            errors.append("BYOC operator source record does not match supplied artifacts")

    if deployment_manifest is not None:
        deploy_result = verify_deployment_manifest(deployment_manifest, root=root)
        if not deploy_result.ok:
            errors.extend(f"deployment manifest invalid: {error}" for error in deploy_result.errors)
        warnings.extend(f"deployment manifest: {warning}" for warning in deploy_result.warnings)

    if worm_receipt is not None:
        worm_audit = WORMStore(store).audit_receipt(worm_receipt, now=str(attestation.get("attested_at") or ""), legal_hold=legal_hold)
        if not worm_audit.ok:
            errors.extend(f"WORM audit invalid: {error}" for error in worm_audit.errors)
        object_lock = attestation.get("object_lock") if isinstance(attestation.get("object_lock"), dict) else {}
        if object_lock.get("legal_hold_required") is True and not worm_audit.legal_hold_active:
            errors.append("BYOC operator legal_hold_required requires supplied active legal hold")
        if not worm_audit.retention_active and not worm_audit.legal_hold_active:
            errors.append("BYOC operator WORM retention must be active or legal hold protected")
        warnings.extend(f"WORM audit: {warning}" for warning in worm_audit.warnings)
    else:
        warnings.append("BYOC operator WORM receipt was not supplied; Object Lock source hash was not replayed")

    _check_no_secret_values(attestation, errors)
    return BYOCOperatorVerification(ok=not errors, errors=errors, warnings=warnings)


def append_byoc_operator_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    deployment_manifest: dict[str, Any] | None = None,
    worm_receipt: dict[str, Any] | None = None,
    *,
    legal_hold: dict[str, Any] | None = None,
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_byoc_operator_attestation(
        attestation,
        deployment_manifest,
        worm_receipt,
        legal_hold=legal_hold,
        root=root,
        store=store,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid BYOC operator attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "source": attestation.get("source"),
        "deployment": attestation.get("deployment"),
        "operator": attestation.get("operator"),
        "tenancy": attestation.get("tenancy"),
        "object_lock": attestation.get("object_lock"),
        "backup": attestation.get("backup"),
        "network": attestation.get("network"),
        "operation": attestation.get("operation"),
        "audit_log": attestation.get("audit_log"),
        "source_artifacts": attestation.get("source_artifacts"),
        "control_summary": _status_summary(attestation.get("controls", [])),
    }
    return chain.append(BYOC_OPERATOR_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _deployment_record(deployment_manifest: dict[str, Any]) -> dict[str, Any]:
    deployment = deployment_manifest.get("deployment", {}) if isinstance(deployment_manifest, dict) else {}
    return {
        "manifest_id": deployment_manifest.get("manifest_id") if isinstance(deployment_manifest, dict) else None,
        "manifest_hash": content_hash(deployment_manifest) if isinstance(deployment_manifest, dict) else None,
        "name": deployment.get("name") if isinstance(deployment, dict) else None,
        "mode": deployment.get("mode") if isinstance(deployment, dict) else None,
        "environment": deployment.get("environment") if isinstance(deployment, dict) else None,
        "artifact_type": deployment.get("artifact_type") if isinstance(deployment, dict) else None,
        "source_file_count": len(deployment_manifest.get("source_files", [])) if isinstance(deployment_manifest, dict) else 0,
    }


def _worm_receipt_record(worm_receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": worm_receipt.get("receipt_id"),
        "receipt_hash": content_hash(worm_receipt),
        "artifact_type": worm_receipt.get("artifact_type"),
        "content_hash": worm_receipt.get("content_hash"),
        "size_bytes": worm_receipt.get("size_bytes"),
        "retention_until": worm_receipt.get("retention_until"),
        "object_path": worm_receipt.get("object_path"),
    }


def _legal_hold_record(legal_hold: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(legal_hold, dict):
        return None
    return {
        "legal_hold_id": legal_hold.get("legal_hold_id"),
        "legal_hold_hash": content_hash(legal_hold),
        "case_id": legal_hold.get("case_id"),
        "status": legal_hold.get("status"),
        "applied_at": legal_hold.get("applied_at"),
    }


def _source_record(
    deployment_manifest: dict[str, Any] | None,
    worm_receipt: dict[str, Any] | None,
    legal_hold: dict[str, Any] | None,
) -> dict[str, Any]:
    deployment = deployment_manifest.get("deployment", {}) if isinstance(deployment_manifest, dict) else {}
    return {
        "deployment_manifest_id": deployment_manifest.get("manifest_id") if isinstance(deployment_manifest, dict) else None,
        "deployment_manifest_hash": content_hash(deployment_manifest) if isinstance(deployment_manifest, dict) else None,
        "deployment_environment": deployment.get("environment") if isinstance(deployment, dict) else None,
        "deployment_mode": deployment.get("mode") if isinstance(deployment, dict) else None,
        "worm_receipt_id": worm_receipt.get("receipt_id") if isinstance(worm_receipt, dict) else None,
        "worm_receipt_hash": content_hash(worm_receipt) if isinstance(worm_receipt, dict) else None,
        "worm_content_hash": worm_receipt.get("content_hash") if isinstance(worm_receipt, dict) else None,
        "worm_retention_until": worm_receipt.get("retention_until") if isinstance(worm_receipt, dict) else None,
        "legal_hold_id": legal_hold.get("legal_hold_id") if isinstance(legal_hold, dict) else None,
        "legal_hold_hash": content_hash(legal_hold) if isinstance(legal_hold, dict) else None,
    }


def _source_artifacts(
    deployment_manifest: dict[str, Any] | None,
    worm_receipt: dict[str, Any] | None,
    legal_hold: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    if isinstance(deployment_manifest, dict):
        artifacts.append(
            {
                "type": "deployment-manifest",
                "id": deployment_manifest.get("manifest_id"),
                "schema": deployment_manifest.get("schema"),
                "hash": content_hash(deployment_manifest),
            }
        )
    if isinstance(worm_receipt, dict):
        artifacts.append(
            {
                "type": "worm-receipt",
                "id": worm_receipt.get("receipt_id"),
                "schema": worm_receipt.get("schema"),
                "hash": content_hash(worm_receipt),
            }
        )
    if isinstance(legal_hold, dict):
        artifacts.append(
            {
                "type": "worm-legal-hold",
                "id": legal_hold.get("legal_hold_id"),
                "schema": legal_hold.get("schema"),
                "hash": content_hash(legal_hold),
            }
        )
    return artifacts


def _verify_source_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("BYOC operator source must be an object")
        return
    for field in ("deployment_manifest_id", "deployment_manifest_hash", "worm_receipt_id", "worm_receipt_hash", "worm_content_hash"):
        if not value.get(field):
            errors.append(f"BYOC operator source.{field} is required")


def _verify_deployment_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("BYOC operator deployment must be an object")
        return
    for field in ("manifest_id", "manifest_hash", "name", "mode", "environment", "artifact_type"):
        if not value.get(field):
            errors.append(f"BYOC operator deployment.{field} is required")
    if value.get("artifact_type") != "docker-image-plus-helm-chart":
        errors.append("BYOC operator deployment.artifact_type must be docker-image-plus-helm-chart")


def _verify_operator_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("BYOC operator operator must be an object")
        return
    for field in ("operator_ref", "version", "image", "image_digest", "namespace", "service_account_ref", "reconciler_ref", "upgrade_policy_ref", "rollback_policy_ref"):
        if not value.get(field):
            errors.append(f"BYOC operator operator.{field} is required")
    if not _is_sha256_ref(str(value.get("image_digest") or "")):
        errors.append("BYOC operator operator.image_digest must be a sha256 reference")


def _verify_tenancy_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("BYOC operator tenancy must be an object")
        return
    for field in ("tenant_id", "customer_account_ref", "data_plane_ref", "keyring_ref"):
        if not value.get(field):
            errors.append(f"BYOC operator tenancy.{field} is required")


def _verify_object_lock_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("BYOC operator object_lock must be an object")
        return
    for field in ("provider", "mode", "bucket_ref", "region", "retention_mode", "retention_until"):
        if not value.get(field):
            errors.append(f"BYOC operator object_lock.{field} is required")
    if value.get("mode") not in OBJECT_LOCK_MODES:
        errors.append("BYOC operator object_lock.mode is unsupported")
    if value.get("retention_mode") not in RETENTION_MODES:
        errors.append("BYOC operator object_lock.retention_mode is unsupported")
    if value.get("object_lock_enabled") is not True:
        errors.append("BYOC operator object_lock.object_lock_enabled must be true")
    if value.get("versioning_enabled") is not True:
        errors.append("BYOC operator object_lock.versioning_enabled must be true")
    if not isinstance(value.get("default_retention_days"), int) or value.get("default_retention_days") <= 0:
        errors.append("BYOC operator object_lock.default_retention_days must be a positive integer")
    receipt = value.get("worm_receipt")
    if not isinstance(receipt, dict) or not receipt.get("receipt_id") or not receipt.get("content_hash"):
        errors.append("BYOC operator object_lock.worm_receipt must bind receipt_id and content_hash")
    legal_hold = value.get("legal_hold")
    if value.get("legal_hold_required") is True and not isinstance(legal_hold, dict):
        errors.append("BYOC operator object_lock.legal_hold is required when legal_hold_required is true")


def _verify_backup_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("BYOC operator backup must be an object")
        return
    for field in ("backup_policy_ref", "schedule", "restore_test_ref", "restore_test_at"):
        if not value.get(field):
            errors.append(f"BYOC operator backup.{field} is required")
    try:
        parse_rfc3339(str(value.get("restore_test_at") or ""))
    except ValueError as exc:
        errors.append(f"BYOC operator backup.restore_test_at invalid: {exc}")
    for field in ("rpo_minutes", "rto_minutes"):
        if not isinstance(value.get(field), int) or value.get(field) < 0:
            errors.append(f"BYOC operator backup.{field} must be a non-negative integer")


def _verify_network_record(value: Any, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("BYOC operator network must be an object")
        return
    for field in ("ingress_mode", "egress_policy_ref"):
        if not value.get(field):
            errors.append(f"BYOC operator network.{field} is required")
    if value.get("private_endpoint") is not True:
        warnings.append("BYOC operator network.private_endpoint is not true")
    if value.get("airgap_bundle_hash") and not _is_sha256_ref(str(value.get("airgap_bundle_hash"))):
        errors.append("BYOC operator network.airgap_bundle_hash must be a sha256 reference")


def _verify_operation_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("BYOC operator operation must be an object")
        return
    if not value.get("actor_ref"):
        errors.append("BYOC operator operation.actor_ref is required")
    _verify_redacted_ref(value.get("credential"), "BYOC operator operation.credential", errors)


def _verify_audit_log(value: Any, attested: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("BYOC operator audit_log must be an object")
        return
    for field in ("audit_log_ref", "root", "retention_until"):
        if not value.get(field):
            errors.append(f"BYOC operator audit_log.{field} is required")
    if not _is_sha256_ref(str(value.get("root") or "")):
        errors.append("BYOC operator audit_log.root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("BYOC operator audit_log.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"BYOC operator audit_log.retention_until invalid: {exc}")


def _controls(
    *,
    mode: str,
    object_lock: dict[str, Any],
    backup: dict[str, Any],
    network: dict[str, Any],
    legal_hold_active: bool,
) -> list[dict[str, str]]:
    return [
        {
            "id": "byoc-operator-reconciliation",
            "status": "operator-attested" if mode == "byoc-operator-attested" else "planned-production",
            "description": "Operator image, digest, service account, reconciler, upgrade, and rollback controls are bound.",
        },
        {
            "id": "cloud-object-lock",
            "status": "operator-attested" if object_lock.get("object_lock_enabled") and object_lock.get("versioning_enabled") else "planned-production",
            "description": "Immutable storage mode, bucket reference, retention mode, WORM receipt, and versioning evidence are bound.",
        },
        {
            "id": "legal-hold-governance",
            "status": "operator-attested" if legal_hold_active else "planned-production",
            "description": "Legal hold evidence is bound to the WORM receipt when required.",
        },
        {
            "id": "backup-restore-drill",
            "status": "operator-attested" if backup.get("restore_test_ref") else "planned-production",
            "description": "Backup schedule, restore test, RPO, and RTO evidence are bound.",
        },
        {
            "id": "tenant-data-plane-isolation",
            "status": "operator-attested",
            "description": "Tenant, customer account, data plane, and keyring references are bound.",
        },
        {
            "id": "private-network-boundary",
            "status": "operator-attested" if network.get("private_endpoint") else "planned-production",
            "description": "Private ingress and egress policy references are bound.",
        },
    ]


def _status_summary(controls: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        if not isinstance(control, dict):
            continue
        status = str(control.get("status", "unknown"))
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                if not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"BYOC operator secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _is_sha256_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value[7:])
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())
