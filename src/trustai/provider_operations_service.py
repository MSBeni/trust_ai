from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .provider_audit import verify_provider_audit_correlation
from .provider_audit_stream import verify_provider_audit_stream_receipt
from .provider_audit_worker import verify_provider_audit_worker_receipt
from .provider_callback_storage import verify_provider_callback_storage_manifest
from .provider_callback_store import verify_provider_callback_store_manifest
from .provider_credential_custody import verify_provider_credential_custody_receipt
from .provider_ingress import verify_provider_ingress_manifest
from .provider_installation import verify_provider_installation_manifest
from .provider_lifecycle import verify_provider_lifecycle_manifest
from .provider_lifecycle_operation import verify_provider_lifecycle_operation_receipt

PROVIDER_OPERATIONS_SERVICE_SCHEMA = "trustai.provider-operations-service-attestation/0.1"
PROVIDER_OPERATIONS_SERVICE_ENTRY_TYPE = "provider.operations_service_attested"
PROVIDER_OPERATIONS_SERVICE_MODES = {"local-reference", "provider-operations-attested", "production-design"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ProviderOperationsServiceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_provider_operations_service_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider operations service attestation must contain an object")
    return value


def write_provider_operations_service_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_provider_operations_service_attestation(
    *,
    provider_installation: dict[str, Any],
    provider_ingress: dict[str, Any],
    callback_storage: dict[str, Any],
    lifecycle: dict[str, Any],
    lifecycle_operation: dict[str, Any],
    audit_lifecycle_operation: dict[str, Any],
    audit_worker: dict[str, Any],
    credential_custody: dict[str, Any],
    callback_store: dict[str, Any] | None = None,
    audit_stream: dict[str, Any] | None = None,
    audit_correlation: dict[str, Any] | None = None,
    callback_store_db_path: str | Path | None = None,
    callback_store_source_artifacts: list[dict[str, Any]] | None = None,
    mode: str = "provider-operations-attested",
    environment: str = "local",
    service_ref: str,
    service_version: str,
    service_image: str,
    service_image_digest: str,
    service_binary_hash: str,
    replicas_min: int,
    replicas_max: int,
    availability_zones: list[str] | None = None,
    public_ingress_ref: str,
    oauth_worker_ref: str,
    callback_worker_ref: str,
    audit_worker_ref: str,
    storage_ref: str,
    vault_ref: str,
    kms_key_ref: str,
    mtls_policy_ref: str,
    auth_policy_ref: str,
    webhook_signature_policy_ref: str,
    replay_window_ref: str,
    dedup_store_ref: str,
    rate_limit_policy_ref: str,
    network_policy_ref: str,
    egress_policy_ref: str,
    scheduler_ref: str,
    lease_ref: str,
    checkpoint_ref: str,
    external_call_policy_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in PROVIDER_OPERATIONS_SERVICE_MODES:
        raise ValueError(f"mode must be one of {sorted(PROVIDER_OPERATIONS_SERVICE_MODES)}")

    source_result = _verify_sources(
        provider_installation=provider_installation,
        provider_ingress=provider_ingress,
        callback_storage=callback_storage,
        lifecycle=lifecycle,
        lifecycle_operation=lifecycle_operation,
        audit_lifecycle_operation=audit_lifecycle_operation,
        audit_worker=audit_worker,
        credential_custody=credential_custody,
        callback_store=callback_store,
        audit_stream=audit_stream,
        audit_correlation=audit_correlation,
        callback_store_db_path=callback_store_db_path,
        callback_store_source_artifacts=callback_store_source_artifacts,
        key=key,
    )
    if not source_result.ok:
        raise ValueError("invalid provider operations source evidence: " + "; ".join(source_result.errors))

    timestamp = attested_at or utc_now()
    parse_rfc3339(timestamp)
    retention = parse_rfc3339(retention_until)
    if retention <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after attested_at")

    for field, value in {
        "service_ref": service_ref,
        "service_version": service_version,
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "public_ingress_ref": public_ingress_ref,
        "oauth_worker_ref": oauth_worker_ref,
        "callback_worker_ref": callback_worker_ref,
        "audit_worker_ref": audit_worker_ref,
        "storage_ref": storage_ref,
        "vault_ref": vault_ref,
        "kms_key_ref": kms_key_ref,
        "mtls_policy_ref": mtls_policy_ref,
        "auth_policy_ref": auth_policy_ref,
        "webhook_signature_policy_ref": webhook_signature_policy_ref,
        "replay_window_ref": replay_window_ref,
        "dedup_store_ref": dedup_store_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "scheduler_ref": scheduler_ref,
        "lease_ref": lease_ref,
        "checkpoint_ref": checkpoint_ref,
        "external_call_policy_ref": external_call_policy_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
    }.items():
        _require_text(value, field)

    service = {
        "service_ref": service_ref,
        "version": service_version,
        "provider": _provider(provider_installation, lifecycle, audit_worker, credential_custody),
        "service_image": service_image,
        "service_image_digest": service_image_digest,
        "service_binary_hash": service_binary_hash,
        "replicas_min": replicas_min,
        "replicas_max": replicas_max,
        "availability_zones": sorted(availability_zones or []),
    }
    operations = {
        "public_ingress_ref": public_ingress_ref,
        "oauth_worker_ref": oauth_worker_ref,
        "callback_worker_ref": callback_worker_ref,
        "audit_worker_ref": audit_worker_ref,
        "storage_ref": storage_ref,
        "vault_ref": vault_ref,
        "kms_key_ref": kms_key_ref,
        "scheduler_ref": scheduler_ref,
        "lease_ref": lease_ref,
        "checkpoint_ref": checkpoint_ref,
        "external_call_policy_ref": external_call_policy_ref,
    }
    security = {
        "mtls_policy_ref": mtls_policy_ref,
        "auth_policy_ref": auth_policy_ref,
        "webhook_signature_policy_ref": webhook_signature_policy_ref,
        "replay_window_ref": replay_window_ref,
        "dedup_store_ref": dedup_store_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
    }
    audit_log = {
        "audit_log_ref": audit_log_ref,
        "root": audit_log_root,
        "retention_until": retention_until,
    }
    operation_actor = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    source_artifacts = _source_artifacts(
        provider_installation=provider_installation,
        provider_ingress=provider_ingress,
        callback_storage=callback_storage,
        lifecycle=lifecycle,
        lifecycle_operation=lifecycle_operation,
        audit_lifecycle_operation=audit_lifecycle_operation,
        audit_worker=audit_worker,
        credential_custody=credential_custody,
        callback_store=callback_store,
        audit_stream=audit_stream,
        audit_correlation=audit_correlation,
    )
    body: dict[str, Any] = {
        "schema": PROVIDER_OPERATIONS_SERVICE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": _source_summary(source_artifacts),
        "service": service,
        "operations": operations,
        "security": security,
        "audit_log": audit_log,
        "operation_actor": operation_actor,
        "source_artifacts": source_artifacts,
        "controls": _controls(service, operations, security, audit_log),
        "limitations": [
            "This attestation binds provider-hosted callback and lifecycle operation receipts to service hardening evidence.",
            "It records public ingress, OAuth lifecycle workers, callback storage, audit workers, credential custody, vault/KMS, scheduler, network, audit, actor, and redacted credential evidence.",
            "It stores redacted credential references and hashes, not raw provider credentials, webhook secrets, or OAuth tokens.",
            "Production deployments should replace local/reference evidence with continuously operated provider workers, provider-owned vault/KMS exports, live ingress, managed HA storage, and external provider call receipts.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "provider_operations_service": body}, key)],
    }


def verify_provider_operations_service_attestation(
    attestation: dict[str, Any],
    *,
    provider_installation: dict[str, Any] | None = None,
    provider_ingress: dict[str, Any] | None = None,
    callback_storage: dict[str, Any] | None = None,
    lifecycle: dict[str, Any] | None = None,
    lifecycle_operation: dict[str, Any] | None = None,
    audit_lifecycle_operation: dict[str, Any] | None = None,
    audit_worker: dict[str, Any] | None = None,
    credential_custody: dict[str, Any] | None = None,
    callback_store: dict[str, Any] | None = None,
    audit_stream: dict[str, Any] | None = None,
    audit_correlation: dict[str, Any] | None = None,
    callback_store_db_path: str | Path | None = None,
    callback_store_source_artifacts: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> ProviderOperationsServiceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != PROVIDER_OPERATIONS_SERVICE_SCHEMA:
        errors.append(f"unsupported provider operations service attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical provider operations service attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider operations service attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "provider_operations_service": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider operations service attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"provider operations service attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in PROVIDER_OPERATIONS_SERVICE_MODES:
        errors.append("provider operations service mode is unsupported")
    elif mode != "provider-operations-attested":
        warnings.append(f"provider operations service mode is {mode}; live hosted provider operation is not fully claimed")

    _verify_service(attestation.get("service"), errors)
    _verify_required_object(attestation.get("operations"), "operations", errors)
    _verify_required_object(attestation.get("security"), "security", errors)
    _verify_audit_log(attestation.get("audit_log"), attested, errors)
    _verify_actor(attestation.get("operation_actor"), errors)

    controls = attestation.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("provider operations service controls are required")

    supplied_sources = _source_artifacts(
        provider_installation=provider_installation,
        provider_ingress=provider_ingress,
        callback_storage=callback_storage,
        lifecycle=lifecycle,
        lifecycle_operation=lifecycle_operation,
        audit_lifecycle_operation=audit_lifecycle_operation,
        audit_worker=audit_worker,
        credential_custody=credential_custody,
        callback_store=callback_store,
        audit_stream=audit_stream,
        audit_correlation=audit_correlation,
    )
    source_artifacts = attestation.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or len(source_artifacts) < 8:
        errors.append("provider operations service source_artifacts must include core provider operation receipts")
    if supplied_sources:
        if source_artifacts != supplied_sources:
            errors.append("provider operations service source_artifacts do not match supplied source artifacts")
        if attestation.get("source") != _source_summary(supplied_sources):
            errors.append("provider operations service source summary does not match supplied source artifacts")
        source_result = _verify_sources(
            provider_installation=provider_installation,
            provider_ingress=provider_ingress,
            callback_storage=callback_storage,
            lifecycle=lifecycle,
            lifecycle_operation=lifecycle_operation,
            audit_lifecycle_operation=audit_lifecycle_operation,
            audit_worker=audit_worker,
            credential_custody=credential_custody,
            callback_store=callback_store,
            audit_stream=audit_stream,
            audit_correlation=audit_correlation,
            callback_store_db_path=callback_store_db_path,
            callback_store_source_artifacts=callback_store_source_artifacts,
            key=key,
        )
        if not source_result.ok:
            errors.extend(f"provider operations source invalid: {error}" for error in source_result.errors)
        warnings.extend(f"provider operations source: {warning}" for warning in source_result.warnings)
    else:
        warnings.append("provider operations service source artifacts were not supplied; provider operation hashes were not replayed")

    _check_no_secret_values(attestation, errors)
    return ProviderOperationsServiceVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_operations_service_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    **sources: Any,
) -> dict[str, Any]:
    key = sources.pop("key", None)
    result = verify_provider_operations_service_attestation(attestation, key=key, **sources)
    if not result.ok:
        raise ValueError("invalid provider operations service attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "source": attestation.get("source"),
        "service": attestation.get("service"),
        "operations": attestation.get("operations"),
        "security": attestation.get("security"),
        "audit_log": attestation.get("audit_log"),
        "operation_actor": attestation.get("operation_actor"),
        "source_artifacts": attestation.get("source_artifacts"),
        "control_summary": _status_summary(attestation.get("controls", [])),
    }
    return chain.append(PROVIDER_OPERATIONS_SERVICE_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _verify_sources(
    *,
    provider_installation: dict[str, Any] | None,
    provider_ingress: dict[str, Any] | None,
    callback_storage: dict[str, Any] | None,
    lifecycle: dict[str, Any] | None,
    lifecycle_operation: dict[str, Any] | None,
    audit_lifecycle_operation: dict[str, Any] | None,
    audit_worker: dict[str, Any] | None,
    credential_custody: dict[str, Any] | None,
    callback_store: dict[str, Any] | None,
    audit_stream: dict[str, Any] | None,
    audit_correlation: dict[str, Any] | None,
    callback_store_db_path: str | Path | None,
    callback_store_source_artifacts: list[dict[str, Any]] | None,
    key: str | None,
) -> ProviderOperationsServiceVerification:
    errors: list[str] = []
    warnings: list[str] = []
    required = {
        "provider_installation": provider_installation,
        "provider_ingress": provider_ingress,
        "callback_storage": callback_storage,
        "lifecycle": lifecycle,
        "lifecycle_operation": lifecycle_operation,
        "audit_lifecycle_operation": audit_lifecycle_operation,
        "audit_worker": audit_worker,
        "credential_custody": credential_custody,
    }
    for name, value in required.items():
        if not isinstance(value, dict):
            errors.append(f"{name} source is required")
    if errors:
        return ProviderOperationsServiceVerification(False, errors, warnings)

    assert provider_installation is not None
    assert provider_ingress is not None
    assert callback_storage is not None
    assert lifecycle is not None
    assert lifecycle_operation is not None
    assert audit_lifecycle_operation is not None
    assert audit_worker is not None
    assert credential_custody is not None

    checks = [
        ("provider installation", verify_provider_installation_manifest(provider_installation, key=key)),
        (
            "callback store",
            verify_provider_callback_store_manifest(callback_store, db_path=callback_store_db_path, source_artifacts=callback_store_source_artifacts, key=key)
            if callback_store is not None and callback_store_db_path is not None
            else None,
        ),
        (
            "provider ingress",
            verify_provider_ingress_manifest(
                provider_ingress,
                provider_installations=[provider_installation],
                callback_store_manifest=callback_store,
                callback_store_db_path=callback_store_db_path,
                callback_store_source_artifacts=callback_store_source_artifacts,
                key=key,
            ),
        ),
        (
            "callback storage",
            verify_provider_callback_storage_manifest(
                callback_storage,
                callback_store_manifest=callback_store,
                callback_store_db_path=callback_store_db_path,
                callback_store_source_artifacts=callback_store_source_artifacts,
                provider_ingress_manifest=provider_ingress,
                key=key,
            ),
        ),
        (
            "provider lifecycle",
            verify_provider_lifecycle_manifest(
                lifecycle,
                provider_installation=provider_installation,
                provider_ingress_manifest=provider_ingress,
                callback_storage_manifest=callback_storage,
                callback_store_manifest=callback_store,
                callback_store_db_path=callback_store_db_path,
                callback_store_source_artifacts=callback_store_source_artifacts,
                key=key,
            ),
        ),
        ("provider lifecycle operation", verify_provider_lifecycle_operation_receipt(lifecycle_operation, lifecycle_manifest=lifecycle, key=key)),
        ("provider audit lifecycle operation", verify_provider_lifecycle_operation_receipt(audit_lifecycle_operation, lifecycle_manifest=lifecycle, key=key)),
        (
            "provider audit stream",
            verify_provider_audit_stream_receipt(
                audit_stream,
                provider_installation=provider_installation,
                correlation=audit_correlation,
                key=key,
            )
            if audit_stream is not None
            else None,
        ),
        ("provider audit correlation", verify_provider_audit_correlation(audit_correlation, key=key) if audit_correlation is not None else None),
        (
            "provider audit worker",
            verify_provider_audit_worker_receipt(
                audit_worker,
                stream_receipts=[audit_stream] if audit_stream is not None else None,
                correlations=[audit_correlation] if audit_correlation is not None else None,
                lifecycle_operation=audit_lifecycle_operation,
                lifecycle_manifest=lifecycle,
                key=key,
            ),
        ),
        (
            "provider credential custody",
            verify_provider_credential_custody_receipt(
                credential_custody,
                provider_installation=provider_installation,
                lifecycle_manifest=lifecycle,
                lifecycle_operation=audit_lifecycle_operation,
                audit_worker=audit_worker,
                provider_ingress_manifest=provider_ingress,
                callback_storage_manifest=callback_storage,
                callback_store_manifest=callback_store,
                callback_store_db_path=callback_store_db_path,
                callback_store_source_artifacts=callback_store_source_artifacts,
                key=key,
            ),
        ),
    ]
    for label, result in checks:
        if result is None:
            warnings.append(f"{label} source not supplied for deep verification")
            continue
        if not result.ok:
            errors.extend(f"{label}: {error}" for error in result.errors)
        warnings.extend(f"{label}: {warning}" for warning in result.warnings)
    return ProviderOperationsServiceVerification(not errors, errors, warnings)


def _source_artifacts(**sources: dict[str, Any] | None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name, value in sources.items():
        if isinstance(value, dict):
            records.append({"type": name.replace("_", "-"), "id": _source_id(value), "schema": value.get("schema"), "hash": content_hash(value)})
    return records


def _source_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_count": len(records),
        "source_hash": content_hash(records),
        "schemas": sorted({str(record.get("schema")) for record in records if record.get("schema")}),
        "required_types": sorted(record["type"] for record in records),
    }


def _source_id(value: dict[str, Any]) -> Any:
    for key in (
        "manifest_id",
        "delivery_id",
        "receipt_id",
        "correlation_id",
        "stream_receipt_id",
        "store_manifest_id",
        "ingress_manifest_id",
        "storage_manifest_id",
        "lifecycle_manifest_id",
        "operation_receipt_id",
        "worker_operation_id",
        "custody_id",
    ):
        if value.get(key):
            return value.get(key)
    nested = value.get("worker") if isinstance(value.get("worker"), dict) else {}
    if nested.get("worker_ref"):
        return nested.get("worker_ref")
    return value.get("schema")


def _provider(*values: dict[str, Any]) -> str | None:
    for value in values:
        if isinstance(value, dict):
            provider = value.get("provider")
            if isinstance(provider, str) and provider:
                return provider
            if isinstance(provider, dict):
                for field in ("name", "provider"):
                    if provider.get(field):
                        return str(provider[field])
            installation = value.get("installation")
            if isinstance(installation, dict) and installation.get("provider"):
                return str(installation["provider"])
    return None


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider operations service service must be an object")
        return
    for field in ("service_ref", "version", "provider", "service_image", "service_image_digest", "service_binary_hash"):
        if not value.get(field):
            errors.append(f"provider operations service service.{field} is required")
    for field in ("service_image_digest", "service_binary_hash"):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"provider operations service service.{field} must be a sha256 reference")
    replicas_min = value.get("replicas_min")
    replicas_max = value.get("replicas_max")
    if not isinstance(replicas_min, int) or replicas_min < 2:
        errors.append("provider operations service service.replicas_min must be an integer >= 2")
    if not isinstance(replicas_max, int) or not isinstance(replicas_min, int) or replicas_max < replicas_min:
        errors.append("provider operations service service.replicas_max must be >= replicas_min")
    if not isinstance(value.get("availability_zones"), list) or len(value.get("availability_zones")) < 2:
        errors.append("provider operations service service.availability_zones must include at least two zones")


def _verify_required_object(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"provider operations service {name} must be an object")
        return
    for field, child in value.items():
        if not child:
            errors.append(f"provider operations service {name}.{field} is required")


def _verify_audit_log(value: Any, attested: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider operations service audit_log must be an object")
        return
    for field in ("audit_log_ref", "root", "retention_until"):
        if not value.get(field):
            errors.append(f"provider operations service audit_log.{field} is required")
    if not _is_sha256_ref(str(value.get("root") or "")):
        errors.append("provider operations service audit_log.root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("provider operations service audit_log.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"provider operations service audit_log.retention_until invalid: {exc}")


def _verify_actor(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("provider operations service operation_actor must be an object")
        return
    if not value.get("actor_ref"):
        errors.append("provider operations service operation_actor.actor_ref is required")
    _verify_redacted_ref(value.get("credential"), "provider operations service operation_actor.credential", errors)


def _controls(service: dict[str, Any], operations: dict[str, Any], security: dict[str, Any], audit_log: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"id": "provider-operations-service-identity", "status": "service-attested" if service.get("service_image_digest") and service.get("service_binary_hash") else "planned-production", "description": "Provider operations service image, binary hash, provider, replica floor, and multi-zone evidence are bound."},
        {"id": "provider-public-ingress-and-callbacks", "status": "service-attested" if operations.get("public_ingress_ref") and operations.get("callback_worker_ref") else "planned-production", "description": "Public ingress, callback worker, OAuth worker, and external call policy evidence are bound."},
        {"id": "provider-storage-and-vault", "status": "service-attested" if operations.get("storage_ref") and operations.get("vault_ref") and operations.get("kms_key_ref") else "planned-production", "description": "Managed callback storage, credential vault, and KMS key references are bound."},
        {"id": "provider-signature-replay-dedup", "status": "service-attested" if security.get("webhook_signature_policy_ref") and security.get("replay_window_ref") and security.get("dedup_store_ref") else "planned-production", "description": "Webhook signature, replay-window, and deduplication controls are bound."},
        {"id": "provider-audit-worker-scheduling", "status": "service-attested" if operations.get("audit_worker_ref") and operations.get("scheduler_ref") and operations.get("checkpoint_ref") else "planned-production", "description": "Audit worker, schedule, lease, and checkpoint evidence are bound."},
        {"id": "provider-operations-audit-retention", "status": "service-attested" if audit_log.get("audit_log_ref") and audit_log.get("root") else "planned-production", "description": "Provider operations audit-log root and retention evidence are bound."},
    ]


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if isinstance(item, dict):
            status = str(item.get("status", "unknown"))
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    return {"ref": ref, "redacted": True} if ref else None


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
                    errors.append(f"provider operations service secret-like field must be redacted reference: {child_path}")
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
