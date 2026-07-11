from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .provider_callback_store import verify_provider_callback_store_manifest
from .provider_ingress import verify_provider_ingress_manifest

PROVIDER_CALLBACK_STORAGE_SCHEMA = "trustai.provider-callback-storage/0.1"
PROVIDER_CALLBACK_STORAGE_ENTRY_TYPE = "provider_callback_storage.attested"

STORAGE_MODES = {
    "local-reference",
    "byoc-reference",
    "managed-postgres-reference",
    "recorded-managed-postgres",
    "production-design",
}
STORAGE_ENGINES = {"postgres", "managed-postgres"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential", "dsn")


@dataclass
class ProviderCallbackStorageVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_provider_callback_storage_manifest(
    *,
    storage_ref: str,
    dsn_ref: str,
    schema_ref: str,
    migration_ref: str,
    migration_hash: str,
    callback_store_manifest: dict[str, Any],
    mode: str = "byoc-reference",
    environment: str = "local",
    engine: str = "managed-postgres",
    primary_region: str | None = None,
    replica_regions: list[str] | None = None,
    min_replicas: int = 2,
    backup_policy_ref: str | None = None,
    retention_until: str | None = None,
    rpo_seconds: int = 60,
    rto_seconds: int = 300,
    encryption_key_ref: str | None = None,
    network_policy_ref: str | None = None,
    monitoring_ref: str | None = None,
    failover_runbook_ref: str | None = None,
    provider_ingress_manifest: dict[str, Any] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in STORAGE_MODES:
        raise ValueError("mode must be local-reference, byoc-reference, managed-postgres-reference, recorded-managed-postgres, or production-design")
    if engine not in STORAGE_ENGINES:
        raise ValueError("engine must be postgres or managed-postgres")
    for value, field in (
        (storage_ref, "storage_ref"),
        (dsn_ref, "dsn_ref"),
        (schema_ref, "schema_ref"),
        (migration_ref, "migration_ref"),
        (migration_hash, "migration_hash"),
    ):
        _require_text(value, field)
    if not isinstance(callback_store_manifest, dict):
        raise ValueError("callback_store_manifest is required")

    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    if retention_until and parse_rfc3339(retention_until) <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after generated_at")

    source_records = _source_artifact_records(
        callback_store_manifest=callback_store_manifest,
        provider_ingress_manifest=provider_ingress_manifest,
    )
    migration_plan = _migration_plan(
        callback_store_manifest,
        target_engine=engine,
        schema_ref=schema_ref,
        migration_ref=migration_ref,
        migration_hash=migration_hash,
    )
    body = {
        "schema": PROVIDER_CALLBACK_STORAGE_SCHEMA,
        "generated_at": timestamp,
        "storage": {
            "mode": mode,
            "environment": environment,
            "storage_ref": storage_ref,
            "engine": engine,
            "dsn": _redacted_ref(dsn_ref),
            "schema_ref": schema_ref,
            "retention_until": retention_until,
        },
        "migration_plan": migration_plan,
        "high_availability": {
            "primary_region": primary_region,
            "replica_regions": _normalized_list(replica_regions),
            "min_replicas": int(min_replicas),
            "failover_runbook_ref": failover_runbook_ref,
            "rpo_seconds": int(rpo_seconds),
            "rto_seconds": int(rto_seconds),
        },
        "security_controls": {
            "encryption_key": _redacted_ref(encryption_key_ref),
            "network_policy_ref": network_policy_ref,
            "backup_policy_ref": backup_policy_ref,
            "monitoring_ref": monitoring_ref,
        },
        "source_artifacts": source_records,
        "controls": _controls(
            mode=mode,
            engine=engine,
            callback_store_manifest=callback_store_manifest,
            provider_ingress_manifest=provider_ingress_manifest,
            min_replicas=min_replicas,
            primary_region=primary_region,
            replica_regions=replica_regions,
            backup_policy_ref=backup_policy_ref,
            retention_until=retention_until,
            encryption_key_ref=encryption_key_ref,
            network_policy_ref=network_policy_ref,
            monitoring_ref=monitoring_ref,
            failover_runbook_ref=failover_runbook_ref,
        ),
        "limitations": [
            "This manifest attests a BYOC or managed-Postgres callback storage target and migration plan for provider callback operations.",
            "It binds the SQLite callback-store source and optional ingress evidence by canonical hash; it does not prove a live managed Postgres service unless recorded-managed-postgres evidence is supplied.",
            "Production SaaS still requires operated Postgres clusters, backup execution, failover drills, request-store SLO monitoring, and provider-authenticated audit-log streaming.",
        ],
    }
    manifest_id = content_hash(body)
    return {
        **body,
        "storage_manifest_id": manifest_id,
        "signatures": [sign_value({"storage_manifest_id": manifest_id, "provider_callback_storage": body}, key)],
    }


def verify_provider_callback_storage_manifest(
    manifest: dict[str, Any],
    *,
    callback_store_manifest: dict[str, Any] | None = None,
    callback_store_db_path: str | Path | None = None,
    callback_store_source_artifacts: list[dict[str, Any]] | None = None,
    provider_ingress_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> ProviderCallbackStorageVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if manifest.get("schema") != PROVIDER_CALLBACK_STORAGE_SCHEMA:
        errors.append(f"unsupported provider callback storage schema: {manifest.get('schema')}")
    body = without_keys(manifest, "storage_manifest_id", "signatures")
    expected_id = content_hash(body)
    if manifest.get("storage_manifest_id") != expected_id:
        errors.append("storage_manifest_id does not match canonical provider callback storage body")

    signatures = manifest.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider callback storage manifest must include at least one signature")
    else:
        signed_value = {"storage_manifest_id": manifest.get("storage_manifest_id"), "provider_callback_storage": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider callback storage signature verification failed")

    try:
        generated_at = parse_rfc3339(str(manifest.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"provider callback storage generated_at invalid: {exc}")
        generated_at = None

    storage = manifest.get("storage", {})
    if not isinstance(storage, dict):
        errors.append("provider callback storage storage must be an object")
        storage = {}
    mode = storage.get("mode")
    if mode not in STORAGE_MODES:
        errors.append("provider callback storage mode is unsupported")
    elif mode != "recorded-managed-postgres":
        warnings.append(f"provider callback storage mode is {mode}; live managed Postgres operation is not claimed")
    engine = storage.get("engine")
    if engine not in STORAGE_ENGINES:
        errors.append("provider callback storage engine must be postgres or managed-postgres")
    for field in ("storage_ref", "schema_ref", "environment"):
        if not storage.get(field):
            errors.append(f"provider callback storage {field} is required")
    if storage.get("dsn") is not None:
        _verify_redacted_ref(storage.get("dsn"), "provider callback storage dsn", errors)
    else:
        errors.append("provider callback storage dsn redacted reference is required")
    retention_until = storage.get("retention_until")
    if retention_until:
        try:
            retention = parse_rfc3339(str(retention_until))
            if generated_at and retention <= generated_at:
                errors.append("provider callback storage retention_until must be after generated_at")
        except ValueError as exc:
            errors.append(f"provider callback storage retention_until invalid: {exc}")
    else:
        errors.append("provider callback storage retention_until is required")

    migration = manifest.get("migration_plan", {})
    if not isinstance(migration, dict):
        errors.append("provider callback storage migration_plan must be an object")
        migration = {}
    errors.extend(_migration_shape_errors(migration))

    ha = manifest.get("high_availability", {})
    if not isinstance(ha, dict):
        errors.append("provider callback storage high_availability must be an object")
        ha = {}
    replica_regions = ha.get("replica_regions", [])
    if not _is_string_list(replica_regions):
        errors.append("provider callback storage replica_regions must be a string array")
    if not ha.get("primary_region"):
        errors.append("provider callback storage primary_region is required")
    min_replicas = ha.get("min_replicas")
    if not isinstance(min_replicas, int) or min_replicas < 2:
        errors.append("provider callback storage min_replicas must be at least 2")
    rpo_seconds = ha.get("rpo_seconds")
    if not isinstance(rpo_seconds, int) or rpo_seconds <= 0 or rpo_seconds > 3600:
        errors.append("provider callback storage rpo_seconds must be an integer between 1 and 3600")
    rto_seconds = ha.get("rto_seconds")
    if not isinstance(rto_seconds, int) or rto_seconds <= 0 or rto_seconds > 14400:
        errors.append("provider callback storage rto_seconds must be an integer between 1 and 14400")
    if not ha.get("failover_runbook_ref"):
        errors.append("provider callback storage failover_runbook_ref is required")

    security = manifest.get("security_controls", {})
    if not isinstance(security, dict):
        errors.append("provider callback storage security_controls must be an object")
        security = {}
    if security.get("encryption_key") is not None:
        _verify_redacted_ref(security.get("encryption_key"), "provider callback storage encryption_key", errors)
    else:
        errors.append("provider callback storage encryption_key redacted reference is required")
    for field in ("network_policy_ref", "backup_policy_ref", "monitoring_ref"):
        if not security.get(field):
            errors.append(f"provider callback storage {field} is required")

    manifest_sources = manifest.get("source_artifacts", [])
    if not isinstance(manifest_sources, list):
        errors.append("provider callback storage source_artifacts must be a list")
        manifest_sources = []
    if callback_store_manifest is None:
        if any(source.get("artifact_type") == "provider_callback_store" for source in manifest_sources if isinstance(source, dict)):
            errors.append("provider callback storage callback-store manifest is required for verification")
        else:
            warnings.append("provider callback storage callback-store manifest was not supplied; source hash and migration plan were not replayed")
    else:
        store_result = verify_provider_callback_store_manifest(
            callback_store_manifest,
            db_path=callback_store_db_path,
            source_artifacts=callback_store_source_artifacts,
            key=key,
        )
        if not store_result.ok:
            errors.extend(f"provider callback storage callback store invalid: {error}" for error in store_result.errors)
        warnings.extend(f"provider callback storage callback store warning: {warning}" for warning in store_result.warnings)
        expected_migration = _migration_plan(
            callback_store_manifest,
            target_engine=str(engine or ""),
            schema_ref=str(storage.get("schema_ref") or ""),
            migration_ref=str(migration.get("migration_ref") or ""),
            migration_hash=str(migration.get("migration_hash") or ""),
        )
        if migration != expected_migration:
            errors.append("provider callback storage migration_plan does not match supplied callback-store manifest")

    if provider_ingress_manifest is not None:
        ingress_provider_installations = _provider_installations_from_callback_sources(callback_store_source_artifacts)
        ingress_result = verify_provider_ingress_manifest(
            provider_ingress_manifest,
            provider_installations=ingress_provider_installations,
            callback_store_manifest=callback_store_manifest,
            callback_store_db_path=callback_store_db_path,
            callback_store_source_artifacts=callback_store_source_artifacts,
            key=key,
        )
        if not ingress_result.ok:
            errors.extend(f"provider callback storage ingress invalid: {error}" for error in ingress_result.errors)
        warnings.extend(f"provider callback storage ingress warning: {warning}" for warning in ingress_result.warnings)
    elif any(source.get("artifact_type") == "provider_ingress" for source in manifest_sources if isinstance(source, dict)):
        warnings.append("provider callback storage ingress manifest was not supplied; ingress hash was not replayed")

    if callback_store_manifest is not None or provider_ingress_manifest is not None:
        expected_sources = _source_artifact_records(
            callback_store_manifest=callback_store_manifest,
            provider_ingress_manifest=provider_ingress_manifest,
        )
        if manifest_sources != expected_sources:
            errors.append("provider callback storage source artifact summaries do not match supplied artifacts")

    controls = manifest.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("provider callback storage controls are required")
    _check_no_secret_values(manifest, errors)

    return ProviderCallbackStorageVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_callback_storage_manifest(
    chain: EvidenceChain,
    manifest: dict[str, Any],
    *,
    callback_store_manifest: dict[str, Any] | None = None,
    callback_store_db_path: str | Path | None = None,
    callback_store_source_artifacts: list[dict[str, Any]] | None = None,
    provider_ingress_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_callback_storage_manifest(
        manifest,
        callback_store_manifest=callback_store_manifest,
        callback_store_db_path=callback_store_db_path,
        callback_store_source_artifacts=callback_store_source_artifacts,
        provider_ingress_manifest=provider_ingress_manifest,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid provider callback storage manifest: " + "; ".join(result.errors))
    migration = manifest.get("migration_plan", {})
    payload = {
        "storage_manifest_id": manifest["storage_manifest_id"],
        "storage_manifest_hash": content_hash(manifest),
        "storage": {
            "mode": manifest.get("storage", {}).get("mode"),
            "environment": manifest.get("storage", {}).get("environment"),
            "storage_ref": manifest.get("storage", {}).get("storage_ref"),
            "engine": manifest.get("storage", {}).get("engine"),
            "schema_ref": manifest.get("storage", {}).get("schema_ref"),
            "retention_until": manifest.get("storage", {}).get("retention_until"),
        },
        "high_availability": manifest.get("high_availability"),
        "security_controls": without_keys(manifest.get("security_controls", {}), "encryption_key") if isinstance(manifest.get("security_controls"), dict) else {},
        "source_store_manifest_id": migration.get("source_store_manifest_id"),
        "source_operation_count": migration.get("source_operation_count"),
        "target_engine": migration.get("target_engine"),
        "source_artifact_count": len(manifest.get("source_artifacts", [])),
        "control_summary": _status_summary(manifest.get("controls", [])),
    }
    return chain.append(PROVIDER_CALLBACK_STORAGE_ENTRY_TYPE, payload, key=key, timestamp=manifest.get("generated_at"))


def load_provider_callback_storage_manifest(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider callback storage manifest must contain an object")
    return value


def write_provider_callback_storage_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def _provider_installations_from_callback_sources(
    artifacts: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    if artifacts is None:
        return None
    return [artifact for artifact in artifacts if artifact.get("schema") == "trustai.provider-installation/0.1"]


def _migration_plan(
    callback_store_manifest: dict[str, Any],
    *,
    target_engine: str,
    schema_ref: str,
    migration_ref: str,
    migration_hash: str,
) -> dict[str, Any]:
    database = callback_store_manifest.get("database", {}) if isinstance(callback_store_manifest.get("database"), dict) else {}
    summary = callback_store_manifest.get("summary", {}) if isinstance(callback_store_manifest.get("summary"), dict) else {}
    tables = database.get("tables", []) if isinstance(database.get("tables"), list) else []
    indexes = database.get("indexes", []) if isinstance(database.get("indexes"), list) else []
    return {
        "source_store_manifest_id": callback_store_manifest.get("store_manifest_id"),
        "source_store_hash": content_hash(callback_store_manifest),
        "source_database_engine": database.get("engine"),
        "source_database_schema_version": database.get("schema_version"),
        "source_operation_count": summary.get("operation_count"),
        "source_operation_type_counts": summary.get("operation_type_counts"),
        "source_tables": sorted(str(table.get("name")) for table in tables if isinstance(table, dict) and table.get("name")),
        "source_indexes": sorted(str(index.get("name")) for index in indexes if isinstance(index, dict) and index.get("name")),
        "target_engine": target_engine,
        "schema_ref": schema_ref,
        "migration_ref": migration_ref,
        "migration_hash": _normalize_sha256_ref(migration_hash),
        "required_tables": ["callback_operations", "metadata"],
    }


def _source_artifact_records(
    *,
    callback_store_manifest: dict[str, Any] | None,
    provider_ingress_manifest: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if callback_store_manifest is not None:
        summary = callback_store_manifest.get("summary", {}) if isinstance(callback_store_manifest.get("summary"), dict) else {}
        database = callback_store_manifest.get("database", {}) if isinstance(callback_store_manifest.get("database"), dict) else {}
        records.append(
            {
                "artifact_type": "provider_callback_store",
                "schema": callback_store_manifest.get("schema"),
                "store_manifest_id": callback_store_manifest.get("store_manifest_id"),
                "source_hash": content_hash(callback_store_manifest),
                "operation_count": summary.get("operation_count"),
                "operation_type_counts": summary.get("operation_type_counts"),
                "database_engine": database.get("engine"),
                "database_schema_version": database.get("schema_version"),
            }
        )
    if provider_ingress_manifest is not None:
        ingress = provider_ingress_manifest.get("ingress", {}) if isinstance(provider_ingress_manifest.get("ingress"), dict) else {}
        records.append(
            {
                "artifact_type": "provider_ingress",
                "schema": provider_ingress_manifest.get("schema"),
                "ingress_manifest_id": provider_ingress_manifest.get("ingress_manifest_id"),
                "source_hash": content_hash(provider_ingress_manifest),
                "base_url": ingress.get("base_url"),
                "endpoint_count": len(provider_ingress_manifest.get("endpoints", [])) if isinstance(provider_ingress_manifest.get("endpoints"), list) else None,
            }
        )
    return sorted(records, key=lambda item: (str(item.get("artifact_type")), str(item.get("store_manifest_id") or item.get("ingress_manifest_id"))))


def _migration_shape_errors(migration: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("source_store_manifest_id", "source_store_hash", "source_database_engine", "source_operation_count", "target_engine", "schema_ref", "migration_ref", "migration_hash"):
        if migration.get(field) in (None, "", []):
            errors.append(f"provider callback storage migration_plan missing {field}")
    if migration.get("target_engine") not in STORAGE_ENGINES:
        errors.append("provider callback storage migration_plan target_engine must be postgres or managed-postgres")
    if migration.get("migration_hash") and not str(migration.get("migration_hash")).startswith("sha256:"):
        errors.append("provider callback storage migration_hash must start with sha256:")
    if not isinstance(migration.get("required_tables"), list) or not {"callback_operations", "metadata"}.issubset(set(migration.get("required_tables", []))):
        errors.append("provider callback storage migration_plan required_tables must include callback_operations and metadata")
    return errors


def _controls(
    *,
    mode: str,
    engine: str,
    callback_store_manifest: dict[str, Any],
    provider_ingress_manifest: dict[str, Any] | None,
    min_replicas: int,
    primary_region: str | None,
    replica_regions: list[str] | None,
    backup_policy_ref: str | None,
    retention_until: str | None,
    encryption_key_ref: str | None,
    network_policy_ref: str | None,
    monitoring_ref: str | None,
    failover_runbook_ref: str | None,
) -> list[dict[str, Any]]:
    return [
        {
            "id": "postgres-callback-storage-target",
            "status": "implemented" if engine in STORAGE_ENGINES else "planned-production",
            "description": "Callback request storage targets a Postgres-compatible managed database rather than local SQLite.",
        },
        {
            "id": "sqlite-source-migration-binding",
            "status": "implemented" if callback_store_manifest else "planned-production",
            "description": "The migration plan is bound to a signed SQLite callback-store manifest and operation summary.",
        },
        {
            "id": "ha-topology",
            "status": "implemented" if min_replicas >= 2 and primary_region and replica_regions else "planned-production",
            "description": "The storage target records primary region, replicas, RPO, RTO, and failover runbook references.",
        },
        {
            "id": "backup-retention-policy",
            "status": "implemented" if backup_policy_ref and retention_until else "planned-production",
            "description": "Backup policy and retention horizon are recorded for callback request storage.",
        },
        {
            "id": "storage-security-boundary",
            "status": "implemented" if encryption_key_ref and network_policy_ref else "planned-production",
            "description": "Database encryption and network boundary controls are represented by redacted/keyed references.",
        },
        {
            "id": "storage-monitoring",
            "status": "implemented" if monitoring_ref else "planned-production",
            "description": "Monitoring and SLO evidence references are recorded for callback request storage.",
        },
        {
            "id": "ingress-storage-correlation",
            "status": "implemented" if provider_ingress_manifest else "planned-production",
            "description": "Public/BYOC ingress evidence is bound to the callback storage target.",
        },
        {
            "id": "live-managed-postgres-operations",
            "status": "implemented" if mode == "recorded-managed-postgres" else "planned-production",
            "description": "Live managed Postgres operation, backup execution, failover drills, and SLO telemetry are operationally evidenced.",
        },
    ]


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls if isinstance(controls, list) else []:
        if isinstance(control, dict):
            status = str(control.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _normalized_list(values: list[str] | None) -> list[str]:
    if not values:
        return []
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def _normalize_sha256_ref(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return normalized


def _require_text(value: str | None, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _check_no_secret_values(value: Any, errors: list[str], *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"provider callback storage secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")
