from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

PROVIDER_CALLBACK_STORE_SCHEMA = "trustai.provider-callback-store/0.1"
PROVIDER_CALLBACK_STORE_ENTRY_TYPE = "provider_callback_store.attested"
PROVIDER_CALLBACK_STORE_DB_SCHEMA_VERSION = "trustai.provider-callback-store-db/0.1"

SUPPORTED_OPERATION_TYPES = {
    "approval_callback",
    "approval_request",
    "provider_audit_correlation",
    "provider_audit_stream",
    "provider_delivery",
    "provider_installation",
    "provider_webhook",
}

ARTIFACT_SCHEMA_TO_OPERATION = {
    "trustai.approval-callback/0.1": "approval_callback",
    "trustai.slack-approval-request/0.1": "approval_request",
    "trustai.provider-audit-correlation/0.1": "provider_audit_correlation",
    "trustai.provider-audit-stream/0.1": "provider_audit_stream",
    "trustai.provider-delivery/0.1": "provider_delivery",
    "trustai.provider-installation/0.1": "provider_installation",
    "trustai.provider-webhook/0.1": "provider_webhook",
}

REQUIRED_INDEXES = {
    "idx_callback_operations_provider",
    "idx_callback_operations_operation_type",
    "idx_callback_operations_source_id",
    "idx_callback_operations_dedup_key",
    "idx_callback_operations_created_at",
}

SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ProviderCallbackStoreVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def init_provider_callback_store(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = _open_callback_store_connection(path)
    try:
        _initialize_provider_callback_store(conn)
    except sqlite3.OperationalError as exc:
        if "locked" not in str(exc).lower():
            conn.close()
            raise
        conn.close()
        conn = _open_callback_store_connection(path, nolock=True)
        _initialize_provider_callback_store(conn)
    return conn


def _open_callback_store_connection(path: Path, *, nolock: bool = False) -> sqlite3.Connection:
    if nolock:
        conn = sqlite3.connect(_sqlite_nolock_uri(path), timeout=2, uri=True)
    else:
        conn = sqlite3.connect(path, timeout=2)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 2000")
    return conn


def _sqlite_nolock_uri(path: Path) -> str:
    absolute = path if path.is_absolute() else path.resolve()
    posix = absolute.as_posix()
    if posix.startswith("//"):
        base = "file://" + posix
    else:
        try:
            base = absolute.as_uri()
        except ValueError:
            base = "file:" + posix
    separator = "&" if "?" in base else "?"
    return base + separator + "nolock=1"


def _initialize_provider_callback_store(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("PRAGMA journal_mode = WAL")
    except sqlite3.DatabaseError:
        try:
            conn.execute("PRAGMA journal_mode = DELETE")
        except sqlite3.DatabaseError:
            pass
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS callback_operations (
            operation_id TEXT PRIMARY KEY,
            operation_type TEXT NOT NULL,
            provider TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_hash TEXT NOT NULL,
            source_schema TEXT,
            received_at TEXT,
            dedup_key TEXT,
            status TEXT NOT NULL,
            payload_hash TEXT,
            redacted_summary_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_callback_operations_provider
            ON callback_operations(provider);
        CREATE INDEX IF NOT EXISTS idx_callback_operations_operation_type
            ON callback_operations(operation_type);
        CREATE INDEX IF NOT EXISTS idx_callback_operations_source_id
            ON callback_operations(source_id);
        CREATE INDEX IF NOT EXISTS idx_callback_operations_dedup_key
            ON callback_operations(dedup_key);
        CREATE INDEX IF NOT EXISTS idx_callback_operations_created_at
            ON callback_operations(created_at);
        """
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
        ("schema_version", PROVIDER_CALLBACK_STORE_DB_SCHEMA_VERSION),
    )
    conn.commit()


def record_callback_operation(
    db_path: str | Path,
    artifact: dict[str, Any],
    *,
    artifact_type: str | None = None,
    recorded_at: str | None = None,
) -> dict[str, Any]:
    conn = init_provider_callback_store(db_path)
    try:
        record = infer_callback_operation(artifact, artifact_type=artifact_type, recorded_at=recorded_at)
        _insert_operation(conn, record)
        conn.commit()
        return record
    finally:
        conn.close()


def build_provider_callback_store_manifest(
    db_path: str | Path,
    *,
    source_artifacts: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    retention_until: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    if retention_until and parse_rfc3339(retention_until) <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after generated_at")

    conn = init_provider_callback_store(db_path)
    try:
        for artifact in source_artifacts or []:
            _insert_operation(conn, infer_callback_operation(artifact, recorded_at=timestamp))
        conn.commit()
        database = _database_record(Path(db_path), conn, retention_until=retention_until)
        summary = _store_summary(conn)
    finally:
        conn.close()

    source_records = _source_artifact_records(source_artifacts or [])
    body = {
        "schema": PROVIDER_CALLBACK_STORE_SCHEMA,
        "generated_at": timestamp,
        "database": database,
        "summary": summary,
        "source_artifacts": source_records,
        "controls": _controls(summary, source_records, retention_until=retention_until),
        "limitations": [
            "This manifest attests a local SQLite provider callback operation store for offline verification and BYOC pilots.",
            "It does not claim managed Postgres high availability, hosted OAuth execution, public ingress ownership, or provider log streaming.",
            "Stored operation summaries are redacted; raw provider secrets, webhook signatures, and approval identities are not persisted in the manifest.",
        ],
    }
    manifest_id = content_hash(body)
    return {
        **body,
        "store_manifest_id": manifest_id,
        "signatures": [sign_value({"store_manifest_id": manifest_id, "provider_callback_store": body}, key)],
    }


def verify_provider_callback_store_manifest(
    manifest: dict[str, Any],
    *,
    db_path: str | Path | None = None,
    source_artifacts: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> ProviderCallbackStoreVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if manifest.get("schema") != PROVIDER_CALLBACK_STORE_SCHEMA:
        errors.append(f"unsupported provider callback store schema: {manifest.get('schema')}")
    body = without_keys(manifest, "store_manifest_id", "signatures")
    expected_id = content_hash(body)
    if manifest.get("store_manifest_id") != expected_id:
        errors.append("store_manifest_id does not match canonical provider callback store body")

    signatures = manifest.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider callback store manifest must include at least one signature")
    else:
        signed_value = {
            "store_manifest_id": manifest.get("store_manifest_id"),
            "provider_callback_store": body,
        }
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider callback store signature verification failed")

    try:
        generated_at = parse_rfc3339(str(manifest.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"provider callback store generated_at invalid: {exc}")
        generated_at = None

    database = manifest.get("database", {})
    if not isinstance(database, dict):
        errors.append("provider callback store database must be an object")
        database = {}
    retention_until = database.get("retention_until")
    if retention_until:
        try:
            retention = parse_rfc3339(str(retention_until))
            if generated_at and retention <= generated_at:
                errors.append("provider callback store retention_until must be after generated_at")
        except ValueError as exc:
            errors.append(f"provider callback store retention_until invalid: {exc}")

    manifest_summary = manifest.get("summary", {})
    if not isinstance(manifest_summary, dict):
        errors.append("provider callback store summary must be an object")
        manifest_summary = {}
    errors.extend(_summary_shape_errors(manifest_summary))
    errors.extend(_secret_value_errors(manifest_summary, context="provider callback store summary"))

    live_db_path = Path(db_path or database.get("path") or "")
    if not str(live_db_path):
        errors.append("provider callback store database path is required for verification")
    elif not live_db_path.exists():
        errors.append(f"provider callback store database not found: {live_db_path}")
    else:
        try:
            conn = _connect_existing(live_db_path)
            try:
                live_database = _database_record(live_db_path, conn, retention_until=retention_until)
                live_summary = _store_summary(conn)
                errors.extend(_database_mismatch_errors(database, live_database))
                if manifest_summary != live_summary:
                    errors.append("provider callback store summary does not match SQLite database contents")
                missing_indexes = REQUIRED_INDEXES - {index.get("name") for index in live_database.get("indexes", [])}
                for index_name in sorted(missing_indexes):
                    errors.append(f"provider callback store required index missing: {index_name}")
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            errors.append(f"provider callback store database read failed: {exc}")
    if db_path is not None and database.get("path") and str(Path(db_path)) != str(database.get("path")):
        warnings.append("provider callback store verified from a different database path than the manifest records")

    source_records = _source_artifact_records(source_artifacts or [])
    manifest_sources = manifest.get("source_artifacts", [])
    if not isinstance(manifest_sources, list):
        errors.append("provider callback store source_artifacts must be a list")
        manifest_sources = []
    if source_artifacts is None:
        if manifest_sources:
            errors.append("provider callback store source artifacts are required for verification")
    elif source_records != manifest_sources:
        errors.append("provider callback store source artifact summaries do not match supplied artifacts")

    controls = manifest.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("provider callback store controls are required")

    return ProviderCallbackStoreVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_callback_store_manifest(
    chain: EvidenceChain,
    manifest: dict[str, Any],
    *,
    db_path: str | Path | None = None,
    source_artifacts: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_callback_store_manifest(
        manifest,
        db_path=db_path,
        source_artifacts=source_artifacts,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid provider callback store manifest: " + "; ".join(result.errors))
    summary = manifest.get("summary", {})
    payload = {
        "store_manifest_id": manifest["store_manifest_id"],
        "store_manifest_hash": content_hash(manifest),
        "database": {
            "engine": manifest.get("database", {}).get("engine"),
            "schema_version": manifest.get("database", {}).get("schema_version"),
            "journal_mode": manifest.get("database", {}).get("journal_mode"),
            "retention_until": manifest.get("database", {}).get("retention_until"),
        },
        "operation_count": summary.get("operation_count"),
        "operation_type_counts": summary.get("operation_type_counts"),
        "provider_counts": summary.get("provider_counts"),
        "source_artifact_count": len(manifest.get("source_artifacts", [])),
        "control_summary": _status_summary(manifest.get("controls", [])),
    }
    return chain.append(PROVIDER_CALLBACK_STORE_ENTRY_TYPE, payload, key=key, timestamp=manifest.get("generated_at"))


def infer_callback_operation(
    artifact: dict[str, Any],
    *,
    artifact_type: str | None = None,
    recorded_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(artifact, dict):
        raise ValueError("callback operation artifact must be an object")
    operation_type = artifact_type or ARTIFACT_SCHEMA_TO_OPERATION.get(str(artifact.get("schema") or ""))
    if operation_type not in SUPPORTED_OPERATION_TYPES:
        raise ValueError(f"unsupported callback operation artifact schema: {artifact.get('schema')}")
    source_id = _source_id(artifact, operation_type)
    if not source_id:
        raise ValueError(f"{operation_type} artifact missing source id")
    provider = _provider(artifact, operation_type)
    if not provider:
        raise ValueError(f"{operation_type} artifact missing provider")
    source_hash = content_hash(artifact)
    created_at = recorded_at or _timestamp(artifact, operation_type) or utc_now()
    parse_rfc3339(created_at)
    received_at = _timestamp(artifact, operation_type)
    if received_at:
        parse_rfc3339(received_at)
    summary = _redacted_summary(artifact, operation_type)
    secret_errors = _secret_value_errors(summary, context=f"{operation_type} redacted summary")
    if secret_errors:
        raise ValueError("; ".join(secret_errors))
    basis = {
        "operation_type": operation_type,
        "source_id": source_id,
        "source_hash": source_hash,
    }
    return {
        "operation_id": content_hash(basis),
        "operation_type": operation_type,
        "provider": provider,
        "source_id": source_id,
        "source_hash": source_hash,
        "source_schema": artifact.get("schema"),
        "received_at": received_at,
        "dedup_key": _dedup_key(artifact, operation_type),
        "status": _status(artifact, operation_type),
        "payload_hash": _payload_hash(artifact, operation_type),
        "redacted_summary": summary,
        "created_at": created_at,
    }


def load_provider_callback_source_artifact(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider callback source artifact must contain an object")
    return value


def load_provider_callback_store_manifest(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider callback store manifest must contain an object")
    return value


def write_provider_callback_store_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def _insert_operation(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO callback_operations(
            operation_id, operation_type, provider, source_id, source_hash,
            source_schema, received_at, dedup_key, status, payload_hash,
            redacted_summary_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["operation_id"],
            record["operation_type"],
            record["provider"],
            record["source_id"],
            record["source_hash"],
            record.get("source_schema"),
            record.get("received_at"),
            record.get("dedup_key"),
            record["status"],
            record.get("payload_hash"),
            _json(record["redacted_summary"]),
            record["created_at"],
        ),
    )


def _connect_existing(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    conn = _open_callback_store_connection(path)
    try:
        conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
        return conn
    except sqlite3.DatabaseError as exc:
        conn.close()
        if "locked" not in str(exc).lower():
            raise
        return _open_callback_store_connection(path, nolock=True)


def _database_record(path: Path, conn: sqlite3.Connection, *, retention_until: str | None) -> dict[str, Any]:
    return {
        "engine": "sqlite",
        "path": str(path),
        "schema_version": _metadata_value(conn, "schema_version"),
        "journal_mode": _journal_mode(conn),
        "retention_until": retention_until,
        "tables": _tables(conn),
        "indexes": _indexes(conn),
    }


def _store_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT operation_id, operation_type, provider, source_id, source_hash,
               source_schema, received_at, dedup_key, status, payload_hash,
               redacted_summary_json, created_at
        FROM callback_operations
        ORDER BY operation_type, provider, source_id, operation_id
        """
    ).fetchall()
    operations = [_operation_summary(dict(row)) for row in rows]
    return {
        "operation_count": len(operations),
        "operation_type_counts": _count_by(operations, "operation_type"),
        "provider_counts": _count_by(operations, "provider"),
        "status_counts": _count_by(operations, "status"),
        "operations": operations,
    }


def _operation_summary(row: dict[str, Any]) -> dict[str, Any]:
    redacted_summary = json.loads(row["redacted_summary_json"])
    return {
        "operation_id": row["operation_id"],
        "operation_type": row["operation_type"],
        "provider": row["provider"],
        "source_id": row["source_id"],
        "source_hash": row["source_hash"],
        "source_schema": row.get("source_schema"),
        "received_at": row.get("received_at"),
        "dedup_key": row.get("dedup_key"),
        "status": row["status"],
        "payload_hash": row.get("payload_hash"),
        "redacted_summary": redacted_summary,
        "redacted_summary_hash": content_hash(redacted_summary),
        "created_at": row["created_at"],
    }


def _source_artifact_records(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records = []
    for artifact in artifacts:
        operation_type = ARTIFACT_SCHEMA_TO_OPERATION.get(str(artifact.get("schema") or ""))
        if operation_type not in SUPPORTED_OPERATION_TYPES:
            raise ValueError(f"unsupported callback operation artifact schema: {artifact.get('schema')}")
        records.append(
            {
                "artifact_type": operation_type,
                "schema": artifact.get("schema"),
                "source_id": _source_id(artifact, operation_type),
                "source_hash": content_hash(artifact),
                "provider": _provider(artifact, operation_type),
            }
        )
    return sorted(records, key=lambda item: (str(item.get("artifact_type")), str(item.get("source_id"))))


def _tables(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = []
    for row in rows:
        name = row["name"]
        columns = [
            {
                "name": column["name"],
                "type": column["type"],
                "notnull": bool(column["notnull"]),
                "primary_key": bool(column["pk"]),
            }
            for column in conn.execute(f"PRAGMA table_info({name})").fetchall()
        ]
        tables.append({"name": name, "columns": columns})
    return tables


def _indexes(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT name, tbl_name, sql
        FROM sqlite_master
        WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    ).fetchall()
    return [
        {
            "name": row["name"],
            "table": row["tbl_name"],
            "sql": " ".join(str(row["sql"] or "").split()),
        }
        for row in rows
    ]


def _database_mismatch_errors(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("engine", "schema_version", "journal_mode", "tables", "indexes"):
        if expected.get(field) != actual.get(field):
            errors.append(f"provider callback store database {field} does not match SQLite database")
    return errors


def _summary_shape_errors(summary: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    operations = summary.get("operations")
    if not isinstance(operations, list):
        return ["provider callback store summary.operations must be a list"]
    if summary.get("operation_count") != len(operations):
        errors.append("provider callback store summary operation_count does not match operations length")
    for operation in operations:
        if not isinstance(operation, dict):
            errors.append("provider callback store operation summary must be an object")
            continue
        for field in ("operation_id", "operation_type", "provider", "source_id", "source_hash", "status", "created_at"):
            if not operation.get(field):
                errors.append(f"provider callback store operation missing {field}")
        if operation.get("operation_type") not in SUPPORTED_OPERATION_TYPES:
            errors.append(f"unsupported provider callback store operation_type: {operation.get('operation_type')}")
        if not isinstance(operation.get("redacted_summary"), dict):
            errors.append("provider callback store operation redacted_summary must be an object")
        elif operation.get("redacted_summary_hash") != content_hash(operation["redacted_summary"]):
            errors.append("provider callback store operation redacted_summary_hash mismatch")
    return errors


def _source_id(artifact: dict[str, Any], operation_type: str) -> str | None:
    fields = {
        "approval_callback": "callback_id",
        "approval_request": "approval_request_id",
        "provider_audit_correlation": "correlation_id",
        "provider_audit_stream": "stream_receipt_id",
        "provider_delivery": "delivery_id",
        "provider_installation": "manifest_id",
        "provider_webhook": "receipt_id",
    }
    value = artifact.get(fields[operation_type])
    return str(value) if value else None


def _provider(artifact: dict[str, Any], operation_type: str) -> str | None:
    provider = artifact.get("provider")
    if provider:
        return str(provider).strip().lower()
    if operation_type in {"approval_callback", "approval_request"}:
        return "slack"
    return None


def _timestamp(artifact: dict[str, Any], operation_type: str) -> str | None:
    fields = {
        "approval_callback": "approved_at",
        "approval_request": "requested_at",
        "provider_audit_correlation": "correlated_at",
        "provider_audit_stream": "recorded_at",
        "provider_delivery": "delivered_at",
        "provider_installation": "installed_at",
        "provider_webhook": "received_at",
    }
    value = artifact.get(fields[operation_type])
    return str(value) if value else None


def _dedup_key(artifact: dict[str, Any], operation_type: str) -> str:
    if operation_type == "provider_delivery":
        return str(artifact.get("idempotency_key") or content_hash(artifact))
    if operation_type == "provider_webhook":
        webhook = artifact.get("webhook", {}) if isinstance(artifact.get("webhook"), dict) else {}
        payload = artifact.get("payload", {}) if isinstance(artifact.get("payload"), dict) else {}
        return content_hash(
            {
                "provider": artifact.get("provider"),
                "event": webhook.get("event"),
                "delivery_id": webhook.get("delivery_id"),
                "payload_sha256": payload.get("sha256"),
            }
        )
    if operation_type == "provider_audit_stream":
        stream = artifact.get("stream", {}) if isinstance(artifact.get("stream"), dict) else {}
        return content_hash(
            {
                "provider": artifact.get("provider"),
                "stream_ref": stream.get("stream_ref"),
                "window_start": stream.get("window_start"),
                "window_end": stream.get("window_end"),
                "cursor_ref": stream.get("cursor_ref"),
                "next_cursor_ref": stream.get("next_cursor_ref"),
            }
        )
    if operation_type == "provider_installation":
        installation = artifact.get("installation", {}) if isinstance(artifact.get("installation"), dict) else {}
        app = artifact.get("app", {}) if isinstance(artifact.get("app"), dict) else {}
        return content_hash(
            {
                "provider": artifact.get("provider"),
                "app_ref": app.get("app_ref"),
                "installation_ref": installation.get("installation_ref"),
                "tenant_ref": installation.get("tenant_ref"),
            }
        )
    if operation_type == "approval_callback":
        return content_hash(
            {
                "approval_request_id": artifact.get("approval_request_id"),
                "role": artifact.get("role"),
                "action_value": artifact.get("action_value"),
            }
        )
    return content_hash({"operation_type": operation_type, "source_id": _source_id(artifact, operation_type)})


def _status(artifact: dict[str, Any], operation_type: str) -> str:
    if operation_type == "provider_installation":
        return str(artifact.get("mode") or "recorded")
    if operation_type == "provider_webhook":
        verification = artifact.get("verification", {}) if isinstance(artifact.get("verification"), dict) else {}
        return "signature-verified" if verification.get("provider_signature_verified") is True else "recorded"
    if operation_type == "provider_delivery":
        response = artifact.get("response", {}) if isinstance(artifact.get("response"), dict) else {}
        if response.get("accepted") is True:
            return "accepted"
        if response.get("status") is not None:
            return "rejected"
        return str(artifact.get("mode") or "dry-run")
    if operation_type == "provider_audit_correlation":
        return "correlated"
    if operation_type == "provider_audit_stream":
        stream = artifact.get("stream", {}) if isinstance(artifact.get("stream"), dict) else {}
        return "stream-accepted" if stream.get("success") is True else str(artifact.get("mode") or "recorded")
    if operation_type == "approval_request":
        return "pending"
    if operation_type == "approval_callback":
        return "approved"
    return "recorded"


def _payload_hash(artifact: dict[str, Any], operation_type: str) -> str | None:
    if operation_type == "provider_webhook":
        payload = artifact.get("payload", {}) if isinstance(artifact.get("payload"), dict) else {}
        return payload.get("sha256")
    if operation_type == "provider_delivery":
        return artifact.get("payload_hash")
    if operation_type == "provider_audit_correlation":
        audit_log = artifact.get("audit_log", {}) if isinstance(artifact.get("audit_log"), dict) else {}
        return audit_log.get("hash")
    if operation_type == "provider_audit_stream":
        audit_log = artifact.get("audit_log", {}) if isinstance(artifact.get("audit_log"), dict) else {}
        return audit_log.get("hash")
    if operation_type in {"approval_request", "approval_callback"}:
        return artifact.get("payload_hash") or artifact.get("request_payload_hash")
    return content_hash(artifact)


def _redacted_summary(artifact: dict[str, Any], operation_type: str) -> dict[str, Any]:
    if operation_type == "provider_installation":
        app = artifact.get("app", {}) if isinstance(artifact.get("app"), dict) else {}
        installation = artifact.get("installation", {}) if isinstance(artifact.get("installation"), dict) else {}
        capabilities = artifact.get("capabilities", {}) if isinstance(artifact.get("capabilities"), dict) else {}
        webhook = artifact.get("webhook", {}) if isinstance(artifact.get("webhook"), dict) else {}
        audit_log = artifact.get("audit_log", {}) if isinstance(artifact.get("audit_log"), dict) else {}
        return {
            "manifest_id": artifact.get("manifest_id"),
            "mode": artifact.get("mode"),
            "app_ref": app.get("app_ref"),
            "installation_ref": installation.get("installation_ref"),
            "tenant_ref": installation.get("tenant_ref"),
            "owner": installation.get("owner"),
            "repository": installation.get("repository"),
            "permissions": capabilities.get("permissions", []),
            "scopes": capabilities.get("scopes", []),
            "events": capabilities.get("events", []),
            "webhook_url": webhook.get("url"),
            "callback_url": webhook.get("callback_url"),
            "webhook_auth_configured": bool(webhook.get("secret")),
            "provider_app_auth_configured": bool(artifact.get("credential")),
            "audit_log_ref": audit_log.get("ref"),
            "audit_log_scopes": audit_log.get("scopes", []),
        }
    if operation_type == "provider_webhook":
        webhook = artifact.get("webhook", {}) if isinstance(artifact.get("webhook"), dict) else {}
        payload = artifact.get("payload", {}) if isinstance(artifact.get("payload"), dict) else {}
        verification = artifact.get("verification", {}) if isinstance(artifact.get("verification"), dict) else {}
        request_headers = artifact.get("request_headers", {}) if isinstance(artifact.get("request_headers"), dict) else {}
        return {
            "receipt_id": artifact.get("receipt_id"),
            "event": webhook.get("event"),
            "delivery_id": webhook.get("delivery_id"),
            "payload": payload,
            "request_headers": request_headers,
            "verification_method": verification.get("method"),
            "verification_header": verification.get("header"),
            "verification_value_hash": verification.get("value_hash"),
        }
    if operation_type == "provider_delivery":
        request = artifact.get("request", {}) if isinstance(artifact.get("request"), dict) else {}
        response = artifact.get("response", {}) if isinstance(artifact.get("response"), dict) else None
        return {
            "delivery_id": artifact.get("delivery_id"),
            "mode": artifact.get("mode"),
            "target_url": artifact.get("target_url"),
            "request": request,
            "response": response,
            "provider_app_auth_configured": bool(artifact.get("credential")),
            "provider_auth_binding_hash": content_hash(artifact.get("credential")) if artifact.get("credential") else None,
        }
    if operation_type == "provider_audit_correlation":
        return {
            "correlation_id": artifact.get("correlation_id"),
            "audit_log": artifact.get("audit_log"),
            "audit_log_ref": artifact.get("audit_log_ref"),
            "source_receipts": artifact.get("source_receipts", []),
            "match_count": len(artifact.get("matches", [])) if isinstance(artifact.get("matches"), list) else 0,
            "match_hash": content_hash(artifact.get("matches", [])),
        }
    if operation_type == "provider_audit_stream":
        stream = artifact.get("stream", {}) if isinstance(artifact.get("stream"), dict) else {}
        bindings = artifact.get("bindings", {}) if isinstance(artifact.get("bindings"), dict) else {}
        return {
            "stream_receipt_id": artifact.get("stream_receipt_id"),
            "mode": artifact.get("mode"),
            "stream_ref": stream.get("stream_ref"),
            "audit_log_ref": stream.get("audit_log_ref"),
            "endpoint_url": stream.get("endpoint_url"),
            "window_start": stream.get("window_start"),
            "window_end": stream.get("window_end"),
            "cursor_ref": stream.get("cursor_ref"),
            "next_cursor_ref": stream.get("next_cursor_ref"),
            "request_hash": stream.get("request_hash"),
            "response_status": stream.get("response_status"),
            "response_hash": stream.get("response_hash"),
            "success": stream.get("success"),
            "audit_log": artifact.get("audit_log"),
            "provider_audit_auth_configured": bool(artifact.get("credential")),
            "provider_audit_auth_binding_hash": content_hash(artifact.get("credential")) if artifact.get("credential") else None,
            "binding_keys": sorted(bindings.keys()),
        }
    if operation_type == "approval_request":
        return {
            "approval_request_id": artifact.get("approval_request_id"),
            "pack_id": artifact.get("pack_id"),
            "contract_id": artifact.get("contract_id"),
            "contract_hash": artifact.get("contract_hash"),
            "channel": artifact.get("channel"),
            "requester_hash": content_hash(artifact.get("requester")) if artifact.get("requester") else None,
            "requested_roles": artifact.get("requested_roles", []),
            "missing_roles": artifact.get("missing_roles", []),
            "expires_at": artifact.get("expires_at"),
            "callback_url": artifact.get("callback_url"),
        }
    if operation_type == "approval_callback":
        return {
            "callback_id": artifact.get("callback_id"),
            "approval_request_id": artifact.get("approval_request_id"),
            "pack_id": artifact.get("pack_id"),
            "contract_id": artifact.get("contract_id"),
            "contract_hash": artifact.get("contract_hash"),
            "channel": artifact.get("channel"),
            "role": artifact.get("role"),
            "approver_hash": content_hash(artifact.get("approver")) if artifact.get("approver") else None,
            "external_user_id_hash": content_hash(artifact.get("external_user_id")) if artifact.get("external_user_id") else None,
            "team_id": artifact.get("team_id"),
        }
    raise ValueError(f"unsupported callback operation type: {operation_type}")


def _controls(
    summary: dict[str, Any],
    source_records: list[dict[str, Any]],
    *,
    retention_until: str | None,
) -> list[dict[str, Any]]:
    operation_count = int(summary.get("operation_count") or 0)
    return [
        {
            "id": "sqlite-callback-operation-store",
            "status": "implemented-reference" if operation_count else "empty-reference",
            "description": "Callback operations are persisted in a SQLite table with canonical operation identifiers.",
        },
        {
            "id": "callback-operation-indexes",
            "status": "implemented-reference",
            "description": "Provider, operation type, source id, deduplication key, and created-at indexes support operational lookups.",
        },
        {
            "id": "redacted-callback-summaries",
            "status": "implemented-reference",
            "description": "Operation summaries omit raw provider secrets, webhook signatures, provider credentials, and approval identities.",
        },
        {
            "id": "source-artifact-binding",
            "status": "implemented-reference" if source_records else "not-supplied",
            "description": "Source provider artifacts are bound by schema, source id, provider, and canonical hash.",
        },
        {
            "id": "retention-bound",
            "status": "implemented-reference" if retention_until else "planned-production",
            "description": "Retention horizon is recorded for callback database evidence and later WORM/Postgres migration.",
        },
        {
            "id": "managed-postgres-callback-store",
            "status": "planned-production",
            "description": "Production deployments should migrate this reference store to HA Postgres with backups and operational SLOs.",
        },
    ]


def _metadata_value(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = conn.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
    except sqlite3.DatabaseError:
        return None
    return str(row["value"]) if row else None


def _journal_mode(conn: sqlite3.Connection) -> str:
    try:
        row = conn.execute("PRAGMA journal_mode").fetchone()
    except sqlite3.DatabaseError:
        return "unknown"
    return str(row[0]).lower() if row else "unknown"


def _count_by(items: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(field) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _secret_value_errors(value: Any, *, context: str, path: str = "") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            normalized = str(key).lower()
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"{context} contains unredacted secret-like field: {child_path}")
            errors.extend(_secret_value_errors(item, context=context, path=child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_secret_value_errors(item, context=context, path=f"{path}[{index}]"))
    return errors


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
