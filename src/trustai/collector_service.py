from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .byoc_operator import verify_byoc_operator_attestation
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .collector_topology import verify_collector_topology
from .crypto import sign_value, verify_value

COLLECTOR_SERVICE_SCHEMA = "trustai.collector-service-attestation/0.1"
COLLECTOR_SERVICE_ENTRY_TYPE = "collector.service_attested"
COLLECTOR_SERVICE_MODES = {"local-reference", "byoc-service-attested", "production-design"}
STREAM_BACKENDS = {"kafka", "redpanda", "local-reference"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class CollectorServiceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_collector_service_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("collector service attestation must contain an object")
    return value


def write_collector_service_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_collector_service_attestation(
    topology: dict[str, Any],
    *,
    byoc_operator: dict[str, Any] | None = None,
    deployment_manifest: dict[str, Any] | None = None,
    worm_receipt: dict[str, Any] | None = None,
    legal_hold: dict[str, Any] | None = None,
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
    mode: str = "byoc-service-attested",
    environment: str = "local",
    service_ref: str,
    service_version: str,
    collector_image: str,
    collector_image_digest: str,
    collector_binary_hash: str,
    replicas_min: int,
    replicas_max: int,
    availability_zones: list[str] | None = None,
    mtls_policy_ref: str,
    auth_policy_ref: str,
    tenant_isolation_ref: str,
    rate_limit_policy_ref: str,
    replay_cache_ref: str,
    idempotency_store_ref: str,
    ingress_ref: str,
    network_policy_ref: str,
    egress_policy_ref: str,
    stream_backend: str = "redpanda",
    stream_ref: str,
    stream_topic: str,
    stream_retention_hours: int,
    stream_tls: bool = True,
    stream_dlq_ref: str,
    clickhouse_ref: str,
    clickhouse_retention_days: int,
    clickhouse_backup_ref: str,
    postgres_ref: str,
    postgres_schema_hash: str,
    postgres_backup_ref: str,
    mcp_proxy_ref: str,
    mcp_proxy_image_digest: str,
    framework_hook_refs: list[str] | None = None,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in COLLECTOR_SERVICE_MODES:
        raise ValueError(f"mode must be one of {sorted(COLLECTOR_SERVICE_MODES)}")
    if stream_backend not in STREAM_BACKENDS:
        raise ValueError(f"stream_backend must be one of {sorted(STREAM_BACKENDS)}")

    topology_result = verify_collector_topology(topology, root=root)
    if not topology_result.ok:
        raise ValueError("invalid collector topology: " + "; ".join(topology_result.errors))

    if byoc_operator is not None:
        byoc_result = verify_byoc_operator_attestation(
            byoc_operator,
            deployment_manifest,
            worm_receipt,
            legal_hold=legal_hold,
            root=root,
            store=store,
        )
        if not byoc_result.ok:
            raise ValueError("invalid BYOC operator attestation: " + "; ".join(byoc_result.errors))

    timestamp = attested_at or utc_now()
    parse_rfc3339(timestamp)
    audit_retention = parse_rfc3339(retention_until)
    if audit_retention <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after attested_at")

    for field, value in {
        "service_ref": service_ref,
        "service_version": service_version,
        "collector_image": collector_image,
        "collector_image_digest": collector_image_digest,
        "collector_binary_hash": collector_binary_hash,
        "mtls_policy_ref": mtls_policy_ref,
        "auth_policy_ref": auth_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "replay_cache_ref": replay_cache_ref,
        "idempotency_store_ref": idempotency_store_ref,
        "ingress_ref": ingress_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "stream_ref": stream_ref,
        "stream_topic": stream_topic,
        "stream_dlq_ref": stream_dlq_ref,
        "clickhouse_ref": clickhouse_ref,
        "clickhouse_backup_ref": clickhouse_backup_ref,
        "postgres_ref": postgres_ref,
        "postgres_schema_hash": postgres_schema_hash,
        "postgres_backup_ref": postgres_backup_ref,
        "mcp_proxy_ref": mcp_proxy_ref,
        "mcp_proxy_image_digest": mcp_proxy_image_digest,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
    }.items():
        _require_text(value, field)

    service = {
        "service_ref": service_ref,
        "version": service_version,
        "collector_image": collector_image,
        "collector_image_digest": collector_image_digest,
        "collector_binary_hash": collector_binary_hash,
        "replicas_min": replicas_min,
        "replicas_max": replicas_max,
        "availability_zones": sorted(availability_zones or []),
    }
    security = {
        "mtls_policy_ref": mtls_policy_ref,
        "auth_policy_ref": auth_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "rate_limit_policy_ref": rate_limit_policy_ref,
        "replay_cache_ref": replay_cache_ref,
        "idempotency_store_ref": idempotency_store_ref,
        "ingress_ref": ingress_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
    }
    streaming = {
        "backend": stream_backend,
        "stream_ref": stream_ref,
        "topic": stream_topic,
        "retention_hours": stream_retention_hours,
        "tls": stream_tls,
        "dead_letter_queue_ref": stream_dlq_ref,
    }
    storage = {
        "clickhouse": {
            "ref": clickhouse_ref,
            "retention_days": clickhouse_retention_days,
            "backup_ref": clickhouse_backup_ref,
        },
        "postgres": {
            "ref": postgres_ref,
            "schema_hash": postgres_schema_hash,
            "backup_ref": postgres_backup_ref,
        },
    }
    mcp_proxy = {
        "proxy_ref": mcp_proxy_ref,
        "image_digest": mcp_proxy_image_digest,
        "framework_hook_refs": sorted(framework_hook_refs or []),
    }
    operation = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    audit_log = {
        "audit_log_ref": audit_log_ref,
        "root": audit_log_root,
        "retention_until": retention_until,
    }
    source = _source_record(topology, byoc_operator)
    body: dict[str, Any] = {
        "schema": COLLECTOR_SERVICE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": source,
        "topology": _topology_record(topology),
        "byoc_operator": _byoc_record(byoc_operator),
        "service": service,
        "security": security,
        "streaming": streaming,
        "storage": storage,
        "mcp_proxy": mcp_proxy,
        "operation": operation,
        "audit_log": audit_log,
        "source_artifacts": _source_artifacts(topology, byoc_operator),
        "controls": _controls(service, security, streaming, storage, mcp_proxy),
        "limitations": [
            "This attestation binds the collector topology to production-service hardening evidence.",
            "It records service image digests, mTLS/authn/z, replay protection, rate limits, network policy, streaming, ClickHouse, Postgres, MCP proxy, framework hook, and audit evidence.",
            "It stores redacted credential references and hashes, not raw provider credentials or raw trace payloads.",
            "Production deployments should replace local references with continuously operated collector, streaming, analytics, and control-plane service evidence.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "collector_service": body}, key)],
    }


def verify_collector_service_attestation(
    attestation: dict[str, Any],
    topology: dict[str, Any] | None = None,
    *,
    byoc_operator: dict[str, Any] | None = None,
    deployment_manifest: dict[str, Any] | None = None,
    worm_receipt: dict[str, Any] | None = None,
    legal_hold: dict[str, Any] | None = None,
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
    key: str | None = None,
) -> CollectorServiceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != COLLECTOR_SERVICE_SCHEMA:
        errors.append(f"unsupported collector service attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical collector service attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("collector service attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "collector_service": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("collector service attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"collector service attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in COLLECTOR_SERVICE_MODES:
        errors.append("collector service mode is unsupported")
    elif mode != "byoc-service-attested":
        warnings.append(f"collector service mode is {mode}; live production service operation is not fully claimed")

    _verify_source_record(attestation.get("source"), errors)
    _verify_topology_record(attestation.get("topology"), errors)
    _verify_service(attestation.get("service"), errors)
    _verify_security(attestation.get("security"), errors)
    _verify_streaming(attestation.get("streaming"), errors)
    _verify_storage(attestation.get("storage"), errors)
    _verify_mcp_proxy(attestation.get("mcp_proxy"), errors)
    _verify_operation(attestation.get("operation"), errors)
    _verify_audit_log(attestation.get("audit_log"), attested, errors)

    controls = attestation.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("collector service controls are required")

    source_artifacts = attestation.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("collector service source_artifacts must contain at least the collector topology")

    supplied_sources = _source_artifacts(topology, byoc_operator)
    if supplied_sources:
        if source_artifacts != supplied_sources:
            errors.append("collector service source_artifacts do not match supplied source artifacts")
        expected_source = _source_record(topology, byoc_operator)
        if attestation.get("source") != expected_source:
            errors.append("collector service source record does not match supplied artifacts")
    else:
        warnings.append("collector service source artifacts were not supplied; topology hash was not replayed")

    if topology is not None:
        topology_result = verify_collector_topology(topology, root=root)
        if not topology_result.ok:
            errors.extend(f"collector topology invalid: {error}" for error in topology_result.errors)
        warnings.extend(f"collector topology: {warning}" for warning in topology_result.warnings)

    if byoc_operator is not None:
        byoc_result = verify_byoc_operator_attestation(
            byoc_operator,
            deployment_manifest,
            worm_receipt,
            legal_hold=legal_hold,
            root=root,
            store=store,
        )
        if not byoc_result.ok:
            errors.extend(f"BYOC operator attestation invalid: {error}" for error in byoc_result.errors)
        warnings.extend(f"BYOC operator: {warning}" for warning in byoc_result.warnings)

    _check_no_secret_values(attestation, errors)
    return CollectorServiceVerification(ok=not errors, errors=errors, warnings=warnings)


def append_collector_service_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    topology: dict[str, Any] | None = None,
    *,
    byoc_operator: dict[str, Any] | None = None,
    deployment_manifest: dict[str, Any] | None = None,
    worm_receipt: dict[str, Any] | None = None,
    legal_hold: dict[str, Any] | None = None,
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_collector_service_attestation(
        attestation,
        topology,
        byoc_operator=byoc_operator,
        deployment_manifest=deployment_manifest,
        worm_receipt=worm_receipt,
        legal_hold=legal_hold,
        root=root,
        store=store,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid collector service attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "source": attestation.get("source"),
        "topology": attestation.get("topology"),
        "byoc_operator": attestation.get("byoc_operator"),
        "service": attestation.get("service"),
        "security": attestation.get("security"),
        "streaming": attestation.get("streaming"),
        "storage": attestation.get("storage"),
        "mcp_proxy": attestation.get("mcp_proxy"),
        "operation": attestation.get("operation"),
        "audit_log": attestation.get("audit_log"),
        "source_artifacts": attestation.get("source_artifacts"),
        "control_summary": _status_summary(attestation.get("controls", [])),
    }
    return chain.append(COLLECTOR_SERVICE_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _source_record(topology: dict[str, Any] | None, byoc_operator: dict[str, Any] | None) -> dict[str, Any]:
    topology_meta = topology.get("topology", {}) if isinstance(topology, dict) else {}
    return {
        "topology_id": topology.get("topology_id") if isinstance(topology, dict) else None,
        "topology_hash": content_hash(topology) if isinstance(topology, dict) else None,
        "topology_mode": topology_meta.get("mode") if isinstance(topology_meta, dict) else None,
        "topology_environment": topology_meta.get("environment") if isinstance(topology_meta, dict) else None,
        "byoc_operator_attestation_id": byoc_operator.get("attestation_id") if isinstance(byoc_operator, dict) else None,
        "byoc_operator_hash": content_hash(byoc_operator) if isinstance(byoc_operator, dict) else None,
    }


def _topology_record(topology: dict[str, Any]) -> dict[str, Any]:
    topology_meta = topology.get("topology", {}) if isinstance(topology, dict) else {}
    return {
        "topology_id": topology.get("topology_id"),
        "topology_hash": content_hash(topology),
        "name": topology_meta.get("name") if isinstance(topology_meta, dict) else None,
        "mode": topology_meta.get("mode") if isinstance(topology_meta, dict) else None,
        "environment": topology_meta.get("environment") if isinstance(topology_meta, dict) else None,
        "endpoint_count": len(topology.get("endpoints", [])),
        "component_summary": _status_summary(topology.get("components", [])),
        "store_summary": _status_summary(topology.get("stores", [])),
        "control_summary": _status_summary(topology.get("controls", [])),
    }


def _byoc_record(byoc_operator: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(byoc_operator, dict):
        return None
    operator = byoc_operator.get("operator", {}) if isinstance(byoc_operator.get("operator"), dict) else {}
    tenancy = byoc_operator.get("tenancy", {}) if isinstance(byoc_operator.get("tenancy"), dict) else {}
    return {
        "attestation_id": byoc_operator.get("attestation_id"),
        "attestation_hash": content_hash(byoc_operator),
        "mode": byoc_operator.get("mode"),
        "operator_ref": operator.get("operator_ref"),
        "tenant_id": tenancy.get("tenant_id"),
    }


def _source_artifacts(topology: dict[str, Any] | None, byoc_operator: dict[str, Any] | None) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    if isinstance(topology, dict):
        artifacts.append(
            {
                "type": "collector-topology",
                "id": topology.get("topology_id"),
                "schema": topology.get("schema"),
                "hash": content_hash(topology),
            }
        )
    if isinstance(byoc_operator, dict):
        artifacts.append(
            {
                "type": "byoc-operator-attestation",
                "id": byoc_operator.get("attestation_id"),
                "schema": byoc_operator.get("schema"),
                "hash": content_hash(byoc_operator),
            }
        )
    return artifacts


def _verify_source_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector service source must be an object")
        return
    for field in ("topology_id", "topology_hash", "topology_mode", "topology_environment"):
        if not value.get(field):
            errors.append(f"collector service source.{field} is required")


def _verify_topology_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector service topology must be an object")
        return
    for field in ("topology_id", "topology_hash", "name", "mode", "environment"):
        if not value.get(field):
            errors.append(f"collector service topology.{field} is required")
    if not isinstance(value.get("component_summary"), dict) or not isinstance(value.get("store_summary"), dict):
        errors.append("collector service topology summaries are required")


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector service service must be an object")
        return
    for field in ("service_ref", "version", "collector_image", "collector_image_digest", "collector_binary_hash"):
        if not value.get(field):
            errors.append(f"collector service service.{field} is required")
    for field in ("collector_image_digest", "collector_binary_hash"):
        if not _is_sha256_ref(str(value.get(field) or "")):
            errors.append(f"collector service service.{field} must be a sha256 reference")
    replicas_min = value.get("replicas_min")
    replicas_max = value.get("replicas_max")
    if not isinstance(replicas_min, int) or replicas_min < 2:
        errors.append("collector service service.replicas_min must be an integer >= 2")
    if not isinstance(replicas_max, int) or not isinstance(replicas_min, int) or replicas_max < replicas_min:
        errors.append("collector service service.replicas_max must be >= replicas_min")
    if not isinstance(value.get("availability_zones"), list) or len(value.get("availability_zones")) < 2:
        errors.append("collector service service.availability_zones must include at least two zones")


def _verify_security(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector service security must be an object")
        return
    for field in (
        "mtls_policy_ref",
        "auth_policy_ref",
        "tenant_isolation_ref",
        "rate_limit_policy_ref",
        "replay_cache_ref",
        "idempotency_store_ref",
        "ingress_ref",
        "network_policy_ref",
        "egress_policy_ref",
    ):
        if not value.get(field):
            errors.append(f"collector service security.{field} is required")


def _verify_streaming(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector service streaming must be an object")
        return
    for field in ("backend", "stream_ref", "topic", "dead_letter_queue_ref"):
        if not value.get(field):
            errors.append(f"collector service streaming.{field} is required")
    if value.get("backend") not in STREAM_BACKENDS:
        errors.append("collector service streaming.backend is unsupported")
    if value.get("tls") is not True:
        errors.append("collector service streaming.tls must be true")
    if not isinstance(value.get("retention_hours"), int) or value.get("retention_hours") < 24:
        errors.append("collector service streaming.retention_hours must be an integer >= 24")


def _verify_storage(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector service storage must be an object")
        return
    clickhouse = value.get("clickhouse")
    postgres = value.get("postgres")
    if not isinstance(clickhouse, dict):
        errors.append("collector service storage.clickhouse must be an object")
    else:
        for field in ("ref", "backup_ref"):
            if not clickhouse.get(field):
                errors.append(f"collector service storage.clickhouse.{field} is required")
        if not isinstance(clickhouse.get("retention_days"), int) or clickhouse.get("retention_days") < 30:
            errors.append("collector service storage.clickhouse.retention_days must be an integer >= 30")
    if not isinstance(postgres, dict):
        errors.append("collector service storage.postgres must be an object")
    else:
        for field in ("ref", "schema_hash", "backup_ref"):
            if not postgres.get(field):
                errors.append(f"collector service storage.postgres.{field} is required")
        if not _is_sha256_ref(str(postgres.get("schema_hash") or "")):
            errors.append("collector service storage.postgres.schema_hash must be a sha256 reference")


def _verify_mcp_proxy(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector service mcp_proxy must be an object")
        return
    for field in ("proxy_ref", "image_digest"):
        if not value.get(field):
            errors.append(f"collector service mcp_proxy.{field} is required")
    if not _is_sha256_ref(str(value.get("image_digest") or "")):
        errors.append("collector service mcp_proxy.image_digest must be a sha256 reference")
    if not isinstance(value.get("framework_hook_refs"), list) or not value.get("framework_hook_refs"):
        errors.append("collector service mcp_proxy.framework_hook_refs must be a non-empty list")


def _verify_operation(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector service operation must be an object")
        return
    if not value.get("actor_ref"):
        errors.append("collector service operation.actor_ref is required")
    _verify_redacted_ref(value.get("credential"), "collector service operation.credential", errors)


def _verify_audit_log(value: Any, attested: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("collector service audit_log must be an object")
        return
    for field in ("audit_log_ref", "root", "retention_until"):
        if not value.get(field):
            errors.append(f"collector service audit_log.{field} is required")
    if not _is_sha256_ref(str(value.get("root") or "")):
        errors.append("collector service audit_log.root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("collector service audit_log.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"collector service audit_log.retention_until invalid: {exc}")


def _controls(
    service: dict[str, Any],
    security: dict[str, Any],
    streaming: dict[str, Any],
    storage: dict[str, Any],
    mcp_proxy: dict[str, Any],
) -> list[dict[str, str]]:
    return [
        {
            "id": "hardened-otel-collector",
            "status": "service-attested" if service.get("replicas_min", 0) >= 2 else "planned-production",
            "description": "Collector image, digest, binary hash, replica floor, and multi-zone evidence are bound.",
        },
        {
            "id": "collector-authn-authz",
            "status": "service-attested" if security.get("mtls_policy_ref") and security.get("auth_policy_ref") else "planned-production",
            "description": "mTLS, authorization, tenant isolation, replay, idempotency, rate-limit, ingress, egress, and network policies are bound.",
        },
        {
            "id": "streaming-bus",
            "status": "service-attested" if streaming.get("tls") else "planned-production",
            "description": "Kafka/Redpanda stream, topic, retention, TLS, and dead-letter queue evidence are bound.",
        },
        {
            "id": "clickhouse-trace-store",
            "status": "service-attested" if storage.get("clickhouse", {}).get("backup_ref") else "planned-production",
            "description": "ClickHouse trace-store retention and backup evidence are bound.",
        },
        {
            "id": "postgres-control-plane",
            "status": "service-attested" if storage.get("postgres", {}).get("backup_ref") else "planned-production",
            "description": "Postgres control-plane schema and backup evidence are bound.",
        },
        {
            "id": "production-mcp-proxy-and-framework-hooks",
            "status": "service-attested" if mcp_proxy.get("framework_hook_refs") else "planned-production",
            "description": "MCP proxy image and release-pinned framework hook references are bound.",
        },
    ]


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "unknown"))
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
                    errors.append(f"collector service secret-like field must be redacted reference: {child_path}")
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
