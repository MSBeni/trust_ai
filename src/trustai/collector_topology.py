from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

COLLECTOR_TOPOLOGY_SCHEMA = "trustai.collector-topology/0.1"
COLLECTOR_TOPOLOGY_ENTRY_TYPE = "collector.topology.published"

DEFAULT_COLLECTOR_SOURCE_PATHS = (
    "src/trustai/ingest.py",
    "src/trustai/server.py",
    "src/trustai/approval_request_store.py",
    "src/trustai/provider_webhook.py",
    "src/trustai/provider_webhook_store.py",
    "src/trustai/provider_audit.py",
    "src/trustai/provider_audit_stream.py",
    "src/trustai/provider_audit_worker.py",
    "src/trustai/provider_credential_custody.py",
    "src/trustai/provider_installation.py",
    "src/trustai/provider_callback_store.py",
    "src/trustai/provider_ingress.py",
    "src/trustai/provider_callback_storage.py",
    "src/trustai/provider_lifecycle.py",
    "src/trustai/provider_lifecycle_operation.py",
    "src/trustai/sdk.py",
    "src/trustai/adapters.py",
    "src/trustai/mcp_gateway.py",
    "src/trustai/control_plane.py",
    "src/trustai/collector_worker.py",
    "sdk/typescript/package.json",
    "sdk/typescript/src/index.mjs",
    "sdk/typescript/src/index.d.ts",
    "docs/specs/otel-ingest-v0.1.md",
    "docs/specs/python-sdk-v0.1.md",
    "docs/specs/typescript-sdk-v0.1.md",
    "docs/specs/framework-adapters-v0.1.md",
    "docs/specs/mcp-gateway-v0.1.md",
    "docs/specs/control-plane-v0.1.md",
    "docs/specs/provider-webhook-v0.1.md",
    "docs/specs/provider-audit-correlation-v0.1.md",
    "docs/specs/provider-audit-stream-v0.1.md",
    "docs/specs/provider-audit-worker-v0.1.md",
    "docs/specs/provider-credential-custody-v0.1.md",
    "docs/specs/provider-installation-v0.1.md",
    "docs/specs/provider-callback-store-v0.1.md",
    "docs/specs/provider-ingress-v0.1.md",
    "docs/specs/provider-callback-storage-v0.1.md",
    "docs/specs/provider-lifecycle-v0.1.md",
    "docs/specs/provider-lifecycle-operation-v0.1.md",
    "docs/specs/collector-topology-v0.1.md",
    "docs/specs/collector-worker-v0.1.md",
    "README.md",
)

REQUIRED_ENDPOINT_IDS = {
    "http-v0-ingest",
    "http-otlp-v1-traces",
    "http-control-index",
    "http-control-summary",
    "http-verify",
    "http-approval-requests-slack",
    "http-approval-callbacks-slack",
    "http-provider-webhooks-github",
    "http-provider-webhooks-gitlab",
    "http-provider-lifecycle-operations",
    "cli-ingest",
    "cli-otlp-ingest",
    "cli-framework-ingest",
    "cli-mcp-capture",
}

REQUIRED_COMPONENT_IDS = {
    "file-event-ingest",
    "otlp-json-ingest",
    "python-sdk-capture",
    "typescript-sdk-capture",
    "framework-adapters",
    "mcp-transcript-capture",
    "local-http-api",
    "sqlite-control-plane",
    "sqlite-provider-callback-store",
    "provider-public-ingress-manifests",
    "provider-callback-storage-manifests",
    "provider-lifecycle-manifests",
    "provider-lifecycle-operation-receipts",
    "provider-audit-stream-receipts",
    "provider-audit-worker-receipts",
    "provider-credential-custody-receipts",
    "hardened-otel-collector",
    "production-mcp-proxy",
    "streaming-bus",
    "clickhouse-trace-store",
    "postgres-control-plane",
    "native-framework-hooks",
}

REQUIRED_STORE_IDS = {
    "evidence-chain-json",
    "sqlite-control-plane",
    "sqlite-provider-callback-store",
    "kafka-redpanda",
    "clickhouse",
    "postgres",
}


@dataclass
class CollectorTopologyVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_collector_topology(
    root: str | Path = ".",
    *,
    name: str = "trustai-local-collector",
    mode: str = "local-reference",
    environment: str = "local",
    source_paths: list[str] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    root_path = Path(root)
    paths = source_paths or list(DEFAULT_COLLECTOR_SOURCE_PATHS)
    body = {
        "schema": COLLECTOR_TOPOLOGY_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "topology": {
            "name": name,
            "mode": mode,
            "environment": environment,
            "ingest_model": "otel-genai-to-evidence-chain",
            "control_plane": "sqlite-reference-index",
            "mcp_path": "transcript-capture-reference",
        },
        "source_files": [_source_record(root_path, path) for path in paths],
        "endpoints": _endpoints(),
        "components": _components(),
        "stores": _stores(),
        "controls": _controls(),
        "limitations": [
            "This topology verifies the local reference collector, SDK, MCP transcript capture, API, and SQLite control-plane path.",
            "It does not claim a hardened production OTel collector service, production MCP proxy process, or native runtime hooks for specific framework releases.",
            "Kafka/Redpanda, ClickHouse, and Postgres are declared as planned-production stores until backed by deployable services and operational controls.",
        ],
    }
    topology_id = content_hash(body)
    return {
        **body,
        "topology_id": topology_id,
        "signatures": [sign_value({"topology_id": topology_id, "topology": body}, key)],
    }


def verify_collector_topology(
    topology: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> CollectorTopologyVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if topology.get("schema") != COLLECTOR_TOPOLOGY_SCHEMA:
        errors.append(f"unsupported collector topology schema: {topology.get('schema')}")
    body = without_keys(topology, "topology_id", "signatures")
    expected_topology_id = content_hash(body)
    if topology.get("topology_id") != expected_topology_id:
        errors.append("topology_id does not match canonical topology body")

    signatures = topology.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("collector topology must include at least one signature")
    else:
        signed_value = {"topology_id": topology.get("topology_id"), "topology": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("collector topology signature verification failed")

    source_files = topology.get("source_files", [])
    if not isinstance(source_files, list) or not source_files:
        errors.append("collector topology must include source_files")
        source_files = []
    paths = set()
    for source in source_files:
        if not isinstance(source, dict):
            errors.append("source file record must be an object")
            continue
        path_value = source.get("path")
        if not isinstance(path_value, str) or not path_value:
            errors.append("source file path missing")
            continue
        paths.add(path_value)
        source_path = root_path / path_value
        if not source_path.exists():
            errors.append(f"source file missing from worktree: {path_value}")
            continue
        current = _source_record(root_path, path_value)
        for field in ("sha256", "size_bytes"):
            if source.get(field) != current.get(field):
                errors.append(f"source file {path_value} {field} mismatch")

    for required in DEFAULT_COLLECTOR_SOURCE_PATHS:
        if required not in paths:
            errors.append(f"required collector source missing from topology: {required}")

    topology_meta = topology.get("topology", {})
    if topology_meta.get("mode") not in {"local-reference", "byoc-reference", "self-hosted-reference", "production-design"}:
        warnings.append(f"collector topology mode is {topology_meta.get('mode')}")
    if topology_meta.get("ingest_model") != "otel-genai-to-evidence-chain":
        errors.append("collector topology ingest_model must be otel-genai-to-evidence-chain")

    endpoint_ids = _ids(topology.get("endpoints", []))
    for endpoint_id in sorted(REQUIRED_ENDPOINT_IDS):
        if endpoint_id not in endpoint_ids:
            errors.append(f"collector endpoint missing: {endpoint_id}")

    components = topology.get("components", [])
    component_ids = _ids(components)
    for component_id in sorted(REQUIRED_COMPONENT_IDS):
        if component_id not in component_ids:
            errors.append(f"collector component missing: {component_id}")
    planned_components = [
        component for component in components if isinstance(component, dict) and component.get("status") == "planned-production"
    ]
    if planned_components:
        warnings.append(f"{len(planned_components)} collector components remain planned-production")

    store_ids = _ids(topology.get("stores", []))
    for store_id in sorted(REQUIRED_STORE_IDS):
        if store_id not in store_ids:
            errors.append(f"collector store missing: {store_id}")

    controls = topology.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("collector topology must include controls")
    else:
        planned_controls = [
            control for control in controls if isinstance(control, dict) and control.get("status") == "planned-production"
        ]
        if planned_controls:
            warnings.append(f"{len(planned_controls)} collector controls remain planned-production")

    return CollectorTopologyVerification(ok=not errors, errors=errors, warnings=warnings)


def append_collector_topology(
    chain: EvidenceChain,
    topology: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_collector_topology(topology, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid collector topology: " + "; ".join(result.errors))
    payload = {
        "topology_id": topology["topology_id"],
        "topology_hash": content_hash(topology),
        "topology": topology.get("topology"),
        "source_file_count": len(topology.get("source_files", [])),
        "endpoint_count": len(topology.get("endpoints", [])),
        "component_summary": _status_summary(topology.get("components", [])),
        "store_summary": _status_summary(topology.get("stores", [])),
        "control_summary": _status_summary(topology.get("controls", [])),
        "limitations": topology.get("limitations", []),
    }
    return chain.append(COLLECTOR_TOPOLOGY_ENTRY_TYPE, payload, key=key, timestamp=topology.get("generated_at"))


def load_collector_topology(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("collector topology must contain an object")
    return value


def write_collector_topology(path: str | Path, topology: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(topology, indent=2, sort_keys=True), encoding="utf-8")


def write_collector_topology_markdown(path: str | Path, topology: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_collector_topology_markdown(topology), encoding="utf-8")


def render_collector_topology_markdown(topology: dict[str, Any]) -> str:
    meta = topology.get("topology", {})
    sources = "\n".join(
        f"- `{source.get('path')}`: `{source.get('sha256')}`"
        for source in topology.get("source_files", [])
    )
    endpoints = "\n".join(
        f"- `{endpoint.get('id')}`: {endpoint.get('method', '')} {endpoint.get('path', endpoint.get('command', ''))}"
        for endpoint in topology.get("endpoints", [])
    )
    components = "\n".join(
        f"- `{component.get('id')}`: {component.get('status')} ({component.get('evidence')})"
        for component in topology.get("components", [])
    )
    stores = "\n".join(
        f"- `{store.get('id')}`: {store.get('status')} ({store.get('role')})"
        for store in topology.get("stores", [])
    )
    controls = "\n".join(
        f"- `{control.get('id')}`: {control.get('status')}"
        for control in topology.get("controls", [])
    )
    limitations = "\n".join(f"- {item}" for item in topology.get("limitations", []))
    return f"""# TrustAI Collector Topology

Topology ID: `{topology.get('topology_id', '')}`

Name: {meta.get('name', '')}

Mode: {meta.get('mode', '')}

Environment: {meta.get('environment', '')}

## Source Files

{sources}

## Endpoints

{endpoints}

## Components

{components}

## Stores

{stores}

## Controls

{controls}

## Limitations

{limitations}
"""


def _source_record(root: Path, path: str) -> dict[str, Any]:
    source_path = root / path
    data = source_path.read_bytes()
    return {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _endpoints() -> list[dict[str, str]]:
    return [
        {
            "id": "http-v0-ingest",
            "kind": "http",
            "method": "POST",
            "path": "/v0/ingest",
            "evidence": "src/trustai/server.py",
            "description": "Accepts normalized OTel-style GenAI events and appends them to the evidence chain.",
        },
        {
            "id": "http-otlp-v1-traces",
            "kind": "http",
            "method": "POST",
            "path": "/v1/traces",
            "evidence": "src/trustai/server.py",
            "description": "Accepts OTLP JSON trace payloads and normalizes spans/events into TrustAI evidence events.",
        },
        {
            "id": "http-control-index",
            "kind": "http",
            "method": "POST",
            "path": "/v0/control/index",
            "evidence": "src/trustai/server.py",
            "description": "Indexes a chain and optional proof pack into the local control-plane database.",
        },
        {
            "id": "http-control-summary",
            "kind": "http",
            "method": "GET",
            "path": "/v0/control/summary",
            "evidence": "src/trustai/server.py",
            "description": "Reads local control-plane summary state.",
        },
        {
            "id": "http-verify",
            "kind": "http",
            "method": "POST",
            "path": "/v0/verify",
            "evidence": "src/trustai/server.py",
            "description": "Verifies proof packs through the local API.",
        },
        {
            "id": "http-approval-requests-slack",
            "kind": "http",
            "method": "POST",
            "path": "/v0/approval-requests/slack",
            "evidence": "src/trustai/server.py",
            "description": "Stores generated Slack approval requests and contract bindings for later payload-only callback resolution.",
        },
        {
            "id": "http-approval-callbacks-slack",
            "kind": "http",
            "method": "POST",
            "path": "/v0/approval-callbacks/slack",
            "evidence": "src/trustai/server.py",
            "description": "Accepts Slack-style approval interactions, validates Slack signatures when configured, resolves pending requests from durable local storage, builds verified callback artifacts, and appends chain-backed approval evidence.",
        },
        {
            "id": "http-provider-webhooks-github",
            "kind": "http",
            "method": "POST",
            "path": "/v0/provider-webhooks/github",
            "evidence": "src/trustai/server.py",
            "description": "Accepts GitHub provider webhooks, verifies X-Hub-Signature-256 with a configured secret, deduplicates retries through the local webhook store, signs a provider webhook receipt, and appends first-seen inbound provider event evidence.",
        },
        {
            "id": "http-provider-webhooks-gitlab",
            "kind": "http",
            "method": "POST",
            "path": "/v0/provider-webhooks/gitlab",
            "evidence": "src/trustai/server.py",
            "description": "Accepts GitLab provider webhooks, verifies X-Gitlab-Token with a configured secret, deduplicates retries through the local webhook store, signs a provider webhook receipt, and appends first-seen inbound provider event evidence.",
        },
        {
            "id": "http-provider-lifecycle-operations",
            "kind": "http",
            "method": "POST",
            "path": "/v0/provider-lifecycle-operations",
            "evidence": "src/trustai/server.py",
            "description": "Accepts provider lifecycle operation payloads, optionally requires a bearer token, builds signed operation receipts, and appends chain-backed provider lifecycle operation evidence.",
        },
        {
            "id": "http-insurer-risk",
            "kind": "http",
            "method": "POST",
            "path": "/v0/insurer-risk",
            "evidence": "src/trustai/server.py",
            "description": "Returns consent-gated insurer risk telemetry from verified proof packs.",
        },
        {
            "id": "cli-ingest",
            "kind": "cli",
            "command": "python -m trustai ingest",
            "evidence": "src/trustai/cli.py",
            "description": "Appends normalized event files to a tenant evidence chain.",
        },
        {
            "id": "cli-otlp-ingest",
            "kind": "cli",
            "command": "python -m trustai otlp-ingest",
            "evidence": "src/trustai/cli.py",
            "description": "Appends OTLP JSON trace payloads to a tenant evidence chain.",
        },
        {
            "id": "cli-framework-ingest",
            "kind": "cli",
            "command": "python -m trustai framework-ingest",
            "evidence": "src/trustai/cli.py",
            "description": "Converts framework-native traces to TrustAI evidence events.",
        },
        {
            "id": "cli-mcp-capture",
            "kind": "cli",
            "command": "python -m trustai mcp-capture",
            "evidence": "src/trustai/cli.py",
            "description": "Appends MCP tool-call transcript evidence to the chain.",
        },
    ]


def _components() -> list[dict[str, str]]:
    return [
        {
            "id": "file-event-ingest",
            "status": "implemented-reference",
            "evidence": "src/trustai/ingest.py",
            "description": "Normalizes TrustAI/OTel-style event files and appends hashed evidence entries.",
        },
        {
            "id": "otlp-json-ingest",
            "status": "implemented-reference",
            "evidence": "src/trustai/ingest.py",
            "description": "Converts OTLP JSON resource spans, scope spans, spans, and span events to TrustAI events.",
        },
        {
            "id": "python-sdk-capture",
            "status": "implemented-reference",
            "evidence": "src/trustai/sdk.py",
            "description": "Captures Python agent decisions and tool calls locally or through /v0/ingest.",
        },
        {
            "id": "typescript-sdk-capture",
            "status": "implemented-reference",
            "evidence": "sdk/typescript/src/index.mjs",
            "description": "Captures TypeScript agent decisions and tool calls through /v0/ingest.",
        },
        {
            "id": "framework-adapters",
            "status": "implemented-reference",
            "evidence": "src/trustai/adapters.py",
            "description": "Maps LangGraph, OpenAI Agents, Claude, CrewAI, Bedrock, and Vertex traces to TrustAI events.",
        },
        {
            "id": "mcp-transcript-capture",
            "status": "local-reference",
            "evidence": "src/trustai/mcp_gateway.py",
            "description": "Captures normalized MCP transcript records and hashes request/response bodies.",
        },
        {
            "id": "local-http-api",
            "status": "implemented-reference",
            "evidence": "src/trustai/server.py",
            "description": "Exposes local ingest, OTLP traces, verification, approval request storage, approval callback, provider webhook receipt/deduplication, provider lifecycle operation receipt, provider audit worker receipt, insurer telemetry, and control-plane endpoints.",
        },
        {
            "id": "sqlite-control-plane",
            "status": "implemented-reference",
            "evidence": "src/trustai/control_plane.py",
            "description": "Indexes contracts, chain entries, agents, anchors, and proof packs into SQLite.",
        },
        {
            "id": "sqlite-provider-callback-store",
            "status": "implemented-reference",
            "evidence": "src/trustai/provider_callback_store.py",
            "description": "Persists provider installations, webhooks, deliveries, audit correlations, audit stream receipts, and approval callbacks into indexed SQLite operational state with signed store manifests.",
        },
        {
            "id": "provider-public-ingress-manifests",
            "status": "implemented-reference",
            "evidence": "src/trustai/provider_ingress.py",
            "description": "Binds provider callback ingress base URL, DNS, TLS, network controls, provider endpoints, installation source hashes, and callback-store evidence into signed manifests.",
        },
        {
            "id": "provider-callback-storage-manifests",
            "status": "implemented-reference",
            "evidence": "src/trustai/provider_callback_storage.py",
            "description": "Binds provider callback operation stores and ingress manifests to Postgres-compatible storage migration, HA, backup, encryption, network, and monitoring controls.",
        },
        {
            "id": "provider-lifecycle-manifests",
            "status": "implemented-reference",
            "evidence": "src/trustai/provider_lifecycle.py",
            "description": "Binds provider OAuth callbacks, token exchange and storage, credential rotation, revocation, uninstall, provider audit-log stream, installation, ingress, and callback storage evidence into signed manifests.",
        },
        {
            "id": "provider-lifecycle-operation-receipts",
            "status": "implemented-reference",
            "evidence": "src/trustai/provider_lifecycle_operation.py",
            "description": "Binds lifecycle manifests to recorded provider OAuth, token, credential, revocation, uninstall, and audit-stream operation response evidence.",
        },
        {
            "id": "provider-audit-stream-receipts",
            "status": "implemented-reference",
            "evidence": "src/trustai/provider_audit_stream.py",
            "description": "Binds provider audit-log stream/export windows to endpoint request/response hashes, cursor refs, redacted credentials, installation/lifecycle manifests, and optional audit correlations.",
        },
        {
            "id": "provider-audit-worker-receipts",
            "status": "implemented-reference",
            "evidence": "src/trustai/provider_audit_worker.py",
            "description": "Binds scheduled or hosted provider audit worker runs to audit stream receipts, correlation receipts, scheduler leases, checkpoints, lifecycle operations, and redacted credentials.",
        },
        {
            "id": "provider-credential-custody-receipts",
            "status": "implemented-reference",
            "evidence": "src/trustai/provider_credential_custody.py",
            "description": "Binds redacted provider credentials to vault/KMS custody metadata, access policy hashes, rotation, revocation, quorum, audit roots, and provider source artifacts.",
        },
        {
            "id": "hardened-otel-collector",
            "status": "planned-production",
            "evidence": "docs/specs/collector-topology-v0.1.md",
            "description": "Replace local CLI/API ingestion with a hardened collector service and deployment controls.",
        },
        {
            "id": "production-mcp-proxy",
            "status": "planned-production",
            "evidence": "docs/specs/mcp-gateway-v0.1.md",
            "description": "Replace transcript capture with a deployable MCP proxy process in front of tool servers.",
        },
        {
            "id": "streaming-bus",
            "status": "planned-production",
            "evidence": "docs/specs/collector-topology-v0.1.md",
            "description": "Add Kafka/Redpanda buffering between collector and durable chain/analytics storage.",
        },
        {
            "id": "clickhouse-trace-store",
            "status": "planned-production",
            "evidence": "docs/specs/collector-topology-v0.1.md",
            "description": "Add ClickHouse for high-volume span analytics without storing raw payloads in the chain.",
        },
        {
            "id": "postgres-control-plane",
            "status": "planned-production",
            "evidence": "docs/specs/collector-topology-v0.1.md",
            "description": "Replace SQLite reference index with a production Postgres control-plane store.",
        },
        {
            "id": "native-framework-hooks",
            "status": "planned-production",
            "evidence": "docs/specs/framework-adapters-v0.1.md",
            "description": "Add release-pinned native hooks for framework runtimes beyond fixture adapters.",
        },
    ]


def _stores() -> list[dict[str, str]]:
    return [
        {
            "id": "evidence-chain-json",
            "status": "implemented-reference",
            "role": "append-only local evidence chain state",
            "evidence": "src/trustai/chain.py",
        },
        {
            "id": "sqlite-control-plane",
            "status": "implemented-reference",
            "role": "local control-plane read model",
            "evidence": "src/trustai/control_plane.py",
        },
        {
            "id": "sqlite-provider-callback-store",
            "status": "implemented-reference",
            "role": "local provider callback operation store",
            "evidence": "src/trustai/provider_callback_store.py",
        },
        {
            "id": "kafka-redpanda",
            "status": "planned-production",
            "role": "collector buffering and backpressure isolation",
            "evidence": "docs/specs/collector-topology-v0.1.md",
        },
        {
            "id": "clickhouse",
            "status": "planned-production",
            "role": "high-volume trace analytics",
            "evidence": "docs/specs/collector-topology-v0.1.md",
        },
        {
            "id": "postgres",
            "status": "planned-production",
            "role": "production control-plane state",
            "evidence": "docs/specs/collector-topology-v0.1.md",
        },
    ]


def _controls() -> list[dict[str, str]]:
    return [
        {
            "id": "otel-semconv-ingest",
            "status": "implemented-reference",
            "description": "Collector accepts normalized OTel GenAI events and OTLP JSON traces.",
        },
        {
            "id": "sdk-event-capture",
            "status": "implemented-reference",
            "description": "Python and TypeScript SDKs capture decisions and tool calls with contract and agent binding.",
        },
        {
            "id": "mcp-tool-call-evidence",
            "status": "local-reference",
            "description": "MCP transcripts are normalized, hashed, and appended as chain evidence entries.",
        },
        {
            "id": "control-plane-indexing",
            "status": "implemented-reference",
            "description": "Local API and CLI can index chain/proof-pack state into a queryable control-plane read model.",
        },
        {
            "id": "callback-operation-storage",
            "status": "implemented-reference",
            "description": "Provider callback artifacts can be persisted into an indexed SQLite operation store with signed source-artifact manifests.",
        },
        {
            "id": "collector-service-hardening",
            "status": "planned-production",
            "description": "Add authn/z, tenancy isolation, rate limits, buffering, replay protection, and operational SLOs.",
        },
        {
            "id": "production-storage-services",
            "status": "planned-production",
            "description": "Add Kafka/Redpanda, ClickHouse, and Postgres services with backup and retention controls.",
        },
        {
            "id": "native-hook-certification",
            "status": "planned-production",
            "description": "Pin and verify native hooks for specific LangGraph/OpenAI/Claude/CrewAI/Bedrock/Vertex releases.",
        },
        {
            "id": "production-mcp-proxy-attestation",
            "status": "planned-production",
            "description": "Ship an MCP proxy process with request signing, policy context, and chain append guarantees.",
        },
    ]


def _ids(items: Any) -> set[str]:
    if not isinstance(items, list):
        return set()
    return {item.get("id") for item in items if isinstance(item, dict) and isinstance(item.get("id"), str)}


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "unknown"))
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))
