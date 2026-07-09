# Collector Topology v0.1

The collector topology manifest is a signed, offline-verifiable record of the
TrustAI ingestion path. It binds the local OTel/file ingest, SDK capture,
framework adapters, MCP transcript capture, HTTP API, and SQLite control-plane
index to source hashes while explicitly declaring production services that are
not yet implemented.

This v0.1 topology does not claim a hardened production OTel collector process,
a production MCP proxy, native framework hooks for pinned runtime releases, or
Kafka/Redpanda, ClickHouse, and Postgres backing services. Those components are
present as `planned-production` records so auditors can see the boundary between
implemented reference code and future production infrastructure.

## Schema

`schema`: `trustai.collector-topology/0.1`

Required top-level fields:

- `topology_id`: canonical hash of the topology body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{topology_id, topology}`.
- `generated_at`: RFC3339 creation timestamp.
- `topology`: topology name, mode, environment, ingest model, control-plane
  model, and MCP capture path.
- `source_files`: hashed source files for ingest, SDKs, framework adapters, MCP
  capture, API, control plane, and related specs.
- `endpoints`: CLI and HTTP ingress points for event ingest, OTLP traces,
  framework traces, MCP transcript capture, verification, insurer telemetry, and
  control-plane indexing.
- `components`: implemented-reference, local-reference, and
  planned-production collector components.
- `stores`: implemented local stores and planned production stores.
- `controls`: implemented and planned controls for collector trust.
- `limitations`: explicit non-production claims.

Default source files:

- `src/trustai/ingest.py`
- `src/trustai/server.py`
- `src/trustai/sdk.py`
- `src/trustai/adapters.py`
- `src/trustai/mcp_gateway.py`
- `src/trustai/control_plane.py`
- `sdk/typescript/package.json`
- `sdk/typescript/src/index.mjs`
- `sdk/typescript/src/index.d.ts`
- `docs/specs/otel-ingest-v0.1.md`
- `docs/specs/python-sdk-v0.1.md`
- `docs/specs/typescript-sdk-v0.1.md`
- `docs/specs/framework-adapters-v0.1.md`
- `docs/specs/mcp-gateway-v0.1.md`
- `docs/specs/control-plane-v0.1.md`
- `docs/specs/collector-topology-v0.1.md`
- `README.md`

## Verification

`trustai collector-topology-verify` checks:

- topology schema and canonical `topology_id`;
- detached topology signature;
- every source file exists in the supplied root;
- source file `sha256` and size match the current worktree;
- required collector source files are present;
- required HTTP and CLI ingress endpoints are declared;
- required implemented and planned collector components are declared;
- local and planned storage services are declared;
- planned-production components and controls are surfaced as warnings.

`trustai collector-topology-append` first verifies the topology, then appends
`collector.topology.published` to an evidence chain. The appended entry records
the topology id/hash, topology metadata, source-file count, endpoint count,
component/store/control summaries, and limitations.

## Example Commands

```powershell
python -m trustai collector-topology --root . --environment aitrade-local --out artifacts/collector-topology.json --markdown artifacts/collector-topology.md
python -m trustai collector-topology-verify artifacts/collector-topology.json --root .
python -m trustai collector-topology-append artifacts/collector-topology.json --root . --state .trustai/collector-topology-demo/evidence-chain.json --tenant collector-topology-local --out artifacts/collector-topology-entry.json
python -m trustai chain-verify --state .trustai/collector-topology-demo/evidence-chain.json --tenant collector-topology-local
```

## Production Notes

A production collector topology should add:

- authenticated multi-tenant collector service with replay protection and rate
  limits;
- Kafka/Redpanda buffering with dead-letter evidence and operational SLOs;
- ClickHouse trace analytics with raw-payload retention controls;
- Postgres control-plane services with backup/restore evidence;
- native framework hooks pinned to specific LangGraph, OpenAI Agents, Claude,
  CrewAI, Bedrock, and Vertex runtime releases;
- a production MCP proxy process with request signing and policy context;
- deployment evidence that ties the topology to BYOC/self-hosted runtime
  controls, KMS/HSM keys, TSA receipts, and WORM storage.

The topology is meant to prevent accidental overclaiming: local reference paths
can be verified today, and production claims must become source-backed records
before they are marked implemented.
