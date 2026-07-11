# Framework Adapters v0.1

TrustAI adapters convert framework-native agent traces into the same
`otel_genai.event.ingested` evidence entries used by file ingest, OTLP ingest,
the Python SDK, and the TypeScript SDK.

The adapters are dependency-free reference mappers. They do not import or
orchestrate agent frameworks; they accept JSON traces exported by those
frameworks and normalize them for evidence capture.

## Supported Local Adapters

- `langgraph`
- `openai_agents` or `openai`
- `claude_agent` or `claude`
- `crewai`
- `bedrock`
- `vertex`

## Input Envelope

Each trace must include TrustAI metadata:

```json
{
  "framework": "langgraph",
  "trace_id": "lg-trace-001",
  "contract_hash": "22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2",
  "agent": {
    "name": "aitrade-risk-agent",
    "version": "sha256:...",
    "risk_class": "trading-prod-write"
  },
  "nodes": []
}
```

A file may also contain `{ "traces": [...] }` to ingest multiple framework
traces at once.

## Output Events

Adapters emit normalized events with:

- `schema_url`: `trustai.framework-adapter/0.1`
- `event_name`: usually `gen_ai.tool.call`, `gen_ai.agent.decision`,
  `gen_ai.agent.message`, `gen_ai.agent.node`, `gen_ai.agent.task`, or
  `gen_ai.agent.invocation`
- `attributes.trustai.adapter.framework`
- `attributes.trustai.adapter.kind`
- `attributes.trustai.adapter.payload_hash`
- `attributes.trustai.adapter.trace_hash`
- `attributes.trustai.adapter.trace_root`
- `attributes.trustai.adapter.event_sequence`
- `attributes.trustai.adapter.event_count`
- `attributes.trustai.adapter.previous_event_node_hash`
- `attributes.trustai.adapter.event_node_hash`

Tool calls preserve `tool.name`, `tool.arguments`, `tool.result`, and
`tool.status` when present. Agent steps preserve hashes of framework input and
output payloads instead of requiring raw payloads in downstream proof checks.

Framework-native trace and span identifiers may be human-readable or provider-specific.
Adapters derive stable OTel-compatible 32-hex `trace_id` and 16-hex `span_id`
values for ingestion while retaining the original values in
`attributes.trustai.adapter.source_trace_id`,
`attributes.trustai.adapter.source_span_id`, and optional
`attributes.trustai.adapter.source_parent_span_id`.

Each source trace is bound into a local event chain with schema
`trustai.framework-adapter-event-chain/0.1`. The first normalized event has no
previous node hash; every following event commits to the previous event node,
the source trace hash, event sequence, total event count, span ID, event name,
and source payload hash. The final event node is copied to
`trustai.adapter.trace_root`, so verifier and matrix checks can detect omitted,
reordered, or edited normalized adapter events without storing raw framework
payloads in the matrix row.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-ingest examples/aitrade/framework-traces.json --state .trustai/framework-demo/evidence-chain.json --tenant framework-local
python -m trustai keyring-init --out .trustai/framework-demo/keyring.local.json --tenant framework-local
python -m trustai chain-verify --state .trustai/framework-demo/evidence-chain.json --tenant framework-local --keyring .trustai/framework-demo/keyring.local.json
```

The bundled fixture covers LangGraph, OpenAI Agents, Claude Agent, CrewAI,
Bedrock, and Vertex-style traces. `framework-hook-release` binds hook package
entrypoints for these runtimes back to the signed adapter matrix and replayed
per-trace event roots. `framework-hook-operation` records per-capture runtime
evidence for a specific trace, hook release row, collector delivery ref, and
audit-log root.

## Compatibility Matrix

`framework-adapter-matrix` turns a declared runtime compatibility matrix into a
signed receipt. Verification replays the checked-in trace fixture through the
adapter code and checks each row's event count, event names, fixture SHA-256,
per-trace event chain, and normalized event root. This makes runtime-version
claims tamper-evident even when native production hooks are still deferred.

## Production Notes

The local adapters are intentionally thin. Production integrations should add
native framework hooks, version-specific compatibility tests, backpressure and
retry behavior, and deployment guidance for each framework runtime.
