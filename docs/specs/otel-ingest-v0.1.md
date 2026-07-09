# OTel GenAI Ingest v0.1

The Phase 0 collector accepts OTel-style GenAI events and commits each event to
the evidence chain. This is a local reference path for the later collector,
gateway, and ClickHouse ingestion stack.

## Event Shape

```json
{
  "trace_id": "0f4a...",
  "span_id": "7b1c...",
  "timestamp": "2026-07-03T12:00:10Z",
  "event_name": "gen_ai.tool.call",
  "contract_hash": "sha256...",
  "agent": {
    "name": "aitrade-risk-agent",
    "version": "sha256:..."
  },
  "risk_class": "trading-prod-write",
  "attributes": {
    "tool.name": "place_shadow_order",
    "tool.action": "shadow_trade"
  }
}
```

The collector writes `otel_genai.event.ingested` entries containing the canonical
event hash, trace id, span id, contract hash, and original event body.

## OTLP JSON Traces

The local collector also accepts OTLP HTTP JSON trace payloads in the
`resourceSpans[].scopeSpans[].spans[]` shape. This is available through both
the CLI and the standard OTLP HTTP traces path:

```powershell
python -m trustai otlp-ingest examples/aitrade/otlp-traces.json --state .trustai/demo/evidence-chain.json --tenant aitrade-local
# POST the same JSON body to http://127.0.0.1:8080/v1/traces
```

The converter maps each span, or each span event when present, into the same
`otel_genai.event.ingested` evidence entry used by file and SDK ingestion.
Trust metadata can appear as resource, scope, span, or span-event attributes:

- `trustai.contract_hash`, `contract_hash`, or `contract.hash`;
- `trustai.agent.name`, `agent.name`, or `service.name`;
- `trustai.agent.version`, `agent.version`, or `service.version`;
- optional `trustai.risk_class`, `risk_class`, or `action.risk_class`.

Resource, scope, span, and event attributes are retained in the normalized
event body so downstream proof packs can reference the original telemetry
context while the chain stores only hashes and compact evidence entries.

## Framework Adapters

`framework-ingest` accepts exported JSON traces from LangGraph, OpenAI Agents,
Claude Agent, CrewAI, Bedrock, and Vertex-style agent runtimes. The adapters
normalize framework-native steps, messages, tool calls, tasks, and invocations
into the same `otel_genai.event.ingested` evidence entries used by file, OTLP,
API, and SDK ingestion.

```powershell
python -m trustai framework-ingest examples/aitrade/framework-traces.json --state .trustai/framework-demo/evidence-chain.json --tenant framework-local
```

See `docs/specs/framework-adapters-v0.1.md` for the adapter envelope, supported
framework names, normalized event fields, and production notes.

## Collector Topology

The collector topology manifest signs and verifies the source-backed ingestion path across file/OTLP ingest, Python and TypeScript SDK capture, framework adapters, MCP transcript capture, the local HTTP API, and the SQLite control-plane index. It also declares the hardened collector service, production MCP proxy, Kafka/Redpanda, ClickHouse, Postgres, and native runtime hooks as planned-production components until those services have deployable evidence.

See `docs/specs/collector-topology-v0.1.md` and the `collector-topology`, `collector-topology-verify`, and `collector-topology-append` commands.

## TypeScript SDK

`sdk/typescript` provides the Node.js ingestion SDK for agent teams using
TypeScript or JavaScript. It posts the same normalized event shape to
`/v0/ingest` and includes helpers for decisions, tool calls, traces, and tool
instrumentation. See `docs/specs/typescript-sdk-v0.1.md`.

## Python SDK

`trustai.sdk.TrustAIClient` emits the same event shape without requiring users to
write JSON files by hand.

Local chain capture:

```python
from trustai.contracts import load_contract
from trustai.sdk import TrustAIClient

contract = load_contract("examples/aitrade/verification-contract.yaml")
client = TrustAIClient.from_contract(contract, state_path=".trustai/sdk-demo/evidence-chain.json")
client.record_decision("allow_shadow_order", attributes={"symbol": "BTCUSDT"})
```

API capture:

```python
client = TrustAIClient.from_contract(contract, endpoint="http://127.0.0.1:8080")
client.record_tool_call("place_shadow_order", attributes={"tool.mode": "shadow"})
```

The SDK also provides `trace(...)` helpers and `instrument_tool(...)` decorator
instrumentation for low-friction onboarding.
