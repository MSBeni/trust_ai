# TypeScript SDK v0.1

The TypeScript SDK is the self-serve ingestion surface for Node.js agent teams.
It emits the same OTel-style GenAI events accepted by `trustai ingest`, the
Python SDK, and `/v0/ingest`.

The package lives in `sdk/typescript` and has no runtime dependencies. It ships
ESM JavaScript plus TypeScript declarations:

```text
sdk/typescript/
|-- package.json
|-- src/
|   |-- index.mjs
|   `-- index.d.ts
`-- test/
    `-- sdk.test.mjs
```

## Client Setup

```js
import { TrustAIClient } from "./sdk/typescript/src/index.mjs";

const client = new TrustAIClient({
  endpoint: "http://127.0.0.1:8080",
  contractHash: "22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2",
  agent: {
    name: "aitrade-risk-agent",
    version: "sha256:0d5bbd8d2357b7d36e0f3f7c5e9a0a3e1f5b7a0d2c4e6f8a9b1c3d5e7f901234",
    risk_class: "trading-prod-write"
  }
});
```

The SDK currently posts to a TrustAI collector/API endpoint. Local direct chain
writing remains a Python SDK feature because evidence-chain signing and
timestamping are implemented in the Python package.

## Event Capture

```js
await client.recordDecision("allow_shadow_order", {
  attributes: { symbol: "BTCUSDT" }
});

const trace = client.trace("trace-001");
await trace.toolCall("place_shadow_order", {
  attributes: { "tool.mode": "shadow", notional_usd: 7500 }
});
```

The client records:

- `gen_ai.agent.decision`
- `gen_ai.tool.call`
- arbitrary event names through `emitEvent(...)`

All events normalize to the same fields used by file ingest and the Python SDK:
`trace_id`, `span_id`, `timestamp`, `event_name`, `schema_url`,
`contract_hash`, `agent`, `risk_class`, and `attributes`.

## Tool Instrumentation

```js
const checked = client.instrumentTool("risk_limit_check", async (notionalUsd) => {
  return notionalUsd < 10000;
});

await checked(7500);
```

The wrapper records `tool.status`, `latency_ms`, and `error.type` when the
wrapped function raises.

## Example

Start the local API:

```powershell
$env:PYTHONPATH = "src"
python -m trustai serve --host 127.0.0.1 --port 8080 --state .trustai/typescript-sdk/evidence-chain.json --tenant typescript-sdk
```

Then run:

```powershell
& "C:\Users\moham\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe" examples/aitrade/typescript_capture.mjs
```

The integration test `tests/test_typescript_sdk.py` starts the server, runs the
Node test script, and verifies the signed evidence chain.
