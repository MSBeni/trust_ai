# Python SDK v0.1

The Python SDK is the self-serve ingestion surface for agent teams. It emits the
same OTel-style GenAI events accepted by `trustai ingest` and `/v0/ingest`, while
adding TrustAI evidence fields such as agent version and verification contract
hash.

## Client Setup

```python
from trustai.contracts import load_contract
from trustai.sdk import TrustAIClient

contract = load_contract("examples/aitrade/verification-contract.yaml")
client = TrustAIClient.from_contract(
    contract,
    state_path=".trustai/sdk-demo/evidence-chain.json",
    tenant_id="aitrade-sdk",
)
```

The client can write directly to a local evidence chain:

```python
client.record_decision("allow_shadow_order", attributes={"symbol": "BTCUSDT"})
```

Or post to the local API:

```python
client = TrustAIClient.from_contract(contract, endpoint="http://127.0.0.1:8080")
client.record_tool_call("place_shadow_order", attributes={"tool.mode": "shadow"})
```

## Event Shape

Each SDK event normalizes to the same schema used by file ingest:

- `trace_id`
- `span_id`
- `timestamp`
- `event_name`
- `schema_url`
- `contract_hash`
- `agent`
- `risk_class`
- `attributes`

The current default `schema_url` is `opentelemetry.semconv.gen_ai/1.0`.

## Trace Helper

```python
with client.trace("trace-001") as trace:
    trace.decision("allow_shadow_order", attributes={"symbol": "BTCUSDT"})
    trace.tool_call("place_shadow_order", attributes={"notional_usd": 7500})
```

All events emitted through the trace helper share the same trace id.

## Tool Decorator

```python
@client.instrument_tool("risk_limit_check")
def check_limit(value: int) -> bool:
    return value < 10000
```

The decorator records a `gen_ai.tool.call` event with `tool.status` and
`latency_ms`. Exceptions are recorded with `tool.status: error` and re-raised.

## Example

```powershell
$env:PYTHONPATH = "src"
python examples/aitrade/sdk_capture.py
```

The example writes `.trustai/sdk-demo/evidence-chain.json`.
