# MCP Evidence Gateway v0.1

The Phase 1 local gateway captures MCP tool call evidence for zero-code-change
agent integrations. It supports two compatible artifacts:

- normalized tool-call transcripts, appended as evidence-chain entries; and
- signed proxy captures derived from raw MCP JSON-RPC request/response
  envelopes.

## Transcript Evidence

Each normalized tool call records:

- session id and request id;
- timestamp;
- tool name;
- agent name and version;
- contract hash;
- canonical request hash;
- canonical response hash;
- transcript sequence number, call count, previous node hash, current node hash,
  and transcript root hash;
- full normalized transcript payload.

Captured calls append `mcp.tool_call.evidenced` entries to the evidence chain.
The transcript node hash is computed from the sequence number, total call count,
previous transcript node hash, and canonical tool-call hash. The last node hash
is copied into every entry as `transcript_root`, so reordered, truncated, or
inserted tool calls change the transcript root even when each individual call is
otherwise valid.

## Proxy Capture Receipts

A proxy capture has schema `trustai.mcp-proxy-capture/0.1` and records a signed,
redacted replay of the MCP JSON-RPC wire envelopes observed by the gateway.
Each proxy event includes:

- `session_id`, timestamp, and direction (`client_to_server` or
  `server_to_client`);
- the redacted JSON-RPC message;
- canonical message hash;
- event sequence, previous event hash, and event hash.

When a retained source export path is supplied, the capture also records
`proxy_events_artifact`: normalized path, byte SHA-256, byte size, canonical raw
export content hash, redacted event content hash, event count, event chain root,
and artifact id. Verification replays the retained raw export bytes,
normalizes/redacts the events, and rejects byte SHA-256 mismatches even when
parsed JSON content is unchanged. The event chain root binds the full
request/response envelope order. The capture pairs each `tools/call` client
request with the matching server response by typed JSON-RPC id. Tool-call
requests and matched responses must use JSON-RPC 2.0 with a non-empty string id
or integer id; numeric ids are rendered in normalized transcripts as
`number:<id>` to avoid string/number collisions. Matched responses must contain
exactly one of `result` or `error`. Result responses derive the normalized tool
response; JSON-RPC error responses are preserved under `response.jsonrpc_error`
and marked with `proxy_capture.response_kind = "error"` rather than being
converted into an empty success response. Sensitive message fields whose keys
include token, secret, password, credential, api key, or authorization are
replaced with `[REDACTED]` before hashing and signing.

A valid proxy capture must verify:

- capture id and signature over the canonical body;
- event hash chain, message hashes, event order, and chain root;
- retained source export bytes when `proxy_events_artifact` is present;
- no retained sensitive field value remains unredacted;
- every `tools/call` request has a matching response;
- matched tool-call envelopes use JSON-RPC 2.0, stable string/integer ids, and
  exactly one response `result` or `error`;
- JSON-RPC error responses are retained as explicit error evidence;
- derived normalized tool calls match the embedded tool calls;
- transcript root matches the derived tool-call transcript.

Verified captures append `mcp.proxy_capture.evidenced` entries containing the
capture id, event root, transcript root, event hashes, tool-call hashes, proxy
ref, upstream ref, session id, agent, and contract hash.

## Offline Verification

Proof packs that include `mcp.tool_call.evidenced` entries must replay the
transcript chain offline. The verifier rejects packs when request/response hashes,
tool-call hashes, sequence numbers, call counts, previous-node pointers, node
hashes, transcript roots, timestamps, or contract hashes do not match the
embedded normalized tool calls.

Proxy capture receipts are verified before chain append and can be independently
verified with:

```powershell
python -m trustai mcp-proxy-capture examples/aitrade/mcp-proxy-events.json --agent-name aitrade-risk-agent --agent-version sha256:0d5bbd8d2357b7d36e0f3f7c5e9a0a3e1f5b7a0d2c4e6f8a9b1c3d5e7f901234 --risk-class trading-prod-write --contract-hash 22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2 --proxy-ref mcp-proxy:trustai/local --upstream-ref mcp-server:aitrade/tools --captured-at 2026-07-03T12:00:12Z --out artifacts/mcp-proxy-capture.json
python -m trustai mcp-proxy-capture-verify artifacts/mcp-proxy-capture.json --events examples/aitrade/mcp-proxy-events.json
python -m trustai mcp-proxy-capture-append artifacts/mcp-proxy-capture.json --events examples/aitrade/mcp-proxy-events.json --state .trustai/mcp-proxy-capture-demo/evidence-chain.json --tenant mcp-proxy-capture-local --out artifacts/mcp-proxy-capture-entry.json
```
