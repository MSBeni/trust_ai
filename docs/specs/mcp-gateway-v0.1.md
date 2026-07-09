# MCP Evidence Gateway v0.1

The Phase 1 local gateway captures MCP tool call transcripts as signed evidence.
It is a transcript-first reference for a future network proxy.

Each tool call records:

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

Proof packs that include `mcp.tool_call.evidenced` entries must replay the
transcript chain offline. The verifier rejects packs when request/response hashes,
tool-call hashes, sequence numbers, call counts, previous-node pointers, node
hashes, transcript roots, timestamps, or contract hashes do not match the
embedded normalized tool calls.
