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
- full normalized transcript payload.

Captured calls append `mcp.tool_call.evidenced` entries to the evidence chain.
