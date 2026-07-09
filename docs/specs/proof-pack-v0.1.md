# Proof Pack v0.1

A Proof Pack is a portable artifact that lets a third party verify an agent
promotion decision offline.

## Top-Level Shape

```json
{
  "@context": "https://trustai.dev/spec/proof-pack/v0.1",
  "type": "TrustAIProofPack",
  "spec_version": "trustai.proof-pack/0.1",
  "issued_at": "2026-07-03T13:05:00Z",
  "subject": {
    "agent": { "name": "aitrade-risk-agent", "version": "sha256:..." },
    "environment": { "runtime": "python3.12" }
  },
  "contract": {
    "hash": "sha256...",
    "body": {}
  },
  "gate_decision": {},
  "chain": {
    "tenant_id": "local",
    "tree": { "size": 3, "root": "sha256..." },
    "entries": [],
    "inclusion_proofs": {}
  },
  "framework_mappings": [],
  "pack_id": "sha256...",
  "signatures": []
}
```

## Verification Rules

An offline verifier must reject the pack when any of these checks fail:

1. the pack signature does not verify against the canonical pack body;
2. any evidence entry signature is invalid;
3. any entry payload hash differs from its canonical payload;
4. any entry id differs from its canonical entry core;
5. any Merkle inclusion proof does not resolve to the declared tree root;
6. the contract entry is not ordered before eval and gate entries;
7. the eval or gate entry references a contract hash different from the packed
   contract body;
8. holdout timestamps do not postdate the agent freeze boundary;
9. recomputing the gate decision from the contract, results, and packed
   approval evidence entries produces a different decision;
10. any included `shadow_replay.completed` entry contains a temporal holdout
    manifest that fails signature, record-chain, contract, replay, or summary
    verification;
11. any included `mcp.tool_call.evidenced` entries contain request, response,
    tool-call, sequence, call-count, previous-node, node, root, or contract
    evidence that cannot be replayed into the declared MCP transcript chain.

When a gate decision relies on `human_approval.granted` entries, those entries
must be included in `chain.entries` with valid signatures, timestamp tokens,
payload hashes, and inclusion proofs. Removing them changes the recomputed gate
approval result and invalidates the pack.

The MVP includes signatures inside the JSON artifact. Later versions should use
detached signatures and public-key/KMS-backed verification material.
