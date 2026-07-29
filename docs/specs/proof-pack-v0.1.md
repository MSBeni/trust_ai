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


## Compiler Rules

The compiler must refuse to emit a JSON or PDF pack unless the supplied eval and
gate entries are exact entries from the supplied evidence chain, are ordered
after the contract registration, reference the packed contract hash, contract
ID, and agent, and expose an eval results hash that matches the embedded
results. The supplied gate decision must match the signed gate entry for all
verifier-replayed decision fields, and its `gate_entry_id` must bind to the
supplied gate entry.

## Verification Rules

An offline verifier must reject the pack when any of these checks fail:

1. the pack omits `issued_at` or provides a malformed RFC3339 issuance timestamp;
2. the pack signature does not verify against the canonical pack body;
3. any evidence entry signature is invalid;
4. any entry payload hash differs from its canonical payload;
5. any entry id differs from its canonical entry core;
6. any Merkle inclusion proof does not resolve to the declared tree root;
7. the packed chain tree header has a missing or malformed `size`/`root`, is
   smaller than the packed entries or their indexes, or, when the pack contains
   the complete tree, does not recompute from the packed entries;
8. the contract entry is not ordered before eval and gate entries;
9. the eval or gate entry references a contract hash different from the packed
   contract body;
10. holdout timestamps do not postdate the agent freeze boundary;
11. recomputing the gate decision from the contract, results, and packed
   approval evidence entries produces a different decision;
12. any included `shadow_replay.completed` entry contains a temporal holdout
    manifest that fails signature, record-chain, contract, replay, or summary
    verification;
13. any included `mcp.tool_call.evidenced` entries contain request, response,
    tool-call, sequence, call-count, previous-node, node, root, or contract
    evidence that cannot be replayed into the declared MCP transcript chain;
14. any included `soak_report.completed` entry contains source soak-window,
    hash, metric-check, incident, drift-alarm, timestamp, outcome, or contract
    evidence that cannot be replayed against the packed contract body;
15. any included `runtime.attested` entry contains action hash, timestamp,
    blast-radius check, approval, outcome, or contract evidence that cannot be
    replayed against the packed contract body and embedded action;
16. any included `policy.decision` entry omits the embedded policy pack,
    mismatches the policy pack hash/id/version, timestamp, action hash, proof
    freshness, rule result, outcome, or contract evidence that cannot be
    replayed against the packed proof body, embedded policy pack, and embedded
    action;
17. any included `agent.delegation_graph.exported` entry omits the embedded
    signed graph, mismatches the graph hash/id/summary/filter fields, references
    another contract, fails graph signature/hash/source inclusion checks, or
    names source inventory/delegation entries that are not embedded in the pack;
18. the packed framework control mappings differ from the deterministic mappings
    for the packed gate decision;
19. the packed subject agent or environment differs from the registered
    contract agent, gate decision agent, eval entry agent, or eval results
    environment.

When a gate decision relies on `human_approval.granted` entries, those entries
must be included in `chain.entries` with valid signatures, timestamp tokens,
payload hashes, and inclusion proofs. Removing them changes the recomputed gate
approval result and invalidates the pack.

When a contract has `agent.delegation_graph.exported` entries, the compiler
includes the graph receipt plus the inventory and delegation source entries named
by that graph. This keeps the proof pack self-contained: an offline verifier can
replay the graph artifact, verify its source-entry inclusion proofs, and confirm
that every graph edge is backed by packed delegation evidence.

The MVP includes signatures inside the JSON artifact. Later versions should use
detached signatures and public-key/KMS-backed verification material.
