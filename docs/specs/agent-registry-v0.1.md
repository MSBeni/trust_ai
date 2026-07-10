# Agent Registry and Delegation Evidence v0.1

The local registry records discovered agents, individual delegation edges, and
signed delegation graphs as evidence chain artifacts.

## Inventory

`agent.inventory.discovered` entries capture agent name, version, owner,
environment, risk class, source, and whether the agent is already governed by a
Verification Contract.

## Identity Provider Exports

`trustai identity-inventory` converts Okta, Microsoft Entra, and ServiceNow-style
exported records into the same inventory shape before appending signed
`agent.inventory.discovered` entries. The normalized agents retain
`identity_provider`, `identity_id`, and `identity_record_hash` fields so the
chain can prove which external identity record was observed.

```powershell
python -m trustai identity-inventory examples/aitrade/identity-inventory.json --state .trustai/identity-demo/evidence-chain.json --tenant identity-local
```

## Delegation

`agent.delegation.evidenced` entries capture parent agent, child agent, contract
hash, timestamp, reason, scope, and a canonical delegation hash.

Delegation entries are included in proof packs when they reference the same
contract hash as the promotion gate.

```powershell
python -m trustai delegation examples/aitrade/delegation.json --state .trustai/delegation-demo/evidence-chain.json --tenant delegation-local
```

## Delegation Graphs

`trustai.agent-delegation-graph/0.1` artifacts compile chain-backed delegation
entries into a signed graph that auditors can verify outside the running system.
Each node is keyed as `name@version`; inventory-observed nodes bind to their
`agent.inventory.discovered` source entry, and each edge binds to the exact
`agent.delegation.evidenced` entry, canonical delegation hash, Merkle inclusion
proof, contract hash, timestamp, reason, and scope.

The graph body includes:

- `source_chain`: tenant id, entry count, Merkle tree, first entry id, and last
  entry id for the chain prefix used to build the graph.
- `filters`: optional `contract_hash` and `root_agent` filters.
- `nodes`: agent refs with inventory source-entry bindings when available.
- `edges`: parent-to-child delegation edges with source-entry inclusion proofs.
- `summary`: node and edge counts, root agents, leaf agents, max depth,
  contract hashes, missing inventory, cycle detection, node root, and edge root.
- `controls`: edge binding, inventory binding, acyclic graph, and contract-scope
  control statuses.

Verification recomputes the graph id, verifies the artifact signature, checks
node/edge hashes, verifies embedded inclusion proofs against the recorded source
chain tree, rejects cycles, and, when a source chain is supplied, replays the
source entry bindings against the chain. The supplied chain may be longer than
the source prefix, which allows a graph to keep verifying after its own graph
receipt has been appended.

```powershell
python -m trustai delegation-graph --state .trustai/delegation-demo/evidence-chain.json --tenant delegation-local --contract-hash 22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2 --out artifacts/delegation-graph.json
python -m trustai delegation-graph-verify artifacts/delegation-graph.json --state .trustai/delegation-demo/evidence-chain.json --tenant delegation-local
python -m trustai delegation-graph-append artifacts/delegation-graph.json --state .trustai/delegation-demo/evidence-chain.json --tenant delegation-local --out artifacts/delegation-graph-entry.json
```
