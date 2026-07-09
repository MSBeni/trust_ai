# Agent Registry and Delegation Evidence v0.1

The local registry records discovered agents and delegation edges as evidence
chain entries.

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
