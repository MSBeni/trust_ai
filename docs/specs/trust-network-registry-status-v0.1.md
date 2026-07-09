# Trust Network Registry Status Receipt v0.1

This specification defines a signed receipt for changing the status of a
published TrustAI trust-network registry registration. It sits after the
registry publication receipt and models suspension, revocation, and reactivation
evidence without requiring a hosted registry.

## Schema

`schema`: `trustai.trust-network-registry-status/0.1`

Required top-level fields:

- `status_id`: canonical hash of the status receipt body.
- `decided_at`: RFC3339 decision timestamp.
- `effective_at`: RFC3339 timestamp when the status change takes effect.
- `target_registration`: registration id, registration reference, registry
  namespace, vendor identity summary, and trust-network manifest reference from
  the source registry receipt.
- `status_update`: previous status, new status, reason, optional reason code,
  actor reference, optional dispute metadata, and status payload hash.
- `source_artifacts`: canonical hash record for the source registry receipt.
- `controls`: implemented-reference and planned-production status controls.
- `signatures`: detached local HMAC signature over the status id and body.

`status_update.previous_status` and `status_update.new_status` are each one of
`active`, `suspended`, or `revoked`, and they must differ.

## Verification

`trustai trust-network-registry-status-verify` checks:

- schema, canonical `status_id`, and signature;
- decision/effective timestamps and optional dispute window;
- previous status, new status, reason, actor reference, and actor role;
- source registry receipt hash and full registry verification when supplied;
- target registration consistency with the source registry receipt;
- previous status consistency with the source registry receipt;
- status payload hash consistency.

Without the source registry receipt, verification can only prove receipt
integrity and the embedded registry hash; it emits a warning for the missing
deep-verification input.

## Evidence Chain Entry

`trustai trust-network-registry-status-append` verifies the receipt, then
appends `trust_network.registry.status_changed` to an evidence chain. The entry
payload records the status id, status hash, target registration, previous and
new status, actor, status payload hash, source registry reference, and
limitations.

## Reference Commands

```powershell
python -m trustai trust-network-registry-status artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --status suspended --reason "Buyer dispute opened after procurement review." --reason-code buyer-dispute --actor-ref oidc:buyer.example/procurement-reviewer --actor-role buyer-procurement --decided-at 2026-07-14T00:00:00Z --effective-at 2026-07-14T01:00:00Z --dispute-ref DISPUTE-2026-AITRADE-001 --dispute-window-until 2026-08-14T00:00:00Z --evidence-ref ticket:SNOW-1234 --out artifacts/trust-network-registry-status.json
python -m trustai trust-network-registry-status-verify artifacts/trust-network-registry-status.json --registry artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json
python -m trustai trust-network-registry-status-append artifacts/trust-network-registry-status.json --registry artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --state .trustai/trust-network-registry-demo/evidence-chain.json --tenant trust-network-registry-local --out artifacts/trust-network-registry-status-entry.json
```

## Production Boundary

This local receipt models status-change evidence for a hosted trust-network
registry. Production deployments still need authenticated registry operators,
subscription/index propagation audit, cache invalidation, buyer/vendor dispute
workflows, and enforcement by live registry lookup.
