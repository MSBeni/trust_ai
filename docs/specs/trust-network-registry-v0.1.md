# Trust Network Registry Receipt v0.1

This specification defines a signed receipt for publishing a TrustAI vendor
trust-network submission into a registry. It sits after the trust-network
manifest, vendor identity receipt, identity-provider attestation, procurement
clause receipt, and procurement integration receipt. The receipt proves the
exact evidence bundle a registry would expose for a buyer/vendor relationship.

## Schema

`schema`: `trustai.trust-network-registry/0.1`

Required top-level fields:

- `registration_id`: canonical hash of the registry receipt body.
- `published_at`: RFC3339 publication timestamp.
- `expires_at`: optional RFC3339 expiry timestamp.
- `registry`: registry name, endpoint, namespace, local attestation mode, and
  production replacement guidance.
- `registration`: registration reference, status, visibility, terms reference,
  revocation endpoint, and idempotency key.
- `vendor`: vendor identity receipt summary, canonical hash, subject reference,
  identity-provider reference, trust-network manifest id, accepted flag, and
  proof-pack count.
- `trust_network`: manifest id, canonical hash, buyer, clause hash, accepted
  vendor count, framework requirements, and risk-class requirements.
- `proof_packs`: proof-pack references copied from the verified vendor identity
  receipt.
- `identity_provider`: optional identity-provider attestation summary.
- `procurement`: optional procurement clause and procurement integration
  summary.
- `registry_payload`: portable payload a hosted registry can publish or mirror.
- `source_artifacts`: canonical hash records for all bound source artifacts.
- `controls`: implemented-reference and planned-production registry controls.
- `signatures`: detached local HMAC signature over the registration id and body.

`registration.status` is one of `active`, `suspended`, or `revoked`.
`registration.visibility` is one of `private`, `buyer-vendor`, or `public`.

## Verification

`trustai trust-network-registry-verify` checks:

- schema, canonical `registration_id`, and signature;
- publication and optional expiry timestamps;
- registry name, endpoint, namespace, registration reference, idempotency key,
  status, and visibility;
- trust-network manifest source hash and full manifest verification when
  supplied;
- vendor identity source hash, accepted trust-network binding, and full vendor
  receipt verification when supplied;
- optional identity-provider attestation hash, provider identity match, and full
  attestation verification when supplied;
- optional procurement clause and procurement integration source hashes and full
  receipt verification when supplied;
- registry payload consistency with the supplied source artifacts.

Without source artifacts, verification can only prove receipt integrity and the
embedded artifact hashes; it emits warnings for missing deep-verification
inputs.

## Evidence Chain Entry

`trustai trust-network-registry-append` verifies the receipt, then appends
`trust_network.registry.published` to an evidence chain. The entry payload
records the registration id, receipt hash, registry metadata, registration
status, vendor and trust-network summaries, optional identity/procurement
summaries, source artifact references, and limitations.

## Reference Commands

```powershell
python -m trustai trust-network-registry artifacts/trust-network-manifest.json artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-name "TrustAI Local Registry" --registry-endpoint https://registry.example --namespace finserv-buyer --registration-ref TRUST-NET-2026-AITRADE-001 --published-at 2026-07-13T00:00:00Z --expires-at 2027-07-13T00:00:00Z --out artifacts/trust-network-registry.json
python -m trustai trust-network-registry-verify artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json
python -m trustai trust-network-registry-append artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --state .trustai/trust-network-registry-demo/evidence-chain.json --tenant trust-network-registry-local --out artifacts/trust-network-registry-entry.json
```

## Production Boundary

This local receipt models the hosted trust-network registry evidence shape.
Production deployments still need authenticated cross-org accounts, hosted
registry authorization, live identity-provider callbacks, durable publication
logs, revocation propagation, namespace governance, and dispute workflow for
suspended or revoked registrations.
