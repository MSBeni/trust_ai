# Vendor Identity Receipt v0.1

This specification defines a signed receipt that binds a vendor identity
reference to one or more TrustAI proof packs and, optionally, to a buyer
trust-network manifest submission. It closes the local Phase 4 gap between
"this proof pack verified" and "this vendor identity is the party associated
with that accepted proof."

## Schema

`schema`: `trustai.vendor-identity/0.1`

Required top-level fields:

- `receipt_id`: canonical hash of the receipt body.
- `issued_at`: RFC3339 timestamp for the identity attestation.
- `expires_at`: optional RFC3339 expiry timestamp.
- `issuer`: local issuer or future registry issuer reference.
- `vendor`: vendor display name, legal name, subject reference, optional
  domain, optional identity-provider/id references, local attestation mode, and
  production replacement guidance.
- `proof_packs`: canonical hash bindings for each source proof pack, including
  pack id, contract id/hash, gate outcome, agent summary, and chain root.
- `trust_network`: optional trust-network manifest id/hash, buyer, procurement
  clause summary, and accepted vendor submission references.
- `controls`: implemented-reference and planned-production controls.
- `signatures`: detached local HMAC signature over the receipt id and body.

## Verification

`trustai vendor-identity-verify` checks:

- schema, canonical `receipt_id`, and signature;
- required vendor identity fields;
- issued/expiry timestamp syntax and ordering;
- non-empty proof-pack bindings;
- source proof-pack hashes and full offline proof-pack verification when packs
  are supplied;
- trust-network manifest hash, buyer, accepted submissions, and procurement
  requirement binding when a source manifest is supplied.

Without source proof packs or the source trust-network manifest, verification
can prove receipt integrity and embedded artifact bindings only; it emits
warnings for missing deep-verification inputs.

## Evidence Chain Entry

`trustai vendor-identity-append` verifies the receipt, then appends
`vendor.identity.attested` to an evidence chain. The entry payload records the
receipt id, receipt hash, vendor identity summary, proof-pack references,
optional trust-network reference, and limitations.

## Reference Commands

```powershell
python -m trustai vendor-identity --pack artifacts/aitrade-proof-pack.json --manifest artifacts/trust-network-manifest.json --vendor aitrade --legal-name "Aitrade Labs Inc." --subject-ref did:web:aitrade.example --domain aitrade.example --identity-provider okta --identity-id okta-agent-aitrade-risk --issued-at 2026-07-10T00:00:00Z --expires-at 2027-07-10T00:00:00Z --out artifacts/vendor-identity-receipt.json
python -m trustai vendor-identity-verify artifacts/vendor-identity-receipt.json --pack artifacts/aitrade-proof-pack.json --manifest artifacts/trust-network-manifest.json
python -m trustai vendor-identity-append artifacts/vendor-identity-receipt.json --pack artifacts/aitrade-proof-pack.json --manifest artifacts/trust-network-manifest.json --state .trustai/vendor-identity-demo/evidence-chain.json --tenant vendor-identity-local --out artifacts/vendor-identity-entry.json
```

## Production Boundary

This local receipt models the portable evidence shape. Production deployments
still need authenticated vendor identity-provider events, legal-entity
validation, registry enrollment/revocation, procurement-platform federation,
and dispute workflow for mismatched vendor submissions.
