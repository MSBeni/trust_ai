# Identity Provider Attestation Receipt v0.1

This specification defines a signed receipt for binding a recorded identity
provider export to TrustAI vendor and proof-pack evidence. It complements
identity inventory ingestion: inventory entries discover agents, while this
receipt proves that a specific provider identity record is the identity source
for a vendor identity receipt and its proof-pack-backed agent.

## Schema

`schema`: `trustai.identity-provider-attestation/0.1`

Required top-level fields:

- `attestation_id`: canonical hash of the attestation body.
- `issued_at`: RFC3339 timestamp for the attestation.
- `expires_at`: optional RFC3339 expiry timestamp.
- `issuer`: local issuer or future identity registry issuer reference.
- `authentication`: authentication method, provider, tenant reference,
  observed timestamp, source name, local attestation mode, and production
  replacement guidance.
- `source_payload`: canonical hash of the raw identity-provider export,
  normalized inventory hash, record count, and providers represented.
- `source_artifacts`: optional retained raw identity-provider export artifact
  path, SHA-256 byte hash, size, media type, and canonical payload hash used
  for replay.
- `subject`: selected provider identity id, identity record hash, subject
  reference, and normalized agent summary.
- `vendor_binding`: optional vendor identity receipt id/hash, vendor identity
  references, provider identity match flag, matching proof-pack ids, and
  trust-network manifest id.
- `controls`: implemented-reference and planned-production controls.
- `signatures`: detached local HMAC signature over the attestation id and body.

Supported providers are `okta`, `entra`, and `servicenow`, matching the local
identity inventory adapters.

## Verification

`trustai identity-attestation-verify` checks:

- schema, canonical `attestation_id`, and signature;
- issued/expiry timestamp syntax and ordering;
- supported provider, authentication method, and observed timestamp;
- source payload hash and normalized inventory hash when the raw provider export
  is supplied;
- retained raw export artifact records and supplied identity payload paths when
  present;
- selected subject identity id, identity record hash, and agent summary;
- source vendor identity receipt hash and full verification when supplied;
- provider identity id and proof-pack agent binding against the vendor receipt.

Without the source identity export, retained raw export path, or source vendor
identity receipt, verification can only prove receipt integrity and embedded
artifact bindings; it emits warnings for missing deep-verification inputs.

## Evidence Chain Entry

`trustai identity-attestation-append` verifies the receipt, then appends
`identity.provider.attested` to an evidence chain. The entry payload records the
attestation id, attestation hash, authentication metadata, subject, vendor
binding, source payload hash, source artifact hashes, and limitations.

## Reference Commands

```powershell
python -m trustai identity-attestation examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --provider okta --identity-id okta-agent-aitrade-risk --tenant-ref okta:example-org --issued-at 2026-07-10T01:00:00Z --expires-at 2027-07-10T01:00:00Z --out artifacts/identity-provider-attestation.json
python -m trustai identity-attestation-verify artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json
python -m trustai identity-attestation-append artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --state .trustai/identity-provider-demo/evidence-chain.json --tenant identity-provider-local --out artifacts/identity-provider-attestation-entry.json
```

## Production Boundary

This local receipt models identity-provider authentication evidence using a
recorded export and can replay the retained raw export file by byte hash when
that file path is supplied. Production deployments still need provider-authenticated API
responses, signed SCIM/Graph/Okta events, tenant trust configuration, key
rotation/revocation handling, and legal-entity validation outside the identity
provider record.
