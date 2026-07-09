# Standards-Body Provider Posting Receipt v0.1

## Purpose

The standards-body provider posting receipt records the credentialed posting step
after a hosted ballot-system export is produced. It is the local reference form
for production standards-body API posting evidence: credential exchange metadata,
request hash, response hash, provider-assigned posting reference, and a canonical
binding back to the accepted ballot-system export.

This receipt closes the local chain:

1. standards-body submission receipt;
2. standards-body status receipt;
3. standards-body ballot receipt;
4. hosted ballot-system export receipt;
5. standards-body provider posting receipt.

## Schema

`schema`: `trustai.standards-body-provider-posting/0.1`

Required top-level fields:

- `posting_id`: canonical hash of the receipt body without signatures.
- `mode`: one of `dry-run`, `credential-exchange`, `recorded-response`, or
  `provider-posted`.
- `posted_at`: RFC 3339 timestamp at or after the source export timestamp.
- `provider`: provider name, endpoint base, attestation mode, and production
  replacement description.
- `source`: normalized summary of the ballot-system export receipt, including
  its `integration_id`, canonical hash, export metadata, and accepted ballot
  metadata.
- `credential_exchange`: redacted credential reference, optional audience and
  scope, actor reference, and optional response hash.
- `request`: provider posting method, path, target URL, request body, body hash,
  and idempotency key.
- `posting`: provider posting reference, optional durable URL, actor reference,
  and evidence references.
- `source_artifacts`: exactly one source artifact named
  `standards_body_ballot_system_receipt`.
- `posting_payload_hash`: canonical hash over the normalized source, provider,
  credential-exchange metadata without response, request hash, and posting
  metadata.
- `signatures`: detached signatures over `posting_id` and the receipt body.

`provider-posted` mode additionally requires:

- non-dry-run source ballot-system export receipt;
- authenticated actor reference;
- accepted credential exchange response hash;
- accepted provider posting response hash.

## Verification

`trustai standards-body-provider-posting-verify` checks:

- schema and canonical `posting_id`;
- receipt signature;
- timestamp ordering from source export to provider posting;
- redacted credential reference;
- accepted source ballot;
- request body hash and deterministic request body binding;
- source artifact hash against the supplied ballot-system export receipt;
- source ballot-system export receipt validity when supplied;
- credential-exchange response requirements for credentialed modes;
- provider response requirements for recorded/provider-posted modes;
- `posting_payload_hash` consistency.

Verification can run with only the provider posting receipt, but source artifact
checks are strongest when the ballot-system export receipt and its upstream
standards-body receipts are supplied.

## Chain Entry

`trustai standards-body-provider-posting-append` verifies the receipt and appends
entry type:

`standards.body.provider_posting.recorded`

The entry payload includes:

- `posting_id`;
- canonical receipt hash;
- mode and provider;
- source integration/export/ballot summary;
- redacted credential exchange summary;
- request hash and idempotency key;
- provider response hash if present;
- source artifact references;
- limitations.

## Reference Commands

```powershell
python -m trustai standards-body-provider-posting artifacts/standards-body-ballot-system.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --provider LFStandardsPostingAPI --endpoint-base https://standards.example --credential-ref env:STANDARDS_API_TOKEN --credential-exchange-url https://standards.example/oauth/token --credential-audience standards-api --credential-scope ballot:write --credential-scope export:publish --mode provider-posted --posting-ref LF-TRUSTAI-BALLOT-2026-001:provider-post --posting-url https://standards.example/api/v1/ballot-exports/LF-TRUSTAI-BALLOT-2026-001 --actor-ref oidc:standards.example/ballot-system --credential-response-status 200 --response-status 201 --posted-at 2026-07-25T05:00:00Z --out artifacts/standards-body-provider-posting.json
python -m trustai standards-body-provider-posting-verify artifacts/standards-body-provider-posting.json --ballot-system artifacts/standards-body-ballot-system.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json
python -m trustai standards-body-provider-posting-append artifacts/standards-body-provider-posting.json --ballot-system artifacts/standards-body-ballot-system.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --state .trustai/standards-body-provider-posting-demo/evidence-chain.json --tenant standards-body-provider-posting-local --out artifacts/standards-body-provider-posting-entry.json
```

## Production Boundary

The local implementation records redacted credential references and response
hashes. A production standards-body deployment should supply the actual provider
authentication layer, immutable request/response archives, credential rotation
and revocation evidence, provider-owned actor identity, and durable posting
references.
