# Standards-Body Ballot-System Receipt v0.1

Status: local reference specification

## Purpose

A standards-body ballot-system receipt records a hosted ballot-system export for
an accepted TrustAI standards-body ballot. It binds the accepted ballot receipt,
redacted credential reference, request hash, export payload hash, optional
provider response hash, and export metadata by canonical hash.

This receipt narrows the gap between local ballot certification and production
standards-body hosted ballot-system integration. It does not claim live access
to a standards body unless the receipt is backed by authenticated-export mode,
a standards-body actor reference, and a provider response.

## Schema

`schema`: `trustai.standards-body-ballot-system/0.1`

Required top-level fields:

- `integration_id`: canonical hash of the receipt body.
- `mode`: one of `dry-run`, `recorded-response`, or `authenticated-export`.
- `exported_at`: RFC 3339 timestamp for the recorded export event.
- `ballot_system`: system name, endpoint base, redacted credential reference,
  attestation mode, and production replacement boundary.
- `ballot`: accepted ballot identity, decision reference, submission reference,
  standards-body context, conformance targets, and optional provider-bundle
  source binding.
- `request`: method, path, target URL, request body, request body hash, and
  idempotency key.
- `export`: export reference, format, generated timestamp, content hash,
  payload, record count, optional result URL, actor reference, and evidence
  references.
- `source_artifacts`: canonical hash for the source ballot receipt.
- `integration_payload_hash`: canonical hash over the ballot, system, request
  hash, and export metadata.
- `signatures`: detached local reference signatures over `integration_id` and
  body.

`recorded-response` and `authenticated-export` receipts also include a
`response` object with provider status, response body hash, and accepted flag.

## Verification

`trustai standards-body-ballot-system-verify` checks:

1. Schema, canonical `integration_id`, and signature.
2. Timestamp ordering: `export.generated_at <= exported_at`.
3. Ballot-system name, endpoint, and redacted credential reference.
4. Accepted ballot record and source ballot artifact binding.
5. Request method, path, target URL, body hash, source ballot consistency, and
   conformance target propagation.
6. Export reference, format, payload hash, source ballot consistency, and
   conformance target propagation.
7. Response status/body hash for recorded or authenticated modes.
8. Authenticated mode has a standards-body actor reference and accepted response.
9. Optional source ballot receipt validity and accepted outcome.
10. `integration_payload_hash` matches the normalized integration records.

## Evidence Chain Entry

`trustai standards-body-ballot-system-append` verifies the receipt, then appends
an entry of type `standards.body.ballot_system.exported` with:

- `integration_id`
- `integration_hash`
- mode and ballot-system metadata
- accepted ballot record with conformance scope
- request hash and target
- export metadata without inline payload
- optional provider response hash
- source artifact references
- limitations

## Reference Commands

```powershell
$env:PYTHONPATH = "src"
python -m trustai standards-body-ballot-system artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --ballot-system "LF TrustAI Ballot System" --endpoint-base https://ballots.example --credential-ref env:STANDARDS_BALLOT_TOKEN --mode authenticated-export --export-ref LF-TRUSTAI-BALLOT-2026-001:export --export-url https://ballots.example/exports/LF-TRUSTAI-BALLOT-2026-001 --actor-ref oidc:standards.example/ballot-system --response-status 200 --response-body examples/aitrade/standards-ballot-system-response.json --exported-at 2026-07-25T04:00:00Z --out artifacts/standards-body-ballot-system.json
python -m trustai standards-body-ballot-system-verify artifacts/standards-body-ballot-system.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json
python -m trustai standards-body-ballot-system-append artifacts/standards-body-ballot-system.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --state .trustai/standards-body-ballot-system-demo/evidence-chain.json --tenant standards-body-ballot-system-local --out artifacts/standards-body-ballot-system-entry.json
```

## Production Boundary

This v0.1 receipt is a local reference artifact. Production hosted
standards-body integration should replace local endpoint and credential
references with authenticated standards-body accounts, signed ballot-system
exports, immutable provider response archives, service-account identity
attestation, and public docket/export URLs controlled by the standards body.
