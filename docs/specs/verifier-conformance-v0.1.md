# TrustAI Verifier Conformance Report v0.1

The verifier conformance report is a portable artifact proving that an offline
TrustAI verifier accepts a valid proof pack and rejects representative tamper
vectors. It supports the roadmap requirement that proof packs are verifiable by
third parties without a TrustAI account.

This v0.1 report exercises the local Python verifier implementation. The
roadmap still calls for an independently distributed Go verifier binary; Go
verifier build attestations record source-plan, recorded-build, or binary-attested
evidence separately until a Go toolchain and release workflow are available.

## Schema

`schema`: `trustai.verifier-conformance/0.1`

Required top-level fields:

- `report_id`: canonical hash of the report body.
- `generated_at`: creation timestamp.
- `verifier`: verifier command and mode.
- `source_proof_pack`: source pack id, hash, spec version, and chain summary.
- `test_cases`: verifier conformance vectors.
- `summary`: pass/fail counts.
- `limitations`: explicit production and implementation boundaries.

## Test Cases

The local report includes these cases:

- `valid-proof-pack`: a valid proof pack must verify successfully.
- `pack-signature-tamper`: a changed proof-pack signature must fail.
- `chain-entry-payload-tamper`: a changed evidence entry payload must fail.
- `inclusion-proof-tamper`: a changed Merkle inclusion proof must fail.
- `packed-contract-body-tamper`: a changed packed contract body must fail.

Each case records the expected verifier outcome, actual verifier outcome,
errors, warnings, and mutated pack content hash.

## Verification

`trustai verifier-conformance-verify` checks:

- schema version;
- `report_id` canonical hash;
- non-empty test-case list;
- expected versus actual verifier outcomes;
- test-case pass flags;
- summary consistency;
- offline/accountless verifier mode warning.

## CLI

```bash
python -m trustai verifier-conformance artifacts/aitrade-proof-pack.json --out artifacts/verifier-conformance.json --markdown artifacts/verifier-conformance.md
python -m trustai verifier-conformance-verify artifacts/verifier-conformance.json
```

## Production Boundary


## Release Binding

`trustai verifier-release` packages a conformance report with hashed verifier
source files, standards package metadata, release targets, and a detached
signature. `trustai verifier-release-verify` checks that package and can rerun
deep verification against the referenced conformance and standards artifacts.

A production verifier release still needs:

- independent implementation, ideally the roadmap's Go static binary;
- signed release artifacts and binary-attested Go verifier build records;
- reproducible builds;
- conformance vectors shared outside this repository;
- release-specific conformance reports;
- public verifier documentation and version compatibility policy.
