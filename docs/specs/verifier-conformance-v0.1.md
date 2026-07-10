# TrustAI Verifier Conformance Report v0.1

The verifier conformance report is a portable artifact proving that an offline
TrustAI verifier accepts a valid proof pack and rejects representative tamper
vectors. When supplied with a recorded-export provider review bundle, the same
report also proves that the offline bundle verifier accepts the self-contained
review bundle and rejects representative bundle tamper vectors. When supplied
with a Go verifier release workflow-run receipt, it also proves release-run
receipt verification accepts valid release evidence and rejects representative
release-run tamper vectors. It supports the roadmap requirement that proof packs
and review evidence are verifiable by third parties without a TrustAI account.

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
- `source_proof_pack`: source pack id, hash, spec version, chain summary, and delegation graph entry count.
- `source_provider_bundle`: optional recorded-export provider bundle id, hash,
  schema, source receipt ids, and embedded source artifact summary.
- `source_release_run`: optional Go verifier release-run id, hash, schema,
  release id, build id, workflow run id, commit, artifact count, and check count.
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

When the proof pack contains `agent.delegation_graph.exported` evidence, the
report also includes:

- `delegation-graph-tamper`: a changed embedded delegation graph edge must fail.

When `--provider-bundle` is supplied, the report also includes:

- `valid-provider-bundle`: a valid recorded-export provider bundle must verify
  successfully.
- `provider-bundle-signature-tamper`: a changed bundle signature must fail.
- `provider-bundle-source-tamper`: a changed embedded provider export source
  object must fail.
- `provider-bundle-artifact-byte-tamper`: changed embedded raw source artifact
  bytes must fail.

When `--release-run` is supplied with its release manifest and build attestation
sources, the report also includes:

- `valid-go-verifier-release-run`: a valid Go verifier release workflow-run
  receipt must verify successfully.
- `go-verifier-release-run-signature-tamper`: a changed release-run signature
  must fail.
- `go-verifier-release-run-workflow-tamper`: a changed workflow source digest
  must fail.
- `go-verifier-release-run-artifact-tamper`: a changed release artifact digest
  must fail.

Each case records the expected verifier outcome, actual verifier outcome,
errors, warnings, target artifact type, and the mutated proof-pack, bundle, or
release-run content hash.

## Verification

`trustai verifier-conformance-verify` checks:

- schema version;
- `report_id` canonical hash;
- non-empty test-case list;
- expected versus actual verifier outcomes;
- test-case pass flags;
- summary consistency;
- optional provider-bundle source binding and bundle tamper-vector outcomes;
- optional Go verifier release-run source binding and release-run tamper-vector outcomes;
- offline/accountless verifier mode warning.

## CLI

```bash
python -m trustai verifier-conformance artifacts/aitrade-proof-pack.json --out artifacts/verifier-conformance.json --markdown artifacts/verifier-conformance.md
python -m trustai verifier-conformance artifacts/aitrade-proof-pack.json --provider-bundle artifacts/framework-runtime-service-authority-recorded-export-provider-bundle.json --out artifacts/verifier-conformance.json --markdown artifacts/verifier-conformance.md
python -m trustai verifier-conformance artifacts/aitrade-proof-pack.json --release-run artifacts/go-verifier-release-run.json --release-run-verifier-release artifacts/verifier-release.json --release-run-build-attestation artifacts/go-verifier-build-attestation.json --release-run-conformance-report artifacts/verifier-conformance.json --release-run-standards-package artifacts/standards-submission.json --release-run-root . --release-run-binary artifacts/trustai-verify-linux-amd64 --out artifacts/verifier-conformance.json --markdown artifacts/verifier-conformance.md
python -m trustai verifier-conformance-verify artifacts/verifier-conformance.json
```

## Production Boundary

This v0.1 conformance report is still a local reference artifact. Provider
bundle and release-run vectors prove deterministic offline replay of the
supplied artifacts; they do not prove live access to a provider account, fresh
external-authority evidence, provider-native workflow operation, or
independently shipped verifier binaries. Those requirements remain bound through
the provider receipts, authority dossiers, verifier release manifest,
distribution receipts, build attestations, and release-run receipts.

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
