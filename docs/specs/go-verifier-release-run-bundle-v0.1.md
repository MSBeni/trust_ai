# Go Verifier Release-Run Bundle v0.1

Go verifier release-run bundles are self-contained offline review artifacts for
one signed Go verifier release workflow-run receipt. They package the receipt
with the signed verifier release manifest, Go build attestation, verifier
conformance report, standards package object, raw verifier release source files,
workflow source, build sidecars, hosted provenance, and release artifacts. The
schema is `trustai.go-verifier-release-run-bundle/0.1`.

## Contents

- `mode`: one of `offline-review`, `auditor-review`, or `standards-review`.
- `environment`, `generated_at`, `reviewer_ref`, and `bundle_ref`: review
  context and bundle identity.
- `source`: compact IDs and hashes for the release-run receipt, workflow run,
  verifier release, Go build attestation, build mode, binary hash, artifact
  count, and check count.
- `sources`: embedded parsed source objects. Required sources are
  `release_run`, `verifier_release`, `build_attestation`,
  `conformance_report`, and `standards_package`.
- `source_artifacts`: raw JSON bytes for the five source objects, with SHA-256,
  canonical content hash, expected content hash, size, base64 bytes, and
  artifact ID.
- `raw_artifacts`: embedded release source, workflow, release artifact, build
  sidecar, and hosted provenance bytes. Each record includes the original path
  or ref, size, actual SHA-256, expected SHA-256, base64 bytes, media type, and
  artifact ID.
- `summary`: source and raw artifact counts, hash roots, source object hashes,
  release source count, release artifact count, check count, build sidecar
  count, and release/build control summaries.
- `controls`: derived bundle controls for source object replay, verifier
  release source-byte binding, workflow source-byte binding, release artifact
  byte binding, build sidecar byte binding, hosted provenance byte binding, and
  standards package hash binding.
- `bundle_id` and `signatures`: canonical bundle hash and detached signatures.

## Verification

`trustai go-verifier-release-run-bundle-verify` checks:

1. Schema, canonical `bundle_id`, and at least one valid bundle signature.
2. Review mode, reviewer ref, and RFC 3339 generation timestamp.
3. Embedded source object presence and one-to-one JSON source artifact binding.
4. Verifier release manifest signature, source hashes, and conformance reference
   using only embedded release source bytes.
5. Go build attestation signature, release/conformance source binding, Go
   source records, static-build controls, binary metadata, and build sidecar raw
   byte presence.
6. Release-run receipt signature, release/build source binding, successful
   workflow run/checks, workflow source controls, release artifact byte
   presence, binary artifact binding, and hosted provenance byte presence.
7. Standards package object hash and package ID match the signed verifier
   release reference.
8. Bundle `source`, `summary`, and `controls` are recomputed from embedded
   sources.
9. Secret-like fields in embedded source objects are redacted references or
   hash/root/ref metadata.

Tampering with signed source objects, embedded JSON source bytes, raw workflow
source, build sidecars, hosted provenance, or release artifact bytes invalidates
the bundle. Verification does not need the original repository checkout or
artifact directory.

## CLI

```powershell
python -m trustai go-verifier-release-run-bundle artifacts/go-verifier-release-run.json artifacts/verifier-release.json artifacts/go-verifier-build-attestation.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --binary artifacts/trustai-verify-linux-amd64 --reviewer-ref oidc:auditor.example/go-verifier-release-reviewer --environment release-ci --generated-at 2026-07-16T00:06:00Z --out artifacts/go-verifier-release-run-bundle.json --markdown artifacts/go-verifier-release-run-bundle.md
python -m trustai go-verifier-release-run-bundle-verify artifacts/go-verifier-release-run-bundle.json
python -m trustai go-verifier-release-run-bundle-render artifacts/go-verifier-release-run-bundle.json --out artifacts/go-verifier-release-run-bundle.md
python -m trustai go-verifier-release-run-bundle-extract artifacts/go-verifier-release-run-bundle.json --out-dir artifacts/go-verifier-release-run-bundle-sources
python -m trustai go-verifier-release-run-bundle-append artifacts/go-verifier-release-run-bundle.json --state .trustai/go-verifier-release-run-bundle-demo/evidence-chain.json --tenant go-verifier-release-run-bundle-local --out artifacts/go-verifier-release-run-bundle-entry.json
```

## Limits

This bundle proves offline replay against embedded release-run evidence. It
binds the standards package JSON object by hash, but it does not inline every
standards markdown source file. Production release authority still requires
provider-native workflow run exports, immutable provider audit logs, public
release distribution, public verifier signatures, and independently retained
provider provenance.
