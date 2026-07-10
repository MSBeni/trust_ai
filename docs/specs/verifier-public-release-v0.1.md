# Verifier Public Release Receipt v0.1

Verifier public release receipts bind the open verifier release to the evidence a
third party expects when deciding whether a published verifier binary and source
bundle are acceptable. The schema is `trustai.verifier-public-release/0.1` and
the evidence-chain entry type is `verifier.public_release_attested`.

## Sources

The receipt composes five signed sources:

- verifier release manifest;
- verifier source distribution receipt;
- Go verifier build attestation;
- Go verifier release workflow-run receipt;
- Go verifier release-run review bundle.

When all sources are supplied, verification replays each source verifier and
checks that release, distribution, build, workflow-run, and bundle hashes point
to the same verifier release.

## Contents

- `public_release`: provider, release ref, release URL, tag, publisher, mode,
  and publication timestamp.
- `source`: compact IDs and content hashes for the five source receipts plus
  conformance and standards package bindings.
- `artifacts`: public release artifact records. Each record includes name, local
  path, kind, public URL, SHA-256, size, media type, and artifact ID.
- `provider_evidence`: provider-native workflow run export, release API export,
  artifact manifest export, immutable audit-log root/size, optional transparency
  log root, and retention timestamp.
- `controls`: signed source distribution, build/workflow-run binding, offline
  review bundle binding, public artifact publication, provider-native export
  binding, immutable audit-log binding, and public-release authority.
- `release_publication_id` and `signatures`: canonical receipt hash and detached
  signatures.

## Verification

`trustai verifier-public-release-verify` checks:

1. Schema, canonical `release_publication_id`, and detached signature.
2. Public release metadata and timestamps.
3. Provider evidence hash fields and audit-log shape.
4. Public artifact IDs, local artifact byte hashes when paths are present, and
   duplicate artifact names.
5. Source distribution artifacts from the distribution receipt are present in
   the public release artifact set.
6. Release-run artifacts from the workflow-run receipt are present in the public
   release artifact set.
7. Deep verification of the verifier release, source distribution, Go build
   attestation, release-run receipt, and release-run review bundle when supplied.
8. Recomputed `source` and `controls` match the receipt.

## CLI

```powershell
python -m trustai verifier-public-release artifacts/verifier-release.json artifacts/verifier-distribution.json artifacts/go-verifier-build-attestation.json artifacts/go-verifier-release-run.json artifacts/go-verifier-release-run-bundle.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --distribution-bundle artifacts/verifier-source-bundle.zip --distribution-sbom artifacts/verifier-source-sbom.json --distribution-provenance artifacts/verifier-source-provenance.json --distribution-signature artifacts/verifier-source-signature.json --binary artifacts/trustai-verify-linux-amd64 --artifact "verifier-source-bundle.zip,artifacts/verifier-source-bundle.zip,source-bundle,https://github.com/MSBeni/trust_ai/releases/download/v0.1.0/verifier-source-bundle.zip" --artifact "trustai-verify-linux-amd64,artifacts/trustai-verify-linux-amd64,binary,https://github.com/MSBeni/trust_ai/releases/download/v0.1.0/trustai-verify-linux-amd64" --provider github --release-ref github:MSBeni/trust_ai/releases/tag/v0.1.0 --release-url https://github.com/MSBeni/trust_ai/releases/tag/v0.1.0 --tag v0.1.0 --publisher-ref publisher:trustai/release-bot --workflow-run-export-ref github-actions-run:1234567890 --workflow-run-export-hash sha256:1111111111111111111111111111111111111111111111111111111111111111 --release-api-export-ref github-release-api:v0.1.0 --release-api-export-hash sha256:1111111111111111111111111111111111111111111111111111111111111111 --artifact-manifest-ref github-release-artifacts:v0.1.0 --artifact-manifest-hash sha256:1111111111111111111111111111111111111111111111111111111111111111 --audit-log-ref github-audit-log:MSBeni/trust_ai/releases/v0.1.0 --audit-log-root sha256:1111111111111111111111111111111111111111111111111111111111111111 --audit-log-size 8 --published-at 2026-07-16T00:07:00Z --out artifacts/verifier-public-release.json
python -m trustai verifier-public-release-verify artifacts/verifier-public-release.json artifacts/verifier-release.json artifacts/verifier-distribution.json artifacts/go-verifier-build-attestation.json artifacts/go-verifier-release-run.json artifacts/go-verifier-release-run-bundle.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --distribution-bundle artifacts/verifier-source-bundle.zip --distribution-sbom artifacts/verifier-source-sbom.json --distribution-provenance artifacts/verifier-source-provenance.json --distribution-signature artifacts/verifier-source-signature.json --binary artifacts/trustai-verify-linux-amd64
python -m trustai verifier-public-release-append artifacts/verifier-public-release.json artifacts/verifier-release.json artifacts/verifier-distribution.json artifacts/go-verifier-build-attestation.json artifacts/go-verifier-release-run.json artifacts/go-verifier-release-run-bundle.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --distribution-bundle artifacts/verifier-source-bundle.zip --distribution-sbom artifacts/verifier-source-sbom.json --distribution-provenance artifacts/verifier-source-provenance.json --distribution-signature artifacts/verifier-source-signature.json --binary artifacts/trustai-verify-linux-amd64 --state .trustai/verifier-public-release-demo/evidence-chain.json --tenant verifier-public-release-local --out artifacts/verifier-public-release-entry.json
```

## Production Boundary

This receipt is the offline proof wrapper for public release authority. It does
not perform live GitHub or release-provider API calls. Production use still
requires the referenced provider-native workflow run export, release API export,
artifact manifest export, public signatures, transparency-log entries, and
immutable audit logs to be retained and made available for replay.
