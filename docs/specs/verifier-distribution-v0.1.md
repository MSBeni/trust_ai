# Verifier Distribution Receipt v0.1

Verifier distribution receipts prove that the offline verifier source release was
packaged into a portable source bundle with a file-inventory SBOM, provenance
metadata, and a detached signature artifact.

Schema: `trustai.verifier-distribution/0.1`.

The receipt is intentionally separate from the Go static binary build
attestation. It strengthens the open verifier release by making the source
distribution independently reproducible and inspectable, while still avoiding
any claim that a compiled Go binary exists when no Go toolchain or binary
artifact was supplied.

## Required Inputs

- A signed `trustai.verifier-release/0.1` manifest.
- The verifier conformance report referenced by that release.
- The standards package referenced by that release.
- A bundle path, SBOM path, provenance path, and detached signature path.
- Distribution metadata: reference, channel, publisher, optional release URL,
  and generation time.

## Produced Artifacts

- Source bundle zip containing:
  - `manifest/verifier-release.json`
  - `evidence/verifier-conformance.json`
  - `evidence/standards-submission.json`
  - `source/...` entries for every source file in the release manifest
- `trustai.verifier-source-sbom/0.1` JSON file inventory, including release
  conformance targets and per-target coverage.
- `trustai.verifier-source-provenance/0.1` provenance metadata, including the
  conformance material target list, per-target coverage, and optional provider
  bundle source binding.
- `trustai.verifier-source-bundle-signature/0.1` detached signature subject.
- A signed verifier distribution receipt that binds all artifact hashes.

## Verification

`trustai verifier-distribution-verify` checks:

- receipt schema, canonical `distribution_id`, and signature;
- verifier release, conformance report, conformance target coverage, optional
  provider-bundle source binding, and standards package bindings;
- source bundle SHA-256, size, file list, and per-entry hashes;
- SBOM, provenance, and detached signature artifact schemas and hashes;
- detached signature subject and HMAC signature;
- accountless source-bundle distribution controls.

## Limitations

This receipt proves source distribution integrity and release conformance-scope
binding only. Production binary release authority still requires a compiled
static Go verifier binary, binary hash, binary SBOM/provenance, and public
release signature.

## Example

```bash
python -m trustai verifier-distribution artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --bundle artifacts/verifier-source-bundle.zip --sbom artifacts/verifier-source-sbom.json --provenance artifacts/verifier-source-provenance.json --signature artifacts/verifier-source-signature.json --distribution-ref release:trustai-verifier/source-v0.1 --channel local-source-bundle --publisher-ref publisher:trustai/local --release-url https://github.com/MSBeni/trust_ai/releases/tag/source-v0.1 --generated-at 2026-07-16T00:03:00Z --out artifacts/verifier-distribution.json
python -m trustai verifier-distribution-verify artifacts/verifier-distribution.json artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --bundle artifacts/verifier-source-bundle.zip --sbom artifacts/verifier-source-sbom.json --provenance artifacts/verifier-source-provenance.json --signature artifacts/verifier-source-signature.json
python -m trustai verifier-distribution-append artifacts/verifier-distribution.json artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --bundle artifacts/verifier-source-bundle.zip --sbom artifacts/verifier-source-sbom.json --provenance artifacts/verifier-source-provenance.json --signature artifacts/verifier-source-signature.json --state .trustai/verifier-distribution-demo/evidence-chain.json --tenant verifier-distribution-local --out artifacts/verifier-distribution-entry.json
```
