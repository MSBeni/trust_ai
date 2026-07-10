# Verifier Release Manifest v0.1

The verifier release manifest packages the local verifier release evidence for
third-party review. It binds the verifier command, hashed source files,
conformance report, standards package, release targets, and detached signature
into one offline-verifiable artifact.

This v0.1 manifest signs the Python reference verifier source set and the
dependency-free Go offline verifier source tree. It does not claim that a Go
static binary has been produced. Downstream Go verifier build attestations bind
this release to source-plan, recorded-build, or binary-attested build evidence.

## Schema

`schema`: `trustai.verifier-release/0.1`

Top-level fields:

- `release_id`: canonical hash of the manifest body without `release_id` and
  `signatures`.
- `release`: release name, version, implementation, verifier command, mode,
  license, and runtime requirement.
- `source_files`: verifier source paths with `sha256` and `size_bytes`.
- `targets`: release targets, including the available Python reference module,
  available Go offline verifier source target, and planned Go static binary
  target.
- `conformance_report`: report id, content hash, case counts, verifier command,
  conformance targets, per-target case/pass counts, source proof-pack summary,
  and optional recorded-export provider bundle source summary from
  `trustai.verifier-conformance/0.1`.
- `standards_package`: package id, content hash, spec count, and required spec
  list from `trustai.standards-submission/0.1`.
- `signatures`: one or more signatures over `release_id` and the release body.
- `limitations`: explicit scope notes for production release work.

## Verification

`trustai verifier-release-verify` checks:

- manifest schema;
- release id canonical hash;
- detached signature;
- offline/accountless verifier mode;
- source file existence, size, and SHA-256 digest;
- inclusion of `src/trustai/verifier.py`;
- inclusion of `verifier/go/trustai-verify/main.go` when the Go source target is present;
- at least one available release target;
- referenced conformance report hash, target coverage, per-target case/pass
  counts, optional provider-bundle source binding, and conformance verification
  when supplied;
- referenced standards package hash and standards verification when supplied.

When a manifest references a conformance report but the report is not supplied
to verification, the verifier returns a warning rather than claiming deep
release validation.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai verifier-conformance artifacts/aitrade-proof-pack.json --out artifacts/verifier-conformance.json --markdown artifacts/verifier-conformance.md
python -m trustai verifier-conformance artifacts/aitrade-proof-pack.json --provider-bundle artifacts/framework-runtime-service-authority-recorded-export-provider-bundle.json --out artifacts/verifier-conformance.json --markdown artifacts/verifier-conformance.md
python -m trustai standards-export --out artifacts/standards-submission.json --markdown artifacts/standards-submission.md
python -m trustai verifier-release --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --out artifacts/verifier-release.json --markdown artifacts/verifier-release.md
python -m trustai verifier-release-verify artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json
python -m trustai go-verifier-build-attestation artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --mode source-plan --builder-ref builder:trustai/go-verifier/local --toolchain-ref go:download-required --toolchain-version not-installed-local-reference --goos linux --goarch amd64 --build-started-at 2026-07-16T00:00:00Z --build-finished-at 2026-07-16T00:01:00Z --attested-at 2026-07-16T00:02:00Z --out artifacts/go-verifier-build-attestation.json
python -m trustai go-verifier-build-verify artifacts/go-verifier-build-attestation.json artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root .
```

Production release work still requires independently built binaries, public-key
signatures, SBOMs, binary-attested build records, installer/release-channel governance, and release-specific
conformance reruns.
