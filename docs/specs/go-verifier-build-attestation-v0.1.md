# Go Verifier Build Attestation v0.1

This specification defines signed attestations for the Go offline verifier build
path. It binds the verifier release manifest, conformance report, standards
package, Go source files, static-build controls, optional build logs, optional
binary hashes, supply-chain provenance, and structured binary signature replay
into a portable artifact.

The attestation intentionally separates three modes:

- `source-plan`: the Go verifier source, release binding, and required static
  build controls are attested, but no compiled binary is claimed.
- `recorded-build`: a build was run and a build log reference/hash is included,
  but a final binary hash may still be absent.
- `binary-attested`: a compiled verifier binary is included by path, hash, and
  size, with build log, SBOM, provenance, and a structured binary signature
  artifact that verifies against those bindings.

## Artifact

The JSON artifact uses schema
`trustai.go-verifier-build-attestation/0.1` and appends to the evidence chain as
entry type `verifier.go_build_attested`.

Required top-level fields:

- `schema`: the schema identifier.
- `build_id`: canonical content hash of the attested build body.
- `source`: release, conformance, standards, and Go source binding summary.
- `build`: mode, builder, toolchain, target platform, command, and static-build
  controls.
- `binary`: binary availability status and optional binary hash metadata.
- `provenance`: optional SBOM, provenance, and signature references and hashes.
- `binary_signature`: replay status for the structured binary signature artifact.
- `controls`: verifier build controls and current pass/fail/not-applicable
  status.
- `signatures`: detached signature over the build body and `build_id`.

## Source Binding

`source` must include:

- `release_id`, `release_hash`, and `release_version`.
- `go_source_count` and `go_source_hash`.
- top-level `go_sources`, with each Go verifier source path, SHA-256 hash, and size.
- `conformance_report_id`.
- `standards_package_id`.

Verifiers must re-verify the referenced verifier release manifest when supplied
and must reject attestations whose release metadata or Go source records no
longer match.

## Build Controls

`build` must include:

- `mode`: one of `source-plan`, `recorded-build`, or `binary-attested`.
- `builder_ref`: identity of the local, CI, or release builder.
- `toolchain_ref` and `toolchain_version`.
- `goos` and `goarch`.
- `cgo_enabled`: must be `false` for the static verifier target.
- `trimpath`: must be `true` for reproducible source-path handling.
- `ldflags`: expected to include static release stripping flags such as
  `-s -w`.
- `build_command`: the build command used or planned.
- `build_started_at`, `build_finished_at`, `build_log_ref`, and
  `build_log_hash` when a recorded or binary build is claimed.

`source-plan` attestations may omit build log and binary hashes, but verifiers
must emit warnings that no binary has been produced.

## Binary and Provenance

`binary-attested` mode requires:

- `binary.status` equal to `available`.
- `binary.path`.
- `binary.sha256`.
- `binary.size_bytes`.
- `build.build_log_ref` and `build.build_log_hash`.
- `provenance.sbom_ref` and `provenance.sbom_hash`.
- `provenance.provenance_ref` and `provenance.provenance_hash`.
- `provenance.signature_ref` and `provenance.signature_hash`.
- `binary_signature.verified` equal to `true`.

The signature sidecar referenced by `provenance.signature_ref` must be a JSON
artifact with schema `trustai.go-verifier-binary-signature/0.1`. Its signed
`subject` binds the verifier release/source summary, binary path/hash/size, build
log hash, SBOM hash, and provenance hash. Verifiers must reject a
`binary-attested` attestation when the sidecar is missing, unstructured, signed
with the wrong payload, or its subject no longer matches the replayed release,
binary, build log, SBOM, and provenance bindings.

The verifier must reject a `binary-attested` attestation without those fields or
when the supplied binary bytes do not replay to the recorded hash and size. When
build-log, SBOM, provenance, or signature refs resolve to local paths, their
bytes must also replay to the recorded hashes. `recorded-build` mode requires
build-log metadata but may omit the binary hash while the release process is
still staging the artifact.

## Verification

An implementation verifies:

1. Schema and canonical `build_id`.
2. Detached signature over the build body.
3. Source binding against the supplied verifier release manifest, conformance
   report, standards package, and repository source files.
4. Static-build controls: `cgo_enabled=false` and `trimpath=true`.
5. Mode-specific build-log, binary, provenance, and binary signature
   requirements.
6. Chain append payloads include the full attestation and verification summary.

## CLI

Reference commands:

```powershell
# Source-plan fallback when no local Go toolchain or binary artifact is available.
python -m trustai go-verifier-build-attestation artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --mode source-plan --builder-ref builder:trustai/go-verifier/local --toolchain-ref go:download-required --toolchain-version not-installed-local-reference --goos linux --goarch amd64 --build-started-at 2026-07-16T00:00:00Z --build-finished-at 2026-07-16T00:01:00Z --attested-at 2026-07-16T00:02:00Z --out artifacts/go-verifier-build-attestation.json
python -m trustai go-verifier-build-verify artifacts/go-verifier-build-attestation.json artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root .
python -m trustai go-verifier-build-append artifacts/go-verifier-build-attestation.json artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --state .trustai/go-verifier-build-demo/evidence-chain.json --tenant go-verifier-build-local --out artifacts/go-verifier-build-entry.json

# Binary-attested release evidence after CI or a local Go toolchain emits the binary and sidecars.
$goVerifierBinary = "artifacts/trustai-verify-linux-amd64"
$goVerifierBuildLog = "artifacts/trustai-verify-linux-amd64.build.log"
$goVerifierSbom = "artifacts/trustai-verify-linux-amd64.sbom.json"
$goVerifierProvenance = "artifacts/trustai-verify-linux-amd64.provenance.json"
$goVerifierSignature = "artifacts/trustai-verify-linux-amd64.sig"
python -m trustai go-verifier-binary-signature artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --binary $goVerifierBinary --build-log-ref $goVerifierBuildLog --sbom-ref $goVerifierSbom --provenance-ref $goVerifierProvenance --generated-at 2026-07-16T00:01:30Z --out $goVerifierSignature
$goVerifierBuildLogHash = "sha256:$((Get-FileHash $goVerifierBuildLog -Algorithm SHA256).Hash.ToLower())"
$goVerifierSbomHash = "sha256:$((Get-FileHash $goVerifierSbom -Algorithm SHA256).Hash.ToLower())"
$goVerifierProvenanceHash = "sha256:$((Get-FileHash $goVerifierProvenance -Algorithm SHA256).Hash.ToLower())"
$goVerifierSignatureHash = "sha256:$((Get-FileHash $goVerifierSignature -Algorithm SHA256).Hash.ToLower())"
python -m trustai go-verifier-build-attestation artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --binary $goVerifierBinary --mode binary-attested --builder-ref builder:github-actions/go-verifier --toolchain-ref go:github-actions/setup-go --toolchain-version 1.23.0 --goos linux --goarch amd64 --build-command 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/trustai-verify-linux-amd64 ./verifier/go/trustai-verify' --build-log-ref $goVerifierBuildLog --build-log-hash $goVerifierBuildLogHash --sbom-ref $goVerifierSbom --sbom-hash $goVerifierSbomHash --provenance-ref $goVerifierProvenance --provenance-hash $goVerifierProvenanceHash --signature-ref $goVerifierSignature --signature-hash $goVerifierSignatureHash --build-started-at 2026-07-16T00:00:00Z --build-finished-at 2026-07-16T00:01:00Z --attested-at 2026-07-16T00:02:00Z --out artifacts/go-verifier-build-attestation.json
python -m trustai go-verifier-build-verify artifacts/go-verifier-build-attestation.json artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --binary $goVerifierBinary
python -m trustai go-verifier-build-append artifacts/go-verifier-build-attestation.json artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --binary $goVerifierBinary --state .trustai/go-verifier-build-demo/evidence-chain.json --tenant go-verifier-build-local --out artifacts/go-verifier-build-entry.json
```
