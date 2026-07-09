# Go Verifier Build Attestation v0.1

This specification defines signed attestations for the Go offline verifier build
path. It binds the verifier release manifest, conformance report, standards
package, Go source files, static-build controls, optional build logs, optional
binary hashes, and optional supply-chain provenance into a portable artifact.

The attestation intentionally separates three modes:

- `source-plan`: the Go verifier source, release binding, and required static
  build controls are attested, but no compiled binary is claimed.
- `recorded-build`: a build was run and a build log reference/hash is included,
  but a final binary hash may still be absent.
- `binary-attested`: a compiled verifier binary is included by path, hash, and
  size, with build log and provenance references.

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
- `controls`: verifier build controls and current pass/fail/not-applicable
  status.
- `signatures`: detached signature over the build body and `build_id`.

## Source Binding

`source` must include:

- `verifier_release_id` and `verifier_release_hash`.
- `verifier_release_version`.
- `verifier_release_source_hash` and `verifier_release_source_files_hash`.
- `go_source_count` and `go_source_hash`.
- `go_sources`, with each Go verifier source path and content hash.
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
- `command`: the build command used or planned.
- `started_at`, `finished_at`, `build_log_ref`, and `build_log_hash` when a
  recorded or binary build is claimed.

`source-plan` attestations may omit build log and binary hashes, but verifiers
must emit warnings that no binary has been produced.

## Binary and Provenance

`binary-attested` mode requires:

- `binary.status` equal to `available`.
- `binary.path`.
- `binary.sha256`.
- `binary.size_bytes`.
- `build.build_log_ref` and `build.build_log_hash`.
- at least one provenance hash from SBOM, provenance, or signature metadata.

The verifier must reject a `binary-attested` attestation without those fields.
`recorded-build` mode requires build-log metadata but may omit the binary hash
while the release process is still staging the artifact.

## Verification

An implementation verifies:

1. Schema and canonical `build_id`.
2. Detached signature over the build body.
3. Source binding against the supplied verifier release manifest, conformance
   report, standards package, and repository source files.
4. Static-build controls: `cgo_enabled=false` and `trimpath=true`.
5. Mode-specific build-log, binary, and provenance requirements.
6. Chain append payloads include the full attestation and verification summary.

## CLI

Reference commands:

```powershell
python -m trustai go-verifier-build-attestation artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --mode source-plan --builder-ref builder:trustai/go-verifier/local --toolchain-ref go:download-required --toolchain-version not-installed-local-reference --goos linux --goarch amd64 --build-started-at 2026-07-16T00:00:00Z --build-finished-at 2026-07-16T00:01:00Z --attested-at 2026-07-16T00:02:00Z --out artifacts/go-verifier-build-attestation.json
python -m trustai go-verifier-build-verify artifacts/go-verifier-build-attestation.json artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root .
python -m trustai go-verifier-build-append artifacts/go-verifier-build-attestation.json artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --state .trustai/go-verifier-build-demo/evidence-chain.json --tenant go-verifier-build-local --out artifacts/go-verifier-build-entry.json
```
