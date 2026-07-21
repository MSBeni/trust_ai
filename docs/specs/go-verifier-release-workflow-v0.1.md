# Go Verifier Release Workflow v0.1

## Purpose

This specification defines the public CI/release workflow required for the
TrustAI dependency-free Go verifier. It complements the source-level verifier
release manifest and build attestation formats by describing the repository
automation that can produce static verifier binaries in an environment with a
Go toolchain.

The local reference workspace may not have Go installed. In that case, local
artifacts may only claim source-plan or source-distribution status. Binary
availability is claimed only by workflow runs, recorded builds, or
binary-attested receipts that include binary hashes.

## Required Workflow

The repository MUST include `.github/workflows/go-verifier.yml`.

The workflow MUST:

- run on pull requests and pushes to `main`;
- run on verifier release tags matching `verifier-v*`;
- support manual `workflow_dispatch`;
- use `actions/checkout`;
- use `actions/setup-go`;
- run `go test ./...` in `verifier/go/trustai-verify`;
- build with `CGO_ENABLED=0`;
- build with `go build -trimpath -ldflags "-s -w"`;
- produce Linux amd64, Linux arm64, Darwin amd64, Darwin arm64, and Windows
  amd64 artifacts;
- smoke-test the verifier command on the workflow host with `--help`;
- verify each cross-compiled binary artifact is non-empty;
- generate SHA-256 checksum files;
- generate verifier SBOM JSON that binds source file hashes;
- generate verifier provenance JSON that records builder, repository, ref,
  commit, target OS/architecture, `cgo_enabled=false`, `trimpath=true`, and
  linker flags;
- upload the binary, checksum, SBOM, provenance, and build-log artifacts;
- for the canonical Linux amd64 build, generate a TrustAI binary signature artifact,
  binary-attested Go verifier build receipt, and `trustai.go-verifier-release-run/0.1`
  receipt from GitHub Actions environment metadata;
- upload the release-run evidence bundle as `trustai-verify-release-run-evidence`;
- request build provenance attestation for non-pull-request runs.

## Release Evidence

A released verifier binary is considered eligible for binary-attested release
metadata only when the binary hash in the release manifest or build attestation
matches the workflow artifact checksum.

The signed verifier release manifest and `trustai.go-verifier-release-run/0.1` receipt SHOULD bind:

- workflow file path and content hash;
- workflow run URL or run identifier;
- target artifact names;
- checksum artifact hashes;
- SBOM artifact hashes;
- provenance artifact hashes;
- optional GitHub build provenance attestation references;
- a CI-produced `trustai-verify-release-run-evidence` artifact containing the proof pack,
  conformance report, standards package, verifier release manifest, binary-attested build
  receipt, release-run receipt, build log, and binary signature.

## Verification Rules

Verifier release workflow conformance checks MUST fail if:

- the workflow file is absent;
- the workflow does not run tests;
- the workflow does not enforce `CGO_ENABLED=0`;
- the workflow does not use `-trimpath`;
- any required target platform is missing;
- checksum, SBOM, provenance, or artifact upload steps are missing.

Local verification MAY inspect the workflow file textually. Hosted verification
SHOULD also inspect the GitHub Actions run metadata and artifact digests.

## Limitations

This workflow specification proves that the repository contains a repeatable
build path. It does not prove that a specific binary has been built unless a
workflow run, artifact digest, release/build attestation, and signed `trustai.go-verifier-release-run/0.1` receipt are also supplied.

