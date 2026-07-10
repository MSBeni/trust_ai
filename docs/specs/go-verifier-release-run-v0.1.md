# Go Verifier Release Run Receipt v0.1

This specification defines signed receipts for a recorded Go verifier release
workflow run. It connects four things that otherwise remain separate: the
verifier release manifest, the Go verifier build attestation, the repository
workflow file, and the workflow run artifacts/checks/provenance.

The receipt does not replace provider-native GitHub Actions attestations. It is
the TrustAI evidence wrapper that lets an offline verifier replay local hashes
and confirm that a release run was bound to the same signed verifier source and
build metadata.

## Artifact

The JSON artifact uses schema `trustai.go-verifier-release-run/0.1` and appends
to the evidence chain as entry type `verifier.go_release_run_attested`.

Required top-level fields:

- `schema`: the schema identifier.
- `run_id`: canonical content hash of the release-run body.
- `source`: release and build binding summary.
- `workflow`: repository workflow path, SHA-256 hash, size, and format.
- `workflow_run`: provider, run ID, attempt, commit, runner, status, conclusion,
  and run timestamps.
- `artifacts`: uploaded artifact records with name, path/ref, kind, SHA-256, and
  size when locally replayable.
- `checks`: completed workflow checks and their conclusions.
- `provenance`: hosted build provenance or provider attestation reference/hash,
  plus OIDC issuer and subject when provenance is supplied.
- `controls`: release-run controls and their status.
- `signatures`: detached signature over `run_id` and the release-run body.

## Verification Rules

An implementation verifies:

1. Schema, canonical `run_id`, and detached signature.
2. The supplied verifier release manifest still verifies.
3. The supplied Go verifier build attestation still verifies against the release
   manifest, conformance report, standards package, and optional binary.
4. `source.release_id`, `source.release_hash`, `source.build_id`, and
   `source.build_hash` match the supplied sources.
5. The workflow file hash and size replay locally when the workflow path is
   local.
6. The workflow file contains the required static verifier release controls:
   `actions/setup-go@v5`, `CGO_ENABLED: "0"`, `go build -trimpath`, and
   `actions/attest-build-provenance@v2`.
7. The workflow run status is `completed` and conclusion is `success`.
8. At least one check is present, and every check is completed successfully.
9. If the build attestation includes a verifier binary hash, at least one
   release-run artifact must match that binary hash.
10. Local artifact and hosted provenance references replay to their recorded
    hashes when the bytes are available.

## Controls

Reference controls:

- `go-verifier-release-workflow-source`: workflow source file hash and size are
  bound into the receipt.
- `go-verifier-release-build-binding`: run evidence is bound to the signed
  verifier release manifest and Go build attestation.
- `go-verifier-release-artifacts`: published artifacts include the verifier
  binary hash from the build attestation.
- `go-verifier-release-checks`: hosted workflow checks completed successfully.
- `go-verifier-release-hosted-provenance`: hosted build provenance or provider
  attestation hash is recorded.

## CLI

Reference commands:

```powershell
$goVerifierBinary = "artifacts/trustai-verify-linux-amd64"
$goVerifierSbom = "artifacts/trustai-verify-linux-amd64.sbom.json"
$goVerifierProvenance = "artifacts/trustai-verify-linux-amd64.provenance.json"
$goVerifierSignature = "artifacts/trustai-verify-linux-amd64.sig"
$goVerifierProvenanceHash = "sha256:$((Get-FileHash $goVerifierProvenance -Algorithm SHA256).Hash.ToLower())"
python -m trustai go-verifier-release-run artifacts/verifier-release.json artifacts/go-verifier-build-attestation.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --binary $goVerifierBinary --workflow-run-id 1234567890 --workflow-run-url https://github.com/MSBeni/trust_ai/actions/runs/1234567890 --commit-sha 0000000000000000000000000000000000000000 --started-at 2026-07-16T00:00:00Z --completed-at 2026-07-16T00:04:00Z --artifact "trustai-verify-linux-amd64,$goVerifierBinary,binary" --artifact "trustai-verify-linux-amd64.sbom.json,$goVerifierSbom,sbom" --artifact "trustai-verify-linux-amd64.provenance.json,$goVerifierProvenance,provenance" --artifact "trustai-verify-linux-amd64.sig,$goVerifierSignature,signature" --check "go test ./...,completed,success" --check "build linux/amd64,completed,success" --hosted-provenance-ref $goVerifierProvenance --hosted-provenance-hash $goVerifierProvenanceHash --oidc-issuer https://token.actions.githubusercontent.com --oidc-subject repo:MSBeni/trust_ai:ref:refs/heads/main --generated-at 2026-07-16T00:05:00Z --out artifacts/go-verifier-release-run.json
python -m trustai go-verifier-release-run-verify artifacts/go-verifier-release-run.json artifacts/verifier-release.json artifacts/go-verifier-build-attestation.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --binary $goVerifierBinary
python -m trustai go-verifier-release-run-append artifacts/go-verifier-release-run.json artifacts/verifier-release.json artifacts/go-verifier-build-attestation.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --binary $goVerifierBinary --state .trustai/go-verifier-release-run-demo/evidence-chain.json --tenant go-verifier-release-run-local --out artifacts/go-verifier-release-run-entry.json
```

## Limitations

This receipt can replay local workflow, artifact, and provenance bytes when they
are supplied. It does not by itself prove GitHub Actions, or another hosted
provider, actually operated the run. Production release authority still requires
provider-native run metadata, artifact exports, signed provenance, and immutable
provider audit logs.
