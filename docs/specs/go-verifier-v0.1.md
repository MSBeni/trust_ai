# TrustAI Go Offline Verifier Source v0.1

This specification defines the dependency-free Go verifier source target for
TrustAI proof packs.

## Source Target

- Source path: `verifier/go/trustai-verify/main.go`
- Module path: `trustai.dev/verifier/trustai-verify`
- Runtime dependencies: Go standard library only
- Intended artifact: static offline verifier binary built from the source tree

The Go verifier source mirrors the Python reference verifier's offline
accountless verification checks so proof packs can be inspected by third
parties without network access or a TrustAI tenant.

## Required Verification Checks

An implementation conforming to this source target verifies:

1. Proof pack schema, `pack_id`, and detached pack signature.
2. Canonical JSON hashing compatible with the TrustAI Python reference.
3. HMAC signature envelopes for proof packs, chain entries, and timestamp
   tokens.
4. RFC3161-shaped local timestamp token signatures and payload binding.
5. Merkle leaf and node hashing plus inclusion proofs for every packed chain
   entry.
6. Chain entry `entry_id`, payload hash, and signature validity.
7. Verification contract hash binding between registration, evaluation, and
   gate decision entries.
8. Contract-before-results-before-gate ordering in the evidence chain.
9. Temporal holdout checks for freeze time, record timestamps, sample count,
   and metric thresholds.
10. Required human approval roles and approval chain entries.
11. Recomputed promotion gate decision and packed gate decision consistency.
12. Proof-pack contract and eval wrapper `chain_entry_id` / `results_hash`
    bindings to the included chain entries.
13. Proof-pack subject binding to the registered contract agent and evaluated
    environment, plus eval/gate agent binding to the same contract agent.
14. Deterministic compliance framework mappings derived from the packed gate
    decision.

## Build and Test

Build from the repository root with:

```powershell
Push-Location verifier/go/trustai-verify
go test .
go build -trimpath -ldflags "-s -w" -o ../../../artifacts/trustai-verify-go.exe .
Pop-Location
```

The local workspace used to generate this specification does not currently
have `go` on `PATH`, so the repository includes source-level tests that assert
the expected verifier checks and skips compile verification until a Go toolchain
is available:

```powershell
python -m unittest tests.test_go_verifier_source
```

## Release Boundary

The signed verifier release manifest must include the Go verifier source files
and may list the compiled Go static binary target as planned until a reproducible
build environment is available. The Go verifier build attestation records whether
the current release evidence is a `source-plan`, `recorded-build`, or
`binary-attested` verifier build. A production verifier release should publish
the compiled binary hash, detached signature, SBOM/provenance metadata, build
attestation, and conformance report generated from the released binary.
