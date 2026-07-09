# TrustAI Go Verifier Source

This directory contains the dependency-free Go source for the roadmap's static
offline verifier. It mirrors the local Python verifier checks for proof packs:

- canonical JSON hashing with sorted object keys;
- local HMAC proof-pack, chain-entry, and timestamp-token signature checks;
- Merkle inclusion proof checks;
- contract, eval, and promotion-gate chain ordering;
- contract hash and eval results hash binding;
- recomputed gate decision checks, including temporal holdout and approvals.

Run source tests when a Go toolchain is available:

```powershell
Push-Location verifier/go/trustai-verify
go test .
go run . --help
Pop-Location
```

Build command when a Go toolchain is available:

```powershell
Push-Location verifier/go/trustai-verify
go build -trimpath -ldflags "-s -w" -o ../../../artifacts/trustai-verify-go.exe .
Pop-Location
```

Reference verification command:

```powershell
artifacts/trustai-verify-go.exe artifacts/aitrade-proof-pack.json
```

CI release automation lives in `.github/workflows/go-verifier.yml`. It runs the
source tests, builds static verifier artifacts for Linux, macOS, and Windows,
and uploads SHA-256 checksums, SBOM JSON, provenance JSON, and GitHub build
provenance attestations for non-pull-request runs.

The current workspace does not include `go` on PATH, so this local environment
can track and test verifier source structure but cannot produce the binary
artifact. Production release automation should build this command in a
controlled Go toolchain and include the binary hash in the signed verifier
release manifest or a binary-attested Go verifier build attestation.
