# TrustAI Go Verifier Source

This directory contains the dependency-free Go source for the roadmap's static
offline verifier. It mirrors the local Python verifier checks for proof packs and self-contained roadmap evidence bundles:

- canonical JSON hashing with sorted object keys;
- local HMAC proof-pack, chain-entry, and timestamp-token signature checks;
- Merkle inclusion proof checks;
- contract, eval, and promotion-gate chain ordering;
- contract hash, proof-pack wrapper, and eval results hash binding;
- recomputed gate decision checks, including temporal holdout and approvals;
- proof-pack subject agent/environment binding;
- deterministic compliance framework mapping checks;
- roadmap evidence bundle `bundle_id`, bundled chain tree, report summary, and source artifact hash checks;
- strict `--require-source-artifacts` checks for embedded roadmap audits, external manifests, collection runs, source maps, source snapshots, and intake receipts.

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

After a binary, build log, SBOM, provenance, and signature sidecars exist, write
binary-attested release evidence from the repository root:

```powershell
$goVerifierBinary = "artifacts/trustai-verify-go.exe"
$goVerifierBuildLog = "artifacts/trustai-verify-go.exe.build.log"
$goVerifierSbom = "artifacts/trustai-verify-go.exe.sbom.json"
$goVerifierProvenance = "artifacts/trustai-verify-go.exe.provenance.json"
$goVerifierSignature = "artifacts/trustai-verify-go.exe.sig"
$goVerifierBuildLogHash = "sha256:$((Get-FileHash $goVerifierBuildLog -Algorithm SHA256).Hash.ToLower())"
$goVerifierSbomHash = "sha256:$((Get-FileHash $goVerifierSbom -Algorithm SHA256).Hash.ToLower())"
$goVerifierProvenanceHash = "sha256:$((Get-FileHash $goVerifierProvenance -Algorithm SHA256).Hash.ToLower())"
$goVerifierSignatureHash = "sha256:$((Get-FileHash $goVerifierSignature -Algorithm SHA256).Hash.ToLower())"
python -m trustai go-verifier-build-attestation artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --binary $goVerifierBinary --mode binary-attested --builder-ref builder:local/go-verifier --toolchain-ref go:local --toolchain-version 1.23.0 --goos windows --goarch amd64 --build-command 'go build -trimpath -ldflags "-s -w" -o artifacts/trustai-verify-go.exe ./verifier/go/trustai-verify' --build-log-ref $goVerifierBuildLog --build-log-hash $goVerifierBuildLogHash --sbom-ref $goVerifierSbom --sbom-hash $goVerifierSbomHash --provenance-ref $goVerifierProvenance --provenance-hash $goVerifierProvenanceHash --signature-ref $goVerifierSignature --signature-hash $goVerifierSignatureHash --out artifacts/go-verifier-build-attestation.json
```

Reference verification command:

```powershell
artifacts/trustai-verify-go.exe artifacts/aitrade-proof-pack.json
artifacts/trustai-verify-go.exe --require-source-artifacts artifacts/retained-collection-run-roadmap-evidence-bundle.json
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
