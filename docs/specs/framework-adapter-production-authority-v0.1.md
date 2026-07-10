# Framework Adapter Production Authority Dossier v0.1

Framework adapter production authority dossiers bind a signed framework adapter
matrix and a signed framework hook release receipt to the external evidence
needed before TrustAI can claim production-certified native framework hooks.

## Schema

`trustai.framework-adapter-production-authority-dossier/0.1`

The dossier contains:

- `source_binding`: hashes and identifiers for the adapter matrix, hook release,
  supported frameworks, runtime package versions, and optional framework runtime
  service authority dossier.
- `required_production_authority`: the fixed v0.1 checklist for production
  framework adapter claims.
- `authority_evidence`: hash-bound external evidence references with optional
  `issued_at` and `expires_at` freshness windows.
- `controls`: deterministic verification controls for source binding,
  row-parity, authority evidence coverage, freshness, production-mode gating,
  and secret exclusion.

## Required Authority Categories

Production authority requires external evidence for:

- Exact framework runtime release matrix coverage.
- Native hook package provenance and release signatures.
- Maintained adapter release cadence and compatibility refresh schedule.
- Fixture regression replay for adapter event hash chains.
- Production runtime provider certification or managed runtime exports.
- Collector schema compatibility.
- Immutable release artifact retention.
- Supply-chain vulnerability and SBOM attestation.
- Deprecation, upgrade, and framework release-tracking SLA.
- Framework runtime service production authority binding.
- Tenant rollout, canary, rollback, and compatibility-break controls.

## Verification Rules

A verifier must:

1. Recompute `dossier_id` from the canonical body.
2. Verify at least one dossier signature.
3. Replay the adapter matrix when supplied.
4. Replay the hook release against the supplied adapter matrix when supplied.
5. Replay the optional framework runtime service authority dossier when supplied.
6. Recompute `source_binding`, `summary`, and `controls`.
7. Validate every authority evidence item against the fixed checklist and
   accepted authority kinds.
8. Enforce freshness when `require_fresh` is set.
9. Reject `production-dossier` mode unless all requirements are covered with
   fresh evidence and matrix, hook release, and runtime service authority
   bindings are present.

## CLI

```powershell
python -m trustai framework-adapter-authority artifacts/framework-adapter-matrix.json artifacts/framework-hook-release.json --runtime-service-authority artifacts/framework-runtime-service-authority.json --environment aitrade-prod --dossier-ref dossier:framework-adapter-authority/aitrade-prod --authority-ref authority:framework-adapter/aitrade-prod --producer-ref oidc:trustai.example/framework-adapter-authority-worker --authority-evidence "exact-runtime-release-matrix,ci-run,ci:framework-adapter-matrix/nightly/aitrade-prod,sha256:framework-adapter-matrix-ci-run,Nightly adapter matrix replay export;issuer=TrustAI CI;subject=aitrade-prod framework adapter matrix;source_uri=https://ci.example/trustai/framework-adapter-matrix/aitrade-prod;issued_at=2026-07-09T00:45:00Z;expires_at=2026-12-31T00:00:00Z" --generated-at 2026-07-09T01:05:00Z --out artifacts/framework-adapter-authority.json
python -m trustai framework-adapter-authority-verify artifacts/framework-adapter-authority.json --matrix artifacts/framework-adapter-matrix.json --release artifacts/framework-hook-release.json --runtime-service-authority artifacts/framework-runtime-service-authority.json
python -m trustai framework-adapter-authority-append artifacts/framework-adapter-authority.json artifacts/framework-adapter-matrix.json artifacts/framework-hook-release.json --runtime-service-authority artifacts/framework-runtime-service-authority.json
```

## Production Claim Limit

`local-dossier` and `provider-dossier` modes are reference or provider evidence
dossiers only. They can prove that local artifacts and supplied authority
references are hash-bound, but they do not claim production-native framework
hook operation. `production-dossier` mode is valid only when the full checklist
has fresh external evidence and the runtime service authority dossier is bound.
