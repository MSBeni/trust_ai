# Verifier Public Release Authority Dossier v0.1

Status: Draft reference format

Schema: `trustai.verifier-public-release-authority-dossier/0.1`

Evidence entry type: `verifier.public_release_authority_recorded`

## Purpose

Verifier public release authority dossiers bind a signed verifier public release receipt to external release-authority evidence. The dossier is intended for a third-party reviewer who needs to confirm that a public verifier release is connected to provider workflow, release API, artifact manifest, SBOM/provenance/signature, transparency-log, audit-log, source publication, credential custody, and replay evidence without trusting a hosted TrustAI account.

The dossier does not call provider APIs by itself. It hashes and signs retained provider-owned exports, customer-retained release evidence, hosted-service receipts, and repo-relative retained authority artifacts so they can be replayed offline. A retained artifact hash must match the matching `authority_evidence.evidence_hash`.

## Modes

- `local-dossier`: records local or reference evidence only.
- `provider-dossier`: records supplied provider or hosted-service evidence and reports missing coverage.
- `production-dossier`: requires every production authority requirement to be covered and every authority evidence item to be fresh.

## Required Production Authority Evidence

| Requirement ID | Accepted authority kinds | Required evidence |
|---|---|---|
| `completed-provider-workflow-run` | `ci-run`, `provider-api` | Completed provider workflow run export for the release build. |
| `binary-attested-static-build-artifacts` | `ci-run`, `provider-api`, `customer` | Released static verifier binary, hashes, signatures, and build attestation evidence. |
| `public-release-api-publication` | `provider-api`, `hosted-service` | Provider release API export proving the public release publication. |
| `artifact-manifest-and-download-hashes` | `provider-api`, `cloud-object-lock`, `customer` | Artifact manifest and download hash records for released files. |
| `sbom-provenance-signature-retention` | `provider-api`, `cloud-object-lock`, `customer` | Retained SBOM, provenance, and detached signature evidence. |
| `transparency-log-inclusion` | `provider-api`, `hosted-service` | Transparency-log inclusion or equivalent public log evidence. |
| `immutable-release-audit-logs` | `provider-api`, `cloud-object-lock`, `customer` | Immutable release audit-log exports and roots. |
| `source-distribution-publication` | `provider-api`, `hosted-service`, `customer` | Public source distribution publication evidence. |
| `release-account-and-token-custody` | `kms-hsm`, `provider-api`, `customer` | Release account, token, or signing credential custody evidence. |
| `external-third-party-download-replay` | `provider-api`, `hosted-service`, `customer` | Independent download replay evidence for public artifacts. |

## Dossier Fields

A verifier public release authority dossier contains:

- `schema`: fixed to `trustai.verifier-public-release-authority-dossier/0.1`.
- `dossier_id`: canonical content hash of the unsigned dossier body.
- `mode`: one of the supported modes above.
- `environment`, `dossier_ref`, `authority_ref`, and `producer_ref`.
- `public_release_binding`: hash-bound summary of the verified public release receipt and its source receipts.
- `required_production_authority`: the fixed production authority checklist.
- `authority_evidence`: retained evidence refs, hashes, kinds, issuers, subjects, source URIs, freshness windows, derived `source_context`, and evidence IDs.
- `authority_artifacts`: repo-relative retained evidence artifacts, their sizes, SHA-256 refs, and matching evidence IDs.
- `summary`: coverage counts, freshness counts, missing requirements, and stale or undated evidence refs.
- `artifact_summary`: retained artifact counts, covered requirement IDs, and aggregate artifact hash root.
- `controls`: pass/defer/fail controls for source replay, retained artifact replay, checklist coverage, evidence hash shape, freshness, and production claim gating.
- `limitations`: explicit statement of what is not proven locally.
- `signature`: local reference signature over the canonical dossier body.

## Verification Rules

Verification MUST:

1. Check the dossier schema, canonical `dossier_id`, and signature.
2. Deep-verify the source verifier public release receipt and its nested release, distribution, build, workflow-run, release-run bundle, conformance, standards, source bundle, SBOM, provenance, signature, and optional binary sources.
3. Recompute and compare `public_release_binding` exactly.
4. Require the production authority checklist to match this specification.
5. Require every authority evidence item to declare a known `requirement_id`, accepted `authority_kind`, non-empty `evidence_ref`, `evidence_hash`, description, derived `source_context`, and evidence ID; reject source contexts that do not match `public_release_binding`.
6. Replay every retained `authority_artifacts` path from the supplied root, reject absolute or parent-traversal paths, and require the file SHA-256 to match the matching authority evidence hash.
7. Recompute and compare `artifact_summary` exactly.
8. Recompute controls from the signed dossier body and reject re-signed control tampering.
9. When `--authority-artifact` is supplied during verification or append, require the supplied retained paths to match the dossier's stored artifact metadata.
10. Treat `issued_at` and `expires_at` as freshness metadata when supplied.
11. Reject `--require-complete` when any checklist requirement lacks evidence.
12. Reject `--require-fresh` when any evidence item is stale or missing a freshness window.
13. Reject `production-dossier` unless every requirement is covered and every evidence item is fresh.
14. Reject raw secret material; credentials must be represented by redacted refs such as `env:RELEASE_TOKEN` or KMS/HSM refs.

## CLI Examples

Create a provider dossier with one retained OSS verifier CI authority export:

```powershell
$verifierWorkflowAuthorityHash = "sha256:$((Get-FileHash examples/aitrade/oss-verifier-ci-run-authority-export.json -Algorithm SHA256).Hash.ToLower())"
python -m trustai verifier-release-authority artifacts/verifier-public-release.json artifacts/verifier-release.json artifacts/verifier-distribution.json artifacts/go-verifier-build-attestation.json artifacts/go-verifier-release-run.json artifacts/go-verifier-release-run-bundle.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --distribution-bundle artifacts/verifier-source-bundle.zip --distribution-sbom artifacts/verifier-source-sbom.json --distribution-provenance artifacts/verifier-source-provenance.json --distribution-signature artifacts/verifier-source-signature.json --binary dist/trustai-verify-linux-amd64 --environment release-prod --dossier-ref dossier:verifier-release-authority/v0.1.0 --authority-ref authority:verifier-release/github/v0.1.0 --producer-ref oidc:trustai.example/verifier-release-authority-worker --authority-evidence "completed-provider-workflow-run,ci-run,github-actions-run:1234567890,$verifierWorkflowAuthorityHash,OSS verifier CI authority export;issuer=GitHub Actions;subject=trustai verifier release v0.1.0;source_uri=https://github.com/MSBeni/trust_ai/actions/runs/1234567890;issued_at=2026-07-16T00:10:00Z;expires_at=2026-07-23T00:10:00Z" --authority-artifact "completed-provider-workflow-run,examples/aitrade/oss-verifier-ci-run-authority-export.json" --generated-at 2026-07-16T00:12:00Z --out artifacts/verifier-release-authority.json
```

Verify and append the dossier:

```powershell
python -m trustai verifier-release-authority-verify artifacts/verifier-release-authority.json artifacts/verifier-public-release.json artifacts/verifier-release.json artifacts/verifier-distribution.json artifacts/go-verifier-build-attestation.json artifacts/go-verifier-release-run.json artifacts/go-verifier-release-run-bundle.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --distribution-bundle artifacts/verifier-source-bundle.zip --distribution-sbom artifacts/verifier-source-sbom.json --distribution-provenance artifacts/verifier-source-provenance.json --distribution-signature artifacts/verifier-source-signature.json --binary dist/trustai-verify-linux-amd64 --authority-artifact "completed-provider-workflow-run,examples/aitrade/oss-verifier-ci-run-authority-export.json"
python -m trustai verifier-release-authority-append artifacts/verifier-release-authority.json artifacts/verifier-public-release.json artifacts/verifier-release.json artifacts/verifier-distribution.json artifacts/go-verifier-build-attestation.json artifacts/go-verifier-release-run.json artifacts/go-verifier-release-run-bundle.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --distribution-bundle artifacts/verifier-source-bundle.zip --distribution-sbom artifacts/verifier-source-sbom.json --distribution-provenance artifacts/verifier-source-provenance.json --distribution-signature artifacts/verifier-source-signature.json --binary dist/trustai-verify-linux-amd64 --authority-artifact "completed-provider-workflow-run,examples/aitrade/oss-verifier-ci-run-authority-export.json" --state .trustai/verifier-release-authority-demo/evidence-chain.json --tenant verifier-release-authority-local --out artifacts/verifier-release-authority-entry.json
```

## Limitations

This reference format records and verifies supplied evidence, including retained OSS verifier CI authority export replay when `authority_artifacts` are supplied. A production claim still requires retained fresh provider-owned release API exports, artifact manifests, transparency-log exports, immutable audit exports, and actual released static binary hashes/signatures from a completed provider workflow or equivalent external build authority.
