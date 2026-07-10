# Framework Runtime Service Authority Recorded Export Provider Bundle v0.1

A recorded-export provider bundle is a self-contained offline review artifact for
one signed framework runtime service authority recorded-export provider receipt.
It packages the provider receipt, provider export, recorded-export worker,
recorded-export receipt, all nested source receipts/exports, and the raw JSON
source artifact bytes needed to detect source swaps without the original local
file paths.

## Artifact

A bundle uses schema
`trustai.framework-runtime-service-authority-recorded-export-provider-bundle/0.1`
and contains:

- bundle mode, environment, generation timestamp, reviewer ref, bundle ref, and
  detached signatures;
- source summary with provider receipt ID/hash, provider export hash/ref,
  recorded-export worker operation ID/hash, recorded-export ID/hash, run ref,
  and provider storage/audit roots;
- embedded parsed source objects for the provider receipt path through the
  runtime worker, audit, hook operation, trace payload, hook release, and
  adapter matrix;
- embedded raw JSON source artifacts with byte hash, size, media type, canonical
  content hash, expected content hash, and base64 content;
- verification summary, controls, and limitations for offline review.

## Verification

`framework-runtime-service-authority-recorded-export-provider-bundle-verify`
recalculates the bundle ID, verifies at least one detached signature, checks the
bundle timestamp and mode, replays the embedded provider receipt and nested
sources, and rejects raw secret-like fields.

Because recorded-export receipts bind original artifact paths, the bundle
verifier does not require those original paths to exist. Instead, it verifies
the embedded artifact bytes against the recorded-export `recorded_artifacts`
metadata and the embedded parsed source objects. Tampering with either the
parsed source objects or embedded artifact bytes invalidates the bundle.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-service-authority-recorded-export-provider-bundle artifacts/framework-runtime-service-authority-recorded-export-provider.json artifacts/framework-runtime-service-authority-recorded-export-provider-export.json artifacts/framework-runtime-service-authority-recorded-export-worker.json artifacts/framework-runtime-service-authority-recorded-export.json --authority-attestation artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode offline-review --environment aitrade-prod --reviewer-ref oidc:auditor.example/framework-runtime-reviewer --generated-at 2026-07-09T01:16:00Z --out artifacts/framework-runtime-service-authority-recorded-export-provider-bundle.json
python -m trustai framework-runtime-service-authority-recorded-export-provider-bundle-verify artifacts/framework-runtime-service-authority-recorded-export-provider-bundle.json
python -m trustai framework-runtime-service-authority-recorded-export-provider-bundle-append artifacts/framework-runtime-service-authority-recorded-export-provider-bundle.json --state .trustai/framework-runtime-service-authority-recorded-export-provider-bundle-demo/evidence-chain.json --tenant framework-runtime-service-authority-recorded-export-provider-bundle-local --out artifacts/framework-runtime-service-authority-recorded-export-provider-bundle-entry.json
```
