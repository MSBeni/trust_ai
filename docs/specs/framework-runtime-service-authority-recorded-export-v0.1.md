# Framework Runtime Service Authority Recorded Export v0.1

A framework runtime service authority recorded-export receipt binds a verified
authority attestation to the retained files that were disclosed for offline
review. It is the file-custody layer above
`framework-runtime-service-authority-attestation`: the attestation proves the
authority statement and source chain, while this receipt proves the raw JSON
artifacts kept for replay are byte-identical to the verified source objects.

## Artifact

A receipt uses schema
`trustai.framework-runtime-service-authority-recorded-export/0.1` and contains:

- mode, environment, recording timestamp, recorder ref, redacted credential ref,
  retention backend/ref, and retention-until timestamp;
- source binding for the authority attestation ID/hash, provider receipt/export
  hashes, authority evidence roots, missing requirement roots, dossier ID/hash,
  authority ref, and dossier coverage summary;
- recorded artifact entries for the authority attestation, authority provider
  receipt/export, authority worker, authority dossier, service provider
  receipt/export, service worker, service attestation, storage receipt/export,
  runtime worker, runtime audit, audit export, hook operation, trace payload,
  hook release, and adapter matrix;
- for every retained artifact: normalized path, media type, size, byte SHA-256,
  canonical JSON content hash, expected source content hash, and artifact type;
- artifact roots, controls, limitations, and detached signatures.

## Verification

`framework-runtime-service-authority-recorded-export-verify` recalculates the
recorded export ID, verifies at least one detached signature, validates recorder
and retention metadata, checks redacted credentials, rejects raw secret-like
fields, and recalculates artifact roots.

If authority attestation and artifact files are omitted, verification may warn
that hashes were not replayed, but it still rejects incomplete signed source
bindings with missing attestation metadata, provider receipt/export hashes,
authority evidence roots, missing-requirement roots, dossier hashes, or dossier
coverage-summary fields.

When supplied with the authority attestation and all source artifacts,
verification first replays
`framework-runtime-service-authority-attestation-verify`. It then rereads every
retained file path, recalculates the file byte hash and size, parses the JSON
object, recalculates the canonical content hash, and rejects mismatches against
the receipt or the supplied source object.

`production-recorded-export` mode requires the source authority attestation to be
`production-attestation`. `local-recorded-export` and
`provider-recorded-export` remain local/reference evidence: they prove retained
file custody for offline review, not continuously operated production
infrastructure.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-service-authority-recorded-export artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode provider-recorded-export --environment aitrade-prod --recorder-ref worker:framework-runtime-service-authority-recorded-export --storage-backend s3-object-lock --retention-ref retention:framework-runtime-service-authority-recorded-export/7y --retention-until 2033-07-09T01:12:00Z --credential-ref env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_TOKEN --recorded-at 2026-07-09T01:12:00Z --require-fresh --out artifacts/framework-runtime-service-authority-recorded-export.json
python -m trustai framework-runtime-service-authority-recorded-export-verify artifacts/framework-runtime-service-authority-recorded-export.json --authority-attestation artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --require-fresh --now 2026-07-09T01:12:00Z
python -m trustai framework-runtime-service-authority-recorded-export-append artifacts/framework-runtime-service-authority-recorded-export.json --authority-attestation artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --require-fresh --now 2026-07-09T01:12:00Z --state .trustai/framework-runtime-service-authority-recorded-export-demo/evidence-chain.json --tenant framework-runtime-service-authority-recorded-export-local --out artifacts/framework-runtime-service-authority-recorded-export-entry.json
```
