# Framework Runtime Service Authority Recorded Export Provider Export v0.1

A framework runtime service authority recorded-export provider receipt binds a
verified recorded-export worker operation to provider-native exports for the
scheduler, queue, request, storage, and audit systems that observed that worker
run. It is the provider-owned evidence layer above
`framework-runtime-service-authority-recorded-export-worker`.

## Artifact

A receipt uses schema
`trustai.framework-runtime-service-authority-recorded-export-provider-export/0.1`
and contains:

- provider, environment, export timestamp, endpoint URL, request/response
  hashes, actor ref, redacted credential ref, and detached signatures;
- recorded-export worker binding with worker operation ID/hash, recorded-export
  ID/hash, attestation/dossier refs, run refs, queue refs, storage refs, archive
  refs, artifact roots, metrics refs, and worker audit-log roots;
- provider export metadata and roots for scheduler, queue, request, storage, and
  audit record sets;
- matched provider records for the scheduler lease/checkpoint/cursor, queue
  message, recorded-export request, retained recorded-export object, artifact
  archive, artifact manifest, storage write record, and audit log;
- controls and limitations for production-claim guardrails.

## Verification

`framework-runtime-service-authority-recorded-export-provider-verify`
recalculates the provider receipt ID, verifies at least one detached signature,
validates provider endpoint exchange metadata, checks redacted credentials, and
rejects raw secret-like fields. It also requires every
`recorded_export_worker_binding` and `provider_export` key emitted by the v0.1
builder. Worker identity, recorded-export, attestation, dossier, scheduler,
queue, storage, artifact, request/response, audit, provider export roots, and
record counts must be complete; provider record counts must be positive.
Optional cursor and dead-letter values may be null only when the original source
receipt emitted the key with a null value.

When supplied with the provider export, recorded-export worker receipt,
recorded-export receipt, nested source artifacts, and retained artifact paths,
verification first replays
`framework-runtime-service-authority-recorded-export-worker-verify`. It then
recalculates provider record roots, checks the provider export hash, and rejects
missing or mismatched scheduler, queue, request, storage, or audit records.
Omitted source artifacts during standalone verification may produce replay
warnings, but they must not permit partial recorded-export worker or provider
export summaries.

`production-export` mode only indicates the provider exchange was successful and
the receipt is paired with provider-owned export evidence. It still does not
prove a continuously operated production fleet without live immutable provider
audit exports and production scheduler/storage authority.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-service-authority-recorded-export-provider artifacts/framework-runtime-service-authority-recorded-export-provider-export.json artifacts/framework-runtime-service-authority-recorded-export-worker.json artifacts/framework-runtime-service-authority-recorded-export.json --authority-attestation artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode provider-export --environment aitrade-prod --provider redpanda-s3-postgres-recorded-export --endpoint-url https://storage.example/aitrade/framework-runtime/service-authority-recorded-export-provider-export --credential-ref env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_TOKEN --request-hash sha256:framework-runtime-service-authority-recorded-export-provider-request --response-status 200 --response-hash sha256:framework-runtime-service-authority-recorded-export-provider-response --actor-ref oidc:trustai.example/framework-runtime-service-authority-recorded-export-provider-worker --exported-at 2026-07-09T01:15:00Z --require-fresh --out artifacts/framework-runtime-service-authority-recorded-export-provider.json
python -m trustai framework-runtime-service-authority-recorded-export-provider-verify artifacts/framework-runtime-service-authority-recorded-export-provider.json --recorded-export-provider-export artifacts/framework-runtime-service-authority-recorded-export-provider-export.json --recorded-export-worker artifacts/framework-runtime-service-authority-recorded-export-worker.json --recorded-export artifacts/framework-runtime-service-authority-recorded-export.json --authority-attestation artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root .
python -m trustai framework-runtime-service-authority-recorded-export-provider-append artifacts/framework-runtime-service-authority-recorded-export-provider.json artifacts/framework-runtime-service-authority-recorded-export-provider-export.json artifacts/framework-runtime-service-authority-recorded-export-worker.json artifacts/framework-runtime-service-authority-recorded-export.json --authority-attestation artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-runtime-service-authority-recorded-export-provider-demo/evidence-chain.json --tenant framework-runtime-service-authority-recorded-export-provider-local --out artifacts/framework-runtime-service-authority-recorded-export-provider-entry.json
```
