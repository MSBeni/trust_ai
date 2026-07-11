# Framework Runtime Service Provider Export v0.1

A framework runtime service provider export receipt binds a verified framework
runtime service worker operation to provider-native records for the infrastructure
that operated it. It is the provider-owned evidence companion to
`framework-runtime-service-worker`: the worker receipt records the scheduled run,
while this receipt replays scheduler, queue, KMS, stream, WORM, ClickHouse,
Postgres, control-index, and audit export records for that same run.

## Artifact

A receipt uses schema `trustai.framework-runtime-service-provider-export/0.1`
and contains:

- mode, environment, export timestamp, provider, endpoint evidence, actor, and a
  redacted credential ref;
- service worker binding with worker operation ID/hash, service attestation ID,
  storage receipt ID/hash, run ref, queue message, scheduler lease/checkpoint,
  KMS key, stream message, storage/database/control-index refs, request/response
  hashes, metrics ref, and worker audit root;
- provider export hash, cursor/window refs, audit-log root, and record roots for
  scheduler, queue, KMS, stream, storage, and audit record sets;
- matched scheduler, queue, KMS, stream, storage, and audit record summaries;
- controls, limitations, and detached signatures.

## Verification

`framework-runtime-service-provider-verify` recalculates the provider receipt ID,
verifies at least one detached signature, validates endpoint/request/response
hashes, checks credential redaction, and rejects raw secret-like fields. It also
requires every `service_worker_binding` and `provider_export` key emitted by the
v0.1 builder. The provider-owned worker, scheduler, queue, KMS, stream, storage,
audit, cursor, request/response, and record-root fields must be non-empty, and
provider record counts must be positive. Optional binding values may be null only
when the original source receipt emitted the key with a null value.

When supplied with the provider export, service worker receipt, service
attestation, storage receipt, storage export, runtime worker receipt, runtime
audit receipt, audit export, hook operation, source trace, hook release, and
adapter matrix, verification first replays `framework-runtime-service-worker-verify`.
It then recalculates provider export and record roots, finds the matching
scheduler/queue/KMS/stream/storage/audit records, and rejects mismatches in queue
message hashes, lease/checkpoint/cursor evidence, KMS response hashes, stream
message hashes, WORM object hashes, ClickHouse/Postgres/control-index hashes, or
audit roots.

`framework-runtime-service-provider-append` requires all source artifacts. Offline
verification is also fail-closed: the provider export, service worker receipt,
and every nested service-worker source artifact are required so reviewers can
replay provider records and the worker operation. A detached signature over
partial replay inputs is not enough to verify the receipt.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-service-provider artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode provider-export --environment aitrade-prod --provider redpanda-clickhouse-postgres-kms --endpoint-url https://storage.example/aitrade/framework-runtime/service-provider-export --credential-ref env:FRAMEWORK_RUNTIME_SERVICE_PROVIDER_TOKEN --request-hash sha256:framework-runtime-service-provider-request --response-status 200 --response-hash sha256:framework-runtime-service-provider-response --actor-ref oidc:trustai.example/framework-runtime-service-provider-worker --exported-at 2026-07-09T00:45:00Z --out artifacts/framework-runtime-service-provider.json
python -m trustai framework-runtime-service-provider-verify artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root .
python -m trustai framework-runtime-service-provider-append artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-runtime-service-provider-demo/evidence-chain.json --tenant framework-runtime-service-provider-local --out artifacts/framework-runtime-service-provider-entry.json
```