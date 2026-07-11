# Framework Runtime Service Authority Provider Export v0.1

A framework runtime service authority provider export receipt binds a verified
authority worker operation to provider-native records for the infrastructure
that exported it. It is the provider-owned evidence companion to
`framework-runtime-service-authority-worker`: the worker receipt records the
scheduled authority refresh, while this receipt replays scheduler, queue,
request, storage, and audit export records for that same run.

## Artifact

A receipt uses schema
`trustai.framework-runtime-service-authority-provider-export/0.1` and contains:

- mode, environment, export timestamp, provider, endpoint evidence, actor, and a
  redacted credential ref;
- authority worker binding with worker operation ID/hash, dossier ID/hash,
  provider receipt ID, service worker operation ID, run ref, queue message,
  scheduler lease/checkpoint/cursor refs, authority request ref, stored
  dossier/report refs and hashes, request/response hashes, metrics ref, and
  worker audit root;
- provider export hash, cursor/window refs, audit-log root, and record roots for
  scheduler, queue, request, storage, and audit record sets;
- matched scheduler, queue, request, storage, and audit record summaries;
- controls, limitations, and detached signatures.

## Verification

`framework-runtime-service-authority-provider-verify` recalculates the provider
receipt ID, verifies at least one detached signature, validates
endpoint/request/response hashes, checks credential redaction, and rejects raw
secret-like fields. It also requires every `authority_worker_binding` and
`provider_export` key emitted by the v0.1 builder. Worker identity, dossier,
scheduler, queue, authority request, storage, request/response, audit, provider
export roots, and record counts must be complete; provider record counts must be
positive. Optional cursor, dead-letter, and report-storage values may be null
only when the original source receipt emitted the key with a null value.

When supplied with the authority provider export, authority worker receipt,
authority dossier, service provider receipt/export, service worker receipt,
service attestation, storage receipt/export, runtime worker receipt, runtime
audit receipt, audit export, hook operation, source trace, hook release, and
adapter matrix, verification first replays
`framework-runtime-service-authority-worker-verify`. It then recalculates the
provider export hash and record roots, finds the matching
scheduler/queue/request/storage/audit records, and rejects mismatches in queue
message hashes, lease/checkpoint/cursor evidence, authority request and response
hashes, stored dossier/report object hashes, metrics refs, or audit roots.

`framework-runtime-service-authority-provider-append` requires all source
artifacts. Offline verification is also fail-closed: the authority provider
export, authority worker receipt, authority dossier, service provider
receipt/export, service worker receipt, and every nested service-worker source
artifact are required so reviewers can replay provider records and the full
worker chain. A detached signature over partial replay inputs is not enough to
verify the receipt.

`local-export` and `provider-export` modes produce verifiable local/reference
evidence. `production-export` still requires a successful provider exchange and
live provider-owned export artifacts before the receipt should be treated as
production authority evidence.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-service-authority-provider artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode provider-export --environment aitrade-prod --provider redpanda-s3-postgres-authority --endpoint-url https://storage.example/aitrade/framework-runtime/service-authority-provider-export --credential-ref env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_PROVIDER_TOKEN --request-hash sha256:framework-runtime-service-authority-provider-request --response-status 200 --response-hash sha256:framework-runtime-service-authority-provider-response --actor-ref oidc:trustai.example/framework-runtime-service-authority-provider-worker --exported-at 2026-07-09T01:06:00Z --require-fresh --out artifacts/framework-runtime-service-authority-provider.json
python -m trustai framework-runtime-service-authority-provider-verify artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root .
python -m trustai framework-runtime-service-authority-provider-append artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-runtime-service-authority-provider-demo/evidence-chain.json --tenant framework-runtime-service-authority-provider-local --out artifacts/framework-runtime-service-authority-provider-entry.json
```
