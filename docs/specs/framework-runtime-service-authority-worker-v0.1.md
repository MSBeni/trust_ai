# Framework Runtime Service Authority Worker v0.1

A framework runtime service authority worker receipt records a scheduled worker
operation that refreshes or reconciles a framework runtime service authority
dossier. It is the operational companion to
`framework-runtime-service-authority`: the dossier states which production
authority evidence exists, and the worker receipt proves the refresh run, stored
outputs, queue/scheduler metadata, and observability/audit roots for that run.

## Artifact

A receipt uses schema `trustai.framework-runtime-service-authority-worker/0.1`
and contains:

- mode, environment, record timestamp, worker/run refs, operation kind, actor,
  attempt metadata, and success/error state;
- authority dossier binding with dossier ID/hash, authority ref, provider
  receipt ID/hash, service worker operation ID, authority evidence counts, and
  missing-requirement counts;
- scheduler metadata for cadence, lease, checkpoint, cursor, and next-run refs;
- execution metadata for queue message, authority request, dossier/report
  storage refs and hashes, authority-evidence root, missing-requirement root,
  request/response hashes, and response status;
- metrics, audit-log, retention, redacted credential, source artifact hashes,
  controls, limitations, and detached signatures.

## Verification

`framework-runtime-service-authority-worker-verify` recalculates the worker
operation ID, verifies at least one detached signature, checks worker/scheduler
timestamps and attempts, validates `sha256:` hash refs, verifies redacted
credentials, and rejects raw secret-like fields. It requires every authority
binding key emitted by the v0.1 builder, requires a positive authority evidence
count with non-negative requirement/freshness counts, and requires the
`source_artifacts` array to contain exactly the expected nested receipt/export
hash kinds with no missing, duplicate, or unsupported entries.

When supplied with the authority dossier and provider/source artifacts,
verification replays `framework-runtime-service-authority-verify`, which then
replays the provider receipt, service worker, service attestation, storage
receipt/export, runtime audit, hook operation, hook release, and adapter matrix.
It also compares every supplied source artifact hash to the receipt's
`source_artifacts` list and verifies the stored dossier hash, authority evidence
root, and missing requirement root. Omitted sources during standalone
verification may produce replay warnings, but they must not permit partial
authority bindings or partial source artifact hash summaries.

`--require-complete` and `--require-fresh` can be used to force the underlying
authority dossier to have complete production authority coverage and fresh
authority evidence windows. Without live provider scheduler/queue/storage/audit
exports, this receipt remains local/reference worker evidence rather than proof
of continuously operated production infrastructure.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-service-authority-worker artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode scheduled-worker --environment aitrade-prod --worker-ref worker:framework-runtime-service-authority/refresher --run-ref worker-run:framework-runtime-service-authority/lg-trace-001 --operation-kind authority_evidence_refresh --actor-ref oidc:trustai.example/framework-runtime-authority-worker --schedule-ref schedule:framework-runtime-service-authority/5m --cadence-seconds 300 --lease-ref lease:framework-runtime-service-authority/lg-trace-001 --checkpoint-ref checkpoint:framework-runtime-service-authority --checkpoint-hash sha256:framework-runtime-service-authority-worker-checkpoint --queue-ref queue:framework-runtime-service-authority --queue-message-ref queue-message:framework-runtime-service-authority/lg-trace-001 --queue-message-hash sha256:framework-runtime-service-authority-worker-queue-message --authority-request-ref authority-request:framework-runtime-service/lg-trace-001 --dossier-storage-ref worm:framework-runtime-service-authority/lg-trace-001 --dossier-storage-hash sha256:REPLACE_WITH_DOSSIER_HASH --request-hash sha256:framework-runtime-service-authority-worker-request --response-status 200 --response-hash sha256:framework-runtime-service-authority-worker-response --metrics-ref metrics:framework-runtime-service-authority/workers --audit-log-ref audit-log:framework-runtime-service-authority/workers --audit-log-root sha256:framework-runtime-service-authority-worker-audit-root --retention-until 2033-07-09T01:05:00Z --credential-ref env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_TOKEN --require-fresh --started-at 2026-07-09T01:04:00Z --completed-at 2026-07-09T01:05:00Z --out artifacts/framework-runtime-service-authority-worker.json
python -m trustai framework-runtime-service-authority-worker-verify artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --require-fresh --now 2026-07-09T01:05:00Z
python -m trustai framework-runtime-service-authority-worker-append artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-runtime-service-authority-worker-demo/evidence-chain.json --tenant framework-runtime-service-authority-worker-local --out artifacts/framework-runtime-service-authority-worker-entry.json
```
