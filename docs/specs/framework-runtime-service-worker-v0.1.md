# Framework Runtime Service Worker v0.1

A framework runtime service worker receipt records one scheduled operation run
inside the hosted framework runtime service. It is the operational companion to
`framework-runtime-service`: the service attestation records the fleet design and
control-plane refs, while the worker receipt binds a concrete run to queue,
lease, checkpoint, cursor, stream, WORM, ClickHouse, Postgres, control-index,
request/response, metrics, audit, retention, and credential-redaction evidence.

## Artifact

A receipt uses schema `trustai.framework-runtime-service-worker/0.1` and
contains:

- mode, environment, recorded timestamp, service attestation summary, and source
  summary;
- source artifact hashes for the service attestation, storage receipt, storage
  export, runtime worker receipt, runtime audit receipt, audit export, hook
  operation, source trace, hook release, and adapter matrix;
- worker identity, run ref, operation kind, actor, runtime worker ref,
  timestamps, retry attempt, success flag, and optional error ref;
- scheduler evidence for schedule, cadence, lease, checkpoint, checkpoint hash,
  cursor refs, and next run;
- execution evidence for queue message, stream message, WORM object,
  ClickHouse batch, Postgres index, control index, request/response hashes, and
  optional dead-letter queue;
- observability and custody evidence for metrics, audit-log root, retention,
  evidence refs, and a redacted worker credential reference;
- controls, limitations, and detached signatures.

## Verification

`framework-runtime-service-worker-verify` recalculates the worker operation ID,
verifies at least one detached signature, checks required scheduler/execution
hashes, validates timestamps and retention, and rejects raw secret-like fields.

When supplied with the service attestation, storage receipt, storage export,
runtime worker receipt, runtime audit receipt, audit export, hook operation,
source trace, hook release, and adapter matrix, verification first replays
`framework-runtime-service-verify`. It then checks that the source artifact
hashes and the storage receipt hash match the disclosed artifacts.

`framework-runtime-service-worker-append` requires all source artifacts. The
chain entry records hash-bound summaries for the worker operation, service,
source, scheduler, execution, observability, credential reference, and control
status summary.

Provider-owned infrastructure exports for these worker runs are specified in
`framework-runtime-service-provider-v0.1.md`.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-service-worker --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode hosted-worker --environment aitrade-prod --worker-ref worker:framework-runtime/service-reconciler --run-ref worker-run:framework-runtime/service/2026-07-09T00:44:10Z --operation-kind storage_export_reconcile --actor-ref oidc:trustai.example/framework-runtime-service-worker --schedule-ref schedule:framework-runtime/langgraph/continuous --cadence-seconds 30 --lease-ref lease:framework-runtime/service/2026-07-09T00:44:10Z --checkpoint-ref checkpoint:framework-runtime/service/aitrade --checkpoint-hash sha256:framework-runtime-service-worker-checkpoint --previous-cursor-ref cursor:framework-runtime/service/before-lg-trace-001 --next-cursor-ref cursor:framework-runtime/service/after-lg-trace-001 --queue-ref queue:framework-runtime/work --queue-message-ref queue-message:framework-runtime/service/lg-trace-001 --queue-message-hash sha256:framework-runtime-service-worker-queue-message --dead-letter-queue-ref queue:framework-runtime/dlq --runtime-worker-ref worker:framework-runtime/langgraph --stream-message-ref stream-message:framework-runtime/lg-trace-001 --stream-message-hash sha256:framework-runtime-worker-stream-message --storage-object-ref worm:framework-runtime/aitrade/lg-trace-001.json --storage-object-hash sha256:framework-runtime-worker-storage-object --clickhouse-batch-ref clickhouse:trustai/framework_runtime/batch/lg-trace-001 --clickhouse-batch-hash sha256:framework-runtime-worker-clickhouse-batch --postgres-index-ref postgres:trustai/framework_runtime/lg-trace-001 --postgres-index-hash sha256:framework-runtime-worker-postgres-index --control-index-ref control-index:framework-runtime/lg-trace-001 --control-index-hash sha256:framework-runtime-worker-control-index --request-hash sha256:framework-runtime-service-worker-request --response-status 202 --response-hash sha256:framework-runtime-service-worker-response --metrics-ref metrics:framework-runtime/service-workers --audit-log-ref audit-log:framework-runtime/service-workers --audit-log-root sha256:framework-runtime-service-worker-audit-root --retention-until 2033-07-09T00:00:00Z --credential-ref env:FRAMEWORK_RUNTIME_SERVICE_WORKER_TOKEN --evidence-ref evidence:framework-runtime/service-worker --started-at 2026-07-09T00:44:10Z --completed-at 2026-07-09T00:44:12Z --next-run-at 2026-07-09T00:44:40Z --out artifacts/framework-runtime-service-worker.json
python -m trustai framework-runtime-service-worker-verify artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root .
python -m trustai framework-runtime-service-worker-append artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-runtime-service-worker-demo/evidence-chain.json --tenant framework-runtime-service-worker-local --out artifacts/framework-runtime-service-worker-entry.json
```