# Framework Runtime Worker v0.1

A framework runtime worker receipt records one worker run that processes a
verified framework runtime audit export into TrustAI stream and storage
evidence. It is the operational companion to `framework-runtime-audit`: the
runtime audit receipt proves that a provider/runtime export contains a matching
hook capture; the worker receipt proves a scheduled worker reconciled that
export through leases, checkpoints, stream messages, storage writes, metrics,
and audit roots.

## Artifact

A receipt uses schema `trustai.framework-runtime-worker/0.1` and contains:

- mode, environment, worker ref, run ref, operation kind, actor, attempt,
  success, start/completion timestamps, and redacted credential ref;
- source binding to a verified framework runtime audit receipt, including
  runtime audit ID/hash, operation ID/hash, framework, trace ID, runtime
  instance/process refs, collector hook ref, audit export hash/event root,
  audit log root, cursor refs, and matched event hash;
- scheduler cadence, lease, checkpoint, previous/next cursor, and next-run refs;
- runtime provider/framework/operation/trace/hook metadata copied from the
  source binding;
- stream refs, topic/partition/offsets, stream message hash, DLQ ref, runtime
  export/event refs, and runtime audit-log root;
- storage object hash, ClickHouse batch hash and row count, Postgres index hash
  and row count, control-index hash, metrics ref, worker audit root, retention,
  controls, limitations, and detached signatures.

## Verification

`framework-runtime-worker-verify` recalculates the worker operation ID, verifies
at least one signature, checks scheduler/worker/storage/audit invariants, and
validates that runtime, stream, and source fields agree internally.

When supplied with the runtime audit receipt, audit export, hook operation,
trace, hook release, and adapter matrix, verification first replays
`framework-runtime-audit-verify`; then it recalculates the source binding and
rejects any mismatch. This catches tampering in either the worker receipt or the
source runtime audit/export evidence.

`framework-runtime-worker-append` requires all source artifacts. Chain append
therefore records only hashes and summary metadata, while offline reviewers can
replay the raw trace and runtime audit export when disclosed.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-worker --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode runtime-worker --environment aitrade-prod --worker-ref worker:framework-runtime/langgraph --run-ref worker-run:framework-runtime/langgraph/lg-trace-001/2026-07-09T00:42:05Z --operation-kind audit_export_reconcile --actor-ref oidc:trustai.example/framework-runtime-worker --schedule-ref schedule:framework-runtime/langgraph/continuous --cadence-seconds 30 --lease-ref lease:framework-runtime/langgraph/2026-07-09T00:42:05Z --checkpoint-ref checkpoint:framework-runtime/langgraph/aitrade --checkpoint-hash sha256:framework-runtime-worker-checkpoint --previous-cursor-ref cursor:framework-runtime-audit/before-lg-trace-001 --next-cursor-ref cursor:framework-runtime-worker/after-lg-trace-001 --next-run-at 2026-07-09T00:42:35Z --stream-ref redpanda:trustai/framework-runtime --stream-topic trustai.framework.runtime.audit --partition-ref redpanda:trustai/framework-runtime/0 --offset-start 4200 --offset-end 4201 --stream-message-ref stream-message:framework-runtime/lg-trace-001 --stream-message-hash sha256:framework-runtime-worker-stream-message --storage-object-ref worm:framework-runtime/aitrade/lg-trace-001.json --storage-object-hash sha256:framework-runtime-worker-storage-object --clickhouse-batch-ref clickhouse:trustai/framework_runtime/batch/lg-trace-001 --clickhouse-batch-hash sha256:framework-runtime-worker-clickhouse-batch --clickhouse-rows-written 2 --postgres-index-ref postgres:trustai/framework_runtime/lg-trace-001 --postgres-index-hash sha256:framework-runtime-worker-postgres-index --postgres-rows-written 1 --control-index-ref control-index:framework-runtime/lg-trace-001 --control-index-hash sha256:framework-runtime-worker-control-index --metrics-ref metrics:framework-runtime/workers --audit-log-ref audit-log:framework-runtime/workers --audit-log-root sha256:framework-runtime-worker-audit-root --retention-until 2033-07-09T00:00:00Z --credential-ref env:FRAMEWORK_RUNTIME_WORKER_TOKEN --started-at 2026-07-09T00:42:03Z --completed-at 2026-07-09T00:42:05Z --out artifacts/framework-runtime-worker.json
python -m trustai framework-runtime-worker-verify artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root .
python -m trustai framework-runtime-worker-append artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-runtime-worker-demo/evidence-chain.json --tenant framework-runtime-worker-local --out artifacts/framework-runtime-worker-entry.json
```
