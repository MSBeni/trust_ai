# Framework Runtime Service Authority Recorded Export Worker v0.1

A framework runtime service authority recorded-export worker receipt records one
scheduled worker run that captured, replayed, and stored a
`framework-runtime-service-authority-recorded-export` receipt and its retained
artifact archive. It sits above the recorded-export receipt: the recorded export
binds raw files to verified source objects, while the worker receipt binds that
recording to queue, lease, checkpoint, storage-write, metrics, and audit
evidence for an operational run.

## Artifact

A receipt uses schema
`trustai.framework-runtime-service-authority-recorded-export-worker/0.1` and
contains:

- mode, environment, worker/run refs, operation kind, actor, attempt state,
  start/completion timestamps, and optional error ref;
- scheduler evidence: cadence, lease, checkpoint hash, cursor refs, and next
  run timestamp;
- execution evidence: queue message hash, recorded-export storage object/hash,
  artifact archive ref/hash, artifact manifest ref/hash, storage write ref/hash,
  request/response hashes, artifact roots, and recorded artifact summary hashes;
- observability evidence: metrics ref, audit-log ref/root, retention-until
  timestamp, redacted credential ref, source artifact hashes, controls,
  limitations, and detached signatures.

## Verification

`framework-runtime-service-authority-recorded-export-worker-verify`
recalculates the worker operation ID, verifies at least one detached signature,
validates timestamps, scheduler fields, queue/storage hashes, redacted
credentials, and secret-like fields, and checks that production claims are
conservative. It requires every recorded-export binding key emitted by the v0.1
builder, requires a positive recorded artifact count, and requires the
`source_artifacts` array to contain exactly the expected nested receipt/export
hash kinds with no missing, duplicate, or unsupported entries.

When supplied with the recorded export and its nested source artifacts,
verification first replays
`framework-runtime-service-authority-recorded-export-verify`. It then checks the
worker's recorded-export binding, stored recorded-export hash, artifact manifest
hash, artifact roots, and source artifact hashes against the supplied objects.
Omitted source artifacts during standalone verification may produce replay
warnings, but they must not permit partial recorded-export bindings or partial
source artifact hash summaries.

`production-worker` mode requires a `production-recorded-export` source.
`local-worker`, `scheduled-worker`, and `hosted-worker` remain local/reference
evidence for the worker operation; they do not prove a continuously operated
production fleet by themselves.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-service-authority-recorded-export-worker artifacts/framework-runtime-service-authority-recorded-export.json --authority-attestation artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode hosted-worker --environment aitrade-prod --worker-ref worker:framework-runtime-service-authority-recorded-export --run-ref worker-run:framework-runtime-service-authority-recorded-export/lg-trace-001 --operation-kind recorded_export_capture --actor-ref oidc:trustai.example/framework-runtime-authority-recorded-export-worker --schedule-ref schedule:framework-runtime-service-authority-recorded-export/5m --cadence-seconds 300 --lease-ref lease:framework-runtime-service-authority-recorded-export/lg-trace-001 --checkpoint-ref checkpoint:framework-runtime-service-authority-recorded-export --checkpoint-hash sha256:framework-runtime-service-authority-recorded-export-worker-checkpoint --queue-ref queue:framework-runtime-service-authority-recorded-export --queue-message-ref queue-message:framework-runtime-service-authority-recorded-export/lg-trace-001 --queue-message-hash sha256:framework-runtime-service-authority-recorded-export-worker-queue-message --recorded-export-ref recorded-export:framework-runtime-service-authority/lg-trace-001 --recorded-export-storage-ref worm:framework-runtime-service-authority-recorded-export/lg-trace-001 --recorded-export-storage-hash <content-hash> --artifact-archive-ref worm:framework-runtime-service-authority-recorded-export/archive-lg-trace-001 --artifact-archive-hash sha256:framework-runtime-service-authority-recorded-export-archive --artifact-manifest-ref worm:framework-runtime-service-authority-recorded-export/manifest-lg-trace-001 --artifact-manifest-hash <manifest-hash> --storage-write-ref storage-write:framework-runtime-service-authority-recorded-export/lg-trace-001 --storage-write-hash sha256:framework-runtime-service-authority-recorded-export-storage-write --metrics-ref metrics:framework-runtime-service-authority-recorded-export/workers --audit-log-ref audit-log:framework-runtime-service-authority-recorded-export/workers --audit-log-root sha256:framework-runtime-service-authority-recorded-export-worker-audit-root --retention-until 2033-07-09T01:20:00Z --credential-ref env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_TOKEN --started-at 2026-07-09T01:13:00Z --completed-at 2026-07-09T01:14:00Z --require-fresh --out artifacts/framework-runtime-service-authority-recorded-export-worker.json
python -m trustai framework-runtime-service-authority-recorded-export-worker-verify artifacts/framework-runtime-service-authority-recorded-export-worker.json --recorded-export artifacts/framework-runtime-service-authority-recorded-export.json --authority-attestation artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --require-fresh --now 2026-07-09T01:14:00Z
python -m trustai framework-runtime-service-authority-recorded-export-worker-append artifacts/framework-runtime-service-authority-recorded-export-worker.json artifacts/framework-runtime-service-authority-recorded-export.json --authority-attestation artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --require-fresh --now 2026-07-09T01:14:00Z --state .trustai/framework-runtime-service-authority-recorded-export-worker-demo/evidence-chain.json --tenant framework-runtime-service-authority-recorded-export-worker-local --out artifacts/framework-runtime-service-authority-recorded-export-worker-entry.json
```
