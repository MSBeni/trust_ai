# Framework Runtime Storage v0.1

A framework runtime storage receipt binds a verified framework runtime worker to
provider-native stream and storage exports. It is the storage authority
companion to `framework-runtime-worker`: the worker receipt records the run and
the hashes it claims to write; the storage receipt replays provider export
records for the stream message, WORM object, ClickHouse batch, Postgres index,
control index, scheduler lease, checkpoint, and export audit root.

## Artifact

A receipt uses schema `trustai.framework-runtime-storage/0.1` and contains:

- mode, environment, export timestamp, provider, endpoint evidence, actor, and
  redacted credential ref;
- worker binding with worker operation ID/hash, runtime audit ID/hash, framework,
  trace, runtime instance, stream message, storage, database, scheduler, cursor,
  worker audit, and runtime audit-log refs;
- provider export hash, stream record root, storage record root, scheduler record
  root, export window/cursor refs, and export audit-log root;
- matched stream record hash for the worker stream message and runtime event;
- matched storage record hashes for WORM object, ClickHouse batch, Postgres
  index, and control-index writes;
- matched scheduler record hash for lease/checkpoint/cursor continuity;
- controls, limitations, and detached signatures.

## Verification

`framework-runtime-storage-verify` recalculates the receipt ID, verifies at
least one signature, verifies endpoint and credential redaction, and checks the
internal worker/export bindings.

When supplied with the storage export, worker receipt, runtime audit receipt,
audit export, hook operation, source trace, hook release, and adapter matrix,
verification first replays `framework-runtime-worker-verify`. It then
recalculates the provider export hash and record roots, finds the matching
stream, storage, and scheduler records, and rejects mismatches in stream message
hash, offsets, storage object hash, ClickHouse/Postgres/control-index hashes,
row counts, leases, checkpoints, cursors, or audit roots.

`framework-runtime-storage-append` requires all source artifacts. The chain entry
records only hash-bound summaries while offline reviewers can replay disclosed
provider export records.

The hosted-service control layer that consumes this receipt is documented in
`framework-runtime-service-attestation-v0.1.md`.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-storage examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode provider-export --environment aitrade-prod --provider redpanda-clickhouse-postgres --endpoint-url https://storage.example/aitrade/framework-runtime/export --credential-ref env:FRAMEWORK_RUNTIME_STORAGE_TOKEN --request-hash sha256:framework-runtime-storage-request --response-status 200 --response-hash sha256:framework-runtime-storage-response --actor-ref oidc:trustai.example/framework-runtime-storage-worker --exported-at 2026-07-09T00:43:00Z --out artifacts/framework-runtime-storage.json
python -m trustai framework-runtime-storage-verify artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root .
python -m trustai framework-runtime-storage-append artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-runtime-storage-demo/evidence-chain.json --tenant framework-runtime-storage-local --out artifacts/framework-runtime-storage-entry.json
```
