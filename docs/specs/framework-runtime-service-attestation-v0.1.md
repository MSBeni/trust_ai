# Framework Runtime Service Attestation v0.1

A framework runtime service attestation binds a verified framework runtime
stream/storage export receipt to the hosted service controls needed to operate
that runtime continuously. It is the service-hardening companion to
`framework-runtime-storage`: the storage receipt proves that worker output can be
replayed against provider stream and database exports, while the service
attestation records the service image, scheduler, queue, leases, storage
backends, tenant controls, observability roots, and operator custody references
that would run that worker fleet.

## Artifact

An attestation uses schema `trustai.framework-runtime-service-attestation/0.1`
and contains:

- mode, environment, attestation timestamp, and source storage receipt summary;
- service identity, version, container image, image digest, binary hash,
  replica floor, replica ceiling, and availability zones;
- scheduler binding with runtime worker ref, cadence, queue, dead-letter queue,
  lease store, checkpoint store, cursor store, idempotency store, retry policy,
  concurrency, and source schedule/lease/checkpoint refs;
- stream and storage backends for Redpanda/Kafka-style streams, WORM object
  storage, ClickHouse, Postgres, backups, schema hashes, and source export hash;
- security controls for mTLS, authn/z, tenant isolation, admission, rate limits,
  network, egress, secret store, and KMS key refs;
- observability controls for metrics, alerting, audit log root, access log root,
  and retention;
- operation actor with redacted credential ref, evidence refs, controls,
  limitations, source artifact hashes, and detached signatures.

## Verification

`framework-runtime-service-verify` recalculates the attestation ID, verifies at
least one detached signature, rejects raw secret-like fields, validates hash
references, and checks that retention extends beyond `attested_at`.

When supplied with the storage receipt, storage export, runtime worker receipt,
runtime audit receipt, audit export, hook operation, source trace, hook release,
and adapter matrix, verification first replays
`framework-runtime-storage-verify`. It then checks that the attestation source
summary and source artifact hashes match the disclosed artifacts, and that the
service scheduler/stream refs match the worker binding recorded by the storage
receipt.

Offline verification is fail-closed. A service attestation must carry the
complete source summary and the exact nine source artifact records, and the
verifier must reject signed summaries when any replay artifact is missing,
duplicated, unsupported, or hash-mismatched. A valid detached signature over a
partial source summary is not enough to prove hosted runtime service evidence.

`framework-runtime-service-append` requires all source artifacts. The chain entry
records hash-bound summaries for the attestation, source storage receipt,
service, scheduler, storage backends, security controls, observability controls,
operator actor, and control status summary.

Individual hosted worker runs that consume this service attestation are
specified in `framework-runtime-service-worker-v0.1.md`.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-service `
  --storage-receipt artifacts/framework-runtime-storage.json `
  --storage-export examples/aitrade/framework-runtime-storage-export.json `
  --worker artifacts/framework-runtime-worker.json `
  --runtime-audit artifacts/framework-runtime-audit.json `
  --audit-export examples/aitrade/framework-runtime-audit.json `
  --operation artifacts/framework-hook-operation.json `
  --trace examples/aitrade/framework-traces.json `
  --release artifacts/framework-hook-release.json `
  --matrix artifacts/framework-adapter-matrix.json `
  --root . `
  --mode hosted-runtime-service `
  --environment aitrade-prod `
  --service-ref service:framework-runtime/aitrade `
  --service-version 0.1.0 `
  --service-image ghcr.io/trustai/framework-runtime:0.1.0 `
  --service-image-digest sha256:framework-runtime-service-image `
  --service-binary-hash sha256:framework-runtime-service-binary `
  --replicas-min 3 `
  --replicas-max 9 `
  --availability-zone us-east-1a `
  --availability-zone us-east-1b `
  --runtime-worker-ref worker:framework-runtime/langgraph `
  --scheduler-ref schedule:framework-runtime/langgraph/continuous `
  --schedule-cadence-seconds 30 `
  --queue-ref queue:framework-runtime/work `
  --dead-letter-queue-ref queue:framework-runtime/dlq `
  --lease-store-ref postgres:framework-runtime/leases `
  --lease-store-hash sha256:framework-runtime-service-lease-store `
  --checkpoint-store-ref postgres:framework-runtime/checkpoints `
  --checkpoint-store-hash sha256:framework-runtime-service-checkpoint-store `
  --cursor-store-ref postgres:framework-runtime/cursors `
  --idempotency-store-ref postgres:framework-runtime/idempotency `
  --retry-policy-ref policy:framework-runtime/retry-v0.1 `
  --max-concurrency 64 `
  --stream-backend redpanda `
  --stream-ref redpanda:trustai/framework-runtime `
  --stream-topic trustai.framework.runtime.audit `
  --stream-dlq-ref redpanda:trustai/framework-runtime-dlq `
  --worm-store-ref s3-object-lock:trustai-framework-runtime/aitrade `
  --object-lock-policy-ref policy:framework-runtime/object-lock-7y `
  --clickhouse-ref clickhouse:trustai/framework_runtime `
  --clickhouse-schema-hash sha256:framework-runtime-service-clickhouse-schema `
  --clickhouse-backup-ref backup:clickhouse/framework-runtime/daily `
  --postgres-ref postgres:trustai/framework_runtime `
  --postgres-schema-hash sha256:framework-runtime-service-postgres-schema `
  --postgres-backup-ref backup:postgres/framework-runtime/daily `
  --mtls-policy-ref policy:framework-runtime/mtls-v0.1 `
  --auth-policy-ref policy:framework-runtime/authz-v0.1 `
  --tenant-isolation-ref tenant-isolation:framework-runtime/aitrade `
  --admission-policy-ref policy:framework-runtime/admission-v0.1 `
  --rate-limit-policy-ref rate-limit:framework-runtime/tenant `
  --network-policy-ref netpol:framework-runtime/deny-by-default `
  --egress-policy-ref egress:framework-runtime/storage-only `
  --secret-store-ref vault:framework-runtime/secrets `
  --kms-key-ref kms:framework-runtime/customer-data `
  --metrics-ref metrics:framework-runtime/service `
  --alert-policy-ref alert:framework-runtime/service `
  --audit-log-ref audit-log:framework-runtime/service `
  --audit-log-root sha256:framework-runtime-service-audit-root `
  --access-log-ref access-log:framework-runtime/service `
  --access-log-root sha256:framework-runtime-service-access-root `
  --retention-until 2033-07-09T00:00:00Z `
  --actor-ref oidc:trustai.example/framework-runtime-operator `
  --credential-ref env:FRAMEWORK_RUNTIME_SERVICE_TOKEN `
  --evidence-ref evidence:framework-runtime/service `
  --attested-at 2026-07-09T00:44:00Z `
  --out artifacts/framework-runtime-service.json
python -m trustai framework-runtime-service-verify artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root .
python -m trustai framework-runtime-service-append artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-runtime-service-demo/evidence-chain.json --tenant framework-runtime-service-local --out artifacts/framework-runtime-service-entry.json
```