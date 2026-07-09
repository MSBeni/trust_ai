# Collector Worker Receipt v0.1

Collector worker receipts record a single operated ingestion worker run. They sit below the collector service attestation: the service attestation proves the hardened topology and control surface, while the worker receipt proves an individual batch/flush/capture operation was bound to that service.

## Schema

- `schema`: `trustai.collector-worker/0.1`
- `worker_operation_id`: canonical hash of the receipt body.
- `signatures`: detached TrustAI signatures over the worker operation id and body.
- `service`: signed collector service attestation id, hash, service ref, stream, storage, MCP proxy, replay cache, idempotency store, and audit root.
- `source`: source summary over the collector service attestation, collector topology, and optional BYOC/WORM/legal-hold source artifacts.
- `worker`: worker ref, run ref, operation kind, actor, timestamps, attempt metadata, outcome, and optional error ref.
- `scheduler`: schedule, cadence, lease, checkpoint, cursor, and next-run metadata.
- `ingestion`: tenant, trace-batch ref/hash, source endpoint, span counts, idempotency hash, replay-cache result, and OTLP request/response hashes.
- `streaming`: stream ref, topic, partition, offsets, stream message ref/hash, and dead-letter queue.
- `storage`: ClickHouse trace batch, Postgres control-plane index, local control index, optional MCP transcript, and optional framework hook hashes.
- `observability`: metrics, audit-log root, retention, and evidence refs.
- `credential`: redacted worker credential reference.

## Verification

Offline verification checks:

1. The canonical `worker_operation_id` and detached signature.
2. The collector service attestation hash and source artifacts.
3. The supplied collector service attestation by replaying `collector-service-verify`, including topology, BYOC, WORM, and legal-hold sources when supplied.
4. Scheduler cadence, attempt bounds, timestamp ordering, and retention.
5. Trace batch, idempotency, request/response, stream, ClickHouse, Postgres, MCP, framework, and audit hash syntax.
6. Accepted and rejected span counts cannot exceed received spans.
7. Secret-like fields are redacted references, never raw credentials.

## CLI

```powershell
python -m trustai collector-worker --service-attestation artifacts/collector-service-attestation.json artifacts/collector-topology.json --byoc-operator artifacts/byoc-operator-attestation.json --deployment-manifest artifacts/deployment-manifest.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --mode hosted-worker --environment aitrade-prod --worker-ref worker:collector/otel-batch --run-ref worker-run:collector/otel/2026-07-04T04:05:00Z --operation-kind otlp_batch_ingest --actor-ref oidc:trustai.example/collector-worker --schedule-ref schedule:collector/otel/continuous --cadence-seconds 15 --lease-ref lease:collector/otel/2026-07-04T04:05:00Z --checkpoint-ref checkpoint:collector/otel/aitrade --checkpoint-hash sha256:collector-worker-checkpoint --tenant-ref tenant:aitrade --trace-batch-ref trace-batch:aitrade/2026-07-04T04:05:00Z --trace-batch-hash sha256:collector-worker-trace-batch --source-endpoint-ref otlp:http-v0-ingest --received-span-count 2 --accepted-span-count 2 --rejected-span-count 0 --idempotency-key-hash sha256:collector-worker-idempotency-key --stream-ref redpanda:trustai/collector-events --stream-topic trustai.otel.events --stream-message-ref stream-message:collector/aitrade/2026-07-04T04:05:00Z --stream-message-hash sha256:collector-worker-stream-message --clickhouse-batch-ref clickhouse:trustai/traces/batch/2026-07-04T04:05:00Z --clickhouse-batch-hash sha256:collector-worker-clickhouse-batch --clickhouse-rows-written 2 --postgres-index-ref postgres:trustai/control-plane/index/2026-07-04T04:05:00Z --postgres-index-hash sha256:collector-worker-postgres-index --postgres-rows-written 2 --control-index-ref control-index:collector/aitrade/2026-07-04T04:05:00Z --control-index-hash sha256:collector-worker-control-index --metrics-ref metrics:collector/workers --audit-log-ref audit-log:collector/workers --audit-log-root sha256:collector-worker-audit-root --retention-until 2033-07-04T00:00:00Z --credential-ref env:COLLECTOR_WORKER_TOKEN --started-at 2026-07-04T04:05:00Z --completed-at 2026-07-04T04:05:02Z --out artifacts/collector-worker.json
python -m trustai collector-worker-verify artifacts/collector-worker.json --service-attestation artifacts/collector-service-attestation.json artifacts/collector-topology.json --byoc-operator artifacts/byoc-operator-attestation.json --deployment-manifest artifacts/deployment-manifest.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm
python -m trustai collector-worker-append artifacts/collector-worker.json --service-attestation artifacts/collector-service-attestation.json artifacts/collector-topology.json --byoc-operator artifacts/byoc-operator-attestation.json --deployment-manifest artifacts/deployment-manifest.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --state .trustai/collector-worker-demo/evidence-chain.json --tenant collector-worker-local --out artifacts/collector-worker-entry.json
```

## Production Notes

This receipt is acceptable as local/reference evidence when it binds hashes and redacted credential refs. A production claim still needs scheduler and lease exports, provider stream offsets, ClickHouse/Postgres write confirmations, immutable audit roots, and continuously operated worker infrastructure.
