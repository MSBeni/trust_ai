# Collector Service Attestation v0.1

The collector service attestation binds a verified collector topology to
production-service hardening evidence: collector image digests, mTLS and
authorization, tenant isolation, replay and idempotency controls, network
policies, Kafka/Redpanda buffering, ClickHouse trace analytics, Postgres
control-plane storage, MCP proxy deployment, release-pinned framework hooks,
audit logs, and redacted operational credentials.

This v0.1 artifact does not prove a continuously operated hosted service by
itself. It records the evidence a production deployment must preserve and lets
offline verifiers detect mismatched topology, BYOC operator, storage, network,
or service-hardening claims.

## Schema

`schema`: `trustai.collector-service-attestation/0.1`

Required top-level fields:

- `attestation_id`: canonical hash of the attestation body.
- `signatures`: detached `trustai.signature/0.1` signatures over
  `{attestation_id, collector_service}`.
- `mode`: one of `local-reference`, `byoc-service-attested`, or
  `production-design`.
- `environment` and `attested_at`.
- `source`: collector topology id/hash plus optional BYOC operator attestation
  id/hash.
- `topology`: topology id/hash, mode, environment, endpoint count, component
  summary, store summary, and control summary.
- `byoc_operator`: optional BYOC operator attestation binding.
- `service`: collector service ref, version, image, image digest, binary hash,
  replica range, and availability zones.
- `security`: mTLS, authn/z, tenant isolation, rate limit, replay cache,
  idempotency store, ingress, network policy, and egress policy refs.
- `streaming`: Kafka/Redpanda backend, stream/topic, retention, TLS, and
  dead-letter queue refs.
- `storage`: ClickHouse trace-store retention/backup and Postgres schema/backup
  refs.
- `mcp_proxy`: proxy ref, proxy image digest, and release-pinned framework hook
  refs.
- `operation`: actor reference, redacted credential reference, and supporting
  evidence refs.
- `audit_log`: audit-log reference, root hash, and retention timestamp.
- `source_artifacts`, `controls`, and `limitations`.

## Verification

`trustai collector-service-verify` checks:

- schema, canonical `attestation_id`, and detached signature.
- supplied collector topology signature, source hashes, endpoints, components,
  stores, and controls.
- supplied BYOC operator attestation when present, including deployment/WORM
  replay if those source artifacts are supplied.
- source records and `source_artifacts` match the supplied topology and BYOC
  operator attestation.
- collector image digest and binary hash are `sha256` references.
- replica floor is at least two, replica ceiling is not below the floor, and at
  least two availability zones are present.
- mTLS, authn/z, tenant isolation, replay, idempotency, rate limit, ingress,
  egress, and network policy refs exist.
- stream backend is supported, stream TLS is true, and retention is at least 24
  hours.
- ClickHouse retention is at least 30 days and ClickHouse/Postgres backup refs
  exist.
- Postgres schema hash, MCP proxy image digest, and audit-log root are `sha256`
  references.
- framework hook refs are non-empty.
- operation credentials are redacted references and secret-like fields do not
  contain raw material.

`trustai collector-service-append` first verifies the attestation and source
artifacts, then appends `collector.service_attested` to the evidence chain. The
chain entry records source bindings, topology, BYOC operator reference, service,
security, streaming, storage, MCP proxy, audit, operation, and control summary.

## Example Commands

```powershell
python -m trustai collector-service-attestation artifacts/collector-topology.json --byoc-operator artifacts/byoc-operator-attestation.json --deployment-manifest artifacts/deployment-manifest.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --environment aitrade-prod --service-ref collector:trustai/otel-prod --service-version 0.1.0 --collector-image ghcr.io/trustai/collector:0.1.0 --collector-image-digest sha256:trustai-collector-image --collector-binary-hash sha256:trustai-collector-binary --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --mtls-policy-ref policy:collector/mtls-required-v0.1 --auth-policy-ref policy:collector/oidc-tenant-authz-v0.1 --tenant-isolation-ref tenant-isolation:aitrade/collector --rate-limit-policy-ref rate-limit:collector/aitrade --replay-cache-ref redis:collector/replay-cache --idempotency-store-ref postgres:collector/idempotency --ingress-ref ingress:collector/private --network-policy-ref netpol:collector/deny-by-default --egress-policy-ref egress:collector/kms-tsa-only --stream-backend redpanda --stream-ref redpanda:trustai/collector-events --stream-topic trustai.otel.events --stream-retention-hours 168 --stream-dlq-ref redpanda:trustai/collector-events-dlq --clickhouse-ref clickhouse:trustai/traces --clickhouse-retention-days 2555 --clickhouse-backup-ref backup:clickhouse/trustai/daily --postgres-ref postgres:trustai/control-plane --postgres-schema-hash sha256:trustai-control-plane-schema --postgres-backup-ref backup:postgres/trustai/daily --mcp-proxy-ref mcp-proxy:trustai/prod --mcp-proxy-image-digest sha256:trustai-mcp-proxy-image --framework-hook-ref hook:langgraph/0.3 --framework-hook-ref hook:openai-agents/0.2 --framework-hook-ref hook:claude-agent-sdk/0.1 --audit-log-ref audit-log:collector/service --audit-log-root sha256:collector-service-audit-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/collector-operator --credential-ref env:COLLECTOR_SERVICE_TOKEN --evidence-ref evidence:collector/service --attested-at 2026-07-04T04:00:00Z --out artifacts/collector-service-attestation.json
python -m trustai collector-service-verify artifacts/collector-service-attestation.json artifacts/collector-topology.json --byoc-operator artifacts/byoc-operator-attestation.json --deployment-manifest artifacts/deployment-manifest.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm
python -m trustai collector-service-append artifacts/collector-service-attestation.json artifacts/collector-topology.json --byoc-operator artifacts/byoc-operator-attestation.json --deployment-manifest artifacts/deployment-manifest.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --state .trustai/collector-service-demo/evidence-chain.json --tenant collector-service-local --out artifacts/collector-service-entry.json
python -m trustai chain-verify --state .trustai/collector-service-demo/evidence-chain.json --tenant collector-service-local
```

## Production Notes

A live deployment should replace local references with provider-native exports:

- collector deployment, autoscaling, readiness, admission, SBOM, provenance, and
  rollout evidence;
- mTLS certificate issuance, OIDC/JWT verifier config, tenant authorization,
  replay cache, rate limit, and idempotency store evidence;
- Kafka/Redpanda ACLs, TLS, retention, dead-letter queues, and consumer lag
  controls;
- ClickHouse and Postgres backup/restore drills, retention, migrations, and
  audit logs;
- MCP proxy request signing, policy context injection, and chain append
  guarantees;
- release-pinned native framework hooks for the exact runtime versions deployed.
