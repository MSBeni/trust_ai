# Provider Callback Store v0.1

TrustAI provider callback stores persist callback operations from GitHub, GitLab,
Slack, provider audit exports, and provider audit stream receipts into a local SQLite evidence database. The
store is a reference implementation for the roadmap's operational callback
state requirement and a migration target for production Postgres.

## Scope

The `trustai.provider-callback-store/0.1` manifest binds:

- a SQLite database schema version, journal mode, tables, and indexes;
- provider callback operation records for installation manifests, inbound
  webhooks, outbound delivery receipts, audit correlations, audit stream receipts, Slack approval
  requests, and Slack approval callbacks;
- provider, operation type, source id, source artifact hash, deduplication key,
  status, payload hash, and created/received timestamps for every operation;
- redacted operation summaries that omit raw provider secrets, webhook
  signatures, provider credentials, and approval identities;
- optional source artifact summaries for replaying manifest-to-artifact hashes;
- a retention horizon for callback database evidence.

## SQLite Schema

The reference database stores metadata plus a `callback_operations` table keyed
by `operation_id`. Implementations must index:

- `provider`
- `operation_type`
- `source_id`
- `dedup_key`
- `created_at`

The manifest includes table and index metadata so a verifier can detect missing
indexes or schema drift before trusting the store summary.

## Verification

A verifier recomputes the manifest id from the canonical body, verifies at least
one detached signature, opens the SQLite database, compares schema/index
metadata, replays the operation summary, and optionally recomputes source
artifact hashes from supplied signed artifacts.

Verification fails if the database summary differs, required indexes are
missing, source artifacts do not match, retention timestamps are invalid, or a
redacted summary contains secret-like fields.

## Evidence Chain Entry

`provider_callback_store.attested` entries record the store manifest id and
hash, database engine/schema/journal/retention metadata, operation counts,
provider counts, source artifact count, and control status summary.

## Limitations

This spec covers a local SQLite reference store. Pair it with
`trustai.provider-ingress/0.1` manifests to bind BYOC/public callback ingress
configuration by hash and `trustai.provider-callback-storage/0.1` manifests to
bind Postgres/HA migration controls. Production deployments still need hosted
OAuth/app installation execution, revocation handling, live TrustAI-operated
public ingress, live managed Postgres with backups and SLOs, and
continuously operated provider-authenticated audit-log retrieval or streaming.
