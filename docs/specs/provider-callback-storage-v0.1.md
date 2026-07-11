# Provider Callback Storage Manifest v0.1

Provider callback storage manifests bind the roadmap's managed callback request
storage requirement to verifiable evidence. They describe the Postgres-compatible
target that will replace the local SQLite callback operation store in BYOC or
hosted production deployments.

## Manifest

`schema`: `trustai.provider-callback-storage/0.1`

The manifest binds:

- `storage_manifest_id`: canonical hash of the manifest body.
- `storage`: mode, environment, storage reference, Postgres-compatible engine,
  redacted DSN reference, schema reference, and retention horizon.
- `migration_plan`: source SQLite callback-store id/hash, source schema, source
  operation counts, source tables/indexes, target engine, schema reference,
  migration reference, migration hash, and required target tables.
- `high_availability`: primary region, replica regions, minimum replicas,
  failover runbook, RPO, and RTO.
- `security_controls`: redacted encryption-key reference, network policy,
  backup policy, and monitoring reference.
- `source_artifacts`: canonical summaries for the callback-store manifest and
  optional provider-ingress manifest.
- `controls`: implemented/planned status for Postgres target, source migration
  binding, HA topology, backup retention, security boundary, monitoring,
  ingress/storage correlation, and live managed-Postgres operations.

Supported modes:

- `local-reference`
- `byoc-reference`
- `managed-postgres-reference`
- `recorded-managed-postgres`
- `production-design`

## Verification

`trustai provider-callback-storage-verify` checks:

- canonical `storage_manifest_id` and detached signature;
- RFC3339 `generated_at` and retention timestamps;
- Postgres-compatible target engine;
- redacted DSN and encryption-key references;
- migration hash prefix and required table coverage;
- minimum HA topology of two replicas, primary region, failover runbook, RPO,
  and RTO;
- backup, network, and monitoring references;
- callback-store SQLite replay with source artifacts when callback-store evidence is supplied, plus provider-ingress hash replay.

Verification fails when recorded callback-store source artifacts are omitted; it emits warnings when non-required source artifacts are not supplied or when the
mode does not claim live managed-Postgres operation.

## Chain Entry

`provider_callback_storage.attested` entries record the storage manifest id and
hash, non-secret storage metadata, HA summary, non-secret security controls,
source callback-store id, source operation count, target engine, source-artifact
count, and control summary.

## Limitations

This artifact verifies a storage target and migration plan. Pair it with
`trustai.provider-lifecycle/0.1` manifests to bind callback persistence to OAuth,
token, revocation, uninstall, and provider audit-log stream references. It does
not by itself prove live managed-Postgres operations, successful backups,
failover drills, or hosted SLO monitoring unless those are supplied as
`recorded-managed-postgres` evidence.

