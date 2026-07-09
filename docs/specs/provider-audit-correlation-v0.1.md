# Provider Audit Correlation Receipt v0.1

Provider audit correlation receipts bind TrustAI provider receipts to a
provider-supplied audit-log export. They close the local evidence loop for
CI/CD callback operations: an outbound provider delivery or inbound provider
webhook can be correlated to an independent provider audit event by canonical
hashes and stable provider ids.

This v0.1 artifact supports:

- GitHub/GitLab webhook receipt correlation by provider, event, delivery id,
  raw payload SHA-256, and receipt id when present in the provider export.
- Provider delivery receipt correlation by provider, delivery receipt id,
  provider payload hash, request body hash, target URL, and request path.
- Redacted audit event binding by event hash and match criteria without copying
  full provider audit rows into the receipt.
- Offline verification against the original audit-log export plus source
  TrustAI receipt.
- Evidence-chain append as `provider_audit.correlated`.

## Schema

`schema`: `trustai.provider-audit-correlation/0.1`

Top-level fields:

- `correlation_id`: canonical hash of the correlation body without
  `correlation_id` and `signatures`.
- `provider`: provider namespace such as `github` or `gitlab`.
- `correlated_at`: RFC3339 timestamp when TrustAI correlated the audit export.
- `audit_log_ref`: optional external reference to the provider export.
- `audit_log`: canonical hash and event count for the supplied audit export.
- `source_receipts`: one or more TrustAI source receipt summaries. Each summary
  includes source type, source id, source hash, provider, and non-secret match
  fields such as delivery id, payload hash, request path, or target URL.
- `matches`: matched provider audit event index, event hash, source id, and
  criteria used for the match. Criteria are marked `context` or `strong`.
- `limitations`: explicit local-reference limitations.
- `signatures`: detached TrustAI signatures over correlation id and body.

The receipt never stores provider webhook secrets, raw provider signatures,
authorization tokens, or full provider audit rows. The original audit export is
supplied separately for verification.

## Verification

`trustai provider-audit-verify` checks:

- receipt schema and RFC3339 timestamp;
- correlation id canonical hash;
- detached TrustAI signature;
- audit-log hash and event count against the supplied provider export;
- source receipt summaries against supplied webhook or delivery receipts;
- source receipt signatures using their native verifiers;
- matched audit event hashes and replayed match criteria.

Verification with only a correlation receipt proves the TrustAI signature and
body hash. Verification with `--audit-log` and source receipts proves that the
correlation still matches the provider export and TrustAI receipt evidence.

`trustai provider-audit-append` appends a `provider_audit.correlated` chain entry
containing the correlation id, provider, audit-log hash, source receipt hashes,
and matched audit event hashes.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai provider-audit-correlation examples/webhooks/github-audit-log.json --webhook-receipt artifacts/github-provider-webhook.json --provider github --audit-log-ref github:audit-log:local --out artifacts/github-provider-audit-correlation.json
python -m trustai provider-audit-verify artifacts/github-provider-audit-correlation.json --audit-log examples/webhooks/github-audit-log.json --webhook-receipt artifacts/github-provider-webhook.json
python -m trustai provider-audit-append artifacts/github-provider-audit-correlation.json --audit-log examples/webhooks/github-audit-log.json --webhook-receipt artifacts/github-provider-webhook.json --state .trustai/provider-audit-demo/evidence-chain.json --tenant provider-audit-local --out artifacts/github-provider-audit-correlation-entry.json
```

Production deployments still need provider-hosted OAuth/app installation
management, public ingress, managed Postgres/HA request storage, and
provider-authenticated audit-log retrieval or streaming. This receipt defines
the portable evidence those production audit correlations must emit.
