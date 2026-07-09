# Provider Audit Stream Receipt v0.1

Provider audit stream receipts record a provider-authenticated audit-log retrieval
or stream window. They complement provider audit correlation receipts: the stream
receipt proves which provider endpoint, credential reference, request hash,
response status, response hash, window, cursor, lifecycle binding, and audit-log
hash produced the export that later gets correlated to TrustAI provider events.

## Receipt

`schema`: `trustai.provider-audit-stream/0.1`

The receipt binds:

- `stream_receipt_id`: canonical hash of the receipt body.
- `mode`: `local-reference`, `recorded-provider-stream`,
  `provider-audit-stream`, `http-dispatch`, or `production-design`.
- `provider`, `environment`, and `recorded_at`.
- `stream`: stable stream ref, audit-log export ref, HTTPS endpoint URL,
  window start/end, optional cursor refs, request hash, response status,
  response hash, success flag, and actor ref.
- `audit_log`: canonical hash and event count for the provider audit export.
- `credential`: redacted provider audit credential reference.
- `bindings`: optional provider installation manifest hash, provider lifecycle
  manifest hash and `audit_log_stream_binding` refs, and provider audit
  correlation receipt hash.
- `controls`: implemented/planned status for stream binding, endpoint evidence,
  redacted credential handling, cursor/window scope, installation audit scopes,
  lifecycle binding, correlation binding, and live stream claims.

The receipt never stores provider tokens, private keys, raw response bodies, or
full provider audit rows. The original audit export is supplied separately for
verification.

## Verification

`trustai provider-audit-stream-verify` checks:

- canonical `stream_receipt_id` and detached signature;
- RFC3339 `recorded_at`, `window_start`, and `window_end` ordering;
- supported mode;
- HTTPS endpoint URL;
- request and response SHA-256 references;
- HTTP response status and success flag consistency;
- audit-log hash and event count replay when the audit export is supplied;
- redacted credential reference and absence of raw secret-like values;
- provider installation manifest replay and audit-log ref/scopes when supplied;
- provider lifecycle manifest replay and declared `audit_log_stream_binding`
  stream ref when supplied;
- provider audit correlation receipt hash and provider alignment when supplied.

Verification emits warnings when optional source artifacts are not supplied or
when the mode records a local/reference stream without claiming live hosted
provider retrieval.

## Chain Entry

`provider_audit.stream_recorded` entries record the stream receipt id/hash,
provider, mode, environment, stream metadata, audit-log hash/count, redacted
credential reference, binding summaries, and control summary.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai provider-audit-stream examples/webhooks/github-audit-log.json --provider github --stream-ref github:audit-log-stream:volelabs --audit-log-ref github:audit-log:local-window-001 --endpoint-url https://api.github.com/orgs/volelabs/audit-log --credential-ref env:GITHUB_AUDIT_LOG_TOKEN --request-hash sha256:github-audit-log-request --response-status 200 --response-hash sha256:github-audit-log-response --actor-ref oidc:trustai.example/provider-audit-worker --window-start 2026-07-08T02:00:00Z --window-end 2026-07-08T02:10:00Z --cursor-ref github:audit-cursor:start --next-cursor-ref github:audit-cursor:next --provider-installation artifacts/github-provider-installation.json --lifecycle artifacts/provider-lifecycle.json --correlation artifacts/github-provider-audit-correlation.json --mode provider-audit-stream --recorded-at 2026-07-08T02:11:00Z --out artifacts/provider-audit-stream.json
python -m trustai provider-audit-stream-verify artifacts/provider-audit-stream.json --audit-log examples/webhooks/github-audit-log.json --provider-installation artifacts/github-provider-installation.json --lifecycle artifacts/provider-lifecycle.json --correlation artifacts/github-provider-audit-correlation.json
python -m trustai provider-audit-stream-append artifacts/provider-audit-stream.json --audit-log examples/webhooks/github-audit-log.json --provider-installation artifacts/github-provider-installation.json --lifecycle artifacts/provider-lifecycle.json --correlation artifacts/github-provider-audit-correlation.json --state .trustai/provider-audit-stream-demo/evidence-chain.json --tenant provider-audit-stream-local --out artifacts/provider-audit-stream-entry.json
```

## Limitations

This receipt verifies recorded provider audit stream/export evidence. It does
not by itself prove a continuously operated hosted audit-log streamer, provider
credential custody, retry scheduler, or hosted correlation worker unless paired
with provider audit worker receipts, deployment, ingress, credential-management,
storage, monitoring, and operational runbook evidence.
