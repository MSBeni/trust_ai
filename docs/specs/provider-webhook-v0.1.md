# Provider Webhook Receipt v0.1

Provider webhook receipts bind inbound GitHub/GitLab provider callbacks to
TrustAI evidence. They cover the CI/CD half of promotion gates: after TrustAI
posts a provider check/status, later provider webhooks can be verified, hashed,
signed, retained-body replay-bound, and appended without storing raw provider
secrets.

This v0.1 artifact supports:

- GitHub `X-Hub-Signature-256` HMAC-SHA256 validation over the raw request body.
- GitHub `X-GitHub-Event` and `X-GitHub-Delivery` event binding.
- GitLab `X-Gitlab-Token` shared-token validation.
- GitLab `X-Gitlab-Event` plus optional webhook UUID/event UUID binding.
- Redacted request-header hashing and raw payload SHA-256 binding.
- Optional retained payload artifact binding with path, byte SHA-256, byte
  length, and artifact id.
- Local retry deduplication keyed by provider, event, delivery id, and payload hash.

## Schema

`schema`: `trustai.provider-webhook/0.1`

Top-level fields:

- `receipt_id`: canonical hash of the receipt body without `receipt_id` and
  `signatures`.
- `provider`: `github` or `gitlab`.
- `received_at`: RFC3339 timestamp when the webhook was accepted by TrustAI.
- `payload`: raw payload `sha256`, byte length, and optional content type.
- `payload_artifact`: optional retained body artifact summary with normalized
  path, byte SHA-256, byte length, and artifact id.
- `request_headers`: observed header names and canonical hash of redacted
  headers. Authorization, token, signature, key, secret, and cookie headers are
  redacted before hashing.
- `webhook`: provider event name and delivery/webhook id when supplied.
- `verification`: provider verification method, verified header name, hash of
  the provider signature/token value, and `provider_signature_verified: true`.
- `signatures`: one or more detached TrustAI signatures over receipt id and
  body.

The provider secret and raw provider signature/token are never written to the
receipt. The value hash allows auditors to bind a specific observed provider
header without exposing the secret material.

## Verification

`trustai provider-webhook-verify` checks:

- receipt schema, provider, and RFC3339 timestamp;
- receipt id canonical hash;
- detached TrustAI signature;
- payload SHA-256 and size against the supplied raw body;
- retained payload artifact bytes when `payload_artifact` is present and a body
  artifact path is supplied;
- required event and verification metadata;
- optional provider signature replay when raw headers and secret are supplied;
- redacted header hash against the supplied raw headers when replaying.

Verification with only a receipt and body proves the TrustAI-signed receipt
still matches the payload. Verification with a retained body path also rejects
byte-level artifact substitution, even when parsed JSON content is equivalent.
Verification with body, headers, and secret also replays the original GitHub/GitLab
provider authentication.

`trustai provider-webhook-append` appends a `provider_webhook.recorded` chain
entry containing the receipt id, provider, event, delivery id, payload hash,
redacted header hash, and verification summary.

## HTTP API

The local reference server exposes:

- `POST /v0/provider-webhooks/github`
- `POST /v0/provider-webhooks/gitlab`

The endpoints require configured provider webhook secrets:

```powershell
$env:PYTHONPATH = "src"
python -m trustai serve --github-webhook-secret env:GITHUB_WEBHOOK_SECRET --gitlab-webhook-secret env:GITLAB_WEBHOOK_SECRET
```

On first receipt the server builds the receipt, appends it to the configured
evidence chain, records a deduplication store entry, and returns `receipt_id`,
`webhook_entry_id`, provider event metadata, `dedup_key`, `duplicate: false`,
and the updated tree root. On retry with the same provider/event/delivery id and
payload hash, the endpoint returns `duplicate: true` with the first receipt and
entry ids and does not append a second chain entry.

The local deduplication store defaults to `.trustai/server/provider-webhooks.json`
and can be changed with `trustai serve --provider-webhook-store`.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai provider-webhook github examples/webhooks/github-check-suite.json --secret env:GITHUB_WEBHOOK_SECRET --header "X-Hub-Signature-256: sha256=..." --header "X-GitHub-Delivery: delivery-123" --header "X-GitHub-Event: check_suite" --out artifacts/provider-webhook.json
python -m trustai provider-webhook-verify artifacts/provider-webhook.json examples/webhooks/github-check-suite.json --secret env:GITHUB_WEBHOOK_SECRET --header "X-Hub-Signature-256: sha256=..." --header "X-GitHub-Delivery: delivery-123" --header "X-GitHub-Event: check_suite"
python -m trustai provider-webhook-append artifacts/provider-webhook.json examples/webhooks/github-check-suite.json --state .trustai/provider-webhook-demo/evidence-chain.json --tenant provider-webhook-local --out artifacts/provider-webhook-entry.json
```

Production deployments still need public ingress, provider app/OAuth
configuration, managed Postgres/HA storage, and provider-authenticated
audit-log retrieval or streaming. Provider audit correlation receipts define the
portable evidence those production audit correlations must emit.
