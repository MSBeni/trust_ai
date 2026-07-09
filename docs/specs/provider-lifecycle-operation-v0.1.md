# Provider Lifecycle Operation Receipt v0.1

Provider lifecycle operation receipts record individual provider OAuth, token,
credential, revocation, uninstall, and audit-log stream operations. They turn a
provider lifecycle manifest's operation references into replayable, signed
evidence with provider endpoint, request hash, response status, response hash,
redacted credential references, and optional token-store references.

## Receipt

`schema`: `trustai.provider-lifecycle-operation/0.1`

The receipt binds:

- `operation_receipt_id`: canonical hash of the receipt body.
- `mode`: `local-reference`, `recorded-provider-response`, `http-dispatch`,
  `provider-audit-stream`, or `production-design`.
- `lifecycle`: provider lifecycle manifest id/hash, lifecycle reference,
  provider, environment, and operation count.
- `operation`: operation kind, operation reference, provider event reference,
  HTTPS endpoint URL, request hash, response status, response hash, success
  flag, actor reference, and idempotency key.
- `credential`: redacted provider credential reference.
- `token_store`: optional redacted token-store reference.
- `audit_log`: optional provider audit-log reference for
  `audit_log_stream_binding` operations.
- `controls`: implemented/planned status for lifecycle binding, provider
  endpoint evidence, redacted credential handling, redacted token handling,
  revocation/uninstall operation evidence, audit stream evidence, and live
  provider dispatch claims.

Supported operation kinds:

- `authorization_callback`
- `token_exchange`
- `token_refresh_policy`
- `credential_rotation`
- `revocation_workflow`
- `uninstall_workflow`
- `audit_log_stream_binding`

## Verification

`trustai provider-lifecycle-operation-verify` checks:

- canonical `operation_receipt_id` and detached signature;
- RFC3339 `recorded_at`;
- supported mode and operation kind;
- lifecycle id/hash replay when the lifecycle manifest is supplied;
- operation kind/reference declaration in the lifecycle manifest;
- HTTPS provider endpoint URL;
- request and response SHA-256 references;
- HTTP response status and success flag consistency;
- redacted credential and token-store references;
- audit-log reference for audit stream operations;
- absence of raw token, credential, client secret, password, or private-key
  fields.

Verification emits warnings when the lifecycle manifest is not supplied or when
the receipt mode does not claim live hosted provider dispatch.

## Chain Entry

`provider_lifecycle.operation_recorded` entries record the operation receipt id
and hash, provider, mode, environment, lifecycle source summary, non-secret
operation metadata, redacted credential/token references, optional audit-log
reference, and control summary.

## Local HTTP Endpoint

The local reference server exposes `POST /v0/provider-lifecycle-operations`.
It accepts an inline `lifecycle`, `lifecycle_manifest`, or `lifecycle_path`,
plus operation fields either at the top level or under `operation`. Callers may
provide `request_hash` and `response_hash`, or `request_body` and
`response_body` so the server derives SHA-256 references locally without
persisting raw provider secrets.

When `trustai serve` is configured with
`--provider-lifecycle-operation-token`, the endpoint requires
`Authorization: Bearer <token>`. The endpoint builds and verifies a signed
provider lifecycle operation receipt, appends a
`provider_lifecycle.operation_recorded` entry to the configured evidence chain,
and returns the receipt, operation receipt id, operation entry id, tree head,
and warnings.

## Limitations

This receipt verifies recorded provider operation evidence. It does not by
itself prove a continuously operated hosted OAuth service, credential worker,
revocation worker, or audit-log streamer unless the receipt is produced in
`http-dispatch` or `provider-audit-stream` mode and paired with deployment,
ingress, storage, monitoring, and operational runbook evidence.
