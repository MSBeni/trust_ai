# Identity Provider Lifecycle Operation Receipt v0.1

This specification defines a signed receipt for binding an identity-provider
account, application, token, or session lifecycle operation to a TrustAI
identity-provider attestation. It complements `identity-provider-session`: a
session receipt proves a provider-observed login/token/session event, while a
lifecycle operation receipt proves that a provider mutation such as assignment,
suspension, SCIM sync, token revocation, or session revocation was recorded
against the same agent identity.

## Schema

`schema`: `trustai.identity-provider-lifecycle-operation/0.1`

Required top-level fields:

- `operation_id`: canonical hash of the receipt body.
- `mode`: one of `local-reference`, `recorded-provider-response`,
  `provider-event-stream`, `hosted-lifecycle-worker`, or `production-design`.
- `recorded_at`: RFC3339 timestamp for receipt creation.
- `provider`: `okta`, `entra`, or `servicenow`.
- `identity_attestation`: source attestation id, hash, provider, tenant, and
  subject identity binding.
- `operation`: operation kind/ref, provider operation id, provider tenant,
  subject identity, actor, target state, outcome, timestamps, and idempotency
  key.
- `change_refs`: optional reason, approval, and change-ticket references.
- `provider_evidence`: provider endpoint URL, request/response hashes, HTTP
  status, provider system-log root, TrustAI audit-log root, previous/resulting
  identity record hashes, redacted credential reference, and retention
  timestamp.
- `source_session`: optional binding to an identity-provider session receipt.
- `controls`: conformance controls for source binding, hash evidence, lifecycle
  state, optional session binding, redacted credentials, and live lifecycle
  operation evidence.
- `signatures`: detached local HMAC signature over the operation id and body.

Supported operation kinds are `account_create`, `account_update`,
`account_suspend`, `account_reactivate`, `account_deactivate`,
`account_delete`, `app_assignment`, `app_unassignment`, `token_revocation`,
`session_revocation`, `scim_sync`, and `risk_policy_update`.

## Verification

`trustai identity-lifecycle-operation-verify` checks:

- schema, canonical `operation_id`, and signature;
- mode, supported provider, and source identity-attestation binding;
- lifecycle operation required fields, supported kind, supported target state,
  supported outcome, idempotency key, and RFC3339 timestamp ordering;
- state-pair invariants such as `app_assignment -> assigned`,
  `token_revocation -> revoked`, and `session_revocation -> revoked`;
- HTTPS provider endpoint URL;
- request, response, provider system-log, TrustAI audit-log, previous identity
  record, and optional resulting identity record hash references;
- HTTP response status, success flag, and outcome consistency;
- redacted provider credential reference and absence of secret-like raw values;
- source identity-provider attestation verification when supplied, including
  optional replay of identity payload, vendor identity receipt, trust-network
  manifest, and proof packs;
- source identity-provider session verification when supplied, including
  session hash replay and provider/identity matching.

When source receipts are not supplied, verification can only prove receipt
integrity and embedded hashes. It emits warnings for missing deep replay. Modes
other than `provider-event-stream` or `hosted-lifecycle-worker` also warn that
live provider lifecycle operation is not claimed.

## Evidence Chain Entry

`trustai identity-lifecycle-operation-append` verifies the receipt, then appends
`identity.provider.lifecycle_operation_recorded` to an evidence chain. The entry
payload records the operation id/hash, provider, mode, identity-attestation
binding, optional session binding, operation metadata, change references,
provider evidence minus the redacted credential object, and a control status
summary.

## Reference Commands

```powershell
python -m trustai identity-lifecycle-operation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json --mode hosted-lifecycle-worker --environment aitrade-prod --provider-tenant-ref okta:example-org --operation-ref okta-lifecycle:aitrade-risk/app-assignment/2026-07-12 --operation-kind app_assignment --provider-operation-id evt_20260712_aitrade_app_assignment --actor-ref oidc:trustai.example/identity-lifecycle-worker --target-state assigned --endpoint-url https://okta.example/api/v1/apps/app123/users --credential-ref env:OKTA_LIFECYCLE_TOKEN --request-hash sha256:identity-provider-lifecycle-request --response-status 200 --response-hash sha256:identity-provider-lifecycle-response --system-log-ref okta:system-log/query/aitrade-lifecycle --system-log-root sha256:identity-provider-lifecycle-system-log-root --audit-log-ref audit-log:identity-provider/lifecycle-worker --audit-log-root sha256:identity-provider-lifecycle-audit-root --requested-at 2026-07-12T02:01:00Z --completed-at 2026-07-12T02:01:02Z --recorded-at 2026-07-12T02:01:03Z --retention-until 2033-07-12T00:00:00Z --reason-ref change:aitrade-risk/app-assignment --approval-ref approval:aitrade-risk/app-assignment --change-ticket-ref ticket:IDENTITY-1234 --resulting-identity-record-hash sha256:identity-provider-lifecycle-resulting-record --evidence-ref evidence:identity-provider/lifecycle --out artifacts/identity-provider-lifecycle-operation.json
python -m trustai identity-lifecycle-operation-verify artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json
python -m trustai identity-lifecycle-operation-append artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json --state .trustai/identity-provider-lifecycle-demo/evidence-chain.json --tenant identity-provider-lifecycle-local --out artifacts/identity-provider-lifecycle-operation-entry.json
python -m trustai chain-verify --state .trustai/identity-provider-lifecycle-demo/evidence-chain.json --tenant identity-provider-lifecycle-local
```

## Production Boundary

This local receipt can bind recorded provider request/response evidence,
provider system-log roots, TrustAI audit roots, session receipt bindings, and
identity record hashes. It is not a substitute for a continuously operated
identity-provider lifecycle integration. Production deployments still require
provider-authenticated Okta/Entra/ServiceNow lifecycle workers, immutable
provider system-log exports, SCIM/account propagation logs, revocation
propagation, credential custody, and provider-owned audit evidence retained
outside TrustAI.
