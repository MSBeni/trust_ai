# Identity Provider Session Receipt v0.1

This specification defines a signed receipt for binding an identity-provider
session, token, or account event to a TrustAI identity-provider attestation.
It complements `identity-provider-attestation`: the attestation proves which
provider identity record belongs to an agent, while this receipt proves a
specific provider-authenticated event was observed for that identity.

## Schema

`schema`: `trustai.identity-provider-session/0.1`

Required top-level fields:

- `session_id`: canonical hash of the receipt body.
- `mode`: one of `local-reference`, `recorded-provider-response`,
  `provider-event-stream`, `hosted-session`, or `production-design`.
- `recorded_at`: RFC3339 timestamp for receipt creation.
- `provider`: `okta`, `entra`, or `servicenow`.
- `identity_attestation`: source attestation id, hash, provider, tenant, and
  subject identity binding.
- `session`: session ref, event ref, event kind, provider event id, provider
  tenant, subject identity, actor, start/expiry, and observed timestamp.
- `authentication_context`: auth method, assurance level, scopes, audiences,
  decision, and risk level.
- `provider_evidence`: provider endpoint URL, request/response hashes, HTTP
  status, session-log root, audit-log root, optional source-IP/user-agent
  hashes as canonical `sha256:` plus 64 lowercase hex characters, redacted credential reference, and retention timestamp.
- `controls`: conformance controls for source binding, hash evidence, redacted
  credentials, and live provider session evidence.
- `signatures`: detached local HMAC signature over the session id and body.

Supported event kinds are `agent_login`, `token_introspection`,
`token_refresh`, `session_revocation`, `app_assignment`, `api_access`,
`scim_sync`, `risk_signal`, and `account_lifecycle`.

## Verification

`trustai identity-session-verify` checks:

- schema, canonical `session_id`, and signature;
- mode, supported provider, and source identity-attestation binding;
- session/event required fields and RFC3339 timestamp ordering;
- event kind, decision, scope, and audience structure;
- HTTPS provider endpoint URL;
- request, response, session-log, audit-log, source-IP, and user-agent hashes
  as canonical `sha256:` plus 64 lowercase hex characters;
- HTTP response status and success flag consistency;
- redacted credential reference and absence of secret-like raw values;
- source identity-provider attestation verification when supplied, including
  optional replay of identity payload, retained raw identity export artifact
  bytes recorded in `source_artifacts`, vendor identity receipt, trust-network
  manifest, and proof packs.

When the source attestation is not supplied, verification can only prove receipt
integrity and embedded hashes. It emits a warning for missing deep replay. Modes
other than `provider-event-stream` or `hosted-session` also warn that live
provider session operation is not claimed.

## Evidence Chain Entry

`trustai identity-session-append` verifies the receipt, then appends
`identity.provider.session_recorded` to an evidence chain. The entry payload
records the session id/hash, provider, mode, identity-attestation binding,
session metadata, authentication context, and provider evidence minus the
redacted credential object.

## Reference Commands

```powershell
python -m trustai identity-session artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --mode provider-event-stream --environment aitrade-prod --provider-tenant-ref okta:example-org --session-ref okta-session:aitrade-risk/2026-07-12T02:00:00Z --event-ref okta-event:evt_20260712_aitrade_token_introspection --event-kind token_introspection --provider-event-id evt_20260712_aitrade_token_introspection --actor-ref oidc:trustai.example/identity-session-worker --scope-ref scope:trustai/proof-pack.read --audience-ref audience:trustai-registry --endpoint-url https://okta.example/oauth2/v1/introspect --credential-ref env:OKTA_INTROSPECTION_TOKEN --request-hash sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --response-status 200 --response-hash sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd --session-log-ref okta:system-log/query/aitrade-session --session-log-root sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee --audit-log-ref audit-log:identity-provider/session-worker --audit-log-root sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff --source-ip-hash sha256:1111111111111111111111111111111111111111111111111111111111111111 --device-ref workload:trustai/identity-session-worker --user-agent-hash sha256:2222222222222222222222222222222222222222222222222222222222222222 --session-started-at 2026-07-12T02:00:00Z --session-expires-at 2026-07-12T03:00:00Z --observed-at 2026-07-12T02:00:05Z --recorded-at 2026-07-12T02:00:06Z --retention-until 2033-07-12T00:00:00Z --evidence-ref evidence:identity-provider/session --out artifacts/identity-provider-session.json
python -m trustai identity-session-verify artifacts/identity-provider-session.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json
python -m trustai identity-session-append artifacts/identity-provider-session.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --state .trustai/identity-provider-session-demo/evidence-chain.json --tenant identity-provider-session-local --out artifacts/identity-provider-session-entry.json
python -m trustai chain-verify --state .trustai/identity-provider-session-demo/evidence-chain.json --tenant identity-provider-session-local
```

## Production Boundary

This local receipt can bind recorded provider request/response evidence and
provider audit roots, but it is not a substitute for a continuously operated
identity-provider integration. Production deployments still require
provider-authenticated Okta/Entra/ServiceNow event streams, immutable provider
system-log exports, session revocation propagation, account lifecycle events,
credential custody, and provider-owned audit evidence retained outside TrustAI.
