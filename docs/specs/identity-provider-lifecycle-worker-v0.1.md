# Identity Provider Lifecycle Worker Receipt v0.1

This specification defines a signed receipt for a scheduled or hosted
identity-provider lifecycle worker run. It complements
`identity-provider-lifecycle-operation`: an operation receipt proves a single
provider mutation was recorded, while a worker receipt proves that a TrustAI or
customer-operated worker picked up that operation, bound scheduler state, and
recorded propagation roots for account, session, token, and application state.

## Schema

`schema`: `trustai.identity-provider-lifecycle-worker/0.1`

Required top-level fields:

- `worker_operation_id`: canonical hash of the receipt body.
- `mode`: one of `local-reference`, `scheduled-worker`, `hosted-worker`,
  `provider-event-stream-worker`, or `production-design`.
- `environment`: deployment environment for the worker run.
- `recorded_at`: RFC3339 timestamp for receipt creation. It must equal
  `worker.completed_at`.
- `provider`: `okta`, `entra`, or `servicenow`, inherited from the source
  lifecycle operation.
- `source_operation`: source lifecycle operation id, hash, provider, kind,
  operation refs, identity id, target state, outcome, completion timestamp,
  success flag, provider system-log root, and TrustAI audit-log root.
- `worker`: worker ref, run ref, operation kind, actor, start/completion
  timestamps, attempt metadata, success flag, and optional error reference.
- `scheduler`: schedule ref, cadence seconds, lease ref, checkpoint ref,
  checkpoint hash, optional cursors, and optional next run timestamp.
- `propagation`: queue and destination refs, propagation log root, optional
  queue message, account/session/token log roots, and optional provider
  request/response hashes.
- `observability`: metrics ref, audit-log root, retention timestamp, and
  optional evidence refs.
- `credential`: redacted worker credential reference only.
- `controls`: conformance controls for source-operation binding, scheduler
  lease/checkpoint, propagation roots, source success propagation, provider
  response status, redacted credentials, and hosted worker mode.
- `signatures`: detached local HMAC signature over the worker operation id and
  body.

Supported worker operation kinds are `lifecycle_operation_propagation`,
`account_state_reconcile`, `app_assignment_propagation`,
`token_revocation_propagation`, `session_revocation_propagation`,
`scim_sync_reconcile`, and `dead_letter_replay`.

## Verification

`trustai identity-lifecycle-worker-verify` checks:

- schema, canonical `worker_operation_id`, and signature;
- supported provider and lifecycle worker mode;
- source lifecycle operation object completeness, hash references, provider
  match, success flag, and completion timestamp;
- worker operation kind, attempts, required actor/ref fields, timestamp ordering,
  and success consistency with the source operation, response status, and
  `error_ref`;
- scheduler cadence, lease, checkpoint, checkpoint hash, cursors, and next-run
  timestamp;
- propagation queue/destination refs, propagation log root, account/session/token
  log roots, request hash, response hash, and HTTP response status;
- observability audit root, metrics ref, retention timestamp, and evidence refs;
- redacted credential reference and absence of raw secret-like values;
- source `identity-provider-lifecycle-operation` verification when supplied,
  including optional replay of identity-provider attestation, identity-provider
  session, identity payload, retained raw identity export artifact bytes, vendor
  identity receipt, trust-network manifest, and proof packs.

When source receipts are not supplied, verification can only prove receipt
integrity and embedded hashes. It emits warnings for missing deep replay. Modes
other than `hosted-worker` or `provider-event-stream-worker` warn that live
identity-provider lifecycle worker operation is not claimed.

## Evidence Chain Entry

`trustai identity-lifecycle-worker-append` verifies the receipt, then appends
`identity.provider.lifecycle_worker_recorded` to an evidence chain. The entry
payload records the worker operation id/hash, provider, mode, environment,
source lifecycle operation binding, worker/scheduler/propagation/observability
metadata, and a control status summary. The redacted credential object is not
copied into the entry payload.

## Reference Commands

```powershell
python -m trustai identity-lifecycle-worker artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json --mode hosted-worker --environment aitrade-prod --worker-ref worker:identity-provider/lifecycle/okta --run-ref worker-run:identity-provider/lifecycle/2026-07-12T02:01:05Z --operation-kind app_assignment_propagation --actor-ref oidc:trustai.example/identity-lifecycle-worker --schedule-ref schedule:identity-provider/lifecycle/1m --cadence-seconds 60 --lease-ref lease:identity-provider/lifecycle/2026-07-12T02:01:05Z --checkpoint-ref checkpoint:identity-provider/lifecycle/okta --checkpoint-hash sha256:identity-provider-lifecycle-worker-checkpoint --previous-cursor-ref okta:system-log/cursor/before-assignment --next-cursor-ref okta:system-log/cursor/after-assignment --queue-ref queue:identity-provider/lifecycle --queue-message-ref queue-message:identity-provider/lifecycle/app-assignment --destination-ref identity-provider:okta/example-org --propagation-log-ref propagation-log:identity-provider/lifecycle/okta --propagation-log-root sha256:identity-provider-lifecycle-worker-propagation-root --account-state-log-ref account-state-log:identity-provider/okta --account-state-log-root sha256:identity-provider-lifecycle-worker-account-root --session-revocation-log-ref session-revocation-log:identity-provider/okta --session-revocation-log-root sha256:identity-provider-lifecycle-worker-session-root --token-revocation-log-ref token-revocation-log:identity-provider/okta --token-revocation-log-root sha256:identity-provider-lifecycle-worker-token-root --request-hash sha256:identity-provider-lifecycle-worker-request --response-status 200 --response-hash sha256:identity-provider-lifecycle-worker-response --metrics-ref metrics:identity-provider/lifecycle-worker --audit-log-ref audit-log:identity-provider/lifecycle-worker --audit-log-root sha256:identity-provider-lifecycle-worker-audit-root --credential-ref env:OKTA_LIFECYCLE_WORKER_TOKEN --started-at 2026-07-12T02:01:05Z --completed-at 2026-07-12T02:01:07Z --next-run-at 2026-07-12T02:02:05Z --retention-until 2033-07-12T00:00:00Z --evidence-ref evidence:identity-provider/lifecycle-worker --out artifacts/identity-provider-lifecycle-worker.json
python -m trustai identity-lifecycle-worker-verify artifacts/identity-provider-lifecycle-worker.json artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json
python -m trustai identity-lifecycle-worker-append artifacts/identity-provider-lifecycle-worker.json artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json --state .trustai/identity-provider-lifecycle-worker-demo/evidence-chain.json --tenant identity-provider-lifecycle-worker-local --out artifacts/identity-provider-lifecycle-worker-entry.json
python -m trustai chain-verify --state .trustai/identity-provider-lifecycle-worker-demo/evidence-chain.json --tenant identity-provider-lifecycle-worker-local
```

## Production Boundary

This local receipt can bind source lifecycle operation hashes, scheduler leases,
checkpoints, cursors, queue propagation metadata, provider request/response
hashes, account/session/token log roots, audit roots, and redacted credential
references. It is not a substitute for a continuously operated provider-owned
event stream or hosted worker fleet. Production deployments still require live
Okta/Entra/ServiceNow event streams, production scheduler and lease storage,
credentialed external provider dispatch, immutable provider-owned propagation
logs, live vault/KMS custody, retry/dead-letter operations, and monitored worker
fleets retained outside this local reference artifact.

