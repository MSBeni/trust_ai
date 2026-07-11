# Policy Backend Worker Receipt v0.1

Policy backend worker receipts bind a single scheduled OPA/Cedar backend
operation to the policy backend service attestation and enforcement receipt it
processed. They narrow the gap between service hardening evidence and a
production-operated policy worker by recording scheduler, lease, queue,
checkpoint, backend request/response, decision-log, audit-log, provider export,
and redacted credential evidence. The schema is
`trustai.policy-backend-worker/0.1`.

## Contents

- `mode`: one of `local-reference`, `scheduled-worker`, `hosted-worker`, or
  `production-design`.
- `environment` and `recorded_at`: deployment context and worker completion
  time.
- `service`: policy backend service attestation id/hash, service ref/version,
  engine, backend endpoint, bundle, service decision/audit roots, and redacted
  service credential reference.
- `source_enforcement`: source enforcement receipt id/hash, backend endpoint,
  request/response hashes, policy bundle, policy decision hash, and redacted
  backend credential reference.
- `source`: replayable source summary binding the service attestation,
  enforcement receipt, policy pack, runtime action, proof pack, policy
  decision, policy export, and optional policy engine receipt.
- `worker`: worker identity, run ref, operation kind, actor, start/completion
  timestamps, attempt counters, success flag, and optional error ref.
- `scheduler`: schedule, cadence, lease, checkpoint, cursor, and next-run
  metadata.
- `execution`: queue/DLQ message evidence, backend request ref, engine,
  endpoint, policy bundle, request/response hashes, HTTP status, and accepted
  status.
- `observability`: decision-log root, optional decision-record hash, metrics,
  audit-log root, retention horizon, and evidence refs.
- `provider_exports`: optional scheduler, queue, lease, decision-log, and audit
  provider export refs and hashes.
- `credential` and `backend_credential`: redacted worker and backend
  credential refs only.
- `source_artifacts`: canonical ids, schemas, and hashes for the service
  attestation, enforcement receipt, policy pack, runtime action, proof pack,
  policy decision, policy export, and optional policy engine receipt.
- `controls`: derived source, hosted-worker, scheduler, execution,
  observability, provider-export, credential-redaction, and outcome checks.
- `worker_operation_id` and `signatures`: canonical receipt hash and detached
  signatures.

## Verification

`trustai policy-backend-worker-verify` checks:

1. Schema, canonical `worker_operation_id`, and at least one valid signature.
2. RFC 3339 timestamps, completion after start, and retention after
   `recorded_at`.
3. Supported mode and operation kind, positive cadence, valid retry counters,
   and explicit success/error semantics.
4. Service attestation replay against the supplied enforcement receipt, policy
   pack, runtime action, proof pack, decision, export, and optional policy
   engine receipt.
5. Source enforcement replay against the supplied backend enforcement receipt.
6. Source-artifact hashes and source summaries match supplied artifacts.
7. Execution fields match the source enforcement backend, endpoint, bundle,
   request hash, response status, and response hash.
8. Scheduler lease/checkpoint evidence, queue message hash, decision/audit log
   roots, optional decision record, and provider export hashes are present and
   hash-shaped where required.
9. Service credential refs match the service attestation operation credential,
   and backend credential refs match the enforcement receipt credential.
10. Secret-like fields are redacted references rather than raw tokens,
    passwords, client secrets, private keys, cookies, or authorization headers.

Verification is fail-closed when required source artifacts are omitted from
offline replay. Warnings are emitted when the mode does not claim a
scheduled/hosted worker operation.

## Chain Entry

`trustai policy-backend-worker-append` verifies the receipt and appends a
`policy_backend.worker_recorded` evidence-chain entry containing the worker
operation id/hash, service and enforcement source binding, scheduler evidence,
execution evidence, observability roots, provider export summaries, credential
redaction status, and control summary.

## CLI

```powershell
python -m trustai policy-backend-worker artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --mode hosted-worker --environment aitrade-prod --worker-ref worker:policy-backend/opa-enforcement --run-ref worker-run:policy-backend/opa/2026-07-04T04:05:00Z --operation-kind policy_enforcement --actor-ref oidc:trustai.example/policy-backend-worker --schedule-ref schedule:policy-backend/opa/continuous --cadence-seconds 30 --lease-ref lease:policy-backend/opa/2026-07-04T04:05:00Z --checkpoint-ref checkpoint:policy-backend/opa --checkpoint-hash sha256:policy-backend-worker-checkpoint --previous-cursor-ref cursor:policy-backend/opa/before --next-cursor-ref cursor:policy-backend/opa/after --next-run-at 2026-07-04T04:05:30Z --queue-ref queue:policy-backend/opa-enforcement --queue-message-ref queue-message:policy-backend/opa/action-123 --queue-message-hash sha256:policy-backend-worker-queue-message --dead-letter-queue-ref queue:policy-backend/opa-dlq --backend-request-ref opa-request:policy-backend/opa/action-123 --decision-log-ref decision-log:policy-backend/opa --decision-log-root sha256:policy-backend-worker-decision-log-root --decision-record-hash sha256:policy-backend-worker-decision-record --metrics-ref metrics:policy-backend/workers --audit-log-ref audit-log:policy-backend/service --audit-log-root sha256:policy-backend-worker-audit-root --retention-until 2033-07-04T00:00:00Z --credential-ref env:POLICY_BACKEND_SERVICE_TOKEN --backend-credential-ref env:OPA_BACKEND_TOKEN --scheduler-export-ref aws:scheduler/policy-backend/opa --scheduler-export-hash sha256:policy-backend-worker-scheduler-export --queue-export-ref sqs:policy-backend/opa-enforcement --queue-export-hash sha256:policy-backend-worker-queue-export --lease-export-ref dynamodb:policy-backend/leases/opa --lease-export-hash sha256:policy-backend-worker-lease-export --decision-log-export-ref s3:policy-backend/decision-log/opa --decision-log-export-hash sha256:policy-backend-worker-decision-log-export --audit-export-ref cloudtrail:policy-backend/service --audit-export-hash sha256:policy-backend-worker-audit-export --evidence-ref evidence:policy-backend/worker --started-at 2026-07-04T04:05:00Z --completed-at 2026-07-04T04:05:01Z --out artifacts/policy-backend-worker.json
python -m trustai policy-backend-worker-verify artifacts/policy-backend-worker.json artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json
python -m trustai policy-backend-worker-append artifacts/policy-backend-worker.json artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --state .trustai/policy-backend-worker-demo/evidence-chain.json --tenant policy-backend-worker-local --out artifacts/policy-backend-worker-entry.json
```

## Limits

This receipt proves a worker operation over signed local/reference evidence. It
does not by itself prove a continuously operated external OPA/Cedar backend
unless paired with provider-native scheduler, queue, lease, decision-log,
audit-log, credential custody, and immutable production log exports from the
operated infrastructure.
