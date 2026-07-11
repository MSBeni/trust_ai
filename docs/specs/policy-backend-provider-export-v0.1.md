# Policy Backend Provider Export Receipt v0.1

Policy backend provider export receipts bind a verified OPA/Cedar policy backend
worker operation to provider-native records from scheduler, queue, lease,
backend, decision-log, and audit systems. They narrow the remaining production
gap after policy backend worker receipts by proving that an external export file
contains records matching the worker run. The schema is
`trustai.policy-backend-provider-export/0.1`.

## Contents

- `mode`: one of `local-export`, `provider-export`, or `production-export`.
- `environment` and `exported_at`: deployment context and export completion
  time.
- `provider`: normalized provider name for the exported infrastructure.
- `worker_binding`: source policy backend worker operation id/hash, service
  attestation id, enforcement id, scheduler lease/checkpoint/cursor refs, queue
  message hash, backend request/response hashes, decision-log roots, audit
  roots, and run ref.
- `provider_export`: export metadata, content hash, record counts, record
  roots, export window, cursor refs, and provider export audit root.
- `matched_scheduler_record`, `matched_queue_record`, `matched_lease_record`,
  `matched_backend_record`, `matched_decision_log_record`, and
  `matched_audit_record`: hashes and summaries of provider records matched to
  the worker binding.
- `provider_exchange`: provider endpoint, request hash, response status,
  response hash, success flag, and actor.
- `credential`: redacted provider-export credential reference only.
- `controls`: derived provider mode, endpoint binding, scheduler/queue/lease,
  backend response, decision-log, and audit-root checks.
- `provider_receipt_id` and `signatures`: canonical receipt hash and detached
  signatures.

## Provider Export Shape

The provider export artifact is a JSON object with these required record arrays:

- `scheduler_records`: schedule, lease, checkpoint, cursor, next-run, and worker
  run records.
- `queue_records`: queue message, queue hash, DLQ, and acknowledgement records.
- `lease_records`: lease ownership, checkpoint, cursor, and worker run records.
- `backend_records`: OPA/Cedar backend, endpoint, bundle, request hash,
  response status, response hash, accepted flag, and policy decision hash.
- `decision_log_records`: decision-log root, matched decision record hash, and
  decision hash.
- `audit_records`: audit-log root and metrics refs for the worker operation.

## Verification

`trustai policy-backend-provider-export-verify` checks:

1. Schema, canonical `provider_receipt_id`, and at least one valid signature.
2. RFC 3339 export timestamp and provider export window ordering.
3. Supported mode and warning when live `production-export` is not claimed.
4. Worker receipt replay against supplied service attestation, enforcement
   receipt, policy pack, runtime action, proof pack, policy decision, policy
   export, and optional policy engine receipt.
5. Worker binding equality against the supplied worker receipt.
6. Provider export content hash, record counts, and record roots against the
   supplied provider export artifact.
7. Matching scheduler, queue, lease, backend, decision-log, and audit records
   against worker run refs, queue hashes, backend response hashes, decision
   hashes, decision-log roots, metrics, and audit roots.
8. Provider endpoint, request hash, response status, response hash, and actor.
9. Provider credentials are redacted references and no secret-like field stores
   raw token, cookie, password, private key, client secret, or authorization
   material.

Verification is fail-closed when the provider export artifact or worker source is
not supplied for replay. Warnings are emitted only when the receipt is not in
`production-export` mode.

## Chain Entry

`trustai policy-backend-provider-export-append` verifies the receipt and appends
a `policy_backend.provider_exported` evidence-chain entry containing the
provider receipt id/hash, worker operation id, run ref, provider export summary,
matched record summaries, provider exchange, credential ref, and control
summary.

## CLI

```powershell
python -m trustai policy-backend-provider-export artifacts/policy-backend-provider-export-source.json artifacts/policy-backend-worker.json artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --mode provider-export --environment aitrade-prod --provider aws-scheduler-sqs-dynamodb-s3-cloudtrail-opa --endpoint-url https://provider.example/aitrade/policy-backend/exports --credential-ref env:POLICY_BACKEND_PROVIDER_EXPORT_TOKEN --request-hash sha256:policy-backend-provider-export-request --response-status 200 --response-hash sha256:policy-backend-provider-export-response --actor-ref oidc:trustai.example/policy-backend-provider-exporter --exported-at 2026-07-04T04:06:00Z --out artifacts/policy-backend-provider-export.json
python -m trustai policy-backend-provider-export-verify artifacts/policy-backend-provider-export.json artifacts/policy-backend-provider-export-source.json artifacts/policy-backend-worker.json artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json
python -m trustai policy-backend-provider-export-append artifacts/policy-backend-provider-export.json artifacts/policy-backend-provider-export-source.json artifacts/policy-backend-worker.json artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --state .trustai/policy-backend-provider-export-demo/evidence-chain.json --tenant policy-backend-provider-export-local --out artifacts/policy-backend-provider-export-entry.json
```

## Limits

This receipt proves that a supplied provider export file matches a verified
policy backend worker operation. It does not by itself perform live cloud API
calls or prove continuous operation unless paired with live provider-owned
exports from scheduler, queue, lease, backend, decision-log, audit-log,
credential-custody, and immutable retention systems.
