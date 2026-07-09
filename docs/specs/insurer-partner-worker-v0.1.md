# Insurer Partner Worker Receipt v0.1

## Purpose

An insurer partner worker receipt records one operated delivery or workflow run
for the insurer partner service. It binds an
`trustai.insurer-partner-service-attestation/0.1` source to scheduler leases,
checkpoints, partner API delivery evidence, policy-system workflow hashes,
audit/access roots, and redacted TrustAI and partner worker credentials.

This format narrows the gap between a hardened insurer-facing service and live
underwriter operations by making each local or recorded worker run
replay-verifiable offline. It does not claim that the partner accepted legal
risk unless the receipt is backed by partner-owned logs and credentials.

## Schema

`trustai.insurer-partner-worker/0.1`

Required source artifacts:

- `insurer-partner-service-attestation`
- `insurer-risk-telemetry`
- `underwriting-quote`

Optional source artifacts:

- `actuarial-corpus`
- `actuarial-product`

Supported modes:

- `local-reference`
- `scheduled-worker`
- `hosted-worker`
- `partner-api-worker`
- `production-design`

Supported operation kinds:

- `insurer_telemetry_delivery`
- `underwriting_quote_delivery`
- `policy_binding_workflow`
- `actuarial_product_publish`
- `consent_reconcile`
- `delivery_log_replay`

The worker operation ID is the canonical content hash of the receipt body
excluding `worker_operation_id` and `signatures`. The signature covers:

```json
{
  "worker_operation_id": "...",
  "insurer_partner_worker": { "... canonical body ..." }
}
```

## Required Evidence

A worker receipt must bind:

- Service source: service attestation ID, hash, mode, environment, service
  reference, service kind, service version, endpoint, partner API endpoint,
  queue reference, policy-system reference, and partner contract reference.
- Risk transfer source: proof pack ID, verification contract ID, consent ID,
  telemetry hash, quote ID, quote reference, underwriter, risk tier, risk
  score, quoted premium, coverage limit, and discount.
- Worker run: worker reference, run reference, operation kind, actor reference,
  start/completion timestamps, attempts, success state, and optional error
  reference.
- Scheduler evidence: schedule reference, cadence, lease reference, checkpoint
  reference, checkpoint hash, previous and next cursor references, and optional
  next-run timestamp.
- Delivery evidence: queue reference, queue message reference, destination,
  delivery-log reference and root, partner event-log reference and root, request
  hash, response status, and response hash.
- Policy-system evidence: policy-system reference, workflow reference,
  workflow hash, optional binding reference and hash, and workflow status.
- Observability evidence: metrics reference, audit-log reference/root,
  access-log reference/root, retention timestamp, and evidence references.
- Credential custody: redacted TrustAI worker credential reference and redacted
  partner credential reference.

## Verification

`trustai insurer-partner-worker-verify` verifies:

1. Receipt schema, canonical hash, and signature.
2. Source artifact hashes, service source replay, and service-attestation
   verification.
3. Underwriting quote and telemetry binding, plus optional actuarial product
   and corpus bindings.
4. Worker mode and operation kind.
5. Scheduler lease, checkpoint, cursor, cadence, and timestamp ordering.
6. Delivery log roots, partner event roots, request/response hashes, queue
   evidence, and successful HTTP response status for successful runs.
7. Policy-system workflow hash, workflow status, and binding references.
8. Audit/access roots, retention after completion, and evidence references.
9. Redacted credential references and absence of raw secret-like fields.

## Chain Entry

`trustai insurer-partner-worker-append` appends an
`insurer.partner_worker_recorded` entry containing:

- worker operation ID and receipt hash
- mode, environment, worker run, scheduler, delivery, policy, and service
  summaries
- risk-transfer summary and source artifacts
- control list, status summary, and limitations

## Example

```bash
python -m trustai insurer-partner-worker \
  artifacts/insurer-partner-service-attestation.json \
  artifacts/insurer-risk-telemetry.json \
  artifacts/underwriting-quote.json \
  --actuarial-product artifacts/actuarial-product.json \
  --actuarial-corpus artifacts/actuarial-corpus.json \
  --mode partner-api-worker \
  --environment aitrade-prod \
  --worker-ref worker:insurer-partner/underwriting \
  --run-ref worker-run:insurer-partner/underwriting/2026-07-08T06:05:00Z \
  --operation-kind underwriting_quote_delivery \
  --actor-ref oidc:trustai.example/insurer-partner-worker \
  --schedule-ref schedule:insurer-partner/underwriting/5m \
  --cadence-seconds 300 \
  --lease-ref lease:insurer-partner/underwriting/2026-07-08T06:05:00Z \
  --checkpoint-ref checkpoint:insurer-partner/underwriting \
  --checkpoint-hash sha256:insurer-partner-worker-checkpoint \
  --previous-cursor-ref underwriter:quotes/cursor/before \
  --next-cursor-ref underwriter:quotes/cursor/after \
  --queue-ref queue:insurer-partner/delivery \
  --queue-message-ref queue-message:insurer-partner/underwriting/aitrade \
  --destination-ref underwriter:example/api/v1/quotes \
  --delivery-log-ref delivery-log:insurer-partner/underwriter \
  --delivery-log-root sha256:insurer-partner-worker-delivery-root \
  --partner-event-log-ref underwriter:event-log/quote-bindings \
  --partner-event-log-root sha256:insurer-partner-worker-partner-event-root \
  --policy-system-ref policy-system:underwriter/bindings \
  --policy-workflow-ref policy-workflow:underwriter/bindings/aitrade \
  --policy-workflow-hash sha256:insurer-partner-worker-policy-workflow \
  --policy-binding-ref policy-binding:underwriter/aitrade \
  --policy-binding-hash sha256:insurer-partner-worker-policy-binding \
  --workflow-status bound \
  --request-hash sha256:insurer-partner-worker-request \
  --response-status 201 \
  --response-hash sha256:insurer-partner-worker-response \
  --metrics-ref metrics:insurer-partner/workers \
  --audit-log-ref audit-log:insurer-partner/workers \
  --audit-log-root sha256:insurer-partner-worker-audit-root \
  --access-log-ref access-log:insurer-partner/workers \
  --access-log-root sha256:insurer-partner-worker-access-root \
  --credential-ref env:INSURER_PARTNER_WORKER_TOKEN \
  --partner-credential-ref env:UNDERWRITER_WORKER_TOKEN \
  --retention-until 2033-07-08T00:00:00Z \
  --evidence-ref evidence:insurer-partner/worker \
  --started-at 2026-07-08T06:05:00Z \
  --completed-at 2026-07-08T06:06:00Z \
  --next-run-at 2026-07-08T06:10:00Z \
  --now 2026-07-09T00:00:00Z \
  --out artifacts/insurer-partner-worker.json

python -m trustai insurer-partner-worker-verify \
  artifacts/insurer-partner-worker.json \
  artifacts/insurer-partner-service-attestation.json \
  artifacts/insurer-risk-telemetry.json \
  artifacts/underwriting-quote.json \
  --actuarial-product artifacts/actuarial-product.json \
  --actuarial-corpus artifacts/actuarial-corpus.json \
  --now 2026-07-09T00:00:00Z

python -m trustai insurer-partner-worker-append \
  artifacts/insurer-partner-worker.json \
  artifacts/insurer-partner-service-attestation.json \
  artifacts/insurer-risk-telemetry.json \
  artifacts/underwriting-quote.json \
  --actuarial-product artifacts/actuarial-product.json \
  --actuarial-corpus artifacts/actuarial-corpus.json \
  --state .trustai/insurer-partner-worker-demo/evidence-chain.json \
  --tenant insurer-partner-worker-local \
  --out artifacts/insurer-partner-worker-entry.json
```

## Production Boundary

The local receipt proves that a worker run was described, signed, source-bound,
and replay-verifiable. It does not prove live underwriter authority by itself.
Production use still requires credentialed partner API calls, partner-owned
authentication events, policy-system workflow execution, immutable partner-owned
delivery and event logs, production scheduler/lease storage, and operated worker
fleets that emit receipts from real underwriter responses.