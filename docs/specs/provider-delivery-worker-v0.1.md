# Provider Delivery Worker Receipt v0.1

Provider delivery worker receipts bind a single scheduled dispatch worker run to
the signed provider delivery receipt and the provider delivery service
attestation it processed. They narrow the gap between API-ready CI/CD payloads
and production-operated GitHub, GitLab, or Slack dispatch workers. The schema is
`trustai.provider-delivery-worker/0.1`.

## Contents

- `mode`: one of `dispatch-worker`, `hosted-worker`, `scheduled-worker`,
  `local-reference`, or `production-design`.
- `environment` and `recorded_at`: deployment context and worker completion
  time.
- `service`: provider delivery service attestation id/hash, service ref,
  dispatch worker, queue, DLQ, idempotency store, retry policy, provider
  endpoint, rate-limit/request-signing refs, service audit root, and redacted
  provider credential reference.
- `source_delivery`: delivery id/hash, provider, target URL, payload/contract
  hashes, request method/path/body hash, idempotency key, and optional provider
  response status/body hash.
- `worker`: worker identity, run ref, operation kind, actor, timestamps,
  attempt counters, success flag, and optional error ref.
- `scheduler`: cadence, lease, checkpoint, cursor, and next-run metadata.
- `dispatch`: queue/DLQ, destination, idempotency record hash, provider
  request ref, request/response hashes, response status, rate-limit bucket, and
  retry-after metadata.
- `observability`: delivery-log root, optional provider event-log root,
  metrics, worker audit-log root, retention, and evidence refs.
- `provider_response`: optional retained provider response artifact summary,
  including artifact hash, HTTP status, accepted flag, body hash, optional
  redacted header hash, recorded timestamp, and provider request id.
- `provider_audit`: optional provider audit correlation summary, including
  correlation id/hash, provider, audit-log hash/event count, replay flag,
  matched delivery id/hash, match count, and audit event hashes.
- `credential` and `provider_credential`: redacted worker and provider
  credential refs only.
- `source_artifacts`: canonical ids, schemas, and hashes for the service
  attestation, delivery receipt, optional payload with retained delivery payload
  artifact replay through `--payload`, optional provider operations service
  attestation, optional provider response artifact, optional provider audit
  correlation receipt, and optional provider audit log export.
- `controls`: derived status records for source binding, hosted worker mode,
  scheduler/lease/checkpoint continuity, idempotency, request/response binding,
  provider response artifact replay, provider audit correlation replay, log
  roots, credential redaction, and explicit worker outcome.
- `worker_operation_id` and `signatures`: canonical receipt hash and detached
  signatures.

## Verification

`trustai provider-delivery-worker-verify` checks:

1. Schema, canonical `worker_operation_id`, and at least one valid signature.
2. RFC 3339 timestamps, completion after start, and retention after
   `recorded_at`.
3. Worker mode, operation kind, attempts, scheduler cadence, lease/checkpoint,
   and optional cursor timestamps.
4. Service attestation replay against the supplied delivery, payload, retained
   delivery payload artifact path, and optional provider operations service
   evidence.
5. Delivery receipt replay against the supplied payload and retained payload
   artifact when the delivery receipt contains `payload_artifact`.
6. Optional provider response artifact replay against the delivery response and
   worker dispatch response: status, body hash, optional redacted header hash,
   artifact hash, and recorded timestamp.
7. Optional provider audit correlation replay against the delivery receipt and
   optional provider audit-log export: correlation hash, audit-log hash/event
   count, delivery source hash, matched delivery id, and matched provider event
   hashes.
8. Source-artifact hashes and source summaries match supplied artifacts.
9. Queue/DLQ, target URL, idempotency, request/response, delivery-log, provider
   event-log, audit-log, and metric refs are present and hash-shaped where
   required.
10. Success matches response status and `error_ref`.
11. Secret-like fields are redacted references rather than raw provider tokens,
    OAuth secrets, private keys, or webhook credentials.

## CLI

```powershell
python -m trustai provider-delivery-worker artifacts/github-check-run-delivery.json --service-attestation artifacts/provider-delivery-service-attestation.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json --mode dispatch-worker --environment aitrade-prod --worker-ref worker:provider-delivery/github --run-ref worker-run:provider-delivery/github/2026-07-08T05:15:00Z --operation-kind provider_payload_dispatch --actor-ref oidc:trustai.example/provider-delivery-worker --schedule-ref schedule:provider-delivery/github/continuous --cadence-seconds 30 --lease-ref lease:provider-delivery/github/2026-07-08T05:15:00Z --checkpoint-ref checkpoint:provider-delivery/github --checkpoint-hash sha256:provider-delivery-worker-checkpoint --previous-cursor-ref cursor:provider-delivery/github/before --next-cursor-ref cursor:provider-delivery/github/after --next-run-at 2026-07-08T05:15:30Z --queue-ref queue:provider-delivery/github --queue-message-ref queue-message:provider-delivery/github/check-run --dead-letter-queue-ref queue:provider-delivery/github-dlq --destination-ref https://api.github.com/repos/volelabs/trust_ai/check-runs --idempotency-record-hash sha256:provider-delivery-worker-idempotency --provider-request-ref provider-request:github/check-run/2026-07-08T05:15:00Z --request-hash sha256:provider-delivery-worker-request --rate-limit-bucket-ref github:rate-limit/checks --delivery-log-ref delivery-log:provider-delivery/github --delivery-log-root sha256:provider-delivery-worker-delivery-root --provider-event-log-ref github:check-run-events/aitrade --provider-event-log-root sha256:provider-delivery-worker-provider-event-root --metrics-ref metrics:provider-delivery/workers --audit-log-ref audit-log:provider-delivery/workers --audit-log-root sha256:provider-delivery-worker-audit-root --credential-ref env:PROVIDER_DELIVERY_WORKER_TOKEN --provider-credential-ref env:GITHUB_TOKEN --retention-until 2033-07-08T00:00:00Z --evidence-ref evidence:provider-delivery/worker --started-at 2026-07-08T05:15:00Z --completed-at 2026-07-08T05:15:01Z --out artifacts/provider-delivery-worker.json
# Add --provider-response artifacts/provider-response.json when the delivery receipt is http-dispatch or recorded-response and a retained provider response artifact is available.
# Add --provider-audit-correlation artifacts/provider-audit-correlation.json --provider-audit-log artifacts/provider-audit-log.json when a provider-owned audit export has been correlated with the delivery receipt.
python -m trustai provider-delivery-worker-verify artifacts/provider-delivery-worker.json artifacts/github-check-run-delivery.json --service-attestation artifacts/provider-delivery-service-attestation.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json
python -m trustai provider-delivery-worker-append artifacts/provider-delivery-worker.json artifacts/github-check-run-delivery.json --service-attestation artifacts/provider-delivery-service-attestation.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json --state .trustai/provider-delivery-worker-demo/evidence-chain.json --tenant provider-delivery-worker-local --out artifacts/provider-delivery-worker-entry.json
```

## Limits

This receipt proves a worker operation over signed local/reference evidence. It
does not by itself prove a credentialed external provider call unless the source
delivery receipt is `http-dispatch` or `recorded-response` and the worker is
paired with production scheduler, queue, credential custody, provider response,
provider audit correlation/audit-log replay, provider event-log, delivery-log,
and immutable audit-log exports.
