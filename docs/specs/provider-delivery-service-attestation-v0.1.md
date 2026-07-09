# Provider Delivery Service Attestation v0.1

Provider delivery service attestations bind signed provider delivery receipts to
the dispatch-worker service that would operate credentialed GitHub, GitLab, or
Slack posting in production. The schema is
`trustai.provider-delivery-service-attestation/0.1`.

## Contents

- `mode`: one of `provider-delivery-attested`, `local-reference`, or
  `production-design`.
- `environment` and `attested_at`: deployment context and signing time.
- `source`: count, hash, schemas, and required source artifact types.
- `service`: service reference, version, provider, image, image digest, binary
  hash, replica bounds, and availability zones.
- `dispatch`: dispatch worker, queue, dead-letter queue, idempotency store,
  retry policy, outbound proxy, provider endpoint, redacted provider credential,
  source delivery id/mode, and source target URL.
- `security`: mTLS, auth, network, egress, rate-limit, and request-signing
  policy references.
- `observability`: audit-log root, metrics, alerting, and retention horizon.
- `operation_actor`: operator identity, redacted operator credential, and
  evidence references.
- `source_artifacts`: canonical ids, schemas, and hashes for the provider
  delivery receipt, optional source payload, and optional provider operations
  service attestation.
- `controls`: derived control statuses for service identity, delivery source
  binding, queue/retry/DLQ, idempotent egress, auth/rate limits, and audit
  retention.
- `attestation_id` and `signatures`: canonical attestation hash and detached
  signatures.

## Verification

`trustai provider-delivery-service-verify` checks:

1. Schema, canonical `attestation_id`, and at least one valid signature.
2. RFC 3339 timestamps and retention after `attested_at`.
3. Service image digest, binary hash, replica floor, replica ceiling, and
   multi-zone evidence.
4. Dispatch queue, DLQ, retry, idempotency, outbound proxy, endpoint, source
   delivery, and redacted provider credential references.
5. Security, observability, audit retention, and actor credential references.
6. Source-artifact hashes and source summary match supplied artifacts.
7. Provider delivery receipt verification, payload replay when supplied, and
   optional provider operations service attestation verification.
8. Secret-like fields are redacted references rather than raw provider API
   tokens, OAuth secrets, or webhook credentials.

## CLI

```powershell
python -m trustai provider-delivery-service-attestation artifacts/github-check-run-delivery.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json --environment aitrade-prod --service-ref provider-delivery:trustai/github-prod --service-version 0.1.0 --service-image ghcr.io/trustai/provider-delivery:0.1.0 --service-image-digest sha256:trustai-provider-delivery-image --service-binary-hash sha256:trustai-provider-delivery-binary --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --dispatch-worker-ref worker:provider-delivery/github --queue-ref queue:provider-delivery/github --dead-letter-queue-ref queue:provider-delivery/github-dlq --idempotency-store-ref redis:provider-delivery/idempotency --retry-policy-ref retry:provider-delivery/exponential-v0.1 --outbound-proxy-ref egress-proxy:provider-delivery --provider-endpoint-base https://api.github.com --provider-credential-ref env:GITHUB_TOKEN --mtls-policy-ref policy:provider-delivery/mtls-required-v0.1 --auth-policy-ref policy:provider-delivery/oidc-authz-v0.1 --network-policy-ref netpol:provider-delivery/deny-by-default --egress-policy-ref egress:provider-delivery/provider-apis-only --rate-limit-policy-ref rate-limit:provider-delivery/github --request-signing-policy-ref policy:provider-delivery/request-signing-v0.1 --audit-log-ref audit-log:provider-delivery/service --audit-log-root sha256:provider-delivery-service-audit-root --metrics-ref metrics:provider-delivery/service --alert-policy-ref alert:provider-delivery/service --retention-until 2033-07-08T00:00:00Z --actor-ref oidc:trustai.example/provider-delivery-operator --credential-ref env:PROVIDER_DELIVERY_TOKEN --evidence-ref evidence:provider-delivery/service --attested-at 2026-07-08T05:10:00Z --out artifacts/provider-delivery-service-attestation.json
python -m trustai provider-delivery-service-verify artifacts/provider-delivery-service-attestation.json --delivery artifacts/github-check-run-delivery.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json
python -m trustai provider-delivery-service-append artifacts/provider-delivery-service-attestation.json --delivery artifacts/github-check-run-delivery.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json --state .trustai/provider-delivery-service-demo/evidence-chain.json --tenant provider-delivery-service-local --out artifacts/provider-delivery-service-entry.json
```

## Limits

This attestation strengthens the existing provider delivery receipt with service
fleet, queue, retry, DLQ, idempotency, egress, audit, metrics, actor, and
redacted credential controls. It does not claim a successful credentialed
external provider post unless the source delivery receipt is `http-dispatch` or
otherwise includes a recorded provider response.
