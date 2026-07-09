# Policy Backend Service Attestation v0.1

This document defines the signed TrustAI attestation for production OPA/Cedar
policy backend service hardening.

The policy backend enforcement receipt proves that a specific backend endpoint
returned a response that matches a recorded TrustAI policy decision. The service
attestation sits above that receipt and binds the operated backend fleet to the
receipt: service image digest, backend endpoint, policy bundle hash, mTLS and
authorization policy, tenant isolation, policy sync, rate limits, circuit
breakers, cache store, network policy, decision logs, audit roots, actor, and
redacted credential evidence.

## Schema

`schema`: `trustai.policy-backend-service-attestation/0.1`

Required top-level fields:

- `attestation_id`: canonical hash of the attestation body excluding signatures.
- `signatures`: one or more detached signatures over the attestation id and body.
- `mode`: one of `local-reference`, `backend-service-attested`, or `production-design`.
- `environment`: deployment environment label.
- `attested_at`: RFC3339 timestamp.
- `source`: replayable hash binding to the policy backend enforcement receipt and optional policy engine receipt.
- `enforcement`: normalized backend enforcement receipt summary.
- `service`: OPA/Cedar service identity, endpoint, image, binary, bundle, replica, and availability-zone evidence.
- `security`: mTLS, authorization, tenant isolation, policy sync, admission, rate limit, circuit breaker, cache, network, and egress controls.
- `operation`: decision log root/retention, actor, redacted credential, and evidence references.
- `audit_log`: immutable audit-log root and retention horizon.
- `source_artifacts`: source hashes for enforcement receipt, policy export, and policy engine receipt when supplied.
- `controls`: service-attested control summary.

## Verification

`trustai policy-backend-service-verify` checks:

- canonical `attestation_id` and signature validity;
- supported schema and mode;
- RFC3339 attestation/audit-retention timestamps, with retention after attestation;
- service engine is `opa` or `cedar`;
- service endpoint is HTTPS;
- service image digest, service binary hash, bundle hash, decision-log root, and audit-log root are sha256 references;
- replica minimum is at least two and no greater than replica maximum;
- at least two availability zones are declared;
- all mTLS/authn/z, tenant isolation, policy sync, admission, rate limit, circuit breaker, cache, network, and egress references are present;
- operation credentials are redacted references and no secret-like field contains raw secret material;
- source records and source artifact hashes match supplied source artifacts;
- supplied policy backend enforcement receipts deep-verify against the policy pack, runtime action, proof pack, policy decision, policy export, and policy engine receipt;
- service engine, backend ref, endpoint, bundle ref, and bundle hash match the enforcement receipt backend.

Warnings are emitted when source artifacts are omitted or when the mode does not
claim `backend-service-attested` production operation.

## Chain Entry

`trustai policy-backend-service-append` verifies the attestation and appends a
`policy_backend.service_attested` evidence-chain entry containing the attestation
id/hash, source binding, enforcement summary, service hardening evidence,
security controls, operation/audit evidence, and control summary.

## CLI Example

```powershell
$env:PYTHONPATH = "src"
python -m trustai policy-engine-receipt examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --engine opa --out artifacts/policy-engine-receipt.json
python -m trustai policy-backend-enforcement examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --backend-ref opa:trustai-runtime:prod --engine opa --endpoint-url https://opa.example/v1/data/trustai/runtime/allow --credential-ref env:OPA_BACKEND_TOKEN --request-hash sha256:policy-backend-request --response-status 200 --response-hash sha256:policy-backend-response --actor-ref oidc:trustai.example/runtime-policy --mode hosted-backend --enforced-at 2026-07-04T02:00:01Z --out artifacts/policy-backend-enforcement.json
python -m trustai policy-backend-service-attestation artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --environment aitrade-prod --service-ref policy-backend:trustai/opa-prod --service-version 0.1.0 --engine opa --backend-ref opa:trustai-runtime:prod --endpoint-url https://opa.example/v1/data/trustai/runtime/allow --service-image ghcr.io/trustai/policy-backend:0.1.0 --service-image-digest sha256:trustai-policy-backend-image --service-binary-hash sha256:trustai-policy-backend-binary --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --mtls-policy-ref policy:policy-backend/mtls-required-v0.1 --auth-policy-ref policy:policy-backend/oidc-authz-v0.1 --tenant-isolation-ref tenant-isolation:aitrade/policy-backend --policy-sync-ref policy-sync:trustai/runtime-policy-bundle --admission-policy-ref admission:policy-backend/signed-bundles-only --rate-limit-policy-ref rate-limit:policy-backend/aitrade --circuit-breaker-ref circuit-breaker:policy-backend/opa --cache-store-ref redis:policy-backend/decision-cache --network-policy-ref netpol:policy-backend/deny-by-default --egress-policy-ref egress:policy-backend/kms-tsa-only --decision-log-ref decision-log:policy-backend/opa --decision-log-root sha256:policy-backend-decision-log-root --decision-log-retention-days 2555 --audit-log-ref audit-log:policy-backend/service --audit-log-root sha256:policy-backend-service-audit-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/policy-backend-operator --credential-ref env:POLICY_BACKEND_SERVICE_TOKEN --evidence-ref evidence:policy-backend/service --attested-at 2026-07-04T04:02:00Z --out artifacts/policy-backend-service-attestation.json
python -m trustai policy-backend-service-verify artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json
python -m trustai policy-backend-service-append artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --state .trustai/policy-backend-service-demo/evidence-chain.json --tenant policy-backend-service-local --out artifacts/policy-backend-service-entry.json
python -m trustai chain-verify --state .trustai/policy-backend-service-demo/evidence-chain.json --tenant policy-backend-service-local
```

## Production Notes

This attestation does not replace live cloud operations. It records the evidence
that a live OPA/Cedar policy backend fleet must expose for offline verification.
Production deployments should use customer-controlled KMS/HSM signing, WORM
retention for decision logs, independent timestamping, signed policy bundles,
service-mesh mTLS, tenant-isolated policy stores, and continuously appended
runtime enforcement receipts.