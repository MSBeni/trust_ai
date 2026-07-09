# Insurer Partner Service Attestation v0.1

## Purpose

An insurer partner service attestation binds consented insurer risk telemetry and
underwriting quote evidence to the service controls required for a production
insurer portal or underwriting integration. It is the service-hardening layer
around `trustai.insurer-risk-telemetry/0.1`, `trustai.underwriting-quote/0.1`,
and optional actuarial product manifests.

This format closes the local evidence gap between a signed quote receipt and a
credentialed insurer-facing service by recording partner authentication,
policy-system, request-signing, delivery, audit, access-log, data minimization,
and redacted credential evidence.

## Schema

`trustai.insurer-partner-service-attestation/0.1`

Required source artifacts:

- `insurer-risk-telemetry`
- `underwriting-quote`

Optional source artifacts:

- `actuarial-corpus`
- `actuarial-product`
- `frontend-bundle`

The attestation ID is the canonical content hash of the attestation body
excluding `attestation_id` and `signatures`. The signature covers:

```json
{
  "attestation_id": "...",
  "insurer_partner_service": { "... canonical body ..." }
}
```

## Required Controls

An attestation must bind:

- Service identity: service reference, version, service kind, HTTPS endpoint,
  partner HTTPS API endpoint, image reference, image digest, binary hash,
  frontend bundle hash, optional frontend bundle artifact hash, API reference,
  queue reference, policy-system reference,
  replica floor, replica ceiling, and at least two availability zones.
- Partner binding: underwriter name, quote ID, quote reference, quote product,
  partner contract reference, policy-system reference, and optional actuarial
  product ID.
- Risk transfer evidence: telemetry hash, active consent ID, proof pack ID,
  contract ID, gate outcome, risk score, risk tier, quoted premium, discount,
  and coverage limit.
- Security controls: identity provider, partner authentication policy, RBAC,
  consent policy, data minimization, PII redaction, tenant isolation, rate
  limits, request signing, network policy, egress policy, and encryption key.
- Observability controls: audit log root, access log root, delivery log root,
  metrics, alerting, and retention.
- Operation actor: actor reference, TrustAI credential reference, partner
  credential reference, and service evidence references. Credential references
  must be redacted references, not secret values.

## Verification

`trustai insurer-partner-service-verify` verifies:

1. Attestation schema, canonical hash, and signature.
2. Source artifact hashes and source summary, including frontend bundle replay
   when supplied.
3. Underwriting quote signature and telemetry hash binding.
4. Optional actuarial product signature and corpus bindings.
5. HTTPS service and partner endpoints.
6. SHA-256-style service, frontend, audit, access, and delivery roots, and
   supplied bundle digest matches.
7. Active consent on the insurer telemetry.
8. Replica and availability-zone minimums.
9. Redacted credentials and absence of raw secret-like fields.
10. Retention after the attestation timestamp.

## Chain Entry

`trustai insurer-partner-service-append` appends an
`insurer.partner_service_attested` entry containing:

- attestation ID and attestation hash
- mode and environment
- service, partner, and risk-transfer summaries
- source summary
- control list and status summary
- limitations

## Example

```bash
INSURER_PARTNER_BUNDLE_HASH="sha256:$(sha256sum artifacts/insurer-partner.bundle.js | awk '{print $1}')"
python -m trustai insurer-partner-service-attestation \
  artifacts/insurer-risk-telemetry.json \
  artifacts/underwriting-quote.json \
  --actuarial-product artifacts/actuarial-product.json \
  --actuarial-corpus artifacts/actuarial-corpus.json \
  --frontend-bundle artifacts/insurer-partner.bundle.js \
  --environment aitrade-prod \
  --service-kind underwriting-integration \
  --service-ref insurer-partner:trustai/underwriting-prod \
  --service-version 0.1.0 \
  --endpoint-url https://insurer.example/trustai/aitrade \
  --partner-api-endpoint https://underwriter.example/api/v1/quotes \
  --service-image ghcr.io/trustai/insurer-partner:0.1.0 \
  --service-image-digest sha256:trustai-insurer-partner-image \
  --service-binary-hash sha256:trustai-insurer-partner-binary \
  --frontend-bundle-ref bundle:insurer-partner/underwriter-ui \
  --frontend-bundle-hash "$INSURER_PARTNER_BUNDLE_HASH" \
  --api-ref api:insurer-partner/v0 \
  --queue-ref queue:insurer-partner/delivery \
  --policy-system-ref policy-system:underwriter/bindings \
  --partner-contract-ref partner-contract:underwriter/trustai-2026 \
  --auth-provider-ref oidc:insurer-partner/idp \
  --partner-auth-policy-ref policy:insurer-partner/partner-auth-v0.1 \
  --rbac-policy-ref policy:insurer-partner/rbac-v0.1 \
  --consent-policy-ref policy:insurer-partner/consent-v0.1 \
  --data-minimization-policy-ref policy:insurer-partner/data-minimization-v0.1 \
  --pii-redaction-policy-ref policy:insurer-partner/pii-redaction-v0.1 \
  --tenant-isolation-ref tenant-isolation:insurer-partner/aitrade \
  --rate-limit-policy-ref rate-limit:insurer-partner/underwriter \
  --request-signing-ref sigv4:insurer-partner/underwriter \
  --network-policy-ref netpol:insurer-partner/deny-by-default \
  --egress-policy-ref egress:insurer-partner/underwriter-only \
  --encryption-key-ref kms:insurer-partner/customer-data \
  --replicas-min 3 \
  --replicas-max 9 \
  --availability-zone us-east-1a \
  --availability-zone us-east-1b \
  --audit-log-ref audit-log:insurer-partner/service \
  --audit-log-root sha256:insurer-partner-audit-root \
  --access-log-ref access-log:insurer-partner/sessions \
  --access-log-root sha256:insurer-partner-access-root \
  --delivery-log-ref delivery-log:insurer-partner/underwriter \
  --delivery-log-root sha256:insurer-partner-delivery-root \
  --metrics-ref metrics:insurer-partner/service \
  --alert-policy-ref alert:insurer-partner/service \
  --retention-until 2033-07-08T00:00:00Z \
  --actor-ref oidc:trustai.example/insurer-partner-operator \
  --credential-ref env:INSURER_PARTNER_TOKEN \
  --partner-credential-ref env:UNDERWRITER_API_TOKEN \
  --evidence-ref evidence:insurer-partner/service \
  --attested-at 2026-07-08T06:00:00Z \
  --now 2026-07-09T00:00:00Z \
  --out artifacts/insurer-partner-service-attestation.json

python -m trustai insurer-partner-service-verify \
  artifacts/insurer-partner-service-attestation.json \
  artifacts/insurer-risk-telemetry.json \
  artifacts/underwriting-quote.json \
  --actuarial-product artifacts/actuarial-product.json \
  --actuarial-corpus artifacts/actuarial-corpus.json \
  --frontend-bundle artifacts/insurer-partner.bundle.js \
  --now 2026-07-09T00:00:00Z

python -m trustai insurer-partner-service-append \
  artifacts/insurer-partner-service-attestation.json \
  artifacts/insurer-risk-telemetry.json \
  artifacts/underwriting-quote.json \
  --actuarial-product artifacts/actuarial-product.json \
  --actuarial-corpus artifacts/actuarial-corpus.json \
  --frontend-bundle artifacts/insurer-partner.bundle.js \
  --state .trustai/insurer-partner-service-demo/evidence-chain.json \
  --tenant insurer-partner-service-local \
  --out artifacts/insurer-partner-service-entry.json
```

## Production Boundary

This attestation does not prove live underwriter authority by itself. Production
use still requires credentialed partner API calls, partner-owned authentication
events, policy-system workflow IDs, immutable delivery logs, contractual
redistribution limits for actuarial products, and operated worker fleets. The
local reference format records the evidence those systems must emit and makes
the service claims replay-verifiable offline, including replay of supplied frontend bundle artifacts against the attested bundle hash.
