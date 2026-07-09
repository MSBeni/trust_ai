# Trust Network Service Attestation v0.1

## Purpose

A trust-network service attestation binds signed cross-org trust-network
registry, registry status, marketplace catalog, and marketplace distribution
evidence to the hosted service controls required for production trust-network
and marketplace operation.

It is the service-hardening layer around:

- `trustai.trust-network-registry/0.1`
- `trustai.trust-network-registry-status/0.1`
- `trustai.marketplace-catalog/0.1`
- `trustai.marketplace-distribution/0.1`

The format records hosted identity federation, buyer/vendor/subscriber
authorization, procurement sync, marketplace entitlements, catalog review,
revocation propagation, publication logs, audit roots, and redacted credential
references. It gives buyers, auditors, and marketplace subscribers an offline
verifiable bridge between local registry/catalog receipts and the operated
service those receipts must feed.

## Schema

`trustai.trust-network-service-attestation/0.1`

Required source artifacts for the default `registry-marketplace` service kind:

- `trust-network-registry`
- `marketplace-catalog`
- `marketplace-distribution`

Optional source artifacts:

- `trust-network-registry-status`
- `frontend-bundle`

The registry receipt may itself replay deeper sources:

- trust-network manifest
- vendor identity receipt
- identity-provider attestation and source identity payload
- procurement clause receipt
- procurement integration receipt
- proof packs

The attestation ID is the canonical content hash of the attestation body
excluding `attestation_id` and `signatures`. The signature covers:

```json
{
  "attestation_id": "...",
  "trust_network_service": { "... canonical body ..." }
}
```

## Required Controls

An attestation must bind:

- Service identity: service reference, version, service kind, HTTPS registry
  endpoint, HTTPS marketplace endpoint, image reference, image digest, binary
  hash, frontend bundle hash, optional frontend bundle artifact hash, API reference, registry store, search index,
  entitlement store, subscription queue, replica floor, replica ceiling, and at
  least two availability zones.
- Registry binding: registration ID, registration hash, registration reference,
  registration status, effective status, registry namespace, vendor subject,
  identity-provider reference, trust-network manifest ID, buyer, and optional
  status-change receipt.
- Marketplace binding: catalog ID and hash, asset IDs, distribution ID and hash,
  channel, target, subscriber, subscriber reference, and selected asset count.
- Security controls: identity provider, vendor auth, buyer auth, subscriber
  auth, RBAC, identity federation, procurement sync, entitlements, catalog
  review, revocation, cache invalidation, tenant isolation, rate limits, request
  signing, network policy, egress policy, and encryption key.
- Observability controls: registry audit root, marketplace audit root, access
  log root, publication log root, metrics, alerting, and retention.
- Operation actor: actor reference, TrustAI credential reference, marketplace
  credential reference, and service evidence references. Credential references
  must be redacted references, not secret values.

## Verification

`trustai trust-network-service-verify` checks:

1. Attestation schema, canonical hash, and signature.
2. Source artifact hashes, source summary, and supplied frontend bundle replay when provided.
3. Trust-network registry receipt signature and deep source bindings when
   source artifacts are supplied.
4. Optional registry status-change receipt signature and target binding.
5. Marketplace catalog hashes, asset schemas, asset IDs, and aggregate summary.
6. Marketplace distribution signature, catalog binding, selected assets,
   subscriber, and channel.
7. HTTPS registry and marketplace endpoints.
8. SHA-256-style service, frontend, supplied frontend bundle digest, audit, access, publication, catalog, and
   distribution roots/hashes.
9. Replica and availability-zone minimums.
10. Redacted credentials and absence of raw secret-like fields.
11. Retention after the attestation timestamp.

## Chain Entry

`trustai trust-network-service-append` appends a
`trust_network.service_attested` entry containing:

- attestation ID and attestation hash
- mode and environment
- service, registry, and marketplace summaries
- source summary
- control list and status summary
- limitations

## Example

```bash
TRUST_NETWORK_BUNDLE_HASH="sha256:$(sha256sum artifacts/trust-network.bundle.js | awk '{print $1}')"
python -m trustai trust-network-service-attestation \
  artifacts/trust-network-registry.json \
  --manifest artifacts/trust-network-manifest.json \
  --vendor-identity artifacts/vendor-identity-receipt.json \
  --identity-attestation artifacts/identity-provider-attestation.json \
  --identity-payload examples/aitrade/identity-inventory.json \
  --procurement-receipt artifacts/procurement-clause-receipt.json \
  --procurement-integration artifacts/procurement-integration-receipt.json \
  --pack artifacts/aitrade-proof-pack.json \
  --registry-status artifacts/trust-network-registry-status.json \
  --marketplace-catalog artifacts/marketplace-catalog.json \
  --marketplace-distribution artifacts/marketplace-distribution.json \
  --frontend-bundle artifacts/trust-network.bundle.js \
  --root . \
  --environment aitrade-prod \
  --service-kind registry-marketplace \
  --service-ref trust-network:trustai/hosted-prod \
  --service-version 0.1.0 \
  --registry-endpoint https://registry.example \
  --marketplace-endpoint https://marketplace.example/catalogs/trustai \
  --service-image ghcr.io/trustai/trust-network-service:0.1.0 \
  --service-image-digest sha256:trustai-trust-network-service-image \
  --service-binary-hash sha256:trustai-trust-network-service-binary \
  --frontend-bundle-ref bundle:trust-network/portal \
  --frontend-bundle-hash "$TRUST_NETWORK_BUNDLE_HASH" \
  --api-ref api:trust-network/v0 \
  --registry-store-ref postgres:trustai/trust-network-registry \
  --search-index-ref opensearch:trustai/trust-network-marketplace \
  --entitlement-store-ref postgres:trustai/marketplace-entitlements \
  --subscription-queue-ref queue:trust-network/subscriptions \
  --auth-provider-ref oidc:trust-network/idp \
  --vendor-auth-policy-ref policy:trust-network/vendor-auth-v0.1 \
  --buyer-auth-policy-ref policy:trust-network/buyer-auth-v0.1 \
  --subscriber-auth-policy-ref policy:trust-network/subscriber-auth-v0.1 \
  --rbac-policy-ref policy:trust-network/rbac-v0.1 \
  --identity-federation-policy-ref policy:trust-network/identity-federation-v0.1 \
  --procurement-sync-policy-ref policy:trust-network/procurement-sync-v0.1 \
  --entitlement-policy-ref policy:trust-network/entitlements-v0.1 \
  --catalog-review-policy-ref policy:trust-network/catalog-review-v0.1 \
  --revocation-policy-ref policy:trust-network/revocation-v0.1 \
  --cache-invalidation-policy-ref policy:trust-network/cache-invalidation-v0.1 \
  --tenant-isolation-ref tenant-isolation:trust-network/finserv-buyer \
  --rate-limit-policy-ref rate-limit:trust-network/tenant \
  --request-signing-ref sigv4:trust-network/service \
  --network-policy-ref netpol:trust-network/deny-by-default \
  --egress-policy-ref egress:trust-network/idp-procurement-marketplace-only \
  --encryption-key-ref kms:trust-network/customer-data \
  --replicas-min 3 \
  --replicas-max 9 \
  --availability-zone us-east-1a \
  --availability-zone us-east-1b \
  --registry-audit-log-ref audit-log:trust-network/registry \
  --registry-audit-log-root sha256:trust-network-registry-audit-root \
  --marketplace-audit-log-ref audit-log:trust-network/marketplace \
  --marketplace-audit-log-root sha256:trust-network-marketplace-audit-root \
  --access-log-ref access-log:trust-network/sessions \
  --access-log-root sha256:trust-network-access-root \
  --publication-log-ref publication-log:trust-network/registry-marketplace \
  --publication-log-root sha256:trust-network-publication-root \
  --metrics-ref metrics:trust-network/service \
  --alert-policy-ref alert:trust-network/service \
  --retention-until 2033-07-14T00:00:00Z \
  --actor-ref oidc:trustai.example/trust-network-operator \
  --credential-ref env:TRUST_NETWORK_SERVICE_TOKEN \
  --marketplace-credential-ref env:MARKETPLACE_API_TOKEN \
  --evidence-ref evidence:trust-network/service \
  --attested-at 2026-07-14T06:00:00Z \
  --now 2026-07-15T00:00:00Z \
  --out artifacts/trust-network-service-attestation.json

python -m trustai trust-network-service-verify \
  artifacts/trust-network-service-attestation.json \
  artifacts/trust-network-registry.json \
  --manifest artifacts/trust-network-manifest.json \
  --vendor-identity artifacts/vendor-identity-receipt.json \
  --identity-attestation artifacts/identity-provider-attestation.json \
  --identity-payload examples/aitrade/identity-inventory.json \
  --procurement-receipt artifacts/procurement-clause-receipt.json \
  --procurement-integration artifacts/procurement-integration-receipt.json \
  --pack artifacts/aitrade-proof-pack.json \
  --registry-status artifacts/trust-network-registry-status.json \
  --marketplace-catalog artifacts/marketplace-catalog.json \
  --marketplace-distribution artifacts/marketplace-distribution.json \
  --frontend-bundle artifacts/trust-network.bundle.js \
  --root . \
  --now 2026-07-15T00:00:00Z

python -m trustai trust-network-service-append \
  artifacts/trust-network-service-attestation.json \
  artifacts/trust-network-registry.json \
  --manifest artifacts/trust-network-manifest.json \
  --vendor-identity artifacts/vendor-identity-receipt.json \
  --identity-attestation artifacts/identity-provider-attestation.json \
  --identity-payload examples/aitrade/identity-inventory.json \
  --procurement-receipt artifacts/procurement-clause-receipt.json \
  --procurement-integration artifacts/procurement-integration-receipt.json \
  --pack artifacts/aitrade-proof-pack.json \
  --registry-status artifacts/trust-network-registry-status.json \
  --marketplace-catalog artifacts/marketplace-catalog.json \
  --marketplace-distribution artifacts/marketplace-distribution.json \
  --frontend-bundle artifacts/trust-network.bundle.js \
  --state .trustai/trust-network-service-demo/evidence-chain.json \
  --tenant trust-network-service-local \
  --out artifacts/trust-network-service-entry.json
```

## Production Boundary

This attestation does not prove live hosted trust-network authority by itself.
Production use still requires operated identity-provider sessions, vendor and
buyer account lifecycle events, immutable registry propagation logs, marketplace
entitlement logs, subscriber authentication, revocation propagation, billing or
third-party author governance when applicable, and worker fleets that emit
signed receipts from live hosted operations. Supplying `--frontend-bundle` replays local frontend bundle bytes against the recorded service hash; production UI claims still require hosted identity sessions and immutable access logs.
