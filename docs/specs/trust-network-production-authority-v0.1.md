# Trust Network Production Authority Dossier v0.1

Status: draft
Schema: `trustai.trust-network-production-authority-dossier/0.1`
Entry type: `trust_network.authority_recorded`

## Purpose

A trust-network production authority dossier binds a verified hosted trust-network service attestation, one or more verified trust-network worker receipts, and optional worker review bundles to explicit external production-authority evidence. It is the bridge between local/reference receipts and a production claim for hosted registry, marketplace, identity-provider, procurement, revocation, callback, settlement, and observability operation.

The dossier records what external authority evidence exists, which required categories are still missing, and whether any evidence is fresh at verification time. Local and network dossiers are allowed, but they do not claim live production authority. A production claim requires `mode` set to `production-dossier` and complete fresh evidence for every required category.

## Modes

- `local-dossier`: local or reference authority evidence only.
- `network-dossier`: signed network evidence is present, but production authority is not fully claimed.
- `production-dossier`: every required production authority category must have fresh acceptable evidence.

## Required Production Authority Categories

The verifier checks the required checklist exactly. Each category can be covered by one or more authority evidence records.

| Requirement ID | Expected authority kinds | Purpose |
| --- | --- | --- |
| `hosted-registry-marketplace-worker-fleet` | `hosted-service`, `provider-api` | Continuously operated hosted registry and marketplace worker fleets. |
| `production-scheduler-lease-storage` | `hosted-service`, `provider-api` | Production scheduler, queue, lease, checkpoint, cursor, entitlement, and subscription storage. |
| `live-identity-provider-event-streams` | `identity-provider`, `provider-api` | Live provider-owned identity-provider session, token, account, and app event streams. |
| `identity-provider-lifecycle-worker-authority` | `identity-provider`, `provider-api`, `hosted-service` | Externally operated lifecycle worker authority beyond local lifecycle receipts. |
| `immutable-account-session-token-logs` | `identity-provider`, `provider-api`, `cloud-object-lock`, `customer` | Immutable provider-owned account, session, token, and propagation logs. |
| `registry-publication-status-propagation` | `hosted-service`, `provider-api`, `customer` | Hosted registry publication, suspension, revocation, and status propagation. |
| `marketplace-entitlement-distribution-exports` | `hosted-service`, `provider-api`, `customer` | Hosted marketplace catalog, entitlement, subscription, and distribution exports. |
| `provider-owned-invoice-payout-tax-custody` | `provider-api`, `customer`, `cloud-object-lock` | Provider-owned invoice, payout, revenue-share, and tax-custody exports. |
| `revocation-cache-invalidation-propagation` | `hosted-service`, `provider-api`, `identity-provider` | Production revocation propagation and cache invalidation evidence. |
| `live-external-provider-callbacks` | `provider-api`, `identity-provider`, `hosted-service` | Live external callbacks for identity, procurement, registry, marketplace, and settlement operations. |
| `hosted-registry-marketplace-observability` | `hosted-service`, `provider-api`, `cloud-object-lock` | Hosted registry, marketplace, worker, access, publication, and audit observability with immutable roots. |

## Dossier Fields

A dossier contains:

- `schema`: `trustai.trust-network-production-authority-dossier/0.1`.
- `mode`, `environment`, `generated_at`, `dossier_ref`, `authority_ref`, and `producer_ref`.
- `service_attestation_binding`: content hash and core service, registry, marketplace, security, observability, and actor references from the service attestation.
- `worker_receipt_bindings`: content hashes and worker, scheduler, propagation, provider-log, registry, marketplace, observability, and credential references from each worker receipt.
- `worker_bundle_bindings`: optional worker review bundle IDs/hashes, embedded source artifact roots, marketplace asset and frontend replay status, settlement replay status, and service/worker linkage.
- `required_production_authority`: the exact requirement list above.
- `authority_evidence`: authority evidence records supplied by the producer, including derived `source_context` bindings to the service, worker, and worker-bundle bindings.
- `summary`: covered, missing, fresh, stale, and missing-freshness counts.
- `controls`: passed, deferred, and failed claim controls.
- `limitations`: non-production and missing-live-authority disclaimers.
- `dossier_id`: canonical hash of the dossier body without signatures.
- `signatures`: one or more signatures over the dossier id and body.

## Authority Evidence Records

Each `authority_evidence` record must contain:

- `requirement_id`: one of the required production authority category ids.
- `authority_kind`: an allowed external authority kind for that category.
- `evidence_ref`: stable external reference such as a provider export id, hosted service audit uri, identity-provider event stream, object-lock root, or customer-owned ledger pointer.
- `evidence_hash`: hash or immutable root for the external evidence.
- `description`: human-readable evidence description.
- `source_context`: derived binding to service attestation id/hash, hosted service refs/endpoints, registry/marketplace refs, security policies, audit roots, worker operation ids/hashes/run refs, scheduler/queue/propagation refs, request/response hashes, provider invoice/payout/tax hashes, worker audit roots, and worker bundle roots recorded in the dossier bindings.

Optional metadata fields are `issuer`, `subject`, `source_uri`, `issued_at`, and `expires_at`. The derived `source_context` is computed by the builder and must not be supplied as a CLI field. Freshness checks use `issued_at` and `expires_at`. Evidence without both timestamps is accepted for non-strict verification but counted as missing freshness.

CLI evidence strings use:

```text
requirement_id,authority_kind,evidence_ref,evidence_hash,description[;issuer=value;subject=value;source_uri=value;issued_at=value;expires_at=value]
```

## Verification Rules

A verifier must:

1. Verify the schema, canonical `dossier_id`, and at least one valid signature.
2. Verify `mode`, `environment`, `dossier_ref`, `authority_ref`, `producer_ref`, and RFC3339 timestamps.
3. Re-verify the bound trust-network service attestation against supplied registry, manifest, vendor identity, identity-provider, procurement, proof-pack, marketplace, distribution, and optional frontend bundle sources.
4. Re-verify every bound trust-network worker receipt against the same service and source receipts plus author-governance and settlement receipts when supplied.
5. Verify each supplied worker review bundle and reject bundles that do not reference the supplied service attestation and worker receipt hashes.
6. Compare the dossier service, worker, and worker-bundle binding content hashes to the supplied source documents.
7. Require every recorded service, worker, and worker-bundle binding field emitted by the v0.1 builder, even when source artifacts are omitted. Omitted sources may produce replay warnings, but they must not permit partial binding summaries.
8. Require the `required_production_authority` checklist to match this specification exactly.
9. Reject evidence with unknown requirement ids, disallowed authority kinds, invalid evidence ids, or `source_context` that does not match the service, worker, and worker-bundle bindings.
10. Reject malformed evidence references, hashes, and timestamp windows.
11. Recompute summary and controls from the signed bindings and authority evidence, then reject mismatches.
12. Count missing, stale, and fresh evidence. With `--require-complete`, every requirement id must be covered. With `--require-fresh`, every covered evidence item must include a valid current freshness window.
13. Reject `production-dossier` mode unless all requirements are covered with fresh evidence.
14. Reject raw secrets in the dossier. Secret-bearing fields must be redacted references such as `env:`, `vault:`, `kms:`, or content hashes.

## CLI Examples

Create a network dossier with partial production authority evidence:

```powershell
python -m trustai trust-network-authority artifacts/trust-network-registry.json --service-attestation artifacts/trust-network-service-attestation.json --worker artifacts/trust-network-worker.json --worker-bundle artifacts/trust-network-worker-bundle.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --frontend-bundle artifacts/trust-network.bundle.js --marketplace-author-governance artifacts/marketplace-author-governance.json --marketplace-settlement artifacts/marketplace-settlement.json --root . --source-now 2026-07-15T00:00:00Z --mode network-dossier --environment aitrade-prod --dossier-ref dossier:trust-network-authority/registry-marketplace-prod --authority-ref authority:trust-network/registry-marketplace-prod --producer-ref oidc:trustai.example/trust-network-authority-worker --authority-evidence "hosted-registry-marketplace-worker-fleet,hosted-service,trust-network:hosted/workers,sha256:5e819547081f43e3a074c4c0516b290624104105d96143bf454e3cc516a4c191,Hosted trust-network worker fleet export;issuer=TrustAI Hosted Ops;subject=aitrade-prod trust-network;source_uri=https://trust-network.example/audit/workers;issued_at=2026-07-14T06:10:00Z;expires_at=2026-07-21T06:10:00Z" --authority-evidence "provider-owned-invoice-payout-tax-custody,provider-api,stripe:reporting/marketplace-settlement-20260714,sha256:da49ed69c29945024103460794b24b49217f34d2afee1f7c5e812e5820f61d59,Provider-owned invoice payout and tax-custody export;issuer=Stripe;subject=aitrade-prod marketplace;source_uri=https://dashboard.stripe.example/reports/marketplace-settlement-20260714;issued_at=2026-07-14T06:12:00Z;expires_at=2026-07-21T06:12:00Z" --generated-at 2026-07-14T06:15:00Z --now 2026-07-15T00:00:00Z --out artifacts/trust-network-authority.json
```

Verify and append the dossier:

```powershell
python -m trustai trust-network-authority-verify artifacts/trust-network-authority.json artifacts/trust-network-registry.json --service-attestation artifacts/trust-network-service-attestation.json --worker artifacts/trust-network-worker.json --worker-bundle artifacts/trust-network-worker-bundle.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --frontend-bundle artifacts/trust-network.bundle.js --marketplace-author-governance artifacts/marketplace-author-governance.json --marketplace-settlement artifacts/marketplace-settlement.json --root . --source-now 2026-07-15T00:00:00Z --now 2026-07-15T00:00:00Z
python -m trustai trust-network-authority-append artifacts/trust-network-authority.json artifacts/trust-network-registry.json --service-attestation artifacts/trust-network-service-attestation.json --worker artifacts/trust-network-worker.json --worker-bundle artifacts/trust-network-worker-bundle.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --frontend-bundle artifacts/trust-network.bundle.js --marketplace-author-governance artifacts/marketplace-author-governance.json --marketplace-settlement artifacts/marketplace-settlement.json --root . --source-now 2026-07-15T00:00:00Z --now 2026-07-15T00:00:00Z --state .trustai/trust-network-authority-demo/evidence-chain.json --tenant trust-network-authority-local --out artifacts/trust-network-authority-entry.json
```

## Production Claim Limits

This specification makes production authority auditable, but it does not manufacture live hosted evidence. A `local-dossier` or `network-dossier` may prove the local receipt graph and document missing authority. A real production claim requires current external evidence from provider-owned services, identity providers, marketplace/payment providers, scheduler and lease stores, immutable log roots, revocation propagation, and live callback systems.