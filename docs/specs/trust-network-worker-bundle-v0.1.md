# Trust Network Worker Bundle v0.1

Trust-network worker bundles are self-contained offline review artifacts for one
signed trust-network worker receipt and the source evidence needed to replay it.
They package the worker receipt with its hosted trust-network service
attestation, registry receipt, optional registry status, vendor identity,
identity-provider, procurement, proof-pack, marketplace catalog/distribution,
frontend bundle, author-governance, and settlement evidence. The schema is
`trustai.trust-network-worker-bundle/0.1`.

## Contents

- `mode`: one of `offline-review`, `procurement-review`, or `auditor-review`.
- `environment`, `generated_at`, `reviewer_ref`, and `bundle_ref`: review
  context and bundle identity.
- `verification_options`: offline replay settings. The portable bundle uses a
  temp replay root for embedded marketplace assets.
- `source`: compact IDs and hashes for the worker operation, service
  attestation, registry publication, marketplace catalog/distribution,
  settlement, destination, response status, and publication log root.
- `sources`: embedded parsed source objects. Required sources are
  `worker_receipt`, `service_attestation`, and `registry_receipt`; optional
  sources include trust-network manifest, vendor identity, identity provider
  attestation, identity payload, procurement receipt, procurement integration,
  proof packs, registry status, marketplace catalog/distribution,
  marketplace author governance, and marketplace settlement.
- `source_artifacts`: embedded raw source bytes as base64, plus byte SHA-256,
  canonical content hash, expected content hash, media type, size, and artifact
  ID for each embedded source. Frontend bundles are byte-bound by SHA-256.
  Marketplace contract templates and policy packs are also embedded and replayed
  from a temporary root so catalog verification does not require original local
  paths.
- `summary`: source artifact count, artifact hash roots, source object hashes,
  proof-pack count, marketplace asset count, frontend replay status, settlement
  replay status, and worker control summary.
- `controls`: derived bundle controls for offline worker replay, embedded byte
  binding, marketplace asset replay, frontend bundle replay, procurement review,
  and raw-secret scanning.
- `bundle_id` and `signatures`: canonical bundle hash and detached signatures.

## Verification

`trustai trust-network-worker-bundle-verify` checks:

1. Schema, canonical `bundle_id`, and at least one valid signature.
2. Review mode, reviewer ref, and RFC 3339 generation timestamp.
3. Embedded source object shape and required source presence.
4. Full trust-network worker receipt replay using only embedded source objects,
   extracted frontend bundle bytes, and embedded marketplace assets materialized
   into a temporary replay root.
5. Embedded source artifact byte hashes, sizes, content hashes, artifact IDs,
   and one-to-one binding to embedded parsed source objects.
6. Marketplace asset bytes match catalog `content_hash`, asset ID, and asset
   type for contract templates and policy packs.
7. Bundle `source`, `summary`, and `controls` are recomputed from embedded
   sources.
8. Secret-like source fields are redacted references or hash/root/ref metadata;
   structured proof-pack timestamp tokens are allowed.

Tampering with either parsed source objects or embedded source bytes invalidates
the bundle. The verifier does not need the original local source paths.

## CLI

```powershell
python -m trustai trust-network-worker-bundle artifacts/trust-network-worker.json --service-attestation artifacts/trust-network-service-attestation.json artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --frontend-bundle artifacts/trust-network.bundle.js --marketplace-author-governance artifacts/marketplace-author-governance.json --marketplace-settlement artifacts/marketplace-settlement.json --root . --mode procurement-review --environment aitrade-prod --reviewer-ref oidc:buyer.example/procurement-reviewer --generated-at 2026-07-12T04:00:00Z --out artifacts/trust-network-worker-bundle.json --markdown artifacts/trust-network-worker-bundle.md
python -m trustai trust-network-worker-bundle-verify artifacts/trust-network-worker-bundle.json
python -m trustai trust-network-worker-bundle-render artifacts/trust-network-worker-bundle.json --out artifacts/trust-network-worker-bundle.md
python -m trustai trust-network-worker-bundle-extract artifacts/trust-network-worker-bundle.json --out-dir artifacts/trust-network-worker-bundle-sources
python -m trustai trust-network-worker-bundle-append artifacts/trust-network-worker-bundle.json --state .trustai/trust-network-worker-bundle-demo/evidence-chain.json --tenant trust-network-worker-bundle-local --out artifacts/trust-network-worker-bundle-entry.json
```

## Limits

This bundle proves offline replay against embedded registry, procurement,
marketplace, service, and worker evidence. It does not claim live hosted
trust-network callbacks, credentialed marketplace API operations, externally
operated scheduler/lease stores, provider-owned payout/invoice log retrieval, or
production trust-network authority beyond the evidence embedded in the bundle.
