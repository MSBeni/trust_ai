# Marketplace Distribution Receipt v0.1

Marketplace distribution receipts bind a verified TrustAI marketplace catalog to
a specific publication, channel, subscriber, and selected set of certified
assets. They provide local, chain-appendable evidence for the roadmap's
certified template and policy-pack marketplace.

## Schema

`schema`: `trustai.marketplace-distribution/0.1`

Top-level fields:

- `distribution_id`: canonical hash of the distribution body.
- `distributed_at`: publication or delivery timestamp.
- `distribution_ref`: stable local publication reference.
- `mode`: `local-reference` or `recorded-publication`.
- `channel`: channel type, target, and production replacement boundary.
- `subscriber`: receiving organization, optional subject reference, and
  distribution purpose.
- `catalog`: source catalog id, hash, schema, publisher, status, asset count,
  and aggregate summary.
- `assets`: selected catalog assets with ids, versions, hashes, verticals,
  regulations, and certification metadata.
- `terms`: local redistribution, revocation, and billing terms.
- `limitations`: non-production boundaries.
- `signatures`: detached local signature over `distribution_id` and body.

## Verification

`marketplace-distribution-verify` checks:

- distribution schema, canonical id, and signature.
- channel and subscriber metadata.
- distributed asset uniqueness and supported asset types.
- catalog hash, catalog id, aggregate summary, and selected asset bindings when
  the source catalog is supplied.
- source catalog validity against the worktree using the marketplace catalog
  verifier.

If the source catalog is omitted, the verifier checks the signed receipt binding
and emits a warning that source artifacts were not supplied.

## Chain Evidence

`marketplace-distribution-append` emits a
`marketplace.distribution.published` entry containing:

- distribution id and distribution hash.
- channel and subscriber metadata.
- source catalog binding.
- distributed asset bindings.
- local terms and limitations.

This gives buyers, auditors, and marketplace operators a tamper-evident record
that certified contract templates or policy packs were distributed from a
specific catalog revision.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai marketplace-distribution artifacts/marketplace-catalog.json --channel marketplace-api --target https://marketplace.example/catalogs/trustai --subscriber finserv-buyer --subscriber-ref oidc:buyer.example/procurement --distributed-at 2026-07-12T00:00:00Z --out artifacts/marketplace-distribution.json
python -m trustai marketplace-distribution-verify artifacts/marketplace-distribution.json --catalog artifacts/marketplace-catalog.json
python -m trustai marketplace-distribution-append artifacts/marketplace-distribution.json --catalog artifacts/marketplace-catalog.json --state .trustai/marketplace-demo/evidence-chain.json --tenant marketplace-local --out artifacts/marketplace-distribution-entry.json
```

Production marketplace distribution still needs hosted publication records,
subscriber authentication, and live revocation state. Third-party author
governance is covered by
`docs/specs/marketplace-author-governance-v0.1.md`; entitlement, billing,
payout, and tax-custody settlement evidence is covered by
`docs/specs/marketplace-settlement-v0.1.md`.

