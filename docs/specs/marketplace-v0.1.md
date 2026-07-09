# TrustAI Marketplace Catalog v0.1

The marketplace catalog is a local, verifiable index of certified verification
contract templates and runtime policy packs. It is the reference artifact for
the roadmap's Phase 4 marketplace: reusable templates per vertical and
regulation, potentially third-party authored.

This v0.1 artifact does not claim hosted marketplace distribution, billing,
publisher onboarding, revocation, or external endorsement.

## Schema

`schema`: `trustai.marketplace-catalog/0.1`

Required top-level fields:

- `catalog_id`: canonical hash of the catalog body.
- `generated_at`: creation timestamp.
- `publisher`: catalog publisher.
- `status`: catalog publication status.
- `certification_model`: local certification checks.
- `assets`: contract-template and policy-pack records.
- `aggregate`: counts by type, vertical, and regulation.
- `limitations`: explicit production boundaries.

## Asset Records

Supported asset types:

- `verification_contract_template`
- `policy_pack`

Each asset record includes:

- `asset_id`: hash of asset type, path, and content hash.
- `path`: worktree path to the source artifact.
- `id`, `version`, and `spec_version`: source artifact identifiers.
- `publisher` and `author`: catalog metadata.
- `verticals`: applicable verticals, such as `trading` or `insurance-claims`.
- `regulations`: applicable control or regulatory surfaces, such as `SR 11-7`.
- `risk_class`: source risk class when present.
- `content_hash`: canonical hash of the source artifact.
- `certification`: local schema and hash validation status.

## Verification

`trustai marketplace-verify` checks:

- schema version;
- `catalog_id` canonical hash;
- non-empty asset list;
- supported asset types;
- duplicate asset ids;
- source artifact schema validation;
- source content hashes;
- asset id consistency;
- required vertical and regulation metadata;
- aggregate consistency.

## CLI

```bash
python -m trustai marketplace-export --contract-template examples/aitrade/verification-contract.yaml --policy-pack examples/aitrade/policy-pack.json --vertical trading --regulation "SR 11-7" --regulation "ISO 42001" --out artifacts/marketplace-catalog.json --markdown artifacts/marketplace-catalog.md
python -m trustai marketplace-verify artifacts/marketplace-catalog.json
```

## Production Boundary

A production marketplace still needs:

- publisher identity and signing;
- third-party author workflow;
- listing approval and revocation;
- version compatibility policy;
- hosted distribution and access controls;
- billing or procurement integration;
- independent certification criteria beyond local schema/hash checks.

Use `docs/specs/marketplace-distribution-v0.1.md` for signed, chain-appendable receipts that bind a verified catalog revision to a distribution channel, subscriber, and selected assets.
