# TrustAI Vendor Trust Network Manifest v0.1

The vendor trust-network manifest is a local, verifiable procurement artifact.
It lets a buyer package vendor proof-pack submissions against a procurement
clause such as: agent vendors must supply TrustAI-format proof packs before
their production or money-touching agents are accepted.

This is the local reference shape for the roadmap's cross-org trust network. It
does not claim a hosted external registry, vendor marketplace, or live
procurement-system integration.
Vendor identity receipts can bind accepted manifest submissions to legal/vendor identity references.

## Schema

`schema`: `trustai.trust-network-manifest/0.1`

Required top-level fields:

- `manifest_id`: canonical hash of the manifest body.
- `generated_at`: creation timestamp.
- `buyer`: buyer or relying-party name.
- `procurement_clause`: clause text and machine-checkable requirements.
- `submissions`: vendor proof-pack summaries and source hashes.
- `network_summary`: accepted/rejected vendor counts plus framework and
  risk-class coverage.
- `limitations`: explicit non-production and non-registry boundaries.

## Procurement Clause

The `procurement_clause` object includes:

- `name`: human-readable clause name.
- `text`: procurement language for vendor contracts.
- `required_gate_outcome`: usually `passed`.
- `required_frameworks`: framework mappings that each proof pack must contain.
- `accepted_risk_classes`: optional risk-class allow list.

If `accepted_risk_classes` is empty, the manifest does not apply a risk-class
allow list. It still records the submitted agent risk classes in
`network_summary`.

## Verification

`trustai trust-network-verify` checks:

- schema version;
- `manifest_id` canonical hash;
- non-empty vendor submissions;
- duplicate source proof-pack ids;
- procurement-clause requirement results;
- accepted/rejected status consistency;
- `network_summary` consistency;
- source proof-pack hash and full offline proof-pack verification when source
  packs are supplied with `--pack`.

A manifest verifies successfully only when every vendor submission satisfies the
procurement clause. Source packs should be supplied for deep verification:

```bash
python -m trustai trust-network-verify artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json
```

## CLI

```bash
python -m trustai trust-network-export artifacts/aitrade-proof-pack.json --vendor aitrade --buyer finserv-buyer --required-framework "ISO 42001" --required-framework "NIST AI RMF" --accepted-risk-class trading-prod-write --out artifacts/trust-network-manifest.json --markdown artifacts/trust-network-manifest.md
python -m trustai trust-network-verify artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json
```

## Production Boundary

This v0.1 artifact proves the local procurement mechanic. A production trust
network still needs:

- external buyer authentication and production vendor identity-provider integration;
- hosted registry and revocation workflow;
- procurement-platform integration;
- cross-org access controls and selective disclosure;
- dispute and appeal process for rejected vendor submissions;
- contractual adoption outside this repository.
