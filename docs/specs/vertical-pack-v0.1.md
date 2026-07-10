# TrustAI Vertical Pack v0.1

Status: draft

## Purpose

Vertical packs bind reusable contract templates, policy packs, proof-pack
sources, and industry-specific control mappings for roadmap verticals. They are
the local/reference artifact for Phase 3 vertical packs:

- trading and treasury
- insurance claims
- healthcare revenue-cycle management
- public sector

The artifact is deliberately conservative. It proves local templates and source
bindings, not live regulator, insurer, auditor, healthcare, government, or
customer acceptance.

## Schema

`trustai.vertical-pack/0.1`

## Supported Verticals

- `trading-treasury`: SR 11-7-native trading and treasury evidence.
- `insurance-claims`: NAIC-adjacent claims and insurer workflow evidence.
- `healthcare-rcm`: HIPAA and FDA SaMD-adjacent healthcare RCM evidence.
- `public-sector`: FedRAMP path decision and self-hosted deployment evidence.

## Receipt Fields

- `pack_id`: canonical hash of the pack body excluding `pack_id` and
  `signatures`.
- `pack_ref`: stable pack reference.
- `vertical`: one supported vertical identifier.
- `producer_ref`, `reviewer_ref`: stable producer and optional reviewer
  references.
- `environment`: local or deployment environment label.
- `risk_classes`: risk classes covered by the vertical template.
- `frameworks`: frameworks mapped by the vertical template.
- `source_artifacts`: source paths bound by `sha256:` hash and size.
- `framework_mappings`: deterministic framework mapping references.
- `controls`: local source-binding controls plus a production-claim limit.
- `external_requirements`: live evidence categories required before production
  acceptance.
- `signatures`: one or more signatures over `{pack_id, vertical_pack}`.

## Verification Rules

Verifiers must:

- recompute `pack_id` from the canonical body
- verify at least one signature
- validate generated timestamps and required references
- reject unsupported vertical identifiers
- recompute the expected source-artifact set for the vertical
- reject missing, duplicated, unexpected, or tampered source artifacts
- recompute framework mappings and controls from the vertical definition
- warn when the pack still requires external production evidence

## Evidence Chain Entry

Appending a valid pack writes entry type:

`vertical_pack.published`

The payload records pack identity, vertical, producer/reviewer refs, risk
classes, frameworks, source-artifact count, control summary, and external
requirement count.

## CLI

```powershell
python -m trustai vertical-pack --root . --pack-ref vertical-pack:healthcare-rcm/local --vertical healthcare-rcm --producer-ref oidc:trustai.example/vertical-pack-author --reviewer-ref oidc:auditor.example/vertical-pack-reviewer --out artifacts/healthcare-vertical-pack.json
python -m trustai vertical-pack-verify artifacts/healthcare-vertical-pack.json --root .
python -m trustai vertical-pack-append artifacts/healthcare-vertical-pack.json --root . --state .trustai/vertical-pack-demo/evidence-chain.json --tenant vertical-pack-local --out artifacts/healthcare-vertical-pack-entry.json
```

## Limits

Vertical packs do not prove production deployment, external regulator
acceptance, insurer underwriting acceptance, HIPAA legal posture, FDA
classification, FedRAMP authorization, customer signoff, or live third-party
review. Those remain external evidence requirements.
