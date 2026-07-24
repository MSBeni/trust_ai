# Design-Partner Pilot Dossier v0.1

## Purpose

A design-partner pilot dossier records TrustAI Phase 1 exit-criteria evidence in a portable, signed JSON artifact. It binds local/reference implementation evidence to the roadmap goals for design-partner pilots while separating repository readiness from real business milestones.

The schema supports two modes:

- `readiness`: local/reference evidence that the promotion-gate, proof-pack, MCP gateway, shadow replay, CI/CD, auditor portal, and BYOC sources exist and are hash-bound.
- `external-evidence`: customer-owned evidence references and hashes for paid pilots, signed value, payment records, and external scrutiny survival.

The dossier never stores raw customer contracts, payment records, private proof packs, or customer data. It stores references, hashes, status values, counters, and source-artifact hashes so redacted business evidence can be replay-bound without exposing the underlying private documents.

## Schema

Schema ID: `trustai.design-partner-pilot/0.1`

Required top-level fields:

- `schema`: the schema ID.
- `generated_at`: RFC 3339 timestamp.
- `dossier_ref`: stable dossier reference.
- `producer_ref`: identity of the producer.
- `mode`: `readiness` or `external-evidence`.
- `environment`: environment label.
- `targets`: Phase 1 targets: 3 paying design partners, $250k signed pilot value, and at least one external scrutiny survival event.
- `partners`: canonical partner records.
- `external_scrutiny_events`: canonical third-party or model-risk review records.
- `metrics`: derived partner counts, signed value, hash-bound value, scrutiny counts, and evidence-bound scrutiny counts.
- `source_artifacts`: repository-relative source bindings with `sha256` and `size_bytes`.
- `controls`: status records for each exit-criteria control.
- `limitations`: explicit production and business-evidence limits.
- `dossier_id`: canonical content hash of the unsigned body.
- `signatures`: detached signatures over `{dossier_id, design_partner_pilot}`.

Partner records use:

- `partner_ref`
- `industry`
- `agent_ref`
- `pilot_value_usd`
- `contract_status`: `planned`, `negotiating`, `signed`, or `active`
- `contract_evidence_ref` and `contract_evidence_hash`, required for signed-value controls in `external-evidence` mode
- `payment_evidence_ref` and `payment_evidence_hash`, required for paying-partner controls in `external-evidence` mode

Scrutiny records use:

- `scrutiny_ref`
- `party_type`: `auditor`, `regulator`, `insurer`, `procurement`, `internal-audit`, or `model-risk`
- `party_ref`
- `partner_ref`
- `outcome`: `planned`, `submitted`, `survived`, `accepted`, or `rejected`
- `evidence_ref` and `evidence_hash`, required for scrutiny-survival controls in `external-evidence` mode

## Verification Rules

Verifiers must reject a dossier when:

- `dossier_id` does not match the canonical unsigned body.
- no signature verifies over `{dossier_id, design_partner_pilot}`.
- timestamps, modes, partner records, or scrutiny records are malformed.
- partner or scrutiny references are duplicated.
- scrutiny events reference an unknown partner.
- evidence hashes are malformed or metrics do not match partner and scrutiny records.
- required source artifacts are missing, unexpected, duplicated, or hash-mismatched.
- controls do not match the verifier-recomputed control set.
- `external-evidence` mode still has any `external-required` control.

`readiness` mode must warn that local evidence does not prove paying partners, signed value, or external scrutiny survival.

## Controls

The control set is:

- `pilot-partner-count-target`: at least three design partners are listed.
- `signed-value-target`: in `external-evidence` mode, signed/active partner values total at least $250k and each partner has hash-bound contract and payment evidence refs.
- `external-scrutiny-survival-target`: in `external-evidence` mode, at least one survived/accepted scrutiny event has a hash-bound review evidence ref.
- `promotion-gate-source-bound`: promotion-gate and verification-contract sources are hash-bound.
- `proof-pack-source-bound`: proof-pack compiler and spec are hash-bound.
- `mcp-shadow-cicd-source-bound`: MCP gateway, shadow replay, and CI/CD sources are hash-bound.
- `auditor-byoc-source-bound`: review portal and BYOC authority sources are hash-bound.
- `raw-customer-data-excluded`: the dossier excludes raw customer data, payment records, and private contracts.

## Chain Entry

Appending a verified dossier emits entry type `design_partner.pilot_dossier.attested` with:

- dossier id, hash, ref, mode, and environment
- partner counts, signed pilot value, and hash-bound signed value
- external scrutiny survival count and hash-bound scrutiny survival count
- source artifact count
- control status summary

## CLI

```powershell
python -m trustai design-partner-dossier --root . --dossier-ref dossier:design-partner/phase1-readiness --producer-ref oidc:trustai.example/gtm-ops --partner "partner:bank-a,finserv,agent:payments-risk,60000,negotiating" --partner "partner:insurer-b,insurance,agent:claims-triage,90000,negotiating" --partner "partner:fintech-c,fintech,agent:treasury-ops,100000,negotiating" --scrutiny "scrutiny:model-risk-a,model-risk,team:model-risk,partner:bank-a,submitted" --out artifacts/design-partner-dossier.json
python -m trustai design-partner-dossier --root . --mode external-evidence --dossier-ref dossier:design-partner/phase1-external --producer-ref oidc:trustai.example/gtm-ops --partner "partner:bank-a,finserv,agent:payments-risk,90000,signed,contract:bank-a/MSA-2026,sha256:1111111111111111111111111111111111111111111111111111111111111111,payment:bank-a/pilot-invoice-2026,sha256:2222222222222222222222222222222222222222222222222222222222222222" --partner "partner:insurer-b,insurance,agent:claims-triage,80000,active,contract:insurer-b/pilot-2026,sha256:3333333333333333333333333333333333333333333333333333333333333333,payment:insurer-b/pilot-invoice-2026,sha256:4444444444444444444444444444444444444444444444444444444444444444" --partner "partner:fintech-c,fintech,agent:treasury-ops,90000,signed,contract:fintech-c/SOW-2026,sha256:5555555555555555555555555555555555555555555555555555555555555555,payment:fintech-c/pilot-invoice-2026,sha256:6666666666666666666666666666666666666666666666666666666666666666" --scrutiny "scrutiny:auditor-a,auditor,auditor:example,partner:bank-a,survived,review:auditor-a/proof-pack-accepted,sha256:7777777777777777777777777777777777777777777777777777777777777777" --out artifacts/design-partner-dossier.json
python -m trustai design-partner-dossier-verify artifacts/design-partner-dossier.json --root .
python -m trustai design-partner-dossier-append artifacts/design-partner-dossier.json --root . --state .trustai/design-partner-demo/evidence-chain.json --tenant design-partner-local --out artifacts/design-partner-dossier-entry.json
```
