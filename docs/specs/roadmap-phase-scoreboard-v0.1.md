# Roadmap Phase Scoreboard v0.1

## Purpose

The roadmap phase scoreboard records TrustAI phase exit-criteria evidence in a portable, signed JSON artifact. It covers the business and market milestones that code cannot prove by itself: paying partners, signed value, customers, ARR, insurer pricing, regulator acceptance, standards-track progress, procurement adoption, data-product revenue, and generic market usage of proof packs.

The schema supports two modes:

- `readiness`: local/reference evidence that the repository contains evidence surfaces for the phase scoreboard.
- `external-evidence`: redacted external evidence references and hashes for each phase exit criterion.

The scoreboard never stores raw customer contracts, revenue ledgers, regulator correspondence, insurer files, private proof packs, or market-research source bodies. It stores counters, references, hashes, issuers, timestamps, control statuses, and source-artifact hashes.

## Schema

Schema ID: `trustai.roadmap-phase-scoreboard/0.1`

Required top-level fields:

- `schema`: the schema ID.
- `generated_at`: RFC 3339 timestamp.
- `scoreboard_ref`: stable scoreboard reference.
- `producer_ref`: identity of the producer.
- `mode`: `readiness` or `external-evidence`.
- `environment`: environment label.
- `targets`: P1 through P4 phase exit targets from the roadmap.
- `milestones`: canonical external milestone records.
- `metrics`: derived milestone counts and totals.
- `source_artifacts`: repository-relative source bindings with `sha256` and `size_bytes`.
- `controls`: status records for each phase scoreboard control.
- `limitations`: explicit local-proof and business-evidence limits.
- `scoreboard_id`: canonical content hash of the unsigned body.
- `signatures`: detached signatures over `{scoreboard_id, roadmap_phase_scoreboard}`.

Milestone records use:

- `phase`: `P1`, `P2`, `P3`, or `P4`
- `kind`: one of `paying-design-partner`, `signed-pilot-value`, `external-scrutiny-survival`, `customer-count`, `arr`, `vertical-beyond-finserv`, `insurer-integration-live`, `own-soc2-type-ii`, `own-iso-42001`, `series-a`, `regulator-acceptance`, `insurer-pricing`, `standards-track`, `procurement-contract`, `data-product-revenue`, or `generic-market-usage`
- `metric_value`: non-negative integer count or USD value
- `evidence_ref`: external evidence reference
- `evidence_hash`: `sha256:` hash reference for the redacted evidence source
- `issuer`: external or internal authority that issued the evidence reference
- `issued_at`: RFC 3339 timestamp
- `expires_at`: optional RFC 3339 timestamp
- `milestone_id`: canonical content hash of the milestone

## Verification Rules

Verifiers must reject a scoreboard when:

- `scoreboard_id` does not match the canonical unsigned body.
- no signature verifies over `{scoreboard_id, roadmap_phase_scoreboard}`.
- timestamps, modes, phases, milestone kinds, or metric values are malformed.
- milestone ids or evidence refs are duplicated.
- metrics do not match milestone records.
- required source artifacts are missing, unexpected, duplicated, or hash-mismatched.
- controls do not match the verifier-recomputed control set.
- `external-evidence` mode still has any `external-required` control.

`readiness` mode must warn that local evidence does not prove roadmap business milestones or market adoption.

## Controls

The control set is:

- `p1-paying-design-partner-target`: external evidence for at least three paying design partners.
- `p1-signed-pilot-value-target`: external evidence for at least $250k signed pilot value.
- `p1-external-scrutiny-survival-target`: external evidence that at least one proof pack survived external scrutiny.
- `p2-customer-count-target`: external evidence for at least fifteen customers.
- `p2-arr-and-series-a-target`: external evidence for at least $1M ARR and Series A financing.
- `p2-vertical-expansion-target`: external evidence for at least two verticals beyond financial services.
- `p2-insurer-and-own-compliance-target`: external evidence for a live insurer integration plus TrustAI SOC 2 Type II and ISO/IEC 42001.
- `p3-arr-scale-target`: external evidence for at least $8M ARR.
- `p3-regulator-insurer-standards-target`: external evidence for regulator acceptance, two insurers pricing on packs, and standards-track status.
- `p4-network-data-market-target`: external evidence for procurement clauses, data-product revenue, and generic market usage.
- `roadmap-business-source-artifacts-bound`: local/reference source surfaces for those milestones are hash-bound.
- `raw-business-sensitive-data-excluded`: the scoreboard excludes raw business-sensitive evidence bodies.

## Chain Entry

Appending a verified scoreboard emits entry type `trustai.roadmap_phase_scoreboard.attested` with:

- scoreboard id, hash, ref, mode, and environment
- milestone count
- phase counts
- control status summary

## CLI

```powershell
python -m trustai phase-scoreboard --root . --scoreboard-ref scoreboard:trustai/roadmap/2026 --producer-ref oidc:trustai.example/strategy --out artifacts/phase-scoreboard.json
python -m trustai phase-scoreboard-verify artifacts/phase-scoreboard.json --root .
python -m trustai phase-scoreboard-append artifacts/phase-scoreboard.json --root . --state .trustai/phase-scoreboard-demo/evidence-chain.json --tenant phase-scoreboard-local --out artifacts/phase-scoreboard-entry.json
```