# State of Agent Reliability Report v0.1

## Purpose

The State of Agent Reliability report is the signed public-report artifact for TrustAI's GTM commitment to publish aggregate agent reliability benchmarks from anonymized proof-pack and incident evidence. It sits above actuarial corpus and actuarial product manifests: actuarial artifacts model consented data products for underwriters, while this report models public aggregate storytelling and market education.

The schema supports two modes:

- `draft`: local/reference aggregate report, useful for validating computation, privacy thresholds, source bindings, and offline verification.
- `published-evidence`: stricter mode requiring a publication reference/hash and at least one source actuarial product binding.

The report stores aggregate counts, rates, source product hashes, publication references, and source-artifact hashes. It does not store raw customer identifiers, prompts, traces, contracts, claims, payment data, or private proof-pack payloads.

## Schema

Schema ID: `trustai.state-of-agent-reliability-report/0.1`

Required top-level fields:

- `schema`: the schema ID.
- `generated_at`: RFC 3339 timestamp.
- `report_ref`: stable report reference.
- `producer_ref`: identity of the report producer.
- `mode`: `draft` or `published-evidence`.
- `reporting_period`: start/end timestamps and duration days.
- `privacy_thresholds`: minimum contributing organizations per public cohort and direct-identifier policy.
- `source_actuarial_products`: bindings to signed actuarial product manifests.
- `publication`: publication claim, reference, and optional content hash.
- `cohorts`: canonical aggregate cohort records.
- `aggregate`: report-wide aggregate counts and rates.
- `metrics`: derived cohort/source-product summary.
- `source_artifacts`: repository-relative source bindings with `sha256` and `size_bytes`.
- `controls`: verifier-recomputed control statuses.
- `limitations`: explicit draft/publication limits.
- `report_id`: canonical content hash of the unsigned body.
- `signatures`: detached signatures over `{report_id, state_of_agent_reliability_report}`.

Cohort records use:

- `segment_ref`
- `contributing_org_count`
- `agent_count`
- `proof_pack_count`
- `promotion_pass_count`
- `promotion_fail_count`
- `incident_count`
- `total_action_count`
- `source_ref`, optional
- `derived`: gate pass rate in basis points and incident rate per 100k actions

## Verification Rules

Verifiers must reject a report when:

- `report_id` does not match the canonical unsigned body.
- no signature verifies over `{report_id, state_of_agent_reliability_report}`.
- timestamps, period order, required refs, modes, cohorts, or source-product bindings are malformed.
- cohort refs are duplicated or cohort records are non-canonical.
- aggregates or metrics do not match cohorts and source products.
- required source artifacts are missing, unexpected, duplicated, or hash-mismatched.
- controls do not match the verifier-recomputed control set.
- `published-evidence` mode has failed or external-required controls.

`draft` mode must warn that it does not prove public publication, external review, or market acceptance.

## Controls

The control set is:

- `actuarial-source-artifacts-bound`: actuarial corpus/product source and specs are hash-bound.
- `consent-and-proof-pack-source-bound`: consent and proof-pack sources are hash-bound.
- `privacy-thresholds-met`: every public cohort aggregates at least three contributing organizations.
- `aggregate-only-no-direct-identifiers`: report stores aggregate counts, rates, refs, and hashes only.
- `annual-reporting-period`: report has explicit start/end timestamps and at least one cohort.
- `source-actuarial-product-bound`: at least one signed actuarial product binding is present.
- `publication-evidence-bound`: publication ref/hash is present in `published-evidence` mode.
- `roadmap-gtm-source-bound`: roadmap audit and coverage sources are hash-bound.

## Chain Entry

Appending a verified report emits entry type `trustai.reliability_report.published` with:

- report id, hash, ref, mode, and reporting period
- cohort and source product counts
- aggregate incident rate and gate pass rate
- control status summary

## CLI

```powershell
python -m trustai reliability-report --root . --report-ref report:trustai/state-of-agent-reliability/2026 --producer-ref oidc:trustai.example/reliability-research --period-start 2026-01-01T00:00:00Z --period-end 2026-12-31T00:00:00Z --cohort "segment:finserv,3,12,48,42,6,2,125000,actuarial-product:finserv" --actuarial-product artifacts/actuarial-product.json --out artifacts/state-of-agent-reliability-report.json
python -m trustai reliability-report-verify artifacts/state-of-agent-reliability-report.json --root . --actuarial-product artifacts/actuarial-product.json
python -m trustai reliability-report-append artifacts/state-of-agent-reliability-report.json --root . --actuarial-product artifacts/actuarial-product.json --state .trustai/reliability-report-demo/evidence-chain.json --tenant reliability-report-local --out artifacts/state-of-agent-reliability-report-entry.json
```