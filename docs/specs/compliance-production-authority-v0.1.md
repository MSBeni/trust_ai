# TrustAI Compliance Production Authority Dossier v0.1

Status: draft

## Purpose

The compliance production authority dossier binds a TrustAI compliance export
and signed EU AI Act technical documentation to the external authority evidence
needed before TrustAI can claim production-ready compliance evidence for
regulated agent deployments.

The dossier is designed for offline review. It stores hashes, references,
freshness windows, framework coverage, control summaries, and source bindings.
It must not store raw GRC, regulator, customer, provider, or credential
payloads.

## Schema

`trustai.compliance-production-authority-dossier/0.1`

## Source Bindings

The dossier binds:

- compliance export schema, hash, proof-pack ID, issue time, required
  framework list, mapped framework count, control count, missing frameworks,
  and chain roots
- EU AI Act document ID, hash, schema, issue time, section IDs, source proof
  pack, and source regulator disclosure
- optional proof-pack ID, hash, spec version, issue time, chain root, and
  entry count for source replay
- optional regulator disclosure ID, hash, schema, issue time, and disclosed
  entry count
- optional EU data-plane attestation ID, hash, mode, environment, regions,
  residency references, and control summary

## Modes

- `local-dossier`: records local/reference source bindings only.
- `provider-dossier`: records signed compliance/EU AI Act artifacts and partial
  production authority evidence without claiming complete production authority.
- `production-dossier`: claims production compliance authority only when all
  production authority requirements are covered with fresh evidence and
  complete source bindings.

## Production Authority Requirements

The fixed checklist is:

- `framework-control-mapping-ontology`
- `iso-42001-evidence-package`
- `nist-ai-rmf-evidence-package`
- `eu-ai-act-technical-documentation`
- `sr-11-7-validation-report`
- `soc2-evidence-export`
- `proof-pack-source-replay`
- `regulator-disclosure-selective-proof`
- `grc-platform-export`
- `eu-data-plane-sovereignty-binding`
- `conformity-assessment-review`

Each evidence item records:

- requirement ID
- authority kind
- evidence reference
- evidence hash, prefixed with `sha256:`
- description
- optional issuer, subject, source URI, issued_at, and expires_at
- builder-derived `source_context` computed from the signed `source_binding`
- canonical evidence ID

## Verification Rules

Verifiers must:

- recompute `dossier_id` from the canonical body
- verify at least one dossier signature
- replay the compliance export against the supplied proof pack when supplied
- verify the EU AI Act technical-documentation source when supplied
- verify the EU data-plane attestation when supplied
- compare source bindings to supplied compliance, EU AI Act, proof-pack,
  disclosure, and EU data-plane artifacts
- reject incomplete source bindings even when raw source artifacts are omitted,
  including missing nested IDs, hashes, framework coverage, section summaries,
  source replay summaries, disclosure summaries, EU residency references, or
  control summaries
- recompute the authority evidence summary
- recompute controls from the dossier body
- reject malformed authority evidence, unsupported authority kinds, missing
  source_context, and source_context values that do not match the signed
  source_binding
- reject raw secret-like values that are not references or hashes
- reject `production-dossier` mode unless all production authority requirements
  are covered, all evidence items are fresh, and compliance export, EU AI Act
  document, proof pack, regulator disclosure, and EU data-plane bindings are
  complete

Strict verification may additionally require complete checklist coverage and
fresh evidence windows.

## Evidence Chain Entry

`compliance.production_authority_recorded`

The chain payload records the dossier ID/hash, mode, environment, producer and
authority references, source binding summary, authority evidence summary,
control summary, and authority evidence metadata including derived source
context.
