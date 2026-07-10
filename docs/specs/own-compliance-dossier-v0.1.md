# TrustAI Own Compliance Dossier v0.1

## Purpose

The TrustAI own compliance dossier records the roadmap requirement that TrustAI must become its own best proof-pack customer: SOC 2 Type II and ISO/IEC 42001 for the company itself. It separates local evidence-production readiness from external certification claims.

The schema supports two modes:

- `readiness`: local/reference proof that TrustAI has source-bound machinery for proof packs, framework mapping, standards packaging, evidence retention, trust authority, and roadmap audits.
- `external-certification`: a stricter mode that requires external SOC 2 Type II and ISO/IEC 42001 evidence references and hashes.

The dossier stores references, hashes, framework targets, source artifact hashes, and control summaries. It does not store raw audit reports, customer data, secrets, or compliance workpapers.

## Schema

Schema ID: `trustai.own-compliance-dossier/0.1`

Required top-level fields:

- `schema`: the schema ID.
- `generated_at`: RFC 3339 timestamp.
- `dossier_ref`: stable dossier reference.
- `producer_ref`: identity of the producer.
- `scope_ref`: scoped TrustAI organization/system boundary reference.
- `mode`: `readiness` or `external-certification`.
- `environment`: environment label.
- `framework_targets`: SOC 2 Type II and ISO/IEC 42001 target records.
- `certification_evidence`: canonical external evidence references.
- `metrics`: derived evidence and source-artifact counts.
- `source_artifacts`: repository-relative source bindings with `sha256` and `size_bytes`.
- `controls`: verifier-recomputed control statuses.
- `limitations`: explicit limits for local readiness and external certification claims.
- `dossier_id`: canonical content hash of the unsigned body.
- `signatures`: detached signatures over `{dossier_id, own_compliance_dossier}`.

Certification evidence records use:

- `kind`: `soc2-type-ii-report`, `iso-42001-certificate`, `management-system-scope`, `auditor-bridge-letter`, or `internal-audit-review`.
- `evidence_ref`: stable external reference.
- `evidence_hash`: `sha256:` hash reference.
- `issuer`: external issuer or reviewer.
- `issued_at`: RFC 3339 timestamp.
- `expires_at`: optional RFC 3339 timestamp.
- `evidence_id`: canonical hash of the evidence record without `evidence_id`.

## Verification Rules

Verifiers must reject a dossier when:

- `dossier_id` does not match the canonical unsigned body.
- no signature verifies over `{dossier_id, own_compliance_dossier}`.
- timestamps, mode, scope, or environment fields are malformed.
- evidence records use unknown kinds, invalid hashes, invalid timestamps, duplicate refs, duplicate ids, or non-canonical ordering/fields.
- required source artifacts are missing, unexpected, duplicated, or hash-mismatched.
- metrics do not match evidence and source artifacts.
- controls do not match the verifier-recomputed control set.
- `external-certification` mode still has any `external-required` control.

`readiness` mode must warn that it does not prove SOC 2 Type II or ISO/IEC 42001 certification.

## Controls

The control set is:

- `own-proof-pack-operability-source-bound`: proof-pack compiler, verifier, and proof-pack spec are hash-bound.
- `soc2-control-evidence-readiness-source-bound`: compliance mapper and compliance authority sources are hash-bound.
- `iso42001-management-system-readiness-source-bound`: standards package sources are hash-bound.
- `tamper-evident-retention-readiness-source-bound`: trust authority, WORM store, and retention sources are hash-bound.
- `roadmap-audit-readiness-source-bound`: roadmap audit source and spec are hash-bound.
- `external-soc2-type-ii-certification`: requires SOC 2 Type II evidence in `external-certification` mode.
- `external-iso42001-certification`: requires ISO/IEC 42001 evidence in `external-certification` mode.
- `raw-sensitive-data-excluded`: raw reports, customer data, secrets, and workpapers are excluded.

## Chain Entry

Appending a verified dossier emits entry type `trustai.own_compliance.dossier.attested` with:

- dossier id, hash, ref, scope, mode, and environment
- evidence counts and required certification evidence counts
- source artifact count
- control status summary

## CLI

```powershell
python -m trustai own-compliance-dossier --root . --dossier-ref dossier:trustai/own-compliance-readiness --producer-ref oidc:trustai.example/compliance-ops --scope-ref scope:trustai/company --out artifacts/own-compliance-dossier.json
python -m trustai own-compliance-dossier-verify artifacts/own-compliance-dossier.json --root .
python -m trustai own-compliance-dossier-append artifacts/own-compliance-dossier.json --root . --state .trustai/own-compliance-demo/evidence-chain.json --tenant own-compliance-local --out artifacts/own-compliance-dossier-entry.json
```