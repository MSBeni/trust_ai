# TrustAI Roadmap Audit v0.1

Status: Draft

The roadmap audit is a repository-local proof artifact that maps the uploaded
TrustAI roadmap to concrete files, tests, specs, and workflows in the public
repo. It is meant to prevent README-only claims: a reviewer can verify that the
claimed local evidence still exists at the recorded hashes, while seeing which
roadmap items still require live external authority.

## Schema

`trustai.roadmap-audit/0.1`

## Required Fields

- `schema`: fixed schema identifier.
- `audit_id`: canonical hash of the audit body without `audit_id`.
- `generated_at`: RFC3339 timestamp.
- `source`: hashes for `ROADMAP.md` and
  `docs/architecture/roadmap-coverage.md`.
- `summary`: requirement counts by status and phase.
- `requirements`: one object per roadmap requirement.
- `completion_position`: concise local completion posture.
- `limitations`: explicit non-claims for live services and business milestones.

## Requirement Statuses

- `implemented-local`: all referenced local evidence exists and no live external
  authority is required for the local claim.
- `reference-attested`: all referenced local evidence exists, but production
  completion still requires external provider, cloud, regulator, insurer,
  standards-body, or customer evidence.
- `missing-local-evidence`: at least one referenced local evidence file is absent.

## Verification Rules

A verifier MUST:

1. Recompute `audit_id` from the canonical audit body.
2. Re-hash the roadmap and coverage documents from the repository root.
3. Re-hash every evidence file marked `present`.
4. Reject absolute evidence paths or evidence paths containing `..`.
5. Reject any requirement whose status conflicts with its evidence set.
6. Recompute the summary from the requirement list.

The audit is valid even when requirements are `reference-attested`; those are
explicitly non-final production claims. The audit is not a substitute for live
KMS/HSM, TSA, provider API, hosted worker, regulator, insurer, customer, or
standards-body evidence.
