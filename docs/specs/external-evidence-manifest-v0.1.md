# TrustAI External Evidence Manifest v0.1

Status: Draft

The external evidence manifest binds live authority artifacts to the roadmap
requirements that a local reference implementation cannot prove by itself. It is
the bridge between `roadmap-audit` output and production completion evidence:
GitHub Actions run exports, KMS/HSM attestations, RFC 3161 TSA receipts, cloud
Object Lock reports, provider API responses, hosted service audit roots,
identity-provider events, regulator acknowledgements, insurer responses,
standards-body dockets, and customer acceptance artifacts can all be supplied as
hashed files and verified offline.

## Schema

`trustai.external-evidence-manifest/0.1`

## Required Fields

- `schema`: fixed schema identifier.
- `manifest_id`: canonical hash of the manifest body without `manifest_id`.
- `generated_at`: RFC3339 timestamp.
- `manifest_ref`: caller-supplied reference for the dossier.
- `source_roadmap_audit`: `audit_id`, audit content hash, and completion
  position for the roadmap audit this manifest satisfies.
- `required_external_requirements`: every `reference-attested` requirement from
  the roadmap audit, including the accepted external authority kinds derived
  from that requirement's external-authority claim.
- `required_authority_evidence_units`: one deterministic collection unit for
  every `(requirement_id, authority_kind)` pair required for complete external
  authority coverage.
- `evidence`: supplied external evidence artifacts.
- `summary`: requirement coverage, authority-kind coverage, missing requirement IDs, missing authority kinds, and evidence freshness-window counts.
- `limitations`: explicit non-claims about live fetching and issuer quality.

## Authority Evidence Unit

Each required authority evidence unit contains:

- `unit_id`: canonical hash of `requirement_id` and `authority_kind`, stable
  across manifests until the roadmap authority policy changes.
- `unit_ref`: human-readable `<requirement_id>:<authority_kind>` reference.
- `requirement_id`, `phase`, `priority`, and `title`: roadmap context for the
  collection task.
- `authority_kind`: the required external authority category.
- `coverage_status`: `covered` when at least one supplied evidence item covers
  the same requirement and authority kind, otherwise `missing`.
- `external_authority_required`: the roadmap audit text explaining the external
  evidence need.

## Evidence Item

Each evidence item contains:

- `evidence_id`: canonical hash of the evidence item body.
- `requirement_id`: a `reference-attested` roadmap requirement ID.
- `authority_kind`: one of `ci-run`, `kms-hsm`, `tsa`,
  `cloud-object-lock`, `provider-api`, `hosted-service`,
  `identity-provider`, `regulator`, `insurer`, `standards-body`, `customer`,
  or `other`.
- `accepted_authority_kinds`: the complete authority-kind allowlist for this
  requirement, derived from the roadmap audit and repeated on the evidence item
  so a verifier can reject category swaps.
- `path`: repository-relative path to the supplied evidence artifact.
- `sha256`: SHA-256 hash of the supplied artifact.
- `description`: short human-readable reason the artifact satisfies the
  requirement.
- Optional `issuer`, `subject`, `source_uri`, `issued_at`, and `expires_at`
  fields. `issued_at` and `expires_at` define the freshness window for the
  authority artifact. With strict freshness verification, both timestamps are
  required and `expires_at` MUST be later than the verifier's `now` value.

## Markdown Rendering

The optional Markdown rendering MUST expose the manifest as an external-evidence
collection checklist. It includes every required `reference-attested`
requirement, coverage state, accepted authority kinds, covered authority kinds,
missing authority kinds, deterministic authority evidence unit IDs, human-readable
unit references, and the roadmap audit's external authority text, followed by
supplied evidence rows with accepted authority kinds and freshness windows. This
keeps the human review artifact aligned with the machine-verifiable
authority-kind policy.

## External Evidence Collection Plan

`external-evidence-plan` emits `trustai.external-evidence-collection-plan/0.1`,
a deterministic assignment artifact derived from a verified external evidence
manifest and its source roadmap audit. It turns authority coverage units into
collection tasks without weakening the manifest: a task is covered only after a
matching evidence artifact is supplied to a manifest and verified.

Required fields:

- `plan_id`: canonical hash of the plan body without `plan_id`.
- `status_filter`: `missing`, `covered`, or `all`.
- `source_manifest`: manifest ID, manifest hash, manifest ref, status, and
  generation time.
- `source_roadmap_audit`: the manifest's roadmap-audit binding.
- `summary`: selected task counts, missing/covered task counts, overall
  authority-kind coverage counts, and selected task counts by authority and
  phase.
- `tasks`: assignment-ready collection tasks with `task_id`, `task_ref`,
  `unit_id`, `unit_ref`, requirement context, authority kind, coverage status,
  owner hint, suggested artifact path, evidence argument template, source hints,
  acceptance criteria, and roadmap external-authority text.

A collection-plan verifier MUST recompute the source manifest verification,
rebuild the plan using the same `status_filter` and `generated_at`, recompute
`plan_id`, and reject stale or edited task bodies.

## External Evidence Intake Receipt

`external-evidence-intake` emits `trustai.external-evidence-intake/0.1`, a
pre-manifest receipt for one collected authority artifact. It binds a collected
file to a collection-plan task, records the file hash, validates freshness
metadata when requested, and emits the exact evidence argument that can be used
with `external-evidence-manifest`.

Required fields:

- `intake_id`: canonical hash of the intake body without `intake_id`.
- `source_plan`: plan ID, plan hash, status filter, and source manifest binding.
- `source_manifest`: manifest ID/hash/ref and authority-kind coverage counts.
- `source_roadmap_audit`: the roadmap-audit binding from the manifest.
- `task`: the selected collection task ID/ref/unit/requirement/authority binding.
- `evidence_item`: the manifest-ready evidence item with artifact path, SHA-256,
  accepted authority kinds, issuer metadata, and freshness window.
- `evidence_argument`: the exact CLI argument for a later manifest rebuild.

An intake verifier MUST verify the supplied collection plan against the manifest
and roadmap audit, recompute the source bindings, confirm the selected task still
exists, re-hash the artifact, verify task requirement/authority alignment, check
freshness when requested, and reject stale or edited intake receipts.

## Evidence Chain Entry

A verified manifest can be appended to an evidence chain as
`trustai.external_evidence_manifest.attested`. The chain entry records:

- `manifest_id` and canonical `manifest_hash`.
- `manifest_ref` and `source_roadmap_audit`.
- `source_roadmap_audit_inclusion_proof` when the referenced roadmap audit
  has already been appended to the same evidence chain.
- Coverage status, required/covered/missing requirement counts,
  required/covered/missing authority-kind counts, and evidence count.
- Freshness enforcement mode, verification time, issued/expires/fresh-window
  counts, and fresh/stale/missing-freshness evidence counts.
- Covered and missing requirement IDs, plus covered and missing authority kinds by requirement.
- Whether complete production evidence and fresh evidence were required at
  append time.

The append operation MUST verify the manifest against the supplied roadmap audit
before writing the chain entry. If the same chain already contains a matching
`trustai.roadmap_audit.attested` entry for the manifest source audit, append
SHOULD include that entry inclusion proof in the external-evidence payload. If
`require_complete` is set and any reference-attested requirement is uncovered or
any accepted authority kind for that requirement is uncovered, append MUST fail.
If `require_fresh` is set, append MUST fail unless every
supplied evidence item has valid `issued_at` and `expires_at` timestamps and is
unexpired at the supplied `now` value, or at manifest `generated_at` when `now`
is omitted.

## Semantic Chain Verification

`roadmap-evidence-verify` verifies the evidence chain itself and then checks the
roadmap evidence relationships:

1. At least one `trustai.roadmap_audit.attested` entry is present.
2. Each `trustai.external_evidence_manifest.attested` entry points to a matching
   prior roadmap audit entry by `audit_id` and `audit_hash`.
3. The stored `source_roadmap_audit_inclusion_proof` verifies against the prefix
   tree root that existed before the external-evidence entry was appended.
4. Requirement coverage counts and authority-kind coverage counts are internally consistent.
5. With `--require-complete`, every external-evidence entry must carry authority-kind coverage metadata and cover every required requirement and every accepted authority kind.
6. With `--require-fresh`, every external-evidence entry must have been appended
   with freshness required and must record zero stale or missing-freshness
   evidence items.


## Manifest Rebuild from Intake Receipts

`external-evidence-manifest-from-intakes` consumes a collection plan, the source
manifest that produced that plan, the roadmap audit, and one or more
`trustai.external-evidence-intake/0.1` receipts. The command verifies every
receipt against the supplied plan and source manifest before rebuilding a new
manifest.

The rebuilt manifest preserves evidence already present in the source manifest
and overlays each verified intake by `(requirement_id, authority_kind)`. Duplicate
intake receipts for the same authority coverage unit are rejected so that a
manifest cannot silently choose between conflicting collected artifacts. Use the
rebuilt manifest as the next source manifest before appending to the roadmap
evidence chain.

## Roadmap Evidence Report

`roadmap-evidence-report` emits `trustai.roadmap-evidence-report/0.1`, a
portable JSON and Markdown summary of the linked roadmap audit and external
evidence entries already committed to an evidence chain. The report records:

- `report_id`: canonical hash of the report body without `report_id`.
- `verification_options`: whether external evidence, complete external
  coverage, or fresh external evidence was required when the report was
  generated.
- `chain`: tenant ID, entry count, and current Merkle tree root.
- `summary`: semantic verification status and audit/external-evidence entry
  counts.
- `verification`: the exact `roadmap-evidence-verify` result, including errors
  and warnings.
- `roadmap_audit_entries`: chained audit entry IDs, audit IDs/hashes, completion
  position, and local/reference/missing counts.
- `external_evidence_entries`: chained manifest IDs/hashes, source audit binding,
  source audit inclusion proof summary, coverage status, freshness counts,
  covered IDs, and missing IDs.
- `limitations`: explicit non-claims about live authority fetching and issuer
  quality.

A verifier MUST recompute `report_id`, verify the supplied chain with the same
options, compare the report's chain tree root and entry summaries to the
supplied chain, and reject reports whose embedded semantic verification no longer
matches the chain. `roadmap-evidence-report-verify` performs this offline check
without contacting TrustAI services or live authority systems.


## Roadmap Evidence Bundle

`roadmap-evidence-bundle` emits `trustai.roadmap-evidence-bundle/0.1`, a
self-contained artifact for third-party review. It embeds:

- the evidence-chain snapshot (`spec_version`, tenant ID, tree, and entries),
- the roadmap evidence report generated from that chain or supplied with `--report`,
- optional embedded source artifacts supplied with `--source-artifact` (`roadmap-audit`, `external-evidence-manifest`, `external-evidence-file`, or `other`) as repository-relative paths, SHA-256 hashes, and base64 content; `--include-manifest-evidence` expands embedded external-evidence manifests into their referenced evidence files,
- a summary binding the report hash, report ID, chain tree, evidence counts, and embedded source-artifact count,
- explicit limitations for live authority claims.

`roadmap-evidence-bundle-verify` requires no separate chain state path. It
recomputes `bundle_id`, reconstructs the embedded evidence chain, verifies that
the embedded tree matches the entries, verifies the report against that embedded
chain with the same strictness options, including `--require-fresh`, decodes and
rehashes embedded source artifacts, confirms embedded roadmap-audit and
external-evidence-manifest JSON artifacts are committed to the bundled chain by
content hash, warns when embedded external-evidence-file artifacts are not
referenced by an embedded manifest, warns when an embedded manifest references
evidence files that are not embedded, and rejects stale or tampered bundle
summaries. With `--require-source-artifacts`, every bundled roadmap-audit entry,
external-evidence manifest entry, and manifest-referenced evidence file MUST be
embedded or verification fails. `roadmap-evidence-bundle-extract` runs the same
verification first, then materializes embedded source artifacts under `--out-dir`
using their repository-relative paths; it refuses to overwrite existing files
unless `--overwrite` is set.

## Verification Rules

A verifier MUST:

1. Recompute `manifest_id` from the canonical manifest body.
2. Verify the supplied roadmap audit first.
3. Recompute the roadmap audit content hash and source audit metadata.
4. Confirm the required requirement list and accepted authority-kind policy
   exactly match `reference-attested` roadmap audit requirements.
5. Reject evidence for unknown or non-external requirement IDs.
6. Reject evidence whose `authority_kind` is outside the accepted authority
   kinds for its requirement, and reject evidence whose
   `accepted_authority_kinds` list does not match that derived policy.
7. Reject absolute paths or paths containing `..`.
8. Re-hash every evidence artifact and compare it to the recorded SHA-256.
9. Recompute required authority evidence units, coverage summary, missing requirement IDs, missing authority kinds,
   and freshness-window counts.
10. Parse any `issued_at` and `expires_at` values, reject windows where
   `expires_at <= issued_at`, and warn on missing, future-issued, or expired
   evidence when strict freshness is not requested.
11. When complete production evidence is required, reject manifests that do not
   cover every reference-attested requirement and every accepted authority kind
   for those requirements.
12. When fresh production evidence is required, reject manifests where any
   evidence item lacks a freshness window, has not yet been issued, or has
   expired at the verifier's `now` value.

The manifest verifies that supplied external evidence has not changed, is mapped
to the right roadmap gap, and can optionally be required to be fresh at a named
verification time. It does not independently validate the legal or technical
authority of the issuer beyond the artifact provided.
