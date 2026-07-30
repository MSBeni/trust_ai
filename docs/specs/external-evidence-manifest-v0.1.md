# TrustAI External Evidence Manifest v0.1

Status: Draft

The external evidence manifest binds live authority artifacts to the roadmap
requirements that a local reference implementation cannot prove by itself. It is
the bridge between `roadmap-audit` output and production completion evidence:
GitHub Actions run exports, KMS/HSM attestations, RFC 3161 TSA receipts, cloud
Object Lock reports, provider API responses, hosted service audit roots,
identity-provider events, regulator acknowledgements, insurer responses,
standards-body dockets, and customer acceptance artifacts can all be supplied as
hashed files and verified offline. Source snapshots can preserve fetched or manually exported authority responses before they are mapped to collection-plan tasks.

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
matching evidence artifact is supplied to a manifest and verified. `--generated-at` MAY be supplied for reproducible checked-in collection plans.

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

## External Evidence Source Snapshot

`external-evidence-snapshot` emits
`trustai.external-evidence-source-snapshot/0.1`, a repository-local artifact for
one fetched or manually exported authority response. It is intended to be the
file supplied to `external-evidence-intake` when the original source is a live
provider URL, hosted service endpoint, regulator portal export, insurer API
response, or customer-owned document export.

Required fields:

- `snapshot_id`: canonical hash of the snapshot body without `snapshot_id`.
- `source_uri`: the authority source URI or stable export reference.
- `retrieval_method`: `http-get`, `file-copy`, `manual-export`, or another
  caller-supplied method label.
- Optional `issuer`, `subject`, `content_type`, `status_code`,
  `response_headers`, `issued_at`, and `expires_at` fields.
- `body_sha256`, `body_size_bytes`, and `body_base64`: the captured response
  body and deterministic integrity metadata.
- `limitations`: explicit non-claims about future source availability and
  authority quality.

A snapshot verifier MUST recompute `snapshot_id`, decode `body_base64`, verify
`body_sha256` and `body_size_bytes`, validate optional HTTP metadata, and enforce
freshness windows when requested. Snapshot verification does not replace intake
or manifest verification; it makes the collected source artifact itself portable
and hashable before it is bound to a collection-plan task.

`external-evidence-collect` is a CLI composition over source snapshots and intake
receipts. It loads a collection plan, source manifest, and roadmap audit;
captures the authority source into a snapshot under the repository root; verifies
that snapshot; then creates and verifies the matching intake receipt using the
snapshot's repository-relative artifact path. It emits no additional schema, but
it is the preferred operator workflow for collecting many authority receipts
because the snapshot and intake cannot drift apart.


`external-evidence-source-map-template` emits
`trustai.external-evidence-source-map/0.1` from a verified collection plan. The
source map records `source_map_id`, `generated_at`, `source_plan`, `summary`,
optional shared `defaults`, and one `entries` item per selected collection task.
Template entries include the collection `task`, `task_ref`, `task_id`, `unit_id`,
`unit_ref`, `requirement_id`, `authority_kind`, operator hints, `source_uri`,
`description`, `snapshot_out`, and `intake_out`. URI and description templates
MAY interpolate `{task_id}`, `{task_ref}`, `{unit_id}`, `{unit_ref}`,
`{requirement_id}`, `{authority_kind}`, `{phase}`, `{priority}`, and `{title}`.
The summary records `placeholder_source_uri_count` and `live_source_uri_count`
so operators can distinguish a generated worklist from a ready-to-collect map
that points at real authority-owned sources.

`external-evidence-source-map-verify` verifies a source map against its source
collection plan. It MUST recompute `source_map_id`, verify `source_plan` binding,
validate the status and authority filters, reject duplicate or unknown tasks,
and confirm task metadata plus generated `snapshot_out` and `intake_out` paths
match the supplied plan. With `--require-live-source-uris`, verification MUST
reject maps that still contain placeholder or example `source_uri` values. With
`--require-source-snapshots`, verification MUST load every `snapshot_out` under
`--root`, verify it as `trustai.external-evidence-source-snapshot/0.1`, require
its `source_uri` to match the map entry, and reject HTTP snapshots whose status
code is outside the 2xx/3xx range. With `--require-fresh-source-snapshots`, the
snapshot verifier MUST also require fresh `issued_at`/`expires_at` windows at the
supplied `--now` time. Verification confirms operator worklist integrity and
collected-source integrity only; it does not convert a source-map template into
external authority evidence.

`external-evidence-source-map-fulfill` merges task-bound authority metadata into an existing source map. Each fulfillment record identifies one entry by `task`, `task_ref`, `task_id`, `unit_id`, or `unit_ref`, may update only collection metadata (`source_uri`, `description`, `source_file`, `retrieval_method`, `content_type`, `issuer`, `subject`, `issued_at`, `expires_at`, `timeout_seconds`), recomputes placeholder/live source URI counts, and emits a new canonical `source_map_id`. The command MUST verify the fulfilled map against the original collection plan before export; with `--require-live-source-uris`, any remaining placeholder URI keeps the map from being used as a production collection input, and with `--require-source-snapshots`, the corresponding collected snapshots must already be present and valid under `--root`. `--require-fresh-source-snapshots` additionally requires those snapshots to be fresh at the supplied `--now` time.

`external-evidence-verify` with `--require-live-source-uris` MUST reject final manifest evidence items whose `source_uri` is missing, `TODO`, or an example/placeholder authority URI. `external-evidence-intake-verify`, `external-evidence-manifest-from-intakes`, and `external-evidence-append` expose the same strict option so production evidence cannot bypass the source-map readiness gate.

`external-evidence-verify` and `external-evidence-append` with `--require-source-snapshot-artifacts` MUST load every final manifest evidence item `path` under `--root`, verify it as `trustai.external-evidence-source-snapshot/0.1`, require the snapshot `source_uri` to match the evidence item, and reject HTTP snapshots whose status code is outside the 2xx/3xx range. With `--require-fresh-source-snapshot-artifacts`, final manifest verification MUST also require fresh snapshot `issued_at`/`expires_at` windows at the supplied `--now` time; this freshness option is invalid unless source snapshot artifact verification is also enabled.

`external-evidence-intake-verify` with `--require-source-snapshot-artifact` MUST load the intake evidence item `path` under `--root`, verify it as `trustai.external-evidence-source-snapshot/0.1`, require the snapshot `source_uri` to match the evidence item, and reject HTTP snapshots whose status code is outside the 2xx/3xx range. With `--require-fresh-source-snapshot-artifact`, the verifier MUST also require fresh snapshot `issued_at`/`expires_at` windows at the supplied `--now` time; this freshness option is invalid unless source snapshot artifact verification is also enabled.

`external-evidence-collect-batch` consumes the same source-map schema. Each
entry MUST identify a unique collection `task`, `source_uri`, and `description`;
it MAY provide or inherit `source_file`, `issuer`, `subject`, `content_type`,
`issued_at`, `expires_at`, `retrieval_method`, `snapshot_out`, `intake_out`,
`snapshot_dir`, `intake_dir`, and `timeout_seconds`. The command rejects
duplicate tasks and writes a `trustai.external-evidence-collection-run/0.1`
report with `generated_at` and generated snapshot paths, intake paths, IDs,
evidence arguments, and warnings.

`external-evidence-collect-batch-verify` verifies the collection-run report
offline. It MUST recompute `run_id`, verify the collection plan, and, when a
source map is supplied or recoverable from the run's `source_map.path`, verify
`source_map_hash` plus task, `source_uri`, `snapshot_out`, and `intake_out`
consistency. For every collected item it MUST load the repository-relative
source snapshot artifact under `--root`, verify the snapshot ID, body hash,
source URI, status code, and optional freshness window, then load the intake
receipt, verify it against the supplied plan, manifest, and roadmap audit, and
confirm the run's task, snapshot ID, intake ID, evidence argument, and paths all
match the actual artifacts. Verification MUST reject missing files, tampered
IDs, broken canonical hashes, duplicate tasks, count mismatches, and collected
tasks outside the supplied source map.

`external-evidence-collect-batch-append` MUST run the same collection-run
verification, require the source roadmap audit to already be appended to the
same evidence chain, and append a
`trustai.external_evidence_collection_run.attested` entry. The entry records the
run ID/hash, source-map path/hash, source plan and source manifest bindings,
source roadmap-audit binding and inclusion proof, strict verification options,
verification time, collected task refs, source snapshot IDs, and intake IDs. It
attests retained collection provenance only; final external authority coverage
still requires a verified `trustai.external_evidence_manifest.attested` entry.

`external-evidence-collect-git-ref` is a narrowed source collector for public or
authenticated Git remotes. It runs `git ls-remote <remote> <ref>...`, writes a
`trustai.external-evidence-git-remote-ref-export/0.1` body into a normal source
snapshot with retrieval method `git-ls-remote`, and then creates the matching
intake receipt. The export records `remote`, requested refs, advertised
`records`, optional `expected_sha`, whether that SHA was advertised, and a hash
of raw stdout. This proves the remote advertised the refs at collection time; it
does not prove future remote availability or CI workflow success.

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
`external-evidence-intake` MAY accept `--generated-at` for reproducible checked-in receipts.

## Evidence Chain Entry

A verified collection-run report can be appended to an evidence chain as
`trustai.external_evidence_collection_run.attested`. The append operation MUST
verify the report, its retained source snapshots, and its intake receipts before
writing the entry, and MUST include a prior source roadmap-audit inclusion proof.

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
- Whether complete production evidence, fresh evidence, live source URIs,
  source snapshot artifact verification, and fresh source snapshot artifacts
  were required at append time.

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
3. Each `trustai.external_evidence_collection_run.attested` entry points to a
   matching prior roadmap audit entry by `audit_id` and `audit_hash`.
4. The stored `source_roadmap_audit_inclusion_proof` verifies against the prefix
   tree root that existed before the external-evidence or collection-run entry
   was appended.
5. Collection-run entry task, source snapshot, intake, source-map, and count
   summaries are internally consistent.
6. Requirement coverage counts and authority-kind coverage counts are internally consistent.
7. With `--require-complete`, every external-evidence entry must carry authority-kind coverage metadata and cover every required requirement and every accepted authority kind.
8. With `--require-fresh`, every external-evidence entry must have been appended
   with freshness required and must record zero stale or missing-freshness
   evidence items.


## Manifest Rebuild from Intake Receipts

`external-evidence-manifest-from-intakes` consumes a collection plan, the source
manifest that produced that plan, the roadmap audit, and one or more
`trustai.external-evidence-intake/0.1` receipts. The command verifies every
receipt against the supplied plan and source manifest before rebuilding a new
manifest.

The rebuilt manifest preserves evidence already present in the source manifest
and overlays each verified intake by `(requirement_id, authority_kind)`. Receipts
may be supplied explicitly or discovered recursively from intake directories;
directory discovery only consumes JSON objects whose `schema` is
`trustai.external-evidence-intake/0.1`. Duplicate intake receipts for the same
authority coverage unit are rejected so that a manifest cannot silently choose
between conflicting collected artifacts. With `--require-source-snapshot-artifacts`,
the rebuild MUST apply source snapshot artifact verification to every intake
before overlaying it; with `--require-fresh-source-snapshot-artifacts`, every
required intake snapshot artifact MUST also be fresh at the supplied `--now`
time. `--generated-at` MAY be supplied for reproducible checked-in rebuilt
manifests. Use the rebuilt manifest as the next source manifest before appending
to the roadmap evidence chain.

## External Evidence Gap Report

`external-evidence-gap-report` emits
`trustai.external-evidence-gap-report/0.1` from a verified external-evidence
manifest, collection plan, source-map template, and source roadmap audit. The
report records source artifact IDs and hashes, covered and missing authority
counts, remaining worklist entries with effective source-map collection metadata
(source URI, description, source file, retrieval method, content type, issuer,
subject, freshness window, timeout, snapshot output, and intake output),
placeholder/live source URI counts, grouping by requirement and authority kind,
verification warnings, and explicit limitations. `--generated-at` MAY be supplied for reproducible checked-in gap
reports.

`external-evidence-gap-report-verify` recomputes `gap_report_id`, verifies the
manifest, plan, source map, and roadmap audit with the requested freshness and
source-URI readiness options, rebuilds the expected report body from those
sources, and rejects stale or tampered summaries. With
`--require-live-source-uris`, verification MUST reject reports built from source
maps that still contain placeholder or example `source_uri` values. The report
is a tamper-evident worklist checkpoint;
it does not close an authority gap. A gap is closed only after a matching
external authority artifact, snapshot, and intake receipt are verified and a new
manifest is rebuilt.

## External Evidence Readiness

`external-evidence-readiness` writes a canonical production-readiness report over a verified retained manifest, collection plan, source map, gap report, roadmap audit, and optional work package. The report has schema `trustai.external-evidence-readiness/0.1`, a canonical `readiness_id`, source artifact hashes, readiness checks, blockers, and next actions. It also inspects covered evidence artifacts for explicit retained-fixture or non-live-run markers and reports `production_usable_covered_authority_kind_count` separately from raw covered authority units. `external-evidence-readiness-verify --require-ready` MUST fail until every required authority unit is covered, every collection task is closed, every source-map URI is live, and the optional work package matches the remaining task set. This command is intended to separate CI health from production evidence completeness.

## External Evidence Work Package

`external-evidence-work-package` emits
`trustai.external-evidence-work-package/0.1` from a verified gap report and the
same manifest, collection plan, source map, and roadmap audit used to produce
that report. It is an owner-ready assignment artifact: it groups remaining gap
tasks by owner hint, authority kind, phase, priority, or requirement ID and
includes the exact task refs, snapshot/intake paths, acceptance criteria,
source-map metadata, next actions, and replayable `external-evidence-collect`
and intake verification commands for each task.

Required fields:

- `work_package_id`: canonical hash of the work-package body without
  `work_package_id`.
- `group_by`: one of `owner_hint`, `authority_kind`, `phase`, `priority`, or
  `requirement_id`.
- `command_context`: CLI path context used to render task-level collect,
  intake verification, batch collection, and manifest rebuild commands.
- `sources`: IDs and canonical hashes for the source gap report, manifest,
  collection plan, source map, and roadmap audit.
- `summary`: package count, task count, missing/covered task counts,
  placeholder/live source URI counts, and task counts by owner, authority kind,
  phase, priority, requirement, and package.
- `packages`: grouped task packages. Each package records a deterministic
  `package_id`, `group_by`, `group_key`, the selected grouping field (for
  example `owner_hint` when grouped for owners), grouped task counts,
  authority/requirement coverage lists, package-level batch/rebuild commands,
  and task-level collection commands.

`external-evidence-work-package-verify` recomputes the source gap-report
verification options, verifies every source artifact, rebuilds the work package
with the recorded grouping and command context, recomputes every package hash
and the top-level `work_package_id`, and rejects edited owner assignments,
commands, paths, counts, or task bodies. The artifact remains a work assignment,
not evidence: authority gaps close only after real source snapshots, intake
receipts, a rebuilt manifest, and an evidence-chain entry verify successfully.

## Production Replacement Lifecycle

Retained or local/reference evidence can keep CI examples reproducible, but it
MUST NOT be counted as production authority evidence. The production replacement
lifecycle turns the non-production units reported by `external-evidence-readiness`
into owner-routed collection work and keeps the strict production gate blocked
until live authority sources are supplied.

`external-evidence-production-replacement-plan` emits
`trustai.external-evidence-production-replacement-plan/0.1` from a verified
readiness report, retained manifest, and roadmap audit. It selects every covered
authority unit whose artifact is retained, local-reference, or otherwise not
production-usable, groups those units by owner hint, authority kind, phase,
priority, or requirement, and records replacement tasks with the retained unit
hashes that must be superseded. `external-evidence-production-replacement-plan-verify`
MUST rebuild the expected plan from the supplied readiness report, manifest, and
audit, and MUST reject edited counts, grouping, task refs, source hashes, or
production-usable/non-production unit totals.

`external-evidence-production-replacement-owner-packets` and
`external-evidence-production-replacement-owner-packet-status` produce the owner
handoff and status checkpoint for the replacement plan. Owner packets are
assignment artifacts; status reports may mark task refs open, blocked, or closed,
but closing a task in this status report alone does not close production evidence.
The corresponding verifiers MUST reject task refs that are not present in the
plan and MUST keep packet/status counts consistent with the source replacement
plan.

`external-evidence-production-replacement-intake-template` emits
`trustai.external-evidence-production-replacement-intake-template/0.1`, a
fillable authority intake request set for open or blocked replacement tasks. Each
fulfillment row carries task-bound collection metadata: `source_uri`,
`description`, `source_file`, `retrieval_method`, `content_type`, `issuer`,
`subject`, freshness windows, snapshot output, and intake output. Placeholder
`TODO://production-authority/...` source URIs are allowed in the template so
owners can see the work, but they MUST keep any production review blocked.

`external-evidence-production-replacement-submission` emits
`trustai.external-evidence-production-replacement-submission/0.1` from an
intake template and owner-provided fulfillment metadata. It records the exact
submitted fulfillment rows, applies them to a derived submitted intake template,
recomputes the template hash, and can write that submitted template for the
review step. `external-evidence-production-replacement-submission-verify` MUST
reject stale source-template hashes, edited submitted fulfillments, duplicate
task refs, and unsupported fulfillment keys; with
`--require-submitted-live-source-uris`, placeholder or example URIs in the
submitted rows MUST fail verification.

`external-evidence-production-replacement-submission-review` emits
`trustai.external-evidence-production-replacement-submission-review/0.1` from a
submitted intake template, the owner packet status, and the all-authority
collection plan. It builds a fulfilled source map limited to the submitted
replacement tasks, verifies that every submitted task is anchored to the owner
status report, counts ready and blocked tasks, and exports commands for batch
collection, manifest rebuild, and strict readiness proof. With
`--require-live-source-uris`, placeholder or example source URIs MUST produce
blockers; with `--require-ready`, verification MUST fail unless every submitted
replacement task has live source URIs and the fulfilled source map verifies
under the requested snapshot options.

`external-evidence-production-replacement-remediation-queue` emits
`trustai.external-evidence-production-replacement-remediation-queue/0.1` from a
submission review. It extracts the blocked task rows into an owner-facing
remediation queue with counts by owner, authority kind, requirement, source URI
status, and blocking reason. Each remediation item carries a fulfillment
template so evidence owners can replace placeholder authority metadata without
changing the review body by hand. `external-evidence-production-replacement-remediation-queue-verify --require-empty` MUST fail while any blocked remediation item remains, making
the queue a strict pre-collection control for production readiness.

`external-evidence-production-replacement-remediation-owner-packets` emits
`trustai.external-evidence-production-replacement-remediation-owner-packet-bundle/0.1`
from a remediation queue. It groups blocked rows by `owner_hint`, preserves the
per-task fulfillment templates, and gives each owner a deterministic packet ID,
completion gate, and live-source/snapshot/intake handoff requirements.
`external-evidence-production-replacement-remediation-owner-packets-verify` MUST
rebuild the bundle from the source queue and reject stale packet counts, owner
groupings, task bodies, fulfillment templates, or queue hashes. This is the
operator dispatch artifact for replacing retained/reference evidence without
losing the strict queue-to-review derivation.

`external-evidence-production-replacement-remediation-owner-fulfillment-template`
emits
`trustai.external-evidence-production-replacement-remediation-owner-fulfillment-template/0.1`
from the remediation owner packet bundle. It flattens owner packet fulfillment
templates into a `fulfillments` array that is directly accepted by
`external-evidence-production-replacement-submission --fulfillment-file`, while
preserving owner, requirement, authority, blocked reason, snapshot, intake, and
replacement traceability under `requests`. `REPLACE_WITH_*`, `TODO:*`, and
example-domain source URIs MUST count as placeholders.
`external-evidence-production-replacement-remediation-owner-fulfillment-template-verify`
MUST rebuild the template from the owner packet bundle and reject stale source
packet hashes, owner filters, request bodies, or fulfillment rows.

`external-evidence-production-replacement-remediation-owner-fulfillment-review`
emits
`trustai.external-evidence-production-replacement-remediation-owner-fulfillment-review/0.1`
from an owner-filled remediation fulfillment template, the remediation owner
packet bundle, and the all-authority collection plan. The review MAY accept a
stale template ID after owner edits, but it MUST preserve source packet hashes,
owner filters, request context, and the packet-derived task set. The review
materializes the fulfilled production source map and MUST remain blocked while
any placeholder source URI remains or while the fulfilled source map fails the
requested live-source/snapshot checks.
`external-evidence-production-replacement-remediation-owner-fulfillment-review-verify`
MUST rebuild the review from those source artifacts and reject stale review IDs,
source artifact mismatches, verification-option drift, task-context drift, or a
`--require-ready` review that is not `ready-to-collect`.

`external-evidence-production-replacement-remediation-apply` emits
`trustai.external-evidence-production-replacement-remediation-application/0.1`
from the original submission review and a remediation owner fulfillment review.
It overlays the reviewed remediation task rows onto the original review, writes
a canonical applied submission review for downstream collection/closure, and
preserves source review hashes so operators can prove exactly which blocked
submission was remediated. `external-evidence-production-replacement-remediation-apply-verify`
MUST rebuild the application from both source reviews and, with `--require-ready`,
MUST fail unless the applied review is `ready-to-collect` with no placeholder
source URIs.

`external-evidence-production-replacement-collection-package` emits
`trustai.external-evidence-production-replacement-collection-package/0.1` from a
submission review, source manifest, and roadmap audit. It is the operator handoff
for collection: it binds the reviewed fulfilled source map, ready/blocked task
lists, snapshot/intake output directories, and exact collection/rebuild/readiness
commands into one canonical package. The package MAY be emitted while blocked so
owners can inspect the remaining work, but `external-evidence-production-replacement-collection-package-verify
--require-ready` MUST fail unless the source review is ready to collect and no
placeholder source URIs remain.

`external-evidence-production-replacement-closure` emits
`trustai.external-evidence-production-replacement-closure/0.1` from the
submission review and readiness report. It binds the submitted replacement task
set to the current readiness proof, closes only when every task is ready,
source URIs are live, and readiness is `ready`, and leaves retained/reference
fixtures blocked. `external-evidence-production-replacement-closure-verify
--require-closed` MUST fail until that final production authority boundary is
closed.

A ready production replacement collection package is still not final authority
evidence. Production readiness is proven only after `external-evidence-collect-batch`
collects source snapshots from the package's fulfilled source map,
`external-evidence-manifest-from-intakes` rebuilds the manifest from verified
intake receipts, `external-evidence-readiness-verify --require-ready` passes
against the rebuilt sources,
`external-evidence-production-replacement-closure-verify --require-closed`
passes against the rebuilt readiness proof, and the resulting
manifest/readiness/closure evidence is committed to the evidence chain.

## Roadmap Evidence Report

`roadmap-evidence-report` emits `trustai.roadmap-evidence-report/0.1`, a
portable JSON and Markdown summary of the linked roadmap audit and external
evidence entries already committed to an evidence chain. The report records:

- `report_id`: canonical hash of the report body without `report_id`.
- `verification_options`: whether external evidence, complete external
  coverage, or fresh external evidence was required when the report was
  generated.
- `chain`: tenant ID, entry count, and current Merkle tree root.
- `summary`: semantic verification status and audit, collection-run, and
  external-evidence entry counts.
- `verification`: the exact `roadmap-evidence-verify` result, including errors
  and warnings.
- `roadmap_audit_entries`: chained audit entry IDs, audit IDs/hashes, completion
  position, and local/reference/missing counts.
- `external_evidence_entries`: chained manifest IDs/hashes, source audit binding,
  source audit inclusion proof summary, append verification options, coverage
  status, freshness counts, covered IDs, and missing IDs.
- `external_evidence_collection_run_entries`: chained run IDs/hashes, source-map
  path/hash, source plan and manifest bindings, source audit binding and proof
  summary, strict collection verification options, collected task refs, source
  snapshot IDs, and intake IDs.
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
- optional embedded source artifacts supplied with `--source-artifact` (`roadmap-audit`, `external-evidence-manifest`, `external-evidence-collection-run`, `external-evidence-source-map`, `external-evidence-source-snapshot`, `external-evidence-intake`, `external-evidence-file`, or `other`) as repository-relative paths, SHA-256 hashes, and base64 content; `--include-manifest-evidence` expands embedded external-evidence manifests into their referenced evidence files, and `--include-collection-run-artifacts` expands embedded collection-run reports into their referenced source map, source snapshots, and intake receipts,
- a summary binding the report hash, report ID, chain tree, audit, collection-run and evidence counts, and embedded source-artifact count,
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
