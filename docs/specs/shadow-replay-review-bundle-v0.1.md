# TrustAI Shadow Replay Review Bundle v0.1

A shadow replay review bundle is a self-contained offline handoff for a
third-party reviewer. It packages the verification contract, shadow replay
source, temporal holdout manifest, traffic holdout export, traffic completeness
receipt, provider export, and optional re-execution or soak-demotion evidence
with raw source bytes and canonical hashes.

Schema: `trustai.shadow-replay-review-bundle/0.1`

Evidence entry type: `shadow.replay_review_bundle.attested`

## Required Sources

- verification contract
- shadow replay source
- temporal holdout manifest
- traffic holdout export
- traffic completeness receipt
- traffic completeness provider export

## Optional Sources

- re-execution report
- failed soak report chain entry, demotion chain entry, and soak demotion receipt
- shadow replay production authority dossier

## Verification Rules

- `bundle_id` is the canonical content hash of the bundle body.
- The signature covers `{bundle_id, shadow_replay_review_bundle}`.
- Every embedded source artifact decodes, hashes to its recorded SHA-256, and
  matches the parsed source object by canonical content hash.
- Temporal holdout verification replays against embedded replay source bytes
  while preserving the original recorded replay source path.
- Traffic holdout export verification replays against embedded replay source
  bytes while preserving the original recorded replay source path.
- Traffic completeness verification replays against embedded provider export
  bytes while preserving the original recorded provider export path.
- Optional re-execution reports and soak-demotion receipts are replayed when
  supplied with their required source objects.
- `production-review` mode requires an embedded shadow replay authority dossier.

## CLI Surface

`shadow-replay-review-bundle` writes a signed JSON bundle and optional Markdown
rendering from retained local artifacts.

`shadow-replay-review-bundle-verify` verifies the bundle signature, source
artifact bytes, canonical source hashes, and replayable controls.

`shadow-replay-review-bundle-render` renders a verified bundle as Markdown for
auditor intake.

`shadow-replay-review-bundle-extract` extracts the embedded raw source artifacts
from a verified bundle.

`shadow-replay-review-bundle-append` appends a verified review bundle to a
TrustAI evidence chain as `shadow.replay_review_bundle.attested`.
