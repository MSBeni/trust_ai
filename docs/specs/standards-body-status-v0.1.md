# Standards-Body Status Receipt v0.1

This specification defines a signed receipt for standards-body docket status
updates after a TrustAI standards-body submission receipt has been created. It
models acknowledgement, review, ballot, final acceptance, rejection, or
withdrawal evidence while preserving the local-reference boundary.

The receipt does not claim that an external standards body has actually
accepted, balloted, or approved the TrustAI format. It provides an
offline-verifiable shape for those events and binds them to the submitted
standards package, verifier release, and conformance report through the source
submission receipt.

## Schema

`schema`: `trustai.standards-body-status/0.1`

Required top-level fields:

- `status_id`: canonical hash of the receipt body.
- `decided_at`: RFC3339 timestamp for the status decision.
- `effective_at`: RFC3339 timestamp for the status taking effect.
- `target_submission`: source submission id, content hash, submission
  reference, current status, standards-body metadata, standards package record,
  verifier release record, conformance target coverage, and optional
  provider-bundle source binding from the source submission.
- `status_update`: previous status, new status, docket reference, status
  reference, optional decision reference, optional reason, actor, optional
  ballot record, evidence references, and status payload hash.
- `source_artifacts`: exactly one canonical hash record for the source
  `trustai.standards-body-submission/0.1` receipt.
- `controls`: submission-status binding, docket reference, ballot record,
  decision record, and status-feed propagation controls.
- `limitations`: explicit local-reference and production-boundary statements.
- `signatures`: detached local HMAC signature over the status id and receipt
  body.

`status_update.new_status` is one of `acknowledged`, `under_review`,
`ballot_open`, `changes_requested`, `accepted`, `rejected`, or `withdrawn`.
`ballot_open` requires `ballot.ballot_ref`. `accepted` and `rejected` require
either `decision_ref` or `ballot.ballot_ref`.

## Verification

`trustai standards-body-status-verify` checks:

- schema, canonical `status_id`, and signature;
- decision/effective timestamps and optional current-time future-decision
  detection;
- target submission id and submission reference;
- previous status, new status, and required status transition;
- docket reference, status reference, actor reference, and actor role;
- ballot reference and decision-reference requirements for ballot/final
  statuses;
- ballot opened/closed timestamp ordering when supplied;
- status payload hash consistency;
- exactly one source standards-body submission artifact;
- source submission hash and full submission receipt verification when supplied;
- previous status and target record consistency with the source submission
  receipt, including conformance targets and optional provider-bundle source
  binding.

Without the source standards-body submission receipt, verification can only
prove receipt integrity and embedded source hash binding. It emits a warning for
the missing deep-verification input.

## Evidence Chain Entry

`trustai standards-body-status-append` verifies the receipt, then appends
`standards.body.status.updated` to an evidence chain. The entry payload records
the status id, receipt hash, target submission with conformance scope, status
update summary, source submission reference, and limitations.

## Reference Commands

```powershell
python -m trustai standards-body-status artifacts/standards-body-submission.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --new-status acknowledged --docket-ref LF-TRUSTAI-DKT-2026-001 --status-ref LF-TRUSTAI-DKT-2026-001:ack --actor-ref oidc:standards.example/chair-1 --actor-role working-group-chair --reason "Submission accepted into the working-group intake docket." --evidence-ref mail:trustai-wg/2026-07-18 --decided-at 2026-07-18T00:00:00Z --effective-at 2026-07-18T01:00:00Z --out artifacts/standards-body-status.json
python -m trustai standards-body-status-verify artifacts/standards-body-status.json --submission artifacts/standards-body-submission.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json
python -m trustai standards-body-status-append artifacts/standards-body-status.json --submission artifacts/standards-body-submission.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --state .trustai/standards-body-status-demo/evidence-chain.json --tenant standards-body-status-local --out artifacts/standards-body-status-entry.json
```

## Production Boundary

This local receipt models standards-body docket status evidence for the
reference implementation. Production standards work still needs authenticated
standards-body accounts, signed docket events, working-group minutes, ballot
records, appeal/withdrawal handling, compatibility policy, and public status
feed propagation.
