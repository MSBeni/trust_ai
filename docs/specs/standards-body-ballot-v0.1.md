# Standards-Body Ballot Receipt v0.1

Status: local reference specification

## Purpose

A standards-body ballot receipt records a formal ballot or decision event for a
TrustAI standards-track submission. It binds the ballot tally, quorum math,
decision reference, actor reference, source submission receipt, and optional
docket status receipt by canonical hash.

This receipt narrows the gap between local standards-body status tracking and
production standards-track acceptance. It does not claim that a real standards
body has approved the package unless the source artifacts and actor references
come from that standards body.

## Schema

`schema`: `trustai.standards-body-ballot/0.1`

Required top-level fields:

- `ballot_id`: canonical hash of the receipt body.
- `opened_at`, `closed_at`, `decided_at`, `effective_at`: RFC 3339 timestamps.
- `target_submission`: source standards-body submission identity and package
  references.
- `status_context`: optional docket/status receipt context.
- `ballot`: ballot reference, mode, motion, voter counts, quorum, approval
  threshold, and computed quorum/approval flags.
- `decision`: final outcome, decision reference, actor reference, optional
  minutes reference, and evidence references.
- `ballot_payload_hash`: canonical hash of the target, status context, ballot,
  and decision records.
- `source_artifacts`: canonical hashes for the submission receipt and optional
  status receipt.
- `signatures`: detached local reference signatures over `ballot_id` and body.

Supported `decision.outcome` values:

- `accepted`
- `rejected`
- `changes_requested`
- `deferred`

Supported `ballot.mode` values:

- `working-group`
- `committee`
- `member-ballot`
- `public-review`

## Verification

`trustai standards-body-ballot-verify` checks:

1. Schema, canonical `ballot_id`, and signature.
2. Timestamp ordering: `opened_at <= closed_at <= decided_at <= effective_at`.
3. Vote-count integrity: `vote_count = votes_for + votes_against + abstentions`.
4. Quorum integrity: `quorum_met = vote_count >= quorum_required`.
5. Approval integrity: `approval_met` uses
   `votes_for / (votes_for + votes_against)`.
6. Accepted outcomes require quorum and approval threshold.
7. Rejected outcomes require quorum.
8. Source submission receipt validity when supplied.
9. Optional status receipt validity and context binding when supplied.
10. `ballot_payload_hash` matches the normalized ballot and decision records.

## Evidence Chain Entry

`trustai standards-body-ballot-append` verifies the receipt, then appends an
entry of type `standards.body.ballot.certified` with:

- `ballot_id`
- `ballot_hash`
- target submission record
- optional status context
- ballot and decision records
- source artifact references
- limitations

## Reference Commands

```powershell
$env:PYTHONPATH = "src"
python -m trustai standards-body-ballot artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --ballot-ref LF-TRUSTAI-BALLOT-2026-001 --decision-ref LF-TRUSTAI-DECISION-2026-001 --motion "Accept TrustAI proof-pack v0.1 as a working-group draft specification." --eligible-voters 7 --votes-for 6 --votes-against 1 --abstentions 0 --quorum-required 4 --approval-threshold-percent 66 --opened-at 2026-07-19T00:00:00Z --closed-at 2026-07-25T00:00:00Z --decided-at 2026-07-25T02:00:00Z --effective-at 2026-07-25T03:00:00Z --minutes-ref minutes:trustai-wg/2026-07-25 --actor-ref oidc:standards.example/chair-1 --actor-role working-group-chair --evidence-ref minutes:trustai-wg/2026-07-25 --out artifacts/standards-body-ballot.json
python -m trustai standards-body-ballot-verify artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json
python -m trustai standards-body-ballot-append artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --state .trustai/standards-body-ballot-demo/evidence-chain.json --tenant standards-body-ballot-local --out artifacts/standards-body-ballot-entry.json
```

## Production Boundary

This v0.1 receipt is a local reference artifact. Production standards-track
acceptance should replace local actor references with authenticated standards
body identities, signed ballot-system exports, formal meeting minutes, public
docket URLs, and publication records from the standards body.
