# Standards-Body Submission Receipt v0.1

This specification defines a signed receipt for submitting the TrustAI proof-pack
specification package, verifier release manifest, and verifier conformance report
to a standards-body track. It makes the submitted docket evidence verifiable
without claiming that an external standards body has accepted, balloted, or
approved the format.

## Schema

`schema`: `trustai.standards-body-submission/0.1`

Required top-level fields:

- `submission_id`: canonical hash of the receipt body.
- `submitted_at`: RFC3339 submission timestamp.
- `acknowledgement_due_at`: optional RFC3339 timestamp after `submitted_at`.
- `standards_body`: body name, program reference, target track, endpoint,
  contact reference, attestation mode, and production replacement note.
- `submission`: submission reference, status, channel, submitter reference,
  subject, version label, terms reference, and idempotency key.
- `package`: standards package id, target body, status, spec counts, and
  canonical content hash from `trustai.standards-submission/0.1`.
- `verifier_release`: verifier release id, version, implementation, command,
  mode, content hash, source report/package ids, release conformance targets,
  per-target conformance counts, and optional provider-bundle source binding
  from `trustai.verifier-release/0.1`.
- `conformance_report`: verifier conformance report id, command, mode, case
  counts, passed/failed counts, conformance targets, per-target case/pass
  counts, source proof-pack summary, optional provider-bundle source binding,
  and canonical content hash from `trustai.verifier-conformance/0.1`.
- `submission_payload_hash`: canonical hash over the standards body name,
  submission metadata, package record, verifier release record, and conformance
  report record.
- `source_artifacts`: exactly three canonical hash records for the standards
  package, verifier release manifest, and verifier conformance report.
- `controls`: submission, source binding, docket reference, contact route, and
  acknowledgement controls.
- `limitations`: explicit local-reference and production-boundary statements.
- `signatures`: detached local HMAC signature over the submission id and receipt
  body.

`submission.status` is one of `submitted`, `acknowledged`, `accepted`,
`rejected`, or `withdrawn`. `submission.channel` is one of `repository`, `email`,
`portal`, `api`, or `working-group`.

## Verification

`trustai standards-body-verify` checks:

- schema, canonical `submission_id`, and signature;
- submission and acknowledgement timestamps, including overdue acknowledgement
  detection for receipts still in `submitted` status;
- standards body name, program reference, submission reference, status, channel,
  submitter reference, and idempotency key;
- package, verifier release, and conformance report records, including verifier
  conformance target coverage and optional provider-bundle source binding;
- submission payload hash consistency;
- exactly three source artifact records;
- source standards package hash and full standards package verification when
  supplied;
- source verifier conformance report hash and full report verification when
  supplied;
- source verifier release manifest hash and full release verification when
  supplied;
- verifier release references match the submitted standards package,
  conformance report, conformance target coverage, and optional provider-bundle
  source binding.

Without source artifacts, verification can only prove receipt integrity and the
embedded source hashes. It emits warnings for missing deep-verification inputs.

## Evidence Chain Entry

`trustai standards-body-append` verifies the receipt, then appends
`standards.body.submitted` to an evidence chain. The entry payload records the
submission id, receipt hash, standards-body metadata, submission metadata,
package record, verifier release record, conformance report scope record, source
artifact references, and limitations.

## Reference Commands

```powershell
python -m trustai standards-body-submit --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-body "Linux Foundation TrustAI Working Group" --program-ref LF-TRUSTAI-PROOF-PACKS --target-track draft-specification --endpoint https://standards.example/submissions/trustai --contact-ref wg:trustai-proof-packs --submission-ref STD-TRUSTAI-2026-001 --submitted-at 2026-07-17T00:00:00Z --acknowledgement-due-at 2026-08-17T00:00:00Z --out artifacts/standards-body-submission.json
python -m trustai standards-body-verify artifacts/standards-body-submission.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json
python -m trustai standards-body-append artifacts/standards-body-submission.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --state .trustai/standards-body-demo/evidence-chain.json --tenant standards-body-local --out artifacts/standards-body-submission-entry.json
```

## Production Boundary

This local receipt models standards-track submission evidence for the reference
implementation. Production standards work still needs authenticated submission
accounts, standards-body acknowledgements, docket status feeds, working-group
change control, independent implementer participation, ballot/appeal handling,
and public compatibility policy.
