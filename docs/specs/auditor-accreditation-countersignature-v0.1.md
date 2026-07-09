# Auditor Accreditation Countersignature Receipt v0.1

Status: local reference specification

## Purpose

An auditor accreditation countersignature receipt records sponsor approval for a
specific auditor accreditation operation. It binds an auditor accreditation
receipt to an active auditor program sponsorship receipt, then records the
operation, sponsor actor reference, authority reference, terms reference,
evidence references, and source artifact hashes.

This receipt narrows the gap between local accreditation issuance and
production sponsor-countersigned accreditation operations. It does not claim a
sponsor-controlled signing ceremony unless the source artifacts, actor
references, and response evidence come from the sponsor-controlled workflow.

## Schema

`schema`: `trustai.auditor-accreditation-countersignature/0.1`

Required top-level fields:

- `countersignature_id`: canonical hash of the receipt body.
- `signed_at`, `effective_at`, `expires_at`: RFC 3339 timestamps, with
  `expires_at` optional.
- `operation`: operation name, operation reference, credential status, and
  operation timing.
- `accreditation`: source accreditation identity, auditor subject, credential
  status, scope, and program reference.
- `sponsorship`: active sponsorship identity, program reference, sponsor
  reference, scope, and effective window.
- `sponsor`: sponsor body, sponsor reference, sponsorship reference, mode, and
  authorized scope.
- `countersignature`: countersignature reference, mode, actor reference, terms
  reference, and evidence references.
- `source_artifacts`: canonical hashes for the accreditation and sponsorship
  receipts.
- `countersignature_payload_hash`: canonical hash over operation,
  accreditation, sponsorship, sponsor, countersignature, and source artifacts.
- `signatures`: detached local reference signatures over `countersignature_id`
  and body.

Supported `operation.operation` values:

- `issue`
- `renew`
- `suspend`
- `revoke`
- `reinstate`

Supported `countersignature.mode` values:

- `local-reference`
- `sponsor-countersigned`
- `recorded-response`

## Verification

`trustai auditor-accreditation-countersignature-verify` checks:

1. Schema, canonical `countersignature_id`, and signature.
2. Timestamp ordering: `signed_at <= effective_at < expires_at` when expiry is
   supplied.
3. Operation is supported and matches the credential status.
4. Source accreditation receipt validity when supplied.
5. Source sponsorship receipt validity when supplied.
6. Sponsorship status is `active`.
7. Accreditation program reference and accreditation body match the active
   sponsorship program.
8. Sponsorship scope includes `auditor-accreditation`.
9. Sponsor-countersigned mode includes a sponsor actor reference.
10. Source artifact hashes match supplied source receipts.
11. `countersignature_payload_hash` matches the normalized operation and source
   records.

## Evidence Chain Entry

`trustai auditor-accreditation-countersignature-append` verifies the receipt,
then appends an entry of type `auditor.accreditation.countersigned` with:

- `countersignature_id`
- `countersignature_hash`
- operation record
- accreditation record
- sponsorship and sponsor records
- countersignature actor and terms metadata
- optional response hash
- source artifact references
- limitations

## Reference Commands

```powershell
$env:PYTHONPATH = "src"
python -m trustai auditor-accreditation-countersignature artifacts/auditor-accreditation.json artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --operation issue --mode sponsor-countersigned --countersignature-ref LF-TRUSTAI-AUD-CS-2026-001 --operation-ref TA-AUD-2026-001:issue --sponsor-actor-ref oidc:standards.example/accreditation-sponsor-1 --sponsor-actor-role working-group-chair --authority-ref minutes:trustai-wg/2026-07-26 --terms-ref charter:trustai-auditor-program-v0.1 --evidence-ref minutes:trustai-wg/2026-07-26 --signed-at 2026-07-26T00:00:00Z --effective-at 2026-07-26T01:00:00Z --expires-at 2027-07-15T00:00:00Z --out artifacts/auditor-accreditation-countersignature.json
python -m trustai auditor-accreditation-countersignature-verify artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json
python -m trustai auditor-accreditation-countersignature-append artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --state .trustai/auditor-accreditation-countersignature-demo/evidence-chain.json --tenant auditor-accreditation-countersignature-local --out artifacts/auditor-accreditation-countersignature-entry.json
```

## Production Boundary

This v0.1 receipt is a local reference artifact. Production sponsor
countersigning should replace local actor references with sponsor-controlled
signing keys, public authorization records, accreditation operation workflow
records, immutable response archives, and sponsor-operated revocation or appeal
handling.
