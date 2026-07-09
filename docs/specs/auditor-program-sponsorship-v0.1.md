# Auditor Program Sponsorship Receipt v0.1

Status: local reference specification

## Purpose

An auditor program sponsorship receipt records evidence that an auditor
certification/accreditation program is sponsored or overseen by a standards
body, industry consortium, or independent board.

It binds two source artifacts by canonical hash:

- an auditor program governance receipt
- an accepted standards-body ballot receipt

This narrows the production gap between local auditor governance metadata and
externally operated accreditation governance. It remains a local reference
artifact unless the named sponsor signs or countersigns the receipt.

## Schema

`schema`: `trustai.auditor-program-sponsorship/0.1`

Required top-level fields:

- `sponsorship_id`: canonical hash of the receipt body.
- `issued_at`, `effective_at`, optional `expires_at`: RFC 3339 timestamps.
- `program`: program identity copied from the source auditor governance
  receipt, including `program_id`, `program_ref`, `version`, and
  `governance_mode`.
- `sponsor`: sponsor body, sponsor reference, sponsorship reference,
  sponsorship mode, status, scope, and optional charter/terms/oversight
  references.
- `source_artifacts`: source hashes for the governance and ballot receipts.
- `sponsorship_payload_hash`: canonical hash of `program`, `sponsor`, and
  `source_artifacts`.
- `signatures`: detached local reference signatures over `sponsorship_id` and
  body.

Supported `sponsor.sponsorship_mode` values:

- `standards-body-sponsored`
- `industry-consortium`
- `independent-board`
- `local-reference`

Supported `sponsor.status` values:

- `active`
- `suspended`
- `retired`

## Verification

`trustai auditor-program-sponsorship-verify` checks:

1. Schema, canonical `sponsorship_id`, and signature.
2. Timestamp ordering and expiry.
3. Sponsor identity, sponsorship reference, mode, status, and scope.
4. Source auditor program governance receipt validity when supplied.
5. Source standards-body ballot receipt validity when supplied.
6. Standards-body sponsored receipts bind to an accepted ballot and the
   sponsor body matches the ballot standards body.
7. Source artifact hashes match the supplied source receipts.
8. `sponsorship_payload_hash` matches the normalized program, sponsor, and
   source artifact records.

## Evidence Chain Entry

`trustai auditor-program-sponsorship-append` verifies the receipt, then appends
an entry of type `auditor.program.sponsorship.published` with:

- `sponsorship_id`
- `sponsorship_hash`
- program and sponsor records
- source artifact references
- limitations

## Reference Commands

```powershell
$env:PYTHONPATH = "src"
python -m trustai auditor-program-sponsorship artifacts/auditor-program-governance.json artifacts/standards-body-ballot.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --sponsor-body "Linux Foundation TrustAI Working Group" --sponsor-ref wg:trustai-proof-packs --sponsorship-ref LF-TRUSTAI-AUDITOR-SPONSOR-2026-001 --terms-ref charter:trustai-auditor-program-v0.1 --charter-ref charter:trustai-auditor-program-v0.1 --oversight-ref minutes:trustai-wg/2026-07-25 --evidence-ref minutes:trustai-wg/2026-07-25 --issued-at 2026-07-25T04:00:00Z --effective-at 2026-07-25T05:00:00Z --expires-at 2027-07-25T00:00:00Z --out artifacts/auditor-program-sponsorship.json
python -m trustai auditor-program-sponsorship-verify artifacts/auditor-program-sponsorship.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json
python -m trustai auditor-program-sponsorship-append artifacts/auditor-program-sponsorship.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --state .trustai/auditor-program-sponsorship-demo/evidence-chain.json --tenant auditor-program-sponsorship-local --out artifacts/auditor-program-sponsorship-entry.json
```

## Production Boundary

This v0.1 receipt is a local reference artifact. Production externally operated
accreditation governance should replace local references with sponsor-signed
program charters, public sponsorship records, credentialed board approvals,
renewal/suspension workflows, and public registry obligations.
