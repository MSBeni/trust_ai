# Auditor Program Governance Receipt v0.1

This specification defines a signed receipt for local-reference governance of
the TrustAI auditor accreditation program. It sits between the auditor
certification kit and individual auditor accreditation receipts: the kit defines
what auditors must learn and prove, while this receipt records who governs the
program, which policies apply, and which source artifacts the program is based
on.

It does not claim independent accreditation authority, external proctoring,
public registry operation, or standards-body sponsorship. It provides an
offline-verifiable shape for those governance records and makes them appendable
chain evidence.

## Schema

`schema`: `trustai.auditor-program-governance/0.1`

Required top-level fields:

- `program_id`: canonical hash of the receipt body.
- `issued_at`: RFC3339 timestamp when the governance receipt was issued.
- `effective_at`: RFC3339 timestamp when the governance program takes effect.
- `expires_at`: optional RFC3339 timestamp after `effective_at`.
- `program`: program name, program reference, version, status, accreditation
  body, attestation mode, and production replacement note.
- `governance`: governance body, governance reference, governance mode,
  operator reference, board members, policy references, and evidence
  references.
- `source_artifacts`: canonical hash records for the auditor certification kit
  and, when supplied, the standards submission package.
- `governance_payload_hash`: canonical hash over the program, governance, and
  source artifact records.
- `controls`: certification-kit binding, board governance, independence,
  proctoring, renewal/revocation/appeal, registry operation, and external
  sponsorship controls.
- `limitations`: explicit local-reference and production-boundary statements.
- `signatures`: detached local HMAC signature over the program id and receipt
  body.

`program.status` is one of `draft`, `active`, `suspended`, or `retired`.
`governance.governance_mode` is one of `local-reference`,
`independent-board`, `standards-body-sponsored`, or `industry-consortium`.

## Verification

`trustai auditor-program-governance-verify` checks:

- schema, canonical `program_id`, and signature;
- issued/effective/expiry timestamps, including optional current-time expiry;
- program name, program reference, version, status, and accreditation body;
- governance body, governance reference, governance mode, operator reference,
  and non-empty board member references;
- governance payload hash consistency;
- required certification-kit source artifact;
- source auditor certification kit hash and full kit verification when supplied;
- source standards package hash and full standards package verification when
  supplied;
- program version consistency with the certification kit `program_version`.

Without source artifacts, verification can only prove receipt integrity and
embedded source hash binding. It emits warnings for missing deep-verification
inputs.

## Evidence Chain Entry

`trustai auditor-program-governance-append` verifies the receipt, then appends
`auditor.program.governance.published` to an evidence chain. The entry payload
records the program id, receipt hash, program metadata, governance metadata,
source artifact references, and limitations.

## Reference Commands

```powershell
python -m trustai auditor-program-governance artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --program-name "TrustAI Auditor Program" --program-ref TRUSTAI-AUDITOR-0.1 --accreditation-body "TrustAI Auditor Program" --governance-body "TrustAI Auditor Governance Board" --governance-ref TRUSTAI-AUD-GOV-2026-001 --operator-ref oidc:trustai.example/program-operator --board-member oidc:trustai.example/board-1 --board-member oidc:trustai.example/board-2 --independence-policy-ref policy:auditor-independence-v0.1 --proctoring-policy-ref policy:auditor-proctoring-v0.1 --revocation-policy-ref policy:auditor-revocation-v0.1 --renewal-policy-ref policy:auditor-renewal-v0.1 --appeals-policy-ref policy:auditor-appeals-v0.1 --registry-ref registry:trustai-auditors --evidence-ref minutes:TRUSTAI-AUD-GOV-2026-001 --issued-at 2026-07-14T00:00:00Z --effective-at 2026-07-14T01:00:00Z --expires-at 2027-07-14T00:00:00Z --out artifacts/auditor-program-governance.json
python -m trustai auditor-program-governance-verify artifacts/auditor-program-governance.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json
python -m trustai auditor-program-governance-append artifacts/auditor-program-governance.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --state .trustai/auditor-program-governance-demo/evidence-chain.json --tenant auditor-program-governance-local --out artifacts/auditor-program-governance-entry.json
```

## Production Boundary

This local receipt models accreditation program governance for the reference
implementation. A production auditor ecosystem still needs independent program
ownership, board minutes, conflict-of-interest enforcement, proctored exam
delivery, renewal and revocation workflows, appeal handling, public registry
operation, and standards-body or industry-program sponsorship.
