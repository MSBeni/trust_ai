# TrustAI Auditor Accreditation Receipt v0.1

This specification defines a signed receipt for issuing a local-reference
auditor accreditation credential over a TrustAI auditor certification kit. It
turns the training kit into chain-backed credential evidence without claiming
that an external standards body or public auditor registry exists.

## Schema

`schema`: `trustai.auditor-accreditation/0.1`

Required top-level fields:

- `accreditation_id`: canonical hash of the accreditation receipt body.
- `issued_at`: RFC3339 credential issuance timestamp.
- `expires_at`: optional RFC3339 credential expiry timestamp.
- `accreditation_body`: accrediting program name, program reference,
  attestation mode, and production replacement note.
- `auditor`: auditor name, organization, subject reference, and role.
- `credential`: credential id, status, scope, score, minimum score, issue time,
  optional expiry, renewal due time, proctor reference, and evidence references.
- `source_artifacts`: exactly one canonical hash record for the source auditor
  certification kit.
- `controls`: implemented-reference, local-reference, and planned-production
  controls for certification-kit binding, auditor identity binding, proctored
  exam evidence, credential registry, and renewal/revocation governance.
- `limitations`: explicit local-reference and production-boundary statements.
- `signatures`: detached local HMAC signature over the accreditation id and
  receipt body.

`credential.status` is one of `active`, `suspended`, or `revoked`.

## Verification

`trustai auditor-accreditation-verify` checks:

- schema, canonical `accreditation_id`, and signature;
- issue, expiry, renewal, and optional current-time expiry checks;
- accreditation body name and program reference;
- auditor name, organization, and subject reference;
- credential id, status, scope, score, and minimum score;
- exactly one source auditor-certification-kit artifact;
- certification-kit source hash and full kit verification when supplied;
- minimum score and scope consistency with the source kit rubric.

Without the source auditor certification kit, verification can only prove the
receipt integrity and embedded kit hash. It emits a warning for the missing
deep-verification input.

## Evidence Chain Entry

`trustai auditor-accreditation-append` verifies the receipt, then appends
`auditor.accreditation.issued` to an evidence chain. The entry payload records
the accreditation id, receipt hash, accreditation body, auditor identity,
credential, source kit reference, and limitations.

## Reference Commands

```powershell
python -m trustai auditor-accreditation artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --auditor-name "Example Audit LLP" --auditor-ref oidc:auditor.example/reviewer-123 --auditor-organization "Example Audit LLP" --auditor-role external-ai-auditor --accreditation-body "TrustAI Auditor Program" --program-ref TRUSTAI-AUDITOR-0.1 --credential-id TA-AUD-2026-001 --score-percent 92 --issued-at 2026-07-15T00:00:00Z --expires-at 2027-07-15T00:00:00Z --renewal-due-at 2027-06-15T00:00:00Z --proctor-ref oidc:trustai.example/proctor-1 --evidence-ref exam:TRUSTAI-AUD-2026-001 --out artifacts/auditor-accreditation.json
python -m trustai auditor-accreditation-verify artifacts/auditor-accreditation.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json
python -m trustai auditor-accreditation-append artifacts/auditor-accreditation.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --state .trustai/auditor-accreditation-demo/evidence-chain.json --tenant auditor-accreditation-local --out artifacts/auditor-accreditation-entry.json
```

## Production Boundary

This local receipt is useful for repeatable auditor accreditation evidence in a
reference implementation. A production auditor ecosystem still needs
independent program governance, identity-proofed and proctored exams, public
credential registry publication, renewal and revocation workflows, and
standards-body or industry-program sponsorship.
