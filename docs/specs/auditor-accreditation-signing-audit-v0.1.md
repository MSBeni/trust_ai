# Auditor Accreditation Signing Audit Receipt v0.1

## Purpose

The auditor accreditation signing audit receipt records public key publication
and immutable signing-backend audit evidence for a sponsor-controlled auditor
accreditation signing ceremony.

It binds a signing ceremony to:

- public key reference and fingerprint;
- key status, rotation, and revocation references;
- immutable audit-log root, size, algorithm, entry, and export references;
- publication actor, credential reference, response hash, witness references,
  retention metadata, and evidence references.

This receipt narrows the boundary between a local sponsor-controlled ceremony
and production sponsor-owned HSM/KMS evidence.

## Schema

`schema`: `trustai.auditor-accreditation-signing-audit/0.1`

Required top-level fields:

- `audit_id`: canonical hash of the receipt body without signatures.
- `mode`: one of `local-reference`, `public-key-published`,
  `immutable-audit-log`, or `provider-anchored`.
- `published_at`: RFC 3339 timestamp at or after the source ceremony time.
- `source`: normalized signing ceremony summary including ceremony id, hash,
  mode, key metadata, service metadata, participant quorum, and source
  countersignature reference.
- `publisher`: publisher name, endpoint, redacted credential reference, actor
  reference, attestation mode, and production replacement note.
- `key_publication`: key publication reference, key ref, public key reference,
  fingerprint, status, rotation reference, revocation reference, and publication
  timestamp.
- `audit_log`: audit-log reference, root, size, algorithm, entry reference,
  export reference, retention timestamp, and witness references.
- `audit`: audit reference, mode, and evidence references.
- `source_artifacts`: exactly one source artifact named
  `auditor_accreditation_signing_ceremony_receipt`.
- `audit_payload_hash`: canonical hash over source, publisher, key publication,
  audit log, audit, and source artifacts.
- `signatures`: detached signatures over `audit_id` and the receipt body.

`public-key-published` and `provider-anchored` modes require public key
reference and fingerprint. `immutable-audit-log` and `provider-anchored` modes
require audit log reference, root, algorithm, and positive log size.
`provider-anchored` additionally requires an actor reference and accepted
provider response hash.

## Verification

`trustai auditor-accreditation-signing-audit-verify` checks:

- schema and canonical `audit_id`;
- receipt signature;
- timestamp ordering from ceremony to publication;
- source ceremony mode and source artifact hash;
- supplied signing ceremony validity and upstream countersignature,
  accreditation, sponsorship, standards package, verifier release, and
  conformance evidence when supplied;
- redacted publication credential reference;
- key publication fields and key reference binding to the source ceremony;
- immutable audit-log fields and retention ordering;
- provider response requirements for provider-anchored mode;
- `audit_payload_hash` consistency.

Verification can run with only the audit receipt, but source binding is strongest
when the signing ceremony receipt and upstream evidence are supplied.

## Chain Entry

`trustai auditor-accreditation-signing-audit-append` verifies the receipt and
appends entry type:

`auditor.accreditation.signing_audit.recorded`

The chain entry includes:

- `audit_id`;
- canonical receipt hash;
- mode;
- source ceremony summary;
- publisher metadata;
- key publication metadata;
- audit log metadata;
- optional provider response hash;
- source artifact references;
- limitations.

## Reference Commands

```powershell
python -m trustai auditor-accreditation-signing-audit artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --mode provider-anchored --audit-ref LF-TRUSTAI-AUD-CS-2026-001:audit --publisher LFTrustAISigningTransparency --publication-endpoint https://standards.example/signing-audit --credential-ref env:SPONSOR_SIGNING_AUDIT_TOKEN --actor-ref oidc:standards.example/accreditation-sponsor-1 --public-key-ref https://standards.example/keys/auditor-accreditation-signing.pub --public-key-fingerprint sha256:lf-trustai-auditor-accreditation-signing --publication-ref KEYPUB-2026-TRUSTAI-AUD-001 --rotation-ref key-rotation:lf-trustai/2026-Q3 --revocation-ref crl:lf-trustai/auditor-accreditation-signing --audit-log-ref audit-log:lf-trustai/signing/2026-07-26 --audit-log-root 8c93d55abc6b8425ace8b488ab53ff0ef0ac79d6231cdfe6d5b7dc0c5268eaa2 --audit-log-size 4 --audit-log-entry-ref audit-log-entry:LF-TRUSTAI-AUD-CS-2026-001 --audit-log-export-ref audit-export:LF-TRUSTAI-AUD-CS-2026-001 --retention-until 2033-07-26T00:00:00Z --witness-ref audit-log:lf-trustai/signing/2026-07-26 --evidence-ref key-publication:KEYPUB-2026-TRUSTAI-AUD-001 --response-status 201 --published-at 2026-07-26T00:45:00Z --out artifacts/auditor-accreditation-signing-audit.json
python -m trustai auditor-accreditation-signing-audit-verify artifacts/auditor-accreditation-signing-audit.json --signing-ceremony artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json
python -m trustai auditor-accreditation-signing-audit-append artifacts/auditor-accreditation-signing-audit.json --signing-ceremony artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --state .trustai/auditor-accreditation-signing-audit-demo/evidence-chain.json --tenant auditor-accreditation-signing-audit-local --out artifacts/auditor-accreditation-signing-audit-entry.json
```

## Production Boundary

The local receipt records key publication and audit-log structure by hash. A
production deployment must supply sponsor-owned HSM/KMS enforcement, public key
transparency infrastructure, immutable audit-log storage, retention enforcement,
provider authentication, and externally reviewable audit witnesses.
