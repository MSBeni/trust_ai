# Auditor Accreditation Signing Ceremony Receipt v0.1

## Purpose

The auditor accreditation signing ceremony receipt records sponsor-controlled
signing evidence for an auditor accreditation countersignature. It binds the
credential operation to key metadata, sponsor operator identity, approver quorum,
witness evidence, authority references, policy references, and optional signing
backend response hashes.

This receipt is the local reference bridge between a sponsor-countersigned
accreditation operation and a production sponsor-owned HSM/KMS ceremony.

## Schema

`schema`: `trustai.auditor-accreditation-signing-ceremony/0.1`

Required top-level fields:

- `ceremony_id`: canonical hash of the receipt body without signatures.
- `mode`: one of `local-reference`, `sponsor-controlled`, or
  `recorded-response`.
- `ceremony_at`: RFC 3339 timestamp at or after the source countersignature
  `signed_at` timestamp.
- `source`: normalized countersignature summary including canonical hash,
  operation, credential, sponsor, actor, and timing fields.
- `ceremony`: ceremony reference, mode, timestamp, authority reference, policy
  reference, and evidence references.
- `signing_service`: signing system name, endpoint, redacted credential
  reference, attestation mode, and production replacement note.
- `signing_key`: key provider, key reference, algorithm, optional public key,
  rotation, and revocation references.
- `participants`: sponsor operator, approver references, witness references,
  quorum requirement, and quorum result.
- `source_artifacts`: exactly one source artifact named
  `auditor_accreditation_countersignature_receipt`.
- `ceremony_payload_hash`: canonical hash over the normalized source, ceremony,
  signing service, signing key, participants, and source artifact records.
- `signatures`: detached signatures over `ceremony_id` and the receipt body.

`sponsor-controlled` and `recorded-response` modes require:

- source countersignature mode `sponsor-countersigned`;
- sponsor operator reference;
- signing key reference;
- authority reference;
- policy reference;
- approver quorum satisfied.

`recorded-response` mode additionally requires an accepted provider response
hash from the signing backend.

## Verification

`trustai auditor-accreditation-signing-ceremony-verify` checks:

- schema and canonical `ceremony_id`;
- receipt signature;
- timestamp ordering from countersignature to ceremony;
- source countersignature mode and source artifact hash;
- supplied countersignature receipt validity and upstream accreditation,
  sponsorship, ballot, standards package, verifier release, and conformance
  evidence when provided;
- redacted signing credential reference;
- sponsor-controlled key, operator, authority, policy, and quorum requirements;
- recorded response requirements;
- `ceremony_payload_hash` consistency.

Verification can run with only the ceremony receipt, but source binding is
strongest when the countersignature and its upstream evidence are supplied.

## Chain Entry

`trustai auditor-accreditation-signing-ceremony-append` verifies the receipt and
appends entry type:

`auditor.accreditation.signing_ceremony.recorded`

The chain entry includes:

- `ceremony_id`;
- canonical receipt hash;
- mode;
- source countersignature summary;
- ceremony metadata;
- signing service and key metadata;
- participants and quorum result;
- optional response hash;
- source artifact references;
- limitations.

## Reference Commands

```powershell
python -m trustai auditor-accreditation-signing-ceremony artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --mode sponsor-controlled --ceremony-ref LF-TRUSTAI-AUD-CS-2026-001:ceremony --signing-system LFTrustAISponsorSigningHSM --signing-endpoint https://signing.example/accreditations --key-provider lf-trustai-hsm --key-ref kms:lf-trustai/auditor-accreditation-signing --public-key-ref https://standards.example/keys/auditor-accreditation-signing.pub --credential-ref env:SPONSOR_SIGNING_TOKEN --sponsor-operator-ref oidc:standards.example/accreditation-sponsor-1 --approver-ref oidc:standards.example/chair-1 --approver-ref oidc:standards.example/secretary-1 --witness-ref audit-log:lf-trustai/signing/2026-07-26 --quorum-required 2 --authority-ref minutes:trustai-wg/2026-07-26 --policy-ref policy:auditor-accreditation-signing-v0.1 --rotation-ref key-rotation:lf-trustai/2026-Q3 --revocation-ref crl:lf-trustai/auditor-accreditation-signing --evidence-ref minutes:trustai-wg/2026-07-26 --ceremony-at 2026-07-26T00:30:00Z --out artifacts/auditor-accreditation-signing-ceremony.json
python -m trustai auditor-accreditation-signing-ceremony-verify artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json
python -m trustai auditor-accreditation-signing-ceremony-append artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --state .trustai/auditor-accreditation-signing-ceremony-demo/evidence-chain.json --tenant auditor-accreditation-signing-ceremony-local --out artifacts/auditor-accreditation-signing-ceremony-entry.json
```

## Production Boundary

The local receipt records sponsor-controlled signing ceremony structure and
hashes. A production ceremony must supply sponsor-owned HSM/KMS enforcement,
public key publication, immutable audit logs, credential rotation and revocation
records, and independently reviewable witness evidence.
