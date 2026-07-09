# Auditor Accreditation KMS Enforcement Receipt v0.1

This receipt binds an auditor accreditation signing audit to sponsor-owned
HSM/KMS enforcement evidence. It is the local verification contract for proving
that a sponsor signing key is governed by key custody, public key publication,
immutable audit logs, key policy, quorum, rotation, and revocation controls.

It narrows the production gap between a published signing audit and a live
sponsor-controlled HSM/KMS workflow. The local artifact verifies the evidence
shape offline; production deployments must replace local references with cloud
KMS/HSM attestation exports, provider key-policy exports, and externally
retained audit logs.

## Schema

`schema`: `trustai.auditor-accreditation-kms-enforcement/0.1`

Required top-level fields:

- `mode`: one of `local-reference`, `policy-bound`, `hsm-attested`,
  `provider-enforced`.
- `enforced_at`: RFC 3339 timestamp at or after the source signing audit
  `published_at`.
- `source`: canonical summary of the source signing audit, including audit ID,
  content hash, key publication, source signing key, and immutable audit-log
  root.
- `enforcement`: enforcement reference, mode, timestamp, and evidence
  references.
- `enforcement_service`: provider, endpoint, redacted credential reference,
  actor reference, and attestation mode.
- `key_custody`: provider, key reference, algorithm, status, ownership,
  public key reference/fingerprint, attestation reference/hash, rotation, and
  revocation references.
- `key_policy`: policy reference/hash, allowed actors, permitted key usage,
  denied operations, required quorum, approvers, and quorum result.
- `audit_log`: immutable audit-log reference/root/size/algorithm copied from
  the source signing audit unless explicitly supplied.
- `source_artifacts`: exactly one
  `auditor_accreditation_signing_audit_receipt` artifact reference.
- `enforcement_payload_hash`: canonical hash of source, enforcement service,
  key custody, key policy, audit log, and source artifacts.
- `enforcement_id`: canonical hash of the receipt body.
- `signatures`: detached signature over `{enforcement_id, kms_enforcement}`.

`provider-enforced` mode additionally requires:

- `enforcement_service.actor_ref`.
- `response.status`, `response.body_hash`, and accepted 2xx status.

`hsm-attested` and `provider-enforced` modes additionally require:

- HSM/KMS attestation reference and attestation hash.
- Public key reference and fingerprint matching the source signing audit.
- Immutable audit-log reference/root/size matching the source signing audit.

`policy-bound`, `hsm-attested`, and `provider-enforced` modes additionally
require:

- Key policy reference and hash.
- Non-empty allowed actor references.
- Signing usage in `key_policy.key_usage`.
- Quorum approvers satisfying `key_policy.quorum_required`.

## Verification

`trustai auditor-accreditation-kms-enforcement-verify` checks:

1. Schema, canonical `enforcement_id`, and detached signature.
2. `enforced_at` is not earlier than the source signing audit publication
   timestamp and is not in the future when `--now` is supplied.
3. Non-local modes are backed by a provider-anchored signing audit source.
4. Source artifact content hash and source summary match the supplied signing
   audit receipt.
5. The supplied signing audit receipt verifies, including its signing ceremony
   and upstream accreditation sources when supplied.
6. Credential references are redacted.
7. Key reference, public key reference, fingerprint, audit-log reference, and
   audit-log root match the source signing audit.
8. Attestation and key-policy references/hashes are present for enforcement
   modes that claim them.
9. Actor authorization and quorum controls satisfy the key policy.
10. Provider-enforced mode includes an accepted provider response hash.
11. `enforcement_payload_hash` matches the canonical enforcement records.

## Chain Entry

`trustai auditor-accreditation-kms-enforcement-append` verifies the receipt and
appends an `auditor.accreditation.kms_enforcement.recorded` chain entry with:

- `enforcement_id` and enforcement hash.
- Source signing audit summary.
- Enforcement service and key custody evidence.
- Key policy and immutable audit-log binding.
- Provider response hash when present.
- Source artifact references and limitations.

## Reference Commands

```powershell
python -m trustai auditor-accreditation-kms-enforcement artifacts/auditor-accreditation-signing-audit.json --signing-ceremony artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --mode provider-enforced --enforcement-ref LF-TRUSTAI-AUD-CS-2026-001:kms-enforcement --provider LFTrustAISponsorKMS --provider-endpoint https://kms.example/signing/auditor-accreditation --credential-ref env:SPONSOR_KMS_TOKEN --actor-ref oidc:standards.example/accreditation-sponsor-1 --attestation-ref hsm-attestation:lf-trustai/auditor-accreditation-signing/2026-07-26 --attestation-hash sha256:lf-trustai-hsm-attestation-20260726 --key-policy-ref key-policy:lf-trustai/auditor-accreditation-signing/v0.1 --key-policy-hash sha256:lf-trustai-auditor-accreditation-key-policy --allowed-actor-ref oidc:standards.example/accreditation-sponsor-1 --denied-operation-ref kms:decrypt --denied-operation-ref kms:export-private-key --quorum-required 2 --quorum-approver-ref oidc:standards.example/chair-1 --quorum-approver-ref oidc:standards.example/secretary-1 --evidence-ref hsm-attestation:lf-trustai/auditor-accreditation-signing/2026-07-26 --response-status 200 --enforced-at 2026-07-26T01:00:00Z --out artifacts/auditor-accreditation-kms-enforcement.json
python -m trustai auditor-accreditation-kms-enforcement-verify artifacts/auditor-accreditation-kms-enforcement.json --signing-audit artifacts/auditor-accreditation-signing-audit.json --signing-ceremony artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json
python -m trustai auditor-accreditation-kms-enforcement-append artifacts/auditor-accreditation-kms-enforcement.json --signing-audit artifacts/auditor-accreditation-signing-audit.json --signing-ceremony artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --state .trustai/auditor-accreditation-kms-enforcement-demo/evidence-chain.json --tenant auditor-accreditation-kms-enforcement-local --out artifacts/auditor-accreditation-kms-enforcement-entry.json
```

## Production Boundary

This v0.1 receipt is intentionally offline-verifiable. A production sponsor
must supply provider-native HSM/KMS attestation, exportable key policy evidence,
public verification material, and immutable audit-log retention evidence. The
receipt format makes those controls explicit so third parties can reject packs
that only contain local placeholders.
