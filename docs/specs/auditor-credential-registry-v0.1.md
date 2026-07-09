# TrustAI Auditor Credential Registry Receipt v0.1

This specification defines a signed receipt for publishing an auditor
accreditation credential into a local-reference credential registry. It follows
the roadmap's auditor ecosystem goal by making credential publication
verifiable without requiring a hosted public registry.

## Schema

`schema`: `trustai.auditor-credential-registry/0.1`

Required top-level fields:

- `registry_id`: canonical hash of the registry receipt body.
- `published_at`: RFC3339 publication timestamp.
- `expires_at`: optional RFC3339 registry publication expiry. By default it
  follows the source accreditation expiry.
- `registry`: registry name, endpoint, namespace, attestation mode, and
  production replacement note.
- `publication`: publication reference, credential status, visibility, optional
  terms reference, revocation endpoint, operator reference, and idempotency key.
- `credential_record`: public credential record derived from the source auditor
  accreditation receipt.
- `registry_payload_hash`: canonical hash of the publication and credential
  record payload.
- `source_artifacts`: exactly one canonical hash record for the source auditor
  accreditation receipt.
- `controls`: accreditation source binding, public credential record,
  revocation endpoint, operator authentication, and propagation audit controls.
- `limitations`: explicit local-reference and production-boundary statements.
- `signatures`: detached local HMAC signature over the registry id and receipt
  body.

`publication.status` is one of `active`, `suspended`, or `revoked`, and it must
match the source accreditation credential status. `publication.visibility` is
one of `private`, `partner`, or `public`.

## Verification

`trustai auditor-credential-registry-verify` checks:

- schema, canonical `registry_id`, and signature;
- publication and expiry timestamps, including optional current-time expiry;
- registry name, endpoint, and namespace;
- publication reference, status, visibility, and idempotency key;
- credential record id, accreditation id, auditor subject, and status binding;
- registry payload hash consistency;
- exactly one source auditor-accreditation artifact;
- source accreditation hash and full accreditation verification when supplied;
- credential record/status consistency with the source accreditation receipt;
- registry expiry does not exceed source accreditation expiry.

Without the source auditor accreditation receipt, verification can only prove
receipt integrity and the embedded source hash. It emits a warning for the
missing deep-verification input.

## Evidence Chain Entry

`trustai auditor-credential-registry-append` verifies the receipt, then appends
`auditor.credential.registry.published` to an evidence chain. The entry payload
records the registry id, receipt hash, registry metadata, publication metadata,
credential record, source accreditation reference, and limitations.

## Reference Commands

```powershell
python -m trustai auditor-credential-registry artifacts/auditor-accreditation.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --registry-name "TrustAI Auditor Credential Registry" --registry-endpoint https://auditors.example --namespace trustai-auditors --publication-ref AUD-REG-2026-001 --revocation-endpoint https://auditors.example/revocations/TA-AUD-2026-001 --operator-ref oidc:trustai.example/registry-operator --published-at 2026-07-16T00:00:00Z --out artifacts/auditor-credential-registry.json
python -m trustai auditor-credential-registry-verify artifacts/auditor-credential-registry.json --accreditation artifacts/auditor-accreditation.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json
python -m trustai auditor-credential-registry-append artifacts/auditor-credential-registry.json --accreditation artifacts/auditor-accreditation.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --state .trustai/auditor-credential-registry-demo/evidence-chain.json --tenant auditor-credential-registry-local --out artifacts/auditor-credential-registry-entry.json
```

## Production Boundary

This local receipt models credential publication evidence for the reference
implementation. A production auditor credential registry still needs
authenticated registry operators, public index hosting, verifier cache
propagation, renewal and revocation workflows, subscriber notifications, and
standards-body or industry-program sponsorship.
