# Trust Authority KMS Enforcement Receipt v0.1

This receipt binds a trust authority provider attestation to customer-controlled
KMS/HSM enforcement evidence. It proves, offline, that the provider-attested
signing and RFC 3161 timestamp authority evidence is governed by key custody,
HSM attestation, key policy, timestamp policy, quorum, denied-operation,
provider-response, and immutable audit-log controls.

It narrows the production gap between a recorded KMS/TSA provider attestation
and a live customer-controlled KMS/HSM workflow. The local artifact verifies the
evidence shape and source bindings; production deployments must replace local
references with cloud KMS/HSM attestation exports, provider key-policy exports,
TSA policy exports, and externally retained audit logs.

## Schema

`schema`: `trustai.trust-authority-kms-enforcement/0.1`

Required top-level fields:

- `mode`: one of `local-reference`, `policy-bound`, `hsm-attested`,
  `provider-enforced`.
- `enforced_at`: RFC 3339 timestamp at or after the source provider
  attestation `attested_at`.
- `source`: canonical summary of the source trust-authority provider
  attestation, including the attestation id, trust-authority receipt binding,
  KMS/HSM metadata, timestamp-authority metadata, operation actor, audit-log
  root, and policy hashes.
- `enforcement`: enforcement reference, mode, timestamp, and evidence
  references.
- `enforcement_service`: provider, endpoint, redacted credential reference,
  actor reference, attestation mode, and production replacement note.
- `key_custody`: provider, key reference, algorithm, status, ownership, HSM
  attestation reference/hash, rotation reference, and revocation reference.
- `timestamp_authority`: provider, endpoint, certificate-chain hash,
  timestamp-policy reference/hash, timestamp attestation reference/hash.
- `key_policy`: policy reference/hash, allowed actors, key usage, denied
  operations, required quorum, approvers, and quorum result.
- `audit_log`: immutable audit-log reference, root, retention deadline, size,
  and algorithm copied from the source provider attestation unless explicitly
  supplied.
- `source_artifacts`: exactly one `trust_authority_provider_attestation`
  artifact reference.
- `enforcement_payload_hash`: canonical hash of source, enforcement service,
  key custody, timestamp authority, key policy, audit log, and source
  artifacts.
- `enforcement_id`: canonical hash of the receipt body.
- `signatures`: detached signature over
  `{enforcement_id, trust_authority_kms_enforcement}`.

`provider-enforced` mode additionally requires:

- `enforcement_service.actor_ref`.
- `response.status`, `response.body_hash`, and accepted 2xx status.

`hsm-attested` and `provider-enforced` modes additionally require:

- HSM/KMS attestation reference and attestation hash.
- KMS key reference matching the source provider attestation.
- Timestamp authority certificate-chain hash and immutable audit-log root
  matching the source provider attestation.

`policy-bound`, `hsm-attested`, and `provider-enforced` modes additionally
require:

- Key policy reference/hash matching the source provider attestation when the
  source declares a policy hash.
- Timestamp policy reference/hash matching the source provider attestation when
  the source declares a policy hash.
- Non-empty allowed actor references.
- `sign` and `timestamp` usage in `key_policy.key_usage`.
- Quorum approvers satisfying `key_policy.quorum_required`.

## Verification

`trustai trust-authority-kms-enforcement-verify` checks:

1. Schema, canonical `enforcement_id`, and detached signature.
2. `enforced_at` is not earlier than the source provider attestation timestamp
   and is not in the future when `--now` is supplied.
3. Non-local modes are backed by a `provider-attested` trust-authority provider
   attestation source.
4. Source artifact content hash and source summary match the supplied provider
   attestation.
5. The supplied provider attestation verifies, including the upstream trust
   authority receipt, source evidence chain, keyring, and optional proof pack.
6. Credential references are redacted.
7. KMS key reference, key policy hash, timestamp policy hash, TSA
   certificate-chain hash, audit-log reference, and audit-log root match the
   source provider attestation when present there.
8. Attestation, key-policy, timestamp-policy, actor, denied-operation, and
   quorum controls satisfy the selected enforcement mode.
9. Provider-enforced mode includes an accepted provider response hash.
10. `enforcement_payload_hash` matches the canonical enforcement records.

## Chain Entry

`trustai trust-authority-kms-enforcement-append` verifies the receipt and
appends a `trust_authority.kms_enforcement.recorded` chain entry with:

- `enforcement_id` and enforcement hash.
- Source provider attestation summary.
- Enforcement service and key custody evidence.
- Timestamp authority, key policy, quorum, and immutable audit-log binding.
- Provider response hash when present.
- Source artifact references and limitations.

## Reference Commands

```powershell
python -m trustai trust-authority-kms-enforcement artifacts/trust-authority-provider-attestation.json artifacts/trust-authority-receipt.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json --mode provider-enforced --enforcement-ref kms-enforcement:trust-authority/provider/2026-07-04 --provider "Example Cloud HSM" --provider-endpoint https://kms.example/enforcement/trust-authority --credential-ref env:TRUST_AUTHORITY_KMS_TOKEN --actor-ref oidc:trustai.example/trust-authority-kms-worker --hsm-attestation-ref hsm-attestation:example/trust-authority/2026-07-04 --hsm-attestation-hash sha256:trust-authority-hsm-attestation --key-policy-ref policy:kms/trustai-evidence-signing-v0.1 --key-policy-hash sha256:kms-key-policy --timestamp-policy-ref policy:tsa/trustai-timestamping-v0.1 --timestamp-policy-hash sha256:tsa-policy --timestamp-attestation-ref tsa-attestation:example/trust-authority/2026-07-04 --timestamp-attestation-hash sha256:trust-authority-tsa-attestation --allowed-actor-ref oidc:trustai.example/trust-authority-kms-worker --denied-operation-ref kms:export-private-key --quorum-required 2 --quorum-approver-ref oidc:trustai.example/security-admin --quorum-approver-ref oidc:trustai.example/compliance-admin --audit-log-ref audit-log:trust-authority/provider --audit-log-root sha256:trust-authority-provider-audit-root --audit-log-size 7 --evidence-ref evidence:trust-authority/kms-enforcement --response-status 200 --response-body examples/aitrade/trust-authority-kms-response.json --enforced-at 2026-07-04T03:02:00Z --out artifacts/trust-authority-kms-enforcement.json
python -m trustai trust-authority-kms-enforcement-verify artifacts/trust-authority-kms-enforcement.json artifacts/trust-authority-provider-attestation.json artifacts/trust-authority-receipt.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json
python -m trustai trust-authority-kms-enforcement-append artifacts/trust-authority-kms-enforcement.json artifacts/trust-authority-provider-attestation.json artifacts/trust-authority-receipt.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json --state .trustai/trust-authority-kms-demo/evidence-chain.json --tenant trust-authority-kms-local --out artifacts/trust-authority-kms-enforcement-entry.json
python -m trustai chain-verify --state .trustai/trust-authority-kms-demo/evidence-chain.json --tenant trust-authority-kms-local
```

## Production Boundary

This v0.1 receipt is intentionally offline-verifiable. A production trust
authority must supply provider-native HSM/KMS attestation, exportable key and
timestamp policy evidence, independent RFC 3161 timestamp material, immutable
provider audit-log retention, and customer-controlled key custody evidence. The
receipt format makes those controls explicit so third parties can reject proof
packs that only contain local placeholders.
