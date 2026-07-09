# Provider Credential Custody Receipts v0.1

Provider credential custody receipts record how provider-facing credentials are
held, accessed, rotated, revoked, and audited without exposing the credential
material. They bind provider installation, lifecycle, lifecycle-operation, and
audit-worker artifacts to vault/KMS custody metadata and policy hashes.

## Receipt

The JSON receipt uses schema `trustai.provider-credential-custody/0.1` and
includes:

- `custody_id`: canonical hash of the signed receipt body.
- `mode`: one of `local-reference`, `vault-policy`, `kms-attested`,
  `provider-managed-vault`, or `production-design`.
- `provider`: normalized provider name derived from source artifacts.
- `credential`: redacted credential reference and credential kind.
- `custody`: custody reference, environment, issue time, optional expiry,
  retention boundary, access grant reference, and evidence references.
- `vault`: vault/KMS reference, endpoint, key reference, key algorithm,
  attestation reference/hash, rotation reference, and revocation reference.
- `policy`: policy reference/hash, allowed actor references, denied operations,
  quorum requirement, quorum approvers, and quorum state.
- `audit_log`: custody audit-log reference, immutable root hash, and retention
  boundary.
- `source_artifacts`: source ids, hashes, providers, operation metadata, and
  redacted credential references for supplied provider artifacts.
- `source_credential_refs`: all redacted credential references discovered in
  source artifacts.
- `response`: optional provider vault/KMS response status and response hash.
- `controls`: implemented/planned status for redaction, vault/KMS binding,
  policy hash binding, attestation, rotation/revocation, audit-log root, quorum,
  and provider response binding.
- `signatures`: detached signatures over `custody_id` and the canonical receipt
  body.

## Verification

A verifier MUST:

1. Recompute `custody_id` from the canonical body.
2. Verify at least one detached signature.
3. Validate mode, provider, issue/expiry/retention timestamps, credential kind,
   and redacted credential reference shape.
4. Confirm vault/KMS metadata is complete and uses HTTPS in attested modes.
5. Confirm `kms-attested` and `provider-managed-vault` modes include
   attestation reference/hash and provider response status/hash.
6. Validate policy hash, allowed actor set, denied-operation references, quorum
   requirement, and quorum approver count.
7. Validate custody audit-log root hash and retention binding.
8. Confirm source artifact records match supplied provider installation,
   lifecycle, lifecycle-operation, and audit-worker artifacts when supplied.
9. Confirm the custody credential reference appears in source credential refs.
10. Reject secret-like fields unless they are redacted references.

Verification MAY warn, rather than fail, when replay source artifacts are not
supplied and the signed receipt body is otherwise internally valid.

## Chain Entry

Appending a valid receipt emits entry type
`provider_credential.custody_recorded` with the receipt id/hash, provider,
mode, environment, redacted credential, custody metadata, vault/KMS metadata,
policy, audit-log reference, source bindings, and control summary.

## CLI

```bash
python -m trustai provider-credential-custody --provider-installation artifacts/github-provider-installation.json --lifecycle artifacts/provider-lifecycle.json --lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --audit-worker artifacts/provider-audit-worker.json --provider-ingress artifacts/provider-ingress.json --callback-storage artifacts/provider-callback-storage.json --credential-ref env:GITHUB_AUDIT_LOG_TOKEN --credential-kind audit_log_token --custody-ref custody:github-audit-token:local --vault-ref vault:trustai/provider-audit --kms-provider "TrustAI Provider Credential Vault" --kms-endpoint https://vault.example/provider-credentials --key-ref kms:trustai/provider-audit-token --key-algorithm HMAC-SHA256 --policy-ref policy:provider-audit-token-custody-v0.1 --policy-hash sha256:provider-audit-token-custody-policy --rotation-ref rotation:github-audit-token:2026-07 --revocation-ref revocation:github-audit-token --audit-log-ref audit-log:trustai/provider-credentials --audit-log-root sha256:provider-credential-custody-root --retention-until 2033-07-08T00:00:00Z --actor-ref oidc:trustai.example/provider-audit-worker --allowed-actor-ref oidc:trustai.example/provider-audit-worker --denied-operation-ref vault:export-secret --denied-operation-ref vault:plaintext-read --quorum-required 1 --quorum-approver-ref oidc:trustai.example/security-admin --attestation-ref hsm-attestation:trustai/provider-audit-token/2026-07-08 --attestation-hash sha256:provider-audit-token-attestation --response-status 200 --response-hash sha256:provider-audit-token-vault-response --mode kms-attested --issued-at 2026-07-08T02:13:00Z --out artifacts/provider-credential-custody.json
python -m trustai provider-credential-custody-verify artifacts/provider-credential-custody.json --provider-installation artifacts/github-provider-installation.json --lifecycle artifacts/provider-lifecycle.json --lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --audit-worker artifacts/provider-audit-worker.json --provider-ingress artifacts/provider-ingress.json --callback-storage artifacts/provider-callback-storage.json
python -m trustai provider-credential-custody-append artifacts/provider-credential-custody.json --provider-installation artifacts/github-provider-installation.json --lifecycle artifacts/provider-lifecycle.json --lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --audit-worker artifacts/provider-audit-worker.json --provider-ingress artifacts/provider-ingress.json --callback-storage artifacts/provider-callback-storage.json --state .trustai/provider-credential-custody-demo/evidence-chain.json --tenant provider-credential-custody-local --out artifacts/provider-credential-custody-entry.json
```

## Limitations

This receipt proves that provider credential custody metadata, policy, source
artifact hashes, and audit roots are bound into the evidence chain without
revealing credentials. It proves production custody only when attested/provider
managed modes are paired with live vault/KMS exports, deployment evidence,
monitoring, incident response, and independent audit-log evidence.
