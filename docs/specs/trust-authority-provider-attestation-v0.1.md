# Trust Authority Provider Attestation v0.1

Trust authority receipts prove that a source evidence chain and optional proof
pack verified against a supplied keyring. A provider attestation adds the next
production-envelope proof: the receipt is bound to recorded KMS/HSM signing
evidence and independent RFC 3161 timestamp-authority evidence.

This v0.1 artifact records provider endpoints, request hashes, response hashes,
HTTP status, key policy references, TSA certificate-chain hashes, audit-log
roots, retention deadlines, actor references, and redacted credential
references. It does not perform live cloud KMS or TSA calls by itself.

## Schema

`schema`: `trustai.trust-authority-provider-attestation/0.1`

Required top-level fields:

- `attestation_id`: canonical hash of the attestation body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{attestation_id, trust_authority_provider}`.
- `mode`: `local-reference`, `provider-attested`, or `production-design`.
- `environment`: deployment/environment label.
- `attested_at`: RFC3339 timestamp for the provider evidence record.
- `source`: trust-authority receipt id/hash, source-chain hash/root, keyring
  hash, optional proof-pack hash, and provider summaries from the receipt.
- `kms`: KMS/HSM provider, HTTPS endpoint, key reference, key algorithm,
  request hash, response status, response hash, accepted flag, and optional
  key-policy reference/hash.
- `timestamp_authority`: TSA provider, HTTPS endpoint, request hash, response
  status, response hash, accepted flag, certificate-chain hash, and optional
  timestamp-policy reference/hash.
- `operation`: actor reference, redacted provider credential reference, and
  optional evidence references.
- `audit_log`: provider audit-log reference, audit-log root hash, and retention
  deadline.
- `source_artifacts`: hashes of the trust-authority receipt, source evidence
  chain, keyring, and optional proof pack supplied to verification.
- `controls`: implementation/planned-production status for provider signing,
  timestamping, certificate-chain, policy, audit-log, and credential controls.

Provider credentials, private keys, raw KMS responses, raw timestamp responses,
and raw provider secrets are never copied into the attestation.

## Verification

`trustai trust-authority-provider-verify` checks:

- attestation schema and canonical `attestation_id`.
- detached signature over the attestation body.
- RFC3339 `attested_at` and audit-log retention ordering.
- supported mode.
- required source receipt, source-chain, and keyring hashes.
- HTTPS KMS/HSM and TSA endpoint URLs.
- SHA-256 references for KMS/TSA request hashes, response hashes,
  certificate-chain hashes, policy hashes, and audit-log roots.
- response status and accepted-flag consistency.
- redacted provider credential reference.
- source artifact hashes against supplied source artifacts.
- full verification of the supplied trust-authority receipt.
- absence of raw secret-like fields outside approved redacted references.

`trustai trust-authority-provider-append` first verifies the attestation and
source artifacts, then appends `trust_authority.provider_attested` to an
evidence chain. The appended entry contains the attestation id/hash, source
receipt binding, KMS/HSM metadata, TSA metadata, operation reference, audit-log
metadata, source-artifact hashes, and control summary.

## Example Commands

```powershell
python -m trustai trust-authority-provider-attestation artifacts/trust-authority-receipt.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json --kms-provider "Example Cloud KMS" --kms-endpoint https://kms.example/sign --kms-key-ref kms:example/trustai/evidence-signing --kms-request-hash sha256:kms-sign-request --kms-response-status 200 --kms-response-hash sha256:kms-sign-response --tsa-provider "Example RFC3161 TSA" --tsa-endpoint https://tsa.example/timestamp --tsa-request-hash sha256:tsa-request --tsa-response-status 200 --tsa-response-hash sha256:tsa-response --tsa-certificate-chain-hash sha256:tsa-certificate-chain --actor-ref oidc:trustai.example/trust-authority-worker --credential-ref env:TRUST_AUTHORITY_PROVIDER_TOKEN --audit-log-ref audit-log:trust-authority/provider --audit-log-root sha256:trust-authority-provider-audit-root --retention-until 2033-07-04T00:00:00Z --key-policy-ref policy:kms/trustai-evidence-signing-v0.1 --key-policy-hash sha256:kms-key-policy --timestamp-policy-ref policy:tsa/trustai-timestamping-v0.1 --timestamp-policy-hash sha256:tsa-policy --evidence-ref evidence:trust-authority/provider --mode provider-attested --attested-at 2026-07-04T03:01:00Z --out artifacts/trust-authority-provider-attestation.json
python -m trustai trust-authority-provider-verify artifacts/trust-authority-provider-attestation.json artifacts/trust-authority-receipt.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json
python -m trustai trust-authority-provider-append artifacts/trust-authority-provider-attestation.json artifacts/trust-authority-receipt.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json --state .trustai/trust-authority-provider-demo/evidence-chain.json --tenant trust-authority-provider-local --out artifacts/trust-authority-provider-entry.json
python -m trustai chain-verify --state .trustai/trust-authority-provider-demo/evidence-chain.json --tenant trust-authority-provider-local
```

## Production Notes

A production deployment should preserve provider-native request/response bodies
or structured evidence in WORM storage when retention policy requires replay
beyond hashes, use customer-controlled KMS/HSM keys, record independent TSA
certificate chains and RFC 3161 response material, rotate/revoke provider
credentials through key custody controls, and correlate provider audit-log
entries to the attestation. This v0.1 local reference defines the offline
verification contract for that evidence.
