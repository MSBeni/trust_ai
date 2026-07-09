# Trust Authority Receipt v0.1

TrustAI evidence chains are signed and timestamped. In production, those
operations should come from customer-controlled KMS/HSM keys and an independent
RFC 3161 timestamp authority. The local reference uses HMAC-backed `local-kms`,
`local-dev`, and `local-tsa` providers. A trust authority receipt is the
portable artifact that proves a chain and optional proof pack verified against a
specific verifier-side keyring.

This v0.1 receipt does not claim live cloud KMS/HSM or independent TSA use. It
binds the verification shape that a production deployment must preserve.

## Schema

`schema`: `trustai.trust-authority-receipt/0.1`

Required top-level fields:

- `receipt_id`: canonical hash of the receipt body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{receipt_id, receipt}`.
- `generated_at`: RFC3339 creation timestamp.
- `authority`: local authority mode and production replacement expectation.
- `chain`: source evidence-chain tenant, content hash, tree, entry count, first
  and last entry ids, and entry-type counts.
- `keyring`: redacted keyring summary plus full keyring content hash.
- `providers`: observed evidence-signing, artifact-signing, timestamp-token,
  and keyring-provider summaries.
- `verification`: passing chain verification summary and optional proof-pack
  verification summary.

When a proof pack is supplied, `proof_pack` also binds:

- pack id.
- proof-pack content hash.
- contract hash.
- chain tree inside the pack.
- gate outcome.
- proof-pack signature provider, key id, and algorithm.

Key secrets are never copied into the receipt. Offline verifiers supply the full
keyring separately and compare its canonical content hash to the receipt.

## Verification

`trustai trust-authority-verify` checks:

- receipt schema and canonical `receipt_id`.
- detached receipt signature.
- source evidence-chain verification with the supplied keyring.
- source chain hash, tenant, tree, entry count, and entry-type counts.
- keyring schema, tenant, redacted key list, rotation count, and content hash.
- optional proof-pack verification with the supplied keyring.
- proof-pack id/hash, contract hash, chain tree, and signature refs.
- provider summary consistency across source artifacts.

`trustai trust-authority-append` first verifies the receipt and source artifacts,
then appends `trust_authority.attested` to an evidence chain. The appended entry
contains the receipt id/hash, authority metadata, source chain reference,
redacted keyring reference, optional proof-pack reference, provider summary, and
verification summary.

## Example Commands

```powershell
python -m trustai trust-authority-receipt --state .trustai/demo/evidence-chain.json --tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json --out artifacts/trust-authority-receipt.json
python -m trustai trust-authority-verify artifacts/trust-authority-receipt.json --state .trustai/demo/evidence-chain.json --tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json
python -m trustai trust-authority-append artifacts/trust-authority-receipt.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json --state .trustai/trust-authority-demo/evidence-chain.json --tenant trust-authority-local --out artifacts/trust-authority-entry.json
python -m trustai chain-verify --state .trustai/trust-authority-demo/evidence-chain.json --tenant trust-authority-local
```

## Production Notes

A production replacement should include KMS/HSM public verification material,
key policy identifiers, signing-operation audit ids, TSA certificate chains,
RFC 3161 response bytes or hashes, rotation/revocation records, and independent
provider identity. The receipt keeps those controls separable from the proof
pack so a third party can verify cryptographic custody without trusting the
producer's dashboard.
