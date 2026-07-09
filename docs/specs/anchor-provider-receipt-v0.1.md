# Anchor Provider Receipt v0.1

Chain anchors prove a TrustAI evidence-chain tree head existed at a timestamped
moment. An anchor provider receipt adds the external-publication proof required
for production: the signed TrustAI anchor entry is bound to recorded provider
publication evidence, public-log inclusion metadata, optional witness or
blockchain references, and immutable provider audit-log references.

This v0.1 artifact records provider endpoint, publication reference, request
hash, response status, response hash, public-log root, public-log size,
public-log entry reference, inclusion proof hash, optional consistency proof
hash, optional witness or blockchain references, actor reference, redacted
credential reference, audit-log root, retention deadline, and source hashes. It
does not perform live network anchoring by itself.

## Schema

`schema`: `trustai.anchor-provider-receipt/0.1`

Required top-level fields:

- `receipt_id`: canonical hash of the receipt body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{receipt_id, anchor_provider}`.
- `mode`: `local-reference`, `recorded-public-log`, `provider-anchored`, or
  `blockchain-anchored`.
- `environment`: deployment/environment label.
- `published_at`: RFC3339 timestamp for the external anchoring record.
- `source`: anchor entry id/hash, anchor id, anchor tenant, anchored prefix
  tree root/size, anchor publication timestamp, and optional source-chain
  hash/root/size.
- `provider`: provider name, HTTPS endpoint, publication reference, request
  hash, response status, response hash, and accepted flag.
- `public_log`: public log reference, tree root, tree size, entry reference,
  inclusion proof hash, optional consistency proof hash, and witness
  references.
- `blockchain`: optional network, transaction reference, and block reference.
- `operation`: actor reference, redacted provider credential reference, and
  optional evidence references.
- `audit_log`: provider audit-log reference, audit-log root hash, and
  retention deadline.
- `source_artifacts`: hashes of the source anchor entry and optional source
  evidence chain supplied to verification.
- `controls`: implementation/planned-production status for source binding,
  provider publication, public-log inclusion, witness/blockchain cross-anchor,
  audit retention, and provider mode.

Provider credentials, request bodies, response bodies, private keys, raw witness
signatures, and raw customer proof-pack payloads are never copied into the
receipt.

## Verification

`trustai anchor-provider-verify` checks:

- receipt schema and canonical `receipt_id`.
- detached signature over the receipt body.
- RFC3339 `published_at` and audit-log retention ordering.
- supported mode.
- required source anchor fields.
- HTTPS provider endpoint URL.
- SHA-256 references for request hashes, response hashes, public-log roots,
  inclusion proof hashes, consistency proof hashes, and audit-log roots.
- provider response status and accepted-flag consistency.
- public-log root, size, and entry reference presence.
- blockchain references when `mode` is `blockchain-anchored`.
- redacted provider credential reference.
- source artifact hashes against supplied anchor entry and source chain.
- full verification of the supplied anchor entry and anchor payload.
- full verification of the supplied source chain, when present.
- anchor payload tree equality against the source-chain prefix that existed
  before the anchor entry was appended.
- absence of raw secret-like fields outside approved redacted references.

`trustai anchor-provider-append` first verifies the receipt and source artifacts,
then appends `chain.anchor.provider_published` to an evidence chain. The
appended entry contains the receipt id/hash, source binding, provider metadata,
public-log metadata, optional blockchain metadata, operation reference,
audit-log metadata, source-artifact hashes, and control summary.

## Example Commands

```powershell
python -m trustai anchor-provider-receipt artifacts/chain-anchor.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --provider "TrustAI Public Transparency Log" --endpoint https://transparency.example/anchors --publication-ref publog:trustai/aitrade-local/2026-07-04 --request-hash sha256:anchor-provider-request --response-status 201 --response-hash sha256:anchor-provider-response --public-log-ref rekor:trustai-public-log --public-log-root sha256:trustai-public-log-root --public-log-size 128 --public-log-entry-ref rekor-entry:trustai-anchor-aitrade-local --inclusion-proof-hash sha256:anchor-provider-inclusion-proof --consistency-proof-hash sha256:anchor-provider-consistency-proof --witness-ref witness:sigstore --witness-ref witness:lf-trustai --actor-ref oidc:trustai.example/anchor-publisher --credential-ref env:ANCHOR_PROVIDER_TOKEN --audit-log-ref audit-log:anchor-provider/publication --audit-log-root sha256:anchor-provider-audit-root --retention-until 2033-07-04T00:00:00Z --evidence-ref evidence:anchor-provider/public-log --published-at 2026-07-04T00:10:00Z --out artifacts/chain-anchor-provider.json
python -m trustai anchor-provider-verify artifacts/chain-anchor-provider.json artifacts/chain-anchor.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local
python -m trustai anchor-provider-append artifacts/chain-anchor-provider.json artifacts/chain-anchor.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --state .trustai/anchor-provider-demo/evidence-chain.json --tenant anchor-provider-local --out artifacts/chain-anchor-provider-entry.json
python -m trustai chain-verify --state .trustai/anchor-provider-demo/evidence-chain.json --tenant anchor-provider-local
```

## Production Notes

A production deployment should preserve provider-native request/response bodies,
public-log inclusion proofs, consistency proofs, witness signatures, blockchain
transaction receipts when used, and immutable provider audit-log exports in WORM
storage when retention policy requires replay beyond hashes. This v0.1 local
reference defines the offline verification contract for that evidence while
keeping live provider calls outside the deterministic local verifier.
