# Production Trust Primitives v0.1

This local reference implements production-facing trust primitives without
network or cloud dependencies. They are designed to be replaced by managed
services in a real BYOC/SaaS deployment.

## Local KMS-Style Signatures

Evidence entries and proof packs use HMAC-SHA256 signatures with provider
metadata:

- `provider`: `local-kms`, `local-tsa`, or `local-dev`;
- `key_id`: `TRUSTAI_KEY_ID` or `local-dev`;
- `alg`: `HMAC-SHA256`.

Production deployments should replace this with customer-controlled KMS/HSM
signatures.

## Local Keyring Manifest

`trustai keyring-init` writes a `trustai.keyring/0.1` manifest that maps
signature `key_id` and `provider` metadata to local verification secrets.
The offline verifier can use it for direct chain verification and proof-pack
verification:

```powershell
python -m trustai chain-verify --state .trustai/demo/evidence-chain.json --tenant aitrade-local --keyring .trustai/keyring.local.json
python -m trustai verify artifacts/aitrade-proof-pack.json --keyring .trustai/keyring.local.json
```

See `docs/specs/keyring-v0.1.md` for the manifest schema and production
replacement expectations.

## Trust Authority Receipts

`trustai trust-authority-receipt` writes a signed
`trustai.trust-authority-receipt/0.1` artifact after a source evidence chain and
optional proof pack verify against a supplied keyring. The receipt redacts key
secrets, binds the full keyring by canonical hash, summarizes observed
`local-kms`, `local-dev`, and `local-tsa` providers, and can be appended as
`trust_authority.attested` evidence with `trustai trust-authority-append`.

This is the local bridge to customer-controlled KMS/HSM signing and independent
RFC 3161 timestamp authority evidence; see
`docs/specs/trust-authority-receipt-v0.1.md`.

## Timestamp Tokens

Every new evidence-chain entry carries a `trustai.timestamp-token/0.1` token.
The token binds:

- entry id;
- entry timestamp;
- payload hash.

The token is signed by the local TSA provider and verified by the offline
verifier as part of entry verification.

## Chain Anchors

`trustai anchor` publishes a signed `chain.anchor.published` event for the
current tree size and root. The anchor also carries a timestamp token.

`trustai anchor-provider-receipt` records the production envelope for external
or public anchoring: HTTPS provider endpoint, request/response hashes,
public-log root and entry reference, inclusion proof hash, optional witness or
blockchain references, redacted provider credential reference, and immutable
audit-log root. See `docs/specs/anchor-provider-receipt-v0.1.md`.

## Persisted Chain Tree Headers

Every saved evidence-chain document stores `tree.size` and `tree.root`.
`EvidenceChain.verify_all()` recomputes the tree from the entry list and rejects
missing headers, non-object headers, size mismatches, and root mismatches.
Appends after load clear the stale declared header until the chain is saved
again, so verification compares against current entries while saved snapshots
cannot hide metadata tampering.

## WORM Receipts and Legal Holds

`trustai seal` writes an artifact to a content-addressed local WORM object store
and emits a receipt with content hash, object path, size, retention timestamp,
and receipt id.

`trustai worm-legal-hold` writes a `trustai.worm-legal-hold/0.1` receipt that
binds a legal matter, reason, actor, timestamp, WORM receipt id, object path,
and content hash. The command first audits the referenced WORM receipt so holds
cannot be applied to missing or tampered local objects.

`trustai worm-audit` verifies the receipt id, stored object hash, object size,
retention timestamps, missing-object status, whether retention is still active,
and, when `--legal-hold` is supplied, whether the hold still matches the WORM
receipt. A legal hold can remain active after the retention timestamp has
expired.

The local developer store models the verification shape; production still needs
cloud Object Lock compliance mode, privileged deletion controls, legal hold
release governance, bucket policy enforcement, and independent storage audit
logs.
## Local API

`trustai serve` starts a local HTTP API:

- `GET /health`;
- `POST /v0/ingest`;
- `POST /v1/traces` for OTLP JSON trace ingestion;
- `POST /v0/verify`;
- `POST /v0/insurer-risk`.

This is the local reference for later network collectors, verifier services, and
insurer APIs.

The API accepts input filenames only from `--input-dir` (default: the state
file's directory). Place proof packs, contracts, and other input files there,
then pass their filenames, not paths, in HTTP requests. Symlinks cannot escape
this directory; requests cannot select a different evidence-chain state file.
The default bind address remains `127.0.0.1`.

