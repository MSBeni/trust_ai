# Keyring Manifest v0.1

The local keyring is the verifier-side trust material for development and
offline demos. It models the production shape where signatures are resolved by
`key_id` and `provider`, while keeping this repository self-contained and
network-free.

## Schema

```json
{
  "schema": "trustai.keyring/0.1",
  "tenant_id": "aitrade-local",
  "keys": [
    {
      "key_id": "local-dev",
      "provider": "local-kms",
      "alg": "HMAC-SHA256",
      "secret": "trustai-local-dev-key-change-me",
      "status": "active",
      "usages": ["evidence-signing"]
    },
    {
      "key_id": "local-dev",
      "provider": "local-dev",
      "alg": "HMAC-SHA256",
      "secret": "trustai-local-dev-key-change-me",
      "status": "active",
      "usages": ["artifact-signing"]
    },
    {
      "key_id": "local-dev",
      "provider": "local-tsa",
      "alg": "HMAC-SHA256",
      "secret": "trustai-local-tsa-key-change-me",
      "status": "active",
      "usages": ["timestamping"]
    }
  ]
}
```

Required key fields are `key_id`, `provider`, `alg`, and `secret`. The local
reference supports `HMAC-SHA256` only. A verifier resolves a signature by exact
`key_id` and `provider` match. Keys with `active` or `retired` status can verify
historical material; `revoked` keys are rejected.

## Local Rotation

`trustai keyring-rotate` appends a new local key id for `local-kms`, `local-dev`,
and `local-tsa`. By default it marks existing active local keys as `retired` so
old evidence remains verifiable while new signatures can use the new key id.

```powershell
python -m trustai keyring-rotate .trustai/keyring.local.json --key-id local-dev-v2 --secret trustai-rotated-local-secret --out .trustai/keyring.rotated.local.json
```

To sign new local evidence with the rotated key, set `TRUSTAI_KEY_ID` to the new
key id and pass the matching `--key` secret to signing commands. Production
rotation should use KMS/HSM public verification material instead of local
secrets.

## Local CLI Workflow

```powershell
$env:PYTHONPATH = "src"
python -m trustai keyring-init --out .trustai/keyring.local.json --tenant aitrade-local
python -m trustai chain-verify --state .trustai/demo/evidence-chain.json --tenant aitrade-local --keyring .trustai/keyring.local.json
python -m trustai keyring-rotate .trustai/keyring.local.json --key-id local-dev-v2 --secret trustai-rotated-local-secret --out .trustai/keyring.rotated.local.json
python -m trustai chain-verify --state .trustai/demo/evidence-chain.json --tenant aitrade-local --keyring .trustai/keyring.rotated.local.json
python -m trustai verify artifacts/aitrade-proof-pack.json --keyring .trustai/keyring.local.json
```

`chain-verify` validates entry ids, payload hashes, previous-entry pointers,
timestamp tokens, entry signatures, and Merkle inclusion. `verify --keyring`
validates the proof pack signature plus all selected evidence-chain entries
using the same manifest.

## Production Replacement

The manifest is deliberately shaped like production trust metadata, but the
local secrets are not production key custody. A real deployment should replace
this with customer-controlled KMS/HSM public verification material, rotation and
revocation metadata, audit logs for signing operations, and independent RFC 3161
timestamp authority certificates.
