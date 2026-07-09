# Insurer Consent v0.1

TrustAI insurer telemetry is only useful if it is consented by the customer that
owns the proof evidence. Consent is therefore represented as signed evidence in
the same chain as contracts, gates, runtime attestations, and incidents.

## Consent Grant

`trustai consent-grant` appends `consent.granted`.

Required consent document fields:

- `consent_id`: stable customer consent id.
- `granted_to`: recipient organization or contact.
- `scope`: currently `proof-pack-risk-telemetry`.
- `granted_at`: RFC3339 grant timestamp.

Optional fields:

- `expires_at`: RFC3339 expiry timestamp.
- `contract_ids`: contracts covered by the grant.
- `pack_ids`: proof packs covered by the grant. Empty means any pack matching the
  other constraints.
- `terms`: retention, redistribution, or purpose constraints.

## Consent Revocation

`trustai consent-revoke` appends `consent.revoked` with:

- `consent_id`
- `reason`
- `revoked_at`

The latest revocation after a grant makes the consent inactive.

## Validation

Consent validation checks:

- grant exists.
- scope matches the requested telemetry scope.
- pack id is covered when the grant lists pack ids.
- contract id is covered when the grant lists contract ids.
- grant is not expired for the requested `now` timestamp.
- grant has not been revoked.

`trustai insurer-export --require-consent` refuses to write telemetry unless the
consent is active.

`/v0/insurer-risk` requires `consent_id`, checks active consent against the
server evidence chain, and can require a bearer token when the server starts
with `--insurer-token`.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai consent-grant examples/aitrade/insurer-consent.json --state .trustai/demo/evidence-chain.json --tenant aitrade-local
python -m trustai insurer-export artifacts/aitrade-proof-pack.json --consent-id aitrade-underwriting-consent-20260704 --require-consent --state .trustai/demo/evidence-chain.json --tenant aitrade-local
python -m trustai consent-revoke aitrade-underwriting-consent-20260704 --reason "customer withdrew underwriting consent" --state .trustai/demo/evidence-chain.json --tenant aitrade-local
```
