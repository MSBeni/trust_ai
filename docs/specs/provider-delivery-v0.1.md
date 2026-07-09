# Provider Delivery Receipt v0.1

Provider delivery receipts bind an API-ready TrustAI payload to a provider
delivery attempt. They are the local verifiable shape for GitHub Checks, GitLab
statuses, and Slack approval request posting.

This v0.1 artifact can represent a dry run, a recorded provider response, or
an HTTP dispatch performed by the reference CLI with an `env:` credential
reference. It redacts credentials and records only hashes of request/response
evidence needed for offline verification.

## Schema

`schema`: `trustai.provider-delivery/0.1`

Top-level fields:

- `delivery_id`: canonical hash of the delivery body without `delivery_id` and
  `signatures`.
- `mode`: `dry-run`, `recorded-response`, or `http-dispatch`.
- `provider`: provider from the source payload, such as `github`, `gitlab`, or
  `slack`.
- `payload_schema`: source payload schema.
- `payload_hash`: canonical source payload hash.
- `pack_id`, `contract_id`, `contract_hash`: source proof-pack binding when the
  payload carries it.
- `request`: HTTP method, provider path, request body hash, and optional
  redacted request header names/hash for HTTP dispatch.
- `endpoint_base`: provider base URL.
- `target_url`: full URL assembled from base URL and path.
- `credential`: redacted credential reference, such as `env:GITHUB_TOKEN`.
- `idempotency_key`: stable hash for replay-safe dispatch workers.
- `delivered_at`: RFC3339 delivery timestamp.
- `response`: optional status, body hash, accepted flag, and response header
  hash for `recorded-response` or `http-dispatch` mode.
- `signatures`: one or more detached signatures over the delivery id and body.

## Verification

`trustai provider-delivery-verify` checks:

- delivery schema;
- delivery id canonical hash;
- detached signature;
- redacted credential reference presence;
- request method, path, and body hash;
- payload schema, provider, payload hash, proof-pack ids, contract ids, request
  method/path, and request body hash against the source payload when supplied;
- recorded response status/body hash when `mode` is `recorded-response`;
- request header hash and response header hash when `mode` is `http-dispatch`.

`dry-run` receipts verify with a warning because no provider response is
claimed.

`trustai provider-delivery-append` appends a `provider_delivery.recorded` chain
entry containing the delivery id, provider, mode, payload hash, target URL,
request hash, and optional response summary.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai ci-payload artifacts/aitrade-proof-pack.json --provider github --commit-sha 0123456789abcdef0123456789abcdef01234567 --repository volelabs/trust_ai --target-url https://example.test/trustai/artifacts/aitrade-proof-pack.json --out artifacts/github-check-run-payload.json
python -m trustai provider-delivery artifacts/github-check-run-payload.json --endpoint-base https://api.github.com --credential-ref env:GITHUB_TOKEN --out artifacts/github-check-run-delivery.json
python -m trustai provider-delivery-verify artifacts/github-check-run-delivery.json --payload artifacts/github-check-run-payload.json
# With GITHUB_TOKEN set, --send performs HTTP dispatch and records response hashes.
python -m trustai provider-delivery artifacts/github-check-run-payload.json --endpoint-base https://api.github.com --credential-ref env:GITHUB_TOKEN --send --out artifacts/github-check-run-dispatch.json
python -m trustai provider-delivery-append artifacts/github-check-run-delivery.json --payload artifacts/github-check-run-payload.json --state .trustai/provider-delivery-demo/evidence-chain.json --tenant provider-delivery-local --out artifacts/github-check-run-delivery-entry.json
```

The reference CLI performs dependency-free HTTP dispatch for API-ready payloads
and binds response evidence into the receipt. Production workers still need
provider-specific OAuth flows, retry policies, rate-limit handling, audit log
streaming, and hosted callback processing. The delivery receipt defines what
those workers must prove.
