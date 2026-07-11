# Promotion Status Receipt v0.1

A promotion status receipt is a signed proof that a verified TrustAI proof-pack
promotion gate was translated into the provider status/check payload used by
CI/CD, and optionally that the payload is bound to a provider delivery receipt.
It sits between `ci-payload` and `provider-delivery`: the payload says what will
be sent, delivery says how it was dispatched, and this receipt proves the two
still match the gate decision.

## Artifact

The receipt uses schema `trustai.promotion-status/0.1` and records:

- provider: `github` or `gitlab`;
- proof-pack ID, proof-pack hash, offline verification status, and verifier error
  and warning counts;
- gate decision contract ID, contract hash, agent identity, outcome, pass flag,
  gate entry ID, and eval entry ID;
- provider payload schema, payload hash, request method/path, request body hash,
  pack ID, contract ID, and contract hash;
- provider status shape, including GitHub check-run status/conclusion/head SHA or
  GitLab commit-status state;
- provider target ref binding, including concrete GitHub repository or GitLab
  project path plus a 40-character commit SHA;
- optional provider delivery binding, including delivery ID, delivery hash,
  payload hash match, accepted/dry-run status, response summary, and delivery
  verification result;
- source checks, controls, violations, pass/fail status, limitations, receipt ID,
  and detached signatures.

## Verification

`promotion-status-verify` recalculates the receipt ID, verifies the detached
signature, recomputes violations from the embedded source checks, and can replay
all source artifacts:

- the source proof pack and offline verifier result;
- the GitHub/GitLab API-ready status payload; and
- the optional provider delivery receipt.

When sources are supplied, the verifier recomputes proof-pack hash, provider
payload hash, provider status success/failure and provider-native status shape, concrete repository/project commit ref binding, delivery receipt verification,
delivery payload binding, controls, violations, and pass/fail status. Editing the
proof-pack gate decision, provider payload conclusion/state, contract hash,
payload hash, delivery payload hash, or delivery signature changes the replayed
receipt result.

A receipt passes only when the proof pack verifies offline, the payload pack and
contract bindings match the gate decision, the provider status/check result
matches the TrustAI gate outcome, the provider payload targets a concrete repository/project commit ref, and any supplied provider delivery receipt
verifies and binds to the same payload.

## Chain Entry

Verified receipts append `promotion_status.attested` entries with:

- receipt ID and receipt hash;
- provider;
- proof-pack, gate-decision, provider-payload, provider-delivery, and
  provider-status summaries;
- source checks;
- violation count; and
- pass/fail status.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai ci-payload artifacts/aitrade-proof-pack.json --provider github --commit-sha 0123456789abcdef0123456789abcdef01234567 --repository volelabs/trust_ai --target-url https://example.test/trustai/artifacts/aitrade-proof-pack.json --out artifacts/github-check-run-payload.json
python -m trustai provider-delivery artifacts/github-check-run-payload.json --endpoint-base https://api.github.com --credential-ref env:GITHUB_TOKEN --out artifacts/github-check-run-delivery.json
python -m trustai promotion-status artifacts/aitrade-proof-pack.json artifacts/github-check-run-payload.json --delivery artifacts/github-check-run-delivery.json --attested-at 2026-07-04T00:01:00Z --out artifacts/promotion-status.json
python -m trustai promotion-status-verify artifacts/promotion-status.json --pack artifacts/aitrade-proof-pack.json --payload artifacts/github-check-run-payload.json --delivery artifacts/github-check-run-delivery.json
python -m trustai promotion-status-append artifacts/promotion-status.json --pack artifacts/aitrade-proof-pack.json --payload artifacts/github-check-run-payload.json --delivery artifacts/github-check-run-delivery.json --state .trustai/promotion-status-demo/evidence-chain.json --tenant promotion-status-local --out artifacts/promotion-status-entry.json
```

## Limits

This receipt proves local replay binding between a proof-pack gate, the provider
status payload, and an optional delivery receipt. It does not prove the external
provider displayed or retained the status without provider-owned webhook,
audit-log, or production authority evidence.