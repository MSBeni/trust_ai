# Policy Backend Enforcement Receipt v0.1

TrustAI runtime policy can be evaluated locally, exported to OPA/Rego or Cedar,
and enforced by a hosted policy backend. The policy backend enforcement receipt
is the portable evidence artifact that binds a backend request/response record
to the already recorded policy pack, runtime action, proof pack, policy
decision, policy export, and optional policy-engine decision receipt.

This artifact is intentionally narrower than a deployment certification. It
records backend identity, endpoint URL, request hash, response hash, response
status, exported policy bundle hash, actor reference, and redacted credential
reference. Production deployments should pair it with deployment, key custody,
WORM retention, monitoring, and chain evidence.

## Schema

`schema`: `trustai.policy-backend-enforcement/0.1`

Required top-level fields:

- `enforcement_id`: canonical hash of the receipt body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{enforcement_id, policy_backend_enforcement}`.
- `mode`: enforcement evidence mode.
- `environment`: environment label.
- `enforced_at`: RFC3339 timestamp for the backend enforcement record.
- `backend`: hosted OPA/Cedar backend metadata.
- `credential`: redacted backend credential reference.
- `policy`: policy pack id, version, and hash.
- `action`: runtime action hash and optional action metadata.
- `proof_pack`: proof pack id, content hash, contract hash, and gate outcome.
- `decision`: policy decision hash, outcome, pass status, and optional chain
  entry binding.
- `backend_decision`: backend outcome metadata and match flag.
- `policy_export`: exported OPA/Rego or Cedar target binding.
- `source_artifacts`: hashes for source artifacts supplied to verification.
- `controls`: implementation/planned-production status for backend controls.

Supported engines:

- `opa`: hosted or recorded OPA/Rego policy backend.
- `cedar`: hosted or recorded Cedar policy backend.

Supported modes:

- `recorded-backend-response`: binds a supplied backend response hash without
  claiming continuous hosted operation.
- `hosted-backend`: claims a hosted HTTPS policy backend answered the bound
  request.
- `production-design`: records the intended production backend shape before all
  live controls are available.

## Verification

`trustai policy-backend-enforcement-verify` checks:

- receipt schema and canonical `enforcement_id`.
- detached signature over the receipt body.
- RFC3339 `enforced_at` timestamp.
- supported backend engine and mode.
- absolute HTTPS backend endpoint URL.
- SHA-256 references for bundle, request, and response hashes.
- HTTP response status and `success` consistency.
- redacted credential reference.
- policy pack id, version, and hash.
- runtime action hash.
- proof pack id, content hash, and contract hash.
- policy decision hash, outcome, pass status, and chain entry binding.
- backend outcome metadata matches the recorded policy decision.
- policy export schema, content hash, backend target, and target hash.
- optional policy-engine receipt hash, engine, mode, and decision binding.
- source artifact hashes when supplied.
- absence of secret-like plaintext fields.

`trustai policy-backend-enforcement-append` first verifies the receipt and
source artifacts, then appends `policy_backend.enforcement_recorded` to the
evidence chain. The chain entry is a compact summary containing the enforcement
id/hash, backend metadata, credential reference, policy/action/proof-pack
bindings, decision binding, source artifacts, evidence refs, and control
summary.

## Example Commands

```powershell
python -m trustai policy-check examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --state .trustai/demo/evidence-chain.json --tenant aitrade-local --out artifacts/policy-decision.json --now 2026-07-04T02:00:00Z
python -m trustai policy-export examples/aitrade/policy-pack.json --out artifacts/policy-export.json
python -m trustai policy-engine-receipt examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --engine opa --out artifacts/policy-engine-receipt.json
python -m trustai policy-backend-enforcement examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --backend-ref opa:trustai-runtime:prod --engine opa --endpoint-url https://opa.example/v1/data/trustai/runtime/allow --credential-ref env:OPA_BACKEND_TOKEN --request-hash sha256:policy-backend-request --response-status 200 --response-hash sha256:policy-backend-response --actor-ref oidc:trustai.example/runtime-policy --mode hosted-backend --enforced-at 2026-07-04T02:00:01Z --out artifacts/policy-backend-enforcement.json
python -m trustai policy-backend-enforcement-verify artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json
python -m trustai policy-backend-enforcement-append artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --state .trustai/policy-backend-enforcement-demo/evidence-chain.json --tenant policy-backend-local --out artifacts/policy-backend-enforcement-entry.json
python -m trustai chain-verify --state .trustai/policy-backend-enforcement-demo/evidence-chain.json --tenant policy-backend-local
```

## Production Notes

A production deployment should run OPA/Cedar in a hardened service or
customer-controlled data plane, preserve request/response bodies or structured
summaries in WORM storage when retention requires it, authenticate backend
workers with least-privilege credentials, rotate credentials through KMS/HSM
custody, monitor backend availability, and record deployment version plus policy
bundle provenance. This receipt is the verification contract for that hosted
runtime-attestation path.
