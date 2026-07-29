# Policy Engine Decision Receipt v0.1

TrustAI runtime policy can be evaluated by the local JSON reference evaluator or
by a production policy backend such as OPA or Cedar. The policy engine decision
receipt is the portable evidence artifact that binds those pieces together for
offline review.

This v0.1 artifact does not claim that TrustAI operated a hosted OPA/Cedar
service. It proves which policy pack, action, proof pack, local policy decision,
and exported backend artifact were bound into a signed receipt, and lets offline
verifiers replay the supplied decision from the active gate outcome and
proof-decay inputs. In `recorded-response` mode it also binds the hash of a
supplied backend response.

## Schema

`schema`: `trustai.policy-engine-receipt/0.1`

Required top-level fields:

- `receipt_id`: canonical hash of the receipt body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{receipt_id, receipt}`.
- `evaluated_at`: RFC3339 timestamp for the engine decision receipt.
- `engine`: policy engine name and mode.
- `policy`: policy pack id, version, and hash.
- `action`: runtime action hash and optional action metadata.
- `proof_pack`: proof pack id, content hash, contract hash, and gate outcome.
- `decision`: policy decision hash, outcome, pass status, and optional chain
  entry binding.

Supported engines:

- `local-json`: the deterministic TrustAI reference evaluator.
- `opa`: a receipt for an OPA/Rego backend export.
- `cedar`: a receipt for a Cedar-shaped backend export.

Supported modes:

- `local-reference`: no hosted backend response is claimed.
- `recorded-response`: binds a supplied engine response by content hash.

OPA and Cedar receipts must include `policy_export`. The export reference binds:

- export schema.
- policy pack id, version, and hash.
- export content hash.
- target names, such as `opa_rego` or `cedar`.

`recorded-response` receipts must include `engine_response` with the response
hash and optional status/outcome metadata.

## Verification

`trustai policy-engine-verify` checks:

- receipt schema and canonical `receipt_id`.
- detached signature over the receipt body.
- policy pack hash, id, and version.
- runtime action hash.
- proof pack content hash, pack id, and contract hash.
- policy decision hash, outcome, pass status, and chain entry binding.
- consistency between the policy decision and receipt policy/action/contract
  references.
- local policy decision replay from the supplied policy pack, action, proof pack,
  active gate outcome, and proof-decay timestamps.
- OPA/Cedar export target presence and export hash when supplied.
- recorded response hash when supplied.

`trustai policy-engine-append` first verifies the receipt and source artifacts,
then appends `policy_engine.evaluated` to the evidence chain. The chain entry is
a compact summary containing the receipt id/hash, engine metadata, policy/action
hashes, proof-pack binding, decision binding, export reference, and optional
engine-response reference.

## Example Commands

```powershell
python -m trustai policy-check examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --state .trustai/demo/evidence-chain.json --tenant aitrade-local --out artifacts/policy-decision.json --now 2026-07-04T02:00:00Z
python -m trustai policy-export examples/aitrade/policy-pack.json --out artifacts/policy-export.json
python -m trustai policy-engine-receipt examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --engine opa --out artifacts/policy-engine-receipt.json
python -m trustai policy-engine-verify artifacts/policy-engine-receipt.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json
python -m trustai policy-engine-append artifacts/policy-engine-receipt.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --state .trustai/policy-engine-demo/evidence-chain.json --tenant policy-engine-local --out artifacts/policy-engine-entry.json
```

## Production Notes

A production deployment should replace local HMAC signatures with
customer-controlled KMS/HSM signing, execute OPA/Cedar in a hardened service or
customer-controlled data plane, preserve request/response bodies in WORM object
storage when retention requires it, and record backend identity plus deployment
version. This local receipt is the verification contract for that future hosted
backend.
