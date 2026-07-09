# Procurement Integration Receipt v0.1

This specification defines a signed receipt for packaging TrustAI vendor proof
evidence into a procurement-system integration payload. It sits after vendor
identity and procurement clause receipts: those receipts prove the vendor and
buyer requirements; this receipt proves the exact payload prepared for, or
recorded from, a procurement platform such as Coupa, SAP Ariba, ServiceNow, or
a contract-management system.

## Schema

`schema`: `trustai.procurement-integration/0.1`

Required top-level fields:

- `integration_id`: canonical hash of the integration receipt body.
- `mode`: `dry-run` or `recorded-response`.
- `delivered_at`: RFC3339 timestamp for payload preparation or dispatch.
- `procurement_system`: system name, endpoint base, redacted credential
  reference, optional integration reference, local attestation mode, and
  production replacement guidance.
- `request`: HTTP method, path, target URL, full procurement payload, canonical
  body hash, and idempotency key.
- `source_artifacts`: canonical hash records for the procurement clause receipt,
  vendor identity receipt, and optional trust-network manifest.
- `response`: required only for `recorded-response`; includes provider status,
  response body hash, and accepted flag.
- `controls`: implemented-reference and planned-production controls.
- `signatures`: detached local HMAC signature over the integration id and body.

The request body uses `trustai.procurement-system-payload/0.1` and includes
buyer, contract, requirements, vendor identity, proof-pack references,
trust-network binding, source receipt ids, and the acceptance decision sent to
the procurement system.

## Verification

`trustai procurement-integration-verify` checks:

- schema, canonical `integration_id`, and signature;
- delivery timestamp and mode;
- procurement system, target URL, redacted credential reference, request method,
  path, request body, and body hash;
- response status/body hash when `mode` is `recorded-response`;
- source procurement clause receipt hash and full verification when supplied;
- source vendor identity receipt hash and full verification when supplied;
- optional trust-network manifest hash and accepted vendor binding;
- request body consistency with the supplied source receipts.

Without source receipts, verification can only prove receipt integrity and the
embedded artifact hashes; it emits warnings for missing deep-verification
inputs.

## Evidence Chain Entry

`trustai procurement-integration-append` verifies the receipt, then appends
`procurement.integration.recorded` to an evidence chain. The entry payload
records the integration id, integration hash, system, request target/body hash,
optional response, source artifact references, and limitations.

## Reference Commands

```powershell
python -m trustai procurement-integration artifacts/procurement-clause-receipt.json artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --procurement-system servicenow --endpoint-base https://procurement.example --credential-ref env:PROCUREMENT_TOKEN --integration-ref REQ-2026-TRUSTAI-001 --delivered-at 2026-07-12T12:00:00Z --out artifacts/procurement-integration-receipt.json
python -m trustai procurement-integration-verify artifacts/procurement-integration-receipt.json --procurement-receipt artifacts/procurement-clause-receipt.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json
python -m trustai procurement-integration-append artifacts/procurement-integration-receipt.json --procurement-receipt artifacts/procurement-clause-receipt.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --state .trustai/procurement-integration-demo/evidence-chain.json --tenant procurement-integration-local --out artifacts/procurement-integration-entry.json
```

## Production Boundary

This local receipt models the procurement integration evidence shape. Production
deployments still need authenticated procurement-platform APIs, provider-signed
responses or durable event logs, buyer/vendor identity-provider federation,
retry and idempotency handling, and dispute workflow for rejected vendor
submissions.
