# Procurement Clause Receipt v0.1

This specification defines a signed buyer-side receipt for recording that a
procurement or contract reference requires TrustAI-format proof packs from
vendors. It complements the trust-network manifest: the manifest verifies vendor
submissions against machine-checkable requirements, while this receipt records
the buyer's clause acknowledgement and makes it appendable evidence.
Procurement integration receipts can then package this clause evidence and vendor identity evidence into a procurement-system payload.

## Schema

`schema`: `trustai.procurement-clause/0.1`

Required top-level fields:

- `receipt_id`: canonical hash of the receipt body.
- `issued_at`: RFC3339 timestamp for the buyer acknowledgement.
- `buyer`: buyer name, optional legal entity, approver reference, procurement
  system reference, and local attestation mode.
- `contract`: contract reference, effective/expiry timestamps, clause name,
  clause hash, and clause text.
- `requirements`: trust-network manifest id, vendor counts, accepted vendor
  count, required gate outcome, required frameworks, and accepted risk classes.
- `source_artifacts`: exactly one canonical hash record for the trust-network
  manifest.
- `controls`: implemented-reference and planned-production controls.
- `signatures`: detached local HMAC signature over the receipt id and body.

## Verification

`trustai procurement-clause-verify` checks:

- schema, canonical `receipt_id`, and signature;
- buyer, approver, procurement system, contract reference, and clause fields;
- effective/expiry timestamp ordering;
- at least one accepted vendor;
- trust-network source artifact hash and manifest id when a manifest is
  supplied;
- full trust-network manifest verification and source proof-pack verification
  when source packs are supplied.

Without the source manifest, verification can only prove receipt integrity and
the embedded manifest binding; it emits a warning.

## Evidence Chain Entry

`trustai procurement-clause-append` verifies the receipt, then appends
`procurement.clause.recorded` to an evidence chain. The entry payload records
the receipt id, receipt hash, buyer, contract reference, requirements, source
artifact reference, and limitations.

## Reference Commands

```powershell
python -m trustai procurement-clause artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --contract-ref MSA-2026-AITRADE-001 --approver-ref procurement@example.com --effective-at 2026-07-11T00:00:00Z --expires-at 2027-07-11T00:00:00Z --issued-at 2026-07-10T00:00:00Z --out artifacts/procurement-clause-receipt.json
python -m trustai procurement-clause-verify artifacts/procurement-clause-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json
python -m trustai procurement-clause-append artifacts/procurement-clause-receipt.json --state .trustai/procurement-demo/evidence-chain.json --tenant procurement-local --out artifacts/procurement-clause-entry.json
```

## Production Boundary

This local receipt models the procurement evidence shape. Production deployments
still need authenticated buyer/vendor identity-provider events, contract-management or procurement-platform
integration, immutable approval trails, delegated approver policy, and dispute
workflow for rejected vendor submissions.
