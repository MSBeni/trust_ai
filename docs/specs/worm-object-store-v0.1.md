# WORM Object Store v0.1

The local WORM object store models immutable artifact retention for proof packs,
chain anchors, release manifests, and other TrustAI evidence. It is a
content-addressed local reference for the roadmap's S3 Object Lock/WORM store.

## Receipt Schema

`schema`: `trustai.worm-receipt/0.1`

Fields:

- `receipt_id`: canonical hash of the receipt body without `receipt_id`.
- `artifact_type`: producer supplied artifact category.
- `content_hash`: canonical hash over the stored object's SHA-256 digest.
- `size_bytes`: stored object size.
- `stored_at`: RFC3339 storage timestamp.
- `retention_until`: RFC3339 retention timestamp.
- `object_path`: content-addressed object path relative to the store root.

`trustai worm-audit` verifies the receipt id, stored object existence, stored
object hash, stored object size, retention timestamp validity, and retention
active status.

## Legal Hold Schema

`schema`: `trustai.worm-legal-hold/0.1`

Fields:

- `legal_hold_id`: canonical hash of the hold body without `legal_hold_id`.
- `status`: `on`.
- `worm_receipt_id`: referenced WORM receipt id.
- `artifact_type`, `content_hash`, `object_path`: receipt fields bound into the
  hold.
- `case_id`: legal, regulatory, or audit matter identifier.
- `reason`: preservation reason.
- `applied_by`: actor applying the hold.
- `applied_at`: RFC3339 hold timestamp.

`trustai worm-legal-hold` creates a hold receipt only after the referenced WORM
receipt and stored object audit successfully. `trustai worm-audit --legal-hold`
then verifies the receipt and the hold together. A legal hold can be active even
when the original retention timestamp has expired.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai seal artifacts/aitrade-proof-pack.json --artifact-type proof-pack --out artifacts/aitrade-proof-pack.worm-receipt.json
python -m trustai worm-legal-hold artifacts/aitrade-proof-pack.worm-receipt.json --case-id external-audit-2026-001 --reason "Preserve proof pack for external audit." --applied-by legal@example.com --out artifacts/aitrade-proof-pack.legal-hold.json
python -m trustai worm-audit artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json
```

This local store verifies the evidence shape. Production deployments still need
cloud Object Lock compliance mode, privileged deletion controls, legal hold
release governance, bucket policy enforcement, and independent storage audit
logs.
