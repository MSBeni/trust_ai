# External Evidence Owner Fulfillment Template

- Template ID: `8bba81d8ff9fb77e8fb7e98ddc42391146ec7af6739e77a6209732b059ceb51c`
- Generated at: `2026-07-12T00:01:00Z`
- Fulfillments: 0
- Owners: 0
- Blocked tasks: 0
- Open tasks: 0
- Closed tasks: 0
- Placeholder source URIs: 0
- Missing intakes: 0

## Fulfillments

| Task | Source URI | Description |
|---|---|---|

## Assignments

| Task | Owner | Status | Blocking Reasons | Snapshot | Intake |
|---|---|---|---|---|---|

## Commands

- fill_then_fulfill_source_map: `python -m trustai external-evidence-source-map-fulfill <source-map.json> <plan.json> --fulfillment-file <this-template.json> --require-live-source-uris --out <fulfilled-source-map.json>`
- collect_after_fulfillment: `python -m trustai external-evidence-collect-batch <fulfilled-source-map.json> <manifest.json> <roadmap-audit.json> --root . --require-live-source-uris`
- rebuild_manifest_after_intakes: `python -m trustai external-evidence-manifest-from-intakes <plan.json> <manifest.json> <roadmap-audit.json> --intake-dir <intake-dir> --require-live-source-uris --require-source-snapshot-artifacts`

## Limitations

- This template is a handoff artifact; it does not satisfy missing external authority evidence by itself.
- Placeholder source URIs intentionally keep readiness blocked until owners replace them with live authority sources.
