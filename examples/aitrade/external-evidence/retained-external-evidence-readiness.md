# External Evidence Production Readiness

- Readiness ID: `86a40b34729695f30bf8813bad227752b2b40d8ccc1c7b66ad99180742f9435d`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `not-ready`
- Covered authority units: 72/72
- Production-usable covered authority units: 0
- Non-production covered authority units: 72
- Missing authority units: 0
- Remaining collection tasks: 0
- Placeholder source URIs: 0
- Work packages: 0

## Checks

| Check | Status | Summary |
|---|---|---|
| `artifacts-verify` | `passed` | All referenced external-evidence artifacts verify. |
| `covered-evidence-production-usable` | `failed` | Covered authority units use production authority evidence rather than retained examples or fixtures. |
| `authority-coverage-complete` | `passed` | Every required authority unit has accepted evidence. |
| `collection-work-closed` | `passed` | No external-evidence collection tasks remain open. |
| `source-map-live` | `passed` | Every source-map entry has a live authority source URI. |
| `work-package-current` | `passed` | The work package covers the current remaining task set. |

## Blockers

- 72 covered authority units use example or non-production evidence

## Next Actions

- Replace retained/example authority evidence with production authority exports, assign owner work packages, replace TODO source URIs with authority-owned sources, collect snapshots and intake receipts, rebuild the manifest, and rerun readiness with --require-ready.
