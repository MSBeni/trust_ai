# External Evidence Production Readiness

- Readiness ID: `e2e8626cfcf0ed3ec0699d37b8f09c4dcffe8aa3d109d6342f5b0fa3db51804f`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `not-ready`
- Covered authority units: 15/71
- Production-usable covered authority units: 14
- Non-production covered authority units: 1
- Missing authority units: 56
- Remaining collection tasks: 56
- Placeholder source URIs: 56
- Work packages: 10

## Checks

| Check | Status | Summary |
|---|---|---|
| `artifacts-verify` | `passed` | All referenced external-evidence artifacts verify. |
| `covered-evidence-production-usable` | `failed` | Covered authority units use production authority evidence rather than retained examples or fixtures. |
| `authority-coverage-complete` | `failed` | Every required authority unit has accepted evidence. |
| `collection-work-closed` | `failed` | No external-evidence collection tasks remain open. |
| `source-map-live` | `failed` | Every source-map entry has a live authority source URI. |
| `work-package-current` | `passed` | The work package covers the current remaining task set. |

## Blockers

- 1 covered authority units use example or non-production evidence
- 56 authority units still lack accepted evidence
- 56 external evidence collection tasks remain open
- 56 source-map entries still use placeholder source URIs

## Next Actions

- Replace retained/example authority evidence with production authority exports, assign owner work packages, replace TODO source URIs with authority-owned sources, collect snapshots and intake receipts, rebuild the manifest, and rerun readiness with --require-ready.
