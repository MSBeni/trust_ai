# External Evidence Production Readiness

- Readiness ID: `96e7787ebb33fe0704d3a51017e1eb8528602695f62fee5b0015391085611fef`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `not-ready`
- Covered authority units: 25/71
- Production-usable covered authority units: 24
- Non-production covered authority units: 1
- Missing authority units: 46
- Remaining collection tasks: 46
- Placeholder source URIs: 46
- Work packages: 9

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
- 46 authority units still lack accepted evidence
- 46 external evidence collection tasks remain open
- 46 source-map entries still use placeholder source URIs

## Next Actions

- Replace retained/example authority evidence with production authority exports, assign owner work packages, replace TODO source URIs with authority-owned sources, collect snapshots and intake receipts, rebuild the manifest, and rerun readiness with --require-ready.
