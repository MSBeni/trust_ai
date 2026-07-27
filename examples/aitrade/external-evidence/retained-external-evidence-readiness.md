# External Evidence Production Readiness

- Readiness ID: `1cb4304ba960ed5ef8a1308af9e531c1ad195df472c750bb8ba240c27a6ed4e7`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `not-ready`
- Covered authority units: 50/71
- Production-usable covered authority units: 49
- Non-production covered authority units: 1
- Missing authority units: 21
- Remaining collection tasks: 21
- Placeholder source URIs: 21
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
- 21 authority units still lack accepted evidence
- 21 external evidence collection tasks remain open
- 21 source-map entries still use placeholder source URIs

## Next Actions

- Replace retained/example authority evidence with production authority exports, assign owner work packages, replace TODO source URIs with authority-owned sources, collect snapshots and intake receipts, rebuild the manifest, and rerun readiness with --require-ready.
