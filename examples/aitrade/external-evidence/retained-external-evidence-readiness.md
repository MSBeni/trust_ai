# External Evidence Production Readiness

- Readiness ID: `93e39f3bdf981e4afc361f3f28b7fdb86192594691f427f683c3620a052bfe7d`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `not-ready`
- Covered authority units: 32/71
- Production-usable covered authority units: 31
- Non-production covered authority units: 1
- Missing authority units: 39
- Remaining collection tasks: 39
- Placeholder source URIs: 39
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
- 39 authority units still lack accepted evidence
- 39 external evidence collection tasks remain open
- 39 source-map entries still use placeholder source URIs

## Next Actions

- Replace retained/example authority evidence with production authority exports, assign owner work packages, replace TODO source URIs with authority-owned sources, collect snapshots and intake receipts, rebuild the manifest, and rerun readiness with --require-ready.
