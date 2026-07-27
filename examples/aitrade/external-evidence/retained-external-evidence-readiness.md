# External Evidence Production Readiness

- Readiness ID: `2afe40860c69e8f35f4306034b5a8aa61d59df0c0797aa529fab7a20d27e9df7`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `not-ready`
- Covered authority units: 19/71
- Production-usable covered authority units: 18
- Non-production covered authority units: 1
- Missing authority units: 52
- Remaining collection tasks: 52
- Placeholder source URIs: 52
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
- 52 authority units still lack accepted evidence
- 52 external evidence collection tasks remain open
- 52 source-map entries still use placeholder source URIs

## Next Actions

- Replace retained/example authority evidence with production authority exports, assign owner work packages, replace TODO source URIs with authority-owned sources, collect snapshots and intake receipts, rebuild the manifest, and rerun readiness with --require-ready.
