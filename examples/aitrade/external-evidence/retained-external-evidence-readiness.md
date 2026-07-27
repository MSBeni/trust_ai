# External Evidence Production Readiness

- Readiness ID: `5bde5a2db9fb47a0027714ed9b54623d6baa3c4eade3cb3897d9a1a472f4e42c`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `not-ready`
- Covered authority units: 3/71
- Production-usable covered authority units: 2
- Non-production covered authority units: 1
- Missing authority units: 68
- Remaining collection tasks: 68
- Placeholder source URIs: 68
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
- 68 authority units still lack accepted evidence
- 68 external evidence collection tasks remain open
- 68 source-map entries still use placeholder source URIs

## Next Actions

- Replace retained/example authority evidence with production authority exports, assign owner work packages, replace TODO source URIs with authority-owned sources, collect snapshots and intake receipts, rebuild the manifest, and rerun readiness with --require-ready.
