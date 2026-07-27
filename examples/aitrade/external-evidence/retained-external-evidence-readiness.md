# External Evidence Production Readiness

- Readiness ID: `23a2e4766f63393b8496947b9666c353d77b816340abf158c1364caede018cb5`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `not-ready`
- Covered authority units: 45/71
- Production-usable covered authority units: 44
- Non-production covered authority units: 1
- Missing authority units: 26
- Remaining collection tasks: 26
- Placeholder source URIs: 26
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
- 26 authority units still lack accepted evidence
- 26 external evidence collection tasks remain open
- 26 source-map entries still use placeholder source URIs

## Next Actions

- Replace retained/example authority evidence with production authority exports, assign owner work packages, replace TODO source URIs with authority-owned sources, collect snapshots and intake receipts, rebuild the manifest, and rerun readiness with --require-ready.
