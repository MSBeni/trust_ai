# External Evidence Production Replacement Remediation Application

- Application ID: `9a089ee7d6bf84f642cfcfadd8a472a2a6c92b39293aa0fc30ccc223e64be0e1`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `blocked`
- Source review status: `blocked`
- Remediation review status: `blocked`
- Applied review status: `blocked`
- Tasks: 72
- Applied remediation tasks: 72
- Ready tasks: 0
- Blocked tasks: 72
- Placeholder source URIs: 72
- Live source URIs: 0

## Applied Review

- Applied submission review ID: `7a602827b844e8089af6581cdb465b0dbd84bac89492cb05302e8cf57aa80308`

## Blockers

- 72 applied production replacement tasks still use placeholder source_uri values
- 72 applied production replacement tasks are not ready to collect

## Next Actions

- Replace remaining placeholder source URIs in the remediation owner fulfillment template and rerun this application.
- Resolve blocked applied review tasks before creating a production collection package.

## Commands

- write_applied_review: `python -m trustai external-evidence-production-replacement-remediation-apply <submission-review.json> <remediation-review.json> --applied-review-out <applied-review.json>`
- collect_after_ready_application: `python -m trustai external-evidence-production-replacement-collection-package <applied-review.json> <manifest.json> <roadmap-audit.json> --require-ready`

## Limitations

- This artifact applies reviewed owner remediation into the production replacement review stream; it does not collect evidence or prove readiness by itself.
- Collection and closure still require source snapshots, intake receipts, rebuilt manifest coverage, and a ready external-evidence readiness report.
