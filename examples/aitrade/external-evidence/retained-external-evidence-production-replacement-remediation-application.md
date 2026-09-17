# External Evidence Production Replacement Remediation Application

- Application ID: `5d32027b46dde5295ce35d01f63652c92eb85bacba3012d4f7f78418796a933d`
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

- Applied submission review ID: `353f8127d547755b1331cab9f104c2a9d458ec18e743f5a3934ec5e55db3f144`

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
