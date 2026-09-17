# External Evidence Production Replacement Remediation Queue

- Queue ID: `db372bc13109fc5afa3db4e3e924c09ec5e2e23a3fffe829018b7d5a6b8b8dd9`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `blocked`
- Review status: `blocked`
- Tasks: 72
- Ready tasks: 0
- Remediation tasks: 72
- Owners: 10
- Placeholder source URIs: 72
- Live source URIs in blocked rows: 0

## Counts By Owner

- IAM/identity owner: 8
- cloud storage owner: 1
- customer success/account owner: 10
- integration/platform owner: 13
- legal/compliance owner: 5
- release engineering: 9
- risk/insurance owner: 4
- security/platform KMS owner: 7
- service owner: 9
- standards/governance owner: 6

## Counts By Authority

- `ci-run`: 9
- `cloud-object-lock`: 1
- `customer`: 10
- `hosted-service`: 9
- `identity-provider`: 8
- `insurer`: 4
- `kms-hsm`: 7
- `provider-api`: 13
- `regulator`: 5
- `standards-body`: 6

## Remediation Items

| Task | Owner | Requirement | Authority | Source URI Status | Blocking Reasons | Action |
|---|---|---|---|---|---|---|
| `agent-inventory-and-identity:identity-provider` | IAM/identity owner | `agent-inventory-and-identity` | `identity-provider` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `auditor-and-review-portal:identity-provider` | IAM/identity owner | `auditor-and-review-portal` | `identity-provider` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `cicd-provider-approvals:identity-provider` | IAM/identity owner | `cicd-provider-approvals` | `identity-provider` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `insurer-api-and-actuarial-products:identity-provider` | IAM/identity owner | `insurer-api-and-actuarial-products` | `identity-provider` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `runtime-policy-and-attestation:identity-provider` | IAM/identity owner | `runtime-policy-and-attestation` | `identity-provider` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `self-serve-onboarding:identity-provider` | IAM/identity owner | `self-serve-onboarding` | `identity-provider` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `shadow-replay-temporal-holdout:identity-provider` | IAM/identity owner | `shadow-replay-temporal-holdout` | `identity-provider` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `trust-network-procurement-and-marketplace:identity-provider` | IAM/identity owner | `trust-network-procurement-and-marketplace` | `identity-provider` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `byoc-self-hosted:cloud-object-lock` | cloud storage owner | `byoc-self-hosted` | `cloud-object-lock` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `byoc-self-hosted:customer` | customer success/account owner | `byoc-self-hosted` | `customer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `design-partner-pilot-exit-criteria:customer` | customer success/account owner | `design-partner-pilot-exit-criteria` | `customer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `insurer-api-and-actuarial-products:customer` | customer success/account owner | `insurer-api-and-actuarial-products` | `customer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `product-scope-discipline:customer` | customer success/account owner | `product-scope-discipline` | `customer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `roadmap-phase-scoreboard:customer` | customer success/account owner | `roadmap-phase-scoreboard` | `customer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `shadow-replay-temporal-holdout:customer` | customer success/account owner | `shadow-replay-temporal-holdout` | `customer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `state-of-agent-reliability-report:customer` | customer success/account owner | `state-of-agent-reliability-report` | `customer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `trust-network-procurement-and-marketplace:customer` | customer success/account owner | `trust-network-procurement-and-marketplace` | `customer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `trustai-own-compliance:customer` | customer success/account owner | `trustai-own-compliance` | `customer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `vertical-packs:customer` | customer success/account owner | `vertical-packs` | `customer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `agent-inventory-and-identity:provider-api` | integration/platform owner | `agent-inventory-and-identity` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `auditor-and-review-portal:provider-api` | integration/platform owner | `auditor-and-review-portal` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `byoc-self-hosted:provider-api` | integration/platform owner | `byoc-self-hosted` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `cicd-provider-approvals:provider-api` | integration/platform owner | `cicd-provider-approvals` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `compliance-mapper-and-eu-ai-act:provider-api` | integration/platform owner | `compliance-mapper-and-eu-ai-act` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `framework-adapters:provider-api` | integration/platform owner | `framework-adapters` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `insurer-api-and-actuarial-products:provider-api` | integration/platform owner | `insurer-api-and-actuarial-products` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `mcp-gateway:provider-api` | integration/platform owner | `mcp-gateway` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `oss-verifier-and-public-spec:provider-api` | integration/platform owner | `oss-verifier-and-public-spec` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `runtime-policy-and-attestation:provider-api` | integration/platform owner | `runtime-policy-and-attestation` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `self-serve-onboarding:provider-api` | integration/platform owner | `self-serve-onboarding` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `shadow-replay-temporal-holdout:provider-api` | integration/platform owner | `shadow-replay-temporal-holdout` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `trust-network-procurement-and-marketplace:provider-api` | integration/platform owner | `trust-network-procurement-and-marketplace` | `provider-api` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `auditor-and-review-portal:regulator` | legal/compliance owner | `auditor-and-review-portal` | `regulator` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `compliance-mapper-and-eu-ai-act:regulator` | legal/compliance owner | `compliance-mapper-and-eu-ai-act` | `regulator` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `design-partner-pilot-exit-criteria:regulator` | legal/compliance owner | `design-partner-pilot-exit-criteria` | `regulator` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `roadmap-phase-scoreboard:regulator` | legal/compliance owner | `roadmap-phase-scoreboard` | `regulator` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `vertical-packs:regulator` | legal/compliance owner | `vertical-packs` | `regulator` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `byoc-self-hosted:ci-run` | release engineering | `byoc-self-hosted` | `ci-run` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `cicd-provider-approvals:ci-run` | release engineering | `cicd-provider-approvals` | `ci-run` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `framework-adapters:ci-run` | release engineering | `framework-adapters` | `ci-run` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `insurer-api-and-actuarial-products:ci-run` | release engineering | `insurer-api-and-actuarial-products` | `ci-run` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `mcp-gateway:ci-run` | release engineering | `mcp-gateway` | `ci-run` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `oss-verifier-and-public-spec:ci-run` | release engineering | `oss-verifier-and-public-spec` | `ci-run` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `product-scope-discipline:ci-run` | release engineering | `product-scope-discipline` | `ci-run` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `roadmap-phase-scoreboard:ci-run` | release engineering | `roadmap-phase-scoreboard` | `ci-run` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `runtime-policy-and-attestation:ci-run` | release engineering | `runtime-policy-and-attestation` | `ci-run` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `design-partner-pilot-exit-criteria:insurer` | risk/insurance owner | `design-partner-pilot-exit-criteria` | `insurer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `insurer-api-and-actuarial-products:insurer` | risk/insurance owner | `insurer-api-and-actuarial-products` | `insurer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `roadmap-phase-scoreboard:insurer` | risk/insurance owner | `roadmap-phase-scoreboard` | `insurer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `vertical-packs:insurer` | risk/insurance owner | `vertical-packs` | `insurer` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `auditor-and-review-portal:kms-hsm` | security/platform KMS owner | `auditor-and-review-portal` | `kms-hsm` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `byoc-self-hosted:kms-hsm` | security/platform KMS owner | `byoc-self-hosted` | `kms-hsm` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `insurer-api-and-actuarial-products:kms-hsm` | security/platform KMS owner | `insurer-api-and-actuarial-products` | `kms-hsm` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `mcp-gateway:kms-hsm` | security/platform KMS owner | `mcp-gateway` | `kms-hsm` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `runtime-policy-and-attestation:kms-hsm` | security/platform KMS owner | `runtime-policy-and-attestation` | `kms-hsm` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `shadow-replay-temporal-holdout:kms-hsm` | security/platform KMS owner | `shadow-replay-temporal-holdout` | `kms-hsm` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `standards-track-and-auditor-ecosystem:kms-hsm` | security/platform KMS owner | `standards-track-and-auditor-ecosystem` | `kms-hsm` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `auditor-and-review-portal:hosted-service` | service owner | `auditor-and-review-portal` | `hosted-service` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `cicd-provider-approvals:hosted-service` | service owner | `cicd-provider-approvals` | `hosted-service` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `framework-adapters:hosted-service` | service owner | `framework-adapters` | `hosted-service` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `insurer-api-and-actuarial-products:hosted-service` | service owner | `insurer-api-and-actuarial-products` | `hosted-service` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `mcp-gateway:hosted-service` | service owner | `mcp-gateway` | `hosted-service` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `oss-verifier-and-public-spec:hosted-service` | service owner | `oss-verifier-and-public-spec` | `hosted-service` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `runtime-policy-and-attestation:hosted-service` | service owner | `runtime-policy-and-attestation` | `hosted-service` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `self-serve-onboarding:hosted-service` | service owner | `self-serve-onboarding` | `hosted-service` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `trust-network-procurement-and-marketplace:hosted-service` | service owner | `trust-network-procurement-and-marketplace` | `hosted-service` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `byoc-self-hosted:standards-body` | standards/governance owner | `byoc-self-hosted` | `standards-body` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `compliance-mapper-and-eu-ai-act:standards-body` | standards/governance owner | `compliance-mapper-and-eu-ai-act` | `standards-body` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `roadmap-phase-scoreboard:standards-body` | standards/governance owner | `roadmap-phase-scoreboard` | `standards-body` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `shadow-replay-temporal-holdout:standards-body` | standards/governance owner | `shadow-replay-temporal-holdout` | `standards-body` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `standards-track-and-auditor-ecosystem:standards-body` | standards/governance owner | `standards-track-and-auditor-ecosystem` | `standards-body` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |
| `trustai-own-compliance:standards-body` | standards/governance owner | `trustai-own-compliance` | `standards-body` | placeholder | placeholder-source-uri | replace source_uri and authority metadata with a live production authority-owned source, then regenerate the submission review |

## Review Blockers

- production replacement submission review contains 72 placeholder source_uri values
- fulfilled production source map: source map contains 72 placeholder source_uri values but live source URIs are required

## Commands

- apply_fulfillment: `python -m trustai external-evidence-production-replacement-submission <intake-template.json> --fulfillment-file <remediated-fulfillments.json> --require-submitted-live-source-uris --submitted-template-out <submitted-template.json>`
- review_after_remediation: `python -m trustai external-evidence-production-replacement-submission-review <submitted-template.json> <status-report.json> <plan-all.json> --require-live-source-uris --require-ready --out <review.json>`
- verify_queue_clear: `python -m trustai external-evidence-production-replacement-remediation-queue-verify <queue.json> <review.json> --require-empty`
- collect_after_clear: `python -m trustai external-evidence-production-replacement-collection-package <ready-review.json> <manifest.json> <roadmap-audit.json> --require-ready`

## Next Actions

- Assign every remediation item to its owner_hint and replace placeholder authority metadata with live production authority exports.
- Regenerate the production replacement submission and submission review with strict live-source URI checks.
- Only collect source snapshots after this queue verifies with --require-empty against a ready submission review.

## Limitations

- This queue is a remediation control artifact; it does not claim production evidence has been collected or accepted.
- A blocked queue preserves the exact production replacement work still needed before proof packs can be production-ready.
