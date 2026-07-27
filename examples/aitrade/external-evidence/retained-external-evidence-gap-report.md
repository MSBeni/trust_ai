# External Evidence Gap Report

- Gap report ID: `c726507ea4542d558fc70fa1d0cb876d24d76513099b65c29c1cbaa07c18589d`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `partial`
- Covered authority kinds: 3/71
- Missing authority kinds: 68
- Remaining collection tasks: 68
- Source-map entries: 68
- Placeholder source URIs: 68
- Live source URIs: 0

## Gaps By Authority Kind

- `ci-run`: 8
- `cloud-object-lock`: 1
- `customer`: 9
- `hosted-service`: 8
- `identity-provider`: 8
- `insurer`: 4
- `kms-hsm`: 7
- `provider-api`: 12
- `regulator`: 5
- `standards-body`: 6

## Gaps By Requirement

- `agent-inventory-and-identity`: 2
- `auditor-and-review-portal`: 5
- `byoc-self-hosted`: 6
- `cicd-provider-approvals`: 4
- `compliance-mapper-and-eu-ai-act`: 3
- `design-partner-pilot-exit-criteria`: 3
- `framework-adapters`: 3
- `insurer-api-and-actuarial-products`: 7
- `mcp-gateway`: 4
- `product-scope-discipline`: 2
- `roadmap-phase-scoreboard`: 5
- `runtime-policy-and-attestation`: 5
- `self-serve-onboarding`: 3
- `shadow-replay-temporal-holdout`: 4
- `standards-track-and-auditor-ecosystem`: 2
- `state-of-agent-reliability-report`: 1
- `trust-network-procurement-and-marketplace`: 4
- `trustai-own-compliance`: 2
- `vertical-packs`: 3

## Collection Worklist

### self-serve-onboarding:provider-api

- Title: Self-serve SDK and MCP gateway onboarding
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for self-serve-onboarding
- Source URI: `TODO://authority/self-serve-onboarding/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/self-serve-onboarding/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/self-serve-onboarding/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### self-serve-onboarding:hosted-service

- Title: Self-serve SDK and MCP gateway onboarding
- Authority kind: `hosted-service`
- Owner hint: service owner
- Description: hosted-service evidence for self-serve-onboarding
- Source URI: `TODO://authority/self-serve-onboarding/hosted-service`
- Snapshot output: `artifacts/external-evidence-sources/self-serve-onboarding/hosted-service.json`
- Intake output: `artifacts/external-evidence-intakes/self-serve-onboarding/hosted-service.json`
- Suggested evidence sources: hosted service health or deployment export; service audit root; operational SLO/status evidence

### self-serve-onboarding:identity-provider

- Title: Self-serve SDK and MCP gateway onboarding
- Authority kind: `identity-provider`
- Owner hint: IAM/identity owner
- Description: identity-provider evidence for self-serve-onboarding
- Source URI: `TODO://authority/self-serve-onboarding/identity-provider`
- Snapshot output: `artifacts/external-evidence-sources/self-serve-onboarding/identity-provider.json`
- Intake output: `artifacts/external-evidence-intakes/self-serve-onboarding/identity-provider.json`
- Suggested evidence sources: identity-provider event export; OIDC/session/lifecycle evidence; RBAC or account-state report

### mcp-gateway:ci-run

- Title: MCP evidence gateway reference capture
- Authority kind: `ci-run`
- Owner hint: release engineering
- Description: ci-run evidence for mcp-gateway
- Source URI: `TODO://authority/mcp-gateway/ci-run`
- Snapshot output: `artifacts/external-evidence-sources/mcp-gateway/ci-run.json`
- Intake output: `artifacts/external-evidence-intakes/mcp-gateway/ci-run.json`
- Suggested evidence sources: completed CI workflow export; release run URL or provider-native run record; artifact/check provenance

### mcp-gateway:kms-hsm

- Title: MCP evidence gateway reference capture
- Authority kind: `kms-hsm`
- Owner hint: security/platform KMS owner
- Description: kms-hsm evidence for mcp-gateway
- Source URI: `TODO://authority/mcp-gateway/kms-hsm`
- Snapshot output: `artifacts/external-evidence-sources/mcp-gateway/kms-hsm.json`
- Intake output: `artifacts/external-evidence-intakes/mcp-gateway/kms-hsm.json`
- Suggested evidence sources: KMS/HSM key policy export; signing operation receipt; custody or audit-log root

### mcp-gateway:provider-api

- Title: MCP evidence gateway reference capture
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for mcp-gateway
- Source URI: `TODO://authority/mcp-gateway/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/mcp-gateway/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/mcp-gateway/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### mcp-gateway:hosted-service

- Title: MCP evidence gateway reference capture
- Authority kind: `hosted-service`
- Owner hint: service owner
- Description: hosted-service evidence for mcp-gateway
- Source URI: `TODO://authority/mcp-gateway/hosted-service`
- Snapshot output: `artifacts/external-evidence-sources/mcp-gateway/hosted-service.json`
- Intake output: `artifacts/external-evidence-intakes/mcp-gateway/hosted-service.json`
- Suggested evidence sources: hosted service health or deployment export; service audit root; operational SLO/status evidence

### shadow-replay-temporal-holdout:kms-hsm

- Title: Shadow replay, temporal holdout, soak reports, and distributional re-execution
- Authority kind: `kms-hsm`
- Owner hint: security/platform KMS owner
- Description: kms-hsm evidence for shadow-replay-temporal-holdout
- Source URI: `TODO://authority/shadow-replay-temporal-holdout/kms-hsm`
- Snapshot output: `artifacts/external-evidence-sources/shadow-replay-temporal-holdout/kms-hsm.json`
- Intake output: `artifacts/external-evidence-intakes/shadow-replay-temporal-holdout/kms-hsm.json`
- Suggested evidence sources: KMS/HSM key policy export; signing operation receipt; custody or audit-log root

### shadow-replay-temporal-holdout:provider-api

- Title: Shadow replay, temporal holdout, soak reports, and distributional re-execution
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for shadow-replay-temporal-holdout
- Source URI: `TODO://authority/shadow-replay-temporal-holdout/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/shadow-replay-temporal-holdout/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/shadow-replay-temporal-holdout/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### shadow-replay-temporal-holdout:identity-provider

- Title: Shadow replay, temporal holdout, soak reports, and distributional re-execution
- Authority kind: `identity-provider`
- Owner hint: IAM/identity owner
- Description: identity-provider evidence for shadow-replay-temporal-holdout
- Source URI: `TODO://authority/shadow-replay-temporal-holdout/identity-provider`
- Snapshot output: `artifacts/external-evidence-sources/shadow-replay-temporal-holdout/identity-provider.json`
- Intake output: `artifacts/external-evidence-intakes/shadow-replay-temporal-holdout/identity-provider.json`
- Suggested evidence sources: identity-provider event export; OIDC/session/lifecycle evidence; RBAC or account-state report

### shadow-replay-temporal-holdout:standards-body

- Title: Shadow replay, temporal holdout, soak reports, and distributional re-execution
- Authority kind: `standards-body`
- Owner hint: standards/governance owner
- Description: standards-body evidence for shadow-replay-temporal-holdout
- Source URI: `TODO://authority/shadow-replay-temporal-holdout/standards-body`
- Snapshot output: `artifacts/external-evidence-sources/shadow-replay-temporal-holdout/standards-body.json`
- Intake output: `artifacts/external-evidence-intakes/shadow-replay-temporal-holdout/standards-body.json`
- Suggested evidence sources: standards-body submission receipt; working-group status record; ballot or docket export

### cicd-provider-approvals:ci-run

- Title: CI/CD promotion gates, provider callbacks, and Slack approvals
- Authority kind: `ci-run`
- Owner hint: release engineering
- Description: ci-run evidence for cicd-provider-approvals
- Source URI: `TODO://authority/cicd-provider-approvals/ci-run`
- Snapshot output: `artifacts/external-evidence-sources/cicd-provider-approvals/ci-run.json`
- Intake output: `artifacts/external-evidence-intakes/cicd-provider-approvals/ci-run.json`
- Suggested evidence sources: completed CI workflow export; release run URL or provider-native run record; artifact/check provenance

### cicd-provider-approvals:provider-api

- Title: CI/CD promotion gates, provider callbacks, and Slack approvals
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for cicd-provider-approvals
- Source URI: `TODO://authority/cicd-provider-approvals/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/cicd-provider-approvals/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/cicd-provider-approvals/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### cicd-provider-approvals:hosted-service

- Title: CI/CD promotion gates, provider callbacks, and Slack approvals
- Authority kind: `hosted-service`
- Owner hint: service owner
- Description: hosted-service evidence for cicd-provider-approvals
- Source URI: `TODO://authority/cicd-provider-approvals/hosted-service`
- Snapshot output: `artifacts/external-evidence-sources/cicd-provider-approvals/hosted-service.json`
- Intake output: `artifacts/external-evidence-intakes/cicd-provider-approvals/hosted-service.json`
- Suggested evidence sources: hosted service health or deployment export; service audit root; operational SLO/status evidence

### cicd-provider-approvals:identity-provider

- Title: CI/CD promotion gates, provider callbacks, and Slack approvals
- Authority kind: `identity-provider`
- Owner hint: IAM/identity owner
- Description: identity-provider evidence for cicd-provider-approvals
- Source URI: `TODO://authority/cicd-provider-approvals/identity-provider`
- Snapshot output: `artifacts/external-evidence-sources/cicd-provider-approvals/identity-provider.json`
- Intake output: `artifacts/external-evidence-intakes/cicd-provider-approvals/identity-provider.json`
- Suggested evidence sources: identity-provider event export; OIDC/session/lifecycle evidence; RBAC or account-state report

### design-partner-pilot-exit-criteria:regulator

- Title: Design-partner pilot and external-scrutiny exit criteria
- Authority kind: `regulator`
- Owner hint: legal/compliance owner
- Description: regulator evidence for design-partner-pilot-exit-criteria
- Source URI: `TODO://authority/design-partner-pilot-exit-criteria/regulator`
- Snapshot output: `artifacts/external-evidence-sources/design-partner-pilot-exit-criteria/regulator.json`
- Intake output: `artifacts/external-evidence-intakes/design-partner-pilot-exit-criteria/regulator.json`
- Suggested evidence sources: regulator acknowledgement; supervisor portal receipt; conformity-assessment record

### design-partner-pilot-exit-criteria:insurer

- Title: Design-partner pilot and external-scrutiny exit criteria
- Authority kind: `insurer`
- Owner hint: risk/insurance owner
- Description: insurer evidence for design-partner-pilot-exit-criteria
- Source URI: `TODO://authority/design-partner-pilot-exit-criteria/insurer`
- Snapshot output: `artifacts/external-evidence-sources/design-partner-pilot-exit-criteria/insurer.json`
- Intake output: `artifacts/external-evidence-intakes/design-partner-pilot-exit-criteria/insurer.json`
- Suggested evidence sources: underwriter response; premium or policy-system quote; insurer API response export

### design-partner-pilot-exit-criteria:customer

- Title: Design-partner pilot and external-scrutiny exit criteria
- Authority kind: `customer`
- Owner hint: customer success/account owner
- Description: customer evidence for design-partner-pilot-exit-criteria
- Source URI: `TODO://authority/design-partner-pilot-exit-criteria/customer`
- Snapshot output: `artifacts/external-evidence-sources/design-partner-pilot-exit-criteria/customer.json`
- Intake output: `artifacts/external-evidence-intakes/design-partner-pilot-exit-criteria/customer.json`
- Suggested evidence sources: customer acceptance artifact; contract/payment/procurement evidence; deployment or signoff record

### framework-adapters:ci-run

- Title: Framework adapters for LangGraph, OpenAI Agents, Claude, CrewAI, Bedrock, and Vertex
- Authority kind: `ci-run`
- Owner hint: release engineering
- Description: ci-run evidence for framework-adapters
- Source URI: `TODO://authority/framework-adapters/ci-run`
- Snapshot output: `artifacts/external-evidence-sources/framework-adapters/ci-run.json`
- Intake output: `artifacts/external-evidence-intakes/framework-adapters/ci-run.json`
- Suggested evidence sources: completed CI workflow export; release run URL or provider-native run record; artifact/check provenance

### framework-adapters:provider-api

- Title: Framework adapters for LangGraph, OpenAI Agents, Claude, CrewAI, Bedrock, and Vertex
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for framework-adapters
- Source URI: `TODO://authority/framework-adapters/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/framework-adapters/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/framework-adapters/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### framework-adapters:hosted-service

- Title: Framework adapters for LangGraph, OpenAI Agents, Claude, CrewAI, Bedrock, and Vertex
- Authority kind: `hosted-service`
- Owner hint: service owner
- Description: hosted-service evidence for framework-adapters
- Source URI: `TODO://authority/framework-adapters/hosted-service`
- Snapshot output: `artifacts/external-evidence-sources/framework-adapters/hosted-service.json`
- Intake output: `artifacts/external-evidence-intakes/framework-adapters/hosted-service.json`
- Suggested evidence sources: hosted service health or deployment export; service audit root; operational SLO/status evidence

### auditor-and-review-portal:kms-hsm

- Title: Auditor view, supervised access, regulator view, and review portal attestations
- Authority kind: `kms-hsm`
- Owner hint: security/platform KMS owner
- Description: kms-hsm evidence for auditor-and-review-portal
- Source URI: `TODO://authority/auditor-and-review-portal/kms-hsm`
- Snapshot output: `artifacts/external-evidence-sources/auditor-and-review-portal/kms-hsm.json`
- Intake output: `artifacts/external-evidence-intakes/auditor-and-review-portal/kms-hsm.json`
- Suggested evidence sources: KMS/HSM key policy export; signing operation receipt; custody or audit-log root

### auditor-and-review-portal:provider-api

- Title: Auditor view, supervised access, regulator view, and review portal attestations
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for auditor-and-review-portal
- Source URI: `TODO://authority/auditor-and-review-portal/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/auditor-and-review-portal/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/auditor-and-review-portal/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### auditor-and-review-portal:hosted-service

- Title: Auditor view, supervised access, regulator view, and review portal attestations
- Authority kind: `hosted-service`
- Owner hint: service owner
- Description: hosted-service evidence for auditor-and-review-portal
- Source URI: `TODO://authority/auditor-and-review-portal/hosted-service`
- Snapshot output: `artifacts/external-evidence-sources/auditor-and-review-portal/hosted-service.json`
- Intake output: `artifacts/external-evidence-intakes/auditor-and-review-portal/hosted-service.json`
- Suggested evidence sources: hosted service health or deployment export; service audit root; operational SLO/status evidence

### auditor-and-review-portal:identity-provider

- Title: Auditor view, supervised access, regulator view, and review portal attestations
- Authority kind: `identity-provider`
- Owner hint: IAM/identity owner
- Description: identity-provider evidence for auditor-and-review-portal
- Source URI: `TODO://authority/auditor-and-review-portal/identity-provider`
- Snapshot output: `artifacts/external-evidence-sources/auditor-and-review-portal/identity-provider.json`
- Intake output: `artifacts/external-evidence-intakes/auditor-and-review-portal/identity-provider.json`
- Suggested evidence sources: identity-provider event export; OIDC/session/lifecycle evidence; RBAC or account-state report

### auditor-and-review-portal:regulator

- Title: Auditor view, supervised access, regulator view, and review portal attestations
- Authority kind: `regulator`
- Owner hint: legal/compliance owner
- Description: regulator evidence for auditor-and-review-portal
- Source URI: `TODO://authority/auditor-and-review-portal/regulator`
- Snapshot output: `artifacts/external-evidence-sources/auditor-and-review-portal/regulator.json`
- Intake output: `artifacts/external-evidence-intakes/auditor-and-review-portal/regulator.json`
- Suggested evidence sources: regulator acknowledgement; supervisor portal receipt; conformity-assessment record

### byoc-self-hosted:ci-run

- Title: BYOC and self-hosted deployment scaffold with WORM/Object Lock attestations
- Authority kind: `ci-run`
- Owner hint: release engineering
- Description: ci-run evidence for byoc-self-hosted
- Source URI: `TODO://authority/byoc-self-hosted/ci-run`
- Snapshot output: `artifacts/external-evidence-sources/byoc-self-hosted/ci-run.json`
- Intake output: `artifacts/external-evidence-intakes/byoc-self-hosted/ci-run.json`
- Suggested evidence sources: completed CI workflow export; release run URL or provider-native run record; artifact/check provenance

### byoc-self-hosted:kms-hsm

- Title: BYOC and self-hosted deployment scaffold with WORM/Object Lock attestations
- Authority kind: `kms-hsm`
- Owner hint: security/platform KMS owner
- Description: kms-hsm evidence for byoc-self-hosted
- Source URI: `TODO://authority/byoc-self-hosted/kms-hsm`
- Snapshot output: `artifacts/external-evidence-sources/byoc-self-hosted/kms-hsm.json`
- Intake output: `artifacts/external-evidence-intakes/byoc-self-hosted/kms-hsm.json`
- Suggested evidence sources: KMS/HSM key policy export; signing operation receipt; custody or audit-log root

### byoc-self-hosted:cloud-object-lock

- Title: BYOC and self-hosted deployment scaffold with WORM/Object Lock attestations
- Authority kind: `cloud-object-lock`
- Owner hint: cloud storage owner
- Description: cloud-object-lock evidence for byoc-self-hosted
- Source URI: `TODO://authority/byoc-self-hosted/cloud-object-lock`
- Snapshot output: `artifacts/external-evidence-sources/byoc-self-hosted/cloud-object-lock.json`
- Intake output: `artifacts/external-evidence-intakes/byoc-self-hosted/cloud-object-lock.json`
- Suggested evidence sources: Object Lock retention export; legal-hold report; bucket/versioning policy evidence

### byoc-self-hosted:provider-api

- Title: BYOC and self-hosted deployment scaffold with WORM/Object Lock attestations
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for byoc-self-hosted
- Source URI: `TODO://authority/byoc-self-hosted/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/byoc-self-hosted/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/byoc-self-hosted/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### byoc-self-hosted:standards-body

- Title: BYOC and self-hosted deployment scaffold with WORM/Object Lock attestations
- Authority kind: `standards-body`
- Owner hint: standards/governance owner
- Description: standards-body evidence for byoc-self-hosted
- Source URI: `TODO://authority/byoc-self-hosted/standards-body`
- Snapshot output: `artifacts/external-evidence-sources/byoc-self-hosted/standards-body.json`
- Intake output: `artifacts/external-evidence-intakes/byoc-self-hosted/standards-body.json`
- Suggested evidence sources: standards-body submission receipt; working-group status record; ballot or docket export

### byoc-self-hosted:customer

- Title: BYOC and self-hosted deployment scaffold with WORM/Object Lock attestations
- Authority kind: `customer`
- Owner hint: customer success/account owner
- Description: customer evidence for byoc-self-hosted
- Source URI: `TODO://authority/byoc-self-hosted/customer`
- Snapshot output: `artifacts/external-evidence-sources/byoc-self-hosted/customer.json`
- Intake output: `artifacts/external-evidence-intakes/byoc-self-hosted/customer.json`
- Suggested evidence sources: customer acceptance artifact; contract/payment/procurement evidence; deployment or signoff record

### compliance-mapper-and-eu-ai-act:provider-api

- Title: Compliance framework mapper and EU AI Act technical documentation
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for compliance-mapper-and-eu-ai-act
- Source URI: `TODO://authority/compliance-mapper-and-eu-ai-act/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/compliance-mapper-and-eu-ai-act/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### compliance-mapper-and-eu-ai-act:regulator

- Title: Compliance framework mapper and EU AI Act technical documentation
- Authority kind: `regulator`
- Owner hint: legal/compliance owner
- Description: regulator evidence for compliance-mapper-and-eu-ai-act
- Source URI: `TODO://authority/compliance-mapper-and-eu-ai-act/regulator`
- Snapshot output: `artifacts/external-evidence-sources/compliance-mapper-and-eu-ai-act/regulator.json`
- Intake output: `artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/regulator.json`
- Suggested evidence sources: regulator acknowledgement; supervisor portal receipt; conformity-assessment record

### compliance-mapper-and-eu-ai-act:standards-body

- Title: Compliance framework mapper and EU AI Act technical documentation
- Authority kind: `standards-body`
- Owner hint: standards/governance owner
- Description: standards-body evidence for compliance-mapper-and-eu-ai-act
- Source URI: `TODO://authority/compliance-mapper-and-eu-ai-act/standards-body`
- Snapshot output: `artifacts/external-evidence-sources/compliance-mapper-and-eu-ai-act/standards-body.json`
- Intake output: `artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/standards-body.json`
- Suggested evidence sources: standards-body submission receipt; working-group status record; ballot or docket export

### trustai-own-compliance:standards-body

- Title: TrustAI own SOC 2 Type II and ISO/IEC 42001 compliance proof
- Authority kind: `standards-body`
- Owner hint: standards/governance owner
- Description: standards-body evidence for trustai-own-compliance
- Source URI: `TODO://authority/trustai-own-compliance/standards-body`
- Snapshot output: `artifacts/external-evidence-sources/trustai-own-compliance/standards-body.json`
- Intake output: `artifacts/external-evidence-intakes/trustai-own-compliance/standards-body.json`
- Suggested evidence sources: standards-body submission receipt; working-group status record; ballot or docket export

### trustai-own-compliance:customer

- Title: TrustAI own SOC 2 Type II and ISO/IEC 42001 compliance proof
- Authority kind: `customer`
- Owner hint: customer success/account owner
- Description: customer evidence for trustai-own-compliance
- Source URI: `TODO://authority/trustai-own-compliance/customer`
- Snapshot output: `artifacts/external-evidence-sources/trustai-own-compliance/customer.json`
- Intake output: `artifacts/external-evidence-intakes/trustai-own-compliance/customer.json`
- Suggested evidence sources: customer acceptance artifact; contract/payment/procurement evidence; deployment or signoff record

### vertical-packs:regulator

- Title: Vertical packs for trading, insurance claims, healthcare, and public sector
- Authority kind: `regulator`
- Owner hint: legal/compliance owner
- Description: regulator evidence for vertical-packs
- Source URI: `TODO://authority/vertical-packs/regulator`
- Snapshot output: `artifacts/external-evidence-sources/vertical-packs/regulator.json`
- Intake output: `artifacts/external-evidence-intakes/vertical-packs/regulator.json`
- Suggested evidence sources: regulator acknowledgement; supervisor portal receipt; conformity-assessment record

### vertical-packs:insurer

- Title: Vertical packs for trading, insurance claims, healthcare, and public sector
- Authority kind: `insurer`
- Owner hint: risk/insurance owner
- Description: insurer evidence for vertical-packs
- Source URI: `TODO://authority/vertical-packs/insurer`
- Snapshot output: `artifacts/external-evidence-sources/vertical-packs/insurer.json`
- Intake output: `artifacts/external-evidence-intakes/vertical-packs/insurer.json`
- Suggested evidence sources: underwriter response; premium or policy-system quote; insurer API response export

### vertical-packs:customer

- Title: Vertical packs for trading, insurance claims, healthcare, and public sector
- Authority kind: `customer`
- Owner hint: customer success/account owner
- Description: customer evidence for vertical-packs
- Source URI: `TODO://authority/vertical-packs/customer`
- Snapshot output: `artifacts/external-evidence-sources/vertical-packs/customer.json`
- Intake output: `artifacts/external-evidence-intakes/vertical-packs/customer.json`
- Suggested evidence sources: customer acceptance artifact; contract/payment/procurement evidence; deployment or signoff record

### insurer-api-and-actuarial-products:ci-run

- Title: Consent-gated insurer telemetry, underwriting quotes, and actuarial products
- Authority kind: `ci-run`
- Owner hint: release engineering
- Description: ci-run evidence for insurer-api-and-actuarial-products
- Source URI: `TODO://authority/insurer-api-and-actuarial-products/ci-run`
- Snapshot output: `artifacts/external-evidence-sources/insurer-api-and-actuarial-products/ci-run.json`
- Intake output: `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/ci-run.json`
- Suggested evidence sources: completed CI workflow export; release run URL or provider-native run record; artifact/check provenance

### insurer-api-and-actuarial-products:kms-hsm

- Title: Consent-gated insurer telemetry, underwriting quotes, and actuarial products
- Authority kind: `kms-hsm`
- Owner hint: security/platform KMS owner
- Description: kms-hsm evidence for insurer-api-and-actuarial-products
- Source URI: `TODO://authority/insurer-api-and-actuarial-products/kms-hsm`
- Snapshot output: `artifacts/external-evidence-sources/insurer-api-and-actuarial-products/kms-hsm.json`
- Intake output: `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/kms-hsm.json`
- Suggested evidence sources: KMS/HSM key policy export; signing operation receipt; custody or audit-log root

### insurer-api-and-actuarial-products:provider-api

- Title: Consent-gated insurer telemetry, underwriting quotes, and actuarial products
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for insurer-api-and-actuarial-products
- Source URI: `TODO://authority/insurer-api-and-actuarial-products/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/insurer-api-and-actuarial-products/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### insurer-api-and-actuarial-products:hosted-service

- Title: Consent-gated insurer telemetry, underwriting quotes, and actuarial products
- Authority kind: `hosted-service`
- Owner hint: service owner
- Description: hosted-service evidence for insurer-api-and-actuarial-products
- Source URI: `TODO://authority/insurer-api-and-actuarial-products/hosted-service`
- Snapshot output: `artifacts/external-evidence-sources/insurer-api-and-actuarial-products/hosted-service.json`
- Intake output: `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/hosted-service.json`
- Suggested evidence sources: hosted service health or deployment export; service audit root; operational SLO/status evidence

### insurer-api-and-actuarial-products:identity-provider

- Title: Consent-gated insurer telemetry, underwriting quotes, and actuarial products
- Authority kind: `identity-provider`
- Owner hint: IAM/identity owner
- Description: identity-provider evidence for insurer-api-and-actuarial-products
- Source URI: `TODO://authority/insurer-api-and-actuarial-products/identity-provider`
- Snapshot output: `artifacts/external-evidence-sources/insurer-api-and-actuarial-products/identity-provider.json`
- Intake output: `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/identity-provider.json`
- Suggested evidence sources: identity-provider event export; OIDC/session/lifecycle evidence; RBAC or account-state report

### insurer-api-and-actuarial-products:insurer

- Title: Consent-gated insurer telemetry, underwriting quotes, and actuarial products
- Authority kind: `insurer`
- Owner hint: risk/insurance owner
- Description: insurer evidence for insurer-api-and-actuarial-products
- Source URI: `TODO://authority/insurer-api-and-actuarial-products/insurer`
- Snapshot output: `artifacts/external-evidence-sources/insurer-api-and-actuarial-products/insurer.json`
- Intake output: `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/insurer.json`
- Suggested evidence sources: underwriter response; premium or policy-system quote; insurer API response export

### insurer-api-and-actuarial-products:customer

- Title: Consent-gated insurer telemetry, underwriting quotes, and actuarial products
- Authority kind: `customer`
- Owner hint: customer success/account owner
- Description: customer evidence for insurer-api-and-actuarial-products
- Source URI: `TODO://authority/insurer-api-and-actuarial-products/customer`
- Snapshot output: `artifacts/external-evidence-sources/insurer-api-and-actuarial-products/customer.json`
- Intake output: `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/customer.json`
- Suggested evidence sources: customer acceptance artifact; contract/payment/procurement evidence; deployment or signoff record

### state-of-agent-reliability-report:customer

- Title: State of Agent Reliability aggregate publication
- Authority kind: `customer`
- Owner hint: customer success/account owner
- Description: customer evidence for state-of-agent-reliability-report
- Source URI: `TODO://authority/state-of-agent-reliability-report/customer`
- Snapshot output: `artifacts/external-evidence-sources/state-of-agent-reliability-report/customer.json`
- Intake output: `artifacts/external-evidence-intakes/state-of-agent-reliability-report/customer.json`
- Suggested evidence sources: customer acceptance artifact; contract/payment/procurement evidence; deployment or signoff record

### roadmap-phase-scoreboard:ci-run

- Title: Roadmap phase exit-criteria business scoreboard
- Authority kind: `ci-run`
- Owner hint: release engineering
- Description: ci-run evidence for roadmap-phase-scoreboard
- Source URI: `TODO://authority/roadmap-phase-scoreboard/ci-run`
- Snapshot output: `artifacts/external-evidence-sources/roadmap-phase-scoreboard/ci-run.json`
- Intake output: `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/ci-run.json`
- Suggested evidence sources: completed CI workflow export; release run URL or provider-native run record; artifact/check provenance

### roadmap-phase-scoreboard:regulator

- Title: Roadmap phase exit-criteria business scoreboard
- Authority kind: `regulator`
- Owner hint: legal/compliance owner
- Description: regulator evidence for roadmap-phase-scoreboard
- Source URI: `TODO://authority/roadmap-phase-scoreboard/regulator`
- Snapshot output: `artifacts/external-evidence-sources/roadmap-phase-scoreboard/regulator.json`
- Intake output: `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json`
- Suggested evidence sources: regulator acknowledgement; supervisor portal receipt; conformity-assessment record

### roadmap-phase-scoreboard:insurer

- Title: Roadmap phase exit-criteria business scoreboard
- Authority kind: `insurer`
- Owner hint: risk/insurance owner
- Description: insurer evidence for roadmap-phase-scoreboard
- Source URI: `TODO://authority/roadmap-phase-scoreboard/insurer`
- Snapshot output: `artifacts/external-evidence-sources/roadmap-phase-scoreboard/insurer.json`
- Intake output: `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json`
- Suggested evidence sources: underwriter response; premium or policy-system quote; insurer API response export

### roadmap-phase-scoreboard:standards-body

- Title: Roadmap phase exit-criteria business scoreboard
- Authority kind: `standards-body`
- Owner hint: standards/governance owner
- Description: standards-body evidence for roadmap-phase-scoreboard
- Source URI: `TODO://authority/roadmap-phase-scoreboard/standards-body`
- Snapshot output: `artifacts/external-evidence-sources/roadmap-phase-scoreboard/standards-body.json`
- Intake output: `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json`
- Suggested evidence sources: standards-body submission receipt; working-group status record; ballot or docket export

### roadmap-phase-scoreboard:customer

- Title: Roadmap phase exit-criteria business scoreboard
- Authority kind: `customer`
- Owner hint: customer success/account owner
- Description: customer evidence for roadmap-phase-scoreboard
- Source URI: `TODO://authority/roadmap-phase-scoreboard/customer`
- Snapshot output: `artifacts/external-evidence-sources/roadmap-phase-scoreboard/customer.json`
- Intake output: `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/customer.json`
- Suggested evidence sources: customer acceptance artifact; contract/payment/procurement evidence; deployment or signoff record

### product-scope-discipline:ci-run

- Title: Product scope discipline and anti-focus decisions
- Authority kind: `ci-run`
- Owner hint: release engineering
- Description: ci-run evidence for product-scope-discipline
- Source URI: `TODO://authority/product-scope-discipline/ci-run`
- Snapshot output: `artifacts/external-evidence-sources/product-scope-discipline/ci-run.json`
- Intake output: `artifacts/external-evidence-intakes/product-scope-discipline/ci-run.json`
- Suggested evidence sources: completed CI workflow export; release run URL or provider-native run record; artifact/check provenance

### product-scope-discipline:customer

- Title: Product scope discipline and anti-focus decisions
- Authority kind: `customer`
- Owner hint: customer success/account owner
- Description: customer evidence for product-scope-discipline
- Source URI: `TODO://authority/product-scope-discipline/customer`
- Snapshot output: `artifacts/external-evidence-sources/product-scope-discipline/customer.json`
- Intake output: `artifacts/external-evidence-intakes/product-scope-discipline/customer.json`
- Suggested evidence sources: customer acceptance artifact; contract/payment/procurement evidence; deployment or signoff record

### runtime-policy-and-attestation:ci-run

- Title: Runtime attestation, policy engine receipts, and proof decay
- Authority kind: `ci-run`
- Owner hint: release engineering
- Description: ci-run evidence for runtime-policy-and-attestation
- Source URI: `TODO://authority/runtime-policy-and-attestation/ci-run`
- Snapshot output: `artifacts/external-evidence-sources/runtime-policy-and-attestation/ci-run.json`
- Intake output: `artifacts/external-evidence-intakes/runtime-policy-and-attestation/ci-run.json`
- Suggested evidence sources: completed CI workflow export; release run URL or provider-native run record; artifact/check provenance

### runtime-policy-and-attestation:kms-hsm

- Title: Runtime attestation, policy engine receipts, and proof decay
- Authority kind: `kms-hsm`
- Owner hint: security/platform KMS owner
- Description: kms-hsm evidence for runtime-policy-and-attestation
- Source URI: `TODO://authority/runtime-policy-and-attestation/kms-hsm`
- Snapshot output: `artifacts/external-evidence-sources/runtime-policy-and-attestation/kms-hsm.json`
- Intake output: `artifacts/external-evidence-intakes/runtime-policy-and-attestation/kms-hsm.json`
- Suggested evidence sources: KMS/HSM key policy export; signing operation receipt; custody or audit-log root

### runtime-policy-and-attestation:provider-api

- Title: Runtime attestation, policy engine receipts, and proof decay
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for runtime-policy-and-attestation
- Source URI: `TODO://authority/runtime-policy-and-attestation/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/runtime-policy-and-attestation/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/runtime-policy-and-attestation/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### runtime-policy-and-attestation:hosted-service

- Title: Runtime attestation, policy engine receipts, and proof decay
- Authority kind: `hosted-service`
- Owner hint: service owner
- Description: hosted-service evidence for runtime-policy-and-attestation
- Source URI: `TODO://authority/runtime-policy-and-attestation/hosted-service`
- Snapshot output: `artifacts/external-evidence-sources/runtime-policy-and-attestation/hosted-service.json`
- Intake output: `artifacts/external-evidence-intakes/runtime-policy-and-attestation/hosted-service.json`
- Suggested evidence sources: hosted service health or deployment export; service audit root; operational SLO/status evidence

### runtime-policy-and-attestation:identity-provider

- Title: Runtime attestation, policy engine receipts, and proof decay
- Authority kind: `identity-provider`
- Owner hint: IAM/identity owner
- Description: identity-provider evidence for runtime-policy-and-attestation
- Source URI: `TODO://authority/runtime-policy-and-attestation/identity-provider`
- Snapshot output: `artifacts/external-evidence-sources/runtime-policy-and-attestation/identity-provider.json`
- Intake output: `artifacts/external-evidence-intakes/runtime-policy-and-attestation/identity-provider.json`
- Suggested evidence sources: identity-provider event export; OIDC/session/lifecycle evidence; RBAC or account-state report

### agent-inventory-and-identity:provider-api

- Title: Agent registry, inventory, identity provider attestations, and lifecycle receipts
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for agent-inventory-and-identity
- Source URI: `TODO://authority/agent-inventory-and-identity/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/agent-inventory-and-identity/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/agent-inventory-and-identity/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### agent-inventory-and-identity:identity-provider

- Title: Agent registry, inventory, identity provider attestations, and lifecycle receipts
- Authority kind: `identity-provider`
- Owner hint: IAM/identity owner
- Description: identity-provider evidence for agent-inventory-and-identity
- Source URI: `TODO://authority/agent-inventory-and-identity/identity-provider`
- Snapshot output: `artifacts/external-evidence-sources/agent-inventory-and-identity/identity-provider.json`
- Intake output: `artifacts/external-evidence-intakes/agent-inventory-and-identity/identity-provider.json`
- Suggested evidence sources: identity-provider event export; OIDC/session/lifecycle evidence; RBAC or account-state report

### standards-track-and-auditor-ecosystem:kms-hsm

- Title: Standards-track package and auditor certification ecosystem
- Authority kind: `kms-hsm`
- Owner hint: security/platform KMS owner
- Description: kms-hsm evidence for standards-track-and-auditor-ecosystem
- Source URI: `TODO://authority/standards-track-and-auditor-ecosystem/kms-hsm`
- Snapshot output: `artifacts/external-evidence-sources/standards-track-and-auditor-ecosystem/kms-hsm.json`
- Intake output: `artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/kms-hsm.json`
- Suggested evidence sources: KMS/HSM key policy export; signing operation receipt; custody or audit-log root

### standards-track-and-auditor-ecosystem:standards-body

- Title: Standards-track package and auditor certification ecosystem
- Authority kind: `standards-body`
- Owner hint: standards/governance owner
- Description: standards-body evidence for standards-track-and-auditor-ecosystem
- Source URI: `TODO://authority/standards-track-and-auditor-ecosystem/standards-body`
- Snapshot output: `artifacts/external-evidence-sources/standards-track-and-auditor-ecosystem/standards-body.json`
- Intake output: `artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json`
- Suggested evidence sources: standards-body submission receipt; working-group status record; ballot or docket export

### trust-network-procurement-and-marketplace:provider-api

- Title: Trust network, procurement clauses, and marketplace distribution
- Authority kind: `provider-api`
- Owner hint: integration/platform owner
- Description: provider-api evidence for trust-network-procurement-and-marketplace
- Source URI: `TODO://authority/trust-network-procurement-and-marketplace/provider-api`
- Snapshot output: `artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/provider-api.json`
- Intake output: `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/provider-api.json`
- Suggested evidence sources: provider API response export; request/response transcript; provider-owned audit event

### trust-network-procurement-and-marketplace:hosted-service

- Title: Trust network, procurement clauses, and marketplace distribution
- Authority kind: `hosted-service`
- Owner hint: service owner
- Description: hosted-service evidence for trust-network-procurement-and-marketplace
- Source URI: `TODO://authority/trust-network-procurement-and-marketplace/hosted-service`
- Snapshot output: `artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/hosted-service.json`
- Intake output: `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/hosted-service.json`
- Suggested evidence sources: hosted service health or deployment export; service audit root; operational SLO/status evidence

### trust-network-procurement-and-marketplace:identity-provider

- Title: Trust network, procurement clauses, and marketplace distribution
- Authority kind: `identity-provider`
- Owner hint: IAM/identity owner
- Description: identity-provider evidence for trust-network-procurement-and-marketplace
- Source URI: `TODO://authority/trust-network-procurement-and-marketplace/identity-provider`
- Snapshot output: `artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/identity-provider.json`
- Intake output: `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/identity-provider.json`
- Suggested evidence sources: identity-provider event export; OIDC/session/lifecycle evidence; RBAC or account-state report

### trust-network-procurement-and-marketplace:customer

- Title: Trust network, procurement clauses, and marketplace distribution
- Authority kind: `customer`
- Owner hint: customer success/account owner
- Description: customer evidence for trust-network-procurement-and-marketplace
- Source URI: `TODO://authority/trust-network-procurement-and-marketplace/customer`
- Snapshot output: `artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/customer.json`
- Intake output: `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/customer.json`
- Suggested evidence sources: customer acceptance artifact; contract/payment/procurement evidence; deployment or signoff record

## Limitations

- This gap report verifies the retained manifest, remaining collection plan, and source-map worklist; it does not satisfy missing external authority evidence.
- A gap is closed only by collecting a matching authority artifact, verifying its source snapshot and intake receipt, then rebuilding the external evidence manifest.
- Live authority access, issuer quality, and production status remain outside this report unless supplied as external evidence artifacts.
