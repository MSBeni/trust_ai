# External Evidence Gap Report

- Gap report ID: `c91ac2c0d063aa2945697ed5922d778e5b863e62ba34a37f08ca668333dc187e`
- Generated at: `2026-07-12T00:01:00Z`
- Status: `partial`
- Covered authority kinds: 35/71
- Missing authority kinds: 36
- Remaining collection tasks: 36
- Source-map entries: 36
- Placeholder source URIs: 36
- Live source URIs: 0

## Gaps By Authority Kind

- `ci-run`: 5
- `customer`: 8
- `hosted-service`: 3
- `identity-provider`: 3
- `insurer`: 3
- `kms-hsm`: 2
- `provider-api`: 3
- `regulator`: 4
- `standards-body`: 5

## Gaps By Requirement

- `auditor-and-review-portal`: 3
- `byoc-self-hosted`: 3
- `compliance-mapper-and-eu-ai-act`: 3
- `insurer-api-and-actuarial-products`: 7
- `product-scope-discipline`: 2
- `roadmap-phase-scoreboard`: 5
- `runtime-policy-and-attestation`: 1
- `standards-track-and-auditor-ecosystem`: 2
- `state-of-agent-reliability-report`: 1
- `trust-network-procurement-and-marketplace`: 4
- `trustai-own-compliance`: 2
- `vertical-packs`: 3

## Collection Worklist

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
