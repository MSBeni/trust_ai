# External Evidence Work Packages

- Work package ID: `9ddb5e03257e1d2f236796ab8604db7e07ceea44ee0af8162c6ff59b2082b940`
- Generated at: `2026-07-12T00:01:00Z`
- Grouped by: `owner_hint`
- Packages: 9
- Tasks: 33
- Missing tasks: 33
- Placeholder source URIs: 33
- Live source URIs: 0

## Tasks By Owner

- IAM/identity owner: 2
- customer success/account owner: 8
- integration/platform owner: 3
- legal/compliance owner: 3
- release engineering: 5
- risk/insurance owner: 3
- security/platform KMS owner: 2
- service owner: 2
- standards/governance owner: 5

## Packages

### IAM/identity owner

- Package ref: `owner_hint:IAM-identity-owner`
- Package ID: `2d1cb6e52a1ec656c4a2de161dbbe8b1758554616a7f23ec5ee6ecb3c0df57fe`
- Owner Hint: `IAM/identity owner`
- Tasks: 2
- Authority kinds: `identity-provider`
- Requirements: `insurer-api-and-actuarial-products`, `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `insurer-api-and-actuarial-products:identity-provider` | P2-P4 | P0 | `identity-provider` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/identity-provider.json` |
| `trust-network-procurement-and-marketplace:identity-provider` | P4 | P1 | `identity-provider` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/identity-provider.json` |

#### Task Commands

- `insurer-api-and-actuarial-products:identity-provider` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/insurer-api-and-actuarial-products/identity-provider --root . --task insurer-api-and-actuarial-products:identity-provider --description 'identity-provider evidence for insurer-api-and-actuarial-products' --snapshot-out artifacts/external-evidence-sources/insurer-api-and-actuarial-products/identity-provider.json --intake-out artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/identity-provider.json`
- `insurer-api-and-actuarial-products:identity-provider` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/identity-provider.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `trust-network-procurement-and-marketplace:identity-provider` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trust-network-procurement-and-marketplace/identity-provider --root . --task trust-network-procurement-and-marketplace:identity-provider --description 'identity-provider evidence for trust-network-procurement-and-marketplace' --snapshot-out artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/identity-provider.json --intake-out artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/identity-provider.json`
- `trust-network-procurement-and-marketplace:identity-provider` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/identity-provider.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### customer success/account owner

- Package ref: `owner_hint:customer-success-account-owner`
- Package ID: `985e925d5c4aecaa5b7c422b7ed885a21345ff389af65549004cacbfcc1ad0ee`
- Owner Hint: `customer success/account owner`
- Tasks: 8
- Authority kinds: `customer`
- Requirements: `byoc-self-hosted`, `insurer-api-and-actuarial-products`, `product-scope-discipline`, `roadmap-phase-scoreboard`, `state-of-agent-reliability-report`, `trust-network-procurement-and-marketplace`, `trustai-own-compliance`, `vertical-packs`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `product-scope-discipline:customer` | P0-P4 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/product-scope-discipline/customer.json` |
| `byoc-self-hosted:customer` | P1-P2 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/byoc-self-hosted/customer.json` |
| `roadmap-phase-scoreboard:customer` | P1-P4 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/customer.json` |
| `trustai-own-compliance:customer` | P2 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/trustai-own-compliance/customer.json` |
| `insurer-api-and-actuarial-products:customer` | P2-P4 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/customer.json` |
| `state-of-agent-reliability-report:customer` | P2-P4 | P1 | `customer` | placeholder | `artifacts/external-evidence-intakes/state-of-agent-reliability-report/customer.json` |
| `vertical-packs:customer` | P3 | P1 | `customer` | placeholder | `artifacts/external-evidence-intakes/vertical-packs/customer.json` |
| `trust-network-procurement-and-marketplace:customer` | P4 | P1 | `customer` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/customer.json` |

#### Task Commands

- `product-scope-discipline:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/product-scope-discipline/customer --root . --task product-scope-discipline:customer --description 'customer evidence for product-scope-discipline' --snapshot-out artifacts/external-evidence-sources/product-scope-discipline/customer.json --intake-out artifacts/external-evidence-intakes/product-scope-discipline/customer.json`
- `product-scope-discipline:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/product-scope-discipline/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `byoc-self-hosted:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/byoc-self-hosted/customer --root . --task byoc-self-hosted:customer --description 'customer evidence for byoc-self-hosted' --snapshot-out artifacts/external-evidence-sources/byoc-self-hosted/customer.json --intake-out artifacts/external-evidence-intakes/byoc-self-hosted/customer.json`
- `byoc-self-hosted:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/byoc-self-hosted/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `roadmap-phase-scoreboard:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/customer --root . --task roadmap-phase-scoreboard:customer --description 'customer evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/customer.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/customer.json`
- `roadmap-phase-scoreboard:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `trustai-own-compliance:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trustai-own-compliance/customer --root . --task trustai-own-compliance:customer --description 'customer evidence for trustai-own-compliance' --snapshot-out artifacts/external-evidence-sources/trustai-own-compliance/customer.json --intake-out artifacts/external-evidence-intakes/trustai-own-compliance/customer.json`
- `trustai-own-compliance:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trustai-own-compliance/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `insurer-api-and-actuarial-products:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/insurer-api-and-actuarial-products/customer --root . --task insurer-api-and-actuarial-products:customer --description 'customer evidence for insurer-api-and-actuarial-products' --snapshot-out artifacts/external-evidence-sources/insurer-api-and-actuarial-products/customer.json --intake-out artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/customer.json`
- `insurer-api-and-actuarial-products:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `state-of-agent-reliability-report:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/state-of-agent-reliability-report/customer --root . --task state-of-agent-reliability-report:customer --description 'customer evidence for state-of-agent-reliability-report' --snapshot-out artifacts/external-evidence-sources/state-of-agent-reliability-report/customer.json --intake-out artifacts/external-evidence-intakes/state-of-agent-reliability-report/customer.json`
- `state-of-agent-reliability-report:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/state-of-agent-reliability-report/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `vertical-packs:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/vertical-packs/customer --root . --task vertical-packs:customer --description 'customer evidence for vertical-packs' --snapshot-out artifacts/external-evidence-sources/vertical-packs/customer.json --intake-out artifacts/external-evidence-intakes/vertical-packs/customer.json`
- `vertical-packs:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/vertical-packs/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `trust-network-procurement-and-marketplace:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trust-network-procurement-and-marketplace/customer --root . --task trust-network-procurement-and-marketplace:customer --description 'customer evidence for trust-network-procurement-and-marketplace' --snapshot-out artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/customer.json --intake-out artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/customer.json`
- `trust-network-procurement-and-marketplace:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### integration/platform owner

- Package ref: `owner_hint:integration-platform-owner`
- Package ID: `6549a48689eaaac88345796b04709176da85bb977fb948961eac7a405aaf97cd`
- Owner Hint: `integration/platform owner`
- Tasks: 3
- Authority kinds: `provider-api`
- Requirements: `compliance-mapper-and-eu-ai-act`, `insurer-api-and-actuarial-products`, `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `compliance-mapper-and-eu-ai-act:provider-api` | P2-P3 | P0 | `provider-api` | placeholder | `artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/provider-api.json` |
| `insurer-api-and-actuarial-products:provider-api` | P2-P4 | P0 | `provider-api` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/provider-api.json` |
| `trust-network-procurement-and-marketplace:provider-api` | P4 | P1 | `provider-api` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/provider-api.json` |

#### Task Commands

- `compliance-mapper-and-eu-ai-act:provider-api` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/compliance-mapper-and-eu-ai-act/provider-api --root . --task compliance-mapper-and-eu-ai-act:provider-api --description 'provider-api evidence for compliance-mapper-and-eu-ai-act' --snapshot-out artifacts/external-evidence-sources/compliance-mapper-and-eu-ai-act/provider-api.json --intake-out artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/provider-api.json`
- `compliance-mapper-and-eu-ai-act:provider-api` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/provider-api.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `insurer-api-and-actuarial-products:provider-api` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/insurer-api-and-actuarial-products/provider-api --root . --task insurer-api-and-actuarial-products:provider-api --description 'provider-api evidence for insurer-api-and-actuarial-products' --snapshot-out artifacts/external-evidence-sources/insurer-api-and-actuarial-products/provider-api.json --intake-out artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/provider-api.json`
- `insurer-api-and-actuarial-products:provider-api` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/provider-api.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `trust-network-procurement-and-marketplace:provider-api` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trust-network-procurement-and-marketplace/provider-api --root . --task trust-network-procurement-and-marketplace:provider-api --description 'provider-api evidence for trust-network-procurement-and-marketplace' --snapshot-out artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/provider-api.json --intake-out artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/provider-api.json`
- `trust-network-procurement-and-marketplace:provider-api` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/provider-api.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### legal/compliance owner

- Package ref: `owner_hint:legal-compliance-owner`
- Package ID: `5e6da67d5dd555392f6178a7bbe1d56dfd810c33ba443f74384b50a00829da15`
- Owner Hint: `legal/compliance owner`
- Tasks: 3
- Authority kinds: `regulator`
- Requirements: `compliance-mapper-and-eu-ai-act`, `roadmap-phase-scoreboard`, `vertical-packs`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `roadmap-phase-scoreboard:regulator` | P1-P4 | P0 | `regulator` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json` |
| `compliance-mapper-and-eu-ai-act:regulator` | P2-P3 | P0 | `regulator` | placeholder | `artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/regulator.json` |
| `vertical-packs:regulator` | P3 | P1 | `regulator` | placeholder | `artifacts/external-evidence-intakes/vertical-packs/regulator.json` |

#### Task Commands

- `roadmap-phase-scoreboard:regulator` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/regulator --root . --task roadmap-phase-scoreboard:regulator --description 'regulator evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/regulator.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json`
- `roadmap-phase-scoreboard:regulator` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `compliance-mapper-and-eu-ai-act:regulator` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/compliance-mapper-and-eu-ai-act/regulator --root . --task compliance-mapper-and-eu-ai-act:regulator --description 'regulator evidence for compliance-mapper-and-eu-ai-act' --snapshot-out artifacts/external-evidence-sources/compliance-mapper-and-eu-ai-act/regulator.json --intake-out artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/regulator.json`
- `compliance-mapper-and-eu-ai-act:regulator` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/regulator.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `vertical-packs:regulator` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/vertical-packs/regulator --root . --task vertical-packs:regulator --description 'regulator evidence for vertical-packs' --snapshot-out artifacts/external-evidence-sources/vertical-packs/regulator.json --intake-out artifacts/external-evidence-intakes/vertical-packs/regulator.json`
- `vertical-packs:regulator` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/vertical-packs/regulator.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### release engineering

- Package ref: `owner_hint:release-engineering`
- Package ID: `2d66b908b1c514e9de2383639c4fd297c727de50301ed9975373e37019da76a1`
- Owner Hint: `release engineering`
- Tasks: 5
- Authority kinds: `ci-run`
- Requirements: `byoc-self-hosted`, `insurer-api-and-actuarial-products`, `product-scope-discipline`, `roadmap-phase-scoreboard`, `runtime-policy-and-attestation`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `product-scope-discipline:ci-run` | P0-P4 | P0 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/product-scope-discipline/ci-run.json` |
| `byoc-self-hosted:ci-run` | P1-P2 | P0 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/byoc-self-hosted/ci-run.json` |
| `roadmap-phase-scoreboard:ci-run` | P1-P4 | P0 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/ci-run.json` |
| `runtime-policy-and-attestation:ci-run` | P2 | P1 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/runtime-policy-and-attestation/ci-run.json` |
| `insurer-api-and-actuarial-products:ci-run` | P2-P4 | P0 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/ci-run.json` |

#### Task Commands

- `product-scope-discipline:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/product-scope-discipline/ci-run --root . --task product-scope-discipline:ci-run --description 'ci-run evidence for product-scope-discipline' --snapshot-out artifacts/external-evidence-sources/product-scope-discipline/ci-run.json --intake-out artifacts/external-evidence-intakes/product-scope-discipline/ci-run.json`
- `product-scope-discipline:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/product-scope-discipline/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `byoc-self-hosted:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/byoc-self-hosted/ci-run --root . --task byoc-self-hosted:ci-run --description 'ci-run evidence for byoc-self-hosted' --snapshot-out artifacts/external-evidence-sources/byoc-self-hosted/ci-run.json --intake-out artifacts/external-evidence-intakes/byoc-self-hosted/ci-run.json`
- `byoc-self-hosted:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/byoc-self-hosted/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `roadmap-phase-scoreboard:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/ci-run --root . --task roadmap-phase-scoreboard:ci-run --description 'ci-run evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/ci-run.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/ci-run.json`
- `roadmap-phase-scoreboard:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `runtime-policy-and-attestation:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/runtime-policy-and-attestation/ci-run --root . --task runtime-policy-and-attestation:ci-run --description 'ci-run evidence for runtime-policy-and-attestation' --snapshot-out artifacts/external-evidence-sources/runtime-policy-and-attestation/ci-run.json --intake-out artifacts/external-evidence-intakes/runtime-policy-and-attestation/ci-run.json`
- `runtime-policy-and-attestation:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/runtime-policy-and-attestation/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `insurer-api-and-actuarial-products:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/insurer-api-and-actuarial-products/ci-run --root . --task insurer-api-and-actuarial-products:ci-run --description 'ci-run evidence for insurer-api-and-actuarial-products' --snapshot-out artifacts/external-evidence-sources/insurer-api-and-actuarial-products/ci-run.json --intake-out artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/ci-run.json`
- `insurer-api-and-actuarial-products:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### risk/insurance owner

- Package ref: `owner_hint:risk-insurance-owner`
- Package ID: `e3cfe80dd86841fba5e8da22ab8afdd1a30befa5474e40b2fb087b69418df27c`
- Owner Hint: `risk/insurance owner`
- Tasks: 3
- Authority kinds: `insurer`
- Requirements: `insurer-api-and-actuarial-products`, `roadmap-phase-scoreboard`, `vertical-packs`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `roadmap-phase-scoreboard:insurer` | P1-P4 | P0 | `insurer` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json` |
| `insurer-api-and-actuarial-products:insurer` | P2-P4 | P0 | `insurer` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/insurer.json` |
| `vertical-packs:insurer` | P3 | P1 | `insurer` | placeholder | `artifacts/external-evidence-intakes/vertical-packs/insurer.json` |

#### Task Commands

- `roadmap-phase-scoreboard:insurer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/insurer --root . --task roadmap-phase-scoreboard:insurer --description 'insurer evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/insurer.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json`
- `roadmap-phase-scoreboard:insurer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `insurer-api-and-actuarial-products:insurer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/insurer-api-and-actuarial-products/insurer --root . --task insurer-api-and-actuarial-products:insurer --description 'insurer evidence for insurer-api-and-actuarial-products' --snapshot-out artifacts/external-evidence-sources/insurer-api-and-actuarial-products/insurer.json --intake-out artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/insurer.json`
- `insurer-api-and-actuarial-products:insurer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/insurer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `vertical-packs:insurer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/vertical-packs/insurer --root . --task vertical-packs:insurer --description 'insurer evidence for vertical-packs' --snapshot-out artifacts/external-evidence-sources/vertical-packs/insurer.json --intake-out artifacts/external-evidence-intakes/vertical-packs/insurer.json`
- `vertical-packs:insurer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/vertical-packs/insurer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### security/platform KMS owner

- Package ref: `owner_hint:security-platform-KMS-owner`
- Package ID: `88a8b81dae5232660ca7f181c889975e7cfa3bedea3b87712dea11b7ecb8d732`
- Owner Hint: `security/platform KMS owner`
- Tasks: 2
- Authority kinds: `kms-hsm`
- Requirements: `insurer-api-and-actuarial-products`, `standards-track-and-auditor-ecosystem`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `insurer-api-and-actuarial-products:kms-hsm` | P2-P4 | P0 | `kms-hsm` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/kms-hsm.json` |
| `standards-track-and-auditor-ecosystem:kms-hsm` | P3 | P1 | `kms-hsm` | placeholder | `artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/kms-hsm.json` |

#### Task Commands

- `insurer-api-and-actuarial-products:kms-hsm` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/insurer-api-and-actuarial-products/kms-hsm --root . --task insurer-api-and-actuarial-products:kms-hsm --description 'kms-hsm evidence for insurer-api-and-actuarial-products' --snapshot-out artifacts/external-evidence-sources/insurer-api-and-actuarial-products/kms-hsm.json --intake-out artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/kms-hsm.json`
- `insurer-api-and-actuarial-products:kms-hsm` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/kms-hsm.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `standards-track-and-auditor-ecosystem:kms-hsm` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/standards-track-and-auditor-ecosystem/kms-hsm --root . --task standards-track-and-auditor-ecosystem:kms-hsm --description 'kms-hsm evidence for standards-track-and-auditor-ecosystem' --snapshot-out artifacts/external-evidence-sources/standards-track-and-auditor-ecosystem/kms-hsm.json --intake-out artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/kms-hsm.json`
- `standards-track-and-auditor-ecosystem:kms-hsm` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/kms-hsm.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### service owner

- Package ref: `owner_hint:service-owner`
- Package ID: `45400e51f2d0df4e403178f1d6affb71b03f1c90378c4715c7367a53c5172a2d`
- Owner Hint: `service owner`
- Tasks: 2
- Authority kinds: `hosted-service`
- Requirements: `insurer-api-and-actuarial-products`, `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `insurer-api-and-actuarial-products:hosted-service` | P2-P4 | P0 | `hosted-service` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/hosted-service.json` |
| `trust-network-procurement-and-marketplace:hosted-service` | P4 | P1 | `hosted-service` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/hosted-service.json` |

#### Task Commands

- `insurer-api-and-actuarial-products:hosted-service` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/insurer-api-and-actuarial-products/hosted-service --root . --task insurer-api-and-actuarial-products:hosted-service --description 'hosted-service evidence for insurer-api-and-actuarial-products' --snapshot-out artifacts/external-evidence-sources/insurer-api-and-actuarial-products/hosted-service.json --intake-out artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/hosted-service.json`
- `insurer-api-and-actuarial-products:hosted-service` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/hosted-service.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `trust-network-procurement-and-marketplace:hosted-service` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trust-network-procurement-and-marketplace/hosted-service --root . --task trust-network-procurement-and-marketplace:hosted-service --description 'hosted-service evidence for trust-network-procurement-and-marketplace' --snapshot-out artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/hosted-service.json --intake-out artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/hosted-service.json`
- `trust-network-procurement-and-marketplace:hosted-service` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/hosted-service.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### standards/governance owner

- Package ref: `owner_hint:standards-governance-owner`
- Package ID: `96c90200c8c4b1844ee79604a51e4dce17bf1caf11868b750d0ab837b5b08b2f`
- Owner Hint: `standards/governance owner`
- Tasks: 5
- Authority kinds: `standards-body`
- Requirements: `byoc-self-hosted`, `compliance-mapper-and-eu-ai-act`, `roadmap-phase-scoreboard`, `standards-track-and-auditor-ecosystem`, `trustai-own-compliance`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `byoc-self-hosted:standards-body` | P1-P2 | P0 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/byoc-self-hosted/standards-body.json` |
| `roadmap-phase-scoreboard:standards-body` | P1-P4 | P0 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json` |
| `trustai-own-compliance:standards-body` | P2 | P0 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/trustai-own-compliance/standards-body.json` |
| `compliance-mapper-and-eu-ai-act:standards-body` | P2-P3 | P0 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/standards-body.json` |
| `standards-track-and-auditor-ecosystem:standards-body` | P3 | P1 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json` |

#### Task Commands

- `byoc-self-hosted:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/byoc-self-hosted/standards-body --root . --task byoc-self-hosted:standards-body --description 'standards-body evidence for byoc-self-hosted' --snapshot-out artifacts/external-evidence-sources/byoc-self-hosted/standards-body.json --intake-out artifacts/external-evidence-intakes/byoc-self-hosted/standards-body.json`
- `byoc-self-hosted:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/byoc-self-hosted/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `roadmap-phase-scoreboard:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/standards-body --root . --task roadmap-phase-scoreboard:standards-body --description 'standards-body evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/standards-body.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json`
- `roadmap-phase-scoreboard:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `trustai-own-compliance:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trustai-own-compliance/standards-body --root . --task trustai-own-compliance:standards-body --description 'standards-body evidence for trustai-own-compliance' --snapshot-out artifacts/external-evidence-sources/trustai-own-compliance/standards-body.json --intake-out artifacts/external-evidence-intakes/trustai-own-compliance/standards-body.json`
- `trustai-own-compliance:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trustai-own-compliance/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `compliance-mapper-and-eu-ai-act:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/compliance-mapper-and-eu-ai-act/standards-body --root . --task compliance-mapper-and-eu-ai-act:standards-body --description 'standards-body evidence for compliance-mapper-and-eu-ai-act' --snapshot-out artifacts/external-evidence-sources/compliance-mapper-and-eu-ai-act/standards-body.json --intake-out artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/standards-body.json`
- `compliance-mapper-and-eu-ai-act:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/compliance-mapper-and-eu-ai-act/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `standards-track-and-auditor-ecosystem:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/standards-track-and-auditor-ecosystem/standards-body --root . --task standards-track-and-auditor-ecosystem:standards-body --description 'standards-body evidence for standards-track-and-auditor-ecosystem' --snapshot-out artifacts/external-evidence-sources/standards-track-and-auditor-ecosystem/standards-body.json --intake-out artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json`
- `standards-track-and-auditor-ecosystem:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
