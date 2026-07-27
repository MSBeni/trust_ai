# External Evidence Work Packages

- Work package ID: `f84c30b2ca9105d37fc6afac5b580a3b6b934a25decd925462e91c3d0e6f92b2`
- Generated at: `2026-07-12T00:01:00Z`
- Grouped by: `owner_hint`
- Packages: 9
- Tasks: 23
- Missing tasks: 23
- Placeholder source URIs: 23
- Live source URIs: 0

## Tasks By Owner

- IAM/identity owner: 2
- customer success/account owner: 6
- integration/platform owner: 2
- legal/compliance owner: 1
- release engineering: 4
- risk/insurance owner: 2
- security/platform KMS owner: 2
- service owner: 2
- standards/governance owner: 2

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
- Package ID: `63dc4cc2a4e8f1ef42a0f12b8555d093d62c7469e409bc75506b65a6c929dce2`
- Owner Hint: `customer success/account owner`
- Tasks: 6
- Authority kinds: `customer`
- Requirements: `insurer-api-and-actuarial-products`, `product-scope-discipline`, `roadmap-phase-scoreboard`, `state-of-agent-reliability-report`, `trust-network-procurement-and-marketplace`, `vertical-packs`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `product-scope-discipline:customer` | P0-P4 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/product-scope-discipline/customer.json` |
| `roadmap-phase-scoreboard:customer` | P1-P4 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/customer.json` |
| `insurer-api-and-actuarial-products:customer` | P2-P4 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/customer.json` |
| `state-of-agent-reliability-report:customer` | P2-P4 | P1 | `customer` | placeholder | `artifacts/external-evidence-intakes/state-of-agent-reliability-report/customer.json` |
| `vertical-packs:customer` | P3 | P1 | `customer` | placeholder | `artifacts/external-evidence-intakes/vertical-packs/customer.json` |
| `trust-network-procurement-and-marketplace:customer` | P4 | P1 | `customer` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/customer.json` |

#### Task Commands

- `product-scope-discipline:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/product-scope-discipline/customer --root . --task product-scope-discipline:customer --description 'customer evidence for product-scope-discipline' --snapshot-out artifacts/external-evidence-sources/product-scope-discipline/customer.json --intake-out artifacts/external-evidence-intakes/product-scope-discipline/customer.json`
- `product-scope-discipline:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/product-scope-discipline/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `roadmap-phase-scoreboard:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/customer --root . --task roadmap-phase-scoreboard:customer --description 'customer evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/customer.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/customer.json`
- `roadmap-phase-scoreboard:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
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
- Package ID: `f18fc99fa79341522684ce6a225c084780252ffd83b940e745fe502f9e1a7e36`
- Owner Hint: `integration/platform owner`
- Tasks: 2
- Authority kinds: `provider-api`
- Requirements: `insurer-api-and-actuarial-products`, `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `insurer-api-and-actuarial-products:provider-api` | P2-P4 | P0 | `provider-api` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/provider-api.json` |
| `trust-network-procurement-and-marketplace:provider-api` | P4 | P1 | `provider-api` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/provider-api.json` |

#### Task Commands

- `insurer-api-and-actuarial-products:provider-api` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/insurer-api-and-actuarial-products/provider-api --root . --task insurer-api-and-actuarial-products:provider-api --description 'provider-api evidence for insurer-api-and-actuarial-products' --snapshot-out artifacts/external-evidence-sources/insurer-api-and-actuarial-products/provider-api.json --intake-out artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/provider-api.json`
- `insurer-api-and-actuarial-products:provider-api` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/provider-api.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `trust-network-procurement-and-marketplace:provider-api` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trust-network-procurement-and-marketplace/provider-api --root . --task trust-network-procurement-and-marketplace:provider-api --description 'provider-api evidence for trust-network-procurement-and-marketplace' --snapshot-out artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/provider-api.json --intake-out artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/provider-api.json`
- `trust-network-procurement-and-marketplace:provider-api` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/provider-api.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### legal/compliance owner

- Package ref: `owner_hint:legal-compliance-owner`
- Package ID: `2c71272911d5f7cbca255f7a27a0dbf0c70d4378e80ebea18013226d9e7520c8`
- Owner Hint: `legal/compliance owner`
- Tasks: 1
- Authority kinds: `regulator`
- Requirements: `roadmap-phase-scoreboard`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `roadmap-phase-scoreboard:regulator` | P1-P4 | P0 | `regulator` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json` |

#### Task Commands

- `roadmap-phase-scoreboard:regulator` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/regulator --root . --task roadmap-phase-scoreboard:regulator --description 'regulator evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/regulator.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json`
- `roadmap-phase-scoreboard:regulator` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### release engineering

- Package ref: `owner_hint:release-engineering`
- Package ID: `25f5c035e7f769203df0832bec73992c58b1920c712a6b8570107d32faba4096`
- Owner Hint: `release engineering`
- Tasks: 4
- Authority kinds: `ci-run`
- Requirements: `insurer-api-and-actuarial-products`, `product-scope-discipline`, `roadmap-phase-scoreboard`, `runtime-policy-and-attestation`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `product-scope-discipline:ci-run` | P0-P4 | P0 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/product-scope-discipline/ci-run.json` |
| `roadmap-phase-scoreboard:ci-run` | P1-P4 | P0 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/ci-run.json` |
| `runtime-policy-and-attestation:ci-run` | P2 | P1 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/runtime-policy-and-attestation/ci-run.json` |
| `insurer-api-and-actuarial-products:ci-run` | P2-P4 | P0 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/ci-run.json` |

#### Task Commands

- `product-scope-discipline:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/product-scope-discipline/ci-run --root . --task product-scope-discipline:ci-run --description 'ci-run evidence for product-scope-discipline' --snapshot-out artifacts/external-evidence-sources/product-scope-discipline/ci-run.json --intake-out artifacts/external-evidence-intakes/product-scope-discipline/ci-run.json`
- `product-scope-discipline:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/product-scope-discipline/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `roadmap-phase-scoreboard:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/ci-run --root . --task roadmap-phase-scoreboard:ci-run --description 'ci-run evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/ci-run.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/ci-run.json`
- `roadmap-phase-scoreboard:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `runtime-policy-and-attestation:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/runtime-policy-and-attestation/ci-run --root . --task runtime-policy-and-attestation:ci-run --description 'ci-run evidence for runtime-policy-and-attestation' --snapshot-out artifacts/external-evidence-sources/runtime-policy-and-attestation/ci-run.json --intake-out artifacts/external-evidence-intakes/runtime-policy-and-attestation/ci-run.json`
- `runtime-policy-and-attestation:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/runtime-policy-and-attestation/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `insurer-api-and-actuarial-products:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/insurer-api-and-actuarial-products/ci-run --root . --task insurer-api-and-actuarial-products:ci-run --description 'ci-run evidence for insurer-api-and-actuarial-products' --snapshot-out artifacts/external-evidence-sources/insurer-api-and-actuarial-products/ci-run.json --intake-out artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/ci-run.json`
- `insurer-api-and-actuarial-products:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### risk/insurance owner

- Package ref: `owner_hint:risk-insurance-owner`
- Package ID: `8817058d3c7ee61e246e8f1859af539435aabdb452c13ee1ab1d46dbb6d8649b`
- Owner Hint: `risk/insurance owner`
- Tasks: 2
- Authority kinds: `insurer`
- Requirements: `insurer-api-and-actuarial-products`, `roadmap-phase-scoreboard`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `roadmap-phase-scoreboard:insurer` | P1-P4 | P0 | `insurer` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json` |
| `insurer-api-and-actuarial-products:insurer` | P2-P4 | P0 | `insurer` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/insurer.json` |

#### Task Commands

- `roadmap-phase-scoreboard:insurer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/insurer --root . --task roadmap-phase-scoreboard:insurer --description 'insurer evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/insurer.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json`
- `roadmap-phase-scoreboard:insurer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `insurer-api-and-actuarial-products:insurer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/insurer-api-and-actuarial-products/insurer --root . --task insurer-api-and-actuarial-products:insurer --description 'insurer evidence for insurer-api-and-actuarial-products' --snapshot-out artifacts/external-evidence-sources/insurer-api-and-actuarial-products/insurer.json --intake-out artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/insurer.json`
- `insurer-api-and-actuarial-products:insurer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/insurer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

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
- Package ID: `16a9c153460006b972fad1bb4d357a6ba384857774ebc60806d530a07aff01b2`
- Owner Hint: `standards/governance owner`
- Tasks: 2
- Authority kinds: `standards-body`
- Requirements: `roadmap-phase-scoreboard`, `standards-track-and-auditor-ecosystem`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `roadmap-phase-scoreboard:standards-body` | P1-P4 | P0 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json` |
| `standards-track-and-auditor-ecosystem:standards-body` | P3 | P1 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json` |

#### Task Commands

- `roadmap-phase-scoreboard:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/standards-body --root . --task roadmap-phase-scoreboard:standards-body --description 'standards-body evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/standards-body.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json`
- `roadmap-phase-scoreboard:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `standards-track-and-auditor-ecosystem:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/standards-track-and-auditor-ecosystem/standards-body --root . --task standards-track-and-auditor-ecosystem:standards-body --description 'standards-body evidence for standards-track-and-auditor-ecosystem' --snapshot-out artifacts/external-evidence-sources/standards-track-and-auditor-ecosystem/standards-body.json --intake-out artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json`
- `standards-track-and-auditor-ecosystem:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
