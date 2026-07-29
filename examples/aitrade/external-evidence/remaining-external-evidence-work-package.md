# External Evidence Work Packages

- Work package ID: `022227e85b1363a802eb738b95dafa23450d9f00c49c8a4e39c0024f6935f3d0`
- Generated at: `2026-07-12T00:01:00Z`
- Grouped by: `owner_hint`
- Packages: 9
- Tasks: 15
- Missing tasks: 15
- Placeholder source URIs: 15
- Live source URIs: 0

## Tasks By Owner

- IAM/identity owner: 1
- customer success/account owner: 4
- integration/platform owner: 1
- legal/compliance owner: 1
- release engineering: 3
- risk/insurance owner: 1
- security/platform KMS owner: 1
- service owner: 1
- standards/governance owner: 2

## Packages

### IAM/identity owner

- Package ref: `owner_hint:IAM-identity-owner`
- Package ID: `8fabcbf6254507a22ae760759837b8fd30cf21ac1918dd9f6e003bb91e0118e0`
- Owner Hint: `IAM/identity owner`
- Tasks: 1
- Authority kinds: `identity-provider`
- Requirements: `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `trust-network-procurement-and-marketplace:identity-provider` | P4 | P1 | `identity-provider` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/identity-provider.json` |

#### Task Commands

- `trust-network-procurement-and-marketplace:identity-provider` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trust-network-procurement-and-marketplace/identity-provider --root . --task trust-network-procurement-and-marketplace:identity-provider --description 'identity-provider evidence for trust-network-procurement-and-marketplace' --snapshot-out artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/identity-provider.json --intake-out artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/identity-provider.json`
- `trust-network-procurement-and-marketplace:identity-provider` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/identity-provider.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### customer success/account owner

- Package ref: `owner_hint:customer-success-account-owner`
- Package ID: `d9a57efc2974ed03ef865246162574898db5fc3742dbe8f749a555bf0eeadc88`
- Owner Hint: `customer success/account owner`
- Tasks: 4
- Authority kinds: `customer`
- Requirements: `product-scope-discipline`, `roadmap-phase-scoreboard`, `state-of-agent-reliability-report`, `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `product-scope-discipline:customer` | P0-P4 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/product-scope-discipline/customer.json` |
| `roadmap-phase-scoreboard:customer` | P1-P4 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/customer.json` |
| `state-of-agent-reliability-report:customer` | P2-P4 | P1 | `customer` | placeholder | `artifacts/external-evidence-intakes/state-of-agent-reliability-report/customer.json` |
| `trust-network-procurement-and-marketplace:customer` | P4 | P1 | `customer` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/customer.json` |

#### Task Commands

- `product-scope-discipline:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/product-scope-discipline/customer --root . --task product-scope-discipline:customer --description 'customer evidence for product-scope-discipline' --snapshot-out artifacts/external-evidence-sources/product-scope-discipline/customer.json --intake-out artifacts/external-evidence-intakes/product-scope-discipline/customer.json`
- `product-scope-discipline:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/product-scope-discipline/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `roadmap-phase-scoreboard:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/customer --root . --task roadmap-phase-scoreboard:customer --description 'customer evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/customer.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/customer.json`
- `roadmap-phase-scoreboard:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `state-of-agent-reliability-report:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/state-of-agent-reliability-report/customer --root . --task state-of-agent-reliability-report:customer --description 'customer evidence for state-of-agent-reliability-report' --snapshot-out artifacts/external-evidence-sources/state-of-agent-reliability-report/customer.json --intake-out artifacts/external-evidence-intakes/state-of-agent-reliability-report/customer.json`
- `state-of-agent-reliability-report:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/state-of-agent-reliability-report/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `trust-network-procurement-and-marketplace:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trust-network-procurement-and-marketplace/customer --root . --task trust-network-procurement-and-marketplace:customer --description 'customer evidence for trust-network-procurement-and-marketplace' --snapshot-out artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/customer.json --intake-out artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/customer.json`
- `trust-network-procurement-and-marketplace:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### integration/platform owner

- Package ref: `owner_hint:integration-platform-owner`
- Package ID: `9125b6a40780f8dffc53478632387c7369daa470a2553c299be80bfde9947563`
- Owner Hint: `integration/platform owner`
- Tasks: 1
- Authority kinds: `provider-api`
- Requirements: `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `trust-network-procurement-and-marketplace:provider-api` | P4 | P1 | `provider-api` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/provider-api.json` |

#### Task Commands

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
- Package ID: `ebcb91eb3848bf19444bde463ada5610d0aa5ec36d6b2429386d2441c19c4d61`
- Owner Hint: `release engineering`
- Tasks: 3
- Authority kinds: `ci-run`
- Requirements: `product-scope-discipline`, `roadmap-phase-scoreboard`, `runtime-policy-and-attestation`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `product-scope-discipline:ci-run` | P0-P4 | P0 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/product-scope-discipline/ci-run.json` |
| `roadmap-phase-scoreboard:ci-run` | P1-P4 | P0 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/ci-run.json` |
| `runtime-policy-and-attestation:ci-run` | P2 | P1 | `ci-run` | placeholder | `artifacts/external-evidence-intakes/runtime-policy-and-attestation/ci-run.json` |

#### Task Commands

- `product-scope-discipline:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/product-scope-discipline/ci-run --root . --task product-scope-discipline:ci-run --description 'ci-run evidence for product-scope-discipline' --snapshot-out artifacts/external-evidence-sources/product-scope-discipline/ci-run.json --intake-out artifacts/external-evidence-intakes/product-scope-discipline/ci-run.json`
- `product-scope-discipline:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/product-scope-discipline/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `roadmap-phase-scoreboard:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/ci-run --root . --task roadmap-phase-scoreboard:ci-run --description 'ci-run evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/ci-run.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/ci-run.json`
- `roadmap-phase-scoreboard:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `runtime-policy-and-attestation:ci-run` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/runtime-policy-and-attestation/ci-run --root . --task runtime-policy-and-attestation:ci-run --description 'ci-run evidence for runtime-policy-and-attestation' --snapshot-out artifacts/external-evidence-sources/runtime-policy-and-attestation/ci-run.json --intake-out artifacts/external-evidence-intakes/runtime-policy-and-attestation/ci-run.json`
- `runtime-policy-and-attestation:ci-run` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/runtime-policy-and-attestation/ci-run.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### risk/insurance owner

- Package ref: `owner_hint:risk-insurance-owner`
- Package ID: `2f119cde6795e109896f7f51e1d62adee9bf282ee357e1546f0974349a114aaa`
- Owner Hint: `risk/insurance owner`
- Tasks: 1
- Authority kinds: `insurer`
- Requirements: `roadmap-phase-scoreboard`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `roadmap-phase-scoreboard:insurer` | P1-P4 | P0 | `insurer` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json` |

#### Task Commands

- `roadmap-phase-scoreboard:insurer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/insurer --root . --task roadmap-phase-scoreboard:insurer --description 'insurer evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/insurer.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json`
- `roadmap-phase-scoreboard:insurer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### security/platform KMS owner

- Package ref: `owner_hint:security-platform-KMS-owner`
- Package ID: `6394fa8dafdcbcde6250ea663ed133092525ed1a5a0c86c29fa4e84d485cc1c0`
- Owner Hint: `security/platform KMS owner`
- Tasks: 1
- Authority kinds: `kms-hsm`
- Requirements: `standards-track-and-auditor-ecosystem`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `standards-track-and-auditor-ecosystem:kms-hsm` | P3 | P1 | `kms-hsm` | placeholder | `artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/kms-hsm.json` |

#### Task Commands

- `standards-track-and-auditor-ecosystem:kms-hsm` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/standards-track-and-auditor-ecosystem/kms-hsm --root . --task standards-track-and-auditor-ecosystem:kms-hsm --description 'kms-hsm evidence for standards-track-and-auditor-ecosystem' --snapshot-out artifacts/external-evidence-sources/standards-track-and-auditor-ecosystem/kms-hsm.json --intake-out artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/kms-hsm.json`
- `standards-track-and-auditor-ecosystem:kms-hsm` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/kms-hsm.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### service owner

- Package ref: `owner_hint:service-owner`
- Package ID: `a7d9acefa42eda43e0df423aa92aee67ea03c2ae33852bd8f6de6ea106cf66a8`
- Owner Hint: `service owner`
- Tasks: 1
- Authority kinds: `hosted-service`
- Requirements: `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `trust-network-procurement-and-marketplace:hosted-service` | P4 | P1 | `hosted-service` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/hosted-service.json` |

#### Task Commands

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
