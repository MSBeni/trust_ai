# External Evidence Owner Packets

- Owner packet bundle ID: `a9c8171f271da0438a00bdd57fa17434ec3869425a77e5e25efc697aa42b10e4`
- Generated at: `2026-07-12T00:01:00Z`
- Source work package ID: `5bb50cac07b336c80cff845561badad6eae585fb3365174492576bc35f1f538a`
- Source work package hash: `097f77a484a3411518d22df3b516af46a0fd02a183ebe34feb3c2a0d871ac5a7`
- Packets: 9
- Tasks: 27
- Missing tasks: 27
- Placeholder source URIs: 27

## Packets

### IAM/identity owner

- Packet ref: `owner-packet:owner_hint:IAM-identity-owner`
- Packet ID: `e55fc2f56440e6c4905b575522d26dcb8f246132a61b353a232899b630c311cc`
- Package ref: `owner_hint:IAM-identity-owner`
- Tasks: 2
- Missing tasks: 2
- Authority kinds: `identity-provider`
- Requirements: `insurer-api-and-actuarial-products`, `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

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

- Packet ref: `owner-packet:owner_hint:customer-success-account-owner`
- Packet ID: `6b4bf83f36c3cd91d030801e75a094ec8149c42370feba8c461a01f327b7d6f0`
- Package ref: `owner_hint:customer-success-account-owner`
- Tasks: 7
- Missing tasks: 7
- Authority kinds: `customer`
- Requirements: `insurer-api-and-actuarial-products`, `product-scope-discipline`, `roadmap-phase-scoreboard`, `state-of-agent-reliability-report`, `trust-network-procurement-and-marketplace`, `trustai-own-compliance`, `vertical-packs`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `product-scope-discipline:customer` | P0-P4 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/product-scope-discipline/customer.json` |
| `roadmap-phase-scoreboard:customer` | P1-P4 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/customer.json` |
| `trustai-own-compliance:customer` | P2 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/trustai-own-compliance/customer.json` |
| `insurer-api-and-actuarial-products:customer` | P2-P4 | P0 | `customer` | placeholder | `artifacts/external-evidence-intakes/insurer-api-and-actuarial-products/customer.json` |
| `state-of-agent-reliability-report:customer` | P2-P4 | P1 | `customer` | placeholder | `artifacts/external-evidence-intakes/state-of-agent-reliability-report/customer.json` |
| `vertical-packs:customer` | P3 | P1 | `customer` | placeholder | `artifacts/external-evidence-intakes/vertical-packs/customer.json` |
| `trust-network-procurement-and-marketplace:customer` | P4 | P1 | `customer` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/customer.json` |

#### Task Commands

- `product-scope-discipline:customer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/product-scope-discipline/customer --root . --task product-scope-discipline:customer --description 'customer evidence for product-scope-discipline' --snapshot-out artifacts/external-evidence-sources/product-scope-discipline/customer.json --intake-out artifacts/external-evidence-intakes/product-scope-discipline/customer.json`
- `product-scope-discipline:customer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/product-scope-discipline/customer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
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

- Packet ref: `owner-packet:owner_hint:integration-platform-owner`
- Packet ID: `67ef146647256379520b2b8e5bf228f70b30a9ef1ea512e0055a2385bcbed9e3`
- Package ref: `owner_hint:integration-platform-owner`
- Tasks: 2
- Missing tasks: 2
- Authority kinds: `provider-api`
- Requirements: `insurer-api-and-actuarial-products`, `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

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

- Packet ref: `owner-packet:owner_hint:legal-compliance-owner`
- Packet ID: `8f1652ae3ca84ee785a75cab454bb5e4f91e31a0b107717b83dcbe5c2ed605e9`
- Package ref: `owner_hint:legal-compliance-owner`
- Tasks: 2
- Missing tasks: 2
- Authority kinds: `regulator`
- Requirements: `roadmap-phase-scoreboard`, `vertical-packs`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `roadmap-phase-scoreboard:regulator` | P1-P4 | P0 | `regulator` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json` |
| `vertical-packs:regulator` | P3 | P1 | `regulator` | placeholder | `artifacts/external-evidence-intakes/vertical-packs/regulator.json` |

#### Task Commands

- `roadmap-phase-scoreboard:regulator` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/regulator --root . --task roadmap-phase-scoreboard:regulator --description 'regulator evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/regulator.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json`
- `roadmap-phase-scoreboard:regulator` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `vertical-packs:regulator` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/vertical-packs/regulator --root . --task vertical-packs:regulator --description 'regulator evidence for vertical-packs' --snapshot-out artifacts/external-evidence-sources/vertical-packs/regulator.json --intake-out artifacts/external-evidence-intakes/vertical-packs/regulator.json`
- `vertical-packs:regulator` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/vertical-packs/regulator.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### release engineering

- Packet ref: `owner-packet:owner_hint:release-engineering`
- Packet ID: `550ebd49510b9cd7c91bdd975d5cac50408aa5d9c18acc0c77ef0210ec1b898b`
- Package ref: `owner_hint:release-engineering`
- Tasks: 4
- Missing tasks: 4
- Authority kinds: `ci-run`
- Requirements: `insurer-api-and-actuarial-products`, `product-scope-discipline`, `roadmap-phase-scoreboard`, `runtime-policy-and-attestation`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

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

- Packet ref: `owner-packet:owner_hint:risk-insurance-owner`
- Packet ID: `694680aa2bbf1b45c8bef8f737fced0b3f9a67164d45795e9998eb5e4823e6fa`
- Package ref: `owner_hint:risk-insurance-owner`
- Tasks: 3
- Missing tasks: 3
- Authority kinds: `insurer`
- Requirements: `insurer-api-and-actuarial-products`, `roadmap-phase-scoreboard`, `vertical-packs`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

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

- Packet ref: `owner-packet:owner_hint:security-platform-KMS-owner`
- Packet ID: `06e78b0ed0578bee00b1903d8cc2c624fbf2980be434184e94190ac4f6b2f9a0`
- Package ref: `owner_hint:security-platform-KMS-owner`
- Tasks: 2
- Missing tasks: 2
- Authority kinds: `kms-hsm`
- Requirements: `insurer-api-and-actuarial-products`, `standards-track-and-auditor-ecosystem`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

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

- Packet ref: `owner-packet:owner_hint:service-owner`
- Packet ID: `6b9bf39cc7fc0daf80fae3de35ece909cc1511d0155261ca7606c7f1828612a0`
- Package ref: `owner_hint:service-owner`
- Tasks: 2
- Missing tasks: 2
- Authority kinds: `hosted-service`
- Requirements: `insurer-api-and-actuarial-products`, `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

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

- Packet ref: `owner-packet:owner_hint:standards-governance-owner`
- Packet ID: `838d085ee812c50bf0c19a889eaafb6f36ada00802725f343aa3f5e00020337d`
- Package ref: `owner_hint:standards-governance-owner`
- Tasks: 3
- Missing tasks: 3
- Authority kinds: `standards-body`
- Requirements: `roadmap-phase-scoreboard`, `standards-track-and-auditor-ecosystem`, `trustai-own-compliance`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `roadmap-phase-scoreboard:standards-body` | P1-P4 | P0 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json` |
| `trustai-own-compliance:standards-body` | P2 | P0 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/trustai-own-compliance/standards-body.json` |
| `standards-track-and-auditor-ecosystem:standards-body` | P3 | P1 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json` |

#### Task Commands

- `roadmap-phase-scoreboard:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/standards-body --root . --task roadmap-phase-scoreboard:standards-body --description 'standards-body evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/standards-body.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json`
- `roadmap-phase-scoreboard:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `trustai-own-compliance:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trustai-own-compliance/standards-body --root . --task trustai-own-compliance:standards-body --description 'standards-body evidence for trustai-own-compliance' --snapshot-out artifacts/external-evidence-sources/trustai-own-compliance/standards-body.json --intake-out artifacts/external-evidence-intakes/trustai-own-compliance/standards-body.json`
- `trustai-own-compliance:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trustai-own-compliance/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `standards-track-and-auditor-ecosystem:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/standards-track-and-auditor-ecosystem/standards-body --root . --task standards-track-and-auditor-ecosystem:standards-body --description 'standards-body evidence for standards-track-and-auditor-ecosystem' --snapshot-out artifacts/external-evidence-sources/standards-track-and-auditor-ecosystem/standards-body.json --intake-out artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json`
- `standards-track-and-auditor-ecosystem:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`


## Limitations

- Owner packets assign collection work; they do not satisfy missing external authority evidence by themselves.
- Source URIs marked TODO or placeholder must be replaced with authority-owned source exports before collection.
- Packet completion is proven only by verified source snapshots, intake receipts, rebuilt manifests, and readiness reports.
