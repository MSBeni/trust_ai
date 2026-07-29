# External Evidence Owner Packets

- Owner packet bundle ID: `9299c2ba203679a8f07af845233f9c083fb62efb047836f53270b20d80fe523c`
- Generated at: `2026-07-12T00:01:00Z`
- Source work package ID: `022227e85b1363a802eb738b95dafa23450d9f00c49c8a4e39c0024f6935f3d0`
- Source work package hash: `46bc1771831e6ac2d5851c1ded6a44720a0e20a1570f0906f37ba75c952fdc4a`
- Packets: 9
- Tasks: 15
- Missing tasks: 15
- Placeholder source URIs: 15

## Packets

### IAM/identity owner

- Packet ref: `owner-packet:owner_hint:IAM-identity-owner`
- Packet ID: `f17a78460bd552757fab26692125f0de50658e4379276fa6014cf73749ca0851`
- Package ref: `owner_hint:IAM-identity-owner`
- Tasks: 1
- Missing tasks: 1
- Authority kinds: `identity-provider`
- Requirements: `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `trust-network-procurement-and-marketplace:identity-provider` | P4 | P1 | `identity-provider` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/identity-provider.json` |

#### Task Commands

- `trust-network-procurement-and-marketplace:identity-provider` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trust-network-procurement-and-marketplace/identity-provider --root . --task trust-network-procurement-and-marketplace:identity-provider --description 'identity-provider evidence for trust-network-procurement-and-marketplace' --snapshot-out artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/identity-provider.json --intake-out artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/identity-provider.json`
- `trust-network-procurement-and-marketplace:identity-provider` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/identity-provider.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### customer success/account owner

- Packet ref: `owner-packet:owner_hint:customer-success-account-owner`
- Packet ID: `955a503f61587a9398da53ffd1ceb4e7d0807d753dcd3c2ea8d230ef749d8702`
- Package ref: `owner_hint:customer-success-account-owner`
- Tasks: 4
- Missing tasks: 4
- Authority kinds: `customer`
- Requirements: `product-scope-discipline`, `roadmap-phase-scoreboard`, `state-of-agent-reliability-report`, `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

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

- Packet ref: `owner-packet:owner_hint:integration-platform-owner`
- Packet ID: `2726dbfa77a03fe869d3914f98eb7eb523c2e622d776d1adf71cbc08ee0c9e94`
- Package ref: `owner_hint:integration-platform-owner`
- Tasks: 1
- Missing tasks: 1
- Authority kinds: `provider-api`
- Requirements: `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `trust-network-procurement-and-marketplace:provider-api` | P4 | P1 | `provider-api` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/provider-api.json` |

#### Task Commands

- `trust-network-procurement-and-marketplace:provider-api` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trust-network-procurement-and-marketplace/provider-api --root . --task trust-network-procurement-and-marketplace:provider-api --description 'provider-api evidence for trust-network-procurement-and-marketplace' --snapshot-out artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/provider-api.json --intake-out artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/provider-api.json`
- `trust-network-procurement-and-marketplace:provider-api` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/provider-api.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### legal/compliance owner

- Packet ref: `owner-packet:owner_hint:legal-compliance-owner`
- Packet ID: `37e1261d09d55a02bda8eb23092922efc512f324e8d6a2a60fb9f1f47ec3c7f1`
- Package ref: `owner_hint:legal-compliance-owner`
- Tasks: 1
- Missing tasks: 1
- Authority kinds: `regulator`
- Requirements: `roadmap-phase-scoreboard`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `roadmap-phase-scoreboard:regulator` | P1-P4 | P0 | `regulator` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json` |

#### Task Commands

- `roadmap-phase-scoreboard:regulator` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/regulator --root . --task roadmap-phase-scoreboard:regulator --description 'regulator evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/regulator.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json`
- `roadmap-phase-scoreboard:regulator` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/regulator.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### release engineering

- Packet ref: `owner-packet:owner_hint:release-engineering`
- Packet ID: `8b0fd05c14e2f3fb13b26441c507ee5ebbd516db0abf4e138b877df03cd006f2`
- Package ref: `owner_hint:release-engineering`
- Tasks: 3
- Missing tasks: 3
- Authority kinds: `ci-run`
- Requirements: `product-scope-discipline`, `roadmap-phase-scoreboard`, `runtime-policy-and-attestation`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

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

- Packet ref: `owner-packet:owner_hint:risk-insurance-owner`
- Packet ID: `644129225c8473486ce2d3911031bfae46027d1c9cd5382ea0eed48eaf3dd463`
- Package ref: `owner_hint:risk-insurance-owner`
- Tasks: 1
- Missing tasks: 1
- Authority kinds: `insurer`
- Requirements: `roadmap-phase-scoreboard`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `roadmap-phase-scoreboard:insurer` | P1-P4 | P0 | `insurer` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json` |

#### Task Commands

- `roadmap-phase-scoreboard:insurer` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/insurer --root . --task roadmap-phase-scoreboard:insurer --description 'insurer evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/insurer.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json`
- `roadmap-phase-scoreboard:insurer` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/insurer.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### security/platform KMS owner

- Packet ref: `owner-packet:owner_hint:security-platform-KMS-owner`
- Packet ID: `087444437d2aeeaec6a4f18babcabf1e4d52b83dd00129f48d512f9dc2a3805f`
- Package ref: `owner_hint:security-platform-KMS-owner`
- Tasks: 1
- Missing tasks: 1
- Authority kinds: `kms-hsm`
- Requirements: `standards-track-and-auditor-ecosystem`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `standards-track-and-auditor-ecosystem:kms-hsm` | P3 | P1 | `kms-hsm` | placeholder | `artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/kms-hsm.json` |

#### Task Commands

- `standards-track-and-auditor-ecosystem:kms-hsm` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/standards-track-and-auditor-ecosystem/kms-hsm --root . --task standards-track-and-auditor-ecosystem:kms-hsm --description 'kms-hsm evidence for standards-track-and-auditor-ecosystem' --snapshot-out artifacts/external-evidence-sources/standards-track-and-auditor-ecosystem/kms-hsm.json --intake-out artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/kms-hsm.json`
- `standards-track-and-auditor-ecosystem:kms-hsm` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/kms-hsm.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### service owner

- Packet ref: `owner-packet:owner_hint:service-owner`
- Packet ID: `ddbad1aa5642285ff9b4131398d20aea75030c38f41cfb2d447055255d38fdd8`
- Package ref: `owner_hint:service-owner`
- Tasks: 1
- Missing tasks: 1
- Authority kinds: `hosted-service`
- Requirements: `trust-network-procurement-and-marketplace`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `trust-network-procurement-and-marketplace:hosted-service` | P4 | P1 | `hosted-service` | placeholder | `artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/hosted-service.json` |

#### Task Commands

- `trust-network-procurement-and-marketplace:hosted-service` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/trust-network-procurement-and-marketplace/hosted-service --root . --task trust-network-procurement-and-marketplace:hosted-service --description 'hosted-service evidence for trust-network-procurement-and-marketplace' --snapshot-out artifacts/external-evidence-sources/trust-network-procurement-and-marketplace/hosted-service.json --intake-out artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/hosted-service.json`
- `trust-network-procurement-and-marketplace:hosted-service` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/trust-network-procurement-and-marketplace/hosted-service.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`

### standards/governance owner

- Packet ref: `owner-packet:owner_hint:standards-governance-owner`
- Packet ID: `3af7d7d535f2b83bc1cbea78c72d5abd450f6ff4dcf91c1d8ec246636e18d308`
- Package ref: `owner_hint:standards-governance-owner`
- Tasks: 2
- Missing tasks: 2
- Authority kinds: `standards-body`
- Requirements: `roadmap-phase-scoreboard`, `standards-track-and-auditor-ecosystem`
- Batch collect command: `python -m trustai external-evidence-collect-batch examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json --root . --out artifacts/external-evidence-collection-run.json`
- Rebuild manifest command: `python -m trustai external-evidence-manifest-from-intakes examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root . --intake-dir artifacts/external-evidence-intakes --out artifacts/external-evidence-manifest-from-intakes.json`
- Completion gate: Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.

| Task | Phase | Priority | Authority | Source URI Status | Intake |
|---|---|---|---|---|---|
| `roadmap-phase-scoreboard:standards-body` | P1-P4 | P0 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json` |
| `standards-track-and-auditor-ecosystem:standards-body` | P3 | P1 | `standards-body` | placeholder | `artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json` |

#### Task Commands

- `roadmap-phase-scoreboard:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/roadmap-phase-scoreboard/standards-body --root . --task roadmap-phase-scoreboard:standards-body --description 'standards-body evidence for roadmap-phase-scoreboard' --snapshot-out artifacts/external-evidence-sources/roadmap-phase-scoreboard/standards-body.json --intake-out artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json`
- `roadmap-phase-scoreboard:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/roadmap-phase-scoreboard/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`
- `standards-track-and-auditor-ecosystem:standards-body` collect: `python -m trustai external-evidence-collect examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json TODO://authority/standards-track-and-auditor-ecosystem/standards-body --root . --task standards-track-and-auditor-ecosystem:standards-body --description 'standards-body evidence for standards-track-and-auditor-ecosystem' --snapshot-out artifacts/external-evidence-sources/standards-track-and-auditor-ecosystem/standards-body.json --intake-out artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json`
- `standards-track-and-auditor-ecosystem:standards-body` verify intake: `python -m trustai external-evidence-intake-verify artifacts/external-evidence-intakes/standards-track-and-auditor-ecosystem/standards-body.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json examples/aitrade/external-evidence/retained-external-evidence-manifest.json examples/aitrade/external-evidence/source-roadmap-audit.json --root .`


## Limitations

- Owner packets assign collection work; they do not satisfy missing external authority evidence by themselves.
- Source URIs marked TODO or placeholder must be replaced with authority-owned source exports before collection.
- Packet completion is proven only by verified source snapshots, intake receipts, rebuilt manifests, and readiness reports.
