# Re-execution Runner Production Authority Dossier v0.1

## Purpose

The re-execution runner production authority dossier binds signed runner service and worker evidence to the external production evidence required before TrustAI can claim live runner isolation. It is the production-claim guardrail for the roadmap item covering shadow replay, temporal holdout, soak reports, and distributional re-execution.

The dossier is intentionally stricter than local isolation attestations. Local runner evidence can prove that a plan, policy, service attestation, and worker receipt were constructed correctly. Production authority additionally requires fresh provider-owned evidence for the continuously operated runner fleet, scheduler, queue, leases, checkpoints, container runtime, kernel isolation, immutable audit logs, custody, KMS, and observability.

## Schema

`trustai.reexecution-runner-production-authority-dossier/0.1`

A dossier contains:

- `dossier_id`: canonical hash of the dossier body.
- `mode`: one of `local-dossier`, `runner-service-dossier`, or `production-dossier`.
- `environment`: deployment environment covered by the authority claim.
- `dossier_ref`, `authority_ref`, `producer_ref`: stable references for the dossier, authority system, and producer identity.
- `source_binding`: hashes and selected fields from the signed runner service attestation and runner worker receipts.
- `required_production_authority`: fixed v0.1 production authority checklist.
- `authority_evidence`: external evidence references, hashes, issuer/subject metadata, and freshness windows.
- `summary`: covered and missing production authority categories.
- `controls`: deterministic control outcomes derived from the body.
- `signatures`: detached signatures over `{dossier_id, reexecution_runner_authority}`.

## Source Binding

`source_binding` records the runner service attestation hash, service ref, runner image digest, binary hash, replica/AZ floor, scheduler/queue/DLQ/lease/checkpoint refs, source isolation id, runner evidence id, policy/report hashes, source network/read-only-rootfs controls, isolation/admission/tenant/network/egress controls, artifact/result stores, secret store, KMS key, audit root, retention, and worker receipt hashes.

Verifiers should replay the supplied source artifacts and require an exact binding match. If source artifacts are omitted, verification may warn, but it must still reject incomplete source bindings with missing service identifiers, scheduler references, source artifact hashes, isolation/custody/audit refs, worker operation hashes, or worker result hashes. Production workflows should always replay source artifacts.

## Required Production Authority Categories

1. `production-runner-fleet`
2. `scheduler-queue-lease-checkpoint`
3. `container-orchestrator-admission`
4. `kernel-container-isolation-enforcement`
5. `immutable-runtime-audit-logs`
6. `artifact-result-custody`
7. `deterministic-execution-controls`
8. `tenant-network-egress-controls`
9. `credential-custody-and-kms`
10. `observability-and-alerting`

Each evidence item must reference one accepted authority kind for its category and include a hash of the external record. Freshness windows use RFC 3339 `issued_at` and `expires_at`.

## Verification Rules

A verifier MUST reject a dossier when:

- `dossier_id` does not match the canonical body hash.
- No signature verifies.
- `source_binding` is missing required service, scheduler, source artifact, isolation, custody, audit, worker operation, or worker result fields.
- `source_binding` does not match supplied runner service and worker source artifacts.
- `required_production_authority` differs from the v0.1 checklist.
- `summary` or `controls` do not match the dossier body.
- An authority evidence item has an unknown requirement, invalid authority kind, invalid hash/ref, bad freshness window, or mismatched `evidence_id`.
- `production-dossier` mode is used without complete and fresh evidence for every required authority category.
- `production-dossier` mode is used without at least one verified runner worker receipt.
- Raw secret-like values appear instead of redacted references, hashes, ids, or roots.

`runner-service-dossier` and `local-dossier` modes may verify with warnings. They do not claim live production runner isolation.

## CLI

```powershell
python -m trustai reexecution-runner-authority artifacts/reexecution-runner-service-attestation.json --worker-receipt artifacts/reexecution-runner-worker.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --environment aitrade-prod --dossier-ref dossier:reexecution-runner-authority/aitrade-prod --authority-ref authority:reexecution-runner/prod --producer-ref oidc:trustai.example/reexecution-runner-authority-worker --authority-evidence "production-runner-fleet,hosted-service,runner-fleet:trustai/reexecution-prod,sha256:reexecution-runner-prod-fleet,Hosted re-execution runner fleet export for production replay jobs;issuer=TrustAI Hosted Ops;subject=aitrade-prod re-execution runner fleet;source_uri=https://runner.example/audit/fleet/aitrade-prod;issued_at=2026-07-04T04:09:00Z;expires_at=2026-07-11T04:09:00Z" --generated-at 2026-07-04T04:10:00Z --out artifacts/reexecution-runner-authority.json
python -m trustai reexecution-runner-authority-verify artifacts/reexecution-runner-authority.json artifacts/reexecution-runner-service-attestation.json --worker-receipt artifacts/reexecution-runner-worker.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json
python -m trustai reexecution-runner-authority-append artifacts/reexecution-runner-authority.json artifacts/reexecution-runner-service-attestation.json --worker-receipt artifacts/reexecution-runner-worker.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --state .trustai/reexecution-runner-authority-demo/evidence-chain.json --tenant reexecution-runner-authority-local --out artifacts/reexecution-runner-authority-entry.json
```

## Production Claim Limit

A signed dossier is not itself proof that TrustAI operates a live production runner fleet. It is proof that the source runner artifacts and external authority records are hash-bound, freshness-checked, and verifiable offline. A live production claim requires `production-dossier` mode plus fresh external records for every checklist category.
