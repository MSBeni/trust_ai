# Control Plane v0.1

The local control plane is a SQLite-backed reference for the roadmap's
Postgres-backed control plane. It indexes evidence-chain and proof-pack state
into queryable registry tables while keeping the chain as the source of truth.

## Tables

- `contracts`: registered Verification Contracts and agent version binding.
- `agents`: discovered agent inventory records.
- `chain_entries`: indexed evidence entries with type, timestamp, payload hash,
  and contract hash where present.
- `eval_runs`: eval result evidence bound to contract and agent versions.
- `gate_decisions`: promotion gate decisions with check, holdout, and approval outcomes.
- `proof_packs`: issued proof packs and gate outcomes.
- `ingest_events`: OTel GenAI event evidence indexed by trace, span, agent, risk class, and contract hash.
- `promotion_statuses`: CI/CD provider promotion-status receipts bound to proof packs.
- `runtime_attestations`: high-risk runtime action checks against contract blast-radius limits.
- `policy_decisions`: local runtime policy/proof-decay decisions.
- `policy_engine_receipts`: OPA/Cedar/local policy engine receipt metadata.
- `incidents`: post-promotion incident evidence for drift and runtime failures.
- `roadmap_audits`: roadmap completion audits with local/reference/missing evidence counts.
- `external_evidence_collection_runs`: retained live-authority collection-run provenance, source-map hashes, strict flags, and collected intake IDs.
- `external_evidence_manifests`: roadmap external-authority coverage and missing-evidence counts.
- `authority_dossiers`: production authority dossiers with mode, freshness windows, coverage, and missing requirement counts.
- `anchors`: published chain-root anchors.

## CLI

```powershell
python -m trustai control-index --state .trustai/demo/evidence-chain.json --tenant aitrade-local --pack artifacts/aitrade-proof-pack.json --db .trustai/control-plane.sqlite
python -m trustai control-summary --db .trustai/control-plane.sqlite --contracts --agents --eval-runs --gate-decisions --proof-packs --ingest-events --promotion-statuses --runtime-evidence --roadmap-evidence --readiness --external-evidence --authority-dossiers --contract-id aitrade-btcusdt-canary --agent-name aitrade-risk-agent
```

## API

`trustai serve` exposes:

- `POST /v0/control/index`;
- `GET /v0/control/summary`;
- `GET /v0/control/contract-evidence?contract_id=...` or `?contract_hash=...`;
- `GET /v0/control/agent-evidence?agent_name=...` with optional `agent_version=...`;
- `GET /v0/contracts`;
- `GET /v0/agents`;
- `GET /v0/eval-runs`;
- `GET /v0/gate-decisions`;
- `GET /v0/proof-packs`;
- `GET /v0/ingest-events`;
- `GET /v0/promotion-statuses`;
- `GET /v0/runtime-evidence`;
- `GET /v0/roadmap-evidence`;
- `GET /v0/readiness` or `GET /v0/control/readiness`;
- `GET /v0/external-evidence`;
- `GET /v0/authority-dossiers`.

The contract evidence endpoint returns one contract-scoped review surface with
counts and recent rows for chain entries, eval runs, gate decisions, proof packs,
OTel ingest events, promotion statuses, runtime attestations, policy evidence,
and incidents. The agent evidence endpoint provides the same kind of review
surface from the Agent/Version Registry side: inventory records, associated
contracts, direct agent evidence, and contract-hash-linked runtime/policy rows.
These are the local analogues of model-risk or auditor review pages for a single
pre-registered contract or governed agent version. The roadmap-evidence list
binds roadmap audit entries, retained collection-run provenance, and external
evidence manifests into one progress view. The readiness view aggregates those
surfaces with promotion-gate, proof-pack, runtime-policy, and authority-dossier
evidence into a conservative `ready` / `not_ready` status plus concrete blockers.
The external-evidence list exposes roadmap authority coverage and missing
live-evidence counts, while the authority-dossier list exposes production
authority dossier modes, coverage, freshness windows, and missing requirement
IDs so production readiness gaps stay visible in the same control-plane surface.

The implementation falls back to SQLite `nolock=1` mode when running on local
filesystems that do not support normal SQLite locking, such as some UNC-backed
development workspaces. Production deployments should use Postgres.
