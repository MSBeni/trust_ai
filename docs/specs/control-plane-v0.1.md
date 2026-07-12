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
- `anchors`: published chain-root anchors.

## CLI

```powershell
python -m trustai control-index --state .trustai/demo/evidence-chain.json --tenant aitrade-local --pack artifacts/aitrade-proof-pack.json --db .trustai/control-plane.sqlite
python -m trustai control-summary --db .trustai/control-plane.sqlite --contracts --agents --eval-runs --gate-decisions --proof-packs --ingest-events --promotion-statuses --runtime-evidence --contract-id aitrade-btcusdt-canary --agent-name aitrade-risk-agent
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
- `GET /v0/runtime-evidence`.

The contract evidence endpoint returns one contract-scoped review surface with
counts and recent rows for chain entries, eval runs, gate decisions, proof packs,
OTel ingest events, promotion statuses, runtime attestations, policy evidence,
and incidents. The agent evidence endpoint provides the same kind of review
surface from the Agent/Version Registry side: inventory records, associated
contracts, direct agent evidence, and contract-hash-linked runtime/policy rows.
These are the local analogues of model-risk or auditor review pages for a single
pre-registered contract or governed agent version.

The implementation falls back to SQLite `nolock=1` mode when running on local
filesystems that do not support normal SQLite locking, such as some UNC-backed
development workspaces. Production deployments should use Postgres.
