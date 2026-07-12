# Control Plane v0.1

The local control plane is a SQLite-backed reference for the roadmap's
Postgres-backed control plane. It indexes evidence-chain and proof-pack state
into queryable registry tables while keeping the chain as the source of truth.

## Tables

- `contracts`: registered Verification Contracts and agent version binding.
- `agents`: discovered agent inventory records.
- `chain_entries`: indexed evidence entries with type, timestamp, payload hash,
  and contract hash where present.
- `proof_packs`: issued proof packs and gate outcomes.
- `promotion_statuses`: CI/CD provider promotion-status receipts bound to proof packs.
- `runtime_attestations`: high-risk runtime action checks against contract blast-radius limits.
- `policy_decisions`: local runtime policy/proof-decay decisions.
- `policy_engine_receipts`: OPA/Cedar/local policy engine receipt metadata.
- `incidents`: post-promotion incident evidence for drift and runtime failures.
- `anchors`: published chain-root anchors.

## CLI

```powershell
python -m trustai control-index --state .trustai/demo/evidence-chain.json --tenant aitrade-local --pack artifacts/aitrade-proof-pack.json --db .trustai/control-plane.sqlite
python -m trustai control-summary --db .trustai/control-plane.sqlite --agents --proof-packs --promotion-statuses --runtime-evidence
```

## API

`trustai serve` exposes:

- `POST /v0/control/index`;
- `GET /v0/control/summary`;
- `GET /v0/agents`;
- `GET /v0/proof-packs`;
- `GET /v0/promotion-statuses`;
- `GET /v0/runtime-evidence`.

The implementation falls back to SQLite `nolock=1` mode when running on local
filesystems that do not support normal SQLite locking, such as some UNC-backed
development workspaces. Production deployments should use Postgres.
