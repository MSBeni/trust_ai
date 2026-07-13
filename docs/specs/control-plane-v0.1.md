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
- `mcp_tool_calls`: MCP transcript tool-call receipts with request/response hashes, transcript sequence, and transcript root.
- `mcp_proxy_captures`: MCP proxy capture receipts with proxy/upstream refs, event-chain roots, transcript roots, and artifact hashes.
- `human_approvals`: human approval entries bound to contract, agent, role, approver, source, and external reference metadata.
- `promotion_demotions`: promotion gate demotion decisions with source/target environment, trigger, reason, and contract/agent binding.
- `promotion_rollbacks`: rollback decisions with target agent version, reason, triggering evidence, and contract/agent binding.
- `soak_demotion_receipts`: signed failed-soak demotion receipts linking soak reports, demotion entries, controls, source replay, and violations.
- `promotion_statuses`: CI/CD provider promotion-status receipts bound to proof packs.
- `runtime_attestations`: high-risk runtime action checks against contract blast-radius limits.
- `policy_decisions`: local runtime policy/proof-decay decisions.
- `policy_engine_receipts`: OPA/Cedar/local policy engine receipt metadata.
- `incidents`: post-promotion incident evidence for drift and runtime failures.
- `roadmap_audits`: roadmap completion audits with local/reference/missing evidence counts.
- `external_evidence_collection_runs`: retained live-authority collection-run provenance, source-map hashes, strict flags, and collected intake IDs.
- `external_evidence_manifests`: roadmap external-authority coverage and missing-evidence counts.
- `authority_dossiers`: production authority dossiers with mode, freshness windows, coverage, and missing requirement counts.
- `phase_scoreboards`: roadmap phase scoreboard dossiers with P1-P4 milestone and control counts.
- `design_partner_dossiers`: Phase 1 design-partner pilot dossiers with partner, signed-value, scrutiny, and control summaries.
- `own_compliance_dossiers`: TrustAI SOC 2 Type II / ISO 42001 own-compliance dossiers with certification evidence and control summaries.
- `product_scope_decisions`: product-scope discipline decisions with proof-impact, anti-focus, and failed-control summaries.
- `vertical_packs`: vertical pack receipts with vertical, risk-class, framework, source-artifact, external-requirement, and control summaries.
- `reliability_reports`: State of Agent Reliability reports with reporting-period, cohort, source-product, incident-rate, gate-pass-rate, and control summaries.
- `temporal_holdout_manifests`: signed post-freeze/post-holdout replay manifests with record roots and violation counts.
- `shadow_replays`: candidate shadow replay outcomes, metric checks, holdout status, and linked temporal holdout manifests.
- `soak_reports`: post-promotion soak windows, incidents, drift alarms, metric checks, and outcomes.
- `traffic_holdout_exports`: signed production traffic holdout export receipts with source refs, windows, record roots, and privacy-safe counts.
- `traffic_completeness_receipts`: provider/collector completeness receipts binding traffic exports to stream, cursor, audit, and provider exchange evidence.
- `anchors`: published chain-root anchors.

## CLI

```powershell
python -m trustai control-index --state .trustai/demo/evidence-chain.json --tenant aitrade-local --pack artifacts/aitrade-proof-pack.json --db .trustai/control-plane.sqlite
python -m trustai control-summary --db .trustai/control-plane.sqlite --contracts --agents --eval-runs --gate-decisions --proof-packs --ingest-events --promotion-statuses --runtime-evidence --holdout-evidence --mcp-evidence --promotion-lifecycle-evidence --framework-adapter-evidence --roadmap-evidence --phase-scoreboards --design-partner-dossiers --own-compliance-dossiers --product-scope-decisions --vertical-packs --reliability-reports --readiness --external-evidence --external-authority-gaps --authority-kind provider-api --gap-limit 10 --authority-dossiers --contract-id aitrade-btcusdt-canary --agent-name aitrade-risk-agent
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
- `GET /v0/holdout-evidence` or `GET /v0/control/holdout-evidence`;
- `GET /v0/mcp-evidence` or `GET /v0/control/mcp-evidence`;
- `GET /v0/promotion-lifecycle-evidence` or `GET /v0/control/promotion-lifecycle-evidence`;
- `GET /v0/framework-adapter-evidence` or `GET /v0/control/framework-adapter-evidence`;
- `GET /v0/roadmap-evidence`;
- `GET /v0/phase-scoreboards` or `GET /v0/control/phase-scoreboards`;
- `GET /v0/design-partner-dossiers` or `GET /v0/control/design-partner-dossiers`;
- `GET /v0/own-compliance-dossiers` or `GET /v0/control/own-compliance-dossiers`;
- `GET /v0/product-scope-decisions` or `GET /v0/control/product-scope-decisions`;
- `GET /v0/vertical-packs` or `GET /v0/control/vertical-packs`;
- `GET /v0/reliability-reports` or `GET /v0/control/reliability-reports`;
- `GET /v0/readiness` or `GET /v0/control/readiness`;
- `GET /v0/external-evidence`;
- `GET /v0/external-authority-gaps` or `GET /v0/control/external-authority-gaps`, with optional `authority_kind=...`, `requirement_id=...`, and `limit=...` filters;
- `GET /v0/authority-dossiers`.

The contract evidence endpoint returns one contract-scoped review surface with
counts and recent rows for chain entries, eval runs, gate decisions, proof packs,
OTel ingest events, human approvals, promotion demotions, rollbacks,
soak-demotion receipts, promotion statuses, runtime attestations, policy evidence,
and incidents. The agent evidence endpoint provides the same kind of review
surface from the Agent/Version Registry side: inventory records, associated
contracts, direct agent evidence, and contract-hash-linked runtime/policy rows.
These are the local analogues of model-risk or auditor review pages for a single
pre-registered contract or governed agent version. The holdout-evidence list
binds temporal holdout manifests, shadow replays, soak reports, traffic holdout
exports, and traffic completeness receipts into one Phase 1 promotion-readiness
surface. The MCP evidence list binds tool-call transcript hashes and proxy-capture
event roots into one gateway review surface without exposing raw tool payloads.
The promotion-lifecycle evidence list binds human approvals, demotions,
rollbacks, and failed-soak demotion receipts into one CI/CD promotion review
surface. The framework-adapter evidence list binds adapter matrices, native hook
releases, hook operation receipts, and framework adapter production-authority
dossiers into one Phase 1 adapter coverage surface.
The roadmap-evidence list binds roadmap audit entries, retained
collection-run provenance, external
evidence manifests, phase scoreboard entries, design-partner pilot dossiers,
own-compliance dossiers, product-scope decisions, vertical packs, and State of
Agent Reliability reports into one progress view. The phase-scoreboard list
exposes P1-P4 milestone counters, phase counts, and control summaries without
treating unverified business milestones as local proof. The design-partner and
own-compliance lists expose P1 pilot and SOC 2 / ISO 42001 evidence readiness
without claiming external customer or certification proof before those artifacts
exist. The product-scope, vertical-pack, and reliability-report lists expose
scope discipline, vertical acceptance, and public reliability publication gaps
without treating local receipts as external market proof. The readiness view
aggregates those surfaces with promotion-gate, proof-pack, runtime-policy,
authority-dossier, phase-scoreboard, design-partner, own-compliance,
product-scope, vertical-pack, and reliability-report evidence into a conservative `ready` /
`not_ready` status plus concrete blockers.
The external-evidence list exposes roadmap authority coverage, missing
requirement IDs, missing requirement-to-authority-kind maps, deterministic
missing authority unit/task IDs, and live-evidence counts. The external-authority
gap worklist returns the latest deterministic missing-unit tasks with exact
authority-kind, requirement-ID, and limit filters so collection owners can pull
their remaining live-evidence queue without parsing the full manifest. The
authority-dossier list exposes production authority dossier modes, coverage,
freshness windows, and missing requirement IDs so production readiness gaps stay
visible in the same control-plane surface.

The implementation falls back to SQLite `nolock=1` mode when running on local
filesystems that do not support normal SQLite locking, such as some UNC-backed
development workspaces. Production deployments should use Postgres.
