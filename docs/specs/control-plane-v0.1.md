# Control Plane v0.1

The local control plane is a SQLite-backed reference for the roadmap's
Postgres-backed control plane. It indexes evidence-chain and proof-pack state
into queryable registry tables while keeping the chain as the source of truth.

## Tables

- `contracts`: registered Verification Contracts and agent version binding.
- `agents`: discovered agent inventory records.
- `agent_delegations`: signed parent/child agent delegation receipts bound to contracts and reasons.
- `agent_delegation_graphs`: signed delegation graph exports with node/edge counts, roots, leaves, cycles, and source-chain bindings.
- `chain_entries`: indexed evidence entries with type, timestamp, payload hash,
  and contract hash where present.
- `eval_runs`: eval result evidence bound to contract and agent versions.
- `gate_decisions`: promotion gate decisions with check, holdout, and approval outcomes.
- `proof_packs`: issued proof packs and gate outcomes.
- `ingest_events`: OTel GenAI event evidence indexed by trace, span, agent, risk class, and contract hash.
- `mcp_tool_calls`: MCP transcript tool-call receipts with request/response hashes, transcript sequence, and transcript root.
- `mcp_proxy_captures`: MCP proxy capture receipts with proxy/upstream refs, event-chain roots, transcript roots, and artifact hashes.
- `mcp_gateway_authority_evidence_bundles`: retained MCP gateway authority evidence bundles with freshness and live source URI counts for offline proxy authority review.
- `supervised_access_receipts`: time-bounded reviewer sessions with audience, reviewer, and disclosed artifact references.
- `regulator_acceptances`: regulator review decisions with authority, examination, scope, and source references.
- `review_portal_service_attestations`: hosted/static portal service identity, frontend integrity, supervised access, and control summaries.
- `review_portal_authority_dossiers`: hosted portal production-authority coverage, freshness, service bindings, and evidence references.
- `review_portal_authority_evidence_bundles`: retained hosted portal authority evidence bundles with freshness and live source URI counts for offline auditor review.
- `trust_network_evidence`: procurement, registry, marketplace, service, worker, bundle, and authority receipts normalized for cross-org trust-network review.
- `provider_delivery_evidence`: provider delivery receipts, delivery-service attestations, worker dispatch receipts, worker bundles, and authority dossiers normalized for provider, target, response, source-artifact, and control review.
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
- `byoc_operator_attestations`: BYOC operator, Object Lock, legal hold, keyring, network, backup, and audit-log attestations.
- `byoc_authority_dossiers`: BYOC production-authority dossiers with deployment, operator, customer account, WORM, KMS, and freshness evidence.
- `vendor_identity_receipts`: vendor identity receipts binding legal identity, identity-provider IDs, proof-pack counts, and trust-network references.
- `identity_provider_attestations`: raw provider identity export attestations for agent identities.
- `identity_provider_sessions`: identity-provider session and token event receipts.
- `identity_provider_lifecycle_operations`: account/app/token lifecycle operation receipts.
- `identity_provider_lifecycle_workers`: lifecycle propagation worker receipts with queue, scheduler, destination, and audit evidence.
- `identity_provider_authority_dossiers`: identity-provider production-authority dossiers with lifecycle worker bindings, coverage, freshness, and controls.
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
- `underwriting_quotes`: signed proof-pack-backed underwriting quotes with risk evidence, discount, consent, term, and freshness fields.
- `insurer_partner_authority_dossiers`: insurer partner production-authority dossiers with service, worker, quote, actuarial, authority-evidence, and control summaries.
- `self_serve_onboarding_receipts`: self-serve SDK/gateway onboarding receipts with tenant, agent, requester, environment, SDK scope, gateway mode, source-artifact counts, quickstart replay counts, and control summaries.
- `anchors`: published chain-root anchors.

## CLI

```powershell
python -m trustai control-index --state .trustai/demo/evidence-chain.json --tenant aitrade-local --pack artifacts/aitrade-proof-pack.json --db .trustai/control-plane.sqlite --rebuild
python -m trustai control-summary --db .trustai/control-plane.sqlite --contracts --agents --eval-runs --gate-decisions --proof-packs --ingest-events --promotion-statuses --runtime-evidence --holdout-evidence --mcp-evidence --onboarding-evidence --promotion-lifecycle-evidence --framework-adapter-evidence --review-portal-evidence --standards-auditor-evidence --trust-network-evidence --provider-delivery-evidence --provider-operations-evidence --compliance-evidence --policy-backend-evidence --insurer-evidence --multi-agent-evidence --byoc-evidence --identity-provider-evidence --roadmap-evidence --phase-scoreboards --design-partner-dossiers --own-compliance-dossiers --product-scope-decisions --vertical-packs --reliability-reports --readiness --external-evidence --external-authority-gaps --authority-kind provider-api --gap-limit 10 --authority-dossiers --contract-id aitrade-btcusdt-canary --agent-name aitrade-risk-agent
```

## API

`trustai serve` exposes:

- `POST /v0/control/index`, with optional `rebuild: true` to clear the read model before indexing;
- `GET /v0/control/summary`;
- `GET /v0/control/contract-evidence?contract_id=...` or `?contract_hash=...`;
- `GET /v0/control/agent-evidence?agent_name=...` with optional `agent_version=...`;
- `GET /v0/contracts` or `GET /v0/control/contracts`;
- `GET /v0/agents` or `GET /v0/control/agents`;
- `GET /v0/eval-runs` or `GET /v0/control/eval-runs`;
- `GET /v0/gate-decisions` or `GET /v0/control/gate-decisions`;
- `GET /v0/proof-packs` or `GET /v0/control/proof-packs`;
- `GET /v0/ingest-events` or `GET /v0/control/ingest-events`;
- `GET /v0/promotion-statuses` or `GET /v0/control/promotion-statuses`;
- `GET /v0/runtime-evidence` or `GET /v0/control/runtime-evidence`;
- `GET /v0/holdout-evidence` or `GET /v0/control/holdout-evidence`;
- `GET /v0/mcp-evidence` or `GET /v0/control/mcp-evidence`;
- `GET /v0/onboarding-evidence` or `GET /v0/control/onboarding-evidence`;
- `GET /v0/promotion-lifecycle-evidence` or `GET /v0/control/promotion-lifecycle-evidence`;
- `GET /v0/framework-adapter-evidence` or `GET /v0/control/framework-adapter-evidence`;
- `GET /v0/review-portal-evidence` or `GET /v0/control/review-portal-evidence`;
- `GET /v0/standards-auditor-evidence` or `GET /v0/control/standards-auditor-evidence`;
- `GET /v0/trust-network-evidence` or `GET /v0/control/trust-network-evidence`;
- `GET /v0/provider-delivery-evidence` or `GET /v0/control/provider-delivery-evidence`;
- `GET /v0/provider-operations-evidence` or `GET /v0/control/provider-operations-evidence`;
- `GET /v0/compliance-evidence` or `GET /v0/control/compliance-evidence`;
- `GET /v0/policy-backend-evidence` or `GET /v0/control/policy-backend-evidence`;
- `GET /v0/insurer-evidence` or `GET /v0/control/insurer-evidence`;
- `GET /v0/multi-agent-evidence` or `GET /v0/control/multi-agent-evidence`;
- `GET /v0/byoc-evidence` or `GET /v0/control/byoc-evidence`;
- `GET /v0/identity-provider-evidence` or `GET /v0/control/identity-provider-evidence`;
- `GET /v0/roadmap-evidence` or `GET /v0/control/roadmap-evidence`;
- `GET /v0/phase-scoreboards` or `GET /v0/control/phase-scoreboards`;
- `GET /v0/design-partner-dossiers` or `GET /v0/control/design-partner-dossiers`;
- `GET /v0/own-compliance-dossiers` or `GET /v0/control/own-compliance-dossiers`;
- `GET /v0/product-scope-decisions` or `GET /v0/control/product-scope-decisions`;
- `GET /v0/vertical-packs` or `GET /v0/control/vertical-packs`;
- `GET /v0/reliability-reports` or `GET /v0/control/reliability-reports`;
- `GET /v0/readiness` or `GET /v0/control/readiness`;
- `GET /v0/external-evidence` or `GET /v0/control/external-evidence`;
- `GET /v0/external-authority-gaps` or `GET /v0/control/external-authority-gaps`, with optional `authority_kind=...`, `requirement_id=...`, and `limit=...` filters;
- `GET /v0/authority-dossiers` or `GET /v0/control/authority-dossiers`.

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
surface. The MCP evidence list binds tool-call transcript hashes, proxy-capture
event roots, and MCP gateway authority evidence bundles into one gateway review
surface without exposing raw tool payloads.
The onboarding evidence list binds self-serve SDK/gateway onboarding receipts
into one startup review surface with source-artifact, quickstart replay, and
control-summary counts.
The insurer evidence list binds underwriting quote receipts and insurer partner
production-authority dossiers into one third-party underwriting review surface.
The multi-agent evidence list binds delegation receipts and signed delegation
graph exports into one cross-agent review surface. The BYOC evidence list binds
operator attestations and production-authority dossiers into one self-hosted
readiness surface. The identity-provider evidence list binds vendor identity,
provider identity exports, sessions, lifecycle operations, lifecycle workers,
and authority dossiers into one identity governance review surface.
The promotion-lifecycle evidence list binds human approvals, demotions,
rollbacks, and failed-soak demotion receipts into one CI/CD promotion review
surface. The framework-adapter evidence list binds adapter matrices, native hook
releases, hook operation receipts, and framework adapter production-authority
dossiers into one Phase 1 adapter coverage surface.
The review-portal evidence list binds supervised access, regulator acceptance,
service attestation, and production-authority dossier records into one hosted
auditor/regulator review surface. The trust-network evidence list binds
procurement clause and integration receipts, registry publication/status
receipts, marketplace distribution/author/settlement receipts, trust-network
service and worker receipts, worker bundles, and authority dossiers into one
cross-org review surface. Rebuild mode clears all derived read-model tables
before replaying the evidence chain, while leaving the chain itself as the
source of truth.
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
missing authority unit/task IDs, roadmap requirement titles/phases/priorities,
authority owner/source hints, and live-evidence counts. The external-authority
gap worklist returns the latest deterministic missing-unit tasks with exact
authority-kind, requirement-ID, and limit filters, plus grouped counts by
authority kind, collection-priority bucket, requirement phase, and requirement
priority so collection owners can pull and triage their remaining live-evidence
queue without parsing the full manifest. The authority-dossier list exposes
production authority dossier modes, coverage, freshness windows, and missing
requirement IDs so production readiness gaps stay visible in the same
control-plane surface.

The implementation falls back to SQLite `nolock=1` mode when running on local
filesystems that do not support normal SQLite locking, such as some UNC-backed
development workspaces. Production deployments should use Postgres.
