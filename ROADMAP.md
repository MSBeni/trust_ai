# Agent Trust Layer — Technical Roadmap

**Working name:** TrustAI (placeholder)
**One-liner:** Verifiable proof of agent behavior. Pre-registered success criteria, tamper-evident evidence chains, and portable "proof packs" that a regulator, auditor, or insurer can verify **without trusting us or you**.
**Date:** July 2026 · **Status:** v1 planning doc · **Audience:** founder/engineering

---

## 1. Thesis

Everyone is building dashboards for the agent *operator*. Nobody is building **proof for the third party** — the auditor, the regulator, the insurer, the counterparty, the customer's procurement team.

The analogy that matters: **Vanta made infrastructure compliance evidence automatic. We make agent *behavioral* evidence automatic.** SOC 2 answered "can I trust your company's security posture?" Proof packs answer "can I trust your agent with money/production?"

### Why the current stack doesn't solve this

| Layer | Players (mid-2026) | What they produce | What they DON'T produce |
|---|---|---|---|
| Observability/tracing | Braintrust, LangSmith, Arize, Fiddler, Galileo | Dashboards, traces for the operator | Nothing verifiable by an outsider |
| Evals | Braintrust, Patronus (Agent Eval Suite, Mar 2026), DeepEval | Scores chosen *after* the fact, movable goalposts | Pre-registered, tamper-proof criteria |
| Agent identity | Okta for AI Agents (GA Apr 2026), Microsoft Entra Agent ID | Who the agent is, what it may access | What the agent actually *did* and whether it worked |
| GRC/compliance automation | Vanta, Drata (ISO 42001, EU AI Act modules) | Policy docs + infra config evidence | Behavioral evidence about agent decisions |
| Platform control towers | ServiceNow AI Control Tower, IBM watsonx.governance | Inventory + governance *inside their ecosystem* | Neutral, portable, cross-platform proof |

The gap: **evidence that survives adversarial scrutiny.** A LangSmith dashboard is testimony. A signed, pre-registered, temporally-held-out, hash-chained proof pack is *evidence*. Regulated industries know the difference — it's why SR 11-7 model validation, SOX audit trails, and clinical trial pre-registration all exist.

### Why now (the forcing functions)

1. **Deployment outran governance.** 54% of orgs actively deploying agents in core operations (up from 11% two years ago); yet 88% of agent pilots never reach production — largely because nobody can prove they're safe to promote. We sell the promotion path itself.
2. **EU AI Act high-risk obligations land Dec 2, 2027** (Annex III: credit scoring, recruitment, etc.) and Aug 2, 2028 (Annex I embedded systems) — delayed from Aug 2026, which is a *gift*: the enforcement wave arrives exactly when a company started now is enterprise-ready. Transparency obligations already bite Aug 2026.
3. **Insurers are fleeing AI risk.** Berkshire, Chubb, Travelers won approval to exclude AI damages from general liability (regulators approved >80% of exclusion requests). New AI-liability startups (Mount, Klaimee, HSB/Munich Re) must underwrite agent risk with *no actuarial data*. Proof packs are that data. This is the network-effect wedge (§8).
4. **88% of orgs report suspected/confirmed AI agent security incidents**; only 22% treat agents as identity-bearing entities. Boards are asking "prove it's safe" and getting screenshots of dashboards.
5. **Banking/insurance lead agent adoption (47% with agents in production)** — and they already have model-risk-management teams (SR 11-7) with budget and muscle memory for exactly this discipline. We are not creating a category in their heads; we're tooling one they're legally required to run.

### Heritage

This generalizes what was already built for aitrade: **promotion gates** (agents advance dev→shadow→canary→prod only by passing pre-set criteria), **proof packs** (evidence bundles per promotion), and **soak reports** (temporal holdout performance before capital exposure). aitrade is design partner #0 and the reference implementation for "agents that touch money."

---

## 2. Core primitives (the product's vocabulary)

Everything in the product reduces to six primitives. Get these right and the rest is plumbing.

1. **Verification Contract** — a declarative, versioned spec (YAML/DSL) registered *before* testing begins: success metrics, thresholds, eval datasets, holdout policy, soak duration, blast-radius limits, required approvals. Its hash is committed to the evidence chain at registration → criteria cannot be quietly moved after results come in. This is clinical-trial pre-registration applied to agents; it kills Goodharting and cherry-picking, which is the #1 way agent "evals" lie today.
2. **Evidence Chain** — an append-only, Merkle-tree transparency log (Certificate Transparency / Sigstore-Rekor style) of everything: contract registrations, eval runs, traces, human approvals, promotions, incidents, config changes. Entries signed (org keys via KMS), RFC 3161 timestamped, periodically anchored externally. Tamper-*evident*, not merely access-controlled.
3. **Temporal Holdout** — first-class enforcement that evaluation data postdates agent/prompt/model freeze. The platform manages the time boundary, not the customer's honor system. Includes shadow-mode replay (agent runs on live inputs, actions not executed) and soak windows.
4. **Promotion Gate** — a CI/CD-native checkpoint (GitHub/GitLab checks, API) binding an agent *version* (model + prompts + tools + config, content-addressed) to a Verification Contract. Promotion emits a signed gate decision into the chain. Demotion/rollback is also an evidenced event.
5. **Proof Pack** — the flagship artifact. A portable, signed bundle: the contract, the results, chain inclusion proofs, environment fingerprint, human sign-offs, framework control mappings (ISO 42001, NIST AI RMF, EU AI Act, SR 11-7, SOC 2). Machine-verifiable (JSON-LD + detached signatures) and human-readable (rendered PDF). **Verifiable offline by anyone with the open-source verifier CLI — no account with us needed.**
6. **Runtime Attestation** — continuous post-promotion evidence: policy checks on high-risk actions (spend caps, approval workflows via OPA/Cedar-style policies), drift alarms against the contract's assumptions, incident capture. Proof isn't a point-in-time certificate; it decays without fresh attestation.

---

## 3. What we build vs. what we refuse to build

### In scope (focus)

- Agents that touch **money or production systems**: payments, trading, procurement, claims, infra changes, customer-affecting actions. Highest stakes → highest willingness to pay → clearest proof requirements.
- **Framework-neutral ingestion**: OTel GenAI semantic conventions first; adapters for LangGraph, CrewAI, OpenAI Agents SDK, Claude Agent SDK, Bedrock/Vertex agents; an MCP gateway that transparently evidences tool calls.
- **BYOC / self-hosted deployment** from early on. Regulated buyers will not ship trade/claims data to a startup's SaaS. This is painful and it is the moat vs. SaaS-only eval startups.
- **The open verifier + spec.** Give away the ability to *check* proofs; sell the machinery to *produce* them. (Sigstore/Let's Encrypt playbook.)
- **Third-party consumption surfaces**: auditor portal, insurer API, regulator export formats.

### Out of scope (anti-focus — write these on the wall)

- **Not another observability dashboard.** We ingest traces; we don't compete on trace-viewer UX. Integrate with LangSmith/Braintrust, don't replace them.
- **Not an agent framework or orchestrator.** The moment we build agents, we lose neutrality — neutrality is the product.
- **Not a guardrails/content-safety company.** Toxicity filters are commoditized; runtime policy here is about *authority and blast radius*, not content.
- **Not an eval library.** Evals are an input we orchestrate and notarize, not our IP. Support theirs (Braintrust, DeepEval, Patronus, customer-written).
- **Not general MLOps/model registry.** Agents, not models.
- **Not an insurer.** We sell underwriting *data* to insurers; we never hold risk.
- **No consumer anything.**

The discipline test for any feature request: *"Does this make the proof stronger, cheaper to produce, or more widely accepted?"* If no → decline.

---

## 4. Architecture

```
                        ┌─────────────────────────────────────────────┐
                        │              CONTROL PLANE                  │
                        │  Contract Registry · Agent/Version Registry │
                        │  Gate Engine · Policy Engine (Cedar/OPA)    │
                        │  Framework Mapper (ISO42001/NIST/EUAIA/SR11-7)│
                        └──────────────┬──────────────────────────────┘
                                       │
 ┌──────────────┐   OTel GenAI   ┌─────▼──────────┐    ┌──────────────────┐
 │ Customer     │──spans/events──▶  INGEST        │    │  EVIDENCE CHAIN  │
 │ agents       │                │  Collector →    │───▶│  Merkle log      │
 │ (LangGraph,  │◀──MCP gateway──│  Kafka/Redpanda │    │  (Trillian-style)│
 │  CrewAI,     │                │  → ClickHouse   │    │  KMS signing     │
 │  OpenAI SDK, │                └─────┬──────────┘    │  RFC3161 TSA     │
 │  Claude SDK) │                      │               │  WORM store      │
 └──────────────┘                ┌─────▼──────────┐    │  (S3 ObjectLock) │
                                 │ EVAL/HOLDOUT   │    └───────┬──────────┘
                                 │ ORCHESTRATOR   │            │
                                 │ shadow replay, │      ┌─────▼──────────┐
                                 │ soak windows,  │      │ PROOF PACK     │
                                 │ deterministic  │      │ COMPILER       │
                                 │ re-execution   │      │ JSON-LD + PDF  │
                                 └────────────────┘      └─────┬──────────┘
                                                               │
                              ┌────────────────────────────────▼─────────┐
                              │ CONSUMPTION: auditor portal · insurer API│
                              │ regulator exports · OSS verifier CLI     │
                              └──────────────────────────────────────────┘
```

### Component decisions

- **Ingestion**: OTel-native (GenAI semantic conventions are winning as the standard — ride it, don't fight it). Thin SDKs (Python/TS first) that add evidence semantics (agent version hash, contract ID, action risk class) on top of vanilla OTel. The **MCP gateway** is the killer integration: a proxy in front of tool servers that evidences every tool call with zero agent-code changes — deploy in an afternoon.
- **Evidence chain**: Merkle transparency log per tenant; entries = canonical CBOR/JSON, signed via customer-controlled KMS keys (AWS KMS/HSM), RFC 3161 timestamps from an independent TSA, tree heads periodically cross-anchored (to our public log, optionally to a public blockchain if a customer demands it — anchoring is a checkbox, not an ideology). Raw payloads in WORM object storage (S3 Object Lock compliance mode) for configurable retention (7y default for finserv). **Key property: we can prove we didn't tamper, and the customer can prove *they* didn't either.**
- **Trace store**: ClickHouse for high-volume span analytics; Postgres for control-plane state. Chain stores *hashes + pointers*, not bulk payloads.
- **Eval/holdout orchestrator**: runs customer evals (their harnesses, Braintrust/DeepEval/Patronus adapters, or ours) inside sandboxed runners; enforces that holdout data timestamps postdate the version freeze; supports shadow replay against recorded production traffic and deterministic re-execution (seeded, temperature-pinned where possible; where nondeterminism is irreducible, evidence *distributions* over N runs — be honest about this in the spec, auditors respect honesty about limits).
- **Policy engine**: Cedar (or OPA) policies over action risk classes: `spend > $X → require human approval`, `prod-write → require active gate pass < 30d old`. Approval events are chain entries.
- **Proof pack compiler**: assembles contract + results + inclusion proofs + env fingerprint (model IDs, prompt hashes, tool manifests) + sign-offs into a signed JSON-LD bundle; renders PDF for humans; maps results onto compliance frameworks via a versioned controls ontology.
- **Verifier**: open-source Go CLI + spec (Apache-2.0). Verifies signatures, chain inclusion, contract-hash-precedes-results ordering, holdout timestamps. **This repo is the marketing.**
- **Deployment**: single Helm chart; SaaS, BYOC (their cloud account, our operator), and air-gapped self-hosted. Control plane multi-tenant; data plane per-tenant.
- **Stack**: Go for chain/verifier/gateway (single static binaries matter for on-prem), Python for eval orchestration (ecosystem gravity), TypeScript/React for portal. Boring choices on purpose.

---

## 5. Phased build plan

### Phase 0 — Extraction & spec (Weeks 0–8)

*Goal: turn aitrade's internal machinery into a general spec + skeleton. No customers yet.*

1. Wk 1–2: Write the **Proof Pack spec v0.1** and **Verification Contract DSL v0.1** as public documents. Extract the generalizable shape of aitrade's gates/packs/soak reports. This document *is* the company; iterate it before code.
2. Wk 2–4: Build the **evidence chain core** (Merkle log, signing, inclusion proofs) + **verifier CLI**. Test: verifier detects any single-byte tamper in a 1M-entry log.
3. Wk 4–6: **Contract registry + gate engine** MVP: register contract → hash to chain → run evals → gate decision → chain entry.
4. Wk 6–8: **OTel ingest** (Python SDK + collector) and **proof pack compiler v0** (JSON-LD + PDF). Re-implement aitrade's promotion flow on the new stack end-to-end — aitrade becomes customer #0.

**Exit criteria:** aitrade promotions run through the platform; a proof pack from aitrade verifies offline with the public CLI; spec published on GitHub.

### Phase 1 — Design-partner MVP (Months 3–8)

*Goal: 3–5 design partners in finserv/fintech running real promotion gates. Charge from day one ($30–60k pilots) — free pilots produce fake signal.*

Features, in priority order:

1. **MCP gateway** (zero-code-change evidence capture for tool calls) — the fastest "wow."
2. **Shadow replay + temporal holdout enforcement** — the technically hardest, most differentiated feature. Recorded prod traffic → replay against candidate version → holdout-clean comparison.
3. **CI/CD promotion gates**: GitHub/GitLab checks API, Slack approvals, demotion on soak failure.
4. **Framework adapters**: LangGraph + OpenAI Agents SDK + Claude Agent SDK (cover ~70% of enterprise agent code); CrewAI next.
5. **Soak reports v1**: automated post-promotion windows with drift alarms against contract assumptions.
6. **Auditor view v0**: read-only portal where the customer's *internal audit / model risk team* reviews packs. (Internal auditors are the beachhead persona — they already exist and already have this job.)
7. **BYOC deployment** for at least one partner.

Deliberately **deferred**: SOC-2-style continuous dashboards, multi-agent trust scoring, non-English UX, fancy analytics.

**Exit criteria:** ≥3 paying partners with agents gated in production; ≥1 partner shows a proof pack to an external party (auditor, regulator, or insurer) and it *survives*; that story becomes the seed/Series-A narrative.

### Phase 2 — Platform (Months 8–18)

*Goal: repeatable product, $1–3M ARR, Series A.*

1. **Compliance framework mapper**: contract results → ISO 42001, NIST AI RMF, EU AI Act Annex-III technical documentation, SR 11-7 validation reports, SOC 2 evidence. One eval run → five frameworks' evidence. (This is where Vanta/Drata become *partners*: export packs into their platforms as evidence sources rather than competing for the GRC seat.)
2. **Insurer API v1**: structured risk telemetry from proof packs, with customer consent, to AI-liability underwriters (Mount, Klaimee, HSB-class). Target: an underwriter offers a premium discount for pack-backed agents. **The first discount is the network-effect ignition** (§8).
3. **Runtime attestation GA**: Cedar policy packs per vertical (trading, claims, procurement), approval workflows, spend/blast-radius limits, proof decay (packs expire without fresh soak evidence).
4. **Agent registry & inventory**: discovery of ungoverned agents (integrate Okta Agent identities, Entra Agent ID, ServiceNow inventory — complement, don't fight, the identity layer).
5. **Multi-agent evidence**: delegation chains (agent A invoked agent B under contract C) — evidence graphs, not just per-agent logs. Nobody has this; multi-agent systems are where 2027 incidents will come from.
6. **Self-serve onboarding** for the SDK/gateway tier (PLG motion for engineers; enterprise sales motion for the platform).

**Exit criteria:** 15–25 customers; ≥2 verticals beyond finserv (healthcare RCM, insurance claims are adjacent); first insurer integration live; SOC 2 Type II + ISO 42001 for *ourselves* (we must be our own best proof pack).

### Phase 3 — Regulatory wave (Months 18–30, i.e., landing at EU AI Act Dec 2027 enforcement)

1. **EU AI Act product**: Annex III technical-documentation generator from evidence chains; conformity-assessment support packs; EU-hosted data plane (Frankfurt), digital-sovereignty story.
2. **Regulator/supervisor portal**: read-only supervised access with selective disclosure (Merkle proofs let you reveal *specific* entries without exposing the whole log — this is why the chain architecture matters, not just vibes).
3. **Auditor ecosystem**: train/certify Big-4 and boutique AI-audit shops on the verifier and pack format; they become a channel, not a competitor. (Auditors billing hours to review packs = auditors selling our product for us.)
4. **Vertical packs**: trading/treasury (SR 11-7 native), insurance claims (NAIC model bulletin), healthcare (HIPAA + FDA SaMD-adjacent), public sector (FedRAMP path decision here, not earlier).
5. **Proof Pack spec v1.0 → standards track**: submit to a body (ETSI/ISO/IEEE or a Linux Foundation project). The spec becoming *the* format is the endgame moat.

**Exit criteria:** $8–15M ARR; a named regulator or supervisor has accepted packs in a real examination; ≥2 insurers price on packs.

### Phase 4 — The standard (Months 30+)

- **Trust network**: enterprises demand proof packs from their *vendors'* agents (procurement clause: "agent vendors must supply TrustAI-format packs"). Cross-org verification = the GitHub-like network effect: every verified party recruits the next.
- **Actuarial data products**: anonymized, consented incident/performance corpus → the only longitudinal dataset on agent reliability in existence. Insurers, and eventually regulators, price from it. Data moat compounds yearly and cannot be fast-followed.
- **Marketplace**: certified contract templates and policy packs per vertical/regulation, third-party authored.

---

## 6. Feature master list (condensed)

| Feature | Phase | Priority | Notes |
|---|---|---|---|
| Verification Contract DSL + registry | 0 | P0 | The pre-registration primitive |
| Merkle evidence chain + KMS signing + TSA | 0 | P0 | Tamper-evidence core |
| OSS verifier CLI + public spec | 0 | P0 | The moat/marketing repo |
| OTel GenAI ingest + Python/TS SDKs | 0–1 | P0 | Ride the standard |
| Proof pack compiler (JSON-LD + PDF) | 0–1 | P0 | Flagship artifact |
| MCP evidence gateway | 1 | P0 | Zero-code adoption wedge |
| Shadow replay + temporal holdout enforcement | 1 | P0 | Hardest, most differentiated |
| CI/CD promotion gates (GitHub/GitLab/Slack) | 1 | P0 | Where engineers live |
| Framework adapters (LangGraph/OpenAI/Claude SDK/CrewAI) | 1 | P1 | Coverage play |
| Soak reports + drift alarms | 1 | P1 | aitrade heritage, generalized |
| Internal-auditor portal | 1 | P1 | Beachhead persona |
| BYOC/self-hosted (Helm) | 1–2 | P0 | Regulated-buyer table stakes |
| Compliance framework mapper (ISO 42001/NIST/EU/SR 11-7/SOC 2) | 2 | P0 | One run → five frameworks |
| Insurer risk API | 2 | P0 | Network-effect ignition |
| Runtime policy (Cedar) + approvals + proof decay | 2 | P1 | Continuous, not point-in-time |
| Agent inventory + identity integrations (Okta/Entra) | 2 | P1 | Complement identity layer |
| Multi-agent delegation evidence graphs | 2 | P2 | 2027's incidents, today's design |
| EU AI Act doc generator + EU data plane | 3 | P0 | Timed to Dec 2027 |
| Selective-disclosure regulator portal | 3 | P1 | Merkle proofs earn their keep |
| Auditor certification program | 3 | P1 | Channel, not feature |
| Standards submission (spec v1.0) | 3 | P1 | Category ownership |
| Cross-org vendor trust network | 4 | P1 | The unicorn mechanic |
| Actuarial data products | 4 | P2 | Compounding data moat |

---

## 7. GTM

- **Beachhead:** financial services agent teams (47% already have agents in production — highest adoption, hardest requirements, existing model-risk budget lines). Persona pair: the *agent platform engineer* (feels the 88%-pilots-die pain; wants promotion gates) and the *model risk / internal audit lead* (owns the mandate; signs the check). Sell to the pair — engineer adopts gateway free-tier, risk lead buys the platform.
- **Pricing:** platform fee + per-governed-agent-version per-environment + evidence volume. Pilot $30–60k; enterprise ACV target $150–400k. Never price per-seat (agents are the users).
- **Motion:** OSS verifier + spec for top-of-funnel credibility; self-serve gateway tier; enterprise sales for BYOC/compliance. Publish "State of Agent Reliability" from anonymized data annually — own the discourse.
- **Partners, not enemies:** Okta/Entra (identity → we do behavior), Vanta/Drata (GRC seat → we're their agent-evidence source), Braintrust/LangSmith (traces/evals → we notarize), auditors (channel), insurers (demand generator). The only true head-on competitor is ServiceNow AI Control Tower — beat it on **neutrality** (they govern best inside their ecosystem; multi-cloud, multi-framework enterprises need Switzerland) and on **verifiability** (inventory ≠ proof).

## 8. Unicorn logic, explicitly

A $1B+ outcome requires a mechanic beyond "good product in growing market." Ours is a three-stage ratchet:

1. **Compliance pull (2026–28):** EU AI Act Dec-2027 + sector regulators force documented, verifiable agent governance. Every regulated deployer needs *something*; we're the only *portable, third-party-verifiable* something. This gets us to tens of millions ARR but is not, alone, a unicorn — Vanta-for-agents is a $300M company.
2. **Insurance ratchet (2027–29):** insurers exclude AI from general liability (already happening) → standalone AI-liability coverage becomes mandatory in enterprise contracts (already becoming standard in procurement) → underwriters demand risk data → proof packs are the *only* standardized underwriting evidence → **premium discounts make proof packs self-funding**. Compliance is a cost; an insurance discount is ROI. This flips the sale from "must buy" to "profitable to buy."
3. **Network lock-in (2028+):** procurement clauses require vendors' agents to ship packs → every verified org pressures its supply chain to join → cross-org verification graph + the actuarial corpus become infrastructure nobody can rip out. That's the $1B+ shape: **the trust protocol for the agent economy**, not a governance SaaS.

## 9. Risks & counters

| Risk | Likelihood | Counter |
|---|---|---|
| ServiceNow/Okta/hyperscalers bundle "good enough" governance | High | Neutrality + open spec + verifiability depth they won't build (their incentive is lock-in, ours is portability — structurally defensible) |
| Regulation slips again (EU already delayed once) | Medium | Insurance ratchet and the 88%-pilot-death pain are market-driven, not regulation-driven; regulation is an accelerant, not the engine |
| Eval/observability players move up into "evidence" | Medium | The chain + spec + third-party consumption surfaces are a different architecture, not a feature; ship the verifier ecosystem before they pivot |
| Nondeterminism makes "proof" scientifically contestable | Medium | Be rigorously honest: distributional evidence, N-run confidence intervals, documented limits in the spec. Overclaiming kills us with the exact audience we serve |
| Enterprises won't ship agent data out | High | BYOC from Phase 1 — this is why it's P0 despite the pain |
| Proof-pack theater (customers game contracts) | Medium | Contract templates with mandatory minimums per risk class; auditor certification keeps humans in the loop |

## 10. Definition of done per phase (scoreboard)

- **P0:** aitrade fully on-platform; public spec + verifier; tamper test passes.
- **P1:** 3+ paying design partners; 1 pack survives external scrutiny; $250k+ signed.
- **P2:** $1–3M ARR; insurer integration live; SOC 2 + ISO 42001 ourselves; Series A.
- **P3:** $8–15M ARR; regulator accepts packs in a live examination; 2+ insurers pricing on packs; spec on standards track.
- **P4:** packs appear in third-party procurement contracts we didn't sell; data products revenue; the word "proof pack" used generically in the market.

---

## Appendix: market sources (mid-2026)

- Agent deployment: 54% actively deploying in core ops (up from 11%); 88% of pilots never reach production; banking/insurance lead at 47% — [Digital Applied](https://www.digitalapplied.com/blog/ai-agent-adoption-2026-enterprise-data-points), [LumiChats](https://lumichats.com/blog/ai-agents-97-percent-deployed-11-percent-production-2026), [First Page Sage](https://firstpagesage.com/reports/agentic-ai-adoption-statistics/)
- EU AI Act: high-risk delayed to Dec 2, 2027 (Annex III) / Aug 2, 2028 (Annex I); transparency Aug 2026 — [Gibson Dunn](https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/), [Latham & Watkins](https://www.lw.com/en/insights/ai-act-update-eu-resolves-to-change-rules-and-extend-deadlines), [Implementation timeline](https://artificialintelligenceact.eu/implementation-timeline/)
- Agent identity: Okta for AI Agents GA Apr 30, 2026; 88% report agent incidents, 22% treat agents as identities — [Okta](https://www.okta.com/blog/ai/okta-ai-agents-early-access-announcement/), [HyperFRAME](https://hyperframeresearch.com/2026/03/16/identity-as-the-last-firewall-analyzing-okta-for-ai-agents/)
- Control towers: ServiceNow AI Control Tower expansion + IBM alliance (Jun 2026) — [diginomica](https://diginomica.com/servicenow-knowledge-2026-ai-control-tower-expands-autonomous-workforce-reaches-every-function-and), [Forbes](https://www.forbes.com/sites/victordey/2026/05/05/servicenow-deepens-agent-governance-as-enterprise-demand-counters-saaspocalypse/)
- Evals: Patronus $50M Series B + Agent Eval Suite (Mar 2026); Braintrust/LangSmith/Galileo positioning — [Galileo](https://galileo.ai/blog/best-ai-agent-evaluation-platforms), [Braintrust](https://www.braintrust.dev/articles/best-ai-observability-tools-2026)
- GRC: Vanta/Drata ISO 42001 + EU AI Act modules — [Vanta](https://www.vanta.com/products/iso-42001), [Drata](https://drata.com/frameworks/iso-42001)
- Insurance: AI exclusions from GL (>80% of requests approved); Mount, Klaimee, HSB AI-liability products — [PYMNTS](https://www.pymnts.com/news/artificial-intelligence/2026/big-insurance-backs-away-from-ai-risk-and-startups-rush-in/), [Munich Re/HSB](https://www.munichre.com/hsb/en/press-and-publications/press-releases/2026/2026-03-18-introducing-ai-liability-insurance-for-small-businesses.html), [The Insurer](https://www.theinsurer.com/program-manager/news/standalone-ai-liability-market-takes-shape-with-underwriting-discipline-key-to-2026-04-24/)
- Funding: agent execution infrastructure = 20.7% of 2026 YTD deals; first financings 43% of capital — [New Market Pitch](https://newmarketpitch.com/blogs/news/agentic-ai-funding-trends)
