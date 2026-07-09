# Shadow Replay and Soak Reports v0.1

Shadow replay evaluates a frozen candidate agent against production-like traffic
whose timestamps postdate the freeze boundary. The local reference evaluator
computes:

- shadow action match rate;
- trade policy compliance rate;
- maximum position error;
- p95 decision latency;
- holdout timestamp violations.

The output can be appended as `shadow_replay.completed` evidence and converted
into normal eval results for promotion gates. Shadow replay entries also embed a
signed temporal holdout manifest whose per-record hash chain binds record order,
record hashes, freeze boundary, holdout minimum, and the final replay root.

`temporal-holdout-manifest`, `temporal-holdout-verify`, and
`temporal-holdout-append` expose that manifest as a standalone artifact for
third-party review before a full proof pack is assembled.

Soak reports summarize post-promotion windows and append
`soak_report.completed` evidence. Blocking high/critical incidents or drift
alarms fail the report.

Proof-pack verification replays soak reports from the embedded source soak
window. The verifier rejects packs when the source soak hash, window timestamps,
metric checks, incidents, drift alarms, outcome, entry timestamp, or contract
hash do not reproduce the signed `soak_report.completed` payload.
