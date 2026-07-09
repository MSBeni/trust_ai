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
into normal eval results for promotion gates.

Soak reports summarize post-promotion windows and append
`soak_report.completed` evidence. Blocking high/critical incidents or drift
alarms fail the report.
