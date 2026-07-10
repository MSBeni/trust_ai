# Soak Demotion Receipt v0.1

A soak demotion receipt is a signed proof that a failed post-promotion soak report
caused a TrustAI demotion event. It binds the verification contract, the
`soak_report.completed` chain entry, and the resulting `promotion_gate.demoted`
chain entry into a portable artifact for offline review.

## Artifact

The receipt uses schema `trustai.soak-demotion/0.1` and records:

- contract ID, contract hash, and agent metadata;
- failed soak report entry ID, entry hash, report ID, evaluated timestamp,
  outcome, pass flag, failed metric checks, blocking incidents, and blocking
  drift alarms;
- demotion entry ID, entry hash, source and target environments, reason,
  triggering entry ID, and decision timestamp;
- source checks proving contract binding, soak replay, failure status, trigger
  entry binding, trigger summary binding, environment movement, reason, and
  decision timestamp;
- controls, violations, pass/fail status, limitations, receipt ID, and detached
  signatures.

## Verification

`soak-demotion-verify` recalculates the receipt ID, verifies the detached
signature, recomputes violations from the embedded source checks, and can replay
all source artifacts:

- the verification contract;
- the failed `soak_report.completed` chain entry; and
- the `promotion_gate.demoted` chain entry.

When sources are supplied, the verifier recomputes the contract hash, replays the
soak report payload against the contract, checks that the soak outcome is failed,
rebuilds the expected demotion trigger summary from failed checks, high/critical
incidents, and high/critical drift alarms, and verifies that the demotion entry
points at the same failed soak entry.

Editing the soak metrics, drift alarms, incident severity, demotion trigger,
contract hash, reason, environment transition, or receipt signature changes the
verification result.

## Chain Entry

Verified receipts append `soak_demotion.attested` entries with:

- receipt ID and receipt hash;
- contract, soak-report, and demotion summaries;
- source checks;
- violation count; and
- pass/fail status.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai soak-report examples/aitrade/verification-contract.yaml examples/aitrade/failed-soak-window.json --out artifacts/soak-report-entry.json --demote-on-failure --auto-register --state .trustai/soak-demotion-demo/evidence-chain.json --tenant soak-demotion-local --demotion-out artifacts/soak-demotion-entry.json
python -m trustai soak-demotion examples/aitrade/verification-contract.yaml artifacts/soak-report-entry.json artifacts/soak-demotion-entry.json --attested-at 2026-07-04T01:00:00Z --out artifacts/soak-demotion-receipt.json
python -m trustai soak-demotion-verify artifacts/soak-demotion-receipt.json --contract examples/aitrade/verification-contract.yaml --soak-entry artifacts/soak-report-entry.json --demotion-entry artifacts/soak-demotion-entry.json
python -m trustai soak-demotion-append artifacts/soak-demotion-receipt.json --contract examples/aitrade/verification-contract.yaml --soak-entry artifacts/soak-report-entry.json --demotion-entry artifacts/soak-demotion-entry.json --state .trustai/soak-demotion-demo/evidence-chain.json --tenant soak-demotion-local --out artifacts/soak-demotion-receipt-entry.json
```

## Limits

This receipt proves the evidence-chain decision to demote after failed soak
replay. It does not prove that production traffic was actually shifted or that a
cloud orchestrator rolled the agent back without deployment, provider, runtime,
or BYOC authority evidence.