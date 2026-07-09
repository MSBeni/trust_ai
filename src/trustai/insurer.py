from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def build_insurer_telemetry(
    proof_pack: dict[str, Any],
    consent_id: str = "local-demo-consent",
    consent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    decision = proof_pack.get("gate_decision", {})
    checks = decision.get("checks", [])
    failed_checks = [check for check in checks if not check.get("passed")]
    holdout = decision.get("holdout", {})
    approvals = decision.get("approvals", {})

    score = 100
    if decision.get("outcome") != "passed":
        score -= 40
    score -= 10 * len(failed_checks)
    if not holdout.get("passed"):
        score -= 20
    if holdout.get("records_checked", 0) < 100:
        score -= 5
    if not approvals.get("passed", True):
        score -= 15
    score = max(0, min(100, score))

    return {
        "schema": "trustai.insurer-risk-telemetry/0.1",
        "consent": {
            "consent_id": consent_id,
            "scope": "proof-pack-risk-telemetry",
            "status": consent,
        },
        "pack_id": proof_pack.get("pack_id"),
        "contract_id": decision.get("contract_id"),
        "agent": decision.get("agent", {}),
        "gate_outcome": decision.get("outcome"),
        "risk_score": score,
        "risk_tier": "low" if score >= 85 else "medium" if score >= 65 else "high",
        "signals": {
            "failed_checks": failed_checks,
            "holdout": holdout,
            "approvals": approvals,
            "chain_root": proof_pack.get("chain", {}).get("tree", {}).get("root"),
            "frameworks": [
                mapping.get("framework")
                for mapping in proof_pack.get("framework_mappings", [])
            ],
        },
    }


def write_insurer_telemetry(path: str | Path, telemetry: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(telemetry, indent=2, sort_keys=True), encoding="utf-8")
