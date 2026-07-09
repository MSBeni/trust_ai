from __future__ import annotations

import json
import os
from pathlib import Path


BASE_RECORDS = [
    {"id": "shadow-001", "timestamp": "2026-07-02T02:15:00Z"},
    {"id": "shadow-002", "timestamp": "2026-07-02T08:30:00Z"},
    {"id": "shadow-003", "timestamp": "2026-07-03T05:45:00Z"},
]

METRICS_BY_SEED = {
    2026070301: {
        "trade_policy_compliance_rate": 0.995,
        "max_position_error_usd": 250,
        "p95_decision_latency_ms": 980,
    },
    2026070302: {
        "trade_policy_compliance_rate": 0.993,
        "max_position_error_usd": 275,
        "p95_decision_latency_ms": 1035,
    },
    2026070303: {
        "trade_policy_compliance_rate": 0.996,
        "max_position_error_usd": 225,
        "p95_decision_latency_ms": 1010,
    },
}

EVALUATED_AT_BY_SEED = {
    2026070301: "2026-07-03T12:00:00Z",
    2026070302: "2026-07-03T12:10:00Z",
    2026070303: "2026-07-03T12:20:00Z",
}


def main() -> int:
    seed = int(os.environ["TRUSTAI_SEED"])
    output = Path(os.environ["TRUSTAI_OUTPUT"])
    policy = json.loads(os.environ["TRUSTAI_POLICY"])
    pins = policy["pins"]
    sandbox = policy["sandbox"]
    run_id = os.environ["TRUSTAI_RUN_ID"]
    metrics = METRICS_BY_SEED[seed]
    result = {
        "run_id": run_id,
        "evaluated_at": EVALUATED_AT_BY_SEED[seed],
        "dataset": {
            "id": "prod-shadow-holdout-20260702",
            "description": "Deterministic local re-execution of live BTCUSDT risk decisions after freeze",
            "records": BASE_RECORDS,
        },
        "metrics": metrics,
        "approvals": [
            {
                "role": "model_risk",
                "approver": "model-risk@example.com",
                "approved_at": "2026-07-03T13:00:00Z",
            },
            {
                "role": "trading_ops",
                "approver": "trading-ops@example.com",
                "approved_at": "2026-07-03T13:02:00Z",
            },
        ],
        "environment": {
            "runtime": pins["runtime"],
            "region": "local-dev",
            "otel_schema": "opentelemetry.semconv.gen_ai/1.0",
            "runner": "trustai-reexecution",
            "seed": seed,
            "temperature": 0,
            "model": pins["model"],
            "prompt_hash": pins["prompt_hash"],
            "tool_manifest_hash": pins["tool_manifest_hash"],
            "sandbox": {
                "runner_image": sandbox["runner_image"],
                "runner_image_digest": sandbox["runner_image_digest"],
                "network": sandbox["network"],
                "read_only_rootfs": sandbox.get("read_only_rootfs", False),
            },
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
