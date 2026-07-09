from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain
from .contracts import contract_hash, validate_contract
from .gate import OPS, evaluate_contract
from .reexecution_policy import evaluate_reexecution_policy

REEXECUTION_REPORT_SCHEMA = "trustai.reexecution-report/0.1"
REEXECUTION_ENTRY_TYPE = "reexecution.completed"


@dataclass
class ReexecutionVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    run_count: int = 0


def load_eval_results(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("eval results file must contain an object")
    return value


def load_reexecution_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def build_reexecution_report(
    contract: dict[str, Any],
    runs: list[dict[str, Any]],
    *,
    method: str = "n-run-reexecution",
    seed_policy: str = "recorded-or-fixed-seed",
    temperature: float | None = None,
    required_pass_rate: float = 1.0,
    policy: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not runs:
        raise ValueError("at least one re-execution run is required")
    errors = validate_contract(contract)
    if errors:
        raise ValueError("invalid verification contract: " + "; ".join(errors))
    if required_pass_rate < 0 or required_pass_rate > 1:
        raise ValueError("required_pass_rate must be between 0 and 1")

    body = _report_body(
        contract,
        runs,
        method=method,
        seed_policy=seed_policy,
        temperature=temperature,
        required_pass_rate=required_pass_rate,
        policy=policy,
        generated_at=generated_at or utc_now(),
    )
    return {**body, "report_id": content_hash(body)}


def verify_reexecution_report(report: dict[str, Any]) -> ReexecutionVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if report.get("schema") != REEXECUTION_REPORT_SCHEMA:
        errors.append(f"unsupported re-execution report schema: {report.get('schema')}")
    body = without_keys(report, "report_id")
    if report.get("report_id") != content_hash(body):
        errors.append("report_id does not match canonical report body")

    contract = report.get("contract", {}).get("body")
    if not isinstance(contract, dict):
        errors.append("re-execution report missing contract body")
        contract = {}
    else:
        contract_errors = validate_contract(contract)
        errors.extend(f"contract invalid: {error}" for error in contract_errors)

    source_runs = report.get("source_runs", [])
    if not isinstance(source_runs, list) or not source_runs:
        errors.append("re-execution report must include source runs")
        source_runs = []
    runs: list[dict[str, Any]] = []
    for index, source in enumerate(source_runs):
        if not isinstance(source, dict):
            errors.append(f"source_runs[{index}] must be an object")
            continue
        results = source.get("results")
        if not isinstance(results, dict):
            errors.append(f"source_runs[{index}] missing embedded results")
            continue
        if source.get("results_hash") != content_hash(results):
            errors.append(f"source_runs[{index}] results_hash mismatch")
        runs.append(results)

    policy: dict[str, Any] | None = None
    policy_record = report.get("policy")
    if policy_record is not None:
        if not isinstance(policy_record, dict):
            errors.append("policy must be an object when present")
        elif not isinstance(policy_record.get("body"), dict):
            errors.append("policy.body must be an object when policy is present")
        else:
            policy = policy_record["body"]

    if contract and runs:
        expected = _report_body(
            contract,
            runs,
            method=report.get("execution", {}).get("method", "n-run-reexecution"),
            seed_policy=report.get("execution", {}).get("seed_policy", "recorded-or-fixed-seed"),
            temperature=report.get("execution", {}).get("temperature"),
            required_pass_rate=report.get("execution", {}).get("required_pass_rate", 1.0),
            policy=policy,
            generated_at=report.get("generated_at") or utc_now(),
        )
        for field in ("contract", "execution", "source_runs", "metric_distributions", "policy", "policy_result", "overall"):
            if report.get(field) != expected.get(field):
                errors.append(f"{field} does not match recomputed re-execution report")

    if not report.get("overall", {}).get("passed"):
        warnings.append("re-execution report is valid but overall outcome is not passed")

    return ReexecutionVerification(ok=not errors, errors=errors, warnings=warnings, run_count=len(source_runs))


def append_reexecution_report(
    chain: EvidenceChain,
    report: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_reexecution_report(report)
    if not result.ok:
        raise ValueError("invalid re-execution report: " + "; ".join(result.errors))
    payload = {
        "report_id": report["report_id"],
        "report_hash": content_hash(report),
        "contract_id": report["contract"]["id"],
        "contract_hash": report["contract"]["hash"],
        "agent": report["contract"]["agent"],
        "run_count": report["execution"]["run_count"],
        "required_pass_rate": report["execution"]["required_pass_rate"],
        "passed": report["overall"]["passed"],
        "outcome": report["overall"]["outcome"],
        "metric_distributions": report["metric_distributions"],
        "policy": report.get("policy"),
        "policy_result": report.get("policy_result"),
        "report": report,
    }
    return chain.append(REEXECUTION_ENTRY_TYPE, payload, key=key, timestamp=report["generated_at"])


def write_reexecution_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def write_reexecution_markdown(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_reexecution_markdown(report), encoding="utf-8")


def render_reexecution_markdown(report: dict[str, Any]) -> str:
    metrics = "\n".join(
        f"- `{metric['name']}`: pass_rate={metric['pass_rate']:.3f}, "
        f"mean={metric.get('mean')}, worst={metric.get('worst_actual')}, "
        f"passed={str(metric['passed']).lower()}"
        for metric in report.get("metric_distributions", [])
    )
    overall = report.get("overall", {})
    policy_result = report.get("policy_result") or {}
    policy_line = ""
    if policy_result:
        policy_line = f"\nPolicy: `{policy_result.get('policy_id', '')}` passed={str(policy_result.get('passed')).lower()}\n"
    return f"""# TrustAI Re-execution Report

Report ID: `{report.get('report_id', '')}`

Contract: `{report.get('contract', {}).get('id', '')}`

Runs: {report.get('execution', {}).get('run_count')}

Outcome: {overall.get('outcome', '')}
{policy_line}
## Metric Distributions

{metrics}
"""


def _report_body(
    contract: dict[str, Any],
    runs: list[dict[str, Any]],
    *,
    method: str,
    seed_policy: str,
    temperature: float | None,
    required_pass_rate: float,
    policy: dict[str, Any] | None,
    generated_at: str,
) -> dict[str, Any]:
    digest = contract_hash(contract)
    source_runs = [_run_summary(contract, run, index) for index, run in enumerate(runs)]
    distributions = [
        _metric_distribution(metric, source_runs, required_pass_rate)
        for metric in contract.get("metrics", [])
    ]
    run_gate_pass_count = sum(1 for run in source_runs if run["gate_decision"]["passed"])
    holdout_passed_all = all(run["gate_decision"]["holdout"]["passed"] for run in source_runs)
    metric_distributions_passed = all(metric["passed"] for metric in distributions)
    policy_result = None
    policy_passed = True
    if policy is not None:
        policy_result = evaluate_reexecution_policy(
            contract,
            runs,
            policy,
            method=method,
            seed_policy=seed_policy,
            temperature=temperature,
            required_pass_rate=required_pass_rate,
        )
        policy_passed = policy_result["passed"]
    passed = run_gate_pass_count == len(source_runs) and holdout_passed_all and metric_distributions_passed and policy_passed
    body = {
        "schema": REEXECUTION_REPORT_SCHEMA,
        "generated_at": generated_at,
        "contract": {
            "id": contract.get("id"),
            "version": contract.get("version"),
            "hash": digest,
            "agent": contract.get("agent", {}),
            "body": contract,
        },
        "execution": {
            "method": method,
            "seed_policy": seed_policy,
            "temperature": temperature,
            "run_count": len(source_runs),
            "required_pass_rate": required_pass_rate,
        },
        "source_runs": source_runs,
        "metric_distributions": distributions,
        "overall": {
            "passed": passed,
            "outcome": "passed" if passed else "failed",
            "run_gate_pass_count": run_gate_pass_count,
            "run_count": len(source_runs),
            "holdout_passed_all": holdout_passed_all,
            "metric_distributions_passed": metric_distributions_passed,
            "policy_passed": policy_passed,
        },
        "limitations": [
            "Distributional evidence summarizes repeated eval results; it does not remove model nondeterminism.",
            "Confidence intervals are descriptive and should be interpreted with the recorded run count.",
        ],
    }
    if policy is not None:
        body["policy"] = {
            "id": policy.get("id"),
            "version": policy.get("version"),
            "hash": content_hash(policy),
            "body": policy,
        }
        body["policy_result"] = policy_result
    return body


def _run_summary(contract: dict[str, Any], run: dict[str, Any], index: int) -> dict[str, Any]:
    decision = evaluate_contract(contract, run)
    return {
        "index": index,
        "run_id": run.get("run_id") or f"run-{index + 1}",
        "evaluated_at": run.get("evaluated_at"),
        "results_hash": content_hash(run),
        "dataset": {
            "id": run.get("dataset", {}).get("id"),
            "record_count": len(run.get("dataset", {}).get("records", [])),
        },
        "environment": run.get("environment", {}),
        "metrics": run.get("metrics", {}),
        "gate_decision": decision,
        "results": run,
    }


def _metric_distribution(
    metric: dict[str, Any],
    source_runs: list[dict[str, Any]],
    required_pass_rate: float,
) -> dict[str, Any]:
    name = metric["name"]
    operator = metric["operator"]
    threshold = metric["threshold"]
    values = [
        float(run["metrics"][name])
        for run in source_runs
        if isinstance(run.get("metrics", {}).get(name), (int, float))
    ]
    pass_count = sum(1 for value in values if bool(OPS[operator](value, threshold)))
    run_count = len(source_runs)
    pass_rate = pass_count / run_count if run_count else 0
    worst_actual = _worst_actual(values, operator, threshold)
    worst_case_passed = _worst_passed(values, operator, threshold)
    mean = sum(values) / len(values) if values else None
    sample_stdev = _sample_stdev(values)
    mean_ci = _mean_ci_95(values, mean, sample_stdev)
    pass_rate_ci = _wilson_interval(pass_count, run_count)
    passed = len(values) == run_count and pass_rate >= required_pass_rate and worst_case_passed
    return {
        "name": name,
        "operator": operator,
        "threshold": threshold,
        "run_count": run_count,
        "observed_count": len(values),
        "values": values,
        "mean": mean,
        "min": min(values) if values else None,
        "max": max(values) if values else None,
        "sample_stdev": sample_stdev,
        "mean_ci_95": mean_ci,
        "pass_count": pass_count,
        "pass_rate": pass_rate,
        "pass_rate_wilson_ci_95": pass_rate_ci,
        "required_pass_rate": required_pass_rate,
        "worst_actual": worst_actual,
        "worst_case_passed": worst_case_passed,
        "passed": passed,
    }


def _worst_actual(values: list[float], operator: str, threshold: Any) -> float | None:
    if not values:
        return None
    if operator in (">=", ">"):
        return min(values)
    if operator in ("<=", "<"):
        return max(values)
    if operator in ("==", "!="):
        return max(values, key=lambda value: abs(value - float(threshold)))
    return None


def _worst_passed(values: list[float], operator: str, threshold: Any) -> bool:
    if not values:
        return False
    if operator in (">=", ">", "<=", "<"):
        worst = _worst_actual(values, operator, threshold)
        return bool(OPS[operator](worst, threshold))
    return all(bool(OPS[operator](value, threshold)) for value in values)


def _sample_stdev(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
    return math.sqrt(variance)


def _mean_ci_95(values: list[float], mean: float | None, sample_stdev: float | None) -> dict[str, float | None]:
    if not values or mean is None:
        return {"lower": None, "upper": None}
    if len(values) < 2 or sample_stdev is None:
        return {"lower": mean, "upper": mean}
    margin = 1.96 * sample_stdev / math.sqrt(len(values))
    return {"lower": mean - margin, "upper": mean + margin}


def _wilson_interval(successes: int, total: int, z: float = 1.96) -> dict[str, float | None]:
    if total == 0:
        return {"lower": None, "upper": None}
    phat = successes / total
    denominator = 1 + z * z / total
    center = (phat + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * total)) / total) / denominator
    return {"lower": max(0, center - margin), "upper": min(1, center + margin)}

