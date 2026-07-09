from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash
from .contracts import validate_contract

REEXECUTION_POLICY_SCHEMA = "trustai.reexecution-policy/0.1"


@dataclass
class ReexecutionPolicyVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_reexecution_policy(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("re-execution policy file must contain an object")
    result = verify_reexecution_policy(value)
    if not result.ok:
        raise ValueError("invalid re-execution policy: " + "; ".join(result.errors))
    return value


def verify_reexecution_policy(policy: dict[str, Any]) -> ReexecutionPolicyVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if policy.get("schema") != REEXECUTION_POLICY_SCHEMA:
        errors.append(f"schema must be {REEXECUTION_POLICY_SCHEMA}")
    for field in ("id", "version", "risk_class", "minimums", "execution", "pins", "sandbox"):
        if field not in policy:
            errors.append(f"missing required field: {field}")

    minimums = policy.get("minimums", {})
    if not isinstance(minimums, dict):
        errors.append("minimums must be an object")
        minimums = {}
    _require_positive_int(minimums, "run_count", errors)
    _require_positive_int(minimums, "records_per_run", errors)
    pass_rate = minimums.get("required_pass_rate")
    if not isinstance(pass_rate, (int, float)) or pass_rate < 0 or pass_rate > 1:
        errors.append("minimums.required_pass_rate must be between 0 and 1")

    execution = policy.get("execution", {})
    if not isinstance(execution, dict):
        errors.append("execution must be an object")
        execution = {}
    allowed_methods = execution.get("allowed_methods")
    if not isinstance(allowed_methods, list) or not allowed_methods or not all(isinstance(item, str) for item in allowed_methods):
        errors.append("execution.allowed_methods must be a non-empty string list")
    allowed_runners = execution.get("allowed_runners")
    if allowed_runners is not None and (
        not isinstance(allowed_runners, list) or not all(isinstance(item, str) for item in allowed_runners)
    ):
        errors.append("execution.allowed_runners must be a string list when present")
    max_temperature = execution.get("max_temperature")
    if max_temperature is not None and not isinstance(max_temperature, (int, float)):
        errors.append("execution.max_temperature must be numeric when present")
    if "require_seed" in execution and not isinstance(execution.get("require_seed"), bool):
        errors.append("execution.require_seed must be boolean when present")

    pins = policy.get("pins", {})
    if not isinstance(pins, dict):
        errors.append("pins must be an object")
    else:
        for field in ("model", "prompt_hash", "tool_manifest_hash", "runtime"):
            if not pins.get(field):
                errors.append(f"pins.{field} is required")

    sandbox = policy.get("sandbox", {})
    if not isinstance(sandbox, dict):
        errors.append("sandbox must be an object")
        sandbox = {}
    if sandbox.get("required") is not True:
        errors.append("sandbox.required must be true")
    for field in ("runner_image", "runner_image_digest", "network"):
        if not sandbox.get(field):
            errors.append(f"sandbox.{field} is required")
    if "read_only_rootfs" in sandbox and not isinstance(sandbox.get("read_only_rootfs"), bool):
        errors.append("sandbox.read_only_rootfs must be boolean when present")

    return ReexecutionPolicyVerification(ok=not errors, errors=errors, warnings=warnings)


def evaluate_reexecution_policy(
    contract: dict[str, Any],
    runs: list[dict[str, Any]],
    policy: dict[str, Any],
    *,
    method: str,
    seed_policy: str,
    temperature: float | None,
    required_pass_rate: float,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    policy_result = verify_reexecution_policy(policy)
    for error in policy_result.errors:
        _add_check(checks, f"policy.{len(checks) + 1}", False, None, None, error)
    errors.extend(policy_result.errors)

    contract_errors = validate_contract(contract)
    errors.extend(f"contract invalid: {error}" for error in contract_errors)

    risk_class = contract.get("agent", {}).get("risk_class")
    _add_check(
        checks,
        "risk_class",
        risk_class == policy.get("risk_class"),
        policy.get("risk_class"),
        risk_class,
        None if risk_class == policy.get("risk_class") else "contract risk class does not match policy",
    )

    minimums = policy.get("minimums", {}) if isinstance(policy.get("minimums"), dict) else {}
    min_runs = _minimum_int(minimums, "run_count")
    min_records = _minimum_int(minimums, "records_per_run")
    min_pass_rate = _minimum_float(minimums, "required_pass_rate")
    _add_check(
        checks,
        "minimums.run_count",
        len(runs) >= min_runs,
        min_runs,
        len(runs),
        None if len(runs) >= min_runs else "not enough re-execution runs for risk class",
    )
    _add_check(
        checks,
        "minimums.required_pass_rate",
        required_pass_rate >= min_pass_rate,
        min_pass_rate,
        required_pass_rate,
        None if required_pass_rate >= min_pass_rate else "report pass-rate requirement is below policy minimum",
    )

    execution = policy.get("execution", {}) if isinstance(policy.get("execution"), dict) else {}
    allowed_methods = execution.get("allowed_methods", [])
    _add_check(
        checks,
        "execution.method",
        isinstance(allowed_methods, list) and method in allowed_methods,
        allowed_methods,
        method,
        None if isinstance(allowed_methods, list) and method in allowed_methods else "execution method is not allowed",
    )
    expected_seed_policy = execution.get("seed_policy")
    if expected_seed_policy is not None:
        _add_check(
            checks,
            "execution.seed_policy",
            seed_policy == expected_seed_policy,
            expected_seed_policy,
            seed_policy,
            None if seed_policy == expected_seed_policy else "seed policy does not match",
        )
    max_temperature = execution.get("max_temperature")
    if isinstance(max_temperature, (int, float)) and temperature is not None:
        _add_check(
            checks,
            "execution.temperature",
            temperature <= max_temperature,
            max_temperature,
            temperature,
            None if temperature <= max_temperature else "report temperature exceeds policy maximum",
        )

    pins = policy.get("pins", {}) if isinstance(policy.get("pins"), dict) else {}
    freeze = contract.get("freeze", {}) if isinstance(contract.get("freeze"), dict) else {}
    for field in ("model", "prompt_hash", "tool_manifest_hash"):
        expected = pins.get(field)
        actual = freeze.get(field)
        _add_check(
            checks,
            f"contract.freeze.{field}",
            expected == actual,
            expected,
            actual,
            None if expected == actual else "contract freeze pin does not match policy",
        )

    for index, run in enumerate(runs):
        label = run.get("run_id") or f"run-{index + 1}"
        dataset = run.get("dataset", {}) if isinstance(run.get("dataset"), dict) else {}
        records = dataset.get("records", [])
        record_count = len(records) if isinstance(records, list) else 0
        _add_check(
            checks,
            f"runs[{index}].records_per_run",
            record_count >= min_records,
            min_records,
            record_count,
            None if record_count >= min_records else f"{label} has too few holdout records",
        )

        environment = run.get("environment", {}) if isinstance(run.get("environment"), dict) else {}
        for field in _ordered_pin_fields(pins):
            expected = pins.get(field)
            actual = environment.get(field)
            _add_check(
                checks,
                f"runs[{index}].environment.{field}",
                actual == expected,
                expected,
                actual,
                None if actual == expected else f"{label} environment pin mismatch",
            )

        allowed_runners = execution.get("allowed_runners")
        if isinstance(allowed_runners, list) and allowed_runners:
            runner = environment.get("runner")
            _add_check(
                checks,
                f"runs[{index}].environment.runner",
                runner in allowed_runners,
                allowed_runners,
                runner,
                None if runner in allowed_runners else f"{label} runner is not allowed",
            )

        if execution.get("require_seed"):
            _add_check(
                checks,
                f"runs[{index}].environment.seed",
                environment.get("seed") is not None,
                "present",
                environment.get("seed"),
                None if environment.get("seed") is not None else f"{label} seed is missing",
            )

        run_temperature = environment.get("temperature")
        if isinstance(max_temperature, (int, float)):
            passed = isinstance(run_temperature, (int, float)) and run_temperature <= max_temperature
            _add_check(
                checks,
                f"runs[{index}].environment.temperature",
                passed,
                max_temperature,
                run_temperature,
                None if passed else f"{label} temperature exceeds policy maximum or is missing",
            )

        sandbox = policy.get("sandbox", {}) if isinstance(policy.get("sandbox"), dict) else {}
        run_sandbox = environment.get("sandbox")
        if sandbox.get("required"):
            if not isinstance(run_sandbox, dict):
                _add_check(checks, f"runs[{index}].environment.sandbox", False, "present", run_sandbox, f"{label} sandbox evidence is missing")
            else:
                for field in ("runner_image", "runner_image_digest", "network", "read_only_rootfs"):
                    if field not in sandbox:
                        continue
                    actual = run_sandbox.get(field)
                    expected = sandbox.get(field)
                    _add_check(
                        checks,
                        f"runs[{index}].environment.sandbox.{field}",
                        actual == expected,
                        expected,
                        actual,
                        None if actual == expected else f"{label} sandbox {field} mismatch",
                    )

    for check in checks:
        if not check["passed"] and check.get("reason"):
            errors.append(f"{check['name']}: {check['reason']}")

    return {
        "policy_id": policy.get("id"),
        "policy_hash": content_hash(policy),
        "schema": policy.get("schema"),
        "risk_class": policy.get("risk_class"),
        "passed": not errors,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
    }


def _minimum_int(parent: dict[str, Any], field: str) -> int:
    value = parent.get(field)
    return value if isinstance(value, int) and value >= 0 else 0


def _minimum_float(parent: dict[str, Any], field: str) -> float:
    value = parent.get(field)
    return float(value) if isinstance(value, (int, float)) else 0.0


def _ordered_pin_fields(pins: dict[str, Any]) -> list[str]:
    preferred = ["model", "prompt_hash", "tool_manifest_hash", "runtime"]
    extras = sorted(field for field in pins if field not in preferred)
    return [field for field in preferred if field in pins] + extras


def _require_positive_int(parent: dict[str, Any], field: str, errors: list[str]) -> None:
    value = parent.get(field)
    if not isinstance(value, int) or value < 1:
        errors.append(f"minimums.{field} must be a positive integer")


def _add_check(
    checks: list[dict[str, Any]],
    name: str,
    passed: bool,
    expected: Any,
    actual: Any,
    reason: str | None,
) -> None:
    checks.append(
        {
            "name": name,
            "passed": bool(passed),
            "expected": expected,
            "actual": actual,
            "reason": reason,
        }
    )
