from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain
from .reexecution import load_eval_results
from .reexecution_policy import verify_reexecution_policy

REEXECUTION_RUNNER_PLAN_SCHEMA = "trustai.reexecution-runner-plan/0.1"
REEXECUTION_RUNNER_EVIDENCE_SCHEMA = "trustai.reexecution-runner-evidence/0.1"
REEXECUTION_RUNNER_ENTRY_TYPE = "reexecution.runner.completed"


@dataclass
class ReexecutionRunnerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    run_count: int = 0


def load_reexecution_runner_plan(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("re-execution runner plan must contain an object")
    result = verify_reexecution_runner_plan(value)
    if not result.ok:
        raise ValueError("invalid re-execution runner plan: " + "; ".join(result.errors))
    return value


def load_reexecution_runner_evidence(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("re-execution runner evidence must contain an object")
    return value


def verify_reexecution_runner_plan(plan: dict[str, Any]) -> ReexecutionRunnerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if plan.get("schema") != REEXECUTION_RUNNER_PLAN_SCHEMA:
        errors.append(f"schema must be {REEXECUTION_RUNNER_PLAN_SCHEMA}")
    for field in ("id", "version", "command", "runs", "policy"):
        if field not in plan:
            errors.append(f"missing required field: {field}")

    contract = plan.get("contract")
    if contract is not None:
        if not isinstance(contract, dict):
            errors.append("contract must be an object when present")
        elif not contract.get("id") or not contract.get("hash"):
            errors.append("contract.id and contract.hash are required when contract is present")

    command = plan.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        errors.append("command must be a non-empty string list")
    if plan.get("shell") is True:
        errors.append("shell execution is not supported")

    timeout_seconds = plan.get("timeout_seconds", 30)
    if not isinstance(timeout_seconds, int) or timeout_seconds < 1:
        errors.append("timeout_seconds must be a positive integer")

    runs = plan.get("runs", [])
    if not isinstance(runs, list) or not runs:
        errors.append("runs must be a non-empty list")
        runs = []
    seen_outputs: set[str] = set()
    for index, run in enumerate(runs):
        if not isinstance(run, dict):
            errors.append(f"runs[{index}] must be an object")
            continue
        if not run.get("run_id"):
            errors.append(f"runs[{index}].run_id is required")
        if run.get("seed") is None:
            errors.append(f"runs[{index}].seed is required")
        output = run.get("output")
        if not isinstance(output, str) or not output:
            errors.append(f"runs[{index}].output is required")
        elif output in seen_outputs:
            errors.append(f"runs[{index}].output duplicates another run: {output}")
        else:
            seen_outputs.add(output)

    policy = plan.get("policy", {})
    if not isinstance(policy, dict):
        errors.append("policy must be an object")
    else:
        policy_result = verify_reexecution_policy(policy)
        errors.extend(f"policy invalid: {error}" for error in policy_result.errors)

    return ReexecutionRunnerVerification(ok=not errors, errors=errors, warnings=warnings, run_count=len(runs))


def run_reexecution_plan(
    plan: dict[str, Any],
    *,
    base_dir: str | Path = ".",
    generated_at: str | None = None,
) -> dict[str, Any]:
    result = verify_reexecution_runner_plan(plan)
    if not result.ok:
        raise ValueError("invalid re-execution runner plan: " + "; ".join(result.errors))

    base = Path(base_dir).resolve()
    plan_body = {
        "schema": REEXECUTION_RUNNER_PLAN_SCHEMA,
        "id": plan.get("id"),
        "version": plan.get("version"),
        "description": plan.get("description"),
        "command": plan["command"],
        "timeout_seconds": plan.get("timeout_seconds", 30),
        "contract": plan.get("contract"),
        "policy": plan["policy"],
        "runs": plan["runs"],
        "limitations": [
            "Local runner executes commands with shell disabled and records declared sandbox evidence.",
            "OS-level network and filesystem isolation require the production runner service.",
        ],
    }
    run_records = [
        _execute_run(base, plan_body, run, index)
        for index, run in enumerate(plan_body["runs"])
    ]
    body = {
        "schema": REEXECUTION_RUNNER_EVIDENCE_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "plan": {
            "id": plan_body["id"],
            "version": plan_body["version"],
            "hash": content_hash(plan_body),
            "body": plan_body,
        },
        "run_count": len(run_records),
        "runs": run_records,
        "outcome": "passed" if all(run["exit_code"] == 0 and run["output_valid"] for run in run_records) else "failed",
        "limitations": plan_body["limitations"],
    }
    return {**body, "evidence_id": content_hash(body)}


def verify_reexecution_runner_evidence(evidence: dict[str, Any]) -> ReexecutionRunnerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if evidence.get("schema") != REEXECUTION_RUNNER_EVIDENCE_SCHEMA:
        errors.append(f"schema must be {REEXECUTION_RUNNER_EVIDENCE_SCHEMA}")
    body = without_keys(evidence, "evidence_id")
    if evidence.get("evidence_id") != content_hash(body):
        errors.append("evidence_id does not match canonical evidence body")

    plan = evidence.get("plan", {}).get("body")
    if not isinstance(plan, dict):
        errors.append("plan.body is required")
        plan = {}
    else:
        plan_result = verify_reexecution_runner_plan(plan)
        errors.extend(f"plan invalid: {error}" for error in plan_result.errors)
        if evidence.get("plan", {}).get("hash") != content_hash(plan):
            errors.append("plan hash mismatch")

    runs = evidence.get("runs", [])
    if not isinstance(runs, list) or not runs:
        errors.append("runs must be a non-empty list")
        runs = []
    expected_runs = plan.get("runs", []) if isinstance(plan.get("runs"), list) else []
    if len(runs) != len(expected_runs):
        errors.append("run count does not match plan")

    for index, run in enumerate(runs):
        if not isinstance(run, dict):
            errors.append(f"runs[{index}] must be an object")
            continue
        if run.get("run_hash") != content_hash(without_keys(run, "run_hash")):
            errors.append(f"runs[{index}] run_hash mismatch")
        if run.get("exit_code") != 0:
            errors.append(f"runs[{index}] command failed with exit code {run.get('exit_code')}")
        if not run.get("output_valid"):
            errors.append(f"runs[{index}] output is not valid eval results JSON")
        output = run.get("output", {})
        if isinstance(output, dict):
            results = output.get("results")
            if not isinstance(results, dict):
                errors.append(f"runs[{index}] output.results is required")
            elif output.get("results_hash") != content_hash(results):
                errors.append(f"runs[{index}] output results_hash mismatch")
            output_path = output.get("path")
            if output_path and Path(output_path).exists():
                current = load_eval_results(output_path)
                if content_hash(current) != output.get("results_hash"):
                    errors.append(f"runs[{index}] output file hash mismatch")
        else:
            errors.append(f"runs[{index}] output must be an object")

    if evidence.get("outcome") != ("passed" if not errors else "failed"):
        if errors:
            warnings.append("evidence outcome is passed but verifier found errors")

    return ReexecutionRunnerVerification(ok=not errors, errors=errors, warnings=warnings, run_count=len(runs))


def runner_results(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    result = verify_reexecution_runner_evidence(evidence)
    if not result.ok:
        raise ValueError("invalid re-execution runner evidence: " + "; ".join(result.errors))
    return [run["output"]["results"] for run in evidence.get("runs", [])]


def append_reexecution_runner_evidence(
    chain: EvidenceChain,
    evidence: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_reexecution_runner_evidence(evidence)
    if not result.ok:
        raise ValueError("invalid re-execution runner evidence: " + "; ".join(result.errors))
    payload = {
        "evidence_id": evidence["evidence_id"],
        "evidence_hash": content_hash(evidence),
        "plan_id": evidence["plan"]["id"],
        "plan_hash": evidence["plan"]["hash"],
        "contract_id": evidence["plan"].get("body", {}).get("contract", {}).get("id"),
        "contract_hash": evidence["plan"].get("body", {}).get("contract", {}).get("hash"),
        "run_count": evidence["run_count"],
        "outcome": evidence["outcome"],
        "runs": [
            {
                "run_id": run["run_id"],
                "seed": run["seed"],
                "output_path": run["output"]["path"],
                "results_hash": run["output"]["results_hash"],
            }
            for run in evidence["runs"]
        ],
        "evidence": evidence,
    }
    return chain.append(REEXECUTION_RUNNER_ENTRY_TYPE, payload, key=key, timestamp=evidence["generated_at"])


def write_reexecution_runner_evidence(path: str | Path, evidence: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")


def _execute_run(base: Path, plan: dict[str, Any], run: dict[str, Any], index: int) -> dict[str, Any]:
    output_path = _resolve_under_base(base, run["output"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()

    env = os.environ.copy()
    env.update(
        {
            "TRUSTAI_RUN_INDEX": str(index),
            "TRUSTAI_RUN_ID": str(run["run_id"]),
            "TRUSTAI_SEED": str(run["seed"]),
            "TRUSTAI_OUTPUT": str(output_path),
            "TRUSTAI_POLICY": json.dumps(plan["policy"], sort_keys=True),
        }
    )
    command = [sys.executable if item == "{python}" else item for item in plan["command"]]
    completed = subprocess.run(
        command,
        cwd=base,
        env=env,
        shell=False,
        capture_output=True,
        text=True,
        timeout=plan.get("timeout_seconds", 30),
        check=False,
    )
    output_valid = False
    results: dict[str, Any] | None = None
    output_error = None
    try:
        results = load_eval_results(output_path)
        output_valid = True
    except Exception as exc:  # noqa: BLE001 - verifier records the parse failure.
        output_error = str(exc)

    body = {
        "index": index,
        "run_id": run["run_id"],
        "seed": run["seed"],
        "command": command,
        "exit_code": completed.returncode,
        "stdout_hash": content_hash({"stdout": completed.stdout}),
        "stderr_hash": content_hash({"stderr": completed.stderr}),
        "output_valid": output_valid,
        "output_error": output_error,
        "output": {
            "path": str(output_path),
            "results_hash": content_hash(results) if results is not None else None,
            "results": results,
        },
    }
    return {**body, "run_hash": content_hash(body)}


def _resolve_under_base(base: Path, value: str) -> Path:
    target = Path(value)
    if not target.is_absolute():
        target = base / target
    resolved = target.resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"path escapes runner base directory: {value}") from exc
    return resolved
