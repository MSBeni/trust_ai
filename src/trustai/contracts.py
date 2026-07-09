from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339
from .chain import EvidenceChain

CONTRACT_SPEC_VERSION = "trustai.verification-contract/0.1"
CONTRACT_ENTRY_TYPE = "verification_contract.registered"
SUPPORTED_OPERATORS = {">=", ">", "<=", "<", "==", "!="}


def load_structured_file(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    text = source.read_text(encoding="utf-8")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ValueError(
                f"{source} is not JSON and PyYAML is not installed; use JSON syntax or install PyYAML"
            ) from exc
        value = yaml.safe_load(text)
    if not isinstance(value, dict):
        raise ValueError(f"{source} must contain a mapping/object")
    return value


def contract_hash(contract: dict[str, Any]) -> str:
    return content_hash(contract)


def validate_contract(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if contract.get("spec_version") != CONTRACT_SPEC_VERSION:
        errors.append(f"spec_version must be {CONTRACT_SPEC_VERSION}")
    for field in ("id", "version", "agent", "freeze", "holdout", "metrics"):
        if field not in contract:
            errors.append(f"missing required field: {field}")

    agent = contract.get("agent", {})
    if not isinstance(agent, dict):
        errors.append("agent must be an object")
    else:
        for field in ("name", "version"):
            if not agent.get(field):
                errors.append(f"agent.{field} is required")

    freeze = contract.get("freeze", {})
    if not isinstance(freeze, dict) or not freeze.get("frozen_at"):
        errors.append("freeze.frozen_at is required")
    else:
        try:
            parse_rfc3339(freeze["frozen_at"])
        except ValueError as exc:
            errors.append(f"freeze.frozen_at invalid: {exc}")

    holdout = contract.get("holdout", {})
    if not isinstance(holdout, dict) or not holdout.get("min_timestamp"):
        errors.append("holdout.min_timestamp is required")
    else:
        try:
            parse_rfc3339(holdout["min_timestamp"])
        except ValueError as exc:
            errors.append(f"holdout.min_timestamp invalid: {exc}")

    metrics = contract.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        errors.append("metrics must be a non-empty list")
    else:
        for index, metric in enumerate(metrics):
            if not isinstance(metric, dict):
                errors.append(f"metrics[{index}] must be an object")
                continue
            if not metric.get("name"):
                errors.append(f"metrics[{index}].name is required")
            if metric.get("operator") not in SUPPORTED_OPERATORS:
                errors.append(f"metrics[{index}].operator must be one of {sorted(SUPPORTED_OPERATORS)}")
            if "threshold" not in metric:
                errors.append(f"metrics[{index}].threshold is required")

    approvals = contract.get("required_approvals", [])
    if not isinstance(approvals, list):
        errors.append("required_approvals must be a list when present")
    else:
        for index, approval in enumerate(approvals):
            if not isinstance(approval, dict) or not approval.get("role"):
                errors.append(f"required_approvals[{index}].role is required")

    return errors


def load_contract(path: str | Path) -> dict[str, Any]:
    contract = load_structured_file(path)
    errors = validate_contract(contract)
    if errors:
        raise ValueError("invalid verification contract: " + "; ".join(errors))
    return contract


def register_contract(chain: EvidenceChain, contract: dict[str, Any], key: str | None = None) -> dict[str, Any]:
    digest = contract_hash(contract)
    existing = find_contract_registration(chain, digest)
    if existing:
        return existing
    return chain.append(
        CONTRACT_ENTRY_TYPE,
        {
            "contract_id": contract["id"],
            "contract_version": contract["version"],
            "contract_hash": digest,
            "agent": contract["agent"],
            "contract": contract,
        },
        key=key,
    )


def find_contract_registration(chain: EvidenceChain, digest: str) -> dict[str, Any] | None:
    return chain.find_first(CONTRACT_ENTRY_TYPE, "contract_hash", digest)
