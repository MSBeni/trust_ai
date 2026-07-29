from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .policy import POLICY_DECISION_ENTRY_TYPE, evaluate_policy, validate_policy_pack
from .policy_export import POLICY_EXPORT_SCHEMA

POLICY_ENGINE_RECEIPT_SCHEMA = "trustai.policy-engine-receipt/0.1"
POLICY_ENGINE_ENTRY_TYPE = "policy_engine.evaluated"
SUPPORTED_ENGINES = {"local-json", "opa", "cedar"}
SUPPORTED_MODES = {"local-reference", "recorded-response"}


@dataclass
class PolicyEngineReceiptVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_policy_engine_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("policy engine receipt must contain an object")
    return value


def build_policy_engine_receipt(
    policy_pack: dict[str, Any],
    action: dict[str, Any],
    proof_pack: dict[str, Any],
    decision: dict[str, Any],
    *,
    policy_export: dict[str, Any] | None = None,
    engine: str = "local-json",
    mode: str = "local-reference",
    engine_response: dict[str, Any] | None = None,
    evaluated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    validate_policy_pack(policy_pack)
    _validate_engine(engine, mode, policy_export, engine_response)
    decision_ref = _decision_ref(decision)
    decision_payload = decision_ref["payload"]
    proof_contract_hash = proof_pack.get("contract", {}).get("hash")
    timestamp = evaluated_at or decision_payload.get("evaluated_at") or utc_now()

    body: dict[str, Any] = {
        "schema": POLICY_ENGINE_RECEIPT_SCHEMA,
        "evaluated_at": timestamp,
        "engine": {
            "name": engine,
            "mode": mode,
            "claimed_backend": _claimed_backend(engine),
        },
        "policy": {
            "id": policy_pack.get("id"),
            "version": policy_pack.get("version"),
            "hash": content_hash(policy_pack),
        },
        "action": {
            "hash": content_hash(action),
            "id": action.get("id"),
            "type": action.get("type"),
            "risk_class": action.get("risk_class"),
        },
        "proof_pack": {
            "pack_id": proof_pack.get("pack_id"),
            "content_hash": content_hash(proof_pack),
            "contract_id": proof_pack.get("contract", {}).get("id"),
            "contract_hash": proof_contract_hash,
            "gate_outcome": proof_pack.get("gate_decision", {}).get("outcome"),
        },
        "decision": {
            "hash": content_hash(decision_payload),
            "entry_id": decision_ref.get("entry_id"),
            "entry_hash": decision_ref.get("entry_hash"),
            "outcome": decision_payload.get("outcome"),
            "passed": decision_payload.get("passed"),
            "evaluated_at": decision_payload.get("evaluated_at"),
        },
        "limitations": [
            "This receipt binds a deterministic local policy decision and exported backend artifacts.",
            "Recorded OPA/Cedar responses are evidence of a supplied response body, not proof that TrustAI operated a hosted backend.",
        ],
    }
    if policy_export is not None:
        body["policy_export"] = _policy_export_ref(policy_export)
    if engine_response is not None:
        body["engine_response"] = {
            "hash": content_hash(engine_response),
            "outcome": engine_response.get("outcome") or engine_response.get("decision"),
            "allowed": engine_response.get("allowed"),
            "status": engine_response.get("status"),
        }

    receipt_id = content_hash(body)
    return {
        **body,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "receipt": body}, key)],
    }


def verify_policy_engine_receipt(
    receipt: dict[str, Any],
    policy_pack: dict[str, Any] | None = None,
    action: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    *,
    policy_export: dict[str, Any] | None = None,
    engine_response: dict[str, Any] | None = None,
    key: str | None = None,
) -> PolicyEngineReceiptVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != POLICY_ENGINE_RECEIPT_SCHEMA:
        errors.append(f"unsupported policy engine receipt schema: {receipt.get('schema')}")
    body = without_keys(receipt, "receipt_id", "signatures")
    expected_receipt_id = content_hash(body)
    if receipt.get("receipt_id") != expected_receipt_id:
        errors.append("receipt_id does not match canonical receipt body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("policy engine receipt must include at least one signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "receipt": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("policy engine receipt signature verification failed")

    engine = receipt.get("engine", {})
    if not isinstance(engine, dict):
        errors.append("policy engine receipt engine must be an object")
        engine = {}
    engine_name = engine.get("name")
    mode = engine.get("mode")
    if engine_name not in SUPPORTED_ENGINES:
        errors.append(f"policy engine name must be one of {sorted(SUPPORTED_ENGINES)}")
    if mode not in SUPPORTED_MODES:
        errors.append(f"policy engine mode must be one of {sorted(SUPPORTED_MODES)}")

    if policy_pack is not None:
        try:
            validate_policy_pack(policy_pack)
        except ValueError as exc:
            errors.append(f"policy pack invalid: {exc}")
        policy_ref = receipt.get("policy", {})
        if policy_ref.get("id") != policy_pack.get("id"):
            errors.append("receipt policy id does not match policy pack")
        if policy_ref.get("version") != policy_pack.get("version"):
            errors.append("receipt policy version does not match policy pack")
        if policy_ref.get("hash") != content_hash(policy_pack):
            errors.append("receipt policy hash does not match policy pack")

    if action is not None:
        if receipt.get("action", {}).get("hash") != content_hash(action):
            errors.append("receipt action hash does not match action")

    if proof_pack is not None:
        proof_ref = receipt.get("proof_pack", {})
        if proof_ref.get("content_hash") != content_hash(proof_pack):
            errors.append("receipt proof pack hash does not match proof pack")
        if proof_ref.get("pack_id") != proof_pack.get("pack_id"):
            errors.append("receipt proof pack id does not match proof pack")
        if proof_ref.get("contract_hash") != proof_pack.get("contract", {}).get("hash"):
            errors.append("receipt contract hash does not match proof pack")

    if decision is not None:
        try:
            decision_ref = _decision_ref(decision)
        except ValueError as exc:
            errors.append(f"policy decision invalid: {exc}")
            decision_ref = {"payload": {}}
        decision_payload = decision_ref["payload"]
        receipt_decision = receipt.get("decision", {})
        if receipt_decision.get("hash") != content_hash(decision_payload):
            errors.append("receipt decision hash does not match policy decision")
        if receipt_decision.get("entry_id") != decision_ref.get("entry_id"):
            errors.append("receipt decision entry id does not match policy decision")
        if receipt_decision.get("entry_hash") != decision_ref.get("entry_hash"):
            errors.append("receipt decision entry hash does not match policy decision")
        if receipt_decision.get("outcome") != decision_payload.get("outcome"):
            errors.append("receipt decision outcome does not match policy decision")
        if receipt_decision.get("passed") != decision_payload.get("passed"):
            errors.append("receipt decision pass status does not match policy decision")
        _check_decision_consistency(errors, receipt, decision_payload)
        if policy_pack is not None and action is not None and proof_pack is not None:
            replayed = evaluate_policy(
                policy_pack,
                action,
                proof_pack=proof_pack,
                now=decision_payload.get("evaluated_at") or receipt.get("evaluated_at"),
            )
            if content_hash(replayed) != content_hash(decision_payload):
                errors.append("policy decision does not replay from policy, action, proof pack, and proof decay")

    export_ref = receipt.get("policy_export")
    if export_ref:
        if policy_export is None:
            warnings.append("policy export source not supplied for deep receipt verification")
        else:
            export_errors = _policy_export_errors(policy_export)
            errors.extend(export_errors)
            if not export_errors:
                expected = _policy_export_ref(policy_export)
                for field in ("schema", "policy_pack_id", "policy_pack_version", "policy_pack_hash", "export_hash", "targets"):
                    if export_ref.get(field) != expected.get(field):
                        errors.append(f"receipt policy_export {field} does not match supplied export")
    elif engine_name in {"opa", "cedar"}:
        errors.append("opa and cedar engine receipts must include a policy_export reference")

    if policy_export is not None and engine_name in {"opa", "cedar"}:
        targets = policy_export.get("targets", {}) if isinstance(policy_export, dict) else {}
        target_name = "opa_rego" if engine_name == "opa" else "cedar"
        if target_name not in targets:
            errors.append(f"{engine_name} receipt requires policy export target {target_name}")

    response_ref = receipt.get("engine_response")
    if mode == "recorded-response" and not response_ref:
        errors.append("recorded-response receipts must include engine_response")
    if response_ref:
        if engine_response is None:
            warnings.append("engine response source not supplied for deep receipt verification")
        elif response_ref.get("hash") != content_hash(engine_response):
            errors.append("receipt engine response hash does not match supplied response")

    return PolicyEngineReceiptVerification(ok=not errors, errors=errors, warnings=warnings)


def append_policy_engine_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    policy_pack: dict[str, Any] | None = None,
    action: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    *,
    policy_export: dict[str, Any] | None = None,
    engine_response: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_policy_engine_receipt(
        receipt,
        policy_pack,
        action,
        proof_pack,
        decision,
        policy_export=policy_export,
        engine_response=engine_response,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid policy engine receipt: " + "; ".join(result.errors))
    payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "engine": receipt.get("engine"),
        "policy": receipt.get("policy"),
        "action": receipt.get("action"),
        "proof_pack": receipt.get("proof_pack"),
        "decision": receipt.get("decision"),
        "policy_export": receipt.get("policy_export"),
        "engine_response": receipt.get("engine_response"),
    }
    return chain.append(POLICY_ENGINE_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("evaluated_at"))


def write_policy_engine_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _validate_engine(
    engine: str,
    mode: str,
    policy_export: dict[str, Any] | None,
    engine_response: dict[str, Any] | None,
) -> None:
    if engine not in SUPPORTED_ENGINES:
        raise ValueError(f"engine must be one of {sorted(SUPPORTED_ENGINES)}")
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"mode must be one of {sorted(SUPPORTED_MODES)}")
    if mode == "recorded-response" and engine_response is None:
        raise ValueError("engine_response is required for recorded-response mode")
    if engine in {"opa", "cedar"}:
        if policy_export is None:
            raise ValueError(f"{engine} receipts require a policy_export")
        target_name = "opa_rego" if engine == "opa" else "cedar"
        if target_name not in policy_export.get("targets", {}):
            raise ValueError(f"{engine} receipts require policy export target {target_name}")


def _claimed_backend(engine: str) -> str:
    if engine == "opa":
        return "OPA/Rego policy backend"
    if engine == "cedar":
        return "Cedar policy backend"
    return "TrustAI local JSON evaluator"


def _decision_ref(decision: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(decision, dict):
        raise ValueError("policy decision must be an object")
    if decision.get("entry_type") == POLICY_DECISION_ENTRY_TYPE and isinstance(decision.get("payload"), dict):
        return {
            "payload": decision["payload"],
            "entry_id": decision.get("entry_id"),
            "entry_hash": content_hash(decision),
        }
    if "payload" in decision and decision.get("entry_type") != POLICY_DECISION_ENTRY_TYPE:
        raise ValueError("policy decision entry_type must be policy.decision")
    return {"payload": decision, "entry_id": None, "entry_hash": None}


def _policy_export_ref(policy_export: dict[str, Any]) -> dict[str, Any]:
    errors = _policy_export_errors(policy_export)
    if errors:
        raise ValueError("invalid policy export: " + "; ".join(errors))
    return {
        "schema": policy_export.get("schema"),
        "policy_pack_id": policy_export.get("policy_pack_id"),
        "policy_pack_version": policy_export.get("policy_pack_version"),
        "policy_pack_hash": policy_export.get("policy_pack_hash"),
        "export_hash": content_hash(policy_export),
        "targets": sorted(policy_export.get("targets", {}).keys()),
    }


def _policy_export_errors(policy_export: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(policy_export, dict):
        return ["policy export must be an object"]
    if policy_export.get("schema") != POLICY_EXPORT_SCHEMA:
        errors.append(f"unsupported policy export schema: {policy_export.get('schema')}")
    if not policy_export.get("policy_pack_hash"):
        errors.append("policy export policy_pack_hash is required")
    targets = policy_export.get("targets")
    if not isinstance(targets, dict) or not targets:
        errors.append("policy export targets are required")
    if policy_export.get("payload_hash") != content_hash(without_keys(policy_export, "payload_hash")):
        errors.append("policy export payload_hash does not match export body")
    return errors


def _check_decision_consistency(errors: list[str], receipt: dict[str, Any], decision_payload: dict[str, Any]) -> None:
    policy_ref = receipt.get("policy", {})
    if policy_ref.get("id") != decision_payload.get("policy_pack_id"):
        errors.append("receipt policy id does not match decision")
    if policy_ref.get("version") != decision_payload.get("policy_pack_version"):
        errors.append("receipt policy version does not match decision")
    if policy_ref.get("hash") != decision_payload.get("policy_pack_hash"):
        errors.append("receipt policy hash does not match decision")
    action_hash = receipt.get("action", {}).get("hash")
    if action_hash != decision_payload.get("action_hash"):
        errors.append("receipt action hash does not match decision")
    proof_contract_hash = receipt.get("proof_pack", {}).get("contract_hash")
    if proof_contract_hash and proof_contract_hash != decision_payload.get("contract_hash"):
        errors.append("receipt proof contract hash does not match decision")
