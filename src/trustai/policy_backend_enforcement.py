from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .policy import POLICY_DECISION_ENTRY_TYPE, validate_policy_pack
from .policy_engine import verify_policy_engine_receipt
from .policy_export import POLICY_EXPORT_SCHEMA

POLICY_BACKEND_ENFORCEMENT_SCHEMA = "trustai.policy-backend-enforcement/0.1"
POLICY_BACKEND_ENFORCEMENT_ENTRY_TYPE = "policy_backend.enforcement_recorded"

POLICY_BACKEND_ENGINES = {"opa", "cedar"}
POLICY_BACKEND_MODES = {"recorded-backend-response", "hosted-backend", "production-design"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class PolicyBackendEnforcementVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_policy_backend_enforcement_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("policy backend enforcement receipt must contain an object")
    return value


def write_policy_backend_enforcement_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_policy_backend_enforcement_receipt(
    policy_pack: dict[str, Any],
    action: dict[str, Any],
    proof_pack: dict[str, Any],
    decision: dict[str, Any],
    *,
    policy_export: dict[str, Any],
    backend_ref: str,
    engine: str,
    endpoint_url: str,
    credential_ref: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    actor_ref: str,
    policy_engine_receipt: dict[str, Any] | None = None,
    bundle_ref: str | None = None,
    bundle_hash: str | None = None,
    response_outcome: str | None = None,
    response_allowed: bool | None = None,
    latency_ms: int | None = None,
    evidence_refs: list[str] | None = None,
    mode: str = "recorded-backend-response",
    environment: str = "local",
    enforced_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    validate_policy_pack(policy_pack)
    _validate_build_inputs(
        backend_ref=backend_ref,
        engine=engine,
        mode=mode,
        endpoint_url=endpoint_url,
        credential_ref=credential_ref,
        request_hash=request_hash,
        response_status=response_status,
        response_hash=response_hash,
        actor_ref=actor_ref,
        latency_ms=latency_ms,
    )
    timestamp = enforced_at or utc_now()
    parse_rfc3339(timestamp)
    decision_ref = _decision_ref(decision)
    decision_payload = decision_ref["payload"]
    response_outcome = response_outcome or str(decision_payload.get("outcome") or "")
    response_allowed = bool(decision_payload.get("passed")) if response_allowed is None else response_allowed
    proof_contract_hash = proof_pack.get("contract", {}).get("hash")

    body: dict[str, Any] = {
        "schema": POLICY_BACKEND_ENFORCEMENT_SCHEMA,
        "mode": mode,
        "environment": environment,
        "enforced_at": timestamp,
        "backend": {
            "backend_ref": backend_ref,
            "engine": engine,
            "endpoint_url": endpoint_url,
            "bundle_ref": bundle_ref or _default_bundle_ref(policy_export, engine),
            "bundle_hash": bundle_hash or content_hash(policy_export.get("targets", {}).get(_target_name(engine), {})),
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
            "success": 200 <= response_status < 300,
            "actor_ref": actor_ref,
            "latency_ms": latency_ms,
        },
        "credential": _redacted_ref(credential_ref),
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
        "backend_decision": {
            "outcome": response_outcome,
            "allowed": response_allowed,
            "matches_policy_decision": response_outcome == decision_payload.get("outcome")
            and response_allowed == decision_payload.get("passed"),
        },
        "policy_export": _policy_export_record(policy_export, engine),
        "source_artifacts": _source_records(
            policy_pack=policy_pack,
            action=action,
            proof_pack=proof_pack,
            decision=decision,
            policy_export=policy_export,
            policy_engine_receipt=policy_engine_receipt,
        ),
        "evidence_refs": sorted(evidence_refs or []),
        "controls": _controls(
            mode=mode,
            engine=engine,
            endpoint_url=endpoint_url,
            request_hash=request_hash,
            response_status=response_status,
            response_hash=response_hash,
            credential_ref=credential_ref,
            policy_export=policy_export,
            policy_engine_receipt=policy_engine_receipt,
            backend_matches=response_outcome == decision_payload.get("outcome")
            and response_allowed == decision_payload.get("passed"),
        ),
        "limitations": [
            "This receipt binds a recorded OPA/Cedar backend enforcement response to policy, action, proof-pack, policy-export, and policy-decision evidence.",
            "It stores backend request and response hashes plus redacted credential references, not raw secrets or response bodies.",
            "It proves hosted backend identity only to the extent represented by endpoint, credential, bundle, request, response, deployment, and chain evidence supplied with the receipt.",
        ],
    }
    if policy_engine_receipt is not None:
        body["policy_engine_receipt"] = _policy_engine_receipt_record(policy_engine_receipt)
    enforcement_id = content_hash(body)
    return {
        **body,
        "enforcement_id": enforcement_id,
        "signatures": [sign_value({"enforcement_id": enforcement_id, "policy_backend_enforcement": body}, key)],
    }


def verify_policy_backend_enforcement_receipt(
    receipt: dict[str, Any],
    policy_pack: dict[str, Any] | None = None,
    action: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    *,
    policy_export: dict[str, Any] | None = None,
    policy_engine_receipt: dict[str, Any] | None = None,
    key: str | None = None,
) -> PolicyBackendEnforcementVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != POLICY_BACKEND_ENFORCEMENT_SCHEMA:
        errors.append(f"unsupported policy backend enforcement schema: {receipt.get('schema')}")
    body = without_keys(receipt, "enforcement_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("enforcement_id") != expected_id:
        errors.append("enforcement_id does not match canonical policy backend enforcement body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("policy backend enforcement receipt must include at least one signature")
    else:
        signed_value = {"enforcement_id": receipt.get("enforcement_id"), "policy_backend_enforcement": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("policy backend enforcement signature verification failed")

    try:
        parse_rfc3339(str(receipt.get("enforced_at") or ""))
    except ValueError as exc:
        errors.append(f"policy backend enforcement enforced_at invalid: {exc}")

    mode = receipt.get("mode")
    if mode not in POLICY_BACKEND_MODES:
        errors.append("policy backend enforcement mode is unsupported")
    elif mode != "hosted-backend":
        warnings.append(f"policy backend enforcement mode is {mode}; live hosted backend operation is not fully claimed")

    backend = receipt.get("backend", {})
    if not isinstance(backend, dict):
        errors.append("policy backend enforcement backend must be an object")
        backend = {}
    engine = backend.get("engine")
    if engine not in POLICY_BACKEND_ENGINES:
        errors.append(f"policy backend enforcement engine must be one of {sorted(POLICY_BACKEND_ENGINES)}")
    for field in ("backend_ref", "endpoint_url", "bundle_ref", "bundle_hash", "request_hash", "response_hash", "actor_ref"):
        if not backend.get(field):
            errors.append(f"policy backend enforcement backend.{field} is required")
    endpoint_url = str(backend.get("endpoint_url") or "")
    if not _valid_url(endpoint_url):
        errors.append("policy backend enforcement backend.endpoint_url must be an absolute URL")
    elif not _is_https(endpoint_url):
        errors.append("policy backend enforcement backend.endpoint_url must use HTTPS")
    for field in ("bundle_hash", "request_hash", "response_hash"):
        if not _is_hash_ref(str(backend.get(field) or "")):
            errors.append(f"policy backend enforcement backend.{field} must be a sha256 reference")
    response_status = backend.get("response_status")
    if not isinstance(response_status, int) or response_status < 100 or response_status > 599:
        errors.append("policy backend enforcement backend.response_status must be an HTTP status code")
    elif backend.get("success") is not (200 <= response_status < 300):
        errors.append("policy backend enforcement backend.success must match response_status")
    latency = backend.get("latency_ms")
    if latency is not None and (not isinstance(latency, int) or latency < 0):
        errors.append("policy backend enforcement backend.latency_ms must be a non-negative integer")

    _verify_redacted_ref(receipt.get("credential"), "policy backend enforcement credential", errors)

    if policy_pack is not None:
        try:
            validate_policy_pack(policy_pack)
        except ValueError as exc:
            errors.append(f"policy backend enforcement policy pack invalid: {exc}")
        policy_ref = receipt.get("policy", {})
        if policy_ref.get("id") != policy_pack.get("id"):
            errors.append("policy backend enforcement policy id does not match policy pack")
        if policy_ref.get("version") != policy_pack.get("version"):
            errors.append("policy backend enforcement policy version does not match policy pack")
        if policy_ref.get("hash") != content_hash(policy_pack):
            errors.append("policy backend enforcement policy hash does not match policy pack")

    if action is not None and receipt.get("action", {}).get("hash") != content_hash(action):
        errors.append("policy backend enforcement action hash does not match action")

    if proof_pack is not None:
        proof_ref = receipt.get("proof_pack", {})
        if proof_ref.get("content_hash") != content_hash(proof_pack):
            errors.append("policy backend enforcement proof pack hash does not match proof pack")
        if proof_ref.get("pack_id") != proof_pack.get("pack_id"):
            errors.append("policy backend enforcement proof pack id does not match proof pack")
        if proof_ref.get("contract_hash") != proof_pack.get("contract", {}).get("hash"):
            errors.append("policy backend enforcement contract hash does not match proof pack")

    decision_payload: dict[str, Any] = {}
    if decision is not None:
        try:
            expected_decision = _decision_ref(decision)
        except ValueError as exc:
            errors.append(f"policy backend enforcement decision invalid: {exc}")
            expected_decision = {"payload": {}}
        decision_payload = expected_decision["payload"]
        decision_ref = receipt.get("decision", {})
        if decision_ref.get("hash") != content_hash(decision_payload):
            errors.append("policy backend enforcement decision hash does not match policy decision")
        if decision_ref.get("entry_id") != expected_decision.get("entry_id"):
            errors.append("policy backend enforcement decision entry id does not match policy decision")
        if decision_ref.get("entry_hash") != expected_decision.get("entry_hash"):
            errors.append("policy backend enforcement decision entry hash does not match policy decision")
        if decision_ref.get("outcome") != decision_payload.get("outcome"):
            errors.append("policy backend enforcement decision outcome does not match policy decision")
        if decision_ref.get("passed") != decision_payload.get("passed"):
            errors.append("policy backend enforcement decision pass status does not match policy decision")
        _check_decision_consistency(errors, receipt, decision_payload)

    backend_decision = receipt.get("backend_decision", {})
    if not isinstance(backend_decision, dict):
        errors.append("policy backend enforcement backend_decision must be an object")
        backend_decision = {}
    if decision_payload:
        if backend_decision.get("outcome") != decision_payload.get("outcome"):
            errors.append("policy backend enforcement backend outcome does not match policy decision")
        if backend_decision.get("allowed") != decision_payload.get("passed"):
            errors.append("policy backend enforcement backend allowed flag does not match policy decision")
        if backend_decision.get("matches_policy_decision") is not True:
            errors.append("policy backend enforcement backend decision match flag must be true")

    export_ref = receipt.get("policy_export")
    if not isinstance(export_ref, dict):
        errors.append("policy backend enforcement policy_export is required")
    else:
        if policy_export is None:
            warnings.append("policy backend enforcement policy export source not supplied; export hash was not replayed")
        else:
            export_errors = _policy_export_errors(policy_export)
            errors.extend(f"policy backend enforcement policy export invalid: {error}" for error in export_errors)
            if not export_errors:
                expected = _policy_export_record(policy_export, str(engine or ""))
                if export_ref != expected:
                    errors.append("policy backend enforcement policy_export record does not match supplied policy export")

    source_artifacts = receipt.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("policy backend enforcement source_artifacts must contain at least one source")
    supplied_sources = _source_records(
        policy_pack=policy_pack,
        action=action,
        proof_pack=proof_pack,
        decision=decision,
        policy_export=policy_export,
        policy_engine_receipt=policy_engine_receipt,
    )
    if supplied_sources:
        if source_artifacts != supplied_sources:
            errors.append("policy backend enforcement source_artifacts do not match supplied source artifacts")
    else:
        warnings.append("policy backend enforcement source artifacts were not supplied; source hashes were not replayed")

    receipt_engine_ref = receipt.get("policy_engine_receipt")
    if receipt_engine_ref:
        if policy_engine_receipt is None:
            warnings.append("policy backend enforcement policy engine receipt source not supplied; engine receipt hash was not replayed")
        else:
            engine_result = verify_policy_engine_receipt(
                policy_engine_receipt,
                policy_pack,
                action,
                proof_pack,
                decision,
                policy_export=policy_export,
                key=key,
            )
            if not engine_result.ok:
                errors.extend(f"policy backend enforcement engine receipt invalid: {error}" for error in engine_result.errors)
            warnings.extend(f"policy backend enforcement engine receipt warning: {warning}" for warning in engine_result.warnings)
            expected = _policy_engine_receipt_record(policy_engine_receipt)
            if receipt_engine_ref != expected:
                errors.append("policy backend enforcement policy_engine_receipt record does not match supplied receipt")
            engine_name = policy_engine_receipt.get("engine", {}).get("name")
            if engine_name != engine:
                errors.append("policy backend enforcement backend engine does not match policy engine receipt")

    controls = receipt.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("policy backend enforcement controls are required")
    _check_no_secret_values(receipt, errors)

    return PolicyBackendEnforcementVerification(ok=not errors, errors=errors, warnings=warnings)


def append_policy_backend_enforcement_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    policy_pack: dict[str, Any] | None = None,
    action: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    *,
    policy_export: dict[str, Any] | None = None,
    policy_engine_receipt: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_policy_backend_enforcement_receipt(
        receipt,
        policy_pack,
        action,
        proof_pack,
        decision,
        policy_export=policy_export,
        policy_engine_receipt=policy_engine_receipt,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid policy backend enforcement receipt: " + "; ".join(result.errors))
    payload = {
        "enforcement_id": receipt["enforcement_id"],
        "enforcement_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "enforced_at": receipt.get("enforced_at"),
        "backend": receipt.get("backend"),
        "credential": receipt.get("credential"),
        "policy": receipt.get("policy"),
        "action": receipt.get("action"),
        "proof_pack": receipt.get("proof_pack"),
        "decision": receipt.get("decision"),
        "backend_decision": receipt.get("backend_decision"),
        "policy_export": receipt.get("policy_export"),
        "policy_engine_receipt": receipt.get("policy_engine_receipt"),
        "source_artifacts": receipt.get("source_artifacts"),
        "evidence_refs": receipt.get("evidence_refs"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(POLICY_BACKEND_ENFORCEMENT_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("enforced_at"))


def _validate_build_inputs(
    *,
    backend_ref: str,
    engine: str,
    mode: str,
    endpoint_url: str,
    credential_ref: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    actor_ref: str,
    latency_ms: int | None,
) -> None:
    if engine not in POLICY_BACKEND_ENGINES:
        raise ValueError(f"engine must be one of {sorted(POLICY_BACKEND_ENGINES)}")
    if mode not in POLICY_BACKEND_MODES:
        raise ValueError(f"mode must be one of {sorted(POLICY_BACKEND_MODES)}")
    for value, field in (
        (backend_ref, "backend_ref"),
        (endpoint_url, "endpoint_url"),
        (credential_ref, "credential_ref"),
        (request_hash, "request_hash"),
        (response_hash, "response_hash"),
        (actor_ref, "actor_ref"),
    ):
        _require_text(value, field)
    if not isinstance(response_status, int):
        raise ValueError("response_status must be an integer")
    if latency_ms is not None and (not isinstance(latency_ms, int) or latency_ms < 0):
        raise ValueError("latency_ms must be a non-negative integer")


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


def _policy_export_record(policy_export: dict[str, Any], engine: str) -> dict[str, Any]:
    errors = _policy_export_errors(policy_export)
    if errors:
        raise ValueError("invalid policy export: " + "; ".join(errors))
    target_name = _target_name(engine)
    if target_name not in policy_export.get("targets", {}):
        raise ValueError(f"{engine} backend enforcement requires policy export target {target_name}")
    return {
        "schema": policy_export.get("schema"),
        "policy_pack_id": policy_export.get("policy_pack_id"),
        "policy_pack_version": policy_export.get("policy_pack_version"),
        "policy_pack_hash": policy_export.get("policy_pack_hash"),
        "export_hash": content_hash(policy_export),
        "target": target_name,
        "target_hash": content_hash(policy_export.get("targets", {}).get(target_name, {})),
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


def _policy_engine_receipt_record(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": receipt.get("receipt_id"),
        "receipt_hash": content_hash(receipt),
        "engine": receipt.get("engine", {}).get("name") if isinstance(receipt.get("engine"), dict) else None,
        "mode": receipt.get("engine", {}).get("mode") if isinstance(receipt.get("engine"), dict) else None,
        "decision_hash": receipt.get("decision", {}).get("hash") if isinstance(receipt.get("decision"), dict) else None,
    }


def _source_records(
    *,
    policy_pack: dict[str, Any] | None,
    action: dict[str, Any] | None,
    proof_pack: dict[str, Any] | None,
    decision: dict[str, Any] | None,
    policy_export: dict[str, Any] | None,
    policy_engine_receipt: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if policy_pack is not None:
        records.append(
            {
                "source_type": "policy_pack",
                "source_id": policy_pack.get("id"),
                "source_hash": content_hash(policy_pack),
            }
        )
    if action is not None:
        records.append(
            {
                "source_type": "runtime_action",
                "source_id": action.get("id"),
                "source_hash": content_hash(action),
            }
        )
    if proof_pack is not None:
        records.append(
            {
                "source_type": "proof_pack",
                "source_id": proof_pack.get("pack_id"),
                "source_hash": content_hash(proof_pack),
            }
        )
    if decision is not None:
        decision_ref = _decision_ref(decision)
        records.append(
            {
                "source_type": "policy_decision",
                "source_id": decision_ref.get("entry_id"),
                "source_hash": content_hash(decision_ref["payload"]),
                "entry_hash": decision_ref.get("entry_hash"),
            }
        )
    if policy_export is not None:
        records.append(
            {
                "source_type": "policy_export",
                "source_id": policy_export.get("policy_pack_id"),
                "source_hash": content_hash(policy_export),
            }
        )
    if policy_engine_receipt is not None:
        records.append(
            {
                "source_type": "policy_engine_receipt",
                "source_id": policy_engine_receipt.get("receipt_id"),
                "source_hash": content_hash(policy_engine_receipt),
            }
        )
    return records


def _controls(
    *,
    mode: str,
    engine: str,
    endpoint_url: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    credential_ref: str,
    policy_export: dict[str, Any],
    policy_engine_receipt: dict[str, Any] | None,
    backend_matches: bool,
) -> list[dict[str, Any]]:
    target_name = _target_name(engine)
    return [
        {
            "id": "hosted-policy-backend-identity",
            "status": "implemented" if mode == "hosted-backend" and _is_https(endpoint_url) else "planned-production",
            "description": "Backend endpoint identity is bound by HTTPS URL and backend reference.",
        },
        {
            "id": "opa-cedar-policy-export-binding",
            "status": "implemented" if target_name in policy_export.get("targets", {}) else "planned-production",
            "description": "Backend enforcement is bound to an exported OPA/Rego or Cedar policy target.",
        },
        {
            "id": "backend-request-response-hashes",
            "status": "implemented"
            if _is_hash_ref(request_hash) and _is_hash_ref(response_hash) and 100 <= response_status <= 599
            else "planned-production",
            "description": "Backend request hash, response status, and response hash are recorded.",
        },
        {
            "id": "redacted-backend-credential",
            "status": "implemented" if credential_ref else "planned-production",
            "description": "Backend credentials are represented only by a redacted reference.",
        },
        {
            "id": "policy-decision-consistency",
            "status": "implemented" if backend_matches else "planned-production",
            "description": "Backend outcome metadata matches the recorded TrustAI policy decision.",
        },
        {
            "id": "policy-engine-receipt-binding",
            "status": "implemented" if policy_engine_receipt is not None else "planned-production",
            "description": "Hosted backend enforcement is chained to a signed policy engine decision receipt when supplied.",
        },
    ]


def _check_decision_consistency(errors: list[str], receipt: dict[str, Any], decision_payload: dict[str, Any]) -> None:
    policy_ref = receipt.get("policy", {})
    if policy_ref.get("id") != decision_payload.get("policy_pack_id"):
        errors.append("policy backend enforcement policy id does not match decision")
    if policy_ref.get("version") != decision_payload.get("policy_pack_version"):
        errors.append("policy backend enforcement policy version does not match decision")
    if policy_ref.get("hash") != decision_payload.get("policy_pack_hash"):
        errors.append("policy backend enforcement policy hash does not match decision")
    if receipt.get("action", {}).get("hash") != decision_payload.get("action_hash"):
        errors.append("policy backend enforcement action hash does not match decision")
    contract_hash = receipt.get("proof_pack", {}).get("contract_hash")
    if contract_hash and contract_hash != decision_payload.get("contract_hash"):
        errors.append("policy backend enforcement proof contract hash does not match decision")


def _default_bundle_ref(policy_export: dict[str, Any], engine: str) -> str:
    return f"policy-export:{policy_export.get('policy_pack_id')}:{_target_name(engine)}"


def _target_name(engine: str) -> str:
    if engine == "opa":
        return "opa_rego"
    if engine == "cedar":
        return "cedar"
    return engine


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def _is_https(value: str | None) -> bool:
    return bool(value and urlparse(value).scheme.lower() == "https")


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value.removeprefix("sha256:"))
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _require_text(value: str | None, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _check_no_secret_values(value: Any, errors: list[str], *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, item):
                    pass
                elif not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"policy backend enforcement secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        return True
    return False
