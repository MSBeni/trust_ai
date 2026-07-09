from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .reexecution import verify_reexecution_report
from .reexecution_policy import verify_reexecution_policy
from .reexecution_runner import verify_reexecution_runner_evidence

REEXECUTION_ISOLATION_SCHEMA = "trustai.reexecution-isolation-attestation/0.1"
REEXECUTION_ISOLATION_ENTRY_TYPE = "reexecution.isolation_attested"

REEXECUTION_ISOLATION_MODES = {"local-reference", "container-attested", "production-design"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ReexecutionIsolationVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_reexecution_isolation_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("re-execution isolation attestation must contain an object")
    return value


def write_reexecution_isolation_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_reexecution_isolation_attestation(
    runner_evidence: dict[str, Any],
    *,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    mode: str = "container-attested",
    environment: str = "local",
    isolation_ref: str,
    runner_ref: str,
    runner_provider: str,
    runner_image: str | None = None,
    runner_image_digest: str | None = None,
    orchestrator: str,
    container_runtime: str,
    kernel: str,
    namespace_mode: str,
    cgroup_ref: str,
    seccomp_profile_hash: str,
    apparmor_profile_hash: str | None = None,
    network_mode: str | None = None,
    filesystem_policy_ref: str,
    read_only_rootfs: bool | None = None,
    writable_mounts: list[str] | None = None,
    denied_mounts: list[str] | None = None,
    egress_policy_ref: str,
    seed_policy: str | None = None,
    temperature: float | int | None = None,
    entropy_source_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in REEXECUTION_ISOLATION_MODES:
        raise ValueError(f"mode must be one of {sorted(REEXECUTION_ISOLATION_MODES)}")
    runner_result = verify_reexecution_runner_evidence(runner_evidence)
    if not runner_result.ok:
        raise ValueError("invalid re-execution runner evidence: " + "; ".join(runner_result.errors))

    effective_policy = policy or _runner_policy(runner_evidence)
    policy_result = verify_reexecution_policy(effective_policy)
    if not policy_result.ok:
        raise ValueError("invalid re-execution policy: " + "; ".join(policy_result.errors))
    if content_hash(effective_policy) != content_hash(_runner_policy(runner_evidence)):
        raise ValueError("policy does not match re-execution runner plan policy")

    if report is not None:
        report_result = verify_reexecution_report(report)
        if not report_result.ok:
            raise ValueError("invalid re-execution report: " + "; ".join(report_result.errors))
        report_errors = _report_binding_errors(runner_evidence, effective_policy, report)
        if report_errors:
            raise ValueError("re-execution report does not match runner evidence: " + "; ".join(report_errors))

    timestamp = attested_at or utc_now()
    parse_rfc3339(timestamp)
    retention = parse_rfc3339(retention_until)
    if retention <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after attested_at")

    sandbox = effective_policy.get("sandbox", {}) if isinstance(effective_policy.get("sandbox"), dict) else {}
    execution = effective_policy.get("execution", {}) if isinstance(effective_policy.get("execution"), dict) else {}
    image = runner_image or sandbox.get("runner_image")
    image_digest = runner_image_digest or sandbox.get("runner_image_digest")
    network = network_mode or sandbox.get("network")
    readonly = sandbox.get("read_only_rootfs") if read_only_rootfs is None else read_only_rootfs
    seeds = [run.get("seed") for run in runner_evidence.get("runs", []) if isinstance(run, dict)]
    seed = seed_policy or execution.get("seed_policy")
    temp = execution.get("max_temperature") if temperature is None else temperature

    for field, value in {
        "isolation_ref": isolation_ref,
        "runner_ref": runner_ref,
        "runner_provider": runner_provider,
        "runner_image": image,
        "runner_image_digest": image_digest,
        "orchestrator": orchestrator,
        "container_runtime": container_runtime,
        "kernel": kernel,
        "namespace_mode": namespace_mode,
        "cgroup_ref": cgroup_ref,
        "seccomp_profile_hash": seccomp_profile_hash,
        "network_mode": network,
        "filesystem_policy_ref": filesystem_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "seed_policy": seed,
        "entropy_source_ref": entropy_source_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "retention_until": retention_until,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
    }.items():
        _require_text(value, field)

    source = _source_record(runner_evidence, effective_policy, report)
    isolation = {
        "isolation_ref": isolation_ref,
        "runner_ref": runner_ref,
        "runner_provider": runner_provider,
        "orchestrator": orchestrator,
        "container_runtime": container_runtime,
        "kernel": kernel,
        "namespace_mode": namespace_mode,
        "cgroup_ref": cgroup_ref,
        "seccomp_profile_hash": seccomp_profile_hash,
        "apparmor_profile_hash": apparmor_profile_hash,
        "runner_image": image,
        "runner_image_digest": image_digest,
        "network_mode": network,
        "filesystem_policy_ref": filesystem_policy_ref,
        "read_only_rootfs": readonly,
        "writable_mounts": sorted(writable_mounts or []),
        "denied_mounts": sorted(denied_mounts or []),
        "egress_policy_ref": egress_policy_ref,
    }
    execution_controls = {
        "seed_policy": seed,
        "require_seed": execution.get("require_seed") is True,
        "seeds": seeds,
        "temperature": temp,
        "max_temperature": execution.get("max_temperature"),
        "entropy_source_ref": entropy_source_ref,
    }
    audit = {
        "audit_log_ref": audit_log_ref,
        "root": audit_log_root,
        "retention_until": retention_until,
    }
    operation = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    source_artifacts = _source_artifacts(runner_evidence=runner_evidence, policy=effective_policy, report=report)
    body: dict[str, Any] = {
        "schema": REEXECUTION_ISOLATION_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": source,
        "isolation": isolation,
        "execution_controls": execution_controls,
        "operation": operation,
        "audit_log": audit,
        "source_artifacts": source_artifacts,
        "controls": _controls(mode=mode, isolation=isolation, execution_controls=execution_controls, audit_log=audit, credential_ref=credential_ref),
        "limitations": [
            "This attestation binds re-execution runner evidence to recorded container/kernel isolation controls.",
            "It records runner image digest, namespace/cgroup/seccomp, network, filesystem, seed, temperature, and audit-log evidence.",
            "It does not include raw runner credentials or raw audit-log bodies.",
            "Production deployments should preserve runtime-native audit events and enforce controls in the runner service.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "reexecution_isolation": body}, key)],
    }


def verify_reexecution_isolation_attestation(
    attestation: dict[str, Any],
    runner_evidence: dict[str, Any] | None = None,
    *,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    key: str | None = None,
) -> ReexecutionIsolationVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != REEXECUTION_ISOLATION_SCHEMA:
        errors.append(f"unsupported re-execution isolation attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical re-execution isolation attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("re-execution isolation attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "reexecution_isolation": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("re-execution isolation attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"re-execution isolation attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in REEXECUTION_ISOLATION_MODES:
        errors.append("re-execution isolation mode is unsupported")
    elif mode != "container-attested":
        warnings.append(f"re-execution isolation mode is {mode}; production runner isolation is not fully claimed")

    source = attestation.get("source", {})
    if not isinstance(source, dict):
        errors.append("re-execution isolation source must be an object")
        source = {}
    for field in ("runner_evidence_id", "runner_evidence_hash", "plan_hash", "policy_hash"):
        if not source.get(field):
            errors.append(f"re-execution isolation source.{field} is required")

    isolation = attestation.get("isolation", {})
    if not isinstance(isolation, dict):
        errors.append("re-execution isolation.isolation must be an object")
        isolation = {}
    _verify_isolation_record(isolation, errors)

    execution_controls = attestation.get("execution_controls", {})
    if not isinstance(execution_controls, dict):
        errors.append("re-execution isolation execution_controls must be an object")
        execution_controls = {}
    _verify_execution_controls(execution_controls, errors)

    operation = attestation.get("operation", {})
    if not isinstance(operation, dict):
        errors.append("re-execution isolation operation must be an object")
        operation = {}
    if not operation.get("actor_ref"):
        errors.append("re-execution isolation operation.actor_ref is required")
    _verify_redacted_ref(operation.get("credential"), "re-execution isolation operation.credential", errors)

    audit = attestation.get("audit_log", {})
    if not isinstance(audit, dict):
        errors.append("re-execution isolation audit_log must be an object")
        audit = {}
    for field in ("audit_log_ref", "root", "retention_until"):
        if not audit.get(field):
            errors.append(f"re-execution isolation audit_log.{field} is required")
    if not _is_hash_ref(str(audit.get("root") or "")):
        errors.append("re-execution isolation audit_log.root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(audit.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("re-execution isolation audit_log.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"re-execution isolation audit_log.retention_until invalid: {exc}")

    controls = attestation.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("re-execution isolation controls are required")

    source_artifacts = attestation.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("re-execution isolation source_artifacts must contain at least one source")
        source_artifacts = []

    supplied_policy = policy or (_runner_policy(runner_evidence) if runner_evidence is not None else None)
    supplied_sources = _source_artifacts(runner_evidence=runner_evidence, policy=supplied_policy, report=report)
    if supplied_sources:
        if source_artifacts != supplied_sources:
            errors.append("re-execution isolation source_artifacts do not match supplied source artifacts")
        expected_source = _source_record(runner_evidence, supplied_policy, report)
        if source != expected_source:
            errors.append("re-execution isolation source record does not match supplied artifacts")
        errors.extend(_source_binding_errors(attestation, runner_evidence, supplied_policy, report))
    else:
        warnings.append("re-execution isolation source artifacts were not supplied; source hashes were not replayed")

    _check_no_secret_values(attestation, errors)
    return ReexecutionIsolationVerification(ok=not errors, errors=errors, warnings=warnings)


def append_reexecution_isolation_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    runner_evidence: dict[str, Any] | None = None,
    *,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_reexecution_isolation_attestation(attestation, runner_evidence, policy=policy, report=report, key=key)
    if not result.ok:
        raise ValueError("invalid re-execution isolation attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "source": attestation.get("source"),
        "isolation": attestation.get("isolation"),
        "execution_controls": attestation.get("execution_controls"),
        "operation": attestation.get("operation"),
        "audit_log": attestation.get("audit_log"),
        "source_artifacts": attestation.get("source_artifacts"),
        "control_summary": _status_summary(attestation.get("controls", [])),
    }
    return chain.append(REEXECUTION_ISOLATION_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _source_record(
    runner_evidence: dict[str, Any] | None,
    policy: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> dict[str, Any]:
    evidence_plan = runner_evidence.get("plan", {}) if isinstance(runner_evidence, dict) else {}
    body = evidence_plan.get("body", {}) if isinstance(evidence_plan, dict) else {}
    runs = runner_evidence.get("runs", []) if isinstance(runner_evidence, dict) else []
    run_summaries = []
    for run in runs if isinstance(runs, list) else []:
        if isinstance(run, dict):
            run_summaries.append(
                {
                    "run_id": run.get("run_id"),
                    "seed": run.get("seed"),
                    "run_hash": run.get("run_hash"),
                    "results_hash": run.get("output", {}).get("results_hash") if isinstance(run.get("output"), dict) else None,
                }
            )
    return {
        "runner_evidence_id": runner_evidence.get("evidence_id") if isinstance(runner_evidence, dict) else None,
        "runner_evidence_hash": content_hash(runner_evidence) if isinstance(runner_evidence, dict) else None,
        "runner_outcome": runner_evidence.get("outcome") if isinstance(runner_evidence, dict) else None,
        "plan_id": evidence_plan.get("id") if isinstance(evidence_plan, dict) else None,
        "plan_hash": evidence_plan.get("hash") if isinstance(evidence_plan, dict) else None,
        "contract_id": body.get("contract", {}).get("id") if isinstance(body.get("contract"), dict) else None,
        "contract_hash": body.get("contract", {}).get("hash") if isinstance(body.get("contract"), dict) else None,
        "policy_id": policy.get("id") if isinstance(policy, dict) else None,
        "policy_hash": content_hash(policy) if isinstance(policy, dict) else None,
        "policy_risk_class": policy.get("risk_class") if isinstance(policy, dict) else None,
        "report_id": report.get("report_id") if isinstance(report, dict) else None,
        "report_hash": content_hash(report) if isinstance(report, dict) else None,
        "report_outcome": report.get("overall", {}).get("outcome") if isinstance(report, dict) and isinstance(report.get("overall"), dict) else None,
        "run_count": len(run_summaries),
        "runs": run_summaries,
    }


def _source_artifacts(
    *,
    runner_evidence: dict[str, Any] | None,
    policy: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if runner_evidence is not None:
        records.append(
            {
                "source_type": "reexecution_runner_evidence",
                "source_id": runner_evidence.get("evidence_id"),
                "source_hash": content_hash(runner_evidence),
            }
        )
    if policy is not None:
        records.append(
            {
                "source_type": "reexecution_policy",
                "source_id": policy.get("id"),
                "source_hash": content_hash(policy),
            }
        )
    if report is not None:
        records.append(
            {
                "source_type": "reexecution_report",
                "source_id": report.get("report_id"),
                "source_hash": content_hash(report),
            }
        )
    return records


def _source_binding_errors(
    attestation: dict[str, Any],
    runner_evidence: dict[str, Any] | None,
    policy: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    if runner_evidence is None or policy is None:
        return errors
    runner_result = verify_reexecution_runner_evidence(runner_evidence)
    errors.extend(f"source runner evidence invalid: {error}" for error in runner_result.errors)
    policy_result = verify_reexecution_policy(policy)
    errors.extend(f"source policy invalid: {error}" for error in policy_result.errors)
    if content_hash(policy) != content_hash(_runner_policy(runner_evidence)):
        errors.append("source policy does not match re-execution runner plan policy")
    errors.extend(_policy_binding_errors(attestation, runner_evidence, policy))
    if report is not None:
        report_result = verify_reexecution_report(report)
        errors.extend(f"source report invalid: {error}" for error in report_result.errors)
        errors.extend(_report_binding_errors(runner_evidence, policy, report))
    return errors


def _policy_binding_errors(attestation: dict[str, Any], runner_evidence: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    isolation = attestation.get("isolation", {}) if isinstance(attestation.get("isolation"), dict) else {}
    controls = attestation.get("execution_controls", {}) if isinstance(attestation.get("execution_controls"), dict) else {}
    sandbox = policy.get("sandbox", {}) if isinstance(policy.get("sandbox"), dict) else {}
    execution = policy.get("execution", {}) if isinstance(policy.get("execution"), dict) else {}
    for source_field, isolation_field in (
        ("runner_image", "runner_image"),
        ("runner_image_digest", "runner_image_digest"),
        ("network", "network_mode"),
        ("read_only_rootfs", "read_only_rootfs"),
    ):
        if source_field in sandbox and isolation.get(isolation_field) != sandbox.get(source_field):
            errors.append(f"isolation.{isolation_field} does not match re-execution policy sandbox.{source_field}")
    if execution.get("seed_policy") and controls.get("seed_policy") != execution.get("seed_policy"):
        errors.append("execution_controls.seed_policy does not match re-execution policy")
    if execution.get("require_seed") is True and controls.get("require_seed") is not True:
        errors.append("execution_controls.require_seed must be true for the policy")
    expected_seeds = [run.get("seed") for run in runner_evidence.get("runs", []) if isinstance(run, dict)]
    if controls.get("seeds") != expected_seeds:
        errors.append("execution_controls.seeds do not match re-execution runner evidence")
    max_temperature = execution.get("max_temperature")
    if isinstance(max_temperature, (int, float)):
        temperature = controls.get("temperature")
        if not isinstance(temperature, (int, float)) or temperature > max_temperature:
            errors.append("execution_controls.temperature exceeds re-execution policy maximum")
    return errors


def _report_binding_errors(runner_evidence: dict[str, Any], policy: dict[str, Any], report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    runner_hashes = [
        run.get("output", {}).get("results_hash")
        for run in runner_evidence.get("runs", [])
        if isinstance(run, dict) and isinstance(run.get("output"), dict)
    ]
    report_hashes = [
        source.get("results_hash")
        for source in report.get("source_runs", [])
        if isinstance(source, dict)
    ]
    if runner_hashes != report_hashes:
        errors.append("report source run hashes do not match re-execution runner evidence")
    report_policy = report.get("policy", {}) if isinstance(report.get("policy"), dict) else {}
    if report_policy and report_policy.get("hash") != content_hash(policy):
        errors.append("report policy hash does not match supplied re-execution policy")
    report_contract_hash = report.get("contract", {}).get("hash") if isinstance(report.get("contract"), dict) else None
    runner_contract_hash = runner_evidence.get("plan", {}).get("body", {}).get("contract", {}).get("hash")
    if runner_contract_hash and report_contract_hash != runner_contract_hash:
        errors.append("report contract hash does not match re-execution runner evidence")
    return errors


def _runner_policy(runner_evidence: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(runner_evidence, dict):
        return {}
    policy = runner_evidence.get("plan", {}).get("body", {}).get("policy")
    return policy if isinstance(policy, dict) else {}


def _verify_isolation_record(record: dict[str, Any], errors: list[str]) -> None:
    for field in (
        "isolation_ref",
        "runner_ref",
        "runner_provider",
        "orchestrator",
        "container_runtime",
        "kernel",
        "namespace_mode",
        "cgroup_ref",
        "seccomp_profile_hash",
        "runner_image",
        "runner_image_digest",
        "network_mode",
        "filesystem_policy_ref",
        "egress_policy_ref",
    ):
        if not record.get(field):
            errors.append(f"re-execution isolation isolation.{field} is required")
    if not _is_hash_ref(str(record.get("runner_image_digest") or "")):
        errors.append("re-execution isolation isolation.runner_image_digest must be a sha256 reference")
    if not _is_hash_ref(str(record.get("seccomp_profile_hash") or "")):
        errors.append("re-execution isolation isolation.seccomp_profile_hash must be a sha256 reference")
    if record.get("apparmor_profile_hash") and not _is_hash_ref(str(record.get("apparmor_profile_hash"))):
        errors.append("re-execution isolation isolation.apparmor_profile_hash must be a sha256 reference")
    if str(record.get("namespace_mode") or "").lower() in {"host", "none"}:
        errors.append("re-execution isolation isolation.namespace_mode must not be host/none")
    if record.get("network_mode") != "disabled":
        errors.append("re-execution isolation isolation.network_mode must be disabled")
    if record.get("read_only_rootfs") is not True:
        errors.append("re-execution isolation isolation.read_only_rootfs must be true")
    for field in ("writable_mounts", "denied_mounts"):
        value = record.get(field)
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            errors.append(f"re-execution isolation isolation.{field} must be a string list")


def _verify_execution_controls(record: dict[str, Any], errors: list[str]) -> None:
    if not record.get("seed_policy"):
        errors.append("re-execution isolation execution_controls.seed_policy is required")
    if record.get("require_seed") is not True:
        errors.append("re-execution isolation execution_controls.require_seed must be true")
    seeds = record.get("seeds")
    if not isinstance(seeds, list) or not seeds:
        errors.append("re-execution isolation execution_controls.seeds must be a non-empty list")
    elif not all(isinstance(seed, int) for seed in seeds):
        errors.append("re-execution isolation execution_controls.seeds must contain integers")
    if not isinstance(record.get("temperature"), (int, float)):
        errors.append("re-execution isolation execution_controls.temperature must be numeric")
    if record.get("max_temperature") is not None and not isinstance(record.get("max_temperature"), (int, float)):
        errors.append("re-execution isolation execution_controls.max_temperature must be numeric when present")
    if not record.get("entropy_source_ref"):
        errors.append("re-execution isolation execution_controls.entropy_source_ref is required")


def _controls(
    *,
    mode: str,
    isolation: dict[str, Any],
    execution_controls: dict[str, Any],
    audit_log: dict[str, Any],
    credential_ref: str,
) -> list[dict[str, Any]]:
    return [
        {
            "id": "runner-image-digest",
            "status": "implemented" if _is_hash_ref(str(isolation.get("runner_image_digest") or "")) else "planned-production",
            "description": "Runner image digest is bound into the attestation.",
        },
        {
            "id": "kernel-container-isolation",
            "status": "implemented"
            if mode == "container-attested" and isolation.get("namespace_mode") not in {"host", "none"} and isolation.get("cgroup_ref") and _is_hash_ref(str(isolation.get("seccomp_profile_hash") or ""))
            else "planned-production",
            "description": "Namespace, cgroup, and seccomp evidence are recorded.",
        },
        {
            "id": "network-disabled",
            "status": "implemented" if isolation.get("network_mode") == "disabled" else "planned-production",
            "description": "Runner network mode is disabled for deterministic re-execution.",
        },
        {
            "id": "read-only-rootfs",
            "status": "implemented" if isolation.get("read_only_rootfs") is True else "planned-production",
            "description": "Runner filesystem policy uses a read-only root filesystem.",
        },
        {
            "id": "seed-and-temperature-enforcement",
            "status": "implemented"
            if execution_controls.get("require_seed") is True
            and isinstance(execution_controls.get("seeds"), list)
            and isinstance(execution_controls.get("temperature"), (int, float))
            else "planned-production",
            "description": "Seed policy, per-run seeds, and temperature are bound.",
        },
        {
            "id": "immutable-runner-audit-log",
            "status": "implemented" if _is_hash_ref(str(audit_log.get("root") or "")) else "planned-production",
            "description": "Runner audit-log root and retention deadline are recorded.",
        },
        {
            "id": "redacted-runner-credential",
            "status": "implemented" if credential_ref else "planned-production",
            "description": "Runner control-plane credentials are represented only by redacted references.",
        },
    ]


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


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value.removeprefix("sha256:"))
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _require_text(value: Any, field: str) -> None:
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
                    errors.append(f"re-execution isolation secret-like field must be redacted reference: {child_path}")
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
