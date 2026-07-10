from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .go_verifier_build import verify_go_verifier_build_attestation
from .verifier_release import verify_verifier_release_manifest

GO_VERIFIER_RELEASE_RUN_SCHEMA = "trustai.go-verifier-release-run/0.1"
GO_VERIFIER_RELEASE_RUN_ENTRY_TYPE = "verifier.go_release_run_attested"


@dataclass
class GoVerifierReleaseRunVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_go_verifier_release_run_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("Go verifier release-run receipt must contain an object")
    return value


def write_go_verifier_release_run_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_go_verifier_release_run_receipt(
    verifier_release: dict[str, Any],
    build_attestation: dict[str, Any],
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    binary_path: str | Path | None = None,
    workflow_path: str | Path = ".github/workflows/go-verifier.yml",
    provider: str,
    workflow_ref: str,
    workflow_run_id: str,
    workflow_run_url: str | None = None,
    run_attempt: int = 1,
    commit_sha: str,
    branch_ref: str,
    trigger_ref: str,
    runner_ref: str,
    status: str = "completed",
    conclusion: str = "success",
    started_at: str | None = None,
    completed_at: str | None = None,
    artifacts: list[Any] | None = None,
    checks: list[dict[str, Any]] | None = None,
    hosted_provenance_ref: str | None = None,
    hosted_provenance_hash: str | None = None,
    oidc_issuer: str | None = None,
    oidc_subject: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    for field, value in {
        "provider": provider,
        "workflow_ref": workflow_ref,
        "workflow_run_id": workflow_run_id,
        "commit_sha": commit_sha,
        "branch_ref": branch_ref,
        "trigger_ref": trigger_ref,
        "runner_ref": runner_ref,
    }.items():
        _require_text(value, field)
    if run_attempt < 1:
        raise ValueError("run_attempt must be positive")

    release_result = verify_verifier_release_manifest(
        verifier_release,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        key=key,
    )
    if not release_result.ok:
        raise ValueError("invalid verifier release source: " + "; ".join(release_result.errors))
    build_result = verify_go_verifier_build_attestation(
        build_attestation,
        verifier_release,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        binary_path=binary_path,
        key=key,
    )
    if not build_result.ok:
        raise ValueError("invalid Go verifier build source: " + "; ".join(build_result.errors))

    if started_at:
        parse_rfc3339(started_at)
    if completed_at:
        parse_rfc3339(completed_at)
    if started_at and completed_at and parse_rfc3339(completed_at) < parse_rfc3339(started_at):
        raise ValueError("completed_at must be after started_at")
    timestamp = generated_at or completed_at or utc_now()
    parse_rfc3339(timestamp)

    root_path = Path(root)
    workflow = _workflow_record(root_path, workflow_path)
    artifact_records = [_artifact_record(root_path, artifact) for artifact in artifacts or []]
    check_records = [_check_record(check) for check in checks or []]
    provenance = {
        "hosted_provenance_ref": hosted_provenance_ref,
        "hosted_provenance_hash": hosted_provenance_hash,
        "oidc_issuer": oidc_issuer,
        "oidc_subject": oidc_subject,
    }
    binary = build_attestation.get("binary", {}) if isinstance(build_attestation.get("binary"), dict) else {}
    source = {
        "release_id": verifier_release.get("release_id"),
        "release_hash": content_hash(verifier_release),
        "release_version": verifier_release.get("release", {}).get("version"),
        "build_id": build_attestation.get("build_id"),
        "build_hash": content_hash(build_attestation),
        "build_mode": build_attestation.get("build", {}).get("mode"),
        "binary_status": binary.get("status"),
        "binary_sha256": binary.get("sha256"),
    }
    workflow_run = {
        "provider": provider,
        "workflow_ref": workflow_ref,
        "workflow_run_id": workflow_run_id,
        "workflow_run_url": workflow_run_url,
        "run_attempt": int(run_attempt),
        "commit_sha": commit_sha,
        "branch_ref": branch_ref,
        "trigger_ref": trigger_ref,
        "runner_ref": runner_ref,
        "status": status,
        "conclusion": conclusion,
        "started_at": started_at,
        "completed_at": completed_at,
    }
    body = {
        "schema": GO_VERIFIER_RELEASE_RUN_SCHEMA,
        "generated_at": timestamp,
        "source": source,
        "workflow": workflow,
        "workflow_run": workflow_run,
        "artifacts": artifact_records,
        "checks": check_records,
        "provenance": provenance,
        "controls": _controls(workflow, workflow_run, artifact_records, check_records, provenance, binary),
        "limitations": [
            "This receipt binds a recorded verifier release workflow run to signed verifier release and Go build attestations.",
            "It verifies local workflow and artifact hashes when those files are supplied, but it does not itself prove a hosted provider operated the run.",
            "Production release authority still requires provider-native workflow run, artifact, signature, and provenance exports.",
        ],
    }
    run_id = content_hash(body)
    return {
        **body,
        "run_id": run_id,
        "signatures": [sign_value({"run_id": run_id, "go_verifier_release_run": body}, key)],
    }


def verify_go_verifier_release_run_receipt(
    receipt: dict[str, Any],
    verifier_release: dict[str, Any] | None = None,
    build_attestation: dict[str, Any] | None = None,
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    binary_path: str | Path | None = None,
    key: str | None = None,
) -> GoVerifierReleaseRunVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if receipt.get("schema") != GO_VERIFIER_RELEASE_RUN_SCHEMA:
        errors.append(f"unsupported Go verifier release-run schema: {receipt.get('schema')}")
    body = without_keys(receipt, "run_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("run_id") != expected_id:
        errors.append("run_id does not match canonical Go verifier release-run body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("Go verifier release-run receipt must include at least one signature")
    else:
        signed_value = {"run_id": receipt.get("run_id"), "go_verifier_release_run": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("Go verifier release-run signature verification failed")

    try:
        parse_rfc3339(str(receipt.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"Go verifier release-run generated_at invalid: {exc}")

    _verify_source(
        receipt.get("source"),
        verifier_release,
        build_attestation,
        root_path,
        conformance_report,
        standards_package,
        binary_path,
        key,
        errors,
        warnings,
    )
    _verify_workflow(receipt.get("workflow"), root_path, errors, warnings)
    _verify_workflow_run(receipt.get("workflow_run"), errors)
    _verify_checks(receipt.get("checks"), errors, warnings)
    _verify_artifacts(receipt.get("artifacts"), receipt.get("source"), root_path, errors, warnings)
    _verify_provenance(receipt.get("provenance"), root_path, errors, warnings)

    return GoVerifierReleaseRunVerification(ok=not errors, errors=errors, warnings=warnings)


def append_go_verifier_release_run_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    verifier_release: dict[str, Any] | None = None,
    build_attestation: dict[str, Any] | None = None,
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    binary_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_go_verifier_release_run_receipt(
        receipt,
        verifier_release,
        build_attestation,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        binary_path=binary_path,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid Go verifier release-run receipt: " + "; ".join(result.errors))
    payload = {
        "run_id": receipt["run_id"],
        "run_hash": content_hash(receipt),
        "source": receipt.get("source"),
        "workflow": receipt.get("workflow"),
        "workflow_run": receipt.get("workflow_run"),
        "artifact_count": len(receipt.get("artifacts", [])),
        "check_count": len(receipt.get("checks", [])),
        "provenance": receipt.get("provenance"),
        "controls": receipt.get("controls", []),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
        "limitations": receipt.get("limitations", []),
    }
    timestamp = receipt.get("workflow_run", {}).get("completed_at") or receipt.get("generated_at")
    return chain.append(GO_VERIFIER_RELEASE_RUN_ENTRY_TYPE, payload, key=key, timestamp=timestamp)


def parse_release_run_artifact_arg(value: str) -> dict[str, str]:
    parts = [part.strip() for part in value.split(",", 2)]
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError("--artifact must be name,path[,kind]")
    return {"name": parts[0], "path": parts[1], "kind": parts[2] if len(parts) == 3 and parts[2] else "artifact"}


def parse_release_run_check_arg(value: str) -> dict[str, str]:
    parts = [part.strip() for part in value.split(",", 3)]
    if len(parts) < 3 or not parts[0] or not parts[1] or not parts[2]:
        raise ValueError("--check must be name,status,conclusion[,log_ref]")
    item = {"name": parts[0], "status": parts[1], "conclusion": parts[2]}
    if len(parts) == 4 and parts[3]:
        item["log_ref"] = parts[3]
    return item


def _verify_source(
    value: Any,
    verifier_release: dict[str, Any] | None,
    build_attestation: dict[str, Any] | None,
    root: Path,
    conformance_report: dict[str, Any] | None,
    standards_package: dict[str, Any] | None,
    binary_path: str | Path | None,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if not isinstance(value, dict):
        errors.append("Go verifier release-run source must be an object")
        return
    for field in ("release_id", "release_hash", "build_id", "build_hash", "build_mode"):
        if value.get(field) in (None, ""):
            errors.append(f"Go verifier release-run source.{field} is required")
    if verifier_release is None:
        warnings.append("verifier release source was not supplied; release bindings were not replayed")
    else:
        release_result = verify_verifier_release_manifest(
            verifier_release,
            root=root,
            conformance_report=conformance_report,
            standards_package=standards_package,
            key=key,
        )
        errors.extend(f"verifier release source: {error}" for error in release_result.errors)
        if value.get("release_id") != verifier_release.get("release_id"):
            errors.append("Go verifier release-run source.release_id does not match verifier release")
        if value.get("release_hash") != content_hash(verifier_release):
            errors.append("Go verifier release-run source.release_hash does not match verifier release")
    if build_attestation is None:
        warnings.append("Go verifier build source was not supplied; build bindings were not replayed")
    else:
        build_result = verify_go_verifier_build_attestation(
            build_attestation,
            verifier_release,
            root=root,
            conformance_report=conformance_report,
            standards_package=standards_package,
            binary_path=binary_path,
            key=key,
        )
        errors.extend(f"Go verifier build source: {error}" for error in build_result.errors)
        if value.get("build_id") != build_attestation.get("build_id"):
            errors.append("Go verifier release-run source.build_id does not match Go verifier build attestation")
        if value.get("build_hash") != content_hash(build_attestation):
            errors.append("Go verifier release-run source.build_hash does not match Go verifier build attestation")
        build = build_attestation.get("build", {}) if isinstance(build_attestation.get("build"), dict) else {}
        binary = build_attestation.get("binary", {}) if isinstance(build_attestation.get("binary"), dict) else {}
        if value.get("build_mode") != build.get("mode"):
            errors.append("Go verifier release-run source.build_mode does not match Go verifier build attestation")
        if value.get("binary_status") != binary.get("status"):
            errors.append("Go verifier release-run source.binary_status does not match Go verifier build attestation")
        if value.get("binary_sha256") != binary.get("sha256"):
            errors.append("Go verifier release-run source.binary_sha256 does not match Go verifier build attestation")


def _verify_workflow(value: Any, root: Path, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("Go verifier release-run workflow must be an object")
        return
    for field in ("path", "sha256", "size_bytes"):
        if value.get(field) in (None, ""):
            errors.append(f"Go verifier release-run workflow.{field} is required")
    if value.get("sha256") and not _is_sha256(str(value.get("sha256"))):
        errors.append("Go verifier release-run workflow.sha256 must be a SHA-256 hex digest")
    path = value.get("path")
    if not isinstance(path, str) or not path:
        return
    source_path = _local_ref_path(root, path)
    if source_path is None:
        warnings.append("Go verifier release-run workflow path is not local; workflow file was not replayed")
        return
    try:
        data = source_path.read_bytes()
    except OSError as exc:
        errors.append(f"Go verifier release-run workflow file could not be read: {exc}")
        return
    if hashlib.sha256(data).hexdigest() != value.get("sha256"):
        errors.append("Go verifier release-run workflow.sha256 does not match local workflow file")
    if len(data) != value.get("size_bytes"):
        errors.append("Go verifier release-run workflow.size_bytes does not match local workflow file")
    text = data.decode("utf-8", errors="replace")
    for marker in ("actions/setup-go@v5", 'CGO_ENABLED: "0"', "go build -trimpath", "actions/attest-build-provenance@v2"):
        if marker not in text:
            errors.append(f"Go verifier release-run workflow missing required release control: {marker}")


def _verify_workflow_run(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("Go verifier release-run workflow_run must be an object")
        return
    for field in (
        "provider",
        "workflow_ref",
        "workflow_run_id",
        "run_attempt",
        "commit_sha",
        "branch_ref",
        "trigger_ref",
        "runner_ref",
        "status",
        "conclusion",
    ):
        if value.get(field) in (None, ""):
            errors.append(f"Go verifier release-run workflow_run.{field} is required")
    if value.get("status") != "completed":
        errors.append("Go verifier release-run workflow_run.status must be completed")
    if value.get("conclusion") != "success":
        errors.append("Go verifier release-run workflow_run.conclusion must be success")
    if not isinstance(value.get("run_attempt"), int) or value.get("run_attempt") < 1:
        errors.append("Go verifier release-run workflow_run.run_attempt must be a positive integer")
    for field in ("started_at", "completed_at"):
        if value.get(field):
            try:
                parse_rfc3339(str(value.get(field)))
            except ValueError as exc:
                errors.append(f"Go verifier release-run workflow_run.{field} invalid: {exc}")
    if value.get("started_at") and value.get("completed_at"):
        if parse_rfc3339(str(value["completed_at"])) < parse_rfc3339(str(value["started_at"])):
            errors.append("Go verifier release-run workflow_run.completed_at must be after started_at")


def _verify_checks(value: Any, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, list):
        errors.append("Go verifier release-run checks must be a list")
        return
    if not value:
        errors.append("Go verifier release-run must include at least one completed check")
        return
    for item in value:
        if not isinstance(item, dict):
            errors.append("Go verifier release-run check entries must be objects")
            continue
        if not item.get("name"):
            errors.append("Go verifier release-run check.name is required")
        if item.get("status") != "completed":
            errors.append(f"Go verifier release-run check {item.get('name')} status must be completed")
        if item.get("conclusion") != "success":
            errors.append(f"Go verifier release-run check {item.get('name')} conclusion must be success")
        if item.get("log_ref") and not item.get("log_hash"):
            warnings.append(f"Go verifier release-run check {item.get('name')} has log_ref without log_hash")


def _verify_artifacts(value: Any, source: Any, root: Path, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, list):
        errors.append("Go verifier release-run artifacts must be a list")
        return
    binary_sha = source.get("binary_sha256") if isinstance(source, dict) else None
    has_binary_artifact = False
    seen: set[str] = set()
    for artifact in value:
        if not isinstance(artifact, dict):
            errors.append("Go verifier release-run artifact entries must be objects")
            continue
        name = artifact.get("name")
        if not name:
            errors.append("Go verifier release-run artifact.name is required")
        elif name in seen:
            errors.append(f"Go verifier release-run artifact duplicated: {name}")
        else:
            seen.add(name)
        if artifact.get("sha256") and not _is_sha256(str(artifact.get("sha256"))):
            errors.append(f"Go verifier release-run artifact {name} sha256 must be a SHA-256 hex digest")
        if artifact.get("sha256") == binary_sha:
            has_binary_artifact = True
        _verify_local_file_hash(f"Go verifier release-run artifact {name}", artifact.get("path"), artifact.get("sha256"), root, errors)
    if binary_sha and not has_binary_artifact:
        errors.append("Go verifier release-run binary artifact matching Go verifier build binary_sha256 is missing")
    if not value:
        warnings.append("Go verifier release-run has no artifacts; only workflow/check evidence was recorded")


def _verify_provenance(value: Any, root: Path, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("Go verifier release-run provenance must be an object")
        return
    if value.get("hosted_provenance_hash") and not _is_sha256_ref(str(value.get("hosted_provenance_hash"))):
        errors.append("Go verifier release-run provenance.hosted_provenance_hash must be a sha256 reference")
    _verify_local_hash_ref(
        "Go verifier release-run provenance.hosted_provenance_hash",
        value.get("hosted_provenance_ref"),
        value.get("hosted_provenance_hash"),
        root,
        errors,
        warnings,
    )
    if value.get("hosted_provenance_hash") and (not value.get("oidc_issuer") or not value.get("oidc_subject")):
        errors.append("Go verifier release-run hosted provenance requires oidc_issuer and oidc_subject")
    if not value.get("hosted_provenance_hash"):
        warnings.append("Go verifier release-run hosted provenance hash was not supplied")


def _workflow_record(root: Path, workflow_path: str | Path) -> dict[str, Any]:
    path = Path(workflow_path)
    source_path = path if path.is_absolute() else root / path
    data = source_path.read_bytes()
    return {
        "path": str(workflow_path).replace("\\", "/"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "format": "github-actions-workflow",
    }


def _artifact_record(root: Path, item: Any) -> dict[str, Any]:
    if isinstance(item, (str, Path)):
        path = str(item)
        name = Path(path).name
        kind = "artifact"
    elif isinstance(item, dict):
        path = str(item.get("path") or item.get("ref") or "")
        name = str(item.get("name") or Path(path).name)
        kind = str(item.get("kind") or "artifact")
    else:
        raise ValueError("artifact must be a path string or object")
    if not path:
        raise ValueError("artifact path is required")
    source_path = _local_ref_path(root, path)
    if source_path is None:
        sha256 = item.get("sha256") if isinstance(item, dict) else None
        size_bytes = item.get("size_bytes") if isinstance(item, dict) else None
    else:
        data = source_path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        size_bytes = len(data)
    return {
        "name": name,
        "path": path.replace("\\", "/"),
        "kind": kind,
        "sha256": sha256,
        "size_bytes": size_bytes,
    }


def _check_record(check: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(check, dict):
        raise ValueError("check must be an object")
    record = {
        "name": check.get("name"),
        "status": check.get("status"),
        "conclusion": check.get("conclusion"),
    }
    for field in ("started_at", "completed_at", "log_ref", "log_hash"):
        if check.get(field):
            record[field] = check.get(field)
    return record


def _controls(
    workflow: dict[str, Any],
    workflow_run: dict[str, Any],
    artifacts: list[dict[str, Any]],
    checks: list[dict[str, Any]],
    provenance: dict[str, Any],
    binary: dict[str, Any],
) -> list[dict[str, str]]:
    binary_sha = binary.get("sha256")
    binary_artifact = bool(binary_sha and any(artifact.get("sha256") == binary_sha for artifact in artifacts))
    checks_pass = bool(checks) and all(check.get("status") == "completed" and check.get("conclusion") == "success" for check in checks)
    run_success = workflow_run.get("status") == "completed" and workflow_run.get("conclusion") == "success"
    return [
        {"id": "go-verifier-release-workflow-source", "status": "attested" if workflow.get("sha256") else "planned-production", "description": "Release workflow source file hash and size are bound into the receipt."},
        {"id": "go-verifier-release-build-binding", "status": "attested" if binary.get("status") else "planned-production", "description": "Workflow run is bound to the signed verifier release manifest and Go build attestation."},
        {"id": "go-verifier-release-artifacts", "status": "attested" if binary_artifact else "planned-production", "description": "Published workflow artifacts include the verifier binary hash from the build attestation."},
        {"id": "go-verifier-release-checks", "status": "attested" if checks_pass and run_success else "failed", "description": "Hosted workflow checks completed successfully for the recorded run."},
        {"id": "go-verifier-release-hosted-provenance", "status": "attested" if provenance.get("hosted_provenance_hash") else "planned-production", "description": "Hosted build provenance or provider attestation hash is recorded."},
    ]


def _verify_local_file_hash(label: str, ref: Any, expected_hash: Any, root: Path, errors: list[str]) -> None:
    if not ref or not expected_hash or not isinstance(ref, str):
        return
    source_path = _local_ref_path(root, ref)
    if source_path is None:
        return
    try:
        data = source_path.read_bytes()
    except OSError as exc:
        errors.append(f"{label} local source could not be read: {exc}")
        return
    if hashlib.sha256(data).hexdigest() != expected_hash:
        errors.append(f"{label} sha256 does not match local source")


def _verify_local_hash_ref(
    label: str,
    ref: Any,
    expected_hash: Any,
    root: Path,
    errors: list[str],
    warnings: list[str],
) -> None:
    if not ref or not expected_hash or not isinstance(ref, str) or not isinstance(expected_hash, str):
        return
    source_path = _local_ref_path(root, ref)
    if source_path is None:
        return
    try:
        data = source_path.read_bytes()
    except OSError as exc:
        errors.append(f"{label} local source could not be read: {exc}")
        return
    expected = expected_hash[7:] if expected_hash.startswith("sha256:") else expected_hash
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        errors.append(f"{label} does not match local source {ref}")


def _local_ref_path(root: Path, ref: str) -> Path | None:
    if "://" in ref:
        return None
    if ":" in ref and not (len(ref) > 1 and ref[1] == ":"):
        return None
    path = Path(ref)
    if path.is_absolute():
        return path
    return root / path


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if isinstance(item, dict):
            status = str(item.get("status", "unknown"))
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())


def _is_sha256_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return _is_sha256(value[7:])
    return _is_sha256(value)
