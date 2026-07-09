from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .crypto import sign_value, verify_value
from .standards import verify_standards_submission
from .verifier_conformance import verify_verifier_conformance_report

VERIFIER_RELEASE_SCHEMA = "trustai.verifier-release/0.1"

DEFAULT_VERIFIER_SOURCE_PATHS = (
    "src/trustai/verifier.py",
    "src/trustai/chain.py",
    "src/trustai/merkle.py",
    "src/trustai/canonical.py",
    "src/trustai/contracts.py",
    "src/trustai/gate.py",
    "src/trustai/proofpack.py",
    "src/trustai/crypto.py",
    "src/trustai/keyring.py",
    "src/trustai/timestamping.py",
    "verifier/go/trustai-verify/main.go",
    "verifier/go/trustai-verify/go.mod",
    "verifier/go/trustai-verify/README.md",
)


@dataclass
class VerifierReleaseVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_verifier_release_manifest(
    root: str | Path = ".",
    *,
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    version: str | None = None,
    verifier_command: str = "python -m trustai verify",
    source_paths: list[str] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    root_path = Path(root)
    project = _project_metadata(root_path)
    source_records = [_source_record(root_path, path) for path in (source_paths or list(DEFAULT_VERIFIER_SOURCE_PATHS))]
    release_version = version or str(project.get("version") or "unknown")
    body: dict[str, Any] = {
        "schema": VERIFIER_RELEASE_SCHEMA,
        "generated_at": utc_now(),
        "release": {
            "name": "trustai-verifier",
            "version": release_version,
            "implementation": "python-reference",
            "verifier_command": verifier_command,
            "mode": "offline-accountless",
            "license": project.get("license", "Apache-2.0"),
            "requires_python": project.get("requires_python"),
        },
        "source_files": source_records,
        "targets": [
            {
                "id": "python-reference-module",
                "kind": "source",
                "artifact": "src/trustai/verifier.py",
                "status": "available",
            },
            {
                "id": "go-offline-verifier-source",
                "kind": "source",
                "artifact": "verifier/go/trustai-verify/main.go",
                "status": "available",
            },
            {
                "id": "go-static-binary",
                "kind": "binary",
                "artifact": "trustai-verifier",
                "status": "planned",
            },
        ],
        "limitations": [
            "This local release manifest signs the Python reference verifier and Go offline verifier source set; it is not a compiled Go static binary.",
            "Production releases should publish independent binary artifacts, public-key signatures, and release-specific conformance reports.",
        ],
    }
    if conformance_report is not None:
        body["conformance_report"] = {
            "report_id": conformance_report.get("report_id"),
            "content_hash": content_hash(conformance_report),
            "case_count": conformance_report.get("summary", {}).get("case_count"),
            "passed_count": conformance_report.get("summary", {}).get("passed_count"),
            "verifier_command": conformance_report.get("verifier", {}).get("command"),
            "source_proof_pack": conformance_report.get("source_proof_pack", {}),
        }
    if standards_package is not None:
        body["standards_package"] = {
            "package_id": standards_package.get("package_id"),
            "content_hash": content_hash(standards_package),
            "spec_count": len(standards_package.get("specs", [])),
            "required_specs": standards_package.get("required_specs", []),
        }
    release_id = content_hash(body)
    return {
        **body,
        "release_id": release_id,
        "signatures": [sign_value({"release_id": release_id, "release": body}, key)],
    }


def verify_verifier_release_manifest(
    manifest: dict[str, Any],
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    key: str | None = None,
) -> VerifierReleaseVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if manifest.get("schema") != VERIFIER_RELEASE_SCHEMA:
        errors.append(f"unsupported verifier release schema: {manifest.get('schema')}")
    body = without_keys(manifest, "release_id", "signatures")
    expected_release_id = content_hash(body)
    if manifest.get("release_id") != expected_release_id:
        errors.append("release_id does not match canonical release body")

    signatures = manifest.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("verifier release manifest must include at least one signature")
    else:
        signed_value = {"release_id": manifest.get("release_id"), "release": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("verifier release signature verification failed")

    release = manifest.get("release", {})
    if release.get("mode") != "offline-accountless":
        warnings.append("verifier release mode is not offline-accountless")
    if not release.get("verifier_command"):
        errors.append("release verifier_command is required")

    source_files = manifest.get("source_files", [])
    if not isinstance(source_files, list) or not source_files:
        errors.append("verifier release must include source_files")
        source_files = []
    source_paths = set()
    for source in source_files:
        if not isinstance(source, dict):
            errors.append("source file record must be an object")
            continue
        path_value = source.get("path")
        if not isinstance(path_value, str) or not path_value:
            errors.append("source file path missing")
            continue
        source_paths.add(path_value)
        source_path = root_path / path_value
        if not source_path.exists():
            errors.append(f"source file missing from worktree: {path_value}")
            continue
        current = _source_record(root_path, path_value)
        for field in ("sha256", "size_bytes"):
            if source.get(field) != current.get(field):
                errors.append(f"source file {path_value} {field} mismatch")
    if "src/trustai/verifier.py" not in source_paths:
        errors.append("verifier release must include src/trustai/verifier.py")
    target_ids = {target.get("id") for target in manifest.get("targets", []) if isinstance(target, dict)}
    if "go-offline-verifier-source" in target_ids and "verifier/go/trustai-verify/main.go" not in source_paths:
        errors.append("go source target must include verifier/go/trustai-verify/main.go")

    conformance_ref = manifest.get("conformance_report")
    if conformance_report is not None:
        if not isinstance(conformance_ref, dict):
            errors.append("manifest missing conformance_report reference")
        else:
            if conformance_ref.get("content_hash") != content_hash(conformance_report):
                errors.append("conformance report source hash mismatch")
            result = verify_verifier_conformance_report(conformance_report)
            if not result.ok:
                errors.extend(f"conformance report invalid: {error}" for error in result.errors)
    elif conformance_ref:
        warnings.append("conformance report not supplied for deep verification")
    else:
        errors.append("verifier release must reference a conformance report")

    standards_ref = manifest.get("standards_package")
    if standards_package is not None:
        if not isinstance(standards_ref, dict):
            errors.append("manifest missing standards_package reference")
        else:
            if standards_ref.get("content_hash") != content_hash(standards_package):
                errors.append("standards package source hash mismatch")
            result = verify_standards_submission(standards_package, root=root_path)
            if not result.ok:
                errors.extend(f"standards package invalid: {error}" for error in result.errors)
    elif standards_ref:
        warnings.append("standards package not supplied for deep verification")

    targets = manifest.get("targets", [])
    if not any(isinstance(target, dict) and target.get("status") == "available" for target in targets):
        errors.append("verifier release must include at least one available target")

    return VerifierReleaseVerification(ok=not errors, errors=errors, warnings=warnings)


def load_verifier_release_manifest(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_verifier_release_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def write_verifier_release_markdown(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_verifier_release_markdown(manifest), encoding="utf-8")


def render_verifier_release_markdown(manifest: dict[str, Any]) -> str:
    release = manifest.get("release", {})
    files = "\n".join(
        f"- `{source.get('path')}`: `{source.get('sha256')}`"
        for source in manifest.get("source_files", [])
    )
    targets = "\n".join(
        f"- `{target.get('id')}`: {target.get('status')} ({target.get('kind')})"
        for target in manifest.get("targets", [])
    )
    conformance = manifest.get("conformance_report", {})
    standards = manifest.get("standards_package", {})
    return f"""# TrustAI Verifier Release Manifest

Release ID: `{manifest.get('release_id', '')}`

Version: {release.get('version', '')}

Verifier command: `{release.get('verifier_command', '')}`

Mode: {release.get('mode', '')}

## Targets

{targets}

## Source Files

{files}

## Evidence

Conformance report: `{conformance.get('report_id', '')}`

Standards package: `{standards.get('package_id', '')}`
"""


def _source_record(root: Path, path: str) -> dict[str, Any]:
    source_path = root / path
    data = source_path.read_bytes()
    return {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _project_metadata(root: Path) -> dict[str, Any]:
    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.exists():
        return {"name": "trustai", "version": "unknown", "license": "Apache-2.0"}
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project = data.get("project", {})
    license_value = project.get("license", {})
    if isinstance(license_value, dict):
        license_value = license_value.get("text")
    return {
        "name": project.get("name", "trustai"),
        "version": project.get("version", "unknown"),
        "license": license_value or "Apache-2.0",
        "requires_python": project.get("requires-python"),
    }
