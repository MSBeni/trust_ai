from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .verifier_release import verify_verifier_release_manifest

GO_VERIFIER_BUILD_SCHEMA = "trustai.go-verifier-build-attestation/0.1"
GO_VERIFIER_BINARY_SIGNATURE_SCHEMA = "trustai.go-verifier-binary-signature/0.1"
GO_VERIFIER_BUILD_ENTRY_TYPE = "verifier.go_build_attested"
GO_VERIFIER_BUILD_MODES = {"source-plan", "recorded-build", "binary-attested"}


@dataclass
class GoVerifierBuildVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_go_verifier_build_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("Go verifier build attestation must contain an object")
    return value


def write_go_verifier_build_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def write_go_verifier_binary_signature_artifact(path: str | Path, artifact: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")


def build_go_verifier_binary_signature_artifact(
    verifier_release: dict[str, Any],
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    binary_path: str | Path,
    build_log_ref: str | Path,
    sbom_ref: str | Path,
    provenance_ref: str | Path,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    release_result = verify_verifier_release_manifest(
        verifier_release,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        key=key,
    )
    if not release_result.ok:
        raise ValueError("invalid verifier release source: " + "; ".join(release_result.errors))
    root_path = Path(root)
    go_sources = _go_source_records(verifier_release)
    source = _go_verifier_build_source_summary(verifier_release, go_sources, conformance_report, standards_package)
    binary = _binary_record(root_path, binary_path)
    build_log = _sidecar_record(root_path, build_log_ref, "build_log")
    sbom = _sidecar_record(root_path, sbom_ref, "sbom")
    provenance = _sidecar_record(root_path, provenance_ref, "provenance")
    subject = _go_verifier_binary_signature_subject(
        source=source,
        binary=binary,
        build={"build_log_ref": build_log["ref"], "build_log_hash": build_log["sha256_ref"]},
        provenance={
            "sbom_ref": sbom["ref"],
            "sbom_hash": sbom["sha256_ref"],
            "provenance_ref": provenance["ref"],
            "provenance_hash": provenance["sha256_ref"],
        },
    )
    payload = {"schema": GO_VERIFIER_BINARY_SIGNATURE_SCHEMA, "generated_at": generated_at or utc_now(), "subject": subject}
    return {**payload, "signature": sign_value(payload, key)}


def build_go_verifier_build_attestation(
    verifier_release: dict[str, Any],
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    binary_path: str | Path | None = None,
    mode: str = "source-plan",
    builder_ref: str,
    toolchain_ref: str,
    toolchain_version: str,
    goos: str,
    goarch: str,
    cgo_enabled: bool = False,
    trimpath: bool = True,
    ldflags: str = "-s -w",
    build_command: str | None = None,
    build_log_ref: str | None = None,
    build_log_hash: str | None = None,
    sbom_ref: str | None = None,
    sbom_hash: str | None = None,
    provenance_ref: str | None = None,
    provenance_hash: str | None = None,
    signature_ref: str | None = None,
    signature_hash: str | None = None,
    build_started_at: str | None = None,
    build_finished_at: str | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in GO_VERIFIER_BUILD_MODES:
        raise ValueError(f"mode must be one of {sorted(GO_VERIFIER_BUILD_MODES)}")
    if mode == "binary-attested" and binary_path is None:
        raise ValueError("binary_path is required for binary-attested mode")
    for field, value in {
        "builder_ref": builder_ref,
        "toolchain_ref": toolchain_ref,
        "toolchain_version": toolchain_version,
        "goos": goos,
        "goarch": goarch,
    }.items():
        _require_text(value, field)

    release_result = verify_verifier_release_manifest(
        verifier_release,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        key=key,
    )
    if not release_result.ok:
        raise ValueError("invalid verifier release source: " + "; ".join(release_result.errors))

    started = build_started_at
    finished = build_finished_at
    if started:
        parse_rfc3339(started)
    if finished:
        parse_rfc3339(finished)
    if started and finished and parse_rfc3339(finished) < parse_rfc3339(started):
        raise ValueError("build_finished_at must be after build_started_at")
    timestamp = attested_at or utc_now()
    parse_rfc3339(timestamp)

    root_path = Path(root)
    go_sources = _go_source_records(verifier_release)
    binary = _binary_record(root_path, binary_path)
    build = {
        "mode": mode,
        "builder_ref": builder_ref,
        "toolchain_ref": toolchain_ref,
        "toolchain_version": toolchain_version,
        "goos": goos,
        "goarch": goarch,
        "cgo_enabled": bool(cgo_enabled),
        "trimpath": bool(trimpath),
        "ldflags": ldflags,
        "build_command": build_command or _default_build_command(goos, goarch, cgo_enabled, trimpath, ldflags),
        "build_started_at": started,
        "build_finished_at": finished,
        "build_log_ref": build_log_ref,
        "build_log_hash": build_log_hash,
    }
    provenance = {
        "sbom_ref": sbom_ref,
        "sbom_hash": sbom_hash,
        "provenance_ref": provenance_ref,
        "provenance_hash": provenance_hash,
        "signature_ref": signature_ref,
        "signature_hash": signature_hash,
    }
    source = _go_verifier_build_source_summary(verifier_release, go_sources, conformance_report, standards_package)
    binary_signature_subject = _go_verifier_binary_signature_subject(source=source, binary=binary, build=build, provenance=provenance)
    binary_signature = _go_verifier_binary_signature_verification(
        root_path,
        signature_ref,
        binary_signature_subject,
        key=key,
        required=mode == "binary-attested",
    )
    body = {
        "schema": GO_VERIFIER_BUILD_SCHEMA,
        "attested_at": timestamp,
        "source": source,
        "go_sources": go_sources,
        "build": build,
        "binary": binary,
        "provenance": provenance,
        "binary_signature": binary_signature,
        "controls": _controls(build, binary, provenance, binary_signature),
        "limitations": [
            "This attestation binds the Go verifier source and release manifest to static-build controls and optional binary evidence.",
            "source-plan mode records a reproducible build plan and source hashes but does not claim a compiled binary exists.",
            "recorded-build mode records build-log/provenance references supplied by a builder.",
            "binary-attested mode requires a binary hash and should be paired with external signature/SBOM/provenance evidence for production distribution.",
        ],
    }
    build_id = content_hash(body)
    return {
        **body,
        "build_id": build_id,
        "signatures": [sign_value({"build_id": build_id, "go_verifier_build": body}, key)],
    }


def verify_go_verifier_build_attestation(
    attestation: dict[str, Any],
    verifier_release: dict[str, Any] | None = None,
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    binary_path: str | Path | None = None,
    key: str | None = None,
) -> GoVerifierBuildVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != GO_VERIFIER_BUILD_SCHEMA:
        errors.append(f"unsupported Go verifier build schema: {attestation.get('schema')}")
    body = without_keys(attestation, "build_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("build_id") != expected_id:
        errors.append("build_id does not match canonical Go verifier build body")
    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("Go verifier build attestation must include at least one signature")
    else:
        signed_value = {"build_id": attestation.get("build_id"), "go_verifier_build": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("Go verifier build attestation signature verification failed")

    try:
        parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"Go verifier build attested_at invalid: {exc}")

    _verify_source(attestation.get("source"), errors)
    _verify_go_sources(attestation.get("go_sources"), errors)
    _verify_build(attestation.get("build"), errors, warnings)
    _verify_binary(attestation.get("binary"), attestation.get("build", {}).get("mode"), errors, warnings)
    _verify_provenance(attestation.get("provenance"), attestation.get("build", {}).get("mode"), errors, warnings)
    _verify_sidecar_hashes(attestation, Path(root), errors, warnings)
    _verify_binary_signature_replay(attestation, Path(root), key, errors, warnings)

    if verifier_release is None:
        warnings.append("verifier release source was not supplied; release/source bindings were not replayed")
    else:
        release_result = verify_verifier_release_manifest(
            verifier_release,
            root=root,
            conformance_report=conformance_report,
            standards_package=standards_package,
            key=key,
        )
        errors.extend(f"verifier release source: {error}" for error in release_result.errors)
        warnings.extend(f"verifier release source: {warning}" for warning in release_result.warnings)
        source = attestation.get("source", {})
        if isinstance(source, dict):
            expected_sources = _go_source_records(verifier_release)
            expected = {
                "release_id": verifier_release.get("release_id"),
                "release_hash": content_hash(verifier_release),
                "release_version": verifier_release.get("release", {}).get("version"),
                "go_source_count": len(expected_sources),
                "go_source_hash": content_hash(expected_sources),
            }
            for field, expected_value in expected.items():
                if source.get(field) != expected_value:
                    errors.append(f"Go verifier build source.{field} does not match verifier release")
            if attestation.get("go_sources") != expected_sources:
                errors.append("Go verifier build go_sources do not match verifier release source files")

    if binary_path is not None:
        expected_binary = _binary_record(Path(root), binary_path)
        binary = attestation.get("binary", {})
        if isinstance(binary, dict):
            for field in ("sha256", "size_bytes"):
                if binary.get(field) != expected_binary.get(field):
                    errors.append(f"Go verifier build binary.{field} does not match supplied binary")

    return GoVerifierBuildVerification(ok=not errors, errors=errors, warnings=warnings)


def append_go_verifier_build_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    verifier_release: dict[str, Any] | None = None,
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    binary_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_go_verifier_build_attestation(
        attestation,
        verifier_release,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        binary_path=binary_path,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid Go verifier build attestation: " + "; ".join(result.errors))
    payload = {
        "build_id": attestation["build_id"],
        "build_hash": content_hash(attestation),
        "source": attestation.get("source"),
        "build": attestation.get("build"),
        "binary": attestation.get("binary"),
        "provenance": attestation.get("provenance"),
        "binary_signature": attestation.get("binary_signature"),
        "controls": attestation.get("controls", []),
        "control_status_summary": _status_summary(attestation.get("controls", [])),
        "limitations": attestation.get("limitations", []),
    }
    return chain.append(GO_VERIFIER_BUILD_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _go_source_records(release: dict[str, Any]) -> list[dict[str, Any]]:
    records = [
        {
            "path": source.get("path"),
            "sha256": source.get("sha256"),
            "size_bytes": source.get("size_bytes"),
        }
        for source in release.get("source_files", [])
        if isinstance(source, dict) and str(source.get("path", "")).startswith("verifier/go/trustai-verify/")
    ]
    return sorted(records, key=lambda item: str(item.get("path")))


def _go_verifier_build_source_summary(
    verifier_release: dict[str, Any],
    go_sources: list[dict[str, Any]],
    conformance_report: dict[str, Any] | None,
    standards_package: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "release_id": verifier_release.get("release_id"),
        "release_hash": content_hash(verifier_release),
        "release_version": verifier_release.get("release", {}).get("version"),
        "go_source_count": len(go_sources),
        "go_source_hash": content_hash(go_sources),
        "conformance_report_id": conformance_report.get("report_id") if isinstance(conformance_report, dict) else verifier_release.get("conformance_report", {}).get("report_id"),
        "standards_package_id": standards_package.get("package_id") if isinstance(standards_package, dict) else verifier_release.get("standards_package", {}).get("package_id"),
    }


def _binary_record(root: Path, binary_path: str | Path | None) -> dict[str, Any]:
    if binary_path is None:
        return {
            "status": "not-built",
            "path": None,
            "sha256": None,
            "size_bytes": None,
            "format": "go-static-binary",
        }
    path = Path(binary_path)
    source_path = path if path.is_absolute() else root / path
    data = source_path.read_bytes()
    return {
        "status": "available",
        "path": str(binary_path).replace("\\", "/"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "format": "go-static-binary",
    }


def _default_build_command(goos: str, goarch: str, cgo_enabled: bool, trimpath: bool, ldflags: str) -> str:
    trim = " -trimpath" if trimpath else ""
    return f"CGO_ENABLED={1 if cgo_enabled else 0} GOOS={goos} GOARCH={goarch} go build{trim} -ldflags {json.dumps(ldflags)} -o dist/trustai-verify ./verifier/go/trustai-verify"


def _verify_source(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("Go verifier build source must be an object")
        return
    for field in ("release_id", "release_hash", "go_source_count", "go_source_hash"):
        if value.get(field) in (None, ""):
            errors.append(f"Go verifier build source.{field} is required")
    if not isinstance(value.get("go_source_count"), int) or value.get("go_source_count") < 2:
        errors.append("Go verifier build source.go_source_count must be an integer >= 2")


def _verify_go_sources(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append("Go verifier build go_sources must be a non-empty list")
        return
    paths = {item.get("path") for item in value if isinstance(item, dict)}
    for required in ("verifier/go/trustai-verify/main.go", "verifier/go/trustai-verify/go.mod"):
        if required not in paths:
            errors.append(f"Go verifier build go_sources missing {required}")
    for item in value:
        if not isinstance(item, dict):
            errors.append("Go verifier build go_sources entries must be objects")
            continue
        for field in ("path", "sha256", "size_bytes"):
            if item.get(field) in (None, ""):
                errors.append(f"Go verifier build source file {item.get('path')} missing {field}")


def _verify_build(value: Any, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("Go verifier build build must be an object")
        return
    mode = value.get("mode")
    if mode not in GO_VERIFIER_BUILD_MODES:
        errors.append("Go verifier build mode is unsupported")
    if value.get("cgo_enabled") is not False:
        errors.append("Go verifier build must set cgo_enabled=false for static verifier releases")
    if value.get("trimpath") is not True:
        errors.append("Go verifier build must set trimpath=true for reproducible verifier releases")
    for field in ("builder_ref", "toolchain_ref", "toolchain_version", "goos", "goarch", "build_command"):
        if not value.get(field):
            errors.append(f"Go verifier build build.{field} is required")
    if mode == "source-plan":
        warnings.append("Go verifier build is source-plan only; no compiled binary is claimed")
    if mode in {"recorded-build", "binary-attested"}:
        if not value.get("build_log_ref") or not value.get("build_log_hash"):
            errors.append("Go verifier build recorded modes require build_log_ref and build_log_hash")
    for field in ("build_started_at", "build_finished_at"):
        if value.get(field):
            try:
                parse_rfc3339(str(value.get(field)))
            except ValueError as exc:
                errors.append(f"Go verifier build {field} invalid: {exc}")
    if value.get("build_started_at") and value.get("build_finished_at"):
        if parse_rfc3339(str(value["build_finished_at"])) < parse_rfc3339(str(value["build_started_at"])):
            errors.append("Go verifier build build_finished_at must be after build_started_at")


def _verify_binary(value: Any, mode: str | None, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("Go verifier build binary must be an object")
        return
    if mode == "binary-attested":
        if value.get("status") != "available" or not value.get("sha256") or not value.get("size_bytes"):
            errors.append("Go verifier build binary-attested mode requires available binary sha256 and size")
    elif value.get("status") != "available":
        warnings.append("Go verifier static binary was not supplied; source and build controls only were attested")
    if value.get("sha256") and not _is_sha256(str(value.get("sha256"))):
        errors.append("Go verifier build binary.sha256 must be a SHA-256 hex digest")


def _verify_provenance(value: Any, mode: str | None, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("Go verifier build provenance must be an object")
        return
    if mode == "binary-attested":
        for field in ("sbom_ref", "sbom_hash", "provenance_ref", "provenance_hash", "signature_ref", "signature_hash"):
            if not value.get(field):
                errors.append(f"Go verifier build binary-attested mode requires provenance.{field}")
    elif not any(value.get(field) for field in ("sbom_hash", "provenance_hash", "signature_hash")):
        warnings.append("Go verifier build provenance has no SBOM, provenance, or signature hash")
    for field in ("sbom_hash", "provenance_hash", "signature_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"Go verifier build provenance.{field} must be a sha256 reference")


def _controls(build: dict[str, Any], binary: dict[str, Any], provenance: dict[str, Any], binary_signature: dict[str, Any]) -> list[dict[str, str]]:
    binary_available = binary.get("status") == "available" and binary.get("sha256")
    signature_verified = binary_signature.get("verified") is True
    return [
        {"id": "go-verifier-release-source-binding", "status": "attested", "description": "Go verifier source files are bound to the signed verifier release manifest."},
        {"id": "go-static-build-controls", "status": "attested" if build.get("cgo_enabled") is False and build.get("trimpath") is True else "planned-production", "description": "Static/reproducible build controls require CGO disabled, trimpath enabled, pinned target OS/architecture, and recorded build command."},
        {"id": "go-verifier-binary-hash", "status": "attested" if binary_available else "planned-production", "description": "Compiled verifier binary hash and size are bound when a binary artifact is supplied."},
        {"id": "go-verifier-supply-chain-provenance", "status": "attested" if provenance.get("provenance_hash") and provenance.get("signature_hash") and signature_verified else "planned-production", "description": "SBOM/provenance/signature references are bound and the binary signature artifact verifies for production verifier distribution."},
    ]



def _sidecar_record(root: Path, ref: str | Path, kind: str) -> dict[str, Any]:
    path = _local_ref_path(root, str(ref))
    if path is None:
        raise ValueError(f"Go verifier binary signature {kind} ref must be a local path")
    data = path.read_bytes()
    return {
        "kind": kind,
        "ref": str(ref).replace("\\", "/"),
        "sha256_ref": "sha256:" + hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _signature_ref_value(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value).replace("\\", "/")


def _go_verifier_binary_signature_subject(
    *,
    source: dict[str, Any],
    binary: dict[str, Any],
    build: dict[str, Any],
    provenance: dict[str, Any],
) -> dict[str, Any]:
    return {
        "source": {
            "release_id": source.get("release_id"),
            "release_hash": source.get("release_hash"),
            "release_version": source.get("release_version"),
            "go_source_count": source.get("go_source_count"),
            "go_source_hash": source.get("go_source_hash"),
        },
        "binary": {
            "path": binary.get("path"),
            "sha256": binary.get("sha256"),
            "size_bytes": binary.get("size_bytes"),
            "format": binary.get("format"),
        },
        "sidecars": [
            {"kind": "build_log", "ref": _signature_ref_value(build.get("build_log_ref")), "sha256_ref": build.get("build_log_hash")},
            {"kind": "sbom", "ref": _signature_ref_value(provenance.get("sbom_ref")), "sha256_ref": provenance.get("sbom_hash")},
            {"kind": "provenance", "ref": _signature_ref_value(provenance.get("provenance_ref")), "sha256_ref": provenance.get("provenance_hash")},
        ],
    }


def _go_verifier_binary_signature_verification(
    root: Path,
    signature_ref: Any,
    expected_subject: dict[str, Any],
    *,
    key: str | None,
    required: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": GO_VERIFIER_BINARY_SIGNATURE_SCHEMA,
        "path": str(signature_ref).replace("\\", "/") if signature_ref else None,
        "subject_hash": content_hash(expected_subject),
        "verified": False,
        "errors": [],
    }
    if not signature_ref:
        if required:
            result["errors"].append("Go verifier binary signature_ref is required for binary-attested mode")
        else:
            result["verified"] = None
        return result
    path = _local_ref_path(root, str(signature_ref))
    if path is None:
        result["errors"].append("Go verifier binary signature_ref must resolve to a local replay artifact")
        return result
    try:
        artifact = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        result["errors"].append(f"Go verifier binary signature artifact is not valid JSON: {exc}")
        return result
    if not isinstance(artifact, dict):
        result["errors"].append("Go verifier binary signature artifact must contain an object")
        return result
    if artifact.get("schema") != GO_VERIFIER_BINARY_SIGNATURE_SCHEMA:
        result["errors"].append(f"unsupported Go verifier binary signature schema: {artifact.get('schema')}")
    if artifact.get("subject") != expected_subject:
        result["errors"].append("Go verifier binary signature subject does not match replayed release, binary, build log, SBOM, and provenance bindings")
    payload = {"schema": artifact.get("schema"), "generated_at": artifact.get("generated_at"), "subject": artifact.get("subject")}
    signature = artifact.get("signature")
    if not isinstance(signature, dict) or not verify_value(payload, signature, key):
        result["errors"].append("Go verifier binary signature artifact signature verification failed")
    else:
        result["signature_key_id"] = signature.get("key_id")
        result["signature_provider"] = signature.get("provider")
    result["verified"] = not result["errors"]
    return result


def _verify_binary_signature_replay(attestation: dict[str, Any], root: Path, key: str | None, errors: list[str], warnings: list[str]) -> None:
    build = attestation.get("build") if isinstance(attestation.get("build"), dict) else {}
    mode = build.get("mode")
    expected_subject = _go_verifier_binary_signature_subject(
        source=attestation.get("source") if isinstance(attestation.get("source"), dict) else {},
        binary=attestation.get("binary") if isinstance(attestation.get("binary"), dict) else {},
        build=build,
        provenance=attestation.get("provenance") if isinstance(attestation.get("provenance"), dict) else {},
    )
    provenance = attestation.get("provenance") if isinstance(attestation.get("provenance"), dict) else {}
    expected = _go_verifier_binary_signature_verification(
        root,
        provenance.get("signature_ref"),
        expected_subject,
        key=key,
        required=mode == "binary-attested",
    )
    recorded = attestation.get("binary_signature")
    if mode == "binary-attested":
        if recorded != expected:
            errors.append("Go verifier build binary_signature does not match replayed signature artifact")
        if expected.get("verified") is not True:
            errors.extend(f"Go verifier binary signature: {error}" for error in expected.get("errors", []))
    elif isinstance(recorded, dict) and recorded.get("verified") is False:
        warnings.append("Go verifier binary signature artifact is present but did not verify in non-binary mode")


def _verify_sidecar_hashes(attestation: dict[str, Any], root: Path, errors: list[str], warnings: list[str]) -> None:
    build = attestation.get("build")
    provenance = attestation.get("provenance")
    if isinstance(build, dict):
        _verify_local_hash_ref(
            "Go verifier build build.build_log_hash",
            build.get("build_log_ref"),
            build.get("build_log_hash"),
            root,
            errors,
            warnings,
        )
    if isinstance(provenance, dict):
        for label, ref_field, hash_field in (
            ("Go verifier build provenance.sbom_hash", "sbom_ref", "sbom_hash"),
            ("Go verifier build provenance.provenance_hash", "provenance_ref", "provenance_hash"),
            ("Go verifier build provenance.signature_hash", "signature_ref", "signature_hash"),
        ):
            _verify_local_hash_ref(label, provenance.get(ref_field), provenance.get(hash_field), root, errors, warnings)


def _verify_local_hash_ref(label: str, ref: Any, expected_hash: Any, root: Path, errors: list[str], warnings: list[str]) -> None:
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
        return bool(value[7:])
    return _is_sha256(value)
