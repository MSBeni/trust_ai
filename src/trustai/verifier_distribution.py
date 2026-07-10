from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .standards import verify_standards_submission
from .verifier_conformance import verify_verifier_conformance_report
from .verifier_release import verifier_conformance_release_reference, verify_verifier_release_manifest

VERIFIER_DISTRIBUTION_SCHEMA = "trustai.verifier-distribution/0.1"
VERIFIER_DISTRIBUTION_ENTRY_TYPE = "verifier.source_distribution_attested"
VERIFIER_SOURCE_SBOM_SCHEMA = "trustai.verifier-source-sbom/0.1"
VERIFIER_SOURCE_PROVENANCE_SCHEMA = "trustai.verifier-source-provenance/0.1"
VERIFIER_SOURCE_SIGNATURE_SCHEMA = "trustai.verifier-source-bundle-signature/0.1"


@dataclass
class VerifierDistributionVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_verifier_distribution_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("verifier distribution receipt must contain an object")
    return value


def write_verifier_distribution_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_verifier_distribution_receipt(
    verifier_release: dict[str, Any],
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    bundle_path: str | Path,
    sbom_path: str | Path,
    provenance_path: str | Path,
    signature_path: str | Path,
    distribution_ref: str,
    channel: str = "local-source-bundle",
    publisher_ref: str,
    release_url: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    for field, value in {
        "distribution_ref": distribution_ref,
        "channel": channel,
        "publisher_ref": publisher_ref,
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

    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    root_path = Path(root)

    bundle_entries = _bundle_entries(verifier_release, root_path, conformance_report, standards_package)
    _write_bundle(root_path, bundle_path, bundle_entries)
    bundle_artifact = _artifact_record(bundle_path, "application/zip")

    release_reference = _release_reference(verifier_release, conformance_report, standards_package)
    sbom = _build_sbom(timestamp, release_reference, bundle_artifact, bundle_entries)
    _write_json_artifact(sbom_path, sbom)
    sbom_artifact = _json_artifact_record(sbom_path, sbom)

    provenance = _build_provenance(
        timestamp,
        release_reference,
        bundle_artifact,
        sbom_artifact,
        bundle_entries,
        distribution_ref=distribution_ref,
        channel=channel,
        publisher_ref=publisher_ref,
        release_url=release_url,
    )
    _write_json_artifact(provenance_path, provenance)
    provenance_artifact = _json_artifact_record(provenance_path, provenance)

    signature_subject = {
        "release_id": verifier_release.get("release_id"),
        "bundle_sha256": bundle_artifact["sha256"],
        "sbom_content_hash": sbom_artifact["content_hash"],
        "provenance_content_hash": provenance_artifact["content_hash"],
        "distribution_ref": distribution_ref,
    }
    signature_doc = {
        "schema": VERIFIER_SOURCE_SIGNATURE_SCHEMA,
        "signed_at": timestamp,
        "subject": signature_subject,
        "signatures": [sign_value(signature_subject, key)],
    }
    signature_doc["signature_id"] = content_hash(without_keys(signature_doc, "signature_id"))
    _write_json_artifact(signature_path, signature_doc)
    signature_artifact = _json_artifact_record(signature_path, signature_doc)

    body = {
        "schema": VERIFIER_DISTRIBUTION_SCHEMA,
        "generated_at": timestamp,
        "distribution": {
            "distribution_ref": distribution_ref,
            "channel": channel,
            "publisher_ref": publisher_ref,
            "release_url": release_url,
            "mode": "source-bundle",
            "accountless_verification": True,
        },
        "release": release_reference,
        "artifacts": {
            "bundle": bundle_artifact,
            "sbom": sbom_artifact,
            "provenance": provenance_artifact,
            "signature": signature_artifact,
            "bundle_entries_hash": content_hash(_public_bundle_entries(bundle_entries)),
            "bundle_file_count": len(bundle_entries),
        },
        "signature_subject": signature_subject,
        "controls": _controls(bundle_artifact, sbom_artifact, provenance_artifact, signature_artifact),
        "limitations": [
            "This receipt proves a verifier source distribution bundle, SBOM, provenance, and detached signature artifact.",
            "It does not claim that a compiled static Go verifier binary exists.",
            "Production binary releases still require a Go toolchain run, binary hash, binary SBOM/provenance, and public release signature.",
        ],
    }
    distribution_id = content_hash(body)
    return {
        **body,
        "distribution_id": distribution_id,
        "signatures": [sign_value({"distribution_id": distribution_id, "verifier_distribution": body}, key)],
    }


def verify_verifier_distribution_receipt(
    receipt: dict[str, Any],
    verifier_release: dict[str, Any] | None = None,
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    bundle_path: str | Path | None = None,
    sbom_path: str | Path | None = None,
    provenance_path: str | Path | None = None,
    signature_path: str | Path | None = None,
    key: str | None = None,
) -> VerifierDistributionVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != VERIFIER_DISTRIBUTION_SCHEMA:
        errors.append(f"unsupported verifier distribution schema: {receipt.get('schema')}")
    body = without_keys(receipt, "distribution_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("distribution_id") != expected_id:
        errors.append("distribution_id does not match canonical verifier distribution body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("verifier distribution receipt must include at least one signature")
    else:
        signed_value = {"distribution_id": receipt.get("distribution_id"), "verifier_distribution": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("verifier distribution receipt signature verification failed")

    try:
        parse_rfc3339(str(receipt.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"verifier distribution generated_at invalid: {exc}")

    _verify_distribution(receipt.get("distribution"), errors)
    _verify_artifacts(receipt.get("artifacts"), errors)
    _verify_signature_subject(receipt.get("signature_subject"), receipt.get("artifacts"), errors)

    if verifier_release is None:
        warnings.append("verifier release source was not supplied; source distribution bindings were not replayed")
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
        expected_release = _release_reference(verifier_release, conformance_report, standards_package)
        if receipt.get("release") != expected_release:
            errors.append("verifier distribution release binding does not match supplied verifier release")

    root_path = Path(root)
    _verify_bundle_file(receipt, root_path, bundle_path, verifier_release, conformance_report, standards_package, errors)
    _verify_json_artifact("sbom", receipt, sbom_path, VERIFIER_SOURCE_SBOM_SCHEMA, errors)
    _verify_json_artifact("provenance", receipt, provenance_path, VERIFIER_SOURCE_PROVENANCE_SCHEMA, errors)
    _verify_signature_artifact(receipt, signature_path, key, errors)

    if conformance_report is not None:
        result = verify_verifier_conformance_report(conformance_report)
        errors.extend(f"conformance report invalid: {error}" for error in result.errors)
    if standards_package is not None:
        result = verify_standards_submission(standards_package, root=root_path)
        errors.extend(f"standards package invalid: {error}" for error in result.errors)

    return VerifierDistributionVerification(ok=not errors, errors=errors, warnings=warnings)


def append_verifier_distribution_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    verifier_release: dict[str, Any] | None = None,
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    bundle_path: str | Path | None = None,
    sbom_path: str | Path | None = None,
    provenance_path: str | Path | None = None,
    signature_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_verifier_distribution_receipt(
        receipt,
        verifier_release,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        bundle_path=bundle_path,
        sbom_path=sbom_path,
        provenance_path=provenance_path,
        signature_path=signature_path,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid verifier distribution receipt: " + "; ".join(result.errors))
    payload = {
        "distribution_id": receipt["distribution_id"],
        "distribution_hash": content_hash(receipt),
        "distribution": receipt.get("distribution"),
        "release": receipt.get("release"),
        "artifacts": receipt.get("artifacts"),
        "signature_subject": receipt.get("signature_subject"),
        "controls": receipt.get("controls", []),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(VERIFIER_DISTRIBUTION_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("generated_at"))


def _bundle_entries(
    verifier_release: dict[str, Any],
    root: Path,
    conformance_report: dict[str, Any] | None,
    standards_package: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = [
        _json_bundle_entry("manifest/verifier-release.json", verifier_release, "release-manifest"),
    ]
    if conformance_report is not None:
        entries.append(_json_bundle_entry("evidence/verifier-conformance.json", conformance_report, "conformance-report"))
    if standards_package is not None:
        entries.append(_json_bundle_entry("evidence/standards-submission.json", standards_package, "standards-package"))
    for source in verifier_release.get("source_files", []):
        if not isinstance(source, dict):
            continue
        source_path = str(source.get("path") or "")
        if not source_path:
            continue
        data = _resolve_under_root(root, source_path).read_bytes()
        entries.append(
            {
                "path": f"source/{source_path}",
                "role": "source-file",
                "source_path": source_path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
                "data": data,
            }
        )
    return sorted(entries, key=lambda item: str(item["path"]))


def _json_bundle_entry(path: str, value: dict[str, Any], role: str) -> dict[str, Any]:
    data = json.dumps(value, indent=2, sort_keys=True).encode("utf-8")
    return {
        "path": path,
        "role": role,
        "source_path": None,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "data": data,
    }


def _write_bundle(root: Path, bundle_path: str | Path, entries: list[dict[str, Any]]) -> None:
    target = _artifact_path(root, bundle_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in entries:
            info = zipfile.ZipInfo(str(entry["path"]))
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, entry["data"])


def _public_bundle_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "path": entry["path"],
            "role": entry["role"],
            "source_path": entry.get("source_path"),
            "sha256": entry["sha256"],
            "size_bytes": entry["size_bytes"],
        }
        for entry in entries
    ]


def _build_sbom(
    timestamp: str,
    release_reference: dict[str, Any],
    bundle_artifact: dict[str, Any],
    bundle_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    body = {
        "schema": VERIFIER_SOURCE_SBOM_SCHEMA,
        "generated_at": timestamp,
        "format": "trustai-source-file-inventory",
        "release": release_reference,
        "subject": {
            "artifact": bundle_artifact["path"],
            "sha256": bundle_artifact["sha256"],
            "size_bytes": bundle_artifact["size_bytes"],
        },
        "files": _public_bundle_entries(bundle_entries),
    }
    return {**body, "sbom_id": content_hash(body)}


def _build_provenance(
    timestamp: str,
    release_reference: dict[str, Any],
    bundle_artifact: dict[str, Any],
    sbom_artifact: dict[str, Any],
    bundle_entries: list[dict[str, Any]],
    *,
    distribution_ref: str,
    channel: str,
    publisher_ref: str,
    release_url: str | None,
) -> dict[str, Any]:
    body = {
        "schema": VERIFIER_SOURCE_PROVENANCE_SCHEMA,
        "generated_at": timestamp,
        "predicate_type": "trustai.verifier-source-provenance/0.1",
        "builder": {
            "id": "trustai.local-source-bundler",
            "mode": "source-bundle",
            "command": "python -m trustai verifier-distribution",
        },
        "distribution": {
            "distribution_ref": distribution_ref,
            "channel": channel,
            "publisher_ref": publisher_ref,
            "release_url": release_url,
        },
        "materials": [
            {
                "uri": "verifier-release",
                "digest": {"sha256": release_reference.get("release_hash")},
                "release_id": release_reference.get("release_id"),
            },
            {
                "uri": "standards-submission",
                "digest": {"sha256": release_reference.get("standards_package_hash")},
                "package_id": release_reference.get("standards_package_id"),
            },
            {
                "uri": "verifier-conformance",
                "digest": {"sha256": release_reference.get("conformance_report_hash")},
                "report_id": release_reference.get("conformance_report_id"),
                "targets": release_reference.get("conformance_targets", []),
                "case_count_by_target": release_reference.get("conformance_case_count_by_target", {}),
                "source_provider_bundle": release_reference.get("conformance_source_provider_bundle"),
            },
        ],
        "subject": [
            {
                "name": bundle_artifact["path"],
                "digest": {"sha256": bundle_artifact["sha256"]},
                "size_bytes": bundle_artifact["size_bytes"],
            },
            {
                "name": sbom_artifact["path"],
                "digest": {"sha256": sbom_artifact["sha256"], "content_hash": sbom_artifact["content_hash"]},
                "size_bytes": sbom_artifact["size_bytes"],
            },
        ],
        "source_file_count": sum(1 for entry in bundle_entries if entry["role"] == "source-file"),
        "bundle_entries_hash": content_hash(_public_bundle_entries(bundle_entries)),
    }
    return {**body, "provenance_id": content_hash(body)}


def _release_reference(
    verifier_release: dict[str, Any],
    conformance_report: dict[str, Any] | None,
    standards_package: dict[str, Any] | None,
) -> dict[str, Any]:
    conformance_ref = verifier_release.get("conformance_report", {}) if isinstance(verifier_release.get("conformance_report"), dict) else {}
    conformance_summary = verifier_conformance_release_reference(conformance_report) if isinstance(conformance_report, dict) else conformance_ref
    standards_ref = verifier_release.get("standards_package", {}) if isinstance(verifier_release.get("standards_package"), dict) else {}
    return {
        "release_id": verifier_release.get("release_id"),
        "release_hash": content_hash(verifier_release),
        "release_version": verifier_release.get("release", {}).get("version"),
        "release_license": verifier_release.get("release", {}).get("license"),
        "source_file_count": len(verifier_release.get("source_files", [])),
        "source_files_hash": content_hash(verifier_release.get("source_files", [])),
        "conformance_report_id": conformance_summary.get("report_id"),
        "conformance_report_hash": conformance_summary.get("content_hash"),
        "conformance_case_count": conformance_summary.get("case_count"),
        "conformance_passed_count": conformance_summary.get("passed_count"),
        "conformance_failed_count": conformance_summary.get("failed_count"),
        "conformance_targets": conformance_summary.get("targets", []),
        "conformance_case_count_by_target": conformance_summary.get("case_count_by_target", {}),
        "conformance_passed_count_by_target": conformance_summary.get("passed_count_by_target", {}),
        "conformance_source_provider_bundle": conformance_summary.get("source_provider_bundle"),
        "standards_package_id": standards_package.get("package_id") if isinstance(standards_package, dict) else standards_ref.get("package_id"),
        "standards_package_hash": content_hash(standards_package) if isinstance(standards_package, dict) else standards_ref.get("content_hash"),
    }


def _artifact_record(path: str | Path, media_type: str) -> dict[str, Any]:
    target = Path(path)
    data = target.read_bytes()
    return {
        "path": str(path).replace("\\", "/"),
        "media_type": media_type,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _json_artifact_record(path: str | Path, value: dict[str, Any]) -> dict[str, Any]:
    record = _artifact_record(path, "application/json")
    record["content_hash"] = content_hash(value)
    return record


def _write_json_artifact(path: str | Path, value: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def _artifact_path(root: Path, path: str | Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else root / value


def _resolve_under_root(root: Path, relative_path: str) -> Path:
    value = Path(relative_path)
    if value.is_absolute():
        raise ValueError(f"source path must be relative: {relative_path}")
    target = (root / value).resolve()
    root_resolved = root.resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError(f"source path escapes root: {relative_path}")
    return target


def _verify_distribution(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("verifier distribution metadata must be an object")
        return
    for field in ("distribution_ref", "channel", "publisher_ref", "mode"):
        if not value.get(field):
            errors.append(f"verifier distribution.{field} is required")
    if value.get("mode") != "source-bundle":
        errors.append("verifier distribution mode must be source-bundle")
    if value.get("accountless_verification") is not True:
        errors.append("verifier distribution must be accountless-verification capable")


def _verify_artifacts(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("verifier distribution artifacts must be an object")
        return
    for field in ("bundle", "sbom", "provenance", "signature"):
        artifact = value.get(field)
        if not isinstance(artifact, dict):
            errors.append(f"verifier distribution artifacts.{field} must be an object")
            continue
        for required in ("path", "sha256", "size_bytes", "media_type"):
            if artifact.get(required) in (None, ""):
                errors.append(f"verifier distribution artifacts.{field}.{required} is required")
        if artifact.get("sha256") and not _is_sha256(str(artifact.get("sha256"))):
            errors.append(f"verifier distribution artifacts.{field}.sha256 must be a SHA-256 hex digest")
    if not isinstance(value.get("bundle_file_count"), int) or value.get("bundle_file_count") < 3:
        errors.append("verifier distribution bundle_file_count must be an integer >= 3")
    if not value.get("bundle_entries_hash"):
        errors.append("verifier distribution bundle_entries_hash is required")


def _verify_signature_subject(subject: Any, artifacts: Any, errors: list[str]) -> None:
    if not isinstance(subject, dict):
        errors.append("verifier distribution signature_subject must be an object")
        return
    if not isinstance(artifacts, dict):
        return
    bundle = artifacts.get("bundle", {}) if isinstance(artifacts.get("bundle"), dict) else {}
    sbom = artifacts.get("sbom", {}) if isinstance(artifacts.get("sbom"), dict) else {}
    provenance = artifacts.get("provenance", {}) if isinstance(artifacts.get("provenance"), dict) else {}
    checks = {
        "bundle_sha256": bundle.get("sha256"),
        "sbom_content_hash": sbom.get("content_hash"),
        "provenance_content_hash": provenance.get("content_hash"),
    }
    for field, expected in checks.items():
        if subject.get(field) != expected:
            errors.append(f"verifier distribution signature_subject.{field} does not match artifacts")


def _verify_bundle_file(
    receipt: dict[str, Any],
    root: Path,
    bundle_path: str | Path | None,
    verifier_release: dict[str, Any] | None,
    conformance_report: dict[str, Any] | None,
    standards_package: dict[str, Any] | None,
    errors: list[str],
) -> None:
    if bundle_path is None:
        return
    target = _artifact_path(root, bundle_path)
    if not target.exists():
        errors.append(f"verifier source bundle missing: {bundle_path}")
        return
    bundle_artifact = receipt.get("artifacts", {}).get("bundle", {}) if isinstance(receipt.get("artifacts"), dict) else {}
    actual = _artifact_record(target, "application/zip")
    for field in ("sha256", "size_bytes"):
        if bundle_artifact.get(field) != actual.get(field):
            errors.append(f"verifier source bundle {field} mismatch")
    if verifier_release is None:
        return
    expected_entries = _bundle_entries(verifier_release, root, conformance_report, standards_package)
    if receipt.get("artifacts", {}).get("bundle_entries_hash") != content_hash(_public_bundle_entries(expected_entries)):
        errors.append("verifier source bundle entries hash does not match source inputs")
    try:
        with zipfile.ZipFile(target, "r") as archive:
            names = sorted(archive.namelist())
            expected_names = sorted(str(entry["path"]) for entry in expected_entries)
            if names != expected_names:
                errors.append("verifier source bundle file list does not match source inputs")
                return
            for entry in expected_entries:
                data = archive.read(str(entry["path"]))
                if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                    errors.append(f"verifier source bundle entry hash mismatch: {entry['path']}")
    except (OSError, zipfile.BadZipFile) as exc:
        errors.append(f"verifier source bundle is not a readable zip file: {exc}")


def _verify_json_artifact(name: str, receipt: dict[str, Any], path: str | Path | None, schema: str, errors: list[str]) -> None:
    if path is None:
        return
    target = Path(path)
    if not target.exists():
        errors.append(f"verifier distribution {name} artifact missing: {path}")
        return
    try:
        value = json.loads(target.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        errors.append(f"verifier distribution {name} artifact is not valid JSON: {exc}")
        return
    if not isinstance(value, dict):
        errors.append(f"verifier distribution {name} artifact must contain an object")
        return
    if value.get("schema") != schema:
        errors.append(f"verifier distribution {name} artifact schema mismatch")
    expected = receipt.get("artifacts", {}).get(name, {}) if isinstance(receipt.get("artifacts"), dict) else {}
    actual = _json_artifact_record(target, value)
    for field in ("sha256", "size_bytes", "content_hash"):
        if expected.get(field) != actual.get(field):
            errors.append(f"verifier distribution {name} artifact {field} mismatch")


def _verify_signature_artifact(
    receipt: dict[str, Any],
    path: str | Path | None,
    key: str | None,
    errors: list[str],
) -> None:
    if path is None:
        return
    _verify_json_artifact("signature", receipt, path, VERIFIER_SOURCE_SIGNATURE_SCHEMA, errors)
    target = Path(path)
    if not target.exists():
        return
    value = json.loads(target.read_text(encoding="utf-8-sig"))
    subject = receipt.get("signature_subject")
    if value.get("subject") != subject:
        errors.append("verifier distribution signature artifact subject mismatch")
    signatures = value.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("verifier distribution signature artifact must include a signature")
    elif not any(isinstance(signature, dict) and verify_value(subject, signature, key) for signature in signatures):
        errors.append("verifier distribution signature artifact verification failed")
    expected_id = content_hash(without_keys(value, "signature_id"))
    if value.get("signature_id") != expected_id:
        errors.append("verifier distribution signature artifact id mismatch")


def _controls(
    bundle_artifact: dict[str, Any],
    sbom_artifact: dict[str, Any],
    provenance_artifact: dict[str, Any],
    signature_artifact: dict[str, Any],
) -> list[dict[str, str]]:
    return [
        {"id": "verifier-source-bundle", "status": "attested" if bundle_artifact.get("sha256") else "missing", "description": "Verifier release source files and evidence are packaged into a hash-bound source bundle."},
        {"id": "verifier-source-sbom", "status": "attested" if sbom_artifact.get("content_hash") else "missing", "description": "Source distribution includes a file inventory SBOM for offline review."},
        {"id": "verifier-source-provenance", "status": "attested" if provenance_artifact.get("content_hash") else "missing", "description": "Source distribution includes provenance materials and builder metadata."},
        {"id": "verifier-source-detached-signature", "status": "attested" if signature_artifact.get("content_hash") else "missing", "description": "Source distribution includes a detached signature over bundle, SBOM, provenance, and release bindings."},
    ]


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

