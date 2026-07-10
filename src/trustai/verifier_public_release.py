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
from .go_verifier_release_run import verify_go_verifier_release_run_receipt
from .go_verifier_release_run_bundle import verify_go_verifier_release_run_bundle
from .verifier_distribution import verify_verifier_distribution_receipt
from .verifier_release import verify_verifier_release_manifest

VERIFIER_PUBLIC_RELEASE_SCHEMA = "trustai.verifier-public-release/0.1"
VERIFIER_PUBLIC_RELEASE_ENTRY_TYPE = "verifier.public_release_attested"
VERIFIER_PUBLIC_RELEASE_MODES = {"local-reference", "provider-attested", "public-release"}


@dataclass
class VerifierPublicReleaseVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_verifier_public_release_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("verifier public release receipt must contain an object")
    return value


def write_verifier_public_release_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_verifier_public_release_receipt(
    verifier_release: dict[str, Any],
    distribution_receipt: dict[str, Any],
    build_attestation: dict[str, Any],
    release_run: dict[str, Any],
    release_run_bundle: dict[str, Any],
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    distribution_bundle_path: str | Path | None = None,
    distribution_sbom_path: str | Path | None = None,
    distribution_provenance_path: str | Path | None = None,
    distribution_signature_path: str | Path | None = None,
    binary_path: str | Path | None = None,
    public_artifacts: list[dict[str, Any]],
    mode: str = "public-release",
    provider: str,
    release_ref: str,
    release_url: str,
    tag: str,
    publisher_ref: str,
    workflow_run_export_ref: str | None = None,
    workflow_run_export_hash: str | None = None,
    release_api_export_ref: str | None = None,
    release_api_export_hash: str | None = None,
    artifact_manifest_ref: str | None = None,
    artifact_manifest_hash: str | None = None,
    audit_log_ref: str | None = None,
    audit_log_root: str | None = None,
    audit_log_size: int | None = None,
    transparency_log_ref: str | None = None,
    transparency_log_root: str | None = None,
    retention_until: str | None = None,
    published_at: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in VERIFIER_PUBLIC_RELEASE_MODES:
        raise ValueError(f"mode must be one of {sorted(VERIFIER_PUBLIC_RELEASE_MODES)}")
    for field, value in {
        "provider": provider,
        "release_ref": release_ref,
        "release_url": release_url,
        "tag": tag,
        "publisher_ref": publisher_ref,
    }.items():
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    if published_at:
        parse_rfc3339(published_at)
    if retention_until:
        parse_rfc3339(retention_until)
    if published_at and retention_until and parse_rfc3339(retention_until) < parse_rfc3339(published_at):
        raise ValueError("retention_until must be after published_at")

    _verify_composed_sources(
        verifier_release,
        distribution_receipt,
        build_attestation,
        release_run,
        release_run_bundle,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        distribution_bundle_path=distribution_bundle_path,
        distribution_sbom_path=distribution_sbom_path,
        distribution_provenance_path=distribution_provenance_path,
        distribution_signature_path=distribution_signature_path,
        binary_path=binary_path,
        key=key,
    )
    artifact_records = [_artifact_record(item) for item in public_artifacts]
    _assert_artifact_bindings(distribution_receipt, release_run, artifact_records)

    public_release = {
        "mode": mode,
        "provider": provider,
        "release_ref": release_ref,
        "release_url": release_url,
        "tag": tag,
        "publisher_ref": publisher_ref,
        "published_at": published_at,
    }
    provider_evidence = {
        "workflow_run_export_ref": workflow_run_export_ref,
        "workflow_run_export_hash": workflow_run_export_hash,
        "release_api_export_ref": release_api_export_ref,
        "release_api_export_hash": release_api_export_hash,
        "artifact_manifest_ref": artifact_manifest_ref,
        "artifact_manifest_hash": artifact_manifest_hash,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "audit_log_size": audit_log_size,
        "transparency_log_ref": transparency_log_ref,
        "transparency_log_root": transparency_log_root,
        "retention_until": retention_until,
    }
    body = {
        "schema": VERIFIER_PUBLIC_RELEASE_SCHEMA,
        "generated_at": timestamp,
        "public_release": public_release,
        "source": _source_summary(
            verifier_release,
            distribution_receipt,
            build_attestation,
            release_run,
            release_run_bundle,
            conformance_report,
            standards_package,
        ),
        "artifacts": artifact_records,
        "provider_evidence": provider_evidence,
        "controls": _controls(distribution_receipt, release_run, release_run_bundle, artifact_records, provider_evidence, mode),
        "limitations": [
            "This receipt binds a verifier release to public release metadata, source distribution artifacts, Go build evidence, release workflow-run evidence, and provider-native export hashes.",
            "It verifies local artifact bytes when supplied and records public/provider evidence refs by hash for third-party replay.",
            "It is not itself a live GitHub or release-provider API call; production authority requires the referenced provider-native exports and immutable audit logs to be retained by the release provider or customer.",
        ],
    }
    release_publication_id = content_hash(body)
    return {
        **body,
        "release_publication_id": release_publication_id,
        "signatures": [sign_value({"release_publication_id": release_publication_id, "verifier_public_release": body}, key)],
    }


def verify_verifier_public_release_receipt(
    receipt: dict[str, Any],
    verifier_release: dict[str, Any] | None = None,
    distribution_receipt: dict[str, Any] | None = None,
    build_attestation: dict[str, Any] | None = None,
    release_run: dict[str, Any] | None = None,
    release_run_bundle: dict[str, Any] | None = None,
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    distribution_bundle_path: str | Path | None = None,
    distribution_sbom_path: str | Path | None = None,
    distribution_provenance_path: str | Path | None = None,
    distribution_signature_path: str | Path | None = None,
    binary_path: str | Path | None = None,
    key: str | None = None,
) -> VerifierPublicReleaseVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != VERIFIER_PUBLIC_RELEASE_SCHEMA:
        errors.append(f"unsupported verifier public release schema: {receipt.get('schema')}")
    body = without_keys(receipt, "release_publication_id", "signatures")
    if receipt.get("release_publication_id") != content_hash(body):
        errors.append("release_publication_id does not match canonical verifier public release body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("verifier public release receipt must include at least one signature")
    else:
        signed_value = {"release_publication_id": receipt.get("release_publication_id"), "verifier_public_release": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("verifier public release signature verification failed")

    try:
        parse_rfc3339(str(receipt.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"verifier public release generated_at invalid: {exc}")
    _verify_public_release(receipt.get("public_release"), errors)
    _verify_provider_evidence(receipt.get("provider_evidence"), receipt.get("public_release"), errors, warnings)
    _verify_artifacts(receipt.get("artifacts"), errors)

    if all(item is not None for item in (verifier_release, distribution_receipt, build_attestation, release_run, release_run_bundle)):
        _verify_composed_sources(
            verifier_release,
            distribution_receipt,
            build_attestation,
            release_run,
            release_run_bundle,
            root=root,
            conformance_report=conformance_report,
            standards_package=standards_package,
            distribution_bundle_path=distribution_bundle_path,
            distribution_sbom_path=distribution_sbom_path,
            distribution_provenance_path=distribution_provenance_path,
            distribution_signature_path=distribution_signature_path,
            binary_path=binary_path,
            key=key,
            errors=errors,
            warnings=warnings,
        )
        expected_source = _source_summary(
            verifier_release,
            distribution_receipt,
            build_attestation,
            release_run,
            release_run_bundle,
            conformance_report,
            standards_package,
        )
        if receipt.get("source") != expected_source:
            errors.append("verifier public release source summary does not match supplied sources")
        artifacts = receipt.get("artifacts") if isinstance(receipt.get("artifacts"), list) else []
        _verify_artifact_bindings(distribution_receipt, release_run, artifacts, errors)
        expected_controls = _controls(distribution_receipt, release_run, release_run_bundle, artifacts, receipt.get("provider_evidence"), receipt.get("public_release", {}).get("mode"))
        if receipt.get("controls") != expected_controls:
            errors.append("verifier public release controls do not match supplied sources")
    else:
        warnings.append("public release source receipts were not all supplied; deep source bindings were not replayed")

    return VerifierPublicReleaseVerification(ok=not errors, errors=errors, warnings=warnings)


def append_verifier_public_release_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    verifier_release: dict[str, Any] | None = None,
    distribution_receipt: dict[str, Any] | None = None,
    build_attestation: dict[str, Any] | None = None,
    release_run: dict[str, Any] | None = None,
    release_run_bundle: dict[str, Any] | None = None,
    *,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    distribution_bundle_path: str | Path | None = None,
    distribution_sbom_path: str | Path | None = None,
    distribution_provenance_path: str | Path | None = None,
    distribution_signature_path: str | Path | None = None,
    binary_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_verifier_public_release_receipt(
        receipt,
        verifier_release,
        distribution_receipt,
        build_attestation,
        release_run,
        release_run_bundle,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        distribution_bundle_path=distribution_bundle_path,
        distribution_sbom_path=distribution_sbom_path,
        distribution_provenance_path=distribution_provenance_path,
        distribution_signature_path=distribution_signature_path,
        binary_path=binary_path,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid verifier public release receipt: " + "; ".join(result.errors))
    payload = {
        "release_publication_id": receipt["release_publication_id"],
        "release_publication_hash": content_hash(receipt),
        "public_release": receipt.get("public_release"),
        "source": receipt.get("source"),
        "artifact_count": len(receipt.get("artifacts", [])),
        "provider_evidence": receipt.get("provider_evidence"),
        "controls": receipt.get("controls", []),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(VERIFIER_PUBLIC_RELEASE_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("public_release", {}).get("published_at") or receipt.get("generated_at"))


def parse_public_release_artifact_arg(value: str) -> dict[str, str]:
    parts = [part.strip() for part in value.split(",", 3)]
    if len(parts) < 3 or not parts[0] or not parts[1] or not parts[2]:
        raise ValueError("--artifact must be name,path,kind[,url]")
    item = {"name": parts[0], "path": parts[1], "kind": parts[2]}
    if len(parts) == 4 and parts[3]:
        item["url"] = parts[3]
    return item


def _verify_composed_sources(
    verifier_release: dict[str, Any],
    distribution_receipt: dict[str, Any],
    build_attestation: dict[str, Any],
    release_run: dict[str, Any],
    release_run_bundle: dict[str, Any],
    *,
    root: str | Path,
    conformance_report: dict[str, Any] | None,
    standards_package: dict[str, Any] | None,
    distribution_bundle_path: str | Path | None,
    distribution_sbom_path: str | Path | None,
    distribution_provenance_path: str | Path | None,
    distribution_signature_path: str | Path | None,
    binary_path: str | Path | None,
    key: str | None,
    errors: list[str] | None = None,
    warnings: list[str] | None = None,
) -> None:
    local_errors: list[str] = []
    local_warnings: list[str] = []
    release_result = verify_verifier_release_manifest(
        verifier_release,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        key=key,
    )
    local_errors.extend(f"verifier release source: {error}" for error in release_result.errors)
    local_warnings.extend(f"verifier release source: {warning}" for warning in release_result.warnings)
    distribution_result = verify_verifier_distribution_receipt(
        distribution_receipt,
        verifier_release,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        bundle_path=distribution_bundle_path,
        sbom_path=distribution_sbom_path,
        provenance_path=distribution_provenance_path,
        signature_path=distribution_signature_path,
        key=key,
    )
    local_errors.extend(f"verifier distribution source: {error}" for error in distribution_result.errors)
    local_warnings.extend(f"verifier distribution source: {warning}" for warning in distribution_result.warnings)
    build_result = verify_go_verifier_build_attestation(
        build_attestation,
        verifier_release,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        binary_path=binary_path,
        key=key,
    )
    local_errors.extend(f"Go verifier build source: {error}" for error in build_result.errors)
    local_warnings.extend(f"Go verifier build source: {warning}" for warning in build_result.warnings)
    run_result = verify_go_verifier_release_run_receipt(
        release_run,
        verifier_release,
        build_attestation,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        binary_path=binary_path,
        key=key,
    )
    local_errors.extend(f"Go verifier release-run source: {error}" for error in run_result.errors)
    local_warnings.extend(f"Go verifier release-run source: {warning}" for warning in run_result.warnings)
    bundle_result = verify_go_verifier_release_run_bundle(release_run_bundle, key=key)
    local_errors.extend(f"Go verifier release-run bundle source: {error}" for error in bundle_result.errors)
    local_warnings.extend(f"Go verifier release-run bundle source: {warning}" for warning in bundle_result.warnings)

    expected = {
        "release_hash": content_hash(verifier_release),
        "distribution_hash": content_hash(distribution_receipt),
        "build_hash": content_hash(build_attestation),
        "run_hash": content_hash(release_run),
        "bundle_hash": content_hash(release_run_bundle),
    }
    bundle_source = release_run_bundle.get("source", {}) if isinstance(release_run_bundle.get("source"), dict) else {}
    if bundle_source.get("release_hash") != expected["release_hash"]:
        local_errors.append("release-run bundle source.release_hash does not match verifier release")
    if bundle_source.get("build_hash") != expected["build_hash"]:
        local_errors.append("release-run bundle source.build_hash does not match Go build attestation")
    if bundle_source.get("run_hash") != expected["run_hash"]:
        local_errors.append("release-run bundle source.run_hash does not match release-run receipt")
    distribution_release = distribution_receipt.get("release", {}) if isinstance(distribution_receipt.get("release"), dict) else {}
    if distribution_release.get("release_hash") != expected["release_hash"]:
        local_errors.append("verifier distribution release hash does not match verifier release")
    run_source = release_run.get("source", {}) if isinstance(release_run.get("source"), dict) else {}
    if run_source.get("release_hash") != expected["release_hash"]:
        local_errors.append("release-run source.release_hash does not match verifier release")
    if run_source.get("build_hash") != expected["build_hash"]:
        local_errors.append("release-run source.build_hash does not match Go build attestation")

    if errors is None:
        if local_errors:
            raise ValueError("; ".join(local_errors))
    else:
        errors.extend(local_errors)
    if warnings is not None:
        warnings.extend(local_warnings)


def _artifact_record(item: dict[str, Any]) -> dict[str, Any]:
    name = str(item.get("name") or "")
    path = item.get("path")
    kind = str(item.get("kind") or "artifact")
    if not name or not path:
        raise ValueError("public release artifact requires name and path")
    data = Path(path).read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    expected_sha = _normalize_sha256(item.get("sha256"))
    if expected_sha and expected_sha != sha256:
        raise ValueError(f"public release artifact sha256 mismatch: {name}")
    body = {
        "name": name,
        "path": str(path).replace("\\", "/"),
        "kind": kind,
        "url": item.get("url"),
        "sha256": sha256,
        "size_bytes": len(data),
        "media_type": _media_type(Path(path)),
    }
    return {**body, "artifact_id": content_hash(body)}


def _verify_artifacts(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append("verifier public release must include at least one artifact")
        return
    seen: set[str] = set()
    for artifact in value:
        if not isinstance(artifact, dict):
            errors.append("verifier public release artifact entries must be objects")
            continue
        body = without_keys(artifact, "artifact_id")
        if artifact.get("artifact_id") != content_hash(body):
            errors.append(f"verifier public release artifact id mismatch: {artifact.get('name')}")
        name = artifact.get("name")
        if not name:
            errors.append("verifier public release artifact.name is required")
        elif name in seen:
            errors.append(f"verifier public release artifact duplicated: {name}")
        else:
            seen.add(name)
        if artifact.get("sha256") and not _is_sha256(str(artifact.get("sha256"))):
            errors.append(f"verifier public release artifact {name} sha256 must be a SHA-256 digest")
        if artifact.get("path"):
            source_path = Path(str(artifact.get("path")))
            if source_path.exists():
                data = source_path.read_bytes()
                if hashlib.sha256(data).hexdigest() != artifact.get("sha256"):
                    errors.append(f"verifier public release artifact {name} sha256 does not match local file")
                if artifact.get("size_bytes") != len(data):
                    errors.append(f"verifier public release artifact {name} size does not match local file")


def _assert_artifact_bindings(distribution_receipt: dict[str, Any], release_run: dict[str, Any], artifacts: list[dict[str, Any]]) -> None:
    errors: list[str] = []
    _verify_artifact_bindings(distribution_receipt, release_run, artifacts, errors)
    if errors:
        raise ValueError("; ".join(errors))


def _verify_artifact_bindings(
    distribution_receipt: dict[str, Any],
    release_run: dict[str, Any],
    artifacts: list[dict[str, Any]],
    errors: list[str],
) -> None:
    hashes = {artifact.get("sha256") for artifact in artifacts if isinstance(artifact, dict)}
    distribution_artifacts = distribution_receipt.get("artifacts", {}) if isinstance(distribution_receipt.get("artifacts"), dict) else {}
    for name in ("bundle", "sbom", "provenance", "signature"):
        item = distribution_artifacts.get(name)
        if isinstance(item, dict) and item.get("sha256") not in hashes:
            errors.append(f"public release missing source distribution artifact: {name}")
    release_artifacts = release_run.get("artifacts", []) if isinstance(release_run.get("artifacts"), list) else []
    for artifact in release_artifacts:
        if isinstance(artifact, dict) and artifact.get("sha256") not in hashes:
            errors.append(f"public release missing release-run artifact: {artifact.get('name')}")


def _source_summary(
    verifier_release: dict[str, Any],
    distribution_receipt: dict[str, Any],
    build_attestation: dict[str, Any],
    release_run: dict[str, Any],
    release_run_bundle: dict[str, Any],
    conformance_report: dict[str, Any] | None,
    standards_package: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "release_id": verifier_release.get("release_id"),
        "release_hash": content_hash(verifier_release),
        "release_version": verifier_release.get("release", {}).get("version"),
        "distribution_id": distribution_receipt.get("distribution_id"),
        "distribution_hash": content_hash(distribution_receipt),
        "build_id": build_attestation.get("build_id"),
        "build_hash": content_hash(build_attestation),
        "build_mode": build_attestation.get("build", {}).get("mode") if isinstance(build_attestation.get("build"), dict) else None,
        "run_id": release_run.get("run_id"),
        "run_hash": content_hash(release_run),
        "bundle_id": release_run_bundle.get("bundle_id"),
        "bundle_hash": content_hash(release_run_bundle),
        "conformance_report_id": conformance_report.get("report_id") if isinstance(conformance_report, dict) else None,
        "conformance_report_hash": content_hash(conformance_report) if isinstance(conformance_report, dict) else None,
        "standards_package_id": standards_package.get("package_id") if isinstance(standards_package, dict) else None,
        "standards_package_hash": content_hash(standards_package) if isinstance(standards_package, dict) else None,
    }


def _controls(
    distribution_receipt: dict[str, Any],
    release_run: dict[str, Any],
    release_run_bundle: dict[str, Any],
    artifacts: list[dict[str, Any]],
    provider_evidence: Any,
    mode: Any,
) -> list[dict[str, str]]:
    provider = provider_evidence if isinstance(provider_evidence, dict) else {}
    artifact_errors: list[str] = []
    _verify_artifact_bindings(distribution_receipt, release_run, artifacts, artifact_errors)
    provider_exports = all(provider.get(field) for field in ("workflow_run_export_hash", "release_api_export_hash", "artifact_manifest_hash"))
    audit_bound = bool(provider.get("audit_log_ref") and provider.get("audit_log_root") and provider.get("audit_log_size"))
    public_urls = bool(artifacts) and all(isinstance(artifact, dict) and artifact.get("url") for artifact in artifacts)
    return [
        {
            "id": "signed-release-source-distribution",
            "status": "attested" if distribution_receipt.get("distribution_id") else "failed",
            "description": "Signed verifier source distribution receipt is bound into the public release publication.",
        },
        {
            "id": "binary-build-and-workflow-run-binding",
            "status": "attested" if release_run.get("run_id") else "failed",
            "description": "Go build attestation and release workflow-run receipt are bound to the same verifier release.",
        },
        {
            "id": "offline-review-bundle-binding",
            "status": "attested" if release_run_bundle.get("bundle_id") else "failed",
            "description": "Self-contained release-run review bundle is bound for offline third-party replay.",
        },
        {
            "id": "public-artifact-publication",
            "status": "attested" if not artifact_errors and public_urls else "planned-production",
            "description": "Public release artifacts include source distribution and release-run artifacts with URLs and matching hashes.",
        },
        {
            "id": "provider-native-release-exports",
            "status": "attested" if provider_exports else "planned-production",
            "description": "Provider-native workflow run, release API, and artifact manifest export hashes are recorded.",
        },
        {
            "id": "immutable-release-audit-log",
            "status": "attested" if audit_bound else "planned-production",
            "description": "Immutable provider audit-log root and size are recorded for the release publication.",
        },
        {
            "id": "public-release-authority",
            "status": "attested" if mode == "public-release" and provider_exports and audit_bound and not artifact_errors else "planned-production",
            "description": "Public release authority requires matching artifacts plus provider-native exports and immutable audit evidence.",
        },
    ]


def _verify_public_release(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("verifier public release public_release must be an object")
        return
    if value.get("mode") not in VERIFIER_PUBLIC_RELEASE_MODES:
        errors.append("verifier public release mode is unsupported")
    for field in ("provider", "release_ref", "release_url", "tag", "publisher_ref"):
        if not value.get(field):
            errors.append(f"verifier public release public_release.{field} is required")
    for field in ("published_at",):
        if value.get(field):
            try:
                parse_rfc3339(str(value.get(field)))
            except ValueError as exc:
                errors.append(f"verifier public release public_release.{field} invalid: {exc}")


def _verify_provider_evidence(value: Any, public_release: Any, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("verifier public release provider_evidence must be an object")
        return
    for field in ("workflow_run_export_hash", "release_api_export_hash", "artifact_manifest_hash", "audit_log_root", "transparency_log_root"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"verifier public release provider_evidence.{field} must be a sha256 reference")
    if value.get("audit_log_size") is not None and (not isinstance(value.get("audit_log_size"), int) or value.get("audit_log_size") < 1):
        errors.append("verifier public release provider_evidence.audit_log_size must be a positive integer")
    if value.get("retention_until"):
        try:
            parse_rfc3339(str(value.get("retention_until")))
        except ValueError as exc:
            errors.append(f"verifier public release provider_evidence.retention_until invalid: {exc}")
    mode = public_release.get("mode") if isinstance(public_release, dict) else None
    if mode == "public-release":
        missing = [
            field
            for field in ("workflow_run_export_hash", "release_api_export_hash", "artifact_manifest_hash", "audit_log_ref", "audit_log_root", "audit_log_size")
            if not value.get(field)
        ]
        if missing:
            warnings.append("public release provider evidence is incomplete: " + ", ".join(missing))


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


def _normalize_sha256(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if value.startswith("sha256:"):
        return value[7:]
    return value


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())


def _is_sha256_ref(value: str) -> bool:
    return _is_sha256(value[7:]) if value.startswith("sha256:") else _is_sha256(value)


def _media_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix == ".zip":
        return "application/zip"
    if suffix in {".txt", ".log", ".md", ".sig", ".pem"}:
        return "text/plain"
    return "application/octet-stream"
