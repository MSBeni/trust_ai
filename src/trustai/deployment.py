from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

DEPLOYMENT_MANIFEST_SCHEMA = "trustai.deployment-manifest/0.1"
DEPLOYMENT_ENTRY_TYPE = "deployment.manifest.published"

DEFAULT_DEPLOYMENT_SOURCE_PATHS = (
    "deploy/docker/Dockerfile",
    "deploy/helm/trustai/Chart.yaml",
    "deploy/helm/trustai/values.yaml",
    "deploy/helm/trustai/templates/configmap.yaml",
    "deploy/helm/trustai/templates/deployment.yaml",
    "deploy/helm/trustai/templates/service.yaml",
    "deploy/helm/trustai/templates/networkpolicy.yaml",
    "deploy/helm/trustai/templates/demo-job.yaml",
    "deploy/helm/trustai/templates/pvc.yaml",
    "docs/deployment/byoc.md",
    "docs/specs/production-trust-v0.1.md",
    "README.md",
)
DEFAULT_HELM_CHART_SOURCE_PATHS = (
    "deploy/helm/trustai/Chart.yaml",
    "deploy/helm/trustai/values.yaml",
    "deploy/helm/trustai/templates/configmap.yaml",
    "deploy/helm/trustai/templates/deployment.yaml",
    "deploy/helm/trustai/templates/service.yaml",
    "deploy/helm/trustai/templates/networkpolicy.yaml",
    "deploy/helm/trustai/templates/demo-job.yaml",
    "deploy/helm/trustai/templates/pvc.yaml",
)

HELM_CHART_VALIDATION_SCHEMA = "trustai.helm-chart-validation/0.1"
HELM_CHART_VALIDATION_ENTRY_TYPE = "deployment.helm_chart.validated"
DEPLOYMENT_IMAGE_INTEGRITY_SCHEMA = "trustai.deployment-image-integrity/0.1"
DEPLOYMENT_IMAGE_INTEGRITY_ENTRY_TYPE = "deployment.image.integrity_attested"
DEFAULT_IMAGE_INTEGRITY_SOURCE_PATHS = (
    "deploy/docker/Dockerfile",
    "deploy/helm/trustai/values.yaml",
    "deploy/helm/trustai/templates/deployment.yaml",
    "pyproject.toml",
    "src/trustai/server.py",
    "src/trustai/cli.py",
)


@dataclass
class DeploymentManifestVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]

@dataclass
class HelmChartValidationVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class DeploymentImageIntegrityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_deployment_manifest(
    root: str | Path = ".",
    *,
    name: str = "trustai-reference-deployment",
    mode: str = "byoc-reference",
    environment: str = "local",
    source_paths: list[str] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    root_path = Path(root)
    paths = source_paths or list(DEFAULT_DEPLOYMENT_SOURCE_PATHS)
    source_records = [_source_record(root_path, path) for path in paths]
    chart = _chart_metadata(root_path / "deploy" / "helm" / "trustai" / "Chart.yaml")
    values = _values_summary(root_path / "deploy" / "helm" / "trustai" / "values.yaml")
    body = {
        "schema": DEPLOYMENT_MANIFEST_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "deployment": {
            "name": name,
            "mode": mode,
            "environment": environment,
            "artifact_type": "docker-image-plus-helm-chart",
            "chart": chart,
            "image": values.get("image"),
            "tenant_id_default": values.get("tenantId"),
            "api": values.get("api"),
        },
        "source_files": source_records,
        "components": _components(),
        "controls": _controls(),
        "limitations": [
            "This manifest verifies the local Docker/Helm BYOC reference scaffold only.",
            "It does not claim a managed SaaS control plane, production operator, cloud Object Lock, Kafka/ClickHouse/Postgres, or live KMS/TSA providers.",
            "Production deployments should replace local secrets and persistent-volume storage with customer-controlled cloud services and independently audited controls.",
        ],
    }
    manifest_id = content_hash(body)
    return {
        **body,
        "manifest_id": manifest_id,
        "signatures": [sign_value({"manifest_id": manifest_id, "manifest": body}, key)],
    }


def verify_deployment_manifest(
    manifest: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> DeploymentManifestVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if manifest.get("schema") != DEPLOYMENT_MANIFEST_SCHEMA:
        errors.append(f"unsupported deployment manifest schema: {manifest.get('schema')}")
    body = without_keys(manifest, "manifest_id", "signatures")
    expected_manifest_id = content_hash(body)
    if manifest.get("manifest_id") != expected_manifest_id:
        errors.append("manifest_id does not match canonical manifest body")

    signatures = manifest.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("deployment manifest must include at least one signature")
    else:
        signed_value = {"manifest_id": manifest.get("manifest_id"), "manifest": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("deployment manifest signature verification failed")

    source_files = manifest.get("source_files", [])
    if not isinstance(source_files, list) or not source_files:
        errors.append("deployment manifest must include source_files")
        source_files = []
    paths = set()
    for source in source_files:
        if not isinstance(source, dict):
            errors.append("source file record must be an object")
            continue
        path_value = source.get("path")
        if not isinstance(path_value, str) or not path_value:
            errors.append("source file path missing")
            continue
        paths.add(path_value)
        source_path = root_path / path_value
        if not source_path.exists():
            errors.append(f"source file missing from worktree: {path_value}")
            continue
        current = _source_record(root_path, path_value)
        for field in ("sha256", "size_bytes"):
            if source.get(field) != current.get(field):
                errors.append(f"source file {path_value} {field} mismatch")

    for required in DEFAULT_DEPLOYMENT_SOURCE_PATHS:
        if required not in paths:
            errors.append(f"required deployment source missing from manifest: {required}")

    deployment = manifest.get("deployment", {})
    if deployment.get("mode") not in {"byoc-reference", "self-hosted-reference", "airgap-reference"}:
        warnings.append(f"deployment mode is {deployment.get('mode')}")
    if deployment.get("artifact_type") != "docker-image-plus-helm-chart":
        errors.append("deployment artifact_type must be docker-image-plus-helm-chart")

    components = manifest.get("components", [])
    component_ids = {component.get("id") for component in components if isinstance(component, dict)}
    for component_id in {"docker-runtime", "helm-chart", "persistent-evidence-storage", "signing-key-secret", "local-ingestion-api", "api-service"}:
        if component_id not in component_ids:
            errors.append(f"deployment component missing: {component_id}")

    controls = manifest.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("deployment manifest must include controls")
    else:
        production_planned = [
            control for control in controls if isinstance(control, dict) and control.get("status") == "planned-production"
        ]
        if production_planned:
            warnings.append(f"{len(production_planned)} controls remain planned-production")

    return DeploymentManifestVerification(ok=not errors, errors=errors, warnings=warnings)


def append_deployment_manifest(
    chain: EvidenceChain,
    manifest: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_deployment_manifest(manifest, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid deployment manifest: " + "; ".join(result.errors))
    payload = {
        "manifest_id": manifest["manifest_id"],
        "manifest_hash": content_hash(manifest),
        "deployment": manifest.get("deployment"),
        "source_file_count": len(manifest.get("source_files", [])),
        "component_count": len(manifest.get("components", [])),
        "control_summary": _control_summary(manifest.get("controls", [])),
        "limitations": manifest.get("limitations", []),
    }
    return chain.append(DEPLOYMENT_ENTRY_TYPE, payload, key=key, timestamp=manifest.get("generated_at"))



def build_helm_chart_validation_receipt(
    root: str | Path = ".",
    *,
    deployment_manifest: dict[str, Any] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    root_path = Path(root)
    body = _helm_chart_validation_body(
        root_path,
        deployment_manifest=deployment_manifest,
        generated_at=generated_at or utc_now(),
    )
    receipt_id = content_hash(body)
    return {
        **body,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "receipt": body}, key)],
    }


def verify_helm_chart_validation_receipt(
    receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    deployment_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> HelmChartValidationVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if receipt.get("schema") != HELM_CHART_VALIDATION_SCHEMA:
        errors.append(f"unsupported Helm chart validation schema: {receipt.get('schema')}")
    body = without_keys(receipt, "receipt_id", "signatures")
    expected_receipt_id = content_hash(body)
    if receipt.get("receipt_id") != expected_receipt_id:
        errors.append("receipt_id does not match canonical Helm chart validation body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("Helm chart validation receipt must include at least one signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "receipt": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("Helm chart validation signature verification failed")

    source_files = receipt.get("source_files", [])
    if not isinstance(source_files, list) or not source_files:
        errors.append("Helm chart validation receipt must include source_files")
        source_files = []
    source_paths: set[str] = set()
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
    for required in DEFAULT_HELM_CHART_SOURCE_PATHS:
        if required not in source_paths:
            errors.append(f"required Helm chart source missing from receipt: {required}")

    if deployment_manifest is None and receipt.get("deployment_manifest"):
        warnings.append("deployment manifest was not supplied for source replay")
    if deployment_manifest is not None:
        expected_body = _helm_chart_validation_body(
            root_path,
            deployment_manifest=deployment_manifest,
            generated_at=body.get("generated_at"),
        )
        for field in ("chart", "values", "deployment_manifest", "source_files", "checks", "summary", "passed", "limitations"):
            if body.get(field) != expected_body.get(field):
                errors.append(f"Helm chart validation {field} does not match replayed sources")
    else:
        expected_body = _helm_chart_validation_body(root_path, deployment_manifest=None, generated_at=body.get("generated_at"))
        for field in ("chart", "values", "source_files", "checks", "summary", "passed", "limitations"):
            if body.get(field) != expected_body.get(field):
                errors.append(f"Helm chart validation {field} does not match replayed sources")

    checks = receipt.get("checks", [])
    if not isinstance(checks, list) or not checks:
        errors.append("Helm chart validation receipt must include checks")
    else:
        failed = [check.get("id") for check in checks if isinstance(check, dict) and not check.get("passed")]
        if failed:
            errors.append("Helm chart validation checks failed: " + ", ".join(str(item) for item in failed))
    if receipt.get("passed") is not True:
        errors.append("Helm chart validation receipt is not marked passed")

    return HelmChartValidationVerification(ok=not errors, errors=errors, warnings=warnings)


def append_helm_chart_validation_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    deployment_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_helm_chart_validation_receipt(
        receipt,
        root=root,
        deployment_manifest=deployment_manifest,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid Helm chart validation receipt: " + "; ".join(result.errors))
    payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "chart": receipt.get("chart"),
        "deployment_manifest": receipt.get("deployment_manifest"),
        "source_file_count": len(receipt.get("source_files", [])),
        "check_summary": receipt.get("summary"),
        "passed": receipt.get("passed"),
    }
    return chain.append(HELM_CHART_VALIDATION_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("generated_at"))




def build_deployment_image_integrity_receipt(
    root: str | Path = ".",
    *,
    deployment_manifest: dict[str, Any],
    image_digest: str,
    sbom_path: str | Path,
    provenance_path: str | Path,
    signature_path: str | Path,
    image_ref: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    root_path = Path(root)
    body = _deployment_image_integrity_body(
        root_path,
        deployment_manifest=deployment_manifest,
        image_digest=image_digest,
        image_ref=image_ref,
        sbom_path=sbom_path,
        provenance_path=provenance_path,
        signature_path=signature_path,
        generated_at=generated_at or utc_now(),
    )
    receipt_id = content_hash(body)
    return {
        **body,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "receipt": body}, key)],
    }


def verify_deployment_image_integrity_receipt(
    receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    deployment_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> DeploymentImageIntegrityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if receipt.get("schema") != DEPLOYMENT_IMAGE_INTEGRITY_SCHEMA:
        errors.append(f"unsupported deployment image integrity schema: {receipt.get('schema')}")
    body = without_keys(receipt, "receipt_id", "signatures")
    expected_receipt_id = content_hash(body)
    if receipt.get("receipt_id") != expected_receipt_id:
        errors.append("receipt_id does not match canonical deployment image integrity body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("deployment image integrity receipt must include at least one signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "receipt": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("deployment image integrity signature verification failed")

    source_files = receipt.get("source_files", [])
    if not isinstance(source_files, list) or not source_files:
        errors.append("deployment image integrity receipt must include source_files")
        source_files = []
    source_paths: set[str] = set()
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
    for required in DEFAULT_IMAGE_INTEGRITY_SOURCE_PATHS:
        if required not in source_paths:
            errors.append(f"required deployment image integrity source missing from receipt: {required}")

    artifacts = receipt.get("artifacts", [])
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("deployment image integrity receipt must include artifacts")
        artifacts = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("artifact record must be an object")
            continue
        path_value = artifact.get("path")
        kind = artifact.get("kind")
        if not isinstance(path_value, str) or not path_value:
            errors.append("artifact path missing")
            continue
        if not isinstance(kind, str) or not kind:
            errors.append("artifact kind missing")
            continue
        artifact_path = _resolve_artifact_path(root_path, path_value)
        if not artifact_path.exists():
            errors.append(f"artifact missing from worktree: {path_value}")
            continue
        current = _artifact_record(root_path, path_value, kind)
        for field in ("sha256", "size_bytes"):
            if artifact.get(field) != current.get(field):
                errors.append(f"artifact {kind} {field} mismatch")

    if deployment_manifest is None:
        warnings.append("deployment manifest was not supplied for image integrity source replay")
    else:
        image = receipt.get("image", {}) if isinstance(receipt.get("image"), dict) else {}
        artifact_paths = _artifact_paths_by_kind(artifacts)
        missing_artifact_kinds = [kind for kind in ("sbom", "provenance", "signature") if kind not in artifact_paths]
        if missing_artifact_kinds:
            errors.append("deployment image integrity receipt missing artifact kinds: " + ", ".join(missing_artifact_kinds))
        else:
            expected_body = _deployment_image_integrity_body(
                root_path,
                deployment_manifest=deployment_manifest,
                image_digest=str(image.get("image_digest") or ""),
                image_ref=str(image.get("image_ref") or ""),
                sbom_path=artifact_paths["sbom"],
                provenance_path=artifact_paths["provenance"],
                signature_path=artifact_paths["signature"],
                generated_at=body.get("generated_at"),
            )
            for field in ("image", "deployment_manifest", "source_files", "artifacts", "checks", "summary", "passed", "limitations"):
                if body.get(field) != expected_body.get(field):
                    errors.append(f"deployment image integrity {field} does not match replayed sources")

    checks = receipt.get("checks", [])
    if not isinstance(checks, list) or not checks:
        errors.append("deployment image integrity receipt must include checks")
    else:
        failed = [check.get("id") for check in checks if isinstance(check, dict) and not check.get("passed")]
        if failed:
            errors.append("deployment image integrity checks failed: " + ", ".join(str(item) for item in failed))
    if receipt.get("passed") is not True:
        errors.append("deployment image integrity receipt is not marked passed")

    return DeploymentImageIntegrityVerification(ok=not errors, errors=errors, warnings=warnings)


def append_deployment_image_integrity_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    deployment_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_deployment_image_integrity_receipt(
        receipt,
        root=root,
        deployment_manifest=deployment_manifest,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid deployment image integrity receipt: " + "; ".join(result.errors))
    payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "image": receipt.get("image"),
        "deployment_manifest": receipt.get("deployment_manifest"),
        "artifact_count": len(receipt.get("artifacts", [])),
        "source_file_count": len(receipt.get("source_files", [])),
        "check_summary": receipt.get("summary"),
        "passed": receipt.get("passed"),
    }
    return chain.append(DEPLOYMENT_IMAGE_INTEGRITY_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("generated_at"))


def load_deployment_image_integrity_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("deployment image integrity receipt must contain an object")
    return value


def write_deployment_image_integrity_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")

def load_helm_chart_validation_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("Helm chart validation receipt must contain an object")
    return value


def write_helm_chart_validation_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")

def load_deployment_manifest(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("deployment manifest must contain an object")
    return value


def write_deployment_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def write_deployment_markdown(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_deployment_markdown(manifest), encoding="utf-8")


def render_deployment_markdown(manifest: dict[str, Any]) -> str:
    deployment = manifest.get("deployment", {})
    files = "\n".join(
        f"- `{source.get('path')}`: `{source.get('sha256')}`"
        for source in manifest.get("source_files", [])
    )
    components = "\n".join(
        f"- `{component.get('id')}`: {component.get('status')} ({component.get('evidence')})"
        for component in manifest.get("components", [])
    )
    controls = "\n".join(
        f"- `{control.get('id')}`: {control.get('status')}"
        for control in manifest.get("controls", [])
    )
    limitations = "\n".join(f"- {item}" for item in manifest.get("limitations", []))
    return f"""# TrustAI Deployment Manifest

Manifest ID: `{manifest.get('manifest_id', '')}`

Deployment: {deployment.get('name', '')}

Mode: {deployment.get('mode', '')}

Environment: {deployment.get('environment', '')}

## Source Files

{files}

## Components

{components}

## Controls

{controls}

## Limitations

{limitations}
"""



def _helm_chart_validation_body(
    root: Path,
    *,
    deployment_manifest: dict[str, Any] | None,
    generated_at: str | None,
) -> dict[str, Any]:
    source_records = [_source_record(root, path) for path in DEFAULT_HELM_CHART_SOURCE_PATHS]
    chart_path = root / "deploy" / "helm" / "trustai" / "Chart.yaml"
    values_path = root / "deploy" / "helm" / "trustai" / "values.yaml"
    chart = _chart_metadata(chart_path)
    values = _values_summary(values_path)
    manifest_binding = _deployment_manifest_validation_binding(root, deployment_manifest)
    checks = _helm_chart_checks(root, values=values, deployment_manifest_binding=manifest_binding)
    summary = _helm_check_summary(checks)
    passed = summary.get("failed", 0) == 0 and summary.get("passed", 0) == len(checks)
    return {
        "schema": HELM_CHART_VALIDATION_SCHEMA,
        "generated_at": generated_at,
        "chart": chart,
        "values": values,
        "deployment_manifest": manifest_binding,
        "source_files": source_records,
        "checks": checks,
        "summary": summary,
        "passed": passed,
        "limitations": [
            "This receipt performs deterministic offline chart/source validation without invoking helm template.",
            "It does not prove Kubernetes admission, cluster scheduling, network reachability, or provider-owned Helm release state.",
            "Production BYOC deployments should still capture provider-native Helm release, Kubernetes API, secret, network, and audit-log exports.",
        ],
    }


def _deployment_manifest_validation_binding(root: Path, deployment_manifest: dict[str, Any] | None) -> dict[str, Any] | None:
    if deployment_manifest is None:
        return None
    result = verify_deployment_manifest(deployment_manifest, root=root)
    return {
        "manifest_id": deployment_manifest.get("manifest_id"),
        "manifest_hash": content_hash(deployment_manifest),
        "verified": result.ok,
        "errors": result.errors,
        "warnings": result.warnings,
        "source_file_count": len(deployment_manifest.get("source_files", [])),
    }


def _helm_chart_checks(
    root: Path,
    *,
    values: dict[str, Any],
    deployment_manifest_binding: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    chart_text = _read_chart_text(root, "Chart.yaml")
    values_text = _read_chart_text(root, "values.yaml")
    configmap_text = _read_chart_text(root, "templates/configmap.yaml")
    deployment_text = _read_chart_text(root, "templates/deployment.yaml")
    service_text = _read_chart_text(root, "templates/service.yaml")
    network_policy_text = _read_chart_text(root, "templates/networkpolicy.yaml")
    demo_job_text = _read_chart_text(root, "templates/demo-job.yaml")
    pvc_text = _read_chart_text(root, "templates/pvc.yaml")
    api_values = values.get("api") if isinstance(values.get("api"), dict) else {}
    return [
        _helm_check(
            "chart-metadata",
            _contains_all(chart_text, "apiVersion: v2", "name: trustai", "type: application", "version: 0.1.0"),
            "Chart.yaml declares the TrustAI application chart metadata.",
            "deploy/helm/trustai/Chart.yaml",
        ),
        _helm_check(
            "api-values",
            all(api_values.get(field) for field in ("replicas", "port", "state_path", "control_db_path", "approval_request_store_path", "provider_webhook_store_path")),
            "values.yaml provides API replica, port, state, control DB, approval store, and webhook store paths.",
            "deploy/helm/trustai/values.yaml",
        ),
        _helm_check(
            "api-probe-values",
            _contains_all(values_text, "readinessProbe:", "livenessProbe:", "initialDelaySeconds:", "periodSeconds:"),
            "values.yaml configures readiness and liveness probe timing.",
            "deploy/helm/trustai/values.yaml",
        ),
        _helm_check(
            "deployment-resource",
            _contains_all(deployment_text, "apiVersion: apps/v1", "kind: Deployment", "name: trustai-api", "app.kubernetes.io/component: api"),
            "deployment.yaml declares the TrustAI API Deployment and selectors.",
            "deploy/helm/trustai/templates/deployment.yaml",
        ),
        _helm_check(
            "deployment-runs-api",
            _contains_all(deployment_text, "- serve", "- --host", '"0.0.0.0"', "{{ .Values.api.statePath }}", "{{ .Values.api.controlDbPath }}"),
            "The API Deployment runs `trustai serve` with configured host, state path, and control DB path.",
            "deploy/helm/trustai/templates/deployment.yaml",
        ),
        _helm_check(
            "deployment-secret-backed-key",
            _contains_all(deployment_text, "TRUSTAI_SIGNING_KEY", "secretKeyRef:", "{{ .Values.signingKeySecretName }}", "- --key", '"env:TRUSTAI_SIGNING_KEY"'),
            "The API Deployment reads the signing key from a Kubernetes Secret and passes it by env reference.",
            "deploy/helm/trustai/templates/deployment.yaml",
        ),
        _helm_check(
            "deployment-health-probes",
            _contains_all(deployment_text, "readinessProbe:", "livenessProbe:", "path: /health", "port: http"),
            "The API Deployment gates readiness and liveness through `/health`.",
            "deploy/helm/trustai/templates/deployment.yaml",
        ),
        _helm_check(
            "deployment-pvc-state",
            _contains_all(deployment_text, "persistentVolumeClaim:", "claimName: trustai-data", "mountPath: {{ .Values.storage.mountPath }}"),
            "The API Deployment mounts the chart PVC for evidence, control-plane, approval, and webhook state.",
            "deploy/helm/trustai/templates/deployment.yaml",
        ),
        _helm_check(
            "service-resource",
            _contains_all(service_text, "apiVersion: v1", "kind: Service", "name: trustai-api", "targetPort: http", "app.kubernetes.io/component: api"),
            "service.yaml exposes the API Deployment with the expected selector and named target port.",
            "deploy/helm/trustai/templates/service.yaml",
        ),
        _helm_check(
            "network-policy-resource",
            _contains_all(network_policy_text, "apiVersion: networking.k8s.io/v1", "kind: NetworkPolicy", "name: trustai-api", "podSelector:", "policyTypes:", "- Ingress", "- Egress"),
            "networkpolicy.yaml declares a NetworkPolicy for the TrustAI API pods with ingress and egress policy types.",
            "deploy/helm/trustai/templates/networkpolicy.yaml",
        ),
        _helm_check(
            "network-policy-ingress-egress",
            _contains_all(network_policy_text, "namespaceSelector:", "{{ .Values.networkPolicy.ingress.namespace | quote }}", "port: {{ .Values.api.port }}", "kube-system", "port: 53", "ipBlock:", ".Values.networkPolicy.egress.allowedCidrs"),
            "networkpolicy.yaml restricts API ingress by namespace and constrains egress to DNS and configured CIDRs.",
            "deploy/helm/trustai/templates/networkpolicy.yaml",
        ),
        _helm_check(
            "demo-job-secret-backed-key",
            _contains_all(demo_job_text, "kind: Job", "- --key", '"env:TRUSTAI_SIGNING_KEY"', "- demo", "{{ .Values.demo.statePath }}"),
            "The optional demo Job uses the same Secret-backed signing key and configured demo paths.",
            "deploy/helm/trustai/templates/demo-job.yaml",
        ),
        _helm_check(
            "pvc-resource",
            _contains_all(pvc_text, "kind: PersistentVolumeClaim", "name: trustai-data", "storage: {{ .Values.storage.size }}"),
            "pvc.yaml provisions persistent chart state using the configured storage size.",
            "deploy/helm/trustai/templates/pvc.yaml",
        ),
        _helm_check(
            "configmap-tenant",
            _contains_all(configmap_text, "kind: ConfigMap", "TRUSTAI_TENANT_ID", "{{ .Values.tenantId }}"),
            "configmap.yaml binds the default tenant id into the runtime environment.",
            "deploy/helm/trustai/templates/configmap.yaml",
        ),
        _helm_check(
            "deployment-manifest-bound",
            bool(deployment_manifest_binding and deployment_manifest_binding.get("verified")),
            "The Helm validation receipt is bound to a verified deployment manifest.",
            "artifacts/deployment-manifest.json",
        ),
    ]


def _read_chart_text(root: Path, relative: str) -> str:
    return (root / "deploy" / "helm" / "trustai" / relative).read_text(encoding="utf-8-sig")


def _contains_all(text: str, *needles: str) -> bool:
    return all(needle in text for needle in needles)


def _helm_check(check_id: str, passed: bool, description: str, evidence: str) -> dict[str, Any]:
    return {
        "id": check_id,
        "passed": bool(passed),
        "description": description,
        "evidence": evidence,
    }


def _helm_check_summary(checks: list[dict[str, Any]]) -> dict[str, int]:
    passed = sum(1 for check in checks if check.get("passed"))
    failed = len(checks) - passed
    return {"passed": passed, "failed": failed, "total": len(checks)}



def _deployment_image_integrity_body(
    root: Path,
    *,
    deployment_manifest: dict[str, Any],
    image_digest: str,
    image_ref: str | None,
    sbom_path: str | Path,
    provenance_path: str | Path,
    signature_path: str | Path,
    generated_at: str | None,
) -> dict[str, Any]:
    source_records = [_source_record(root, path) for path in DEFAULT_IMAGE_INTEGRITY_SOURCE_PATHS]
    values = _values_summary(root / "deploy" / "helm" / "trustai" / "values.yaml")
    image = _deployment_image_record(
        deployment_manifest,
        chart_values=values.get("image") if isinstance(values.get("image"), dict) else {},
        image_ref=image_ref,
        image_digest=image_digest,
    )
    manifest_binding = _deployment_manifest_validation_binding(root, deployment_manifest)
    artifacts = [
        _artifact_record(root, sbom_path, "sbom"),
        _artifact_record(root, provenance_path, "provenance"),
        _artifact_record(root, signature_path, "signature"),
    ]
    checks = _deployment_image_integrity_checks(
        root,
        image=image,
        source_records=source_records,
        artifacts=artifacts,
        deployment_manifest_binding=manifest_binding,
    )
    summary = _helm_check_summary(checks)
    passed = summary.get("failed", 0) == 0 and summary.get("passed", 0) == len(checks)
    return {
        "schema": DEPLOYMENT_IMAGE_INTEGRITY_SCHEMA,
        "generated_at": generated_at,
        "image": image,
        "deployment_manifest": manifest_binding,
        "source_files": source_records,
        "artifacts": artifacts,
        "checks": checks,
        "summary": summary,
        "passed": passed,
        "limitations": [
            "This receipt verifies source, digest, SBOM, provenance, and signature artifact bindings without building or pulling the image.",
            "It does not prove registry admission, vulnerability scan results, runtime admission-controller enforcement, or cluster image pull success.",
            "Production BYOC deployments should pair this receipt with registry, admission-controller, KMS, and Kubernetes audit-log exports.",
        ],
    }


def _deployment_image_record(
    deployment_manifest: dict[str, Any],
    *,
    chart_values: dict[str, Any],
    image_ref: str | None,
    image_digest: str,
) -> dict[str, Any]:
    manifest_image = deployment_manifest.get("deployment", {}).get("image", {}) if isinstance(deployment_manifest, dict) else {}
    if not isinstance(manifest_image, dict):
        manifest_image = {}
    repository = str(manifest_image.get("repository") or chart_values.get("repository") or "")
    tag = str(manifest_image.get("tag") or chart_values.get("tag") or "")
    pull_policy = str(manifest_image.get("pull_policy") or chart_values.get("pull_policy") or "")
    manifest_image_ref = _image_ref(repository, tag)
    chart_image_ref = _image_ref(str(chart_values.get("repository") or ""), str(chart_values.get("tag") or ""))
    declared_ref = image_ref or manifest_image_ref or chart_image_ref or ""
    normalized_digest = _normalize_sha256_ref(image_digest)
    return {
        "image_ref": declared_ref,
        "image_digest": normalized_digest,
        "repository": repository,
        "tag": tag,
        "pull_policy": pull_policy,
        "manifest_image_ref": manifest_image_ref,
        "chart_image_ref": chart_image_ref,
        "pinned_reference": f"{declared_ref}@{normalized_digest}" if declared_ref and normalized_digest else None,
    }


def _deployment_image_integrity_checks(
    root: Path,
    *,
    image: dict[str, Any],
    source_records: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    deployment_manifest_binding: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    source_paths = {source.get("path") for source in source_records if isinstance(source, dict)}
    artifact_kinds = {artifact.get("kind") for artifact in artifacts if isinstance(artifact, dict) and _is_hex_sha256(str(artifact.get("sha256") or ""))}
    dockerfile_text = (root / "deploy" / "docker" / "Dockerfile").read_text(encoding="utf-8-sig")
    deployment_text = _read_chart_text(root, "templates/deployment.yaml")
    image_ref = str(image.get("image_ref") or "")
    manifest_image_ref = str(image.get("manifest_image_ref") or "")
    chart_image_ref = str(image.get("chart_image_ref") or "")
    tag = str(image.get("tag") or "")
    return [
        _helm_check(
            "deployment-manifest-bound",
            bool(deployment_manifest_binding and deployment_manifest_binding.get("verified")),
            "The image integrity receipt is bound to a verified deployment manifest.",
            "artifacts/deployment-manifest.json",
        ),
        _helm_check(
            "chart-image-reference-bound",
            bool(image_ref and image_ref == manifest_image_ref and image_ref == chart_image_ref),
            "The declared image reference matches the deployment manifest and Helm values image reference.",
            "deploy/helm/trustai/values.yaml",
        ),
        _helm_check(
            "image-digest-present",
            _is_sha256_ref(str(image.get("image_digest") or "")),
            "The receipt records a sha256 image digest suitable for registry/admission binding.",
            "artifacts/deployment-image-integrity.json",
        ),
        _helm_check(
            "image-tag-pinned",
            bool(tag and tag != "latest" and not image_ref.endswith(":latest")),
            "The chart image tag is explicit and does not use latest.",
            "deploy/helm/trustai/values.yaml",
        ),
        _helm_check(
            "dockerfile-source-bound",
            "deploy/docker/Dockerfile" in source_paths and "pyproject.toml" in source_paths and "src/trustai/cli.py" in source_paths,
            "The receipt binds the Dockerfile, package metadata, and CLI source used by the runtime image.",
            "deploy/docker/Dockerfile",
        ),
        _helm_check(
            "dockerfile-entrypoint",
            _contains_all(dockerfile_text, "COPY src ./src", "ENV PYTHONPATH=/app/src", 'ENTRYPOINT ["python", "-m", "trustai"]'),
            "The Dockerfile copies the TrustAI source and starts the package entrypoint.",
            "deploy/docker/Dockerfile",
        ),
        _helm_check(
            "helm-deployment-uses-image-values",
            _contains_all(deployment_text, "{{ .Values.image.repository }}", "{{ .Values.image.tag }}", "{{ .Values.image.pullPolicy }}"),
            "The API Deployment consumes the chart image repository, tag, and pull policy values.",
            "deploy/helm/trustai/templates/deployment.yaml",
        ),
        _helm_check(
            "sbom-artifact-bound",
            "sbom" in artifact_kinds,
            "The receipt binds an SBOM artifact by sha256 and size.",
            "artifacts/trustai-image.sbom.json",
        ),
        _helm_check(
            "provenance-artifact-bound",
            "provenance" in artifact_kinds,
            "The receipt binds a build provenance artifact by sha256 and size.",
            "artifacts/trustai-image.provenance.json",
        ),
        _helm_check(
            "signature-artifact-bound",
            "signature" in artifact_kinds,
            "The receipt binds an image signature artifact by sha256 and size.",
            "artifacts/trustai-image.sig",
        ),
    ]


def _artifact_record(root: Path, path: str | Path, kind: str) -> dict[str, Any]:
    artifact_path = _resolve_artifact_path(root, path)
    data = artifact_path.read_bytes()
    return {
        "kind": kind,
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _artifact_paths_by_kind(artifacts: list[Any]) -> dict[str, str]:
    paths: dict[str, str] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        kind = artifact.get("kind")
        path = artifact.get("path")
        if isinstance(kind, str) and isinstance(path, str) and kind not in paths:
            paths[kind] = path
    return paths


def _resolve_artifact_path(root: Path, path: str | Path) -> Path:
    artifact_path = Path(path)
    return artifact_path if artifact_path.is_absolute() else root / artifact_path


def _image_ref(repository: str, tag: str) -> str | None:
    if not repository or not tag:
        return None
    return f"{repository}:{tag}"


def _normalize_sha256_ref(value: str) -> str:
    stripped = value.strip().lower()
    if _is_hex_sha256(stripped):
        return f"sha256:{stripped}"
    return stripped


def _is_sha256_ref(value: str) -> bool:
    stripped = value.strip().lower()
    return stripped.startswith("sha256:") and _is_hex_sha256(stripped.split(":", 1)[1])


def _is_hex_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value.lower())

def _source_record(root: Path, path: str) -> dict[str, Any]:
    source_path = root / path
    data = source_path.read_bytes()
    return {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _chart_metadata(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    fields = _flat_yaml_fields(path.read_text(encoding="utf-8"), {"name", "version", "appVersion", "description"})
    return {
        "name": fields.get("name"),
        "version": fields.get("version"),
        "app_version": fields.get("appVersion"),
        "description": fields.get("description"),
    }


def _values_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    fields = _flat_yaml_fields(text, {"tenantId", "signingKeySecretName"})
    image = {
        "repository": _nested_yaml_field(text, "image", "repository"),
        "tag": _nested_yaml_field(text, "image", "tag"),
        "pull_policy": _nested_yaml_field(text, "image", "pullPolicy"),
    }
    api = {
        "replicas": _nested_yaml_field(text, "api", "replicas"),
        "port": _nested_yaml_field(text, "api", "port"),
        "state_path": _nested_yaml_field(text, "api", "statePath"),
        "control_db_path": _nested_yaml_field(text, "api", "controlDbPath"),
        "approval_request_store_path": _nested_yaml_field(text, "api", "approvalRequestStorePath"),
        "provider_webhook_store_path": _nested_yaml_field(text, "api", "providerWebhookStorePath"),
    }
    return {
        "tenantId": fields.get("tenantId"),
        "signingKeySecretName": fields.get("signingKeySecretName"),
        "image": image,
        "api": api,
    }


def _flat_yaml_fields(text: str, keys: set[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        if key in keys:
            values[key] = value.strip().strip('"')
    return values


def _nested_yaml_field(text: str, parent: str, key: str) -> str | None:
    in_parent = False
    parent_indent = 0
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if stripped == f"{parent}:":
            in_parent = True
            parent_indent = indent
            continue
        if in_parent and indent <= parent_indent:
            in_parent = False
        if in_parent and stripped.startswith(f"{key}:"):
            return stripped.split(":", 1)[1].strip().strip('"')
    return None


def _components() -> list[dict[str, str]]:
    return [
        {
            "id": "docker-runtime",
            "status": "implemented-reference",
            "evidence": "deploy/docker/Dockerfile",
            "description": "Builds the self-contained Python reference CLI runtime.",
        },
        {
            "id": "helm-chart",
            "status": "implemented-reference",
            "evidence": "deploy/helm/trustai",
            "description": "Renders a Kubernetes API service plus optional proof-pack demo job.",
        },
        {
            "id": "persistent-evidence-storage",
            "status": "implemented-reference",
            "evidence": "deploy/helm/trustai/templates/pvc.yaml",
            "description": "Stores local chain and proof-pack outputs on a persistent volume.",
        },
        {
            "id": "signing-key-secret",
            "status": "operator-supplied",
            "evidence": "deploy/helm/trustai/templates/deployment.yaml",
            "description": "Reads the local signing key from a Kubernetes Secret for the API and demo job.",
        },
        {
            "id": "local-ingestion-api",
            "status": "implemented-reference",
            "evidence": "deploy/helm/trustai/templates/deployment.yaml",
            "description": "Runs the local ingestion, verification, approval, webhook, and insurer API server.",
        },
        {
            "id": "api-service",
            "status": "implemented-reference",
            "evidence": "deploy/helm/trustai/templates/service.yaml",
            "description": "Exposes the TrustAI API inside the customer Kubernetes cluster.",
        },
        {
            "id": "api-network-policy",
            "status": "implemented-reference",
            "evidence": "deploy/helm/trustai/templates/networkpolicy.yaml",
            "description": "Restricts API pod ingress and egress through a chart-managed NetworkPolicy.",
        },
        {
            "id": "worm-store",
            "status": "local-reference",
            "evidence": "src/trustai/object_store.py",
            "description": "Models WORM receipts and legal holds without cloud Object Lock.",
        },
        {
            "id": "trust-authority",
            "status": "local-reference",
            "evidence": "src/trustai/trust_authority.py",
            "description": "Models KMS/TSA verification receipts for future managed providers.",
        },
    ]


def _controls() -> list[dict[str, str]]:
    return [
        {
            "id": "customer-data-plane",
            "status": "implemented-reference",
            "description": "Docker/Helm artifacts can run in the customer's environment without SaaS data egress.",
        },
        {
            "id": "secret-backed-signing-key",
            "status": "implemented-reference",
            "description": "Helm API deployment and demo job read TRUSTAI_SIGNING_KEY from a Kubernetes Secret.",
        },
        {
            "id": "persistent-artifact-storage",
            "status": "implemented-reference",
            "description": "Helm chart provisions a PVC for evidence-chain, control-plane, webhook, approval, and proof-pack outputs.",
        },
        {
            "id": "self-hosted-api-service",
            "status": "implemented-reference",
            "description": "Helm chart runs the TrustAI API as a Deployment and exposes it with a ClusterIP Service.",
        },
        {
            "id": "api-health-probes",
            "status": "implemented-reference",
            "description": "Readiness and liveness probes call the TrustAI /health endpoint before routing traffic.",
        },
        {
            "id": "deployment-image-integrity-receipts",
            "status": "implemented-reference",
            "description": "Deployment image integrity receipts bind the chart image reference to an image digest, SBOM, provenance, and signature artifacts.",
        },
        {
            "id": "network-policy-egress-controls",
            "status": "implemented-reference",
            "description": "Helm chart provisions a NetworkPolicy with namespace-scoped ingress and constrained DNS/CIDR egress.",
        },
        {
            "id": "managed-kms-hsm",
            "status": "planned-production",
            "description": "Replace local HMAC signing with customer-controlled KMS/HSM material.",
        },
        {
            "id": "independent-rfc3161-tsa",
            "status": "planned-production",
            "description": "Replace local TSA tokens with independent RFC 3161 timestamp responses.",
        },
        {
            "id": "cloud-object-lock",
            "status": "planned-production",
            "description": "Replace local WORM store with cloud Object Lock compliance mode and legal-hold governance.",
        },
        {
            "id": "streaming-collector-stack",
            "status": "planned-production",
            "description": "Add hardened collector, Kafka/Redpanda, ClickHouse, and Postgres services.",
        },
        {
            "id": "operator-airgap-hardening",
            "status": "planned-production",
            "description": "Add production operator, air-gap image bundle, network policies, and upgrade/rollback controls.",
        },
    ]


def _control_summary(controls: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        if not isinstance(control, dict):
            continue
        status = str(control.get("status", "unknown"))
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))
