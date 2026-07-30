from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
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
DEPLOYMENT_IMAGE_SIGNATURE_SCHEMA = "trustai.deployment-image-signature/0.1"
KUBERNETES_RELEASE_STATE_SCHEMA = "trustai.kubernetes-release-state/0.1"
KUBERNETES_RELEASE_STATE_ENTRY_TYPE = "deployment.kubernetes_release_state.recorded"
AIRGAP_BUNDLE_SCHEMA = "trustai.airgap-install-bundle/0.1"
AIRGAP_BUNDLE_ENTRY_TYPE = "deployment.airgap_install_bundle.attested"
AIRGAP_BUNDLE_MODES = {"airgap-reference", "airgap-install-bundle", "self-hosted-install-bundle"}
DEFAULT_IMAGE_INTEGRITY_SOURCE_PATHS = (
    "deploy/docker/Dockerfile",
    "deploy/helm/trustai/values.yaml",
    "deploy/helm/trustai/templates/deployment.yaml",
    "pyproject.toml",
    "src/trustai/server.py",
    "src/trustai/cli.py",
)
DEFAULT_KUBERNETES_RELEASE_SOURCE_PATHS = (
    "deploy/helm/trustai/Chart.yaml",
    "deploy/helm/trustai/values.yaml",
    "deploy/helm/trustai/templates/deployment.yaml",
    "deploy/helm/trustai/templates/service.yaml",
    "deploy/helm/trustai/templates/networkpolicy.yaml",
    "docs/specs/kubernetes-release-state-v0.1.md",
    "docs/deployment/byoc.md",
    "src/trustai/deployment.py",
)
DEFAULT_AIRGAP_BUNDLE_SOURCE_PATHS = (
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
    "docs/specs/airgap-install-bundle-v0.1.md",
    "docs/specs/deployment-image-integrity-v0.1.md",
    "docs/specs/helm-chart-validation-v0.1.md",
    "docs/specs/kubernetes-release-state-v0.1.md",
    "src/trustai/deployment.py",
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


@dataclass
class KubernetesReleaseStateVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class AirgapBundleVerification:
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
        key=key,
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
                key=key,
            )
            for field in ("image", "deployment_manifest", "source_files", "image_signature", "artifacts", "checks", "summary", "passed", "limitations"):
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
        "image_signature": receipt.get("image_signature"),
        "artifact_count": len(receipt.get("artifacts", [])),
        "source_file_count": len(receipt.get("source_files", [])),
        "check_summary": receipt.get("summary"),
        "passed": receipt.get("passed"),
    }
    return chain.append(DEPLOYMENT_IMAGE_INTEGRITY_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("generated_at"))




def build_deployment_image_signature_artifact(
    root: str | Path = ".",
    *,
    deployment_manifest: dict[str, Any],
    image_digest: str,
    sbom_path: str | Path,
    provenance_path: str | Path,
    image_ref: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    root_path = Path(root)
    values = _values_summary(root_path / "deploy" / "helm" / "trustai" / "values.yaml")
    image = _deployment_image_record(
        deployment_manifest,
        chart_values=values.get("image") if isinstance(values.get("image"), dict) else {},
        image_ref=image_ref,
        image_digest=image_digest,
    )
    manifest_binding = _deployment_manifest_validation_binding(root_path, deployment_manifest)
    sbom_record = _artifact_record(root_path, sbom_path, "sbom")
    provenance_record = _artifact_record(root_path, provenance_path, "provenance")
    timestamp = generated_at or utc_now()
    subject = _deployment_image_signature_subject(
        image=image,
        deployment_manifest_binding=manifest_binding,
        sbom_record=sbom_record,
        provenance_record=provenance_record,
    )
    payload = {"schema": DEPLOYMENT_IMAGE_SIGNATURE_SCHEMA, "generated_at": timestamp, "subject": subject}
    return {**payload, "signature": sign_value(payload, key)}

def build_kubernetes_release_state_receipt(
    root: str | Path = ".",
    *,
    deployment_manifest: dict[str, Any],
    helm_chart_validation: dict[str, Any],
    environment: str = "local",
    mode: str = "recorded-export",
    provider: str,
    cluster_ref: str,
    namespace: str,
    release_name: str,
    release_revision: str,
    release_status: str,
    export_ref: str,
    export_hash: str,
    service_account_ref: str,
    deployment_ref: str,
    service_ref: str,
    network_policy_ref: str,
    secret_ref: str,
    desired_replicas: int,
    ready_replicas: int,
    network_policy_admitted: bool,
    pod_selector_hash: str,
    ingress_policy_hash: str,
    egress_policy_hash: str,
    audit_log_ref: str,
    audit_log_root: str,
    exported_at: str | None = None,
    issued_at: str | None = None,
    expires_at: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    root_path = Path(root)
    timestamp = generated_at or utc_now()
    body = _kubernetes_release_state_body(
        root_path,
        deployment_manifest=deployment_manifest,
        helm_chart_validation=helm_chart_validation,
        environment=environment,
        mode=mode,
        provider=provider,
        cluster_ref=cluster_ref,
        namespace=namespace,
        release_name=release_name,
        release_revision=release_revision,
        release_status=release_status,
        export_ref=export_ref,
        export_hash=export_hash,
        service_account_ref=service_account_ref,
        deployment_ref=deployment_ref,
        service_ref=service_ref,
        network_policy_ref=network_policy_ref,
        secret_ref=secret_ref,
        desired_replicas=desired_replicas,
        ready_replicas=ready_replicas,
        network_policy_admitted=network_policy_admitted,
        pod_selector_hash=pod_selector_hash,
        ingress_policy_hash=ingress_policy_hash,
        egress_policy_hash=egress_policy_hash,
        audit_log_ref=audit_log_ref,
        audit_log_root=audit_log_root,
        exported_at=exported_at or timestamp,
        issued_at=issued_at,
        expires_at=expires_at,
        generated_at=timestamp,
    )
    receipt_id = content_hash(body)
    return {**body, "receipt_id": receipt_id, "signatures": [sign_value({"receipt_id": receipt_id, "receipt": body}, key)]}


def verify_kubernetes_release_state_receipt(
    receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    deployment_manifest: dict[str, Any] | None = None,
    helm_chart_validation: dict[str, Any] | None = None,
    key: str | None = None,
) -> KubernetesReleaseStateVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if receipt.get("schema") != KUBERNETES_RELEASE_STATE_SCHEMA:
        errors.append(f"unsupported Kubernetes release-state schema: {receipt.get('schema')}")
    body = without_keys(receipt, "receipt_id", "signatures")
    expected_receipt_id = content_hash(body)
    if receipt.get("receipt_id") != expected_receipt_id:
        errors.append("receipt_id does not match canonical Kubernetes release-state body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("Kubernetes release-state receipt must include at least one signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "receipt": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("Kubernetes release-state signature verification failed")

    for field in ("generated_at", "exported_at"):
        try:
            parse_rfc3339(str(body.get(field) or ""))
        except ValueError as exc:
            errors.append(f"Kubernetes release-state {field} invalid: {exc}")
    freshness = body.get("freshness") if isinstance(body.get("freshness"), dict) else {}
    for field in ("issued_at", "expires_at"):
        if freshness.get(field):
            try:
                parse_rfc3339(str(freshness[field]))
            except ValueError as exc:
                errors.append(f"Kubernetes release-state {field} invalid: {exc}")

    source_files = receipt.get("source_files", [])
    if not isinstance(source_files, list) or not source_files:
        errors.append("Kubernetes release-state receipt must include source_files")
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
    for required in DEFAULT_KUBERNETES_RELEASE_SOURCE_PATHS:
        if required not in source_paths:
            errors.append(f"required Kubernetes release-state source missing from receipt: {required}")

    if deployment_manifest is None:
        warnings.append("deployment manifest was not supplied for Kubernetes release-state replay")
    if helm_chart_validation is None:
        warnings.append("Helm chart validation receipt was not supplied for Kubernetes release-state replay")
    if deployment_manifest is not None and helm_chart_validation is not None:
        release_body = body.get("release") if isinstance(body.get("release"), dict) else {}
        workload_body = body.get("workload") if isinstance(body.get("workload"), dict) else {}
        network_policy_body = body.get("network_policy") if isinstance(body.get("network_policy"), dict) else {}
        audit_log_body = body.get("audit_log") if isinstance(body.get("audit_log"), dict) else {}
        for field, section in (
            ("release", release_body),
            ("workload", workload_body),
            ("network_policy", network_policy_body),
            ("audit_log", audit_log_body),
        ):
            if not section:
                errors.append(f"Kubernetes release-state {field} must be an object")
        try:
            desired_replicas = int(workload_body.get("desired_replicas") or 0)
            ready_replicas = int(workload_body.get("ready_replicas") or 0)
        except (TypeError, ValueError) as exc:
            errors.append(f"Kubernetes release-state workload replicas invalid: {exc}")
        else:
            expected_body = _kubernetes_release_state_body(
                root_path,
                deployment_manifest=deployment_manifest,
                helm_chart_validation=helm_chart_validation,
                environment=str(body.get("environment") or ""),
                mode=str(body.get("mode") or ""),
                provider=str(release_body.get("provider") or ""),
                cluster_ref=str(release_body.get("cluster_ref") or ""),
                namespace=str(release_body.get("namespace") or ""),
                release_name=str(release_body.get("release_name") or ""),
                release_revision=str(release_body.get("release_revision") or ""),
                release_status=str(release_body.get("release_status") or ""),
                export_ref=str(release_body.get("export_ref") or ""),
                export_hash=str(release_body.get("export_hash") or ""),
                service_account_ref=str(workload_body.get("service_account_ref") or ""),
                deployment_ref=str(workload_body.get("deployment_ref") or ""),
                service_ref=str(workload_body.get("service_ref") or ""),
                network_policy_ref=str(workload_body.get("network_policy_ref") or ""),
                secret_ref=str(workload_body.get("secret_ref") or ""),
                desired_replicas=desired_replicas,
                ready_replicas=ready_replicas,
                network_policy_admitted=bool(network_policy_body.get("admitted")),
                pod_selector_hash=str(network_policy_body.get("pod_selector_hash") or ""),
                ingress_policy_hash=str(network_policy_body.get("ingress_policy_hash") or ""),
                egress_policy_hash=str(network_policy_body.get("egress_policy_hash") or ""),
                audit_log_ref=str(audit_log_body.get("audit_log_ref") or ""),
                audit_log_root=str(audit_log_body.get("audit_log_root") or ""),
                exported_at=str(body.get("exported_at") or ""),
                issued_at=freshness.get("issued_at"),
                expires_at=freshness.get("expires_at"),
                generated_at=str(body.get("generated_at") or ""),
            )
            for field in ("release", "workload", "network_policy", "audit_log", "freshness", "deployment_manifest", "helm_chart_validation", "source_files", "checks", "summary", "passed", "limitations"):
                if body.get(field) != expected_body.get(field):
                    errors.append(f"Kubernetes release-state {field} does not match replayed sources")

    checks = receipt.get("checks", [])
    if not isinstance(checks, list) or not checks:
        errors.append("Kubernetes release-state receipt must include checks")
    else:
        failed = [check.get("id") for check in checks if isinstance(check, dict) and not check.get("passed")]
        if failed:
            errors.append("Kubernetes release-state checks failed: " + ", ".join(str(item) for item in failed))
    if receipt.get("passed") is not True:
        errors.append("Kubernetes release-state receipt is not marked passed")

    return KubernetesReleaseStateVerification(ok=not errors, errors=errors, warnings=warnings)


def append_kubernetes_release_state_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    deployment_manifest: dict[str, Any] | None = None,
    helm_chart_validation: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_kubernetes_release_state_receipt(
        receipt,
        root=root,
        deployment_manifest=deployment_manifest,
        helm_chart_validation=helm_chart_validation,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid Kubernetes release-state receipt: " + "; ".join(result.errors))
    payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "release": receipt.get("release"),
        "workload": receipt.get("workload"),
        "network_policy": receipt.get("network_policy"),
        "deployment_manifest": receipt.get("deployment_manifest"),
        "helm_chart_validation": receipt.get("helm_chart_validation"),
        "check_summary": receipt.get("summary"),
        "passed": receipt.get("passed"),
    }
    return chain.append(KUBERNETES_RELEASE_STATE_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("generated_at"))


def build_airgap_install_bundle(
    root: str | Path = ".",
    *,
    deployment_manifest: dict[str, Any],
    helm_chart_validation: dict[str, Any],
    deployment_image_integrity: dict[str, Any],
    kubernetes_release_state: dict[str, Any],
    mode: str = "airgap-install-bundle",
    environment: str = "local",
    bundle_ref: str,
    producer_ref: str,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in AIRGAP_BUNDLE_MODES:
        raise ValueError(f"mode must be one of {sorted(AIRGAP_BUNDLE_MODES)}")
    body = _airgap_install_bundle_body(
        Path(root),
        deployment_manifest=deployment_manifest,
        helm_chart_validation=helm_chart_validation,
        deployment_image_integrity=deployment_image_integrity,
        kubernetes_release_state=kubernetes_release_state,
        mode=mode,
        environment=environment,
        bundle_ref=bundle_ref,
        producer_ref=producer_ref,
        generated_at=generated_at or utc_now(),
        key=key,
    )
    bundle_id = content_hash(body)
    return {**body, "bundle_id": bundle_id, "signatures": [sign_value({"bundle_id": bundle_id, "airgap_install_bundle": body}, key)]}


def verify_airgap_install_bundle(
    bundle: dict[str, Any],
    *,
    root: str | Path = ".",
    deployment_manifest: dict[str, Any] | None = None,
    helm_chart_validation: dict[str, Any] | None = None,
    deployment_image_integrity: dict[str, Any] | None = None,
    kubernetes_release_state: dict[str, Any] | None = None,
    key: str | None = None,
) -> AirgapBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)
    if bundle.get("schema") != AIRGAP_BUNDLE_SCHEMA:
        errors.append(f"unsupported air-gap install bundle schema: {bundle.get('schema')}")
    body = without_keys(bundle, "bundle_id", "signatures")
    if bundle.get("bundle_id") != content_hash(body):
        errors.append("bundle_id does not match canonical air-gap install bundle body")
    signatures = bundle.get("signatures", [])
    signed_value = {"bundle_id": bundle.get("bundle_id"), "airgap_install_bundle": body}
    if not isinstance(signatures, list) or not signatures:
        errors.append("air-gap install bundle must include at least one signature")
    elif not any(isinstance(sig, dict) and verify_value(signed_value, sig, key) for sig in signatures):
        errors.append("air-gap install bundle signature verification failed")
    if bundle.get("mode") not in AIRGAP_BUNDLE_MODES:
        errors.append("air-gap install bundle mode is unsupported")
    for field in ("generated_at", "environment", "bundle_ref", "producer_ref"):
        if not isinstance(bundle.get(field), str) or not bundle.get(field):
            errors.append(f"air-gap install bundle {field} missing")
    try:
        parse_rfc3339(str(bundle.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"air-gap install bundle generated_at invalid: {exc}")
    source_files = bundle.get("source_files", [])
    if not isinstance(source_files, list) or not source_files:
        errors.append("air-gap install bundle must include source_files")
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
        if not (root_path / path_value).exists():
            errors.append(f"source file missing from worktree: {path_value}")
            continue
        current = _source_record(root_path, path_value)
        for field in ("sha256", "size_bytes"):
            if source.get(field) != current.get(field):
                errors.append(f"source file {path_value} {field} mismatch")
    for required in DEFAULT_AIRGAP_BUNDLE_SOURCE_PATHS:
        if required not in paths:
            errors.append(f"required air-gap bundle source missing: {required}")
    supplied = [deployment_manifest, helm_chart_validation, deployment_image_integrity, kubernetes_release_state]
    if any(item is not None for item in supplied) and not all(item is not None for item in supplied):
        errors.append("all air-gap bundle source receipts are required for replay")
    elif all(item is not None for item in supplied):
        try:
            expected = _airgap_install_bundle_body(
                root_path,
                deployment_manifest=deployment_manifest or {},
                helm_chart_validation=helm_chart_validation or {},
                deployment_image_integrity=deployment_image_integrity or {},
                kubernetes_release_state=kubernetes_release_state or {},
                mode=str(body.get("mode") or ""),
                environment=str(body.get("environment") or ""),
                bundle_ref=str(body.get("bundle_ref") or ""),
                producer_ref=str(body.get("producer_ref") or ""),
                generated_at=str(body.get("generated_at") or ""),
                key=key,
            )
        except (OSError, ValueError) as exc:
            errors.append(f"air-gap install bundle replay failed: {exc}")
        else:
            for field in ("deployment_manifest", "helm_chart_validation", "deployment_image_integrity", "kubernetes_release_state", "install_package", "source_files", "checks", "summary", "passed", "limitations"):
                if body.get(field) != expected.get(field):
                    errors.append(f"air-gap install bundle {field} does not match replayed sources")
    else:
        warnings.append("source receipts were not supplied for air-gap install bundle replay")
    checks = bundle.get("checks", [])
    if not isinstance(checks, list) or not checks:
        errors.append("air-gap install bundle must include checks")
    else:
        failed = [check.get("id") for check in checks if isinstance(check, dict) and not check.get("passed")]
        if failed:
            errors.append("air-gap install bundle checks failed: " + ", ".join(str(item) for item in failed))
    if bundle.get("passed") is not True:
        errors.append("air-gap install bundle is not marked passed")
    return AirgapBundleVerification(ok=not errors, errors=errors, warnings=warnings)


def append_airgap_install_bundle(chain: EvidenceChain, bundle: dict[str, Any], *, root: str | Path = ".", deployment_manifest: dict[str, Any] | None = None, helm_chart_validation: dict[str, Any] | None = None, deployment_image_integrity: dict[str, Any] | None = None, kubernetes_release_state: dict[str, Any] | None = None, key: str | None = None) -> dict[str, Any]:
    result = verify_airgap_install_bundle(bundle, root=root, deployment_manifest=deployment_manifest, helm_chart_validation=helm_chart_validation, deployment_image_integrity=deployment_image_integrity, kubernetes_release_state=kubernetes_release_state, key=key)
    if not result.ok:
        raise ValueError("invalid air-gap install bundle: " + "; ".join(result.errors))
    payload = {
        "bundle_id": bundle["bundle_id"],
        "bundle_hash": content_hash(bundle),
        "mode": bundle.get("mode"),
        "environment": bundle.get("environment"),
        "bundle_ref": bundle.get("bundle_ref"),
        "producer_ref": bundle.get("producer_ref"),
        "deployment_manifest": bundle.get("deployment_manifest"),
        "helm_chart_validation": bundle.get("helm_chart_validation"),
        "deployment_image_integrity": bundle.get("deployment_image_integrity"),
        "kubernetes_release_state": bundle.get("kubernetes_release_state"),
        "install_package": bundle.get("install_package"),
        "source_file_count": len(bundle.get("source_files", [])),
        "check_summary": bundle.get("summary"),
        "passed": bundle.get("passed"),
    }
    return chain.append(AIRGAP_BUNDLE_ENTRY_TYPE, payload, key=key, timestamp=bundle.get("generated_at"))


def load_airgap_install_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("air-gap install bundle must contain an object")
    return value


def write_airgap_install_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def load_kubernetes_release_state_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("Kubernetes release-state receipt must contain an object")
    return value


def write_kubernetes_release_state_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
def load_deployment_image_integrity_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("deployment image integrity receipt must contain an object")
    return value


def write_deployment_image_integrity_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def write_deployment_image_signature_artifact(path: str | Path, artifact: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")


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





def _airgap_install_bundle_body(root: Path, *, deployment_manifest: dict[str, Any], helm_chart_validation: dict[str, Any], deployment_image_integrity: dict[str, Any], kubernetes_release_state: dict[str, Any], mode: str, environment: str, bundle_ref: str, producer_ref: str, generated_at: str, key: str | None) -> dict[str, Any]:
    for value, field in ((mode, "mode"), (environment, "environment"), (bundle_ref, "bundle_ref"), (producer_ref, "producer_ref"), (generated_at, "generated_at")):
        _require_release_text(value, field)
    parse_rfc3339(generated_at)
    deployment_binding = _deployment_manifest_validation_binding(root, deployment_manifest)
    helm_binding = _helm_chart_validation_binding(root, helm_chart_validation, deployment_manifest)
    image_binding = _deployment_image_integrity_binding(root, deployment_image_integrity, deployment_manifest, key=key)
    release_binding = _kubernetes_release_state_binding(root, kubernetes_release_state, deployment_manifest, helm_chart_validation, key=key)
    source_records = [_source_record(root, path) for path in DEFAULT_AIRGAP_BUNDLE_SOURCE_PATHS]
    install_package = _airgap_install_package(bundle_ref=bundle_ref, helm_chart_validation=helm_chart_validation, deployment_image_integrity=deployment_image_integrity, kubernetes_release_state=kubernetes_release_state, source_records=source_records)
    checks = _airgap_install_bundle_checks(bundle_ref=bundle_ref, producer_ref=producer_ref, deployment_binding=deployment_binding, helm_binding=helm_binding, image_binding=image_binding, release_binding=release_binding, source_records=source_records, install_package=install_package)
    summary = _helm_check_summary(checks)
    passed = summary.get("failed", 0) == 0 and summary.get("passed", 0) == len(checks)
    return {"schema": AIRGAP_BUNDLE_SCHEMA, "mode": mode, "environment": environment, "generated_at": generated_at, "bundle_ref": bundle_ref, "producer_ref": producer_ref, "deployment_manifest": deployment_binding, "helm_chart_validation": helm_binding, "deployment_image_integrity": image_binding, "kubernetes_release_state": release_binding, "install_package": install_package, "source_files": source_records, "checks": checks, "summary": summary, "passed": passed, "limitations": ["This bundle is an offline, deterministic BYOC/air-gap install package manifest over local TrustAI deployment artifacts.", "It binds the deployment manifest, Helm validation, image integrity receipt, and Kubernetes release-state receipt into one signed artifact for external review.", "It does not prove a customer has imported the image or chart into an air-gapped registry unless paired with fresh customer/provider installation evidence."]}


def _deployment_image_integrity_binding(root: Path, receipt: dict[str, Any] | None, deployment_manifest: dict[str, Any], *, key: str | None) -> dict[str, Any] | None:
    if receipt is None:
        return None
    result = verify_deployment_image_integrity_receipt(receipt, root=root, deployment_manifest=deployment_manifest, key=key)
    image = receipt.get("image") if isinstance(receipt.get("image"), dict) else {}
    signature = receipt.get("image_signature") if isinstance(receipt.get("image_signature"), dict) else {}
    return {"receipt_id": receipt.get("receipt_id"), "receipt_hash": content_hash(receipt), "schema": receipt.get("schema"), "verified": result.ok, "passed": receipt.get("passed"), "check_summary": receipt.get("summary"), "image": image, "image_signature": {"verified": signature.get("verified"), "subject_hash": signature.get("subject_hash"), "signature_key_id": signature.get("signature_key_id"), "signature_provider": signature.get("signature_provider")}, "artifacts": receipt.get("artifacts", []), "errors": result.errors, "warnings": result.warnings}


def _kubernetes_release_state_binding(root: Path, receipt: dict[str, Any] | None, deployment_manifest: dict[str, Any], helm_chart_validation: dict[str, Any], *, key: str | None) -> dict[str, Any] | None:
    if receipt is None:
        return None
    result = verify_kubernetes_release_state_receipt(receipt, root=root, deployment_manifest=deployment_manifest, helm_chart_validation=helm_chart_validation, key=key)
    return {"receipt_id": receipt.get("receipt_id"), "receipt_hash": content_hash(receipt), "schema": receipt.get("schema"), "verified": result.ok, "passed": receipt.get("passed"), "check_summary": receipt.get("summary"), "release": receipt.get("release"), "workload": receipt.get("workload"), "network_policy": receipt.get("network_policy"), "audit_log": receipt.get("audit_log"), "errors": result.errors, "warnings": result.warnings}


def _airgap_install_package(*, bundle_ref: str, helm_chart_validation: dict[str, Any], deployment_image_integrity: dict[str, Any], kubernetes_release_state: dict[str, Any], source_records: list[dict[str, Any]]) -> dict[str, Any]:
    image = deployment_image_integrity.get("image") if isinstance(deployment_image_integrity.get("image"), dict) else {}
    release = kubernetes_release_state.get("release") if isinstance(kubernetes_release_state.get("release"), dict) else {}
    workload = kubernetes_release_state.get("workload") if isinstance(kubernetes_release_state.get("workload"), dict) else {}
    network_policy = kubernetes_release_state.get("network_policy") if isinstance(kubernetes_release_state.get("network_policy"), dict) else {}
    artifact_hashes = [artifact.get("sha256") for artifact in deployment_image_integrity.get("artifacts", []) if isinstance(artifact, dict) and artifact.get("sha256")]
    source_hashes = [source.get("sha256") for source in source_records if source.get("sha256")]
    return {"bundle_ref": bundle_ref, "artifact_types": ["docker-image", "helm-chart", "values", "network-policy", "sbom", "provenance", "image-signature", "release-state-export"], "chart": helm_chart_validation.get("chart"), "image": image, "release": release, "namespace": release.get("namespace"), "workload": {"deployment_ref": workload.get("deployment_ref"), "service_ref": workload.get("service_ref"), "network_policy_ref": workload.get("network_policy_ref"), "secret_ref": workload.get("secret_ref"), "service_account_ref": workload.get("service_account_ref")}, "network_policy": network_policy, "offline_inputs": ["deployment-manifest", "helm-chart-validation", "deployment-image-integrity", "kubernetes-release-state"], "source_hash_root": content_hash(sorted(source_hashes)), "artifact_hash_root": content_hash(sorted(artifact_hashes))}


def _airgap_install_bundle_checks(*, bundle_ref: str, producer_ref: str, deployment_binding: dict[str, Any] | None, helm_binding: dict[str, Any] | None, image_binding: dict[str, Any] | None, release_binding: dict[str, Any] | None, source_records: list[dict[str, Any]], install_package: dict[str, Any]) -> list[dict[str, Any]]:
    image = image_binding.get("image", {}) if isinstance(image_binding, dict) else {}
    image_signature = image_binding.get("image_signature", {}) if isinstance(image_binding, dict) else {}
    release = release_binding.get("release", {}) if isinstance(release_binding, dict) else {}
    workload = release_binding.get("workload", {}) if isinstance(release_binding, dict) else {}
    network_policy = release_binding.get("network_policy", {}) if isinstance(release_binding, dict) else {}
    desired = int(workload.get("desired_replicas") or 0) if isinstance(workload, dict) else 0
    ready = int(workload.get("ready_replicas") or 0) if isinstance(workload, dict) else 0
    return [
        _helm_check("bundle-ref-bound", bool(bundle_ref and producer_ref), "Bundle and producer references are recorded for offline custody.", "artifacts/airgap-install-bundle.json"),
        _helm_check("deployment-manifest-verified", bool(deployment_binding and deployment_binding.get("verified")), "The bundle is bound to a verified deployment manifest.", "artifacts/deployment-manifest.json"),
        _helm_check("helm-validation-passed", bool(helm_binding and helm_binding.get("verified") and helm_binding.get("passed") is True), "The bundle is bound to a passing Helm chart validation receipt.", "artifacts/helm-chart-validation.json"),
        _helm_check("image-integrity-passed", bool(image_binding and image_binding.get("verified") and image_binding.get("passed") is True), "The bundle is bound to a passing deployment image integrity receipt.", "artifacts/deployment-image-integrity.json"),
        _helm_check("image-signature-verified", image_signature.get("verified") is True, "The image integrity receipt includes a verified image signature subject.", "artifacts/trustai-image.sig"),
        _helm_check("image-pinned-digest", _is_sha256_ref(str(image.get("image_digest") or "")) and "@sha256:" in str(image.get("pinned_reference") or ""), "The image reference is pinned by digest for offline registry import.", "artifacts/deployment-image-integrity.json"),
        _helm_check("kubernetes-release-passed", bool(release_binding and release_binding.get("verified") and release_binding.get("passed") is True), "The bundle is bound to a passing Kubernetes release-state receipt.", "artifacts/kubernetes-release-state.json"),
        _helm_check("release-ready", release.get("release_status") == "deployed" and desired > 0 and ready >= desired, "The recorded release is deployed and ready replicas meet desired replicas.", "artifacts/kubernetes-release-state.json"),
        _helm_check("network-policy-admitted", network_policy.get("admitted") is True and bool(network_policy.get("network_policy_ref")), "The recorded release includes admitted NetworkPolicy evidence.", "artifacts/kubernetes-release-state.json"),
        _helm_check("source-files-bound", len(source_records) >= len(DEFAULT_AIRGAP_BUNDLE_SOURCE_PATHS), "The bundle binds the expected Docker, Helm, deployment docs, and schema source files.", "docs/specs/airgap-install-bundle-v0.1.md"),
        _helm_check("offline-inputs-covered", set(install_package.get("offline_inputs", [])) == {"deployment-manifest", "helm-chart-validation", "deployment-image-integrity", "kubernetes-release-state"}, "The bundle records every offline input required to replay BYOC install readiness.", "artifacts/airgap-install-bundle.json"),
    ]

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



def _kubernetes_release_state_body(
    root: Path,
    *,
    deployment_manifest: dict[str, Any],
    helm_chart_validation: dict[str, Any],
    environment: str,
    mode: str,
    provider: str,
    cluster_ref: str,
    namespace: str,
    release_name: str,
    release_revision: str,
    release_status: str,
    export_ref: str,
    export_hash: str,
    service_account_ref: str,
    deployment_ref: str,
    service_ref: str,
    network_policy_ref: str,
    secret_ref: str,
    desired_replicas: int,
    ready_replicas: int,
    network_policy_admitted: bool,
    pod_selector_hash: str,
    ingress_policy_hash: str,
    egress_policy_hash: str,
    audit_log_ref: str,
    audit_log_root: str,
    exported_at: str,
    issued_at: str | None,
    expires_at: str | None,
    generated_at: str,
) -> dict[str, Any]:
    for value, field in (
        (environment, "environment"),
        (mode, "mode"),
        (provider, "provider"),
        (cluster_ref, "cluster_ref"),
        (namespace, "namespace"),
        (release_name, "release_name"),
        (release_revision, "release_revision"),
        (release_status, "release_status"),
        (export_ref, "export_ref"),
        (export_hash, "export_hash"),
        (service_account_ref, "service_account_ref"),
        (deployment_ref, "deployment_ref"),
        (service_ref, "service_ref"),
        (network_policy_ref, "network_policy_ref"),
        (secret_ref, "secret_ref"),
        (pod_selector_hash, "pod_selector_hash"),
        (ingress_policy_hash, "ingress_policy_hash"),
        (egress_policy_hash, "egress_policy_hash"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (exported_at, "exported_at"),
        (generated_at, "generated_at"),
    ):
        _require_release_text(value, field)
    parse_rfc3339(generated_at)
    parse_rfc3339(exported_at)
    if issued_at:
        parse_rfc3339(str(issued_at))
    if expires_at:
        parse_rfc3339(str(expires_at))
    release = {
        "provider": provider,
        "cluster_ref": cluster_ref,
        "namespace": namespace,
        "release_name": release_name,
        "release_revision": str(release_revision),
        "release_status": release_status,
        "export_ref": export_ref,
        "export_hash": _normalize_sha256_ref(export_hash),
    }
    workload = {
        "service_account_ref": service_account_ref,
        "deployment_ref": deployment_ref,
        "service_ref": service_ref,
        "network_policy_ref": network_policy_ref,
        "secret_ref": secret_ref,
        "desired_replicas": int(desired_replicas),
        "ready_replicas": int(ready_replicas),
    }
    network_policy = {
        "network_policy_ref": network_policy_ref,
        "admitted": bool(network_policy_admitted),
        "pod_selector_hash": _normalize_sha256_ref(pod_selector_hash),
        "ingress_policy_hash": _normalize_sha256_ref(ingress_policy_hash),
        "egress_policy_hash": _normalize_sha256_ref(egress_policy_hash),
    }
    audit_log = {"audit_log_ref": audit_log_ref, "audit_log_root": _normalize_sha256_ref(audit_log_root)}
    freshness = {"issued_at": issued_at, "expires_at": expires_at}
    deployment_binding = _deployment_manifest_validation_binding(root, deployment_manifest)
    helm_binding = _helm_chart_validation_binding(root, helm_chart_validation, deployment_manifest)
    source_records = [_source_record(root, path) for path in DEFAULT_KUBERNETES_RELEASE_SOURCE_PATHS]
    checks = _kubernetes_release_state_checks(
        release=release,
        workload=workload,
        network_policy=network_policy,
        audit_log=audit_log,
        freshness=freshness,
        deployment_manifest_binding=deployment_binding,
        helm_chart_validation_binding=helm_binding,
    )
    summary = _helm_check_summary(checks)
    passed = summary.get("failed", 0) == 0 and summary.get("passed", 0) == len(checks)
    return {
        "schema": KUBERNETES_RELEASE_STATE_SCHEMA,
        "generated_at": generated_at,
        "exported_at": exported_at,
        "environment": environment,
        "mode": mode,
        "release": release,
        "workload": workload,
        "network_policy": network_policy,
        "audit_log": audit_log,
        "freshness": freshness,
        "deployment_manifest": deployment_binding,
        "helm_chart_validation": helm_binding,
        "source_files": source_records,
        "checks": checks,
        "summary": summary,
        "passed": passed,
        "limitations": [
            "This receipt records a provider/customer Kubernetes release-state export by reference and hash for offline review.",
            "It does not fetch live Kubernetes state; reviewers must obtain the referenced provider export and compare its hash.",
            "Production BYOC authority still requires fresh provider-owned audit logs, KMS/Object Lock evidence, and customer account exports.",
        ],
    }


def _helm_chart_validation_binding(root: Path, receipt: dict[str, Any] | None, deployment_manifest: dict[str, Any]) -> dict[str, Any] | None:
    if receipt is None:
        return None
    result = verify_helm_chart_validation_receipt(receipt, root=root, deployment_manifest=deployment_manifest)
    return {
        "receipt_id": receipt.get("receipt_id"),
        "receipt_hash": content_hash(receipt),
        "schema": receipt.get("schema"),
        "verified": result.ok,
        "passed": receipt.get("passed"),
        "check_summary": receipt.get("summary"),
        "errors": result.errors,
        "warnings": result.warnings,
    }


def _kubernetes_release_state_checks(
    *,
    release: dict[str, Any],
    workload: dict[str, Any],
    network_policy: dict[str, Any],
    audit_log: dict[str, Any],
    freshness: dict[str, Any],
    deployment_manifest_binding: dict[str, Any] | None,
    helm_chart_validation_binding: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    desired = int(workload.get("desired_replicas") or 0)
    ready = int(workload.get("ready_replicas") or 0)
    return [
        _helm_check(
            "deployment-manifest-bound",
            bool(deployment_manifest_binding and deployment_manifest_binding.get("verified")),
            "The Kubernetes release-state receipt is bound to a verified deployment manifest.",
            "artifacts/deployment-manifest.json",
        ),
        _helm_check(
            "helm-validation-bound",
            bool(helm_chart_validation_binding and helm_chart_validation_binding.get("verified") and helm_chart_validation_binding.get("passed") is True),
            "The Kubernetes release-state receipt is bound to a passing Helm chart validation receipt.",
            "artifacts/helm-chart-validation.json",
        ),
        _helm_check(
            "release-export-bound",
            bool(release.get("export_ref") and _is_sha256_ref(str(release.get("export_hash") or ""))),
            "Provider/customer Helm release and namespace export reference is hash-bound.",
            "artifacts/kubernetes-release-state.json",
        ),
        _helm_check(
            "release-namespace-state",
            all(release.get(field) for field in ("provider", "cluster_ref", "namespace", "release_name", "release_revision", "release_status")),
            "Release provider, cluster, namespace, name, revision, and status are recorded.",
            "artifacts/kubernetes-release-state.json",
        ),
        _helm_check(
            "workload-refs-bound",
            all(workload.get(field) for field in ("deployment_ref", "service_ref", "network_policy_ref", "secret_ref", "service_account_ref")),
            "Deployment, Service, NetworkPolicy, Secret, and ServiceAccount refs are bound.",
            "artifacts/kubernetes-release-state.json",
        ),
        _helm_check(
            "ready-replicas-match",
            desired > 0 and ready >= desired,
            "Ready replica count meets or exceeds desired replica count in the recorded export.",
            "artifacts/kubernetes-release-state.json",
        ),
        _helm_check(
            "network-policy-admitted",
            network_policy.get("admitted") is True and bool(network_policy.get("network_policy_ref")),
            "Recorded provider export says the API NetworkPolicy was admitted.",
            "artifacts/kubernetes-release-state.json",
        ),
        _helm_check(
            "network-policy-rules-hashed",
            all(_is_sha256_ref(str(network_policy.get(field) or "")) for field in ("pod_selector_hash", "ingress_policy_hash", "egress_policy_hash")),
            "NetworkPolicy pod selector, ingress, and egress rule summaries are hash-bound.",
            "artifacts/kubernetes-release-state.json",
        ),
        _helm_check(
            "audit-log-root-bound",
            bool(audit_log.get("audit_log_ref") and _is_sha256_ref(str(audit_log.get("audit_log_root") or ""))),
            "Kubernetes/provider audit-log reference and root hash are bound.",
            "artifacts/kubernetes-release-state.json",
        ),
        _helm_check(
            "freshness-window-present",
            bool(freshness.get("issued_at") and freshness.get("expires_at")),
            "The provider export has an explicit issued/expires freshness window.",
            "artifacts/kubernetes-release-state.json",
        ),
    ]


def _require_release_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Kubernetes release-state {field} is required")


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
    key: str | None,
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
    sbom_artifact = _artifact_record(root, sbom_path, "sbom")
    provenance_artifact = _artifact_record(root, provenance_path, "provenance")
    signature_artifact = _artifact_record(root, signature_path, "signature")
    artifacts = [sbom_artifact, provenance_artifact, signature_artifact]
    signature_verification = _deployment_image_signature_verification(
        root,
        signature_path,
        image=image,
        deployment_manifest_binding=manifest_binding,
        sbom_record=sbom_artifact,
        provenance_record=provenance_artifact,
        key=key,
    )
    checks = _deployment_image_integrity_checks(
        root,
        image=image,
        source_records=source_records,
        artifacts=artifacts,
        deployment_manifest_binding=manifest_binding,
        signature_verification=signature_verification,
    )
    summary = _helm_check_summary(checks)
    passed = summary.get("failed", 0) == 0 and summary.get("passed", 0) == len(checks)
    return {
        "schema": DEPLOYMENT_IMAGE_INTEGRITY_SCHEMA,
        "generated_at": generated_at,
        "image": image,
        "deployment_manifest": manifest_binding,
        "source_files": source_records,
        "image_signature": signature_verification,
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
    signature_verification: dict[str, Any],
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
        _helm_check(
            "signature-artifact-verifies-subject",
            bool(signature_verification.get("verified")),
            "The image signature artifact verifies against the image digest, deployment manifest, SBOM, and provenance subject.",
            "artifacts/trustai-image.sig",
        ),
    ]



def _deployment_image_signature_subject(
    *,
    image: dict[str, Any],
    deployment_manifest_binding: dict[str, Any] | None,
    sbom_record: dict[str, Any],
    provenance_record: dict[str, Any],
) -> dict[str, Any]:
    manifest = deployment_manifest_binding or {}
    return {
        "image": {
            "image_ref": image.get("image_ref"),
            "image_digest": image.get("image_digest"),
            "pinned_reference": image.get("pinned_reference"),
        },
        "deployment_manifest": {
            "manifest_id": manifest.get("manifest_id"),
            "manifest_hash": manifest.get("manifest_hash"),
        },
        "artifacts": [
            _deployment_image_signature_artifact_subject(sbom_record),
            _deployment_image_signature_artifact_subject(provenance_record),
        ],
    }


def _deployment_image_signature_artifact_subject(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": artifact.get("kind"),
        "sha256": artifact.get("sha256"),
        "size_bytes": artifact.get("size_bytes"),
    }


def _deployment_image_signature_verification(
    root: Path,
    signature_path: str | Path,
    *,
    image: dict[str, Any],
    deployment_manifest_binding: dict[str, Any] | None,
    sbom_record: dict[str, Any],
    provenance_record: dict[str, Any],
    key: str | None,
) -> dict[str, Any]:
    expected_subject = _deployment_image_signature_subject(
        image=image,
        deployment_manifest_binding=deployment_manifest_binding,
        sbom_record=sbom_record,
        provenance_record=provenance_record,
    )
    result: dict[str, Any] = {
        "schema": DEPLOYMENT_IMAGE_SIGNATURE_SCHEMA,
        "path": str(signature_path),
        "subject_hash": content_hash(expected_subject),
        "verified": False,
        "errors": [],
    }
    try:
        artifact = json.loads(_resolve_artifact_path(root, signature_path).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        result["errors"].append(f"image signature artifact is not valid JSON: {exc}")
        return result
    if not isinstance(artifact, dict):
        result["errors"].append("image signature artifact must contain an object")
        return result
    if artifact.get("schema") != DEPLOYMENT_IMAGE_SIGNATURE_SCHEMA:
        result["errors"].append(f"unsupported image signature schema: {artifact.get('schema')}")
    if artifact.get("subject") != expected_subject:
        result["errors"].append("image signature subject does not match replayed image, manifest, SBOM, and provenance bindings")
    payload = {
        "schema": artifact.get("schema"),
        "generated_at": artifact.get("generated_at"),
        "subject": artifact.get("subject"),
    }
    signature = artifact.get("signature")
    if not isinstance(signature, dict) or not verify_value(payload, signature, key):
        result["errors"].append("image signature artifact signature verification failed")
    else:
        result["signature_key_id"] = signature.get("key_id")
        result["signature_provider"] = signature.get("provider")
    result["verified"] = not result["errors"]
    return result
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
