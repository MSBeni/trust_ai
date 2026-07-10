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
    "deploy/helm/trustai/templates/demo-job.yaml",
    "deploy/helm/trustai/templates/pvc.yaml",
    "docs/deployment/byoc.md",
    "docs/specs/production-trust-v0.1.md",
    "README.md",
)


@dataclass
class DeploymentManifestVerification:
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
