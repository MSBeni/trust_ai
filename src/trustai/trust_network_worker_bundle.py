from __future__ import annotations

import base64
import binascii
import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .contracts import load_contract
from .crypto import sign_value, verify_value
from .policy import load_policy_pack
from .trust_network_worker import verify_trust_network_worker_receipt

TRUST_NETWORK_WORKER_BUNDLE_SCHEMA = "trustai.trust-network-worker-bundle/0.1"
TRUST_NETWORK_WORKER_BUNDLE_ENTRY_TYPE = "trust_network.worker_bundle_exported"
TRUST_NETWORK_WORKER_BUNDLE_MODES = {"offline-review", "procurement-review", "auditor-review"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

JSON_SOURCE_TYPES = {
    "worker_receipt": "trust-network-worker-receipt",
    "service_attestation": "trust-network-service-attestation",
    "registry_receipt": "trust-network-registry",
    "trust_network_manifest": "trust-network-manifest",
    "vendor_identity_receipt": "vendor-identity",
    "identity_provider_attestation": "identity-provider-attestation",
    "identity_payload": "identity-payload",
    "procurement_receipt": "procurement-clause",
    "procurement_integration_receipt": "procurement-integration",
    "registry_status_receipt": "trust-network-registry-status",
    "marketplace_catalog": "marketplace-catalog",
    "marketplace_distribution": "marketplace-distribution",
    "marketplace_author_governance": "marketplace-author-governance",
    "marketplace_settlement": "marketplace-settlement",
}
REQUIRED_JSON_SOURCES = {"worker_receipt", "service_attestation", "registry_receipt"}
SUPPORTED_SOURCE_KEYS = set(JSON_SOURCE_TYPES) | {"proof_packs"}


@dataclass
class TrustNetworkWorkerBundleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_trust_network_worker_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("trust-network worker bundle must contain an object")
    return value


def write_trust_network_worker_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def build_trust_network_worker_bundle(
    receipt: dict[str, Any],
    service_attestation: dict[str, Any],
    registry_receipt: dict[str, Any],
    *,
    trust_network_manifest: dict[str, Any] | None = None,
    vendor_identity_receipt: dict[str, Any] | None = None,
    identity_provider_attestation: dict[str, Any] | None = None,
    identity_payload: dict[str, Any] | None = None,
    procurement_receipt: dict[str, Any] | None = None,
    procurement_integration_receipt: dict[str, Any] | None = None,
    proof_packs: list[dict[str, Any]] | None = None,
    registry_status_receipt: dict[str, Any] | None = None,
    marketplace_catalog: dict[str, Any] | None = None,
    marketplace_distribution: dict[str, Any] | None = None,
    frontend_bundle_path: str | Path | None = None,
    marketplace_author_governance: dict[str, Any] | None = None,
    marketplace_settlement: dict[str, Any] | None = None,
    artifact_paths: dict[str, Any],
    root: str | Path = ".",
    mode: str = "offline-review",
    environment: str | None = None,
    reviewer_ref: str,
    bundle_ref: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in TRUST_NETWORK_WORKER_BUNDLE_MODES:
        raise ValueError(f"mode must be one of {sorted(TRUST_NETWORK_WORKER_BUNDLE_MODES)}")
    if not isinstance(reviewer_ref, str) or not reviewer_ref.strip():
        raise ValueError("trust-network worker bundle reviewer_ref is required")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    packs = proof_packs or []
    replay = verify_trust_network_worker_receipt(
        receipt,
        service_attestation=service_attestation,
        registry_receipt=registry_receipt,
        trust_network_manifest=trust_network_manifest,
        vendor_identity_receipt=vendor_identity_receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_payload=identity_payload,
        procurement_receipt=procurement_receipt,
        procurement_integration_receipt=procurement_integration_receipt,
        proof_packs=packs,
        registry_status_receipt=registry_status_receipt,
        marketplace_catalog=marketplace_catalog,
        marketplace_distribution=marketplace_distribution,
        frontend_bundle_path=frontend_bundle_path,
        marketplace_author_governance=marketplace_author_governance,
        marketplace_settlement=marketplace_settlement,
        root=root,
        key=key,
    )
    if not replay.ok:
        raise ValueError("invalid trust-network worker source: " + "; ".join(replay.errors))
    sources = _source_objects(
        worker_receipt=receipt,
        service_attestation=service_attestation,
        registry_receipt=registry_receipt,
        trust_network_manifest=trust_network_manifest,
        vendor_identity_receipt=vendor_identity_receipt,
        identity_provider_attestation=identity_provider_attestation,
        identity_payload=identity_payload,
        procurement_receipt=procurement_receipt,
        procurement_integration_receipt=procurement_integration_receipt,
        proof_packs=packs,
        registry_status_receipt=registry_status_receipt,
        marketplace_catalog=marketplace_catalog,
        marketplace_distribution=marketplace_distribution,
        marketplace_author_governance=marketplace_author_governance,
        marketplace_settlement=marketplace_settlement,
    )
    secret_errors: list[str] = []
    _check_no_secret_values(sources, secret_errors)
    if secret_errors:
        raise ValueError("trust-network worker bundle source contains secret-like values: " + "; ".join(secret_errors))
    source_artifacts = _build_artifacts(artifact_paths, sources, service_attestation, marketplace_catalog, frontend_bundle_path, root)
    body = {
        "schema": TRUST_NETWORK_WORKER_BUNDLE_SCHEMA,
        "mode": mode,
        "environment": environment or receipt.get("environment"),
        "generated_at": timestamp,
        "reviewer_ref": reviewer_ref,
        "bundle_ref": bundle_ref or f"trust-network-worker-bundle:{receipt.get('worker_operation_id', 'unknown')}",
        "verification_options": {"root": "."},
        "source": _source_summary(receipt, service_attestation, registry_receipt, marketplace_catalog, marketplace_distribution, marketplace_settlement),
        "sources": sources,
        "source_artifacts": source_artifacts,
        "summary": _bundle_summary(receipt, sources, source_artifacts),
        "controls": _controls(receipt, service_attestation, sources, source_artifacts),
        "limitations": [
            "This bundle is self-contained for offline review of one trust-network worker receipt and its replay sources.",
            "It embeds parsed JSON receipts, raw JSON bytes, marketplace asset bytes, and frontend bundle bytes when supplied.",
            "It proves replay against embedded registry, marketplace, procurement, vendor identity, and worker evidence; it does not claim live hosted trust-network callbacks or production scheduler authority beyond the embedded receipts.",
        ],
    }
    bundle_id = content_hash(body)
    return {**body, "bundle_id": bundle_id, "signatures": [sign_value({"bundle_id": bundle_id, "trust_network_worker_bundle": body}, key)]}


def verify_trust_network_worker_bundle(bundle: dict[str, Any], *, key: str | None = None) -> TrustNetworkWorkerBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if bundle.get("schema") != TRUST_NETWORK_WORKER_BUNDLE_SCHEMA:
        errors.append(f"unsupported trust-network worker bundle schema: {bundle.get('schema')}")
    body = without_keys(bundle, "bundle_id", "signatures")
    if bundle.get("bundle_id") != content_hash(body):
        errors.append("bundle_id does not match canonical trust-network worker bundle body")
    signatures = bundle.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("trust-network worker bundle must include at least one signature")
    else:
        signed = {"bundle_id": bundle.get("bundle_id"), "trust_network_worker_bundle": body}
        if not any(isinstance(signature, dict) and verify_value(signed, signature, key) for signature in signatures):
            errors.append("trust-network worker bundle signature verification failed")
    if bundle.get("mode") not in TRUST_NETWORK_WORKER_BUNDLE_MODES:
        errors.append("trust-network worker bundle mode is unsupported")
    try:
        parse_rfc3339(str(bundle.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"trust-network worker bundle generated_at invalid: {exc}")
    if not isinstance(bundle.get("reviewer_ref"), str) or not bundle.get("reviewer_ref", "").strip():
        errors.append("trust-network worker bundle reviewer_ref is required")

    sources = bundle.get("sources")
    if not isinstance(sources, dict):
        errors.append("trust-network worker bundle sources must be an object")
        sources = {}
    source_values = _read_sources(sources, errors)
    verified_artifacts = _verify_artifacts(bundle.get("source_artifacts"), source_values, errors)
    if source_values:
        with tempfile.TemporaryDirectory() as tmp_dir:
            replay_root = Path(tmp_dir)
            _materialize_embedded_assets(replay_root, verified_artifacts)
            frontend_path = None
            frontend = verified_artifacts.get("frontend_bundle")
            if frontend:
                frontend_path = replay_root / _extract_name(frontend["artifact"])
                frontend_path.parent.mkdir(parents=True, exist_ok=True)
                frontend_path.write_bytes(frontend["data"])
            replay = verify_trust_network_worker_receipt(
                source_values["worker_receipt"],
                service_attestation=source_values["service_attestation"],
                registry_receipt=source_values["registry_receipt"],
                trust_network_manifest=source_values.get("trust_network_manifest"),
                vendor_identity_receipt=source_values.get("vendor_identity_receipt"),
                identity_provider_attestation=source_values.get("identity_provider_attestation"),
                identity_payload=source_values.get("identity_payload"),
                procurement_receipt=source_values.get("procurement_receipt"),
                procurement_integration_receipt=source_values.get("procurement_integration_receipt"),
                proof_packs=source_values.get("proof_packs", []),
                registry_status_receipt=source_values.get("registry_status_receipt"),
                marketplace_catalog=source_values.get("marketplace_catalog"),
                marketplace_distribution=source_values.get("marketplace_distribution"),
                frontend_bundle_path=frontend_path,
                marketplace_author_governance=source_values.get("marketplace_author_governance"),
                marketplace_settlement=source_values.get("marketplace_settlement"),
                root=replay_root,
                key=key,
            )
        errors.extend("trust-network worker bundle source replay: " + error for error in replay.errors)
        warnings.extend(replay.warnings)
        if bundle.get("source") != _source_summary(source_values["worker_receipt"], source_values["service_attestation"], source_values["registry_receipt"], source_values.get("marketplace_catalog"), source_values.get("marketplace_distribution"), source_values.get("marketplace_settlement")):
            errors.append("trust-network worker bundle source summary does not match embedded sources")
        artifacts = bundle.get("source_artifacts") if isinstance(bundle.get("source_artifacts"), list) else []
        if bundle.get("summary") != _bundle_summary(source_values["worker_receipt"], source_values, artifacts):
            errors.append("trust-network worker bundle summary does not match embedded sources")
        if bundle.get("controls") != _controls(source_values["worker_receipt"], source_values["service_attestation"], source_values, artifacts):
            errors.append("trust-network worker bundle controls do not match embedded sources")
    _check_no_secret_values(bundle, errors)
    return TrustNetworkWorkerBundleVerification(ok=not errors, errors=errors, warnings=warnings)


def write_trust_network_worker_bundle_markdown(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_trust_network_worker_bundle_markdown(bundle), encoding="utf-8")


def render_trust_network_worker_bundle_markdown(bundle: dict[str, Any]) -> str:
    source = bundle.get("source", {}) if isinstance(bundle.get("source"), dict) else {}
    summary = bundle.get("summary", {}) if isinstance(bundle.get("summary"), dict) else {}
    controls = bundle.get("controls", []) if isinstance(bundle.get("controls"), list) else []
    artifacts = bundle.get("source_artifacts", []) if isinstance(bundle.get("source_artifacts"), list) else []
    control_rows = "\n".join("| {name} | {status} | {detail} |".format(name=_cell(item.get("name", "")), status=_cell(item.get("status", "")), detail=_cell(item.get("detail", ""))) for item in controls if isinstance(item, dict))
    artifact_rows = "\n".join("| {name} | {kind} | {size} | `{sha}` | `{content}` |".format(name=_cell(item.get("name", "")), kind=_cell(item.get("artifact_type", "")), size=item.get("size_bytes", 0), sha=item.get("sha256", ""), content=item.get("content_hash", "")) for item in artifacts if isinstance(item, dict))
    hashes = summary.get("source_object_hashes", {}) if isinstance(summary.get("source_object_hashes"), dict) else {}
    hash_lines = "\n".join(f"- {name}: `{value}`" for name, value in sorted(hashes.items()))
    limitations = "\n".join(f"- {item}" for item in bundle.get("limitations", []))
    return f"""# TrustAI Trust Network Worker Bundle

Bundle ID: `{bundle.get('bundle_id', '')}`

Bundle ref: `{bundle.get('bundle_ref', '')}`

Mode: `{bundle.get('mode', '')}`

Environment: `{bundle.get('environment', '')}`

Generated at: `{bundle.get('generated_at', '')}`

Reviewer: `{bundle.get('reviewer_ref', '')}`

## Source

- Worker operation ID: `{source.get('worker_operation_id', '')}`
- Service attestation ID: `{source.get('service_attestation_id', '')}`
- Registration ID: `{source.get('registration_id', '')}`
- Run ref: `{source.get('run_ref', '')}`
- Operation kind: `{source.get('operation_kind', '')}`
- Catalog ID: `{source.get('catalog_id', '')}`
- Distribution ID: `{source.get('distribution_id', '')}`
- Settlement ID: `{source.get('settlement_id', '')}`
- Destination: `{source.get('destination_ref', '')}`
- Response status: `{source.get('response_status', '')}`

## Embedded Source Summary

- Embedded source artifacts: {summary.get('source_artifact_count', 0)}
- Proof packs replayed: {summary.get('proof_pack_count', 0)}
- Marketplace assets replayed: {summary.get('marketplace_asset_count', 0)}
- Frontend bundle replayed: {summary.get('frontend_bundle_replayed', False)}
- Source artifact sha256 root: `{summary.get('source_artifact_sha256_root', '')}`
- Source artifact content root: `{summary.get('source_artifact_content_root', '')}`

{hash_lines or '- No source hashes recorded.'}

## Controls

| Control | Status | Detail |
|---|---|---|
{control_rows or '| None | unknown | No controls recorded. |'}

## Source Artifacts

| Name | Type | Bytes | SHA-256 | Content Hash |
|---|---|---:|---|---|
{artifact_rows or '| None | none | 0 | `` | `` |'}

## Limitations

{limitations or '- None'}
"""


def extract_trust_network_worker_bundle_sources(bundle: dict[str, Any], out_dir: str | Path, *, key: str | None = None, overwrite: bool = False) -> list[dict[str, Any]]:
    result = verify_trust_network_worker_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid trust-network worker bundle: " + "; ".join(result.errors))
    artifacts = bundle.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        raise ValueError("trust-network worker bundle source_artifacts must be a list")
    root = Path(out_dir)
    extracted: list[dict[str, Any]] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("trust-network worker bundle source artifact must be an object")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("trust-network worker bundle source artifact name is required")
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise ValueError(f"trust-network worker bundle source artifact content_b64 invalid: {name}") from exc
        if artifact.get("sha256") != _sha256_ref(data):
            raise ValueError(f"trust-network worker bundle source artifact sha256 mismatch: {name}")
        target = root / _extract_name(artifact)
        if target.exists() and not overwrite:
            raise ValueError(f"trust-network worker bundle output already exists: {target}")
        if target.exists() and target.is_dir():
            raise ValueError(f"trust-network worker bundle output path is a directory: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        extracted.append({"name": name, "artifact_type": artifact.get("artifact_type"), "sha256": artifact.get("sha256"), "bytes": len(data), "artifact_id": artifact.get("artifact_id"), "extracted_to": str(target)})
    return extracted


def append_trust_network_worker_bundle(chain: EvidenceChain, bundle: dict[str, Any], *, key: str | None = None) -> dict[str, Any]:
    result = verify_trust_network_worker_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid trust-network worker bundle: " + "; ".join(result.errors))
    payload = {"bundle_id": bundle["bundle_id"], "bundle_hash": content_hash(bundle), "mode": bundle.get("mode"), "environment": bundle.get("environment"), "generated_at": bundle.get("generated_at"), "reviewer_ref": bundle.get("reviewer_ref"), "bundle_ref": bundle.get("bundle_ref"), "source": bundle.get("source"), "summary": bundle.get("summary"), "control_summary": _status_summary(bundle.get("controls", []))}
    return chain.append(TRUST_NETWORK_WORKER_BUNDLE_ENTRY_TYPE, payload, key=key, timestamp=bundle.get("generated_at"))


def _source_objects(**objects: Any) -> dict[str, Any]:
    sources: dict[str, Any] = {}
    for name, value in objects.items():
        if value is None:
            continue
        if name == "proof_packs":
            if value:
                sources[name] = [_clone(item) for item in value]
        else:
            sources[name] = _clone(value)
    return sources


def _read_sources(sources: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for name in sources:
        if name not in SUPPORTED_SOURCE_KEYS:
            errors.append(f"trust-network worker bundle sources.{name} is unsupported")
    for name in REQUIRED_JSON_SOURCES:
        value = sources.get(name)
        if not isinstance(value, dict):
            errors.append(f"trust-network worker bundle sources.{name} is required")
        else:
            values[name] = value
    for name in set(JSON_SOURCE_TYPES) - REQUIRED_JSON_SOURCES:
        if name in sources:
            if isinstance(sources.get(name), dict):
                values[name] = sources[name]
            else:
                errors.append(f"trust-network worker bundle sources.{name} must be an object")
    packs = sources.get("proof_packs", [])
    if isinstance(packs, list) and all(isinstance(item, dict) for item in packs):
        values["proof_packs"] = packs
    elif "proof_packs" in sources:
        errors.append("trust-network worker bundle sources.proof_packs must be a list of objects")
    else:
        values["proof_packs"] = []
    return values if REQUIRED_JSON_SOURCES <= set(values) else {}


def _build_artifacts(paths: dict[str, Any], sources: dict[str, Any], service_attestation: dict[str, Any], marketplace_catalog: dict[str, Any] | None, frontend_bundle_path: str | Path | None, root: str | Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for name, artifact_type in JSON_SOURCE_TYPES.items():
        if name in sources:
            path = paths.get(name)
            if path is None:
                raise ValueError(f"trust-network worker bundle artifact path is required: {name}")
            artifacts.append(_json_artifact(name, artifact_type, path, sources[name]))
    packs = sources.get("proof_packs", [])
    if packs:
        pack_paths = paths.get("proof_packs")
        if not isinstance(pack_paths, list) or len(pack_paths) != len(packs):
            raise ValueError("trust-network worker bundle proof_packs artifact paths must match supplied packs")
        for index, pack in enumerate(packs):
            artifacts.append(_json_artifact(f"proof_pack_{index}", "proof-pack", pack_paths[index], pack))
    if frontend_bundle_path is not None:
        artifacts.append(_binary_artifact("frontend_bundle", "frontend-bundle", frontend_bundle_path, _signed_frontend_artifact(service_attestation), expected_hash=_service_frontend_hash(service_attestation)))
    artifacts.extend(_marketplace_asset_artifacts(marketplace_catalog, root))
    return artifacts


def _json_artifact(name: str, artifact_type: str, path: str | Path, expected: Any) -> dict[str, Any]:
    data = Path(path).read_bytes()
    try:
        parsed = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"trust-network worker bundle artifact JSON invalid: {name}: {exc}") from exc
    parsed_hash = content_hash(parsed)
    expected_hash = content_hash(expected)
    if parsed_hash != expected_hash:
        raise ValueError(f"trust-network worker bundle artifact content hash mismatch: {name}")
    body = {"name": name, "artifact_type": artifact_type, "path": str(path).replace("\\", "/"), "media_type": "application/json", "size_bytes": len(data), "sha256": _sha256_ref(data), "content_hash": parsed_hash, "expected_content_hash": expected_hash, "content_b64": base64.b64encode(data).decode("ascii")}
    return {**body, "artifact_id": content_hash(body)}


def _binary_artifact(name: str, artifact_type: str, path: str | Path, signed: dict[str, Any] | None = None, *, expected_hash: str | None = None, expected_content_hash: str | None = None) -> dict[str, Any]:
    source = Path(path)
    data = source.read_bytes()
    sha = _sha256_ref(data)
    byte_expected = expected_hash or (signed or {}).get("hash")
    expected = expected_content_hash or byte_expected or sha
    if byte_expected and byte_expected != sha:
        raise ValueError(f"trust-network worker bundle binary artifact hash mismatch: {name}")
    body = {"name": name, "artifact_type": artifact_type, "path": str(path).replace("\\", "/"), "media_type": _media_type(source), "size_bytes": len(data), "sha256": sha, "content_hash": sha, "expected_content_hash": expected, "signed_source_id": (signed or {}).get("id"), "content_b64": base64.b64encode(data).decode("ascii")}
    return {**body, "artifact_id": content_hash(body)}


def _marketplace_asset_artifacts(catalog: dict[str, Any] | None, root: str | Path) -> list[dict[str, Any]]:
    if not isinstance(catalog, dict):
        return []
    records: list[dict[str, Any]] = []
    root_path = Path(root)
    for index, asset in enumerate(catalog.get("assets", [])):
        if not isinstance(asset, dict) or not asset.get("path"):
            continue
        path = root_path / str(asset["path"])
        artifact = _binary_artifact(f"marketplace_asset_{index}", "marketplace-asset", path, expected_content_hash=asset.get("content_hash"))
        artifact["asset_path"] = str(asset["path"]).replace("\\", "/")
        artifact["asset_type"] = asset.get("type")
        artifact["asset_id"] = asset.get("asset_id")
        artifact["artifact_id"] = content_hash(without_keys(artifact, "artifact_id"))
        records.append(artifact)
    return records


def _verify_artifacts(value: Any, sources: dict[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    verified: dict[str, dict[str, Any]] = {}
    if not isinstance(value, list):
        errors.append("trust-network worker bundle source_artifacts must be a list")
        return verified
    expected_names = _expected_names(sources)
    actual_names: set[str] = set()
    for artifact in value:
        if not isinstance(artifact, dict):
            errors.append("trust-network worker bundle source artifact must be an object")
            continue
        body = without_keys(artifact, "artifact_id")
        if artifact.get("artifact_id") != content_hash(body):
            errors.append(f"trust-network worker bundle source artifact id mismatch: {artifact.get('name')}")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            errors.append("trust-network worker bundle source artifact name is required")
            continue
        actual_names.add(name)
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (ValueError, TypeError) as exc:
            errors.append(f"trust-network worker bundle source artifact content_b64 invalid: {name}: {exc}")
            continue
        if artifact.get("sha256") != _sha256_ref(data):
            errors.append(f"trust-network worker bundle source artifact sha256 mismatch: {name}")
        if artifact.get("size_bytes") != len(data):
            errors.append(f"trust-network worker bundle source artifact size mismatch: {name}")
        if name == "frontend_bundle" or name.startswith("marketplace_asset_"):
            if artifact.get("content_hash") != _sha256_ref(data):
                errors.append(f"trust-network worker bundle binary content hash mismatch: {name}")
            if name == "frontend_bundle":
                _verify_frontend(artifact, data, sources.get("service_attestation"), errors)
            if name.startswith("marketplace_asset_"):
                _verify_marketplace_asset(artifact, data, sources.get("marketplace_catalog"), errors)
            verified[name] = {"artifact": artifact, "data": data}
            continue
        expected = _source_for_name(name, sources)
        if expected is None:
            errors.append(f"trust-network worker bundle source artifact unsupported: {name}")
            continue
        if artifact.get("artifact_type") != _type_for_name(name):
            errors.append(f"trust-network worker bundle source artifact type mismatch: {name}")
        try:
            parsed = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"trust-network worker bundle source artifact JSON invalid: {name}: {exc}")
            continue
        parsed_hash = content_hash(parsed)
        if artifact.get("content_hash") != parsed_hash:
            errors.append(f"trust-network worker bundle source artifact content hash mismatch: {name}")
        if content_hash(expected) != parsed_hash:
            errors.append(f"trust-network worker bundle source artifact does not match embedded source: {name}")
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    if missing:
        errors.append("trust-network worker bundle source artifacts missing: " + ", ".join(missing))
    if extra:
        errors.append("trust-network worker bundle source artifacts unsupported for embedded sources: " + ", ".join(extra))
    return verified

def _verify_frontend(artifact: dict[str, Any], data: bytes, service_attestation: dict[str, Any] | None, errors: list[str]) -> None:
    if artifact.get("artifact_type") != "frontend-bundle":
        errors.append("trust-network worker bundle source artifact type mismatch: frontend_bundle")
    sha = _sha256_ref(data)
    if artifact.get("content_hash") != sha:
        errors.append("trust-network worker bundle frontend bundle content hash must equal byte sha256")
    signed = _signed_frontend_artifact(service_attestation or {})
    expected = signed.get("hash") or _service_frontend_hash(service_attestation or {})
    if expected and artifact.get("sha256") != expected:
        errors.append("trust-network worker bundle frontend bundle sha256 does not match signed service artifact")
    if signed:
        if signed.get("size_bytes") != artifact.get("size_bytes"):
            errors.append("trust-network worker bundle frontend bundle size_bytes does not match signed service artifact")
        if signed.get("schema") != artifact.get("media_type"):
            errors.append("trust-network worker bundle frontend bundle media_type does not match signed service artifact")


def _verify_marketplace_asset(artifact: dict[str, Any], data: bytes, catalog: dict[str, Any] | None, errors: list[str]) -> None:
    if artifact.get("artifact_type") != "marketplace-asset":
        errors.append(f"trust-network worker bundle marketplace asset type mismatch: {artifact.get('name')}")
    if not isinstance(catalog, dict):
        errors.append("trust-network worker bundle marketplace asset embedded without marketplace catalog source")
        return
    asset_path = str(artifact.get("asset_path") or "").replace("\\", "/")
    assets = catalog.get("assets", [])
    catalog_asset = None
    if isinstance(assets, list):
        for item in assets:
            if isinstance(item, dict) and str(item.get("path") or "").replace("\\", "/") == asset_path:
                catalog_asset = item
                break
    if catalog_asset is None:
        errors.append(f"trust-network worker bundle marketplace asset is not listed in catalog: {asset_path}")
        return
    try:
        parsed = _load_marketplace_asset(artifact, data)
    except ValueError as exc:
        errors.append(f"trust-network worker bundle marketplace asset invalid: {asset_path}: {exc}")
        return
    parsed_hash = content_hash(parsed)
    expected = artifact.get("expected_content_hash") or catalog_asset.get("content_hash")
    if expected and parsed_hash != expected:
        errors.append(f"trust-network worker bundle marketplace asset content hash mismatch: {asset_path}")
    if catalog_asset.get("content_hash") != parsed_hash:
        errors.append(f"trust-network worker bundle marketplace asset does not match catalog content hash: {asset_path}")
    if catalog_asset.get("asset_id") != artifact.get("asset_id"):
        errors.append(f"trust-network worker bundle marketplace asset id mismatch: {asset_path}")
    if catalog_asset.get("type") != artifact.get("asset_type"):
        errors.append(f"trust-network worker bundle marketplace asset type mismatch: {asset_path}")


def _load_marketplace_asset(artifact: dict[str, Any], data: bytes) -> dict[str, Any]:
    asset_path = str(artifact.get("asset_path") or "asset.json")
    suffix = Path(asset_path).suffix or ".json"
    with tempfile.TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / f"asset{suffix}"
        target.write_bytes(data)
        asset_type = artifact.get("asset_type")
        if asset_type == "verification_contract_template":
            return load_contract(target)
        if asset_type == "policy_pack":
            return load_policy_pack(target)
    try:
        parsed = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(str(exc)) from exc
    if not isinstance(parsed, dict):
        raise ValueError("asset must contain an object")
    return parsed


def _materialize_embedded_assets(root: Path, verified_artifacts: dict[str, dict[str, Any]]) -> None:
    for name, record in verified_artifacts.items():
        if not name.startswith("marketplace_asset_"):
            continue
        artifact = record["artifact"]
        asset_path = str(artifact.get("asset_path") or "").replace("\\", "/")
        if not asset_path:
            continue
        target = root / asset_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(record["data"])


def _source_summary(
    receipt: dict[str, Any],
    service_attestation: dict[str, Any],
    registry_receipt: dict[str, Any],
    marketplace_catalog: dict[str, Any] | None,
    marketplace_distribution: dict[str, Any] | None,
    marketplace_settlement: dict[str, Any] | None,
) -> dict[str, Any]:
    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    propagation = receipt.get("propagation", {}) if isinstance(receipt.get("propagation"), dict) else {}
    registry = receipt.get("registry", {}) if isinstance(receipt.get("registry"), dict) else {}
    marketplace = receipt.get("marketplace", {}) if isinstance(receipt.get("marketplace"), dict) else {}
    service = service_attestation.get("service", {}) if isinstance(service_attestation.get("service"), dict) else {}
    registration = registry_receipt.get("registration", {}) if isinstance(registry_receipt.get("registration"), dict) else {}
    body = {
        "worker_operation_id": receipt.get("worker_operation_id"),
        "worker_receipt_hash": content_hash(receipt),
        "service_attestation_id": service_attestation.get("attestation_id"),
        "service_attestation_hash": content_hash(service_attestation),
        "service_ref": service.get("service_ref"),
        "registration_id": registry_receipt.get("registration_id"),
        "registration_hash": content_hash(registry_receipt),
        "registration_ref": registration.get("registration_ref") or registry.get("registration_ref"),
        "registration_status": registration.get("status") or registry.get("status"),
        "run_ref": worker.get("run_ref"),
        "operation_kind": worker.get("operation_kind"),
        "destination_ref": propagation.get("destination_ref"),
        "response_status": propagation.get("response_status"),
        "publication_log_root": propagation.get("publication_log_root"),
        "catalog_id": (marketplace_catalog or {}).get("catalog_id") or marketplace.get("catalog_id"),
        "catalog_hash": content_hash(marketplace_catalog) if isinstance(marketplace_catalog, dict) else None,
        "distribution_id": (marketplace_distribution or {}).get("distribution_id") or marketplace.get("distribution_id"),
        "distribution_hash": content_hash(marketplace_distribution) if isinstance(marketplace_distribution, dict) else None,
        "settlement_id": (marketplace_settlement or {}).get("settlement_id") or marketplace.get("settlement_id"),
        "settlement_hash": content_hash(marketplace_settlement) if isinstance(marketplace_settlement, dict) else None,
    }
    return {key: value for key, value in body.items() if value is not None}


def _bundle_summary(receipt: dict[str, Any], sources: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_artifact_count": len(artifacts),
        "source_artifact_sha256_root": content_hash([artifact.get("sha256") for artifact in artifacts]),
        "source_artifact_content_root": content_hash([artifact.get("content_hash") for artifact in artifacts]),
        "source_object_hashes": _source_hashes(sources),
        "proof_pack_count": len(sources.get("proof_packs", [])) if isinstance(sources.get("proof_packs"), list) else 0,
        "marketplace_asset_count": sum(1 for artifact in artifacts if isinstance(artifact, dict) and str(artifact.get("name", "")).startswith("marketplace_asset_")),
        "frontend_bundle_replayed": any(isinstance(artifact, dict) and artifact.get("name") == "frontend_bundle" for artifact in artifacts),
        "marketplace_settlement_replayed": "marketplace_settlement" in sources,
        "worker_control_summary": _status_summary(receipt.get("controls", [])),
    }


def _controls(receipt: dict[str, Any], service_attestation: dict[str, Any], sources: dict[str, Any], artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
    artifact_names = {artifact.get("name") for artifact in artifacts if isinstance(artifact, dict)}
    expected_names = _expected_names(sources)
    signed_frontend = _signed_frontend_artifact(service_attestation)
    marketplace_assets = {name for name in artifact_names if isinstance(name, str) and name.startswith("marketplace_asset_")}
    procurement_ready = {"procurement_receipt", "procurement_integration_receipt", "marketplace_catalog", "marketplace_distribution"} <= set(sources)
    return [
        {"name": "worker-receipt-offline-replay", "status": "passed" if REQUIRED_JSON_SOURCES <= set(sources) else "failed", "detail": "Embedded worker receipt, service attestation, and registry receipt replay through the trust-network worker verifier."},
        {"name": "source-artifact-byte-binding", "status": "passed" if artifact_names == expected_names else "failed", "detail": "Embedded raw source bytes match parsed source objects by SHA-256 and canonical content hash."},
        {"name": "marketplace-asset-replay", "status": "passed" if marketplace_assets else "not-applicable", "detail": "Marketplace catalog asset bytes are embedded, checked against catalog content hashes, and materialized for offline verifier replay."},
        {"name": "frontend-bundle-byte-replay", "status": "passed" if signed_frontend and "frontend_bundle" in artifact_names else "not-applicable", "detail": "Frontend bundle bytes are embedded and replayed when the trust-network service attestation binds a frontend artifact."},
        {"name": "trust-network-procurement-review", "status": "passed" if procurement_ready else "not-applicable", "detail": "Procurement, integration, registry, marketplace, and worker evidence are co-packaged for cross-org vendor trust review."},
        {"name": "raw-secret-scan", "status": "passed", "detail": "Secret-like source fields must be redacted references or hash/root/ref metadata before bundle verification succeeds."},
    ]


def _expected_names(sources: dict[str, Any]) -> set[str]:
    names = {name for name in JSON_SOURCE_TYPES if name in sources}
    packs = sources.get("proof_packs", [])
    if isinstance(packs, list):
        names.update(f"proof_pack_{index}" for index in range(len(packs)))
    if _signed_frontend_artifact(sources.get("service_attestation", {})):
        names.add("frontend_bundle")
    catalog = sources.get("marketplace_catalog")
    assets = catalog.get("assets", []) if isinstance(catalog, dict) else []
    if isinstance(assets, list):
        names.update(f"marketplace_asset_{index}" for index, asset in enumerate(assets) if isinstance(asset, dict) and asset.get("path"))
    return names


def _source_for_name(name: str, sources: dict[str, Any]) -> Any | None:
    if name in sources and name != "proof_packs":
        return sources[name]
    if name.startswith("proof_pack_"):
        try:
            index = int(name.removeprefix("proof_pack_"))
        except ValueError:
            return None
        packs = sources.get("proof_packs", [])
        if isinstance(packs, list) and 0 <= index < len(packs):
            return packs[index]
    return None


def _type_for_name(name: str) -> str:
    if name.startswith("proof_pack_"):
        return "proof-pack"
    return JSON_SOURCE_TYPES.get(name, "")


def _source_hashes(sources: dict[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for name, value in sorted(sources.items()):
        if name == "proof_packs" and isinstance(value, list):
            for index, pack in enumerate(value):
                hashes[f"proof_pack_{index}"] = content_hash(pack)
        else:
            hashes[name] = content_hash(value)
    return hashes


def _signed_frontend_artifact(service_attestation: dict[str, Any]) -> dict[str, Any]:
    artifacts = service_attestation.get("source_artifacts") if isinstance(service_attestation, dict) else None
    if not isinstance(artifacts, list):
        return {}
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("type") == "frontend-bundle":
            return artifact
    return {}


def _service_frontend_hash(service_attestation: dict[str, Any]) -> str | None:
    service = service_attestation.get("service", {}) if isinstance(service_attestation, dict) and isinstance(service_attestation.get("service"), dict) else {}
    value = service.get("frontend_bundle_artifact_hash") or service.get("frontend_bundle_hash")
    return str(value) if value else None


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if isinstance(item, dict):
            status = str(item.get("status", "unknown"))
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def _media_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".js":
        return "application/javascript"
    if suffix == ".css":
        return "text/css"
    if suffix in {".html", ".htm"}:
        return "text/html"
    if suffix == ".json":
        return "application/json"
    return "application/octet-stream"


def _artifact_suffix(artifact: dict[str, Any]) -> str:
    suffix = Path(str(artifact.get("path") or "")).suffix
    if suffix:
        return suffix
    media_type = artifact.get("media_type")
    if media_type == "application/javascript":
        return ".js"
    if media_type == "text/css":
        return ".css"
    if media_type == "text/html":
        return ".html"
    if media_type == "application/json":
        return ".json"
    return ".bin"


def _extract_name(artifact: dict[str, Any]) -> str:
    name = str(artifact.get("name") or "source").replace("\\", "/")
    if name == "frontend_bundle":
        return name + _artifact_suffix(artifact)
    if name.startswith("marketplace_asset_") and artifact.get("asset_path"):
        return str(artifact["asset_path"]).replace("\\", "/")
    return name.replace("/", "_") + ".json"


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"trust-network worker bundle secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if value is None:
        return True
    if key == "timestamp_token":
        return True
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        return True
    if (key.endswith("_root") or key.endswith("_hash")) and isinstance(value, str) and value.startswith("sha256:"):
        return True
    return False
