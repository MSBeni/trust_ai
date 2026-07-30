from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, sha256_hex, utc_now, without_keys
from .chain import EvidenceChain
from .cicd import verify_promotion_status_receipt
from .crypto import sign_value, verify_value
from .verifier import verify_proof_pack

PROMOTION_STATUS_BUNDLE_SCHEMA = "trustai.promotion-status-review-bundle/0.1"
PROMOTION_STATUS_BUNDLE_ENTRY_TYPE = "promotion.status_review_bundle.attested"
PROMOTION_STATUS_BUNDLE_MODES = {"offline-review", "auditor-review", "regulator-review"}

SOURCE_TYPES: tuple[tuple[str, str], ...] = (
    ("receipt", "promotion-status-receipt"),
    ("proof_pack", "proof-pack"),
    ("payload", "provider-status-payload"),
    ("delivery", "provider-delivery"),
    ("delivery_payload_artifact", "provider-delivery-payload-artifact"),
    ("delivery_response_artifact", "provider-delivery-response-artifact"),
)
REQUIRED_SOURCES = {"receipt", "proof_pack", "payload"}


@dataclass
class PromotionStatusBundleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_promotion_status_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("promotion status review bundle must contain an object")
    return value


def write_promotion_status_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def build_promotion_status_bundle(
    receipt: dict[str, Any],
    proof_pack: dict[str, Any],
    payload: dict[str, Any],
    *,
    delivery: dict[str, Any] | None = None,
    artifact_paths: dict[str, str | Path],
    mode: str = "offline-review",
    environment: str | None = None,
    reviewer_ref: str,
    bundle_ref: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in PROMOTION_STATUS_BUNDLE_MODES:
        raise ValueError(f"mode must be one of {sorted(PROMOTION_STATUS_BUNDLE_MODES)}")
    if not isinstance(reviewer_ref, str) or not reviewer_ref.strip():
        raise ValueError("promotion status review bundle reviewer_ref is required")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    verification = verify_proof_pack(proof_pack, key=key)
    replay_paths = _delivery_replay_paths(delivery, artifact_paths)
    replay = verify_promotion_status_receipt(
        receipt,
        proof_pack=proof_pack,
        verification=verification,
        payload=payload,
        delivery=delivery,
        delivery_payload_artifact_path=replay_paths.get("delivery_payload_artifact"),
        delivery_response_artifact_path=replay_paths.get("delivery_response_artifact"),
        key=key,
    )
    if not replay.ok:
        raise ValueError("invalid promotion status source: " + "; ".join(replay.errors))

    sources = _source_objects(receipt=receipt, proof_pack=proof_pack, payload=payload, delivery=delivery)
    source_artifacts = _build_source_artifacts(artifact_paths, sources, delivery)
    body: dict[str, Any] = {
        "schema": PROMOTION_STATUS_BUNDLE_SCHEMA,
        "mode": mode,
        "environment": environment or _source_environment(receipt, delivery),
        "generated_at": timestamp,
        "reviewer_ref": reviewer_ref,
        "bundle_ref": bundle_ref or _default_bundle_ref(receipt),
        "source": _source_summary(receipt, proof_pack, payload, delivery),
        "sources": sources,
        "source_artifacts": source_artifacts,
        "summary": _bundle_summary(receipt, sources, source_artifacts),
        "controls": _controls(receipt, sources, source_artifacts),
        "limitations": [
            "This bundle is self-contained for offline review of one promotion status receipt and its replay sources.",
            "It embeds parsed source objects and raw source bytes so reviewers can detect receipt, proof-pack, provider-payload, delivery, and retained-artifact swaps without original local file paths.",
            "When a delivery receipt records retained payload or response artifacts, embedded artifact bytes replay the recorded path, byte SHA-256, size, and content hash before the promotion status is trusted.",
            "It proves provider-native status payload shape and delivery replay against supplied artifacts; it does not claim the external provider displayed or retained the status without provider-owned webhook/audit exports.",
        ],
    }
    bundle_id = content_hash(body)
    return {
        **body,
        "bundle_id": bundle_id,
        "signatures": [sign_value({"bundle_id": bundle_id, "promotion_status_review_bundle": body}, key)],
    }


def verify_promotion_status_bundle(bundle: dict[str, Any], *, key: str | None = None) -> PromotionStatusBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if bundle.get("schema") != PROMOTION_STATUS_BUNDLE_SCHEMA:
        errors.append(f"unsupported promotion status review bundle schema: {bundle.get('schema')}")
    body = without_keys(bundle, "bundle_id", "signatures")
    if bundle.get("bundle_id") != content_hash(body):
        errors.append("bundle_id does not match canonical promotion status review bundle body")
    signatures = bundle.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append("promotion status review bundle must include at least one signature")
    else:
        signed_value = {"bundle_id": bundle.get("bundle_id"), "promotion_status_review_bundle": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("promotion status review bundle signature verification failed")

    if bundle.get("mode") not in PROMOTION_STATUS_BUNDLE_MODES:
        errors.append("promotion status review bundle mode is unsupported")
    try:
        parse_rfc3339(str(bundle.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"promotion status review bundle generated_at invalid: {exc}")
    if not isinstance(bundle.get("reviewer_ref"), str) or not bundle.get("reviewer_ref", "").strip():
        errors.append("promotion status review bundle reviewer_ref is required")

    sources = bundle.get("sources")
    if not isinstance(sources, dict):
        errors.append("promotion status review bundle sources must be an object")
        sources = {}
    source_values = _required_source_objects(sources, errors)
    artifacts = bundle.get("source_artifacts")
    if source_values:
        _verify_source_artifacts(artifacts, source_values, errors)
        artifact_bytes = _artifact_bytes_by_name(artifacts, errors)
        replay_warnings = _verify_embedded_replay(source_values, artifact_bytes, errors, key=key)
        warnings.extend(replay_warnings)

        expected_source = _source_summary(
            source_values["receipt"],
            source_values["proof_pack"],
            source_values["payload"],
            source_values.get("delivery"),
        )
        if bundle.get("source") != expected_source:
            errors.append("promotion status review bundle source summary does not match embedded sources")
        source_artifacts = artifacts if isinstance(artifacts, list) else []
        expected_summary = _bundle_summary(source_values["receipt"], source_values, source_artifacts)
        if bundle.get("summary") != expected_summary:
            errors.append("promotion status review bundle summary does not match embedded sources")
        if bundle.get("controls") != _controls(source_values["receipt"], source_values, source_artifacts):
            errors.append("promotion status review bundle controls do not match embedded sources")

    return PromotionStatusBundleVerification(ok=not errors, errors=errors, warnings=warnings)


def render_promotion_status_bundle_markdown(bundle: dict[str, Any]) -> str:
    source = bundle.get("source", {}) if isinstance(bundle.get("source"), dict) else {}
    summary = bundle.get("summary", {}) if isinstance(bundle.get("summary"), dict) else {}
    controls = bundle.get("controls", []) if isinstance(bundle.get("controls"), list) else []
    artifacts = bundle.get("source_artifacts", []) if isinstance(bundle.get("source_artifacts"), list) else []
    control_rows = "\n".join(
        "| {name} | {status} | {detail} |".format(
            name=_markdown_cell(control.get("name", "")),
            status=_markdown_cell(control.get("status", "")),
            detail=_markdown_cell(control.get("detail", "")),
        )
        for control in controls
        if isinstance(control, dict)
    )
    artifact_rows = "\n".join(
        "| {name} | {artifact_type} | {size} | `{sha}` | `{content_hash}` |".format(
            name=_markdown_cell(artifact.get("name", "")),
            artifact_type=_markdown_cell(artifact.get("artifact_type", "")),
            size=artifact.get("size_bytes", 0),
            sha=artifact.get("sha256", ""),
            content_hash=artifact.get("content_hash", ""),
        )
        for artifact in artifacts
        if isinstance(artifact, dict)
    )
    limitations = "\n".join(f"- {limitation}" for limitation in bundle.get("limitations", []))
    source_hashes = summary.get("source_object_hashes", {}) if isinstance(summary.get("source_object_hashes"), dict) else {}
    source_hash_lines = "\n".join(f"- {name}: `{value}`" for name, value in sorted(source_hashes.items()))
    return f"""# TrustAI Promotion Status Review Bundle

Bundle ID: `{bundle.get('bundle_id', '')}`

Bundle ref: `{bundle.get('bundle_ref', '')}`

Mode: `{bundle.get('mode', '')}`

Environment: `{bundle.get('environment', '')}`

Generated at: `{bundle.get('generated_at', '')}`

Reviewer: `{bundle.get('reviewer_ref', '')}`

## Source

- Receipt ID: `{source.get('receipt_id', '')}`
- Provider: `{source.get('provider', '')}`
- Pack ID: `{source.get('pack_id', '')}`
- Contract ID: `{source.get('contract_id', '')}`
- Gate outcome: `{source.get('gate_outcome', '')}`
- Provider target: `{source.get('provider_target_ref', '')}`
- Delivery ID: `{source.get('delivery_id', '')}`
- Passed: `{source.get('passed', '')}`

## Embedded Source Summary

- Embedded source artifacts: {summary.get('source_artifact_count', 0)}
- Provider payload replayed: {summary.get('provider_payload_replayed', False)}
- Provider delivery replayed: {summary.get('provider_delivery_replayed', False)}
- Retained payload artifact replayed: {summary.get('retained_payload_artifact_replayed', False)}
- Retained response artifact replayed: {summary.get('retained_response_artifact_replayed', False)}
- Source artifact sha256 root: `{summary.get('source_artifact_sha256_root', '')}`
- Source artifact content root: `{summary.get('source_artifact_content_root', '')}`

{source_hash_lines or '- No source hashes recorded.'}

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


def write_promotion_status_bundle_markdown(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_promotion_status_bundle_markdown(bundle), encoding="utf-8")


def extract_promotion_status_bundle_sources(
    bundle: dict[str, Any],
    out_dir: str | Path,
    *,
    key: str | None = None,
    overwrite: bool = False,
) -> list[dict[str, Any]]:
    result = verify_promotion_status_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid promotion status review bundle: " + "; ".join(result.errors))
    source_artifacts = bundle.get("source_artifacts", [])
    if not isinstance(source_artifacts, list):
        raise ValueError("promotion status review bundle source_artifacts must be a list")
    output_root = Path(out_dir)
    extracted: list[dict[str, Any]] = []
    for artifact in source_artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("promotion status review bundle source artifact must be an object")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("promotion status review bundle source artifact name is required")
        data = _decode_artifact_bytes(artifact, [])
        target = output_root / _artifact_extract_filename(name, str(artifact.get("media_type") or "application/json"))
        if target.exists():
            if target.is_dir():
                raise ValueError(f"promotion status review bundle output path is a directory: {target}")
            if not overwrite:
                raise ValueError(f"promotion status review bundle output already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        extracted.append(
            {
                "name": name,
                "artifact_type": artifact.get("artifact_type"),
                "path": artifact.get("path"),
                "sha256": "sha256:" + sha256_hex(data),
                "bytes": len(data),
                "artifact_id": artifact.get("artifact_id"),
                "extracted_to": str(target),
            }
        )
    return extracted


def append_promotion_status_bundle(
    chain: EvidenceChain,
    bundle: dict[str, Any],
    *,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_promotion_status_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid promotion status review bundle: " + "; ".join(result.errors))
    payload = {
        "bundle_id": bundle["bundle_id"],
        "bundle_hash": content_hash(bundle),
        "mode": bundle.get("mode"),
        "environment": bundle.get("environment"),
        "generated_at": bundle.get("generated_at"),
        "reviewer_ref": bundle.get("reviewer_ref"),
        "bundle_ref": bundle.get("bundle_ref"),
        "source": bundle.get("source"),
        "summary": bundle.get("summary"),
        "control_summary": _status_summary(bundle.get("controls", [])),
    }
    return chain.append(PROMOTION_STATUS_BUNDLE_ENTRY_TYPE, payload, key=key, timestamp=bundle.get("generated_at"))


def _source_objects(**objects: Any) -> dict[str, Any]:
    return {name: _clone(value) for name, value in objects.items() if value is not None}


def _required_source_objects(sources: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    supported = {name for name, _ in SOURCE_TYPES}
    for name in sources:
        if name not in supported:
            errors.append(f"promotion status review bundle sources.{name} is unsupported")
    for name in REQUIRED_SOURCES:
        value = sources.get(name)
        if not isinstance(value, dict):
            errors.append(f"promotion status review bundle sources.{name} is required")
        else:
            values[name] = value
    delivery = sources.get("delivery")
    if delivery is not None:
        if not isinstance(delivery, dict):
            errors.append("promotion status review bundle sources.delivery must be an object")
        else:
            values["delivery"] = delivery
    return values if REQUIRED_SOURCES <= set(values) else {}


def _build_source_artifacts(artifact_paths: dict[str, str | Path], sources: dict[str, Any], delivery: dict[str, Any] | None) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    artifact_types = dict(SOURCE_TYPES)
    for name in ("receipt", "proof_pack", "payload", "delivery"):
        if name not in sources:
            continue
        path = artifact_paths.get(name)
        if path is None:
            raise ValueError(f"promotion status review bundle artifact path is required: {name}")
        data = Path(path).read_bytes()
        parsed = _parse_json_artifact(data, name)
        if content_hash(parsed) != content_hash(sources[name]):
            raise ValueError(f"promotion status review bundle artifact content hash mismatch: {name}")
        artifacts.append(_artifact_record(name, artifact_types[name], path, data, content_hash(parsed), "application/json"))
    if delivery is not None:
        payload_replay = _delivery_replay_paths(delivery, artifact_paths).get("delivery_payload_artifact")
        if payload_replay is not None and "delivery_payload_artifact" in artifact_paths:
            data = Path(payload_replay).read_bytes()
            parsed = _parse_json_artifact(data, "delivery_payload_artifact")
            artifacts.append(
                _artifact_record(
                    "delivery_payload_artifact",
                    artifact_types["delivery_payload_artifact"],
                    payload_replay,
                    data,
                    content_hash(parsed),
                    "application/json",
                )
            )
        response_replay = _delivery_replay_paths(delivery, artifact_paths).get("delivery_response_artifact")
        if response_replay is not None:
            data = Path(response_replay).read_bytes()
            content = _raw_artifact_content_hash(data)
            artifacts.append(
                _artifact_record(
                    "delivery_response_artifact",
                    artifact_types["delivery_response_artifact"],
                    response_replay,
                    data,
                    content,
                    "application/json" if _loads_json(data) is not None else "text/plain",
                )
            )
    return artifacts


def _verify_source_artifacts(value: Any, source_objects: dict[str, Any], errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append("promotion status review bundle source_artifacts must be a list")
        return
    artifact_types = dict(SOURCE_TYPES)
    actual_names: set[str] = set()
    expected_names = set(source_objects)
    delivery = source_objects.get("delivery")
    if isinstance(delivery, dict) and isinstance(delivery.get("response_artifact"), dict):
        expected_names.add("delivery_response_artifact")

    for artifact in value:
        if not isinstance(artifact, dict):
            errors.append("promotion status review bundle source artifact must be an object")
            continue
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            errors.append("promotion status review bundle source artifact name is required")
            continue
        actual_names.add(name)
        if name not in artifact_types:
            errors.append(f"promotion status review bundle source artifact unsupported: {name}")
            continue
        if artifact.get("artifact_type") != artifact_types[name]:
            errors.append(f"promotion status review bundle source artifact type mismatch: {name}")
        body = without_keys(artifact, "artifact_id")
        if artifact.get("artifact_id") != content_hash(body):
            errors.append(f"promotion status review bundle source artifact id mismatch: {name}")
        data = _decode_artifact_bytes(artifact, errors)
        if not data:
            continue
        actual_sha = "sha256:" + sha256_hex(data)
        if artifact.get("sha256") != actual_sha:
            errors.append(f"promotion status review bundle source artifact sha256 mismatch: {name}")
        if artifact.get("size_bytes") != len(data):
            errors.append(f"promotion status review bundle source artifact size mismatch: {name}")
        if name in source_objects:
            try:
                parsed = _parse_json_artifact(data, name)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            parsed_hash = content_hash(parsed)
            if artifact.get("content_hash") != parsed_hash:
                errors.append(f"promotion status review bundle source artifact content hash mismatch: {name}")
            if parsed_hash != content_hash(source_objects[name]):
                errors.append(f"promotion status review bundle source artifact does not match embedded source: {name}")
        elif name == "delivery_response_artifact":
            if artifact.get("content_hash") != _raw_artifact_content_hash(data):
                errors.append("promotion status review bundle delivery response artifact content hash mismatch")
        elif name == "delivery_payload_artifact":
            try:
                parsed = _parse_json_artifact(data, name)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            if artifact.get("content_hash") != content_hash(parsed):
                errors.append("promotion status review bundle delivery payload artifact content hash mismatch")
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    if missing:
        errors.append("promotion status review bundle source artifacts missing: " + ", ".join(missing))
    if isinstance(delivery, dict) and isinstance(delivery.get("payload_artifact"), dict) and not ({"payload", "delivery_payload_artifact"} & actual_names):
        errors.append("promotion status review bundle source artifacts missing: delivery payload artifact bytes")
    if extra:
        errors.append("promotion status review bundle source artifacts unsupported for embedded sources: " + ", ".join(extra))


def _verify_embedded_replay(source_values: dict[str, Any], artifact_bytes: dict[str, bytes], errors: list[str], *, key: str | None) -> list[str]:
    verification = verify_proof_pack(source_values["proof_pack"], key=key)
    delivery = source_values.get("delivery")
    payload_bytes = None
    response_bytes = None
    if isinstance(delivery, dict) and isinstance(delivery.get("payload_artifact"), dict):
        payload_bytes = artifact_bytes.get("delivery_payload_artifact") or artifact_bytes.get("payload")
        if payload_bytes is None:
            errors.append("promotion status review bundle retained delivery payload artifact bytes are required")
    if isinstance(delivery, dict) and isinstance(delivery.get("response_artifact"), dict):
        response_bytes = artifact_bytes.get("delivery_response_artifact")
        if response_bytes is None:
            errors.append("promotion status review bundle retained delivery response artifact bytes are required")
    replay = verify_promotion_status_receipt(
        source_values["receipt"],
        proof_pack=source_values["proof_pack"],
        verification=verification,
        payload=source_values["payload"],
        delivery=delivery,
        delivery_payload_artifact_bytes=payload_bytes,
        delivery_response_artifact_bytes=response_bytes,
        key=key,
    )
    if not replay.ok:
        errors.extend("promotion status review bundle source replay: " + error for error in replay.errors)
    return replay.warnings


def _delivery_replay_paths(delivery: dict[str, Any] | None, artifact_paths: dict[str, str | Path]) -> dict[str, str | Path]:
    if delivery is None:
        return {}
    paths: dict[str, str | Path] = {}
    if isinstance(delivery.get("payload_artifact"), dict):
        paths["delivery_payload_artifact"] = artifact_paths.get("delivery_payload_artifact") or artifact_paths.get("payload")
        if paths["delivery_payload_artifact"] is None:
            raise ValueError("promotion status review bundle delivery payload artifact path is required")
    if isinstance(delivery.get("response_artifact"), dict):
        paths["delivery_response_artifact"] = artifact_paths.get("delivery_response_artifact")
        if paths["delivery_response_artifact"] is None:
            raise ValueError("promotion status review bundle delivery response artifact path is required")
    return paths


def _source_summary(receipt: dict[str, Any], proof_pack: dict[str, Any], payload: dict[str, Any], delivery: dict[str, Any] | None) -> dict[str, Any]:
    gate_decision = receipt.get("gate_decision", {}) if isinstance(receipt.get("gate_decision"), dict) else {}
    provider_payload = receipt.get("provider_payload", {}) if isinstance(receipt.get("provider_payload"), dict) else {}
    body = {
        "receipt_id": receipt.get("receipt_id"),
        "receipt_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "pack_id": proof_pack.get("pack_id"),
        "pack_hash": content_hash(proof_pack),
        "payload_hash": payload.get("payload_hash"),
        "payload_object_hash": content_hash(payload),
        "contract_id": gate_decision.get("contract_id"),
        "contract_hash": gate_decision.get("contract_hash"),
        "gate_outcome": gate_decision.get("outcome"),
        "provider_target_ref": provider_payload.get("target_ref"),
        "provider_proof_pack_ref": provider_payload.get("proof_pack_ref"),
        "delivery_id": delivery.get("delivery_id") if isinstance(delivery, dict) else None,
        "delivery_hash": content_hash(delivery) if isinstance(delivery, dict) else None,
        "passed": receipt.get("passed"),
        "violation_count": len(receipt.get("violations", [])),
    }
    return {key: value for key, value in body.items() if value is not None}


def _bundle_summary(receipt: dict[str, Any], sources: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    artifact_names = {artifact.get("name") for artifact in artifacts if isinstance(artifact, dict)}
    delivery = sources.get("delivery") if isinstance(sources.get("delivery"), dict) else {}
    payload_artifact = delivery.get("payload_artifact") if isinstance(delivery, dict) else None
    response_artifact = delivery.get("response_artifact") if isinstance(delivery, dict) else None
    source = receipt.get("source", {}) if isinstance(receipt.get("source"), dict) else {}
    return {
        "source_artifact_count": len(artifacts),
        "source_artifact_sha256_root": content_hash([artifact.get("sha256") for artifact in artifacts]),
        "source_artifact_content_root": content_hash([artifact.get("content_hash") for artifact in artifacts]),
        "source_object_hashes": {name: content_hash(value) for name, value in sorted(sources.items())},
        "provider_payload_replayed": "payload" in sources and "payload" in artifact_names,
        "provider_delivery_replayed": "delivery" in sources and "delivery" in artifact_names,
        "retained_payload_artifact_replayed": not isinstance(payload_artifact, dict) or "delivery_payload_artifact" in artifact_names or "payload" in artifact_names,
        "retained_response_artifact_replayed": not isinstance(response_artifact, dict) or "delivery_response_artifact" in artifact_names,
        "promotion_status_passed": bool(receipt.get("passed")),
        "provider_target_bound": bool(source.get("provider_target_ref_bound")),
        "provider_proof_pack_ref_bound": bool(source.get("provider_proof_pack_ref_bound")),
        "receipt_control_summary": _status_summary(receipt.get("controls", [])),
    }


def _controls(receipt: dict[str, Any], sources: dict[str, Any], artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
    summary = _bundle_summary(receipt, sources, artifacts)
    return [
        {
            "name": "promotion-status-offline-replay",
            "status": "passed" if REQUIRED_SOURCES <= set(sources) and receipt.get("passed") is True else "failed",
            "detail": "Embedded receipt, proof pack, provider payload, and optional delivery receipt replay through the promotion status verifier.",
        },
        {
            "name": "source-artifact-byte-binding",
            "status": "passed" if summary["source_artifact_count"] >= len(sources) else "failed",
            "detail": "Embedded raw source bytes match parsed source objects by SHA-256 and canonical content hash.",
        },
        {
            "name": "provider-target-bound",
            "status": "passed" if summary["provider_target_bound"] else "failed",
            "detail": "Provider status/check payload is bound to a concrete repository or project commit ref.",
        },
        {
            "name": "provider-proof-pack-ref-bound",
            "status": "passed" if summary["provider_proof_pack_ref_bound"] else "failed",
            "detail": "Provider-native status/check payload carries a proof-pack URL or correlation reference.",
        },
        {
            "name": "provider-delivery-replay",
            "status": "passed" if "delivery" in sources else "not-applicable",
            "detail": "Provider delivery receipt is embedded and replay-bound when supplied.",
        },
        {
            "name": "retained-delivery-artifact-replay",
            "status": "passed" if summary["retained_payload_artifact_replayed"] and summary["retained_response_artifact_replayed"] else "failed",
            "detail": "Retained provider delivery payload and response artifacts are embedded when the delivery receipt binds them.",
        },
    ]


def _source_environment(receipt: dict[str, Any], delivery: dict[str, Any] | None) -> str | None:
    if isinstance(delivery, dict):
        return delivery.get("environment") or delivery.get("mode")
    return receipt.get("provider")


def _default_bundle_ref(receipt: dict[str, Any]) -> str:
    provider = receipt.get("provider") or "provider"
    return f"promotion-status-review:{provider}:{str(receipt.get('receipt_id') or '')[:16]}"


def _artifact_record(name: str, artifact_type: str, path: str | Path, data: bytes, content_hash_value: str, media_type: str) -> dict[str, Any]:
    body = {
        "name": name,
        "artifact_type": artifact_type,
        "path": str(path).replace("\\", "/"),
        "media_type": media_type,
        "size_bytes": len(data),
        "sha256": "sha256:" + sha256_hex(data),
        "content_hash": content_hash_value,
        "content_b64": base64.b64encode(data).decode("ascii"),
    }
    return {**body, "artifact_id": content_hash(body)}


def _artifact_bytes_by_name(value: Any, errors: list[str]) -> dict[str, bytes]:
    if not isinstance(value, list):
        return {}
    artifacts: dict[str, bytes] = {}
    for artifact in value:
        if not isinstance(artifact, dict):
            continue
        name = artifact.get("name")
        if not isinstance(name, str):
            continue
        artifacts[name] = _decode_artifact_bytes(artifact, errors)
    return artifacts


def _decode_artifact_bytes(artifact: dict[str, Any], errors: list[str]) -> bytes:
    try:
        return base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        errors.append(f"promotion status review bundle source artifact content_b64 invalid: {artifact.get('name')}: {exc}")
        return b""


def _parse_json_artifact(data: bytes, name: str) -> Any:
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"promotion status review bundle artifact JSON invalid: {name}: {exc}") from exc


def _loads_json(data: bytes) -> Any | None:
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _raw_artifact_content_hash(data: bytes) -> str:
    parsed = _loads_json(data)
    if parsed is not None:
        return content_hash(parsed)
    return content_hash(data.decode("utf-8-sig", errors="replace"))


def _artifact_extract_filename(name: str, media_type: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in name).strip("-")
    if media_type == "text/plain":
        return f"{safe or 'source'}.txt"
    return f"{safe or 'source'}.json"


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    if isinstance(controls, list):
        for control in controls:
            if not isinstance(control, dict):
                continue
            status = str(control.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))
