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
from .crypto import sign_value, verify_value
from .insurer_partner_worker import verify_insurer_partner_worker_receipt

INSURER_PARTNER_WORKER_BUNDLE_SCHEMA = "trustai.insurer-partner-worker-bundle/0.1"
INSURER_PARTNER_WORKER_BUNDLE_ENTRY_TYPE = "insurer.partner_worker_bundle_exported"
INSURER_PARTNER_WORKER_BUNDLE_MODES = {"offline-review", "underwriter-review", "auditor-review"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

JSON_SOURCE_TYPES = {
    "worker_receipt": "insurer-partner-worker-receipt",
    "service_attestation": "insurer-partner-service-attestation",
    "telemetry": "insurer-risk-telemetry",
    "underwriting_quote": "underwriting-quote",
    "actuarial_product": "actuarial-product",
}
REQUIRED_JSON_SOURCES = {"worker_receipt", "service_attestation", "telemetry", "underwriting_quote"}
SUPPORTED_SOURCE_KEYS = REQUIRED_JSON_SOURCES | {"actuarial_product", "actuarial_corpora"}


@dataclass
class InsurerPartnerWorkerBundleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_insurer_partner_worker_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("insurer partner worker bundle must contain an object")
    return value


def write_insurer_partner_worker_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def build_insurer_partner_worker_bundle(
    receipt: dict[str, Any],
    service_attestation: dict[str, Any],
    telemetry: dict[str, Any],
    underwriting_quote: dict[str, Any],
    *,
    actuarial_product: dict[str, Any] | None = None,
    actuarial_corpora: list[dict[str, Any]] | None = None,
    frontend_bundle_path: str | Path | None = None,
    artifact_paths: dict[str, Any],
    mode: str = "offline-review",
    environment: str | None = None,
    reviewer_ref: str,
    bundle_ref: str | None = None,
    generated_at: str | None = None,
    now: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in INSURER_PARTNER_WORKER_BUNDLE_MODES:
        raise ValueError(f"mode must be one of {sorted(INSURER_PARTNER_WORKER_BUNDLE_MODES)}")
    if not isinstance(reviewer_ref, str) or not reviewer_ref.strip():
        raise ValueError("insurer partner worker bundle reviewer_ref is required")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    verification_time = now or timestamp
    corpora = actuarial_corpora or []
    replay = verify_insurer_partner_worker_receipt(
        receipt,
        service_attestation=service_attestation,
        telemetry=telemetry,
        underwriting_quote=underwriting_quote,
        actuarial_product=actuarial_product,
        actuarial_corpora=corpora,
        frontend_bundle_path=frontend_bundle_path,
        now=verification_time,
        key=key,
    )
    if not replay.ok:
        raise ValueError("invalid insurer partner worker source: " + "; ".join(replay.errors))
    sources = _source_objects(
        worker_receipt=receipt,
        service_attestation=service_attestation,
        telemetry=telemetry,
        underwriting_quote=underwriting_quote,
        actuarial_product=actuarial_product,
        actuarial_corpora=corpora,
    )
    secret_errors: list[str] = []
    _check_no_secret_values(sources, secret_errors)
    if secret_errors:
        raise ValueError("insurer partner worker bundle source contains secret-like values: " + "; ".join(secret_errors))
    source_artifacts = _build_artifacts(artifact_paths, sources, service_attestation, frontend_bundle_path)
    body = {
        "schema": INSURER_PARTNER_WORKER_BUNDLE_SCHEMA,
        "mode": mode,
        "environment": environment or receipt.get("environment"),
        "generated_at": timestamp,
        "reviewer_ref": reviewer_ref,
        "bundle_ref": bundle_ref or f"insurer-partner-worker-bundle:{receipt.get('worker_operation_id', 'unknown')}",
        "verification_options": {"now": verification_time},
        "source": _source_summary(receipt, service_attestation, telemetry, underwriting_quote),
        "sources": sources,
        "source_artifacts": source_artifacts,
        "summary": _bundle_summary(receipt, sources, source_artifacts),
        "controls": _controls(receipt, service_attestation, sources, source_artifacts),
        "limitations": [
            "This bundle is self-contained for offline review of one insurer partner worker receipt and its replay sources.",
            "It embeds parsed JSON sources and raw source bytes, including frontend bundle bytes when the service attestation binds a frontend artifact.",
            "It proves replay against supplied underwriting, actuarial, service, and worker evidence; it does not claim live partner API operation or production scheduler authority beyond the embedded receipts.",
        ],
    }
    bundle_id = content_hash(body)
    return {**body, "bundle_id": bundle_id, "signatures": [sign_value({"bundle_id": bundle_id, "insurer_partner_worker_bundle": body}, key)]}


def verify_insurer_partner_worker_bundle(bundle: dict[str, Any], *, key: str | None = None) -> InsurerPartnerWorkerBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if bundle.get("schema") != INSURER_PARTNER_WORKER_BUNDLE_SCHEMA:
        errors.append(f"unsupported insurer partner worker bundle schema: {bundle.get('schema')}")
    body = without_keys(bundle, "bundle_id", "signatures")
    if bundle.get("bundle_id") != content_hash(body):
        errors.append("bundle_id does not match canonical insurer partner worker bundle body")
    signatures = bundle.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("insurer partner worker bundle must include at least one signature")
    else:
        signed = {"bundle_id": bundle.get("bundle_id"), "insurer_partner_worker_bundle": body}
        if not any(isinstance(signature, dict) and verify_value(signed, signature, key) for signature in signatures):
            errors.append("insurer partner worker bundle signature verification failed")
    if bundle.get("mode") not in INSURER_PARTNER_WORKER_BUNDLE_MODES:
        errors.append("insurer partner worker bundle mode is unsupported")
    try:
        parse_rfc3339(str(bundle.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"insurer partner worker bundle generated_at invalid: {exc}")
    if not isinstance(bundle.get("reviewer_ref"), str) or not bundle.get("reviewer_ref", "").strip():
        errors.append("insurer partner worker bundle reviewer_ref is required")
    sources = bundle.get("sources")
    if not isinstance(sources, dict):
        errors.append("insurer partner worker bundle sources must be an object")
        sources = {}
    source_values = _read_sources(sources, errors)
    verified_artifacts = _verify_artifacts(bundle.get("source_artifacts"), source_values, errors)
    if source_values:
        options = bundle.get("verification_options", {}) if isinstance(bundle.get("verification_options"), dict) else {}
        verification_time = options.get("now") or bundle.get("generated_at")
        try:
            parse_rfc3339(str(verification_time or ""))
        except ValueError as exc:
            errors.append(f"insurer partner worker bundle verification_options.now invalid: {exc}")
        with tempfile.TemporaryDirectory() as tmp_dir:
            frontend_path = None
            frontend = verified_artifacts.get("frontend_bundle")
            if frontend:
                suffix = _artifact_suffix(frontend["artifact"])
                frontend_path = Path(tmp_dir) / f"frontend_bundle{suffix}"
                frontend_path.write_bytes(frontend["data"])
            replay = verify_insurer_partner_worker_receipt(
                source_values["worker_receipt"],
                service_attestation=source_values["service_attestation"],
                telemetry=source_values["telemetry"],
                underwriting_quote=source_values["underwriting_quote"],
                actuarial_product=source_values.get("actuarial_product"),
                actuarial_corpora=source_values.get("actuarial_corpora", []),
                frontend_bundle_path=frontend_path,
                now=str(verification_time) if verification_time else None,
                key=key,
            )
        errors.extend("insurer partner worker bundle source replay: " + error for error in replay.errors)
        warnings.extend(replay.warnings)
        if bundle.get("source") != _source_summary(source_values["worker_receipt"], source_values["service_attestation"], source_values["telemetry"], source_values["underwriting_quote"]):
            errors.append("insurer partner worker bundle source summary does not match embedded sources")
        artifacts = bundle.get("source_artifacts") if isinstance(bundle.get("source_artifacts"), list) else []
        if bundle.get("summary") != _bundle_summary(source_values["worker_receipt"], source_values, artifacts):
            errors.append("insurer partner worker bundle summary does not match embedded sources")
        if bundle.get("controls") != _controls(source_values["worker_receipt"], source_values["service_attestation"], source_values, artifacts):
            errors.append("insurer partner worker bundle controls do not match embedded sources")
    _check_no_secret_values(bundle, errors)
    return InsurerPartnerWorkerBundleVerification(ok=not errors, errors=errors, warnings=warnings)


def write_insurer_partner_worker_bundle_markdown(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_insurer_partner_worker_bundle_markdown(bundle), encoding="utf-8")


def render_insurer_partner_worker_bundle_markdown(bundle: dict[str, Any]) -> str:
    source = bundle.get("source", {}) if isinstance(bundle.get("source"), dict) else {}
    summary = bundle.get("summary", {}) if isinstance(bundle.get("summary"), dict) else {}
    controls = bundle.get("controls", []) if isinstance(bundle.get("controls"), list) else []
    artifacts = bundle.get("source_artifacts", []) if isinstance(bundle.get("source_artifacts"), list) else []
    control_rows = "\n".join(
        "| {name} | {status} | {detail} |".format(name=_cell(item.get("name", "")), status=_cell(item.get("status", "")), detail=_cell(item.get("detail", "")))
        for item in controls
        if isinstance(item, dict)
    )
    artifact_rows = "\n".join(
        "| {name} | {kind} | {size} | `{sha}` | `{content}` |".format(
            name=_cell(item.get("name", "")),
            kind=_cell(item.get("artifact_type", "")),
            size=item.get("size_bytes", 0),
            sha=item.get("sha256", ""),
            content=item.get("content_hash", ""),
        )
        for item in artifacts
        if isinstance(item, dict)
    )
    hashes = summary.get("source_object_hashes", {}) if isinstance(summary.get("source_object_hashes"), dict) else {}
    hash_lines = "\n".join(f"- {name}: `{value}`" for name, value in sorted(hashes.items()))
    limitations = "\n".join(f"- {item}" for item in bundle.get("limitations", []))
    return f"""# TrustAI Insurer Partner Worker Bundle

Bundle ID: `{bundle.get('bundle_id', '')}`

Bundle ref: `{bundle.get('bundle_ref', '')}`

Mode: `{bundle.get('mode', '')}`

Environment: `{bundle.get('environment', '')}`

Generated at: `{bundle.get('generated_at', '')}`

Reviewer: `{bundle.get('reviewer_ref', '')}`

## Source

- Worker operation ID: `{source.get('worker_operation_id', '')}`
- Service attestation ID: `{source.get('service_attestation_id', '')}`
- Run ref: `{source.get('run_ref', '')}`
- Operation kind: `{source.get('operation_kind', '')}`
- Underwriter: `{source.get('underwriter', '')}`
- Quote ID: `{source.get('quote_id', '')}`
- Risk tier: `{source.get('risk_tier', '')}`
- Destination: `{source.get('destination_ref', '')}`
- Response status: `{source.get('response_status', '')}`
- Policy binding: `{source.get('policy_binding_ref', '')}`

## Embedded Source Summary

- Embedded source artifacts: {summary.get('source_artifact_count', 0)}
- Frontend bundle replayed: {summary.get('frontend_bundle_replayed', False)}
- Actuarial corpora replayed: {summary.get('actuarial_corpus_count', 0)}
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


def extract_insurer_partner_worker_bundle_sources(bundle: dict[str, Any], out_dir: str | Path, *, key: str | None = None, overwrite: bool = False) -> list[dict[str, Any]]:
    result = verify_insurer_partner_worker_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid insurer partner worker bundle: " + "; ".join(result.errors))
    artifacts = bundle.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        raise ValueError("insurer partner worker bundle source_artifacts must be a list")
    root = Path(out_dir)
    extracted: list[dict[str, Any]] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("insurer partner worker bundle source artifact must be an object")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("insurer partner worker bundle source artifact name is required")
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise ValueError(f"insurer partner worker bundle source artifact content_b64 invalid: {name}") from exc
        if artifact.get("sha256") != _sha256_ref(data):
            raise ValueError(f"insurer partner worker bundle source artifact sha256 mismatch: {name}")
        target = root / _extract_name(artifact)
        if target.exists() and not overwrite:
            raise ValueError(f"insurer partner worker bundle output already exists: {target}")
        if target.exists() and target.is_dir():
            raise ValueError(f"insurer partner worker bundle output path is a directory: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        extracted.append({"name": name, "artifact_type": artifact.get("artifact_type"), "sha256": artifact.get("sha256"), "bytes": len(data), "artifact_id": artifact.get("artifact_id"), "extracted_to": str(target)})
    return extracted


def append_insurer_partner_worker_bundle(chain: EvidenceChain, bundle: dict[str, Any], *, key: str | None = None) -> dict[str, Any]:
    result = verify_insurer_partner_worker_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid insurer partner worker bundle: " + "; ".join(result.errors))
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
    return chain.append(INSURER_PARTNER_WORKER_BUNDLE_ENTRY_TYPE, payload, key=key, timestamp=bundle.get("generated_at"))


def _source_objects(**objects: Any) -> dict[str, Any]:
    sources: dict[str, Any] = {}
    for name, value in objects.items():
        if value is None:
            continue
        if name == "actuarial_corpora":
            if value:
                sources[name] = [_clone(item) for item in value]
        else:
            sources[name] = _clone(value)
    return sources


def _read_sources(sources: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for name in sources:
        if name not in SUPPORTED_SOURCE_KEYS:
            errors.append(f"insurer partner worker bundle sources.{name} is unsupported")
    for name in REQUIRED_JSON_SOURCES:
        value = sources.get(name)
        if not isinstance(value, dict):
            errors.append(f"insurer partner worker bundle sources.{name} is required")
        else:
            values[name] = value
    if isinstance(sources.get("actuarial_product"), dict):
        values["actuarial_product"] = sources["actuarial_product"]
    elif "actuarial_product" in sources:
        errors.append("insurer partner worker bundle sources.actuarial_product must be an object")
    corpora = sources.get("actuarial_corpora", [])
    if isinstance(corpora, list) and all(isinstance(item, dict) for item in corpora):
        values["actuarial_corpora"] = corpora
    elif "actuarial_corpora" in sources:
        errors.append("insurer partner worker bundle sources.actuarial_corpora must be a list of objects")
    else:
        values["actuarial_corpora"] = []
    return values if REQUIRED_JSON_SOURCES <= set(values) else {}


def _build_artifacts(paths: dict[str, Any], sources: dict[str, Any], service_attestation: dict[str, Any], frontend_bundle_path: str | Path | None) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for name, artifact_type in JSON_SOURCE_TYPES.items():
        if name in sources:
            path = paths.get(name)
            if path is None:
                raise ValueError(f"insurer partner worker bundle artifact path is required: {name}")
            artifacts.append(_json_artifact(name, artifact_type, path, sources[name]))
    corpora = sources.get("actuarial_corpora", [])
    if corpora:
        corpus_paths = paths.get("actuarial_corpora")
        if not isinstance(corpus_paths, list) or len(corpus_paths) != len(corpora):
            raise ValueError("insurer partner worker bundle actuarial_corpora artifact paths must match supplied corpora")
        for index, corpus in enumerate(corpora):
            artifacts.append(_json_artifact(f"actuarial_corpus_{index}", "actuarial-corpus", corpus_paths[index], corpus))
    if frontend_bundle_path is not None:
        artifacts.append(_binary_artifact("frontend_bundle", "frontend-bundle", frontend_bundle_path, service_attestation))
    return artifacts


def _json_artifact(name: str, artifact_type: str, path: str | Path, expected: Any) -> dict[str, Any]:
    data = Path(path).read_bytes()
    try:
        parsed = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"insurer partner worker bundle artifact JSON invalid: {name}: {exc}") from exc
    parsed_hash = content_hash(parsed)
    expected_hash = content_hash(expected)
    if parsed_hash != expected_hash:
        raise ValueError(f"insurer partner worker bundle artifact content hash mismatch: {name}")
    body = {"name": name, "artifact_type": artifact_type, "path": str(path).replace("\\", "/"), "media_type": "application/json", "size_bytes": len(data), "sha256": _sha256_ref(data), "content_hash": parsed_hash, "expected_content_hash": expected_hash, "content_b64": base64.b64encode(data).decode("ascii")}
    return {**body, "artifact_id": content_hash(body)}


def _binary_artifact(name: str, artifact_type: str, path: str | Path, service_attestation: dict[str, Any]) -> dict[str, Any]:
    source = Path(path)
    data = source.read_bytes()
    sha = _sha256_ref(data)
    signed = _signed_frontend_artifact(service_attestation)
    service = service_attestation.get("service", {}) if isinstance(service_attestation.get("service"), dict) else {}
    expected = signed.get("hash") if signed else service.get("frontend_bundle_artifact_hash") or service.get("frontend_bundle_hash")
    if expected and expected != sha:
        raise ValueError("insurer partner worker bundle frontend bundle artifact hash does not match service attestation")
    body = {"name": name, "artifact_type": artifact_type, "path": str(path).replace("\\", "/"), "media_type": _media_type(source), "size_bytes": len(data), "sha256": sha, "content_hash": sha, "expected_content_hash": expected or sha, "signed_source_id": signed.get("id") if signed else None, "content_b64": base64.b64encode(data).decode("ascii")}
    return {**body, "artifact_id": content_hash(body)}


def _verify_artifacts(value: Any, sources: dict[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    verified: dict[str, dict[str, Any]] = {}
    if not isinstance(value, list):
        errors.append("insurer partner worker bundle source_artifacts must be a list")
        return verified
    expected_names = _expected_names(sources)
    actual_names: set[str] = set()
    for artifact in value:
        if not isinstance(artifact, dict):
            errors.append("insurer partner worker bundle source artifact must be an object")
            continue
        body = without_keys(artifact, "artifact_id")
        if artifact.get("artifact_id") != content_hash(body):
            errors.append(f"insurer partner worker bundle source artifact id mismatch: {artifact.get('name')}")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            errors.append("insurer partner worker bundle source artifact name is required")
            continue
        actual_names.add(name)
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (ValueError, TypeError) as exc:
            errors.append(f"insurer partner worker bundle source artifact content_b64 invalid: {name}: {exc}")
            continue
        if artifact.get("sha256") != _sha256_ref(data):
            errors.append(f"insurer partner worker bundle source artifact sha256 mismatch: {name}")
        if artifact.get("size_bytes") != len(data):
            errors.append(f"insurer partner worker bundle source artifact size mismatch: {name}")
        if name == "frontend_bundle":
            _verify_frontend(artifact, data, sources.get("service_attestation"), errors)
            verified[name] = {"artifact": artifact, "data": data}
            continue
        expected = _source_for_name(name, sources)
        if expected is None:
            errors.append(f"insurer partner worker bundle source artifact unsupported: {name}")
            continue
        if artifact.get("artifact_type") != _type_for_name(name):
            errors.append(f"insurer partner worker bundle source artifact type mismatch: {name}")
        try:
            parsed = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"insurer partner worker bundle source artifact JSON invalid: {name}: {exc}")
            continue
        parsed_hash = content_hash(parsed)
        if artifact.get("content_hash") != parsed_hash:
            errors.append(f"insurer partner worker bundle source artifact content hash mismatch: {name}")
        if content_hash(expected) != parsed_hash:
            errors.append(f"insurer partner worker bundle source artifact does not match embedded source: {name}")
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    if missing:
        errors.append("insurer partner worker bundle source artifacts missing: " + ", ".join(missing))
    if extra:
        errors.append("insurer partner worker bundle source artifacts unsupported for embedded sources: " + ", ".join(extra))
    return verified


def _verify_frontend(artifact: dict[str, Any], data: bytes, service_attestation: dict[str, Any] | None, errors: list[str]) -> None:
    if artifact.get("artifact_type") != "frontend-bundle":
        errors.append("insurer partner worker bundle source artifact type mismatch: frontend_bundle")
    sha = _sha256_ref(data)
    if artifact.get("content_hash") != sha:
        errors.append("insurer partner worker bundle frontend bundle content hash must equal byte sha256")
    signed = _signed_frontend_artifact(service_attestation or {})
    service = service_attestation.get("service", {}) if isinstance(service_attestation, dict) and isinstance(service_attestation.get("service"), dict) else {}
    expected = signed.get("hash") if signed else service.get("frontend_bundle_artifact_hash") or service.get("frontend_bundle_hash")
    if expected and artifact.get("sha256") != expected:
        errors.append("insurer partner worker bundle frontend bundle sha256 does not match signed service artifact")
    if signed:
        if signed.get("size_bytes") != artifact.get("size_bytes"):
            errors.append("insurer partner worker bundle frontend bundle size_bytes does not match signed service artifact")
        if signed.get("schema") != artifact.get("media_type"):
            errors.append("insurer partner worker bundle frontend bundle media_type does not match signed service artifact")


def _source_summary(receipt: dict[str, Any], service_attestation: dict[str, Any], telemetry: dict[str, Any], underwriting_quote: dict[str, Any]) -> dict[str, Any]:
    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    delivery = receipt.get("delivery", {}) if isinstance(receipt.get("delivery"), dict) else {}
    policy = receipt.get("policy_system", {}) if isinstance(receipt.get("policy_system"), dict) else {}
    risk = receipt.get("risk_transfer", {}) if isinstance(receipt.get("risk_transfer"), dict) else {}
    partner = service_attestation.get("partner", {}) if isinstance(service_attestation.get("partner"), dict) else {}
    quote = underwriting_quote.get("quote", {}) if isinstance(underwriting_quote.get("quote"), dict) else {}
    body = {
        "worker_operation_id": receipt.get("worker_operation_id"),
        "worker_receipt_hash": content_hash(receipt),
        "service_attestation_id": service_attestation.get("attestation_id"),
        "service_attestation_hash": content_hash(service_attestation),
        "telemetry_hash": content_hash(telemetry),
        "underwriting_quote_hash": content_hash(underwriting_quote),
        "run_ref": worker.get("run_ref"),
        "operation_kind": worker.get("operation_kind"),
        "destination_ref": delivery.get("destination_ref"),
        "response_status": delivery.get("response_status"),
        "partner_event_log_root": delivery.get("partner_event_log_root"),
        "policy_binding_ref": policy.get("policy_binding_ref"),
        "policy_binding_hash": policy.get("policy_binding_hash"),
        "pack_id": risk.get("pack_id") or telemetry.get("pack_id"),
        "contract_id": risk.get("contract_id") or telemetry.get("contract_id"),
        "consent_id": risk.get("consent_id"),
        "underwriter": partner.get("underwriter"),
        "quote_id": partner.get("quote_id") or underwriting_quote.get("quote_id"),
        "risk_tier": risk.get("risk_tier") or telemetry.get("risk_tier"),
        "quoted_premium_usd": quote.get("quoted_premium_usd"),
        "discount_percent": quote.get("discount_percent"),
        "coverage_limit_usd": quote.get("coverage_limit_usd"),
    }
    return {key: value for key, value in body.items() if value is not None}


def _bundle_summary(receipt: dict[str, Any], sources: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_artifact_count": len(artifacts),
        "source_artifact_sha256_root": content_hash([artifact.get("sha256") for artifact in artifacts]),
        "source_artifact_content_root": content_hash([artifact.get("content_hash") for artifact in artifacts]),
        "source_object_hashes": _source_hashes(sources),
        "frontend_bundle_replayed": any(isinstance(artifact, dict) and artifact.get("name") == "frontend_bundle" for artifact in artifacts),
        "actuarial_product_replayed": "actuarial_product" in sources,
        "actuarial_corpus_count": len(sources.get("actuarial_corpora", [])) if isinstance(sources.get("actuarial_corpora"), list) else 0,
        "worker_control_summary": _status_summary(receipt.get("controls", [])),
    }


def _controls(receipt: dict[str, Any], service_attestation: dict[str, Any], sources: dict[str, Any], artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
    artifact_names = {artifact.get("name") for artifact in artifacts if isinstance(artifact, dict)}
    expected_names = _expected_names(sources)
    signed_frontend = _signed_frontend_artifact(service_attestation)
    risk = receipt.get("risk_transfer", {}) if isinstance(receipt.get("risk_transfer"), dict) else {}
    return [
        {"name": "worker-receipt-offline-replay", "status": "passed" if REQUIRED_JSON_SOURCES <= set(sources) else "failed", "detail": "Embedded worker receipt, service attestation, risk telemetry, and underwriting quote replay through the insurer partner worker verifier."},
        {"name": "source-artifact-byte-binding", "status": "passed" if artifact_names == expected_names else "failed", "detail": "Embedded raw source bytes match parsed source objects by SHA-256 and canonical content hash."},
        {"name": "frontend-bundle-byte-replay", "status": "passed" if signed_frontend and "frontend_bundle" in artifact_names else "not-applicable", "detail": "Frontend bundle bytes are embedded and replayed when the insurer partner service attestation binds a frontend artifact."},
        {"name": "actuarial-product-corpus-replay", "status": "passed" if "actuarial_product" in sources and sources.get("actuarial_corpora") else "not-applicable", "detail": "Actuarial product and corpus sources are embedded and replayed when supplied by the worker receipt path."},
        {"name": "underwriting-risk-transfer-review", "status": "passed" if risk.get("quote_id") and risk.get("consent_active") else "failed", "detail": "Bundle summary exposes consented telemetry, quote, premium, coverage, discount, and policy binding evidence for underwriting review."},
        {"name": "raw-secret-scan", "status": "passed", "detail": "Secret-like source fields must be redacted references or hash/root/ref metadata before bundle verification succeeds."},
    ]


def _expected_names(sources: dict[str, Any]) -> set[str]:
    names = {name for name in JSON_SOURCE_TYPES if name in sources}
    corpora = sources.get("actuarial_corpora", [])
    if isinstance(corpora, list):
        names.update(f"actuarial_corpus_{index}" for index in range(len(corpora)))
    if _signed_frontend_artifact(sources.get("service_attestation", {})):
        names.add("frontend_bundle")
    return names


def _source_for_name(name: str, sources: dict[str, Any]) -> Any | None:
    if name in sources and name != "actuarial_corpora":
        return sources[name]
    if name.startswith("actuarial_corpus_"):
        try:
            index = int(name.removeprefix("actuarial_corpus_"))
        except ValueError:
            return None
        corpora = sources.get("actuarial_corpora", [])
        if isinstance(corpora, list) and 0 <= index < len(corpora):
            return corpora[index]
    return None


def _type_for_name(name: str) -> str:
    if name.startswith("actuarial_corpus_"):
        return "actuarial-corpus"
    return JSON_SOURCE_TYPES.get(name, "")


def _source_hashes(sources: dict[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for name, value in sorted(sources.items()):
        if name == "actuarial_corpora" and isinstance(value, list):
            for index, corpus in enumerate(value):
                hashes[f"actuarial_corpus_{index}"] = content_hash(corpus)
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
    return ".bin"


def _extract_name(artifact: dict[str, Any]) -> str:
    name = str(artifact.get("name") or "source").replace("/", "_").replace("\\", "_")
    if name == "frontend_bundle":
        return name + _artifact_suffix(artifact)
    return name + ".json"


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
                    errors.append(f"insurer partner worker bundle secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if value is None:
        return True
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        return True
    if (key.endswith("_root") or key.endswith("_hash")) and isinstance(value, str) and value.startswith("sha256:"):
        return True
    return False
