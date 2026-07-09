from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .provider_callback_store import (
    verify_provider_callback_store_manifest,
)
from .provider_installation import verify_provider_installation_manifest

PROVIDER_INGRESS_SCHEMA = "trustai.provider-ingress/0.1"
PROVIDER_INGRESS_ENTRY_TYPE = "provider_ingress.attested"

INGRESS_MODES = {"local-reference", "byoc-reference", "recorded-public-ingress", "production-design"}
SUPPORTED_PROVIDERS = {"github", "gitlab", "slack"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")

EXPECTED_SIGNATURES = {
    "github": "github-hmac-sha256",
    "gitlab": "gitlab-shared-token",
    "slack": "slack-signing-secret",
}


@dataclass
class ProviderIngressVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_provider_ingress_manifest(
    *,
    ingress_base_url: str,
    ingress_ref: str,
    dns_name: str | None = None,
    mode: str = "byoc-reference",
    environment: str = "local",
    healthcheck_url: str | None = None,
    tls_certificate_ref: str | None = None,
    tls_certificate_fingerprint: str | None = None,
    waf_ref: str | None = None,
    network_policy_ref: str | None = None,
    rate_limit_policy_ref: str | None = None,
    allowed_source_refs: list[str] | None = None,
    replay_window_seconds: int = 300,
    provider_installations: list[dict[str, Any]] | None = None,
    callback_store_manifest: dict[str, Any] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in INGRESS_MODES:
        raise ValueError("mode must be local-reference, byoc-reference, recorded-public-ingress, or production-design")
    _require_text(ingress_base_url, "ingress_base_url")
    _require_text(ingress_ref, "ingress_ref")
    _require_text(environment, "environment")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    base_url = _normalize_base_url(ingress_base_url)
    endpoint_records = _endpoint_records(base_url, provider_installations or [])
    if not endpoint_records:
        raise ValueError("at least one provider installation with a webhook or callback URL is required")

    body = {
        "schema": PROVIDER_INGRESS_SCHEMA,
        "generated_at": timestamp,
        "ingress": {
            "mode": mode,
            "environment": environment,
            "ingress_ref": ingress_ref,
            "base_url": base_url,
            "dns_name": dns_name,
            "healthcheck_url": healthcheck_url or urljoin(base_url + "/", "healthz"),
        },
        "tls": {
            "https_required": True,
            "certificate": _redacted_ref(tls_certificate_ref),
            "certificate_fingerprint": _normalize_fingerprint(tls_certificate_fingerprint),
        },
        "network_controls": {
            "waf_ref": waf_ref,
            "network_policy_ref": network_policy_ref,
            "rate_limit_policy_ref": rate_limit_policy_ref,
            "allowed_source_refs": _normalized_list(allowed_source_refs),
            "replay_window_seconds": int(replay_window_seconds),
        },
        "endpoints": endpoint_records,
        "source_artifacts": _source_artifact_records(
            provider_installations or [],
            callback_store_manifest=callback_store_manifest,
        ),
        "controls": _controls(
            mode=mode,
            base_url=base_url,
            dns_name=dns_name,
            tls_certificate_ref=tls_certificate_ref,
            tls_certificate_fingerprint=tls_certificate_fingerprint,
            waf_ref=waf_ref,
            network_policy_ref=network_policy_ref,
            rate_limit_policy_ref=rate_limit_policy_ref,
            allowed_source_refs=allowed_source_refs,
            replay_window_seconds=replay_window_seconds,
            endpoints=endpoint_records,
            callback_store_manifest=callback_store_manifest,
        ),
        "limitations": [
            "This manifest attests TrustAI provider callback ingress configuration for local, BYOC, or recorded public-ingress evidence.",
            "It binds provider app installations and optional callback-store evidence by canonical hash; it does not prove live DNS, ACME, WAF, or provider delivery unless separate source evidence is supplied.",
            "Production SaaS still requires hosted OAuth or app execution, public ingress operation, revocation workflows, managed HA request storage, and provider-authenticated audit-log streaming.",
        ],
    }
    manifest_id = content_hash(body)
    return {
        **body,
        "ingress_manifest_id": manifest_id,
        "signatures": [sign_value({"ingress_manifest_id": manifest_id, "provider_ingress": body}, key)],
    }


def verify_provider_ingress_manifest(
    manifest: dict[str, Any],
    *,
    provider_installations: list[dict[str, Any]] | None = None,
    callback_store_manifest: dict[str, Any] | None = None,
    callback_store_db_path: str | Path | None = None,
    key: str | None = None,
) -> ProviderIngressVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if manifest.get("schema") != PROVIDER_INGRESS_SCHEMA:
        errors.append(f"unsupported provider ingress schema: {manifest.get('schema')}")
    body = without_keys(manifest, "ingress_manifest_id", "signatures")
    expected_id = content_hash(body)
    if manifest.get("ingress_manifest_id") != expected_id:
        errors.append("ingress_manifest_id does not match canonical provider ingress body")

    signatures = manifest.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider ingress manifest must include at least one signature")
    else:
        signed_value = {"ingress_manifest_id": manifest.get("ingress_manifest_id"), "provider_ingress": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider ingress signature verification failed")

    try:
        parse_rfc3339(str(manifest.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"provider ingress generated_at invalid: {exc}")

    ingress = manifest.get("ingress", {})
    if not isinstance(ingress, dict):
        errors.append("provider ingress ingress must be an object")
        ingress = {}
    mode = ingress.get("mode")
    if mode not in INGRESS_MODES:
        errors.append("provider ingress mode is unsupported")
    elif mode in {"local-reference", "production-design"}:
        warnings.append(f"provider ingress mode is {mode}; live public callback operation is not claimed")

    base_url = str(ingress.get("base_url") or "")
    base_host = _hostname(base_url)
    if not _valid_url(base_url):
        errors.append("provider ingress base_url must be an absolute URL")
    elif not _is_https(base_url):
        errors.append("provider ingress base_url must use HTTPS")
    if not ingress.get("ingress_ref"):
        errors.append("provider ingress ingress_ref is required")
    if not ingress.get("environment"):
        errors.append("provider ingress environment is required")
    dns_name = ingress.get("dns_name")
    if dns_name:
        if base_host and str(dns_name).lower() != base_host.lower():
            errors.append("provider ingress dns_name must match ingress base_url host")
    else:
        warnings.append("provider ingress dns_name is not recorded")

    healthcheck_url = ingress.get("healthcheck_url")
    if healthcheck_url:
        if not _valid_url(str(healthcheck_url)):
            errors.append("provider ingress healthcheck_url must be an absolute URL")
        elif not _is_https(str(healthcheck_url)):
            errors.append("provider ingress healthcheck_url must use HTTPS")
        elif base_host and _hostname(str(healthcheck_url)).lower() != base_host.lower():
            errors.append("provider ingress healthcheck_url must share the ingress base_url host")
    else:
        warnings.append("provider ingress healthcheck_url is not recorded")

    tls = manifest.get("tls", {})
    if not isinstance(tls, dict):
        errors.append("provider ingress tls must be an object")
        tls = {}
    if tls.get("https_required") is not True:
        errors.append("provider ingress tls.https_required must be true")
    certificate = tls.get("certificate")
    if certificate is not None:
        _verify_redacted_ref(certificate, "provider ingress tls.certificate", errors)
    if not certificate and not tls.get("certificate_fingerprint"):
        errors.append("provider ingress must include a TLS certificate reference or sha256 fingerprint")
    fingerprint = tls.get("certificate_fingerprint")
    if fingerprint and not str(fingerprint).startswith("sha256:"):
        errors.append("provider ingress tls.certificate_fingerprint must start with sha256:")

    network = manifest.get("network_controls", {})
    if not isinstance(network, dict):
        errors.append("provider ingress network_controls must be an object")
        network = {}
    allowed_sources = network.get("allowed_source_refs", [])
    if not _is_string_list(allowed_sources):
        errors.append("provider ingress allowed_source_refs must be a string array")
    elif not allowed_sources:
        warnings.append("provider ingress allowed_source_refs is empty")
    replay_window = network.get("replay_window_seconds")
    if not isinstance(replay_window, int) or replay_window <= 0 or replay_window > 600:
        errors.append("provider ingress replay_window_seconds must be an integer between 1 and 600")
    if not network.get("network_policy_ref"):
        errors.append("provider ingress network_policy_ref is required")
    if not network.get("rate_limit_policy_ref"):
        errors.append("provider ingress rate_limit_policy_ref is required")
    if not network.get("waf_ref"):
        warnings.append("provider ingress waf_ref is not recorded")

    endpoints = manifest.get("endpoints", [])
    if not isinstance(endpoints, list) or not endpoints:
        errors.append("provider ingress endpoints must be a non-empty list")
        endpoints = []
    else:
        errors.extend(_endpoint_shape_errors(endpoints, base_host=base_host))

    if provider_installations is None:
        warnings.append("provider ingress provider installation artifacts were not supplied; endpoint source hashes were not replayed")
    else:
        for installation in provider_installations:
            result = verify_provider_installation_manifest(installation, key=key)
            if not result.ok:
                errors.extend(f"provider ingress source installation invalid: {error}" for error in result.errors)
            warnings.extend(f"provider ingress source installation warning: {warning}" for warning in result.warnings)
        expected_endpoints = _endpoint_records(base_url, provider_installations)
        if endpoints != expected_endpoints:
            errors.append("provider ingress endpoints do not match supplied provider installation artifacts")

    manifest_sources = manifest.get("source_artifacts", [])
    if not isinstance(manifest_sources, list):
        errors.append("provider ingress source_artifacts must be a list")
        manifest_sources = []
    if provider_installations is not None or callback_store_manifest is not None:
        expected_sources = _source_artifact_records(
            provider_installations or [],
            callback_store_manifest=callback_store_manifest,
        )
        if manifest_sources != expected_sources:
            errors.append("provider ingress source artifact summaries do not match supplied artifacts")
    else:
        warnings.append("provider ingress source artifacts were not supplied; source hashes were not replayed")

    if callback_store_manifest is not None:
        store_result = verify_provider_callback_store_manifest(
            callback_store_manifest,
            db_path=callback_store_db_path,
            source_artifacts=None,
            key=key,
        )
        if not store_result.ok:
            errors.extend(f"provider ingress callback store invalid: {error}" for error in store_result.errors)
        warnings.extend(f"provider ingress callback store warning: {warning}" for warning in store_result.warnings)
    elif any(source.get("artifact_type") == "provider_callback_store" for source in manifest_sources):
        warnings.append("provider ingress callback-store manifest was not supplied; callback-store hash was not replayed")

    controls = manifest.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("provider ingress controls are required")
    _check_no_secret_values(manifest, errors)

    return ProviderIngressVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_ingress_manifest(
    chain: EvidenceChain,
    manifest: dict[str, Any],
    *,
    provider_installations: list[dict[str, Any]] | None = None,
    callback_store_manifest: dict[str, Any] | None = None,
    callback_store_db_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_ingress_manifest(
        manifest,
        provider_installations=provider_installations,
        callback_store_manifest=callback_store_manifest,
        callback_store_db_path=callback_store_db_path,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid provider ingress manifest: " + "; ".join(result.errors))
    payload = {
        "ingress_manifest_id": manifest["ingress_manifest_id"],
        "ingress_manifest_hash": content_hash(manifest),
        "ingress": manifest.get("ingress"),
        "tls": {
            "https_required": manifest.get("tls", {}).get("https_required"),
            "certificate_fingerprint": manifest.get("tls", {}).get("certificate_fingerprint"),
            "certificate_attested": bool(manifest.get("tls", {}).get("certificate")),
        },
        "network_controls": manifest.get("network_controls"),
        "endpoint_count": len(manifest.get("endpoints", [])),
        "provider_counts": _count_by(manifest.get("endpoints", []), "provider"),
        "source_artifact_count": len(manifest.get("source_artifacts", [])),
        "control_summary": _status_summary(manifest.get("controls", [])),
    }
    return chain.append(PROVIDER_INGRESS_ENTRY_TYPE, payload, key=key, timestamp=manifest.get("generated_at"))


def load_provider_ingress_manifest(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider ingress manifest must contain an object")
    return value


def write_provider_ingress_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def _endpoint_records(base_url: str, provider_installations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    base_host = _hostname(base_url)
    for installation in provider_installations:
        provider = str(installation.get("provider") or "").strip().lower()
        webhook = installation.get("webhook", {}) if isinstance(installation.get("webhook"), dict) else {}
        for source_field, kind in (("url", "provider_webhook"), ("callback_url", "provider_callback")):
            url = webhook.get(source_field)
            if not url:
                continue
            parsed = urlparse(str(url))
            path = parsed.path or "/"
            records.append(
                {
                    "provider": provider,
                    "kind": kind,
                    "url": str(url),
                    "path": path,
                    "base_url_host": base_host,
                    "expected_signature": EXPECTED_SIGNATURES.get(provider),
                    "source_field": f"webhook.{source_field}",
                    "provider_installation_manifest_id": installation.get("manifest_id"),
                    "provider_installation_hash": content_hash(installation),
                }
            )
    return sorted(records, key=lambda item: (item["provider"], item["kind"], item["url"]))


def _source_artifact_records(
    provider_installations: list[dict[str, Any]],
    *,
    callback_store_manifest: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for installation in provider_installations:
        webhook = installation.get("webhook", {}) if isinstance(installation.get("webhook"), dict) else {}
        records.append(
            {
                "artifact_type": "provider_installation",
                "schema": installation.get("schema"),
                "provider": installation.get("provider"),
                "manifest_id": installation.get("manifest_id"),
                "source_hash": content_hash(installation),
                "webhook_url": webhook.get("url"),
                "callback_url": webhook.get("callback_url"),
            }
        )
    if callback_store_manifest is not None:
        summary = callback_store_manifest.get("summary", {}) if isinstance(callback_store_manifest.get("summary"), dict) else {}
        database = callback_store_manifest.get("database", {}) if isinstance(callback_store_manifest.get("database"), dict) else {}
        records.append(
            {
                "artifact_type": "provider_callback_store",
                "schema": callback_store_manifest.get("schema"),
                "store_manifest_id": callback_store_manifest.get("store_manifest_id"),
                "source_hash": content_hash(callback_store_manifest),
                "operation_count": summary.get("operation_count"),
                "operation_type_counts": summary.get("operation_type_counts"),
                "provider_counts": summary.get("provider_counts"),
                "database_engine": database.get("engine"),
                "database_schema_version": database.get("schema_version"),
            }
        )
    return sorted(records, key=lambda item: (str(item.get("artifact_type")), str(item.get("provider")), str(item.get("manifest_id") or item.get("store_manifest_id"))))


def _endpoint_shape_errors(endpoints: list[Any], *, base_host: str) -> list[str]:
    errors: list[str] = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            errors.append("provider ingress endpoint must be an object")
            continue
        provider = endpoint.get("provider")
        if provider not in SUPPORTED_PROVIDERS:
            errors.append(f"provider ingress endpoint provider unsupported: {provider}")
        kind = endpoint.get("kind")
        if kind not in {"provider_webhook", "provider_callback"}:
            errors.append(f"provider ingress endpoint kind unsupported: {kind}")
        url = str(endpoint.get("url") or "")
        if not _valid_url(url):
            errors.append("provider ingress endpoint url must be an absolute URL")
        elif not _is_https(url):
            errors.append("provider ingress endpoint url must use HTTPS")
        elif base_host and _hostname(url).lower() != base_host.lower():
            errors.append("provider ingress endpoint url must share the ingress base_url host")
        path = endpoint.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            errors.append("provider ingress endpoint path must start with /")
        if not endpoint.get("expected_signature"):
            errors.append("provider ingress endpoint expected_signature is required")
        if not endpoint.get("provider_installation_manifest_id"):
            errors.append("provider ingress endpoint provider_installation_manifest_id is required")
        if not endpoint.get("provider_installation_hash"):
            errors.append("provider ingress endpoint provider_installation_hash is required")
    return errors


def _controls(
    *,
    mode: str,
    base_url: str,
    dns_name: str | None,
    tls_certificate_ref: str | None,
    tls_certificate_fingerprint: str | None,
    waf_ref: str | None,
    network_policy_ref: str | None,
    rate_limit_policy_ref: str | None,
    allowed_source_refs: list[str] | None,
    replay_window_seconds: int,
    endpoints: list[dict[str, Any]],
    callback_store_manifest: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    base_host = _hostname(base_url)
    return [
        {
            "id": "public-https-ingress-manifest",
            "status": "implemented" if _is_https(base_url) and endpoints else "planned-production",
            "description": "Ingress base URL and provider callback endpoints are recorded as absolute HTTPS URLs.",
        },
        {
            "id": "dns-binding",
            "status": "implemented" if dns_name and str(dns_name).lower() == base_host.lower() else "planned-production",
            "description": "The ingress DNS name is bound to the attested base URL host.",
        },
        {
            "id": "tls-certificate-binding",
            "status": "implemented" if tls_certificate_ref or tls_certificate_fingerprint else "planned-production",
            "description": "TLS certificate material is represented by a redacted reference or sha256 fingerprint.",
        },
        {
            "id": "provider-signature-verification",
            "status": "implemented" if endpoints and all(endpoint.get("expected_signature") for endpoint in endpoints) else "planned-production",
            "description": "Each provider endpoint declares the expected request-signature scheme.",
        },
        {
            "id": "replay-and-rate-limit-controls",
            "status": "implemented" if replay_window_seconds and rate_limit_policy_ref and allowed_source_refs else "planned-production",
            "description": "Ingress records replay-window, rate-limit, and allowed-source control references.",
        },
        {
            "id": "network-boundary-controls",
            "status": "implemented" if waf_ref and network_policy_ref else "planned-production",
            "description": "Ingress records WAF and network-policy control references.",
        },
        {
            "id": "callback-store-binding",
            "status": "implemented" if callback_store_manifest else "planned-production",
            "description": "Ingress evidence is bound to a signed provider callback operation store.",
        },
        {
            "id": "hosted-provider-ingress-operations",
            "status": "implemented" if mode == "recorded-public-ingress" else "planned-production",
            "description": "Live hosted ingress operation, OAuth/app callbacks, revocation workflows, and HA request storage are operationally evidenced.",
        },
    ]


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls if isinstance(controls, list) else []:
        if isinstance(control, dict):
            status = str(control.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _count_by(items: Any, field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            value = str(item.get(field) or "unknown")
            counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _normalize_base_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("ingress_base_url must be an absolute URL")
    return value.rstrip("/")


def _normalize_fingerprint(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().lower()


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _normalized_list(values: list[str] | None) -> list[str]:
    if not values:
        return []
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def _valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def _is_https(value: str | None) -> bool:
    return bool(value and urlparse(value).scheme.lower() == "https")


def _hostname(value: str) -> str:
    return str(urlparse(value).hostname or "")


def _require_text(value: str | None, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _check_no_secret_values(value: Any, errors: list[str], *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"provider ingress secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")
