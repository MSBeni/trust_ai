from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .provider_callback_storage import verify_provider_callback_storage_manifest
from .provider_ingress import verify_provider_ingress_manifest
from .provider_installation import verify_provider_installation_manifest

PROVIDER_LIFECYCLE_SCHEMA = "trustai.provider-lifecycle/0.1"
PROVIDER_LIFECYCLE_ENTRY_TYPE = "provider_lifecycle.attested"

LIFECYCLE_MODES = {"local-reference", "byoc-reference", "recorded-provider-lifecycle", "production-design"}
SUPPORTED_PROVIDERS = {"github", "gitlab", "slack"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ProviderLifecycleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_provider_lifecycle_manifest(
    *,
    provider_installation: dict[str, Any],
    lifecycle_ref: str,
    oauth_callback_url: str,
    authorization_ref: str,
    token_exchange_ref: str,
    token_store_ref: str,
    refresh_policy_ref: str,
    credential_rotation_ref: str,
    revocation_endpoint: str,
    revocation_ref: str,
    uninstall_ref: str,
    audit_log_stream_ref: str,
    mode: str = "byoc-reference",
    environment: str = "local",
    provider_ingress_manifest: dict[str, Any] | None = None,
    callback_storage_manifest: dict[str, Any] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in LIFECYCLE_MODES:
        raise ValueError("mode must be local-reference, byoc-reference, recorded-provider-lifecycle, or production-design")
    if not isinstance(provider_installation, dict):
        raise ValueError("provider_installation is required")
    for value, field in (
        (lifecycle_ref, "lifecycle_ref"),
        (oauth_callback_url, "oauth_callback_url"),
        (authorization_ref, "authorization_ref"),
        (token_exchange_ref, "token_exchange_ref"),
        (token_store_ref, "token_store_ref"),
        (refresh_policy_ref, "refresh_policy_ref"),
        (credential_rotation_ref, "credential_rotation_ref"),
        (revocation_endpoint, "revocation_endpoint"),
        (revocation_ref, "revocation_ref"),
        (uninstall_ref, "uninstall_ref"),
        (audit_log_stream_ref, "audit_log_stream_ref"),
    ):
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    provider = str(provider_installation.get("provider") or "").strip().lower()
    installation = provider_installation.get("installation", {}) if isinstance(provider_installation.get("installation"), dict) else {}
    app = provider_installation.get("app", {}) if isinstance(provider_installation.get("app"), dict) else {}
    capabilities = provider_installation.get("capabilities", {}) if isinstance(provider_installation.get("capabilities"), dict) else {}
    body = {
        "schema": PROVIDER_LIFECYCLE_SCHEMA,
        "generated_at": timestamp,
        "lifecycle": {
            "mode": mode,
            "environment": environment,
            "lifecycle_ref": lifecycle_ref,
            "provider": provider,
        },
        "installation": {
            "manifest_id": provider_installation.get("manifest_id"),
            "manifest_hash": content_hash(provider_installation),
            "app_ref": app.get("app_ref"),
            "installation_ref": installation.get("installation_ref"),
            "tenant_ref": installation.get("tenant_ref"),
            "owner": installation.get("owner"),
            "repository": installation.get("repository"),
        },
        "oauth": {
            "callback_url": oauth_callback_url,
            "authorization_ref": authorization_ref,
            "token_exchange_ref": token_exchange_ref,
            "token_store": _redacted_ref(token_store_ref),
            "refresh_policy_ref": refresh_policy_ref,
            "scopes": _normalized_list(capabilities.get("scopes")),
            "permissions": _normalized_list(capabilities.get("permissions")),
        },
        "revocation": {
            "endpoint": revocation_endpoint,
            "revocation_ref": revocation_ref,
            "uninstall_ref": uninstall_ref,
        },
        "operations": _operation_records(
            authorization_ref=authorization_ref,
            token_exchange_ref=token_exchange_ref,
            refresh_policy_ref=refresh_policy_ref,
            credential_rotation_ref=credential_rotation_ref,
            revocation_ref=revocation_ref,
            uninstall_ref=uninstall_ref,
            audit_log_stream_ref=audit_log_stream_ref,
        ),
        "source_artifacts": _source_artifact_records(
            provider_installation=provider_installation,
            provider_ingress_manifest=provider_ingress_manifest,
            callback_storage_manifest=callback_storage_manifest,
        ),
        "controls": _controls(
            mode=mode,
            provider_installation=provider_installation,
            oauth_callback_url=oauth_callback_url,
            authorization_ref=authorization_ref,
            token_exchange_ref=token_exchange_ref,
            token_store_ref=token_store_ref,
            refresh_policy_ref=refresh_policy_ref,
            credential_rotation_ref=credential_rotation_ref,
            revocation_endpoint=revocation_endpoint,
            revocation_ref=revocation_ref,
            uninstall_ref=uninstall_ref,
            audit_log_stream_ref=audit_log_stream_ref,
            provider_ingress_manifest=provider_ingress_manifest,
            callback_storage_manifest=callback_storage_manifest,
        ),
        "limitations": [
            "This manifest attests provider OAuth/app lifecycle and revocation evidence for local, BYOC, or recorded lifecycle operation.",
            "It binds provider installation, optional ingress, and optional callback storage evidence by canonical hash; it does not prove live hosted provider operation unless recorded-provider-lifecycle evidence is supplied.",
            "Production SaaS still requires operated OAuth/app callbacks, provider credential issuance and revocation execution, audit-log streaming, and incident-linked lifecycle monitoring.",
        ],
    }
    manifest_id = content_hash(body)
    return {
        **body,
        "lifecycle_manifest_id": manifest_id,
        "signatures": [sign_value({"lifecycle_manifest_id": manifest_id, "provider_lifecycle": body}, key)],
    }


def verify_provider_lifecycle_manifest(
    manifest: dict[str, Any],
    *,
    provider_installation: dict[str, Any] | None = None,
    provider_ingress_manifest: dict[str, Any] | None = None,
    callback_storage_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> ProviderLifecycleVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if manifest.get("schema") != PROVIDER_LIFECYCLE_SCHEMA:
        errors.append(f"unsupported provider lifecycle schema: {manifest.get('schema')}")
    body = without_keys(manifest, "lifecycle_manifest_id", "signatures")
    expected_id = content_hash(body)
    if manifest.get("lifecycle_manifest_id") != expected_id:
        errors.append("lifecycle_manifest_id does not match canonical provider lifecycle body")

    signatures = manifest.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider lifecycle manifest must include at least one signature")
    else:
        signed_value = {"lifecycle_manifest_id": manifest.get("lifecycle_manifest_id"), "provider_lifecycle": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider lifecycle signature verification failed")

    try:
        parse_rfc3339(str(manifest.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"provider lifecycle generated_at invalid: {exc}")

    lifecycle = manifest.get("lifecycle", {})
    if not isinstance(lifecycle, dict):
        errors.append("provider lifecycle lifecycle must be an object")
        lifecycle = {}
    mode = lifecycle.get("mode")
    if mode not in LIFECYCLE_MODES:
        errors.append("provider lifecycle mode is unsupported")
    elif mode != "recorded-provider-lifecycle":
        warnings.append(f"provider lifecycle mode is {mode}; live hosted provider lifecycle operation is not claimed")
    if lifecycle.get("provider") not in SUPPORTED_PROVIDERS:
        errors.append(f"provider lifecycle provider unsupported: {lifecycle.get('provider')}")
    for field in ("environment", "lifecycle_ref"):
        if not lifecycle.get(field):
            errors.append(f"provider lifecycle {field} is required")

    installation = manifest.get("installation", {})
    if not isinstance(installation, dict):
        errors.append("provider lifecycle installation must be an object")
        installation = {}
    for field in ("manifest_id", "manifest_hash", "app_ref", "installation_ref", "tenant_ref"):
        if not installation.get(field):
            errors.append(f"provider lifecycle installation.{field} is required")

    oauth = manifest.get("oauth", {})
    if not isinstance(oauth, dict):
        errors.append("provider lifecycle oauth must be an object")
        oauth = {}
    callback_url = str(oauth.get("callback_url") or "")
    if not _valid_url(callback_url):
        errors.append("provider lifecycle oauth.callback_url must be an absolute URL")
    elif not _is_https(callback_url):
        errors.append("provider lifecycle oauth.callback_url must use HTTPS")
    for field in ("authorization_ref", "token_exchange_ref", "refresh_policy_ref"):
        if not oauth.get(field):
            errors.append(f"provider lifecycle oauth.{field} is required")
    if oauth.get("token_store") is not None:
        _verify_redacted_ref(oauth.get("token_store"), "provider lifecycle oauth.token_store", errors)
    else:
        errors.append("provider lifecycle oauth.token_store redacted reference is required")
    for field in ("scopes", "permissions"):
        if not _is_string_list(oauth.get(field, [])):
            errors.append(f"provider lifecycle oauth.{field} must be a string array")

    revocation = manifest.get("revocation", {})
    if not isinstance(revocation, dict):
        errors.append("provider lifecycle revocation must be an object")
        revocation = {}
    revocation_endpoint = str(revocation.get("endpoint") or "")
    if not _valid_url(revocation_endpoint):
        errors.append("provider lifecycle revocation.endpoint must be an absolute URL")
    elif not _is_https(revocation_endpoint):
        errors.append("provider lifecycle revocation.endpoint must use HTTPS")
    for field in ("revocation_ref", "uninstall_ref"):
        if not revocation.get(field):
            errors.append(f"provider lifecycle revocation.{field} is required")

    operations = manifest.get("operations", [])
    if not isinstance(operations, list):
        errors.append("provider lifecycle operations must be a list")
        operations = []
    errors.extend(_operation_shape_errors(operations))

    manifest_sources = manifest.get("source_artifacts", [])
    if not isinstance(manifest_sources, list):
        errors.append("provider lifecycle source_artifacts must be a list")
        manifest_sources = []

    if provider_installation is None:
        warnings.append("provider lifecycle provider installation was not supplied; installation hash was not replayed")
    else:
        result = verify_provider_installation_manifest(provider_installation, key=key)
        if not result.ok:
            errors.extend(f"provider lifecycle installation invalid: {error}" for error in result.errors)
        warnings.extend(f"provider lifecycle installation warning: {warning}" for warning in result.warnings)
        expected_installation = _installation_record(provider_installation)
        if installation != expected_installation:
            errors.append("provider lifecycle installation record does not match supplied provider installation")

    if provider_ingress_manifest is not None:
        ingress_result = verify_provider_ingress_manifest(provider_ingress_manifest, key=key)
        if not ingress_result.ok:
            errors.extend(f"provider lifecycle ingress invalid: {error}" for error in ingress_result.errors)
        warnings.extend(f"provider lifecycle ingress warning: {warning}" for warning in ingress_result.warnings)
        ingress = provider_ingress_manifest.get("ingress", {}) if isinstance(provider_ingress_manifest.get("ingress"), dict) else {}
        base_url = str(ingress.get("base_url") or "")
        if base_url and _hostname(callback_url).lower() != _hostname(base_url).lower():
            errors.append("provider lifecycle oauth.callback_url must share the provider ingress base URL host")
    elif any(source.get("artifact_type") == "provider_ingress" for source in manifest_sources if isinstance(source, dict)):
        warnings.append("provider lifecycle ingress manifest was not supplied; ingress hash was not replayed")

    if callback_storage_manifest is not None:
        storage_result = verify_provider_callback_storage_manifest(callback_storage_manifest, key=key)
        if not storage_result.ok:
            errors.extend(f"provider lifecycle callback storage invalid: {error}" for error in storage_result.errors)
        warnings.extend(f"provider lifecycle callback storage warning: {warning}" for warning in storage_result.warnings)
    elif any(source.get("artifact_type") == "provider_callback_storage" for source in manifest_sources if isinstance(source, dict)):
        warnings.append("provider lifecycle callback storage manifest was not supplied; storage hash was not replayed")

    if provider_installation is not None or provider_ingress_manifest is not None or callback_storage_manifest is not None:
        expected_sources = _source_artifact_records(
            provider_installation=provider_installation,
            provider_ingress_manifest=provider_ingress_manifest,
            callback_storage_manifest=callback_storage_manifest,
        )
        if manifest_sources != expected_sources:
            errors.append("provider lifecycle source artifact summaries do not match supplied artifacts")

    controls = manifest.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("provider lifecycle controls are required")
    _check_no_secret_values(manifest, errors)

    return ProviderLifecycleVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_lifecycle_manifest(
    chain: EvidenceChain,
    manifest: dict[str, Any],
    *,
    provider_installation: dict[str, Any] | None = None,
    provider_ingress_manifest: dict[str, Any] | None = None,
    callback_storage_manifest: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_lifecycle_manifest(
        manifest,
        provider_installation=provider_installation,
        provider_ingress_manifest=provider_ingress_manifest,
        callback_storage_manifest=callback_storage_manifest,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid provider lifecycle manifest: " + "; ".join(result.errors))
    payload = {
        "lifecycle_manifest_id": manifest["lifecycle_manifest_id"],
        "lifecycle_manifest_hash": content_hash(manifest),
        "lifecycle": manifest.get("lifecycle"),
        "installation": manifest.get("installation"),
        "oauth": without_keys(manifest.get("oauth", {}), "token_store") if isinstance(manifest.get("oauth"), dict) else {},
        "revocation": manifest.get("revocation"),
        "operation_count": len(manifest.get("operations", [])),
        "operation_status_counts": _status_summary(manifest.get("operations", [])),
        "source_artifact_count": len(manifest.get("source_artifacts", [])),
        "control_summary": _status_summary(manifest.get("controls", [])),
    }
    return chain.append(PROVIDER_LIFECYCLE_ENTRY_TYPE, payload, key=key, timestamp=manifest.get("generated_at"))


def load_provider_lifecycle_manifest(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider lifecycle manifest must contain an object")
    return value


def write_provider_lifecycle_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def _operation_records(
    *,
    authorization_ref: str,
    token_exchange_ref: str,
    refresh_policy_ref: str,
    credential_rotation_ref: str,
    revocation_ref: str,
    uninstall_ref: str,
    audit_log_stream_ref: str,
) -> list[dict[str, str]]:
    operations = [
        ("authorization_callback", authorization_ref),
        ("token_exchange", token_exchange_ref),
        ("token_refresh_policy", refresh_policy_ref),
        ("credential_rotation", credential_rotation_ref),
        ("revocation_workflow", revocation_ref),
        ("uninstall_workflow", uninstall_ref),
        ("audit_log_stream_binding", audit_log_stream_ref),
    ]
    return [{"kind": kind, "operation_ref": ref, "status": "recorded-reference" if ref else "planned-production"} for kind, ref in operations]


def _operation_shape_errors(operations: list[Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "authorization_callback",
        "token_exchange",
        "token_refresh_policy",
        "credential_rotation",
        "revocation_workflow",
        "uninstall_workflow",
        "audit_log_stream_binding",
    }
    seen: set[str] = set()
    for operation in operations:
        if not isinstance(operation, dict):
            errors.append("provider lifecycle operation must be an object")
            continue
        kind = operation.get("kind")
        if kind not in required:
            errors.append(f"provider lifecycle operation kind unsupported: {kind}")
        else:
            seen.add(kind)
        if not operation.get("operation_ref"):
            errors.append(f"provider lifecycle operation missing operation_ref: {kind}")
        if operation.get("status") not in {"recorded-reference", "planned-production", "implemented"}:
            errors.append(f"provider lifecycle operation status unsupported: {operation.get('status')}")
    for missing in sorted(required - seen):
        errors.append(f"provider lifecycle operation missing required kind: {missing}")
    return errors


def _installation_record(provider_installation: dict[str, Any]) -> dict[str, Any]:
    installation = provider_installation.get("installation", {}) if isinstance(provider_installation.get("installation"), dict) else {}
    app = provider_installation.get("app", {}) if isinstance(provider_installation.get("app"), dict) else {}
    return {
        "manifest_id": provider_installation.get("manifest_id"),
        "manifest_hash": content_hash(provider_installation),
        "app_ref": app.get("app_ref"),
        "installation_ref": installation.get("installation_ref"),
        "tenant_ref": installation.get("tenant_ref"),
        "owner": installation.get("owner"),
        "repository": installation.get("repository"),
    }


def _source_artifact_records(
    *,
    provider_installation: dict[str, Any] | None,
    provider_ingress_manifest: dict[str, Any] | None,
    callback_storage_manifest: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if provider_installation is not None:
        records.append(
            {
                "artifact_type": "provider_installation",
                "schema": provider_installation.get("schema"),
                "provider": provider_installation.get("provider"),
                "manifest_id": provider_installation.get("manifest_id"),
                "source_hash": content_hash(provider_installation),
            }
        )
    if provider_ingress_manifest is not None:
        ingress = provider_ingress_manifest.get("ingress", {}) if isinstance(provider_ingress_manifest.get("ingress"), dict) else {}
        records.append(
            {
                "artifact_type": "provider_ingress",
                "schema": provider_ingress_manifest.get("schema"),
                "ingress_manifest_id": provider_ingress_manifest.get("ingress_manifest_id"),
                "source_hash": content_hash(provider_ingress_manifest),
                "base_url": ingress.get("base_url"),
                "endpoint_count": len(provider_ingress_manifest.get("endpoints", [])) if isinstance(provider_ingress_manifest.get("endpoints"), list) else None,
            }
        )
    if callback_storage_manifest is not None:
        storage = callback_storage_manifest.get("storage", {}) if isinstance(callback_storage_manifest.get("storage"), dict) else {}
        records.append(
            {
                "artifact_type": "provider_callback_storage",
                "schema": callback_storage_manifest.get("schema"),
                "storage_manifest_id": callback_storage_manifest.get("storage_manifest_id"),
                "source_hash": content_hash(callback_storage_manifest),
                "engine": storage.get("engine"),
                "storage_ref": storage.get("storage_ref"),
            }
        )
    return sorted(records, key=lambda item: (str(item.get("artifact_type")), str(item.get("manifest_id") or item.get("ingress_manifest_id") or item.get("storage_manifest_id"))))


def _controls(
    *,
    mode: str,
    provider_installation: dict[str, Any],
    oauth_callback_url: str,
    authorization_ref: str,
    token_exchange_ref: str,
    token_store_ref: str,
    refresh_policy_ref: str,
    credential_rotation_ref: str,
    revocation_endpoint: str,
    revocation_ref: str,
    uninstall_ref: str,
    audit_log_stream_ref: str,
    provider_ingress_manifest: dict[str, Any] | None,
    callback_storage_manifest: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    audit_log = provider_installation.get("audit_log", {}) if isinstance(provider_installation.get("audit_log"), dict) else {}
    return [
        {
            "id": "provider-installation-binding",
            "status": "implemented" if provider_installation.get("manifest_id") else "planned-production",
            "description": "Lifecycle evidence is bound to a signed provider installation manifest.",
        },
        {
            "id": "oauth-callback-execution",
            "status": "implemented" if _is_https(oauth_callback_url) and authorization_ref and token_exchange_ref else "planned-production",
            "description": "OAuth callback and token-exchange evidence references are recorded.",
        },
        {
            "id": "redacted-token-storage",
            "status": "implemented" if token_store_ref else "planned-production",
            "description": "Provider tokens are represented only by redacted token-store references.",
        },
        {
            "id": "credential-refresh-rotation",
            "status": "implemented" if refresh_policy_ref and credential_rotation_ref else "planned-production",
            "description": "Refresh policy and credential rotation references are recorded.",
        },
        {
            "id": "revocation-workflow",
            "status": "implemented" if _is_https(revocation_endpoint) and revocation_ref and uninstall_ref else "planned-production",
            "description": "Provider token revocation and app uninstall workflow references are recorded.",
        },
        {
            "id": "callback-ingress-binding",
            "status": "implemented" if provider_ingress_manifest else "planned-production",
            "description": "Lifecycle callbacks are bound to provider ingress evidence.",
        },
        {
            "id": "callback-storage-binding",
            "status": "implemented" if callback_storage_manifest else "planned-production",
            "description": "Lifecycle callbacks are bound to callback storage evidence.",
        },
        {
            "id": "provider-audit-log-stream-binding",
            "status": "implemented" if audit_log_stream_ref and audit_log.get("ref") else "planned-production",
            "description": "Provider audit-log stream evidence is tied to the installation audit-log reference.",
        },
        {
            "id": "live-hosted-provider-lifecycle",
            "status": "implemented" if mode == "recorded-provider-lifecycle" else "planned-production",
            "description": "Live hosted OAuth/app execution, credential issuance, revocation, and monitoring are operationally evidenced.",
        },
    ]


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _normalized_list(values: Any) -> list[str]:
    if not values:
        return []
    if not isinstance(values, list):
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
                if _allowed_secret_reference_key(normalized, item):
                    pass
                elif not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"provider lifecycle secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    return key.endswith("_ref") and isinstance(value, str) and bool(value.strip())
