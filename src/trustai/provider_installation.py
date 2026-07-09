from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

PROVIDER_INSTALLATION_SCHEMA = "trustai.provider-installation/0.1"
PROVIDER_INSTALLATION_ENTRY_TYPE = "provider_installation.registered"

SUPPORTED_PROVIDERS = {"github", "gitlab", "slack"}
INSTALLATION_MODES = {"local-reference", "recorded-installation", "oauth-installation", "app-installation"}


@dataclass
class ProviderInstallationVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_provider_installation_manifest(
    *,
    provider: str,
    app_ref: str,
    installation_ref: str,
    tenant_ref: str,
    owner: str | None = None,
    repository: str | None = None,
    mode: str = "recorded-installation",
    app_url: str | None = None,
    webhook_url: str | None = None,
    callback_url: str | None = None,
    permissions: list[str] | None = None,
    scopes: list[str] | None = None,
    events: list[str] | None = None,
    secret_ref: str | None = None,
    credential_ref: str | None = None,
    audit_log_ref: str | None = None,
    audit_log_scopes: list[str] | None = None,
    installed_at: str | None = None,
    expires_at: str | None = None,
    evidence_refs: list[str] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    provider_name = _normalize_provider(provider)
    if mode not in INSTALLATION_MODES:
        raise ValueError("mode must be local-reference, recorded-installation, oauth-installation, or app-installation")
    installed = installed_at or utc_now()
    parse_rfc3339(installed)
    if expires_at:
        if parse_rfc3339(expires_at) <= parse_rfc3339(installed):
            raise ValueError("expires_at must be after installed_at")
    _require_text(app_ref, "app_ref")
    _require_text(installation_ref, "installation_ref")
    _require_text(tenant_ref, "tenant_ref")

    permission_values = _normalized_list(permissions)
    scope_values = _normalized_list(scopes)
    event_values = _normalized_list(events)
    if not permission_values and not scope_values:
        raise ValueError("at least one provider permission or OAuth scope is required")
    if not event_values:
        raise ValueError("at least one subscribed provider event is required")

    body: dict[str, Any] = {
        "schema": PROVIDER_INSTALLATION_SCHEMA,
        "provider": provider_name,
        "mode": mode,
        "installed_at": installed,
        "expires_at": expires_at,
        "app": {
            "app_ref": app_ref,
            "app_url": app_url,
        },
        "installation": {
            "installation_ref": installation_ref,
            "tenant_ref": tenant_ref,
            "owner": owner,
            "repository": repository,
        },
        "capabilities": {
            "permissions": permission_values,
            "scopes": scope_values,
            "events": event_values,
        },
        "webhook": {
            "url": webhook_url,
            "callback_url": callback_url,
            "secret": _redacted_ref(secret_ref),
            "tls_required": _is_https(webhook_url) if webhook_url else None,
        },
        "credential": _redacted_ref(credential_ref),
        "audit_log": {
            "ref": audit_log_ref,
            "scopes": _normalized_list(audit_log_scopes),
        },
        "evidence_refs": _normalized_list(evidence_refs),
        "controls": _controls(
            mode=mode,
            webhook_url=webhook_url,
            callback_url=callback_url,
            secret_ref=secret_ref,
            credential_ref=credential_ref,
            audit_log_ref=audit_log_ref,
            audit_log_scopes=audit_log_scopes,
        ),
        "limitations": [
            "This manifest records provider app installation configuration supplied to TrustAI and binds it by signature.",
            "It does not claim a completed hosted OAuth flow unless backed by provider-owned installation evidence.",
            "Production deployments should pair this manifest with provider callback delivery, webhook, audit-correlation, and database retention evidence.",
        ],
    }
    manifest_id = content_hash(body)
    return {
        **body,
        "manifest_id": manifest_id,
        "signatures": [sign_value({"manifest_id": manifest_id, "provider_installation": body}, key)],
    }


def verify_provider_installation_manifest(
    manifest: dict[str, Any],
    *,
    key: str | None = None,
    now: str | None = None,
) -> ProviderInstallationVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if manifest.get("schema") != PROVIDER_INSTALLATION_SCHEMA:
        errors.append(f"unsupported provider installation schema: {manifest.get('schema')}")
    body = without_keys(manifest, "manifest_id", "signatures")
    expected_id = content_hash(body)
    if manifest.get("manifest_id") != expected_id:
        errors.append("manifest_id does not match canonical provider installation body")

    signatures = manifest.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider installation manifest must include at least one signature")
    else:
        signed_value = {"manifest_id": manifest.get("manifest_id"), "provider_installation": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider installation signature verification failed")

    try:
        provider = _normalize_provider(manifest.get("provider"), allow_none=True)
    except ValueError as exc:
        errors.append(str(exc))
        provider = None
    if provider is None:
        errors.append("provider installation provider is required")
    mode = manifest.get("mode")
    if mode not in INSTALLATION_MODES:
        errors.append("provider installation mode is unsupported")
    elif mode == "local-reference":
        warnings.append("provider installation is a local-reference manifest; no provider OAuth completion is claimed")

    installed_at = manifest.get("installed_at")
    try:
        installed = parse_rfc3339(str(installed_at or ""))
    except ValueError as exc:
        errors.append(f"provider installation installed_at invalid: {exc}")
        installed = None
    expires_at = manifest.get("expires_at")
    if expires_at:
        try:
            expires = parse_rfc3339(str(expires_at))
            if installed and expires <= installed:
                errors.append("provider installation expires_at must be after installed_at")
            if now and expires <= parse_rfc3339(now):
                errors.append("provider installation has expired")
        except ValueError as exc:
            errors.append(f"provider installation expires_at invalid: {exc}")

    app = manifest.get("app", {})
    if not isinstance(app, dict) or not app.get("app_ref"):
        errors.append("provider installation app.app_ref is required")
    installation = manifest.get("installation", {})
    if not isinstance(installation, dict):
        errors.append("provider installation installation must be an object")
        installation = {}
    for field in ("installation_ref", "tenant_ref"):
        if not installation.get(field):
            errors.append(f"provider installation installation.{field} is required")

    capabilities = manifest.get("capabilities", {})
    if not isinstance(capabilities, dict):
        errors.append("provider installation capabilities must be an object")
        capabilities = {}
    permissions = capabilities.get("permissions", [])
    scopes = capabilities.get("scopes", [])
    events = capabilities.get("events", [])
    if not _is_string_list(permissions) or not _is_string_list(scopes) or not _is_string_list(events):
        errors.append("provider installation permissions, scopes, and events must be string arrays")
    elif not permissions and not scopes:
        errors.append("provider installation requires at least one permission or scope")
    if not _is_string_list(events) or not events:
        errors.append("provider installation requires at least one subscribed event")

    webhook = manifest.get("webhook", {})
    if not isinstance(webhook, dict):
        errors.append("provider installation webhook must be an object")
        webhook = {}
    webhook_url = webhook.get("url")
    if webhook_url:
        if not _valid_url(str(webhook_url)):
            errors.append("provider installation webhook.url must be an absolute URL")
        elif not _is_https(str(webhook_url)):
            warnings.append("provider installation webhook.url is not HTTPS")
    elif "webhook" in events or any(str(event).startswith("check_") for event in events):
        warnings.append("provider installation does not include a webhook URL for subscribed callback events")
    if webhook.get("secret") is not None:
        _verify_redacted_ref(webhook.get("secret"), "provider installation webhook.secret", errors)

    callback_url = webhook.get("callback_url")
    if callback_url and not _valid_url(str(callback_url)):
        errors.append("provider installation webhook.callback_url must be an absolute URL")

    if manifest.get("credential") is not None:
        _verify_redacted_ref(manifest.get("credential"), "provider installation credential", errors)

    audit_log = manifest.get("audit_log", {})
    if not isinstance(audit_log, dict):
        errors.append("provider installation audit_log must be an object")
        audit_log = {}
    if audit_log.get("scopes") and not _is_string_list(audit_log.get("scopes")):
        errors.append("provider installation audit_log.scopes must be a string array")
    if audit_log.get("ref") and not audit_log.get("scopes"):
        warnings.append("provider installation has an audit_log ref without audit_log scopes")

    controls = manifest.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("provider installation controls are required")

    _check_no_secret_values(manifest, errors)

    return ProviderInstallationVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_installation_manifest(
    chain: EvidenceChain,
    manifest: dict[str, Any],
    *,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_installation_manifest(manifest, key=key)
    if not result.ok:
        raise ValueError("invalid provider installation manifest: " + "; ".join(result.errors))
    payload = {
        "manifest_id": manifest["manifest_id"],
        "manifest_hash": content_hash(manifest),
        "provider": manifest.get("provider"),
        "mode": manifest.get("mode"),
        "installed_at": manifest.get("installed_at"),
        "expires_at": manifest.get("expires_at"),
        "app": manifest.get("app"),
        "installation": manifest.get("installation"),
        "capabilities": manifest.get("capabilities"),
        "webhook": without_keys(manifest.get("webhook", {}), "secret") if isinstance(manifest.get("webhook"), dict) else {},
        "audit_log": manifest.get("audit_log"),
        "control_summary": _control_summary(manifest.get("controls", [])),
    }
    return chain.append(PROVIDER_INSTALLATION_ENTRY_TYPE, payload, key=key, timestamp=manifest.get("installed_at"))


def load_provider_installation_manifest(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider installation manifest must contain an object")
    return value


def write_provider_installation_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def _normalize_provider(provider: Any, *, allow_none: bool = False) -> str | None:
    if provider is None and allow_none:
        return None
    normalized = str(provider or "").strip().lower()
    if normalized not in SUPPORTED_PROVIDERS:
        if allow_none and not normalized:
            return None
        raise ValueError(f"unsupported provider installation provider: {provider}")
    return normalized


def _require_text(value: str | None, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _normalized_list(values: list[str] | None) -> list[str]:
    if not values:
        return []
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def _is_https(value: str | None) -> bool:
    return bool(value and urlparse(value).scheme.lower() == "https")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def _check_no_secret_values(value: Any, errors: list[str], *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in ("token", "secret", "private_key", "client_secret")):
                if not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"provider installation secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")


def _controls(
    *,
    mode: str,
    webhook_url: str | None,
    callback_url: str | None,
    secret_ref: str | None,
    credential_ref: str | None,
    audit_log_ref: str | None,
    audit_log_scopes: list[str] | None,
) -> list[dict[str, Any]]:
    return [
        {
            "id": "provider-app-installed",
            "status": "implemented" if mode != "local-reference" else "local-reference",
            "description": "Provider app or OAuth installation is recorded with app, installation, and tenant references.",
        },
        {
            "id": "redacted-provider-credentials",
            "status": "implemented" if secret_ref or credential_ref else "planned-production",
            "description": "Webhook secrets and provider credentials are represented only by redacted references.",
        },
        {
            "id": "public-callback-ingress",
            "status": "implemented" if webhook_url and _is_https(webhook_url) else "planned-production",
            "description": "Provider webhook and callback URLs are absolute HTTPS ingress endpoints.",
        },
        {
            "id": "provider-audit-log-access",
            "status": "implemented" if audit_log_ref and audit_log_scopes else "planned-production",
            "description": "Installation includes provider audit-log reference and scopes for later audit correlation.",
        },
        {
            "id": "callback-response-path",
            "status": "implemented" if callback_url else "planned-production",
            "description": "Installation records callback response URL for provider-hosted approval or status interactions.",
        },
    ]


def _control_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls if isinstance(controls, list) else []:
        if isinstance(control, dict):
            status = str(control.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))
