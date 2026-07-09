from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain
from .contracts import load_contract
from .crypto import sign_value, verify_value
from .policy import load_policy_pack

MARKETPLACE_SCHEMA = "trustai.marketplace-catalog/0.1"
MARKETPLACE_DISTRIBUTION_SCHEMA = "trustai.marketplace-distribution/0.1"
MARKETPLACE_DISTRIBUTION_ENTRY_TYPE = "marketplace.distribution.published"

CONTRACT_TEMPLATE_TYPE = "verification_contract_template"
POLICY_PACK_TYPE = "policy_pack"
SUPPORTED_ASSET_TYPES = {CONTRACT_TEMPLATE_TYPE, POLICY_PACK_TYPE}


@dataclass
class MarketplaceDistributionVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class MarketplaceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    asset_count: int = 0


def build_marketplace_catalog(
    *,
    root: str | Path = ".",
    contract_templates: list[str | Path] | None = None,
    policy_packs: list[str | Path] | None = None,
    publisher: str = "trustai-local",
    author: str = "trustai-local",
    verticals: list[str] | None = None,
    regulations: list[str] | None = None,
    status: str = "draft",
) -> dict[str, Any]:
    contract_templates = contract_templates or []
    policy_packs = policy_packs or []
    if not contract_templates and not policy_packs:
        raise ValueError("at least one contract template or policy pack is required")

    root_path = Path(root)
    metadata = {
        "publisher": publisher,
        "author": author,
        "verticals": sorted(set(verticals or [])),
        "regulations": sorted(set(regulations or [])),
        "status": status,
    }
    assets = [
        _contract_asset(root_path, path, metadata)
        for path in contract_templates
    ] + [
        _policy_asset(root_path, path, metadata)
        for path in policy_packs
    ]
    body = {
        "schema": MARKETPLACE_SCHEMA,
        "generated_at": utc_now(),
        "publisher": publisher,
        "status": status,
        "certification_model": {
            "method": "local-hash-and-schema-validation",
            "checks": [
                "asset schema validates",
                "asset content hash matches worktree source",
                "asset has vertical and regulation metadata",
                "catalog id matches canonical body",
            ],
        },
        "assets": assets,
        "aggregate": _aggregate(assets),
        "limitations": [
            "Local marketplace catalog only; no hosted listing, billing, revocation, or third-party author workflow is claimed.",
            "Certification means local schema and hash verification, not independent external endorsement.",
        ],
    }
    return {**body, "catalog_id": content_hash(body)}


def verify_marketplace_catalog(catalog: dict[str, Any], *, root: str | Path = ".") -> MarketplaceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if catalog.get("schema") != MARKETPLACE_SCHEMA:
        errors.append(f"unsupported marketplace schema: {catalog.get('schema')}")
    body = without_keys(catalog, "catalog_id")
    if catalog.get("catalog_id") != content_hash(body):
        errors.append("catalog_id does not match canonical catalog body")

    assets = catalog.get("assets", [])
    if not isinstance(assets, list) or not assets:
        errors.append("marketplace catalog must include assets")
        assets = []

    seen_ids: set[str] = set()
    root_path = Path(root)
    for asset in assets:
        if not isinstance(asset, dict):
            errors.append("marketplace asset must be an object")
            continue
        asset_id = asset.get("asset_id")
        if not asset_id:
            errors.append("marketplace asset missing asset_id")
        elif asset_id in seen_ids:
            errors.append(f"duplicate marketplace asset id: {asset_id}")
        else:
            seen_ids.add(asset_id)

        asset_type = asset.get("type")
        if asset_type not in SUPPORTED_ASSET_TYPES:
            errors.append(f"unsupported marketplace asset type: {asset_type}")
            continue
        if not asset.get("verticals"):
            errors.append(f"asset {asset_id or asset.get('path')} missing vertical metadata")
        if not asset.get("regulations"):
            errors.append(f"asset {asset_id or asset.get('path')} missing regulation metadata")

        try:
            loaded = _load_asset(root_path, asset)
        except Exception as exc:  # ValueError from validation includes the useful reason.
            errors.append(f"asset {asset_id or asset.get('path')} invalid: {exc}")
            continue

        if asset.get("content_hash") != content_hash(loaded):
            errors.append(f"asset {asset_id or asset.get('path')} content_hash mismatch")
        expected_id = _asset_id(asset_type, asset.get("path"), asset.get("content_hash"))
        if asset_id != expected_id:
            errors.append(f"asset {asset.get('path')} asset_id mismatch")

        if asset.get("spec_version") != loaded.get("spec_version"):
            errors.append(f"asset {asset_id} spec_version mismatch")
        if asset.get("id") != loaded.get("id"):
            errors.append(f"asset {asset_id} id mismatch")
        if asset.get("version") != loaded.get("version"):
            errors.append(f"asset {asset_id} version mismatch")

    expected_aggregate = _aggregate([asset for asset in assets if isinstance(asset, dict)])
    if catalog.get("aggregate") != expected_aggregate:
        errors.append("aggregate does not match marketplace assets")
    if catalog.get("status") != "published":
        warnings.append(f"marketplace catalog status is {catalog.get('status')}")

    return MarketplaceVerification(ok=not errors, errors=errors, warnings=warnings, asset_count=len(assets))



def build_marketplace_distribution(
    catalog: dict[str, Any],
    *,
    root: str | Path = ".",
    channel: str = "local-marketplace",
    target: str = "local-catalog",
    mode: str = "local-reference",
    subscriber: str = "local-subscriber",
    subscriber_ref: str | None = None,
    purpose: str = "certified template and policy-pack distribution",
    selected_asset_ids: list[str] | None = None,
    distributed_at: str | None = None,
    distribution_ref: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_marketplace_catalog(catalog, root=root)
    if not result.ok:
        raise ValueError("invalid marketplace catalog: " + "; ".join(result.errors))
    if mode not in {"local-reference", "recorded-publication"}:
        raise ValueError("mode must be local-reference or recorded-publication")
    selected_assets = _distribution_assets(catalog, selected_asset_ids)
    if not selected_assets:
        raise ValueError("at least one marketplace asset must be distributed")
    issued = distributed_at or utc_now()
    catalog_binding = _catalog_binding(catalog)
    body = {
        "schema": MARKETPLACE_DISTRIBUTION_SCHEMA,
        "distributed_at": issued,
        "distribution_ref": distribution_ref or _distribution_ref(catalog_binding, channel, target, issued),
        "mode": mode,
        "channel": {
            "type": channel,
            "target": target,
            "production_replacement": "hosted marketplace publication, subscriber install, or partner-channel delivery event",
        },
        "subscriber": {
            "organization": subscriber,
            "subject_ref": subscriber_ref,
            "purpose": purpose,
        },
        "catalog": catalog_binding,
        "assets": selected_assets,
        "terms": {
            "redistribution": "not granted by local-reference receipt",
            "revocation": "production marketplace should publish signed catalog and asset revocation state",
            "billing": "not claimed by local-reference receipt",
        },
        "limitations": [
            "This is a local signed marketplace distribution receipt over a verified catalog.",
            "It does not claim hosted marketplace publication, billing, entitlement checks, or third-party author payout workflow.",
            "Production deployments should replace local channel metadata with authenticated marketplace delivery records.",
        ],
    }
    distribution_id = content_hash(body)
    return {
        **body,
        "distribution_id": distribution_id,
        "signatures": [sign_value({"distribution_id": distribution_id, "distribution": body}, key)],
    }


def verify_marketplace_distribution(
    distribution: dict[str, Any],
    *,
    catalog: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> MarketplaceDistributionVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if distribution.get("schema") != MARKETPLACE_DISTRIBUTION_SCHEMA:
        errors.append(f"unsupported marketplace distribution schema: {distribution.get('schema')}")
    body = without_keys(distribution, "distribution_id", "signatures")
    if distribution.get("distribution_id") != content_hash(body):
        errors.append("distribution_id does not match canonical distribution body")
    signatures = distribution.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("marketplace distribution missing signature")
    else:
        signed_value = {"distribution_id": distribution.get("distribution_id"), "distribution": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("marketplace distribution signature invalid")

    if distribution.get("mode") not in {"local-reference", "recorded-publication"}:
        errors.append("marketplace distribution mode must be local-reference or recorded-publication")
    channel_info = distribution.get("channel", {})
    if not isinstance(channel_info, dict) or not channel_info.get("type") or not channel_info.get("target"):
        errors.append("marketplace distribution channel type and target are required")
    subscriber = distribution.get("subscriber", {})
    if not isinstance(subscriber, dict) or not subscriber.get("organization"):
        errors.append("marketplace distribution subscriber organization is required")
    assets = distribution.get("assets", [])
    if not isinstance(assets, list) or not assets:
        errors.append("marketplace distribution must include distributed assets")
        assets = []
    seen: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            errors.append("distributed asset must be an object")
            continue
        asset_id = asset.get("asset_id")
        if not asset_id:
            errors.append("distributed asset missing asset_id")
        elif asset_id in seen:
            errors.append(f"duplicate distributed asset id: {asset_id}")
        else:
            seen.add(asset_id)
        if asset.get("type") not in SUPPORTED_ASSET_TYPES:
            errors.append(f"unsupported distributed asset type: {asset.get('type')}")
        if not asset.get("content_hash"):
            errors.append(f"distributed asset {asset_id or asset.get('path')} missing content_hash")

    if catalog is None:
        warnings.append("source marketplace catalog not supplied; verified distribution binding only")
    else:
        catalog_result = verify_marketplace_catalog(catalog, root=root)
        if not catalog_result.ok:
            errors.extend(f"source catalog invalid: {error}" for error in catalog_result.errors)
        warnings.extend(f"source catalog: {warning}" for warning in catalog_result.warnings)
        if distribution.get("catalog") != _catalog_binding(catalog):
            errors.append("marketplace distribution catalog binding mismatch")
        selected_ids = [asset.get("asset_id") for asset in assets if isinstance(asset, dict) and asset.get("asset_id")]
        if assets != _distribution_assets(catalog, selected_ids):
            errors.append("marketplace distribution assets do not match source catalog")
    return MarketplaceDistributionVerification(ok=not errors, errors=errors, warnings=warnings)


def append_marketplace_distribution(
    chain: EvidenceChain,
    distribution: dict[str, Any],
    *,
    catalog: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_marketplace_distribution(distribution, catalog=catalog, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid marketplace distribution: " + "; ".join(result.errors))
    payload = {
        "distribution_id": distribution["distribution_id"],
        "distribution_hash": content_hash(distribution),
        "distribution_ref": distribution.get("distribution_ref"),
        "mode": distribution.get("mode"),
        "channel": distribution.get("channel"),
        "subscriber": distribution.get("subscriber"),
        "catalog": distribution.get("catalog"),
        "assets": distribution.get("assets"),
        "terms": distribution.get("terms"),
        "limitations": distribution.get("limitations", []),
    }
    return chain.append(MARKETPLACE_DISTRIBUTION_ENTRY_TYPE, payload, key=key, timestamp=distribution.get("distributed_at"))


def load_marketplace_distribution(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("marketplace distribution must contain an object")
    return value


def write_marketplace_distribution(path: str | Path, distribution: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(distribution, indent=2, sort_keys=True), encoding="utf-8")

def write_marketplace_catalog(path: str | Path, catalog: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(catalog, indent=2, sort_keys=True), encoding="utf-8")


def write_marketplace_markdown(path: str | Path, catalog: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_marketplace_markdown(catalog), encoding="utf-8")


def render_marketplace_markdown(catalog: dict[str, Any]) -> str:
    assets = "\n".join(
        f"- `{asset.get('type')}` `{asset.get('id')}@{asset.get('version')}`: "
        f"{asset.get('path')} (`{asset.get('asset_id')}`)"
        for asset in catalog.get("assets", [])
    )
    aggregate = json.dumps(catalog.get("aggregate", {}), indent=2, sort_keys=True)
    return f"""# TrustAI Marketplace Catalog

Catalog ID: `{catalog.get('catalog_id', '')}`

Publisher: {catalog.get('publisher', '')}

Status: {catalog.get('status', '')}

## Assets

{assets}

## Aggregate

```json
{aggregate}
```
"""


def load_marketplace_catalog(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))



def _catalog_binding(catalog: dict[str, Any]) -> dict[str, Any]:
    assets = catalog.get("assets", [])
    return {
        "catalog_id": catalog.get("catalog_id"),
        "catalog_hash": content_hash(catalog),
        "schema": catalog.get("schema"),
        "publisher": catalog.get("publisher"),
        "status": catalog.get("status"),
        "asset_count": len(assets) if isinstance(assets, list) else 0,
        "aggregate": catalog.get("aggregate"),
    }


def _distribution_assets(catalog: dict[str, Any], selected_asset_ids: list[str] | None) -> list[dict[str, Any]]:
    assets = [asset for asset in catalog.get("assets", []) if isinstance(asset, dict)]
    if selected_asset_ids:
        selected = set(selected_asset_ids)
        missing = selected - {asset.get("asset_id") for asset in assets}
        if missing:
            raise ValueError(f"selected marketplace assets not found: {', '.join(sorted(missing))}")
        assets = [asset for asset in assets if asset.get("asset_id") in selected]
    return [
        {
            "asset_id": asset.get("asset_id"),
            "type": asset.get("type"),
            "path": asset.get("path"),
            "id": asset.get("id"),
            "version": asset.get("version"),
            "publisher": asset.get("publisher"),
            "author": asset.get("author"),
            "verticals": asset.get("verticals", []),
            "regulations": asset.get("regulations", []),
            "risk_class": asset.get("risk_class"),
            "content_hash": asset.get("content_hash"),
            "certification": asset.get("certification"),
        }
        for asset in assets
    ]


def _distribution_ref(catalog_binding: dict[str, Any], channel: str, target: str, distributed_at: str) -> str:
    digest = content_hash({"catalog": catalog_binding, "channel": channel, "target": target, "distributed_at": distributed_at})
    return f"trustai-marketplace-{digest[:16]}"

def _contract_asset(root: Path, path: str | Path, metadata: dict[str, Any]) -> dict[str, Any]:
    full_path, relative = _paths(root, path)
    contract = load_contract(full_path)
    agent = contract.get("agent", {})
    return _asset_record(
        CONTRACT_TEMPLATE_TYPE,
        relative,
        contract,
        metadata,
        risk_class=agent.get("risk_class"),
        title=contract.get("id"),
        summary={
            "agent_framework": agent.get("framework"),
            "metric_count": len(contract.get("metrics", [])),
            "required_approval_roles": [
                approval.get("role")
                for approval in contract.get("required_approvals", [])
                if isinstance(approval, dict) and approval.get("role")
            ],
            "framework_controls": contract.get("framework_controls", []),
        },
    )


def _policy_asset(root: Path, path: str | Path, metadata: dict[str, Any]) -> dict[str, Any]:
    full_path, relative = _paths(root, path)
    policy = load_policy_pack(full_path)
    return _asset_record(
        POLICY_PACK_TYPE,
        relative,
        policy,
        metadata,
        risk_class=policy.get("risk_class"),
        title=policy.get("description") or policy.get("id"),
        summary={
            "rule_count": len(policy.get("rules", [])),
            "proof_decay_keys": sorted(policy.get("proof_decay", {}).keys()),
            "effects": sorted({rule.get("effect", "deny") for rule in policy.get("rules", []) if isinstance(rule, dict)}),
        },
    )


def _asset_record(
    asset_type: str,
    path: str,
    body: dict[str, Any],
    metadata: dict[str, Any],
    *,
    risk_class: str | None,
    title: str | None,
    summary: dict[str, Any],
) -> dict[str, Any]:
    digest = content_hash(body)
    return {
        "asset_id": _asset_id(asset_type, path, digest),
        "type": asset_type,
        "path": path,
        "id": body.get("id"),
        "version": body.get("version"),
        "spec_version": body.get("spec_version"),
        "title": title,
        "publisher": metadata["publisher"],
        "author": metadata["author"],
        "status": metadata["status"],
        "verticals": metadata["verticals"],
        "regulations": metadata["regulations"],
        "risk_class": risk_class,
        "content_hash": digest,
        "summary": summary,
        "certification": {
            "status": "certified-local",
            "method": "schema-validation-and-content-hash",
            "checked_at": utc_now(),
        },
    }


def _load_asset(root: Path, asset: dict[str, Any]) -> dict[str, Any]:
    path = root / asset.get("path", "")
    if asset.get("type") == CONTRACT_TEMPLATE_TYPE:
        return load_contract(path)
    if asset.get("type") == POLICY_PACK_TYPE:
        return load_policy_pack(path)
    raise ValueError(f"unsupported asset type: {asset.get('type')}")


def _asset_id(asset_type: str | None, path: str | None, digest: str | None) -> str:
    return content_hash({"type": asset_type, "path": path, "content_hash": digest})


def _paths(root: Path, path: str | Path) -> tuple[Path, str]:
    source = Path(path)
    full_path = source if source.is_absolute() else root / source
    if source.is_absolute():
        try:
            relative = source.relative_to(root.resolve()).as_posix()
        except ValueError:
            relative = source.as_posix()
    else:
        relative = source.as_posix()
    return full_path, relative


def _aggregate(assets: list[dict[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_vertical: dict[str, int] = {}
    by_regulation: dict[str, int] = {}
    for asset in assets:
        asset_type = asset.get("type") or "unknown"
        by_type[asset_type] = by_type.get(asset_type, 0) + 1
        for vertical in asset.get("verticals", []):
            by_vertical[vertical] = by_vertical.get(vertical, 0) + 1
        for regulation in asset.get("regulations", []):
            by_regulation[regulation] = by_regulation.get(regulation, 0) + 1
    return {
        "asset_count": len(assets),
        "by_type": by_type,
        "by_vertical": by_vertical,
        "by_regulation": by_regulation,
    }
