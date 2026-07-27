from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .compliance import CONTROL_CATALOG, build_compliance_export
from .crypto import sign_value, verify_value
from .eu_ai_act import verify_eu_ai_act_document
from .eu_data_plane import verify_eu_data_plane_attestation
from .external_evidence import AUTHORITY_KINDS

COMPLIANCE_AUTHORITY_SCHEMA = "trustai.compliance-production-authority-dossier/0.1"
COMPLIANCE_AUTHORITY_ENTRY_TYPE = "compliance.production_authority_recorded"
COMPLIANCE_AUTHORITY_MODES = {"local-dossier", "provider-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

REQUIRED_FRAMEWORKS = tuple(CONTROL_CATALOG.keys())
PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {"id": "framework-control-mapping-ontology", "title": "Versioned framework-control ontology for ISO 42001, NIST AI RMF, EU AI Act, SR 11-7, and SOC 2", "authority_kinds": ["standards-body", "customer", "ci-run"]},
    {"id": "iso-42001-evidence-package", "title": "ISO 42001 evidence package accepted by the customer GRC workflow", "authority_kinds": ["customer", "provider-api", "hosted-service"]},
    {"id": "nist-ai-rmf-evidence-package", "title": "NIST AI RMF evidence package and reviewer mapping export", "authority_kinds": ["customer", "provider-api", "hosted-service"]},
    {"id": "eu-ai-act-technical-documentation", "title": "EU AI Act Annex III technical documentation and conformity-assessment support package", "authority_kinds": ["regulator", "customer", "hosted-service"]},
    {"id": "sr-11-7-validation-report", "title": "SR 11-7 model-risk validation report generated from proof-pack evidence", "authority_kinds": ["customer", "provider-api", "hosted-service"]},
    {"id": "soc2-evidence-export", "title": "SOC 2 change-management, monitoring, and logical-access evidence export", "authority_kinds": ["customer", "provider-api", "hosted-service"]},
    {"id": "proof-pack-source-replay", "title": "Offline proof-pack source replay for every framework mapping", "authority_kinds": ["ci-run", "customer"]},
    {"id": "regulator-disclosure-selective-proof", "title": "Selective-disclosure package with Merkle proofs for regulator or supervisor review", "authority_kinds": ["regulator", "customer"]},
    {"id": "grc-platform-export", "title": "Vanta/Drata or customer GRC platform export package and delivery evidence", "authority_kinds": ["provider-api", "customer", "hosted-service"]},
    {"id": "eu-data-plane-sovereignty-binding", "title": "EU data-plane sovereignty binding for EU AI Act documentation sources", "authority_kinds": ["provider-api", "customer", "hosted-service"]},
    {"id": "conformity-assessment-review", "title": "Human conformity-assessment review, sign-off, or regulator/supervisor acceptance evidence", "authority_kinds": ["regulator", "customer", "standards-body"]},
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class ComplianceAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_compliance_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("compliance authority dossier must contain an object")
    return value


def write_compliance_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_compliance_authority_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 4)
    if len(parts) != 5:
        raise ValueError("authority evidence must be requirement_id,authority_kind,evidence_ref,evidence_hash,description[;key=value...]")
    requirement_id, authority_kind, evidence_ref, evidence_hash, description = [part.strip() for part in parts]
    description_parts = [part.strip() for part in description.split(";")]
    metadata: dict[str, Any] = {}
    allowed_metadata = {"issuer", "subject", "source_uri", "issued_at", "expires_at"}
    for token in description_parts[1:]:
        if not token:
            continue
        if "=" not in token:
            raise ValueError("authority evidence metadata must be key=value")
        key, metadata_value = [part.strip() for part in token.split("=", 1)]
        if key not in allowed_metadata:
            raise ValueError(f"unsupported authority evidence metadata key: {key}")
        metadata[key] = metadata_value
    return {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description_parts[0],
        **metadata,
    }


def build_compliance_authority_dossier(
    compliance_export: dict[str, Any],
    eu_ai_act_document: dict[str, Any],
    *,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    eu_data_plane: dict[str, Any] | None = None,
    mode: str = "provider-dossier",
    environment: str = "local",
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in COMPLIANCE_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(COMPLIANCE_AUTHORITY_MODES)}")
    for value, field in ((environment, "environment"), (dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)

    export_errors = _verify_compliance_export_source(compliance_export, proof_pack)
    if export_errors:
        raise ValueError("invalid compliance export source: " + "; ".join(export_errors))
    document_result = verify_eu_ai_act_document(eu_ai_act_document, proof_pack=proof_pack, regulator_disclosure=regulator_disclosure, key=key)
    if not document_result.ok:
        raise ValueError("invalid EU AI Act document source: " + "; ".join(document_result.errors))
    if eu_data_plane is not None:
        data_plane_result = verify_eu_data_plane_attestation(eu_data_plane, eu_ai_act_document=eu_ai_act_document, key=key)
        if not data_plane_result.ok:
            raise ValueError("invalid EU data-plane source: " + "; ".join(data_plane_result.errors))

    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    binding = _source_binding(compliance_export, eu_ai_act_document, proof_pack, regulator_disclosure, eu_data_plane)
    source_context = _authority_evidence_source_context(binding)
    evidence_items = [_build_authority_evidence_item(item, source_context) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body: dict[str, Any] = {
        "schema": COMPLIANCE_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment,
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "source_binding": binding,
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, binding, evidence_items, summary),
        "limitations": [
            "This dossier binds compliance framework mappings and EU AI Act technical documentation to production-authority evidence for third-party compliance consumption.",
            "It records framework coverage, proof-pack source replay, regulator disclosure, EU data-plane sovereignty, freshness windows, and missing live-authority categories.",
            "It does not claim regulator acceptance, conformity assessment, GRC-platform acceptance, or live EU production operation unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    signed_value = {"dossier_id": dossier_id, "compliance_authority": body}
    return {**body, "dossier_id": dossier_id, "signatures": [sign_value(signed_value, key)]}


def verify_compliance_authority_dossier(
    dossier: dict[str, Any],
    *,
    compliance_export: dict[str, Any] | None = None,
    eu_ai_act_document: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    eu_data_plane: dict[str, Any] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> ComplianceAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != COMPLIANCE_AUTHORITY_SCHEMA:
        errors.append(f"unsupported compliance authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical compliance authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("compliance authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "compliance_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("compliance authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in COMPLIANCE_AUTHORITY_MODES:
        errors.append("compliance authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"compliance authority mode is {mode}; live compliance production authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"compliance authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"compliance authority {field} is required")

    _verify_source_binding(
        dossier.get("source_binding"),
        compliance_export,
        eu_ai_act_document,
        proof_pack,
        regulator_disclosure,
        eu_data_plane,
        errors,
        warnings,
        key=key,
    )
    _verify_required_authority(dossier.get("required_production_authority"), errors)

    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("compliance authority authority_evidence must be a list")
        evidence = []
    evidence_source_context = _authority_evidence_source_context(
        dossier.get("source_binding") if isinstance(dossier.get("source_binding"), dict) else {}
    )
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("compliance authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        status = _verify_authority_evidence_item(
            item,
            errors,
            warnings,
            now=freshness_now,
            require_fresh=require_fresh,
            source_context=evidence_source_context,
        )
        freshness_counts[status] += 1

    evidence_dicts = [item for item in evidence if isinstance(item, dict)]
    expected_summary = _summary(evidence_dicts)
    if dossier.get("summary") != expected_summary:
        errors.append("compliance authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("compliance authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("compliance authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every compliance authority requirement to be covered")
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("production-dossier mode requires every compliance authority evidence item to be fresh")
    binding_for_controls = dossier.get("source_binding") if isinstance(dossier.get("source_binding"), dict) else {}
    if mode == "production-dossier" and not _source_binding_complete(binding_for_controls):
        errors.append("production-dossier mode requires compliance export, EU AI Act document, proof-pack, regulator disclosure, and EU data-plane bindings")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("compliance authority controls are required")
    elif dossier.get("controls") != _controls(str(mode), binding_for_controls, evidence_dicts, expected_summary):
        errors.append("compliance authority controls do not match dossier body")
    _check_no_secret_values(dossier, errors)

    return ComplianceAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_compliance_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    compliance_export: dict[str, Any],
    eu_ai_act_document: dict[str, Any],
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    eu_data_plane: dict[str, Any] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_compliance_authority_dossier(
        dossier,
        compliance_export=compliance_export,
        eu_ai_act_document=eu_ai_act_document,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        eu_data_plane=eu_data_plane,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid compliance authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "source_binding": dossier.get("source_binding"),
        "summary": dossier.get("summary"),
        "control_summary": _status_summary(dossier.get("controls", [])),
        "authority_evidence": [
            {
                "requirement_id": item.get("requirement_id"),
                "authority_kind": item.get("authority_kind"),
                "evidence_ref": item.get("evidence_ref"),
                "evidence_hash": item.get("evidence_hash"),
                "evidence_id": item.get("evidence_id"),
                "issued_at": item.get("issued_at"),
                "expires_at": item.get("expires_at"),
                "source_context": item.get("source_context"),
            }
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(COMPLIANCE_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _source_binding(
    compliance_export: dict[str, Any],
    eu_ai_act_document: dict[str, Any],
    proof_pack: dict[str, Any] | None,
    regulator_disclosure: dict[str, Any] | None,
    eu_data_plane: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "compliance_export": _compliance_export_binding(compliance_export),
        "eu_ai_act_document": _eu_ai_act_binding(eu_ai_act_document),
        "proof_pack": _proof_pack_binding(proof_pack) if proof_pack else None,
        "regulator_disclosure": _regulator_binding(regulator_disclosure) if regulator_disclosure else None,
        "eu_data_plane": _eu_data_plane_binding(eu_data_plane) if eu_data_plane else None,
    }


def _compliance_export_binding(export: dict[str, Any]) -> dict[str, Any]:
    mappings = export.get("mappings", []) if isinstance(export, dict) else []
    frameworks = [str(item.get("framework")) for item in mappings if isinstance(item, dict) and item.get("framework")]
    return {
        "schema": export.get("schema"),
        "export_hash": content_hash(export),
        "pack_id": export.get("pack_id"),
        "issued_at": export.get("issued_at"),
        "frameworks": sorted(frameworks),
        "framework_count": len(frameworks),
        "required_frameworks": list(REQUIRED_FRAMEWORKS),
        "missing_frameworks": [framework for framework in REQUIRED_FRAMEWORKS if framework not in frameworks],
        "control_count": sum(len(item.get("controls", [])) for item in mappings if isinstance(item, dict)),
        "chain_roots": sorted({str(item.get("chain_root")) for item in mappings if isinstance(item, dict) and item.get("chain_root")}),
    }


def _eu_ai_act_binding(document: dict[str, Any]) -> dict[str, Any]:
    sections = document.get("sections", []) if isinstance(document, dict) else []
    source = document.get("source_artifacts", {}) if isinstance(document, dict) else {}
    proof_pack = source.get("proof_pack", {}) if isinstance(source.get("proof_pack"), dict) else {}
    disclosure = source.get("regulator_disclosure", {}) if isinstance(source.get("regulator_disclosure"), dict) else {}
    return {
        "document_id": document.get("document_id"),
        "document_hash": content_hash(document),
        "schema": document.get("schema"),
        "issued_at": document.get("issued_at"),
        "section_ids": [str(section.get("id")) for section in sections if isinstance(section, dict)],
        "section_count": len(sections),
        "source_proof_pack_id": proof_pack.get("pack_id"),
        "source_regulator_disclosure_id": disclosure.get("disclosure_id"),
    }


def _proof_pack_binding(pack: dict[str, Any]) -> dict[str, Any]:
    return {
        "pack_id": pack.get("pack_id"),
        "pack_hash": content_hash(pack),
        "spec_version": pack.get("spec_version"),
        "issued_at": pack.get("issued_at"),
        "chain_root": pack.get("chain", {}).get("tree", {}).get("root"),
        "entry_count": len(pack.get("chain", {}).get("entries", [])),
    }


def _regulator_binding(disclosure: dict[str, Any]) -> dict[str, Any]:
    selection = disclosure.get("selection", {}) if isinstance(disclosure, dict) else {}
    return {
        "disclosure_id": disclosure.get("disclosure_id"),
        "disclosure_hash": content_hash(disclosure),
        "schema": disclosure.get("schema"),
        "issued_at": disclosure.get("issued_at"),
        "disclosed_entry_count": selection.get("disclosed_entry_count") if isinstance(selection, dict) else None,
    }


def _eu_data_plane_binding(attestation: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(attestation, dict):
        return None
    return {
        "attestation_id": attestation.get("attestation_id"),
        "attestation_hash": content_hash(attestation),
        "schema": attestation.get("schema"),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "regions": attestation.get("regions"),
        "residency": {
            "tenant_id": attestation.get("residency", {}).get("tenant_id") if isinstance(attestation.get("residency"), dict) else None,
            "data_plane_ref": attestation.get("residency", {}).get("data_plane_ref") if isinstance(attestation.get("residency"), dict) else None,
            "customer_account_ref": attestation.get("residency", {}).get("customer_account_ref") if isinstance(attestation.get("residency"), dict) else None,
        },
        "control_summary": _status_summary(attestation.get("controls", [])),
    }


def _verify_source_binding(
    binding: Any,
    compliance_export: dict[str, Any] | None,
    eu_ai_act_document: dict[str, Any] | None,
    proof_pack: dict[str, Any] | None,
    regulator_disclosure: dict[str, Any] | None,
    eu_data_plane: dict[str, Any] | None,
    errors: list[str],
    warnings: list[str],
    *,
    key: str | None,
) -> None:
    if not isinstance(binding, dict):
        errors.append("compliance authority source_binding is required")
        return
    _verify_binding_completeness(binding, errors)
    if compliance_export is None:
        warnings.append("compliance authority compliance export source was not supplied; export binding hashes were not replayed")
        return
    errors.extend(_verify_compliance_export_source(compliance_export, proof_pack))
    if eu_ai_act_document is None:
        warnings.append("compliance authority EU AI Act document source was not supplied; document binding hashes were not replayed")
        return
    document_result = verify_eu_ai_act_document(eu_ai_act_document, proof_pack=proof_pack, regulator_disclosure=regulator_disclosure, key=key)
    errors.extend(f"compliance authority EU AI Act source: {error}" for error in document_result.errors)
    warnings.extend(f"compliance authority EU AI Act source: {warning}" for warning in document_result.warnings)
    if eu_data_plane is not None:
        data_plane_result = verify_eu_data_plane_attestation(eu_data_plane, eu_ai_act_document=eu_ai_act_document, key=key)
        errors.extend(f"compliance authority EU data-plane source: {error}" for error in data_plane_result.errors)
        warnings.extend(f"compliance authority EU data-plane source: {warning}" for warning in data_plane_result.warnings)
    elif isinstance(binding.get("eu_data_plane"), dict):
        warnings.append("compliance authority EU data-plane source was not supplied; data-plane binding hashes were not replayed")
    expected = _source_binding(compliance_export, eu_ai_act_document, proof_pack, regulator_disclosure, eu_data_plane)
    if binding != expected:
        errors.append("compliance authority source_binding does not match supplied source artifacts")


def _verify_binding_completeness(binding: dict[str, Any], errors: list[str]) -> None:
    export = binding.get("compliance_export")
    if not isinstance(export, dict):
        errors.append("compliance authority source_binding.compliance_export is required")
        export = {}
    for field in ("schema", "export_hash", "pack_id", "issued_at"):
        _require_binding_field(export, f"source_binding.compliance_export.{field}", errors)
    for field in ("frameworks", "required_frameworks", "chain_roots"):
        _require_binding_field(export, f"source_binding.compliance_export.{field}", errors)
    _require_binding_field(export, "source_binding.compliance_export.missing_frameworks", errors, allow_empty_list=True)
    for field in ("framework_count", "control_count"):
        _require_positive_binding_count(export, f"source_binding.compliance_export.{field}", errors)

    document = binding.get("eu_ai_act_document")
    if not isinstance(document, dict):
        errors.append("compliance authority source_binding.eu_ai_act_document is required")
        document = {}
    for field in ("document_id", "document_hash", "schema", "issued_at", "source_proof_pack_id", "source_regulator_disclosure_id"):
        _require_binding_field(document, f"source_binding.eu_ai_act_document.{field}", errors)
    _require_binding_field(document, "source_binding.eu_ai_act_document.section_ids", errors)
    _require_positive_binding_count(document, "source_binding.eu_ai_act_document.section_count", errors)

    pack = binding.get("proof_pack")
    if pack is not None:
        if not isinstance(pack, dict):
            errors.append("compliance authority source_binding.proof_pack must be an object")
        else:
            for field in ("pack_id", "pack_hash", "spec_version", "issued_at", "chain_root"):
                _require_binding_field(pack, f"source_binding.proof_pack.{field}", errors)
            _require_positive_binding_count(pack, "source_binding.proof_pack.entry_count", errors)

    disclosure = binding.get("regulator_disclosure")
    if disclosure is not None:
        if not isinstance(disclosure, dict):
            errors.append("compliance authority source_binding.regulator_disclosure must be an object")
        else:
            for field in ("disclosure_id", "disclosure_hash", "schema", "issued_at"):
                _require_binding_field(disclosure, f"source_binding.regulator_disclosure.{field}", errors)
            _require_positive_binding_count(disclosure, "source_binding.regulator_disclosure.disclosed_entry_count", errors)

    data_plane = binding.get("eu_data_plane")
    if data_plane is not None:
        if not isinstance(data_plane, dict):
            errors.append("compliance authority source_binding.eu_data_plane must be an object")
        else:
            for field in ("attestation_id", "attestation_hash", "schema", "mode", "environment", "attested_at", "regions"):
                _require_binding_field(data_plane, f"source_binding.eu_data_plane.{field}", errors)
            residency = data_plane.get("residency")
            if not isinstance(residency, dict):
                errors.append("compliance authority source_binding.eu_data_plane.residency is required")
                residency = {}
            for field in ("tenant_id", "data_plane_ref", "customer_account_ref"):
                _require_binding_field(residency, f"source_binding.eu_data_plane.residency.{field}", errors)
            _require_binding_field(data_plane, "source_binding.eu_data_plane.control_summary", errors)


def _require_binding_field(container: dict[str, Any], path: str, errors: list[str], *, allow_empty_list: bool = False) -> None:
    field = path.rsplit(".", 1)[-1]
    value = container.get(field)
    if value is None or value == "" or (value == [] and not allow_empty_list) or value == {}:
        errors.append(f"compliance authority {path} is required")


def _require_positive_binding_count(container: dict[str, Any], path: str, errors: list[str]) -> None:
    field = path.rsplit(".", 1)[-1]
    value = container.get(field)
    if not isinstance(value, int) or value <= 0:
        errors.append(f"compliance authority {path} is required")

def _source_binding_complete(binding: dict[str, Any]) -> bool:
    errors: list[str] = []
    _verify_binding_completeness(binding, errors)
    export = binding.get("compliance_export") if isinstance(binding.get("compliance_export"), dict) else {}
    document = binding.get("eu_ai_act_document") if isinstance(binding.get("eu_ai_act_document"), dict) else {}
    pack = binding.get("proof_pack") if isinstance(binding.get("proof_pack"), dict) else {}
    disclosure = binding.get("regulator_disclosure") if isinstance(binding.get("regulator_disclosure"), dict) else {}
    data_plane = binding.get("eu_data_plane") if isinstance(binding.get("eu_data_plane"), dict) else {}
    return bool(
        not errors
        and export.get("pack_id")
        and not export.get("missing_frameworks")
        and len(export.get("chain_roots", [])) == 1
        and document.get("document_id")
        and document.get("source_proof_pack_id") == export.get("pack_id")
        and pack.get("pack_id") == export.get("pack_id")
        and disclosure.get("disclosure_id")
        and document.get("source_regulator_disclosure_id") == disclosure.get("disclosure_id")
        and data_plane.get("attestation_id")
        and data_plane.get("mode") == "eu-data-plane-attested"
    )


def _verify_compliance_export_source(export: dict[str, Any], proof_pack: dict[str, Any] | None) -> list[str]:
    errors: list[str] = []
    if export.get("schema") != "trustai.compliance-export/0.1":
        errors.append(f"unsupported compliance export schema: {export.get('schema')}")
    mappings = export.get("mappings", [])
    if not isinstance(mappings, list) or not mappings:
        errors.append("compliance export mappings are required")
        mappings = []
    frameworks = [item.get("framework") for item in mappings if isinstance(item, dict)]
    for framework in REQUIRED_FRAMEWORKS:
        if framework not in frameworks:
            errors.append(f"compliance export missing framework mapping: {framework}")
    for item in mappings:
        if not isinstance(item, dict):
            errors.append("compliance export mapping must be an object")
            continue
        if not item.get("pack_id"):
            errors.append(f"compliance export mapping {item.get('framework')} missing pack_id")
        if not item.get("contract_id"):
            errors.append(f"compliance export mapping {item.get('framework')} missing contract_id")
        if not item.get("chain_root"):
            errors.append(f"compliance export mapping {item.get('framework')} missing chain_root")
        if not isinstance(item.get("controls"), list) or not item.get("controls"):
            errors.append(f"compliance export mapping {item.get('framework')} missing controls")
    if proof_pack is not None:
        expected = build_compliance_export(proof_pack)
        if export != expected:
            errors.append("compliance export does not match supplied proof pack")
    return errors


def _build_authority_evidence_item(item: dict[str, Any], source_context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = item.get("evidence_hash")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unsupported compliance authority requirement: {requirement_id}")
    requirement = next(req for req in PRODUCTION_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in requirement["authority_kinds"]:
        raise ValueError(f"authority kind {authority_kind} is not valid for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (description, "description")):
        _require_text(value, field)
    evidence_hash = _normalize_sha256_ref(evidence_hash, "evidence_hash")
    built = {"requirement_id": requirement_id, "authority_kind": authority_kind, "evidence_ref": evidence_ref, "evidence_hash": evidence_hash, "description": description}
    for field in ("issuer", "subject", "source_uri", "issued_at", "expires_at"):
        if item.get(field):
            built[field] = str(item[field])
    for field in ("issued_at", "expires_at"):
        if built.get(field):
            parse_rfc3339(str(built[field]))
    if built.get("issued_at") and built.get("expires_at") and parse_rfc3339(str(built["issued_at"])) > parse_rfc3339(str(built["expires_at"])):
        raise ValueError("authority evidence issued_at must not be after expires_at")
    built["source_context"] = source_context
    built["evidence_id"] = content_hash(built)
    return built


def _verify_authority_evidence_item(
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    now,
    require_fresh: bool,
    source_context: dict[str, Any],
) -> str:
    try:
        expected = _build_authority_evidence_item(item, source_context)
    except ValueError as exc:
        errors.append(f"invalid compliance authority evidence: {exc}")
        return "missing"
    if item.get("evidence_id") != content_hash(without_keys(item, "evidence_id")):
        errors.append(f"compliance authority evidence_id does not match evidence body: {item.get('requirement_id')}")
    if not isinstance(item.get("source_context"), dict):
        errors.append(f"compliance authority source_context is required: {item.get('requirement_id')}")
    elif item.get("source_context") != source_context:
        errors.append(f"compliance authority source_context does not match source binding: {item.get('requirement_id')}")
    issued_at = item.get("issued_at")
    expires_at = item.get("expires_at")
    if not issued_at or not expires_at:
        if require_fresh:
            errors.append(f"compliance authority evidence {item.get('requirement_id')} freshness metadata missing")
        return "missing"
    issued = parse_rfc3339(str(issued_at))
    expires = parse_rfc3339(str(expires_at))
    if issued > expires:
        errors.append(f"compliance authority evidence {item.get('requirement_id')} issued_at is after expires_at")
        return "stale"
    if now < issued or now > expires:
        message = f"compliance authority evidence {item.get('requirement_id')} is outside its freshness window"
        if require_fresh:
            errors.append(message)
        else:
            warnings.append(message)
        return "stale"
    return "fresh"


def _authority_evidence_source_context(binding: dict[str, Any]) -> dict[str, Any]:
    export = binding.get("compliance_export") if isinstance(binding.get("compliance_export"), dict) else {}
    document = binding.get("eu_ai_act_document") if isinstance(binding.get("eu_ai_act_document"), dict) else {}
    pack = binding.get("proof_pack") if isinstance(binding.get("proof_pack"), dict) else {}
    disclosure = binding.get("regulator_disclosure") if isinstance(binding.get("regulator_disclosure"), dict) else {}
    data_plane = binding.get("eu_data_plane") if isinstance(binding.get("eu_data_plane"), dict) else {}
    residency = data_plane.get("residency") if isinstance(data_plane.get("residency"), dict) else {}
    return {
        "source_binding_hash": content_hash(binding),
        "compliance_export_hash": export.get("export_hash"),
        "compliance_pack_id": export.get("pack_id"),
        "frameworks": export.get("frameworks"),
        "missing_frameworks": export.get("missing_frameworks"),
        "control_count": export.get("control_count"),
        "chain_roots": export.get("chain_roots"),
        "eu_ai_act_document_id": document.get("document_id"),
        "eu_ai_act_document_hash": document.get("document_hash"),
        "eu_ai_act_section_count": document.get("section_count"),
        "source_proof_pack_id": document.get("source_proof_pack_id"),
        "source_regulator_disclosure_id": document.get("source_regulator_disclosure_id"),
        "proof_pack_id": pack.get("pack_id"),
        "proof_pack_hash": pack.get("pack_hash"),
        "proof_pack_chain_root": pack.get("chain_root"),
        "regulator_disclosure_id": disclosure.get("disclosure_id"),
        "regulator_disclosure_hash": disclosure.get("disclosure_hash"),
        "eu_data_plane_attestation_id": data_plane.get("attestation_id"),
        "eu_data_plane_attestation_hash": data_plane.get("attestation_hash"),
        "eu_data_plane_environment": data_plane.get("environment"),
        "eu_data_plane_regions": data_plane.get("regions"),
        "eu_data_plane_ref": residency.get("data_plane_ref"),
        "customer_account_ref": residency.get("customer_account_ref"),
    }


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("compliance authority required_production_authority does not match the required checklist")


def _summary(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted({item.get("requirement_id") for item in evidence_items if item.get("requirement_id")})
    missing = [req_id for req_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS if req_id not in covered]
    return {
        "required_requirement_count": len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "covered_requirement_ids": covered,
        "missing_requirement_ids": missing,
        "authority_evidence_count": len(evidence_items),
    }


def _controls(mode: str, binding: dict[str, Any], evidence_items: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, str]]:
    freshness = _freshness_summary(evidence_items)
    missing = summary.get("missing_requirement_count", 0)
    export = binding.get("compliance_export") if isinstance(binding.get("compliance_export"), dict) else {}
    document = binding.get("eu_ai_act_document") if isinstance(binding.get("eu_ai_act_document"), dict) else {}
    pack = binding.get("proof_pack") if isinstance(binding.get("proof_pack"), dict) else {}
    disclosure = binding.get("regulator_disclosure") if isinstance(binding.get("regulator_disclosure"), dict) else {}
    data_plane = binding.get("eu_data_plane") if isinstance(binding.get("eu_data_plane"), dict) else {}
    production_ready = mode == "production-dossier" and _source_binding_complete(binding) and not missing and freshness["missing"] == 0
    return [
        {"id": "compliance-export-bound", "status": "passed" if export.get("pack_id") else "failed", "detail": "Dossier binds the compliance export schema, pack ID, framework list, control count, and chain roots."},
        {"id": "required-framework-mappings-present", "status": "passed" if export.get("pack_id") and not export.get("missing_frameworks") else "deferred", "detail": f"frameworks={','.join(export.get('frameworks', []))}"},
        {"id": "eu-ai-act-document-bound", "status": "passed" if document.get("document_id") else "failed", "detail": "Dossier binds the signed EU AI Act technical documentation, section IDs, source proof pack, and regulator disclosure references."},
        {"id": "proof-pack-source-replay-bound", "status": "passed" if pack.get("pack_id") and pack.get("pack_id") == export.get("pack_id") else "deferred", "detail": "Proof-pack source is hash-bound when supplied and must reproduce the compliance export."},
        {"id": "regulator-disclosure-bound", "status": "passed" if disclosure.get("disclosure_id") else "deferred", "detail": "Selective regulator disclosure is hash-bound when supplied."},
        {"id": "eu-data-plane-sovereignty-bound", "status": "passed" if data_plane.get("attestation_id") else "deferred", "detail": "EU data-plane sovereignty attestation is hash-bound when supplied."},
        {"id": "authority-evidence-checklist-covered", "status": "passed" if not missing else "deferred", "detail": f"{summary.get('covered_requirement_count', 0)}/{summary.get('required_requirement_count', 0)} compliance production authority categories are covered."},
        {"id": "freshness-windows-tracked", "status": "passed" if evidence_items and freshness["missing"] == 0 else "deferred", "detail": f"windowed={freshness['windowed']} missing_freshness={freshness['missing']}"},
        {"id": "production-mode-gated", "status": "passed" if production_ready else "deferred", "detail": "Production compliance authority is claimed only when compliance export, EU AI Act document, proof pack, regulator disclosure, EU data plane, and every authority category are covered with timestamped evidence windows."},
        {"id": "raw-secret-exclusion", "status": "passed", "detail": "Dossier stores hashes and references instead of raw GRC, regulator, customer, or provider credentials."},
    ]


def _freshness_summary(evidence_items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"windowed": 0, "missing": 0}
    for item in evidence_items:
        if item.get("issued_at") and item.get("expires_at"):
            counts["windowed"] += 1
        else:
            counts["missing"] += 1
    return counts


def _freshness_reference(dossier: dict[str, Any], now: str | None, errors: list[str]):
    value = now or dossier.get("generated_at") or utc_now()
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"freshness reference time invalid: {exc}")
        return parse_rfc3339(utc_now())


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    if not isinstance(controls, list):
        return summary
    for control in controls:
        status = str(control.get("status", "unknown")) if isinstance(control, dict) else "unknown"
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            nested_path = f"{path}.{key_text}"
            if any(marker in key_text.lower() for marker in SECRET_KEY_MARKERS) and not _allowed_secret_reference_key(key_text):
                if isinstance(nested, str) and not _is_redacted_reference(nested):
                    errors.append(f"raw secret-like value is not allowed at {nested_path}")
            _check_no_secret_values(nested, errors, nested_path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _check_no_secret_values(nested, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str) -> bool:
    lowered = key.lower()
    return lowered.endswith(("_ref", "_hash", "_root", "_id"))


def _is_redacted_reference(value: str) -> bool:
    return value.startswith(("env:", "vault:", "kms:", "secret-ref:", "sha256:", "hash:"))


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"compliance authority {field} is required")


def _normalize_sha256_ref(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"compliance authority {field} is required")
    if not value.startswith("sha256:"):
        raise ValueError(f"compliance authority {field} must start with sha256:")
    hexdigest = value.removeprefix("sha256:")
    if len(hexdigest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in hexdigest):
        raise ValueError(f"compliance authority {field} must contain a 64-character sha256 digest")
    return "sha256:" + hexdigest.lower()
