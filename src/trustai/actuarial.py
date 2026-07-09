from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain
from .consent import INSURER_SCOPE, consent_status
from .crypto import sign_value, verify_value
from .insurer import build_insurer_telemetry
from .lifecycle import DEMOTION_ENTRY_TYPE, INCIDENT_ENTRY_TYPE, ROLLBACK_ENTRY_TYPE

ACTUARIAL_CORPUS_SCHEMA = "trustai.actuarial-corpus/0.1"
ACTUARIAL_PRODUCT_SCHEMA = "trustai.actuarial-product/0.1"
ACTUARIAL_PRODUCT_ENTRY_TYPE = "actuarial.product.published"
DEFAULT_ANONYMIZATION_SALT = "trustai-local-actuarial-salt-change-me"

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "moderate": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class ActuarialCorpusVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ActuarialProductVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_actuarial_corpus(
    chain: EvidenceChain,
    proof_packs: list[dict[str, Any]],
    *,
    consent_id: str = "local-demo-consent",
    require_consent: bool = False,
    now: str | None = None,
    anonymization_salt: str = DEFAULT_ANONYMIZATION_SALT,
) -> dict[str, Any]:
    if not proof_packs:
        raise ValueError("at least one proof pack is required")

    records = []
    consent_results = []
    for pack in proof_packs:
        decision = pack.get("gate_decision", {})
        status = consent_status(
            chain,
            consent_id,
            INSURER_SCOPE,
            pack_id=pack.get("pack_id"),
            contract_id=decision.get("contract_id"),
            now=now,
        )
        consent_results.append(status)
        if require_consent and not status.get("active"):
            raise ValueError(f"actuarial export denied for {pack.get('pack_id')}: {status.get('reason')}")
        records.append(_pack_record(chain, pack, consent_id, status, anonymization_salt))

    body = {
        "schema": ACTUARIAL_CORPUS_SCHEMA,
        "generated_at": now or utc_now(),
        "record_count": len(records),
        "anonymization": {
            "method": "sha256-content-hash-with-local-salt",
            "salt_hash": content_hash({"salt": anonymization_salt}),
        },
        "consent": {
            "consent_id": consent_id,
            "scope": INSURER_SCOPE,
            "required": require_consent,
            "all_active": all(status.get("active") for status in consent_results),
            "statuses": consent_results,
        },
        "records": records,
        "aggregate": _aggregate(records),
    }
    return {**body, "corpus_id": content_hash(body)}


def verify_actuarial_corpus(corpus: dict[str, Any]) -> ActuarialCorpusVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if corpus.get("schema") != ACTUARIAL_CORPUS_SCHEMA:
        errors.append(f"unsupported actuarial corpus schema: {corpus.get('schema')}")
    body = without_keys(corpus, "corpus_id")
    if corpus.get("corpus_id") != content_hash(body):
        errors.append("corpus_id does not match canonical corpus body")
    records = corpus.get("records", [])
    if not isinstance(records, list) or not records:
        errors.append("actuarial corpus must include at least one record")
        records = []
    valid_records = [record for record in records if isinstance(record, dict)]
    if len(valid_records) != len(records):
        errors.append("actuarial corpus records must be objects")
    if corpus.get("record_count") != len(records):
        errors.append("record_count does not match records length")
    if valid_records and corpus.get("aggregate") != _aggregate(valid_records):
        errors.append("aggregate does not match records")
    consent = corpus.get("consent", {})
    if not isinstance(consent, dict):
        errors.append("consent must be an object")
        consent = {}
    elif consent.get("required") and not consent.get("all_active"):
        errors.append("required consent is not active for every record")
    anonymization = corpus.get("anonymization", {})
    if not isinstance(anonymization, dict) or not anonymization.get("salt_hash"):
        errors.append("anonymization salt_hash missing")
    if any(_record_has_clear_identifier(record) for record in valid_records):
        errors.append("actuarial record contains a clear identifier field")
    if consent and not consent.get("required"):
        warnings.append("corpus was exported without requiring active consent")
    return ActuarialCorpusVerification(ok=not errors, errors=errors, warnings=warnings)


def build_actuarial_product(
    corpora: list[dict[str, Any]],
    *,
    product_name: str = "TrustAI actuarial reliability corpus",
    publisher: str = "trustai-local",
    audience: str = "insurer",
    allowed_use: list[str] | None = None,
    reporting_period_start: str | None = None,
    reporting_period_end: str | None = None,
    minimum_record_count: int = 1,
    require_all_consent_active: bool = True,
    issued_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if not corpora:
        raise ValueError("at least one actuarial corpus is required")
    if minimum_record_count < 1:
        raise ValueError("minimum_record_count must be at least 1")
    corpus_results = [verify_actuarial_corpus(corpus) for corpus in corpora]
    invalid = [result for result in corpus_results if not result.ok]
    if invalid:
        joined = "; ".join(error for result in invalid for error in result.errors)
        raise ValueError(f"invalid actuarial corpus: {joined}")
    total_records = sum(int(corpus.get("record_count", 0)) for corpus in corpora)
    if total_records < minimum_record_count:
        raise ValueError("actuarial product minimum_record_count is not satisfied")
    if require_all_consent_active and any(corpus.get("consent", {}).get("all_active") is not True for corpus in corpora):
        raise ValueError("actuarial product requires all source corpora to have active consent")

    sources = [_corpus_source(corpus) for corpus in corpora]
    combined_records = [record for corpus in corpora for record in corpus.get("records", [])]
    body = {
        "schema": ACTUARIAL_PRODUCT_SCHEMA,
        "issued_at": issued_at or utc_now(),
        "product": {
            "name": product_name,
            "publisher": publisher,
            "audience": audience,
            "allowed_use": allowed_use
            or [
                "ai-liability underwriting",
                "portfolio reliability benchmarking",
                "regulatory trend analysis",
            ],
            "production_replacement": "credentialed privacy-reviewed data product distribution with contractual redistribution limits",
        },
        "reporting_period": _reporting_period(corpora, reporting_period_start, reporting_period_end),
        "privacy_controls": {
            "minimum_record_count": minimum_record_count,
            "requires_all_consent_active": require_all_consent_active,
            "source_salt_hashes": sorted({source["anonymization"]["salt_hash"] for source in sources}),
            "direct_identifier_policy": "raw customer, agent, contract, pack, prompt, trace, and approver identifiers are excluded",
        },
        "source_corpora": sources,
        "aggregate": _aggregate(combined_records),
        "longitudinal": _longitudinal_summary(corpora),
        "limitations": [
            "This is a local signed actuarial data product manifest over anonymized TrustAI corpus exports.",
            "It is not a production actuarial filing, partner portal, or redistribution license.",
            "Production deployments need privacy review, contractual use limits, partner authentication, and re-identification risk controls.",
        ],
    }
    product_id = content_hash(body)
    return {
        **body,
        "product_id": product_id,
        "signatures": [sign_value({"product_id": product_id, "product": body}, key)],
    }


def verify_actuarial_product(
    product: dict[str, Any],
    *,
    corpora: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> ActuarialProductVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if product.get("schema") != ACTUARIAL_PRODUCT_SCHEMA:
        errors.append(f"unsupported actuarial product schema: {product.get('schema')}")
    body = without_keys(product, "product_id", "signatures")
    expected_product_id = content_hash(body)
    if product.get("product_id") != expected_product_id:
        errors.append("product_id does not match canonical product body")
    signatures = product.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("actuarial product missing signature")
    else:
        signed_value = {"product_id": product.get("product_id"), "product": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("actuarial product signature invalid")

    sources = product.get("source_corpora", [])
    if not isinstance(sources, list) or not sources:
        errors.append("actuarial product must include source corpora")
        sources = []
    for source in sources:
        if not isinstance(source, dict):
            errors.append("source corpus binding must be an object")
            continue
        if source.get("schema") != ACTUARIAL_CORPUS_SCHEMA:
            errors.append(f"unsupported source corpus schema: {source.get('schema')}")
        if not source.get("corpus_id") or not source.get("corpus_hash"):
            errors.append("source corpus binding missing id or hash")
    privacy_controls = product.get("privacy_controls", {})
    if not isinstance(privacy_controls, dict):
        errors.append("privacy_controls must be an object")
        privacy_controls = {}
    elif privacy_controls.get("minimum_record_count", 0) < 1:
        errors.append("privacy_controls.minimum_record_count must be at least 1")
    if corpora is None:
        warnings.append("source corpora not supplied; verified product binding only")
    else:
        _verify_product_sources(product, corpora, errors, warnings)
    return ActuarialProductVerification(ok=not errors, errors=errors, warnings=warnings)


def append_actuarial_product(
    chain: EvidenceChain,
    product: dict[str, Any],
    *,
    corpora: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_actuarial_product(product, corpora=corpora, key=key)
    if not result.ok:
        raise ValueError("invalid actuarial product: " + "; ".join(result.errors))
    payload = {
        "product_id": product["product_id"],
        "product_hash": content_hash(product),
        "product": product.get("product"),
        "reporting_period": product.get("reporting_period"),
        "privacy_controls": product.get("privacy_controls"),
        "source_corpora": product.get("source_corpora"),
        "aggregate": product.get("aggregate"),
        "longitudinal": product.get("longitudinal"),
        "limitations": product.get("limitations", []),
    }
    return chain.append(ACTUARIAL_PRODUCT_ENTRY_TYPE, payload, key=key, timestamp=product.get("issued_at"))


def load_actuarial_corpus(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("actuarial corpus must contain an object")
    return value


def write_actuarial_corpus(path: str | Path, corpus: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(corpus, indent=2, sort_keys=True), encoding="utf-8")


def load_actuarial_product(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("actuarial product must contain an object")
    return value


def write_actuarial_product(path: str | Path, product: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(product, indent=2, sort_keys=True), encoding="utf-8")


def _pack_record(
    chain: EvidenceChain,
    proof_pack: dict[str, Any],
    consent_id: str,
    consent: dict[str, Any],
    salt: str,
) -> dict[str, Any]:
    decision = proof_pack.get("gate_decision", {})
    telemetry = build_insurer_telemetry(proof_pack, consent_id=consent_id, consent=consent)
    contract_hash = decision.get("contract_hash") or proof_pack.get("contract", {}).get("hash")
    agent = decision.get("agent", {})
    lifecycle = _lifecycle_summary(chain, contract_hash=contract_hash, agent=agent)
    checks = decision.get("checks", [])
    failed_checks = [check for check in checks if not check.get("passed")]
    holdout = decision.get("holdout", {})
    approvals = decision.get("approvals", {})

    return {
        "record_id": _anon({"pack_id": proof_pack.get("pack_id")}, salt),
        "pack": {
            "id_hash": _anon(proof_pack.get("pack_id"), salt),
            "issued_at": proof_pack.get("issued_at"),
        },
        "contract": {
            "id_hash": _anon(decision.get("contract_id"), salt),
            "hash": contract_hash,
        },
        "agent": {
            "id_hash": _anon(
                {
                    "name": agent.get("name"),
                    "version": agent.get("version"),
                    "risk_class": agent.get("risk_class"),
                },
                salt,
            ),
            "risk_class": agent.get("risk_class"),
            "framework": agent.get("framework"),
        },
        "outcome": {
            "gate": decision.get("outcome"),
            "risk_score": telemetry["risk_score"],
            "risk_tier": telemetry["risk_tier"],
            "failed_check_count": len(failed_checks),
            "check_count": len(checks),
            "holdout_passed": holdout.get("passed"),
            "holdout_records_checked": holdout.get("records_checked"),
            "approvals_passed": approvals.get("passed", True),
        },
        "evidence": {
            "chain_root": proof_pack.get("chain", {}).get("tree", {}).get("root"),
            "frameworks": telemetry.get("signals", {}).get("frameworks", []),
            "lifecycle": lifecycle,
        },
        "consent_active": consent.get("active", False),
    }


def _lifecycle_summary(chain: EvidenceChain, *, contract_hash: str | None, agent: dict[str, Any]) -> dict[str, Any]:
    incident_count = 0
    demotion_count = 0
    rollback_count = 0
    severities: list[str] = []
    incident_types: list[str] = []
    agent_name = agent.get("name")
    for entry in chain.entries:
        payload = entry.get("payload", {})
        if not _entry_matches(payload, contract_hash=contract_hash, agent_name=agent_name):
            continue
        entry_type = entry.get("entry_type")
        if entry_type == INCIDENT_ENTRY_TYPE:
            incident_count += 1
            incident = payload.get("incident", {})
            severity = str(incident.get("severity", "unknown")).lower()
            severities.append(severity)
            if incident.get("type"):
                incident_types.append(str(incident["type"]))
        elif entry_type == DEMOTION_ENTRY_TYPE:
            demotion_count += 1
        elif entry_type == ROLLBACK_ENTRY_TYPE:
            rollback_count += 1
    return {
        "incident_count": incident_count,
        "demotion_count": demotion_count,
        "rollback_count": rollback_count,
        "max_incident_severity": _max_severity(severities),
        "incident_types": sorted(set(incident_types)),
    }


def _entry_matches(payload: dict[str, Any], *, contract_hash: str | None, agent_name: str | None) -> bool:
    if contract_hash and payload.get("contract_hash") == contract_hash:
        return True
    agent = payload.get("agent")
    if isinstance(agent, dict) and agent_name and agent.get("name") == agent_name:
        return True
    return False


def _max_severity(severities: list[str]) -> str | None:
    if not severities:
        return None
    return max(severities, key=lambda severity: SEVERITY_ORDER.get(severity, -1))


def _aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    incident_total = sum(record["evidence"]["lifecycle"]["incident_count"] for record in records)
    demotion_total = sum(record["evidence"]["lifecycle"]["demotion_count"] for record in records)
    rollback_total = sum(record["evidence"]["lifecycle"]["rollback_count"] for record in records)
    tiers: dict[str, int] = {}
    risk_classes: dict[str, int] = {}
    for record in records:
        tier = record["outcome"].get("risk_tier") or "unknown"
        risk_class = record["agent"].get("risk_class") or "unknown"
        tiers[tier] = tiers.get(tier, 0) + 1
        risk_classes[risk_class] = risk_classes.get(risk_class, 0) + 1
    return {
        "incident_count": incident_total,
        "demotion_count": demotion_total,
        "rollback_count": rollback_total,
        "risk_tiers": tiers,
        "risk_classes": risk_classes,
    }


def _corpus_source(corpus: dict[str, Any]) -> dict[str, Any]:
    return {
        "corpus_id": corpus.get("corpus_id"),
        "corpus_hash": content_hash(corpus),
        "schema": corpus.get("schema"),
        "generated_at": corpus.get("generated_at"),
        "record_count": corpus.get("record_count"),
        "consent": {
            "scope": corpus.get("consent", {}).get("scope"),
            "required": corpus.get("consent", {}).get("required"),
            "all_active": corpus.get("consent", {}).get("all_active"),
        },
        "anonymization": {
            "method": corpus.get("anonymization", {}).get("method"),
            "salt_hash": corpus.get("anonymization", {}).get("salt_hash"),
        },
        "aggregate": corpus.get("aggregate"),
    }


def _reporting_period(
    corpora: list[dict[str, Any]],
    start: str | None,
    end: str | None,
) -> dict[str, Any]:
    generated = sorted(str(corpus.get("generated_at")) for corpus in corpora if corpus.get("generated_at"))
    return {
        "start": start or (generated[0] if generated else None),
        "end": end or (generated[-1] if generated else None),
        "basis": "source corpus generated_at timestamps unless explicitly supplied",
    }


def _longitudinal_summary(corpora: list[dict[str, Any]]) -> dict[str, Any]:
    points = [
        {
            "corpus_id": corpus.get("corpus_id"),
            "generated_at": corpus.get("generated_at"),
            "record_count": corpus.get("record_count"),
            "aggregate": corpus.get("aggregate"),
        }
        for corpus in sorted(corpora, key=lambda item: str(item.get("generated_at", "")))
    ]
    return {
        "corpus_count": len(corpora),
        "points": points,
    }


def _verify_product_sources(
    product: dict[str, Any],
    corpora: list[dict[str, Any]],
    errors: list[str],
    warnings: list[str],
) -> None:
    source_list = product.get("source_corpora", [])
    if not isinstance(source_list, list):
        errors.append("source_corpora must be a list")
        return
    source_by_id = {source.get("corpus_id"): source for source in source_list if isinstance(source, dict)}
    if len(source_by_id) != len(source_list):
        errors.append("source_corpora must contain unique corpus_id values")
    corpus_by_id = {corpus.get("corpus_id"): corpus for corpus in corpora}
    if len(corpus_by_id) != len(corpora):
        errors.append("supplied corpora must contain unique corpus_id values")
    for corpus in corpora:
        result = verify_actuarial_corpus(corpus)
        if not result.ok:
            errors.extend(f"source corpus {corpus.get('corpus_id')}: {error}" for error in result.errors)
        warnings.extend(f"source corpus {corpus.get('corpus_id')}: {warning}" for warning in result.warnings)
    if set(source_by_id) != set(corpus_by_id):
        errors.append("source corpus ids do not match supplied corpora")
        return
    for corpus_id, corpus in corpus_by_id.items():
        expected = _corpus_source(corpus)
        if source_by_id[corpus_id] != expected:
            errors.append(f"source corpus binding mismatch: {corpus_id}")
    combined_records = [record for corpus in corpora for record in corpus.get("records", [])]
    if product.get("aggregate") != _aggregate(combined_records):
        errors.append("actuarial product aggregate does not match supplied corpora")
    if product.get("longitudinal") != _longitudinal_summary(corpora):
        errors.append("actuarial product longitudinal summary does not match supplied corpora")
    minimum = product.get("privacy_controls", {}).get("minimum_record_count", 0)
    if len(combined_records) < minimum:
        errors.append("supplied corpora do not satisfy minimum_record_count")
    if product.get("privacy_controls", {}).get("requires_all_consent_active"):
        inactive = [corpus.get("corpus_id") for corpus in corpora if corpus.get("consent", {}).get("all_active") is not True]
        if inactive:
            errors.append(f"source corpora do not all have active consent: {', '.join(str(item) for item in inactive)}")


def _record_has_clear_identifier(record: dict[str, Any]) -> bool:
    forbidden_keys = {"pack_id", "contract_id", "agent_name", "customer", "operator", "approver"}
    stack: list[Any] = [record]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                if key in forbidden_keys:
                    return True
                stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    return False


def _anon(value: Any, salt: str) -> str:
    return content_hash({"salt": salt, "value": value})