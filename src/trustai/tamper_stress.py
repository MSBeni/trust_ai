from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, without_keys
from .chain import compute_entry_id, verify_entry
from .crypto import sign_value, verify_value
from .merkle import inclusion_proof, merkle_root, verify_inclusion
from .timestamping import issue_timestamp_token

TAMPER_STRESS_REPORT_SCHEMA = "trustai.tamper-stress-report/0.1"
DEFAULT_TAMPER_STRESS_TIMESTAMP = "2026-07-16T00:00:00Z"


@dataclass
class TamperStressVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_tamper_stress_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_tamper_stress_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def build_tamper_stress_report(
    *,
    entry_count: int = 1_000_000,
    tenant_id: str = "tamper-stress-local",
    key: str | None = None,
    timestamp: str = DEFAULT_TAMPER_STRESS_TIMESTAMP,
    sample_indexes: list[int] | None = None,
    tamper_index: int | None = None,
) -> dict[str, Any]:
    if entry_count <= 0:
        raise ValueError("entry_count must be positive")
    if tamper_index is None:
        tamper_index = entry_count - 1
    if tamper_index < 0 or tamper_index >= entry_count:
        raise ValueError("tamper_index must be inside the generated chain")

    samples = _normalized_sample_indexes(entry_count, sample_indexes, tamper_index)
    generated = _generate_chain(entry_count, tenant_id, key, timestamp, samples)
    root = merkle_root(generated["entry_ids"])
    sample_records = []
    for index in samples:
        entry = generated["sample_entries"][index]
        proof = inclusion_proof(generated["entry_ids"], index)
        sample_records.append(
            {
                "index": index,
                "entry_id": entry["entry_id"],
                "entry": entry,
                "inclusion_proof": {
                    "tree_size": entry_count,
                    "tree_root": root,
                    "audit_path": proof,
                },
            }
        )

    target_entry = generated["sample_entries"][tamper_index]
    tamper_checks = _tamper_checks(target_entry, root, inclusion_proof(generated["entry_ids"], tamper_index), key)

    body = {
        "generated_at": timestamp,
        "tenant_id": tenant_id,
        "chain": {
            "entry_count": entry_count,
            "entry_type": "tamper_stress.event",
            "tree_root": root,
            "sample_indexes": samples,
            "tamper_index": tamper_index,
            "entries_verified_during_generation": generated["verified_count"],
            "generation_errors": generated["generation_errors"],
        },
        "samples": sample_records,
        "tamper_checks": tamper_checks,
        "summary": {
            "tamper_checks_total": len(tamper_checks),
            "tamper_checks_detected": sum(1 for check in tamper_checks if check.get("detected")),
            "all_generated_entries_verified": generated["verified_count"] == entry_count and not generated["generation_errors"],
            "all_tamper_checks_detected": all(check.get("detected") for check in tamper_checks),
        },
        "limitations": [
            "The report records a generated TrustAI-compatible hash-chained Merkle log and representative single-byte tamper vectors.",
            "Report verification checks sampled entries and tamper vectors by default; use deep verification to regenerate every entry and recompute the full root.",
            "Local HMAC signer and TSA keys model production KMS/TSA behavior but do not replace customer-controlled KMS/HSM and independent RFC 3161 services.",
        ],
    }
    report_id = content_hash(body)
    return {
        "schema": TAMPER_STRESS_REPORT_SCHEMA,
        "report_id": report_id,
        **body,
        "signatures": [sign_value({"report_id": report_id, "tamper_stress_report": body}, key)],
    }


def verify_tamper_stress_report(report: dict[str, Any], key: str | None = None, deep: bool = False) -> TamperStressVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if report.get("schema") != TAMPER_STRESS_REPORT_SCHEMA:
        errors.append(f"unsupported tamper stress report schema: {report.get('schema')}")

    body = without_keys(report, "schema", "report_id", "signatures")
    expected_report_id = content_hash(body)
    if report.get("report_id") != expected_report_id:
        errors.append("report_id does not match canonical report body")

    signatures = report.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("tamper stress report must include a signature")
    else:
        signed_value = {"report_id": report.get("report_id"), "tamper_stress_report": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("tamper stress report signature invalid")

    chain = report.get("chain", {})
    entry_count = chain.get("entry_count")
    root = chain.get("tree_root")
    if not isinstance(entry_count, int) or entry_count <= 0:
        errors.append("chain.entry_count must be a positive integer")
    if not isinstance(root, str) or len(root) != 64:
        errors.append("chain.tree_root must be a SHA-256 hex root")

    samples = report.get("samples", [])
    if not isinstance(samples, list) or not samples:
        errors.append("tamper stress report must include sample entries")
        samples = []
    for sample in samples:
        if not isinstance(sample, dict):
            errors.append("sample record must be an object")
            continue
        entry = sample.get("entry")
        proof = sample.get("inclusion_proof", {})
        if not isinstance(entry, dict):
            errors.append("sample entry missing")
            continue
        entry_errors = verify_entry(entry, key)
        if entry_errors:
            errors.extend(f"sample {sample.get('index')} {error}" for error in entry_errors)
        if proof.get("tree_root") != root:
            errors.append(f"sample {sample.get('index')} proof root mismatch")
        if proof.get("tree_size") != entry_count:
            errors.append(f"sample {sample.get('index')} proof tree size mismatch")
        if not verify_inclusion(entry.get("entry_id", ""), proof.get("audit_path", []), root or ""):
            errors.append(f"sample {sample.get('index')} inclusion proof failed")

    tamper_checks = report.get("tamper_checks", [])
    if not isinstance(tamper_checks, list) or not tamper_checks:
        errors.append("tamper checks missing")
        tamper_checks = []
    for check in tamper_checks:
        if not isinstance(check, dict):
            errors.append("tamper check must be an object")
            continue
        if not check.get("detected"):
            errors.append(f"tamper check did not detect mutation: {check.get('id')}")
        mutated_entry = check.get("mutated_entry")
        if isinstance(mutated_entry, dict):
            mutated_errors = verify_entry(mutated_entry, key)
            if not mutated_errors:
                errors.append(f"mutated entry unexpectedly verified: {check.get('id')}")
        if check.get("id") == "entry-id-single-byte":
            if check.get("inclusion_ok_after_tamper") is not False:
                errors.append("entry-id tamper should fail inclusion proof")

    summary = report.get("summary", {})
    if summary.get("tamper_checks_total") != len(tamper_checks):
        errors.append("summary tamper check count mismatch")
    detected_count = sum(1 for check in tamper_checks if isinstance(check, dict) and check.get("detected"))
    if summary.get("tamper_checks_detected") != detected_count:
        errors.append("summary detected tamper count mismatch")
    if summary.get("all_tamper_checks_detected") is not True:
        errors.append("summary does not mark all tamper checks detected")
    if summary.get("all_generated_entries_verified") is not True:
        errors.append("summary does not mark all generated entries verified")

    if deep and isinstance(entry_count, int) and entry_count > 0:
        expected_samples = [sample.get("index") for sample in samples if isinstance(sample, dict) and isinstance(sample.get("index"), int)]
        generated = _generate_chain(
            entry_count,
            str(report.get("tenant_id") or "tamper-stress-local"),
            key,
            str(report.get("generated_at") or DEFAULT_TAMPER_STRESS_TIMESTAMP),
            expected_samples,
        )
        regenerated_root = merkle_root(generated["entry_ids"])
        if regenerated_root != root:
            errors.append("deep verification regenerated tree root mismatch")
        if generated["generation_errors"]:
            errors.extend(f"deep generation {error}" for error in generated["generation_errors"])
    elif isinstance(entry_count, int) and entry_count >= 1_000_000:
        warnings.append("deep verification was not requested for a roadmap-scale tamper stress report")

    return TamperStressVerification(ok=not errors, errors=errors, warnings=warnings)


def _normalized_sample_indexes(entry_count: int, requested: list[int] | None, tamper_index: int) -> list[int]:
    if requested:
        values = list(requested)
    else:
        values = [0, entry_count // 2, entry_count - 1]
    values.append(tamper_index)
    normalized = sorted({value for value in values if 0 <= value < entry_count})
    if not normalized:
        raise ValueError("at least one sample index must be inside the generated chain")
    return normalized


def _generate_chain(entry_count: int, tenant_id: str, key: str | None, timestamp: str, sample_indexes: list[int]) -> dict[str, Any]:
    entry_ids: list[str] = []
    sample_set = set(sample_indexes)
    sample_entries: dict[int, dict[str, Any]] = {}
    generation_errors: list[str] = []
    verified_count = 0
    previous_entry_id = None
    for index in range(entry_count):
        entry = _build_entry(index, previous_entry_id, tenant_id, key, timestamp)
        entry_ids.append(entry["entry_id"])
        if index in sample_set:
            sample_entries[index] = entry
        entry_errors = verify_entry(entry, key)
        if entry_errors:
            generation_errors.extend(f"entry {index} {error}" for error in entry_errors)
        else:
            verified_count += 1
        previous_entry_id = entry["entry_id"]
    return {
        "entry_ids": entry_ids,
        "sample_entries": sample_entries,
        "generation_errors": generation_errors,
        "verified_count": verified_count,
    }


def _build_entry(index: int, previous_entry_id: str | None, tenant_id: str, key: str | None, timestamp: str) -> dict[str, Any]:
    payload = {
        "index": index,
        "digest": content_hash({"index": index}),
        "stress_profile": "roadmap-p0-tamper-evidence",
    }
    frozen_payload = json.loads(json.dumps(payload, sort_keys=True))
    core = {
        "index": index,
        "tenant_id": tenant_id,
        "entry_type": "tamper_stress.event",
        "timestamp": timestamp,
        "previous_entry_id": previous_entry_id,
        "payload_hash": content_hash(frozen_payload),
        "payload": frozen_payload,
    }
    entry_id = compute_entry_id(core)
    timestamp_token = issue_timestamp_token(_timestamp_message(entry_id, core), key=key, issued_at=timestamp)
    return {
        **core,
        "entry_id": entry_id,
        "timestamp_token": timestamp_token,
        "signature": sign_value(
            {"entry_id": entry_id, "core": core, "timestamp_token": timestamp_token},
            key,
            provider="local-kms",
        ),
    }


def _timestamp_message(entry_id: str, core: dict[str, Any]) -> dict[str, Any]:
    return {
        "entry_id": entry_id,
        "entry_timestamp": core.get("timestamp"),
        "payload_hash": core.get("payload_hash"),
    }


def _tamper_checks(entry: dict[str, Any], root: str, proof: list[dict[str, str]], key: str | None) -> list[dict[str, Any]]:
    checks = []
    checks.append(_check_mutation("payload-single-byte", entry, key, lambda value: _mutate_payload_digest(value)))
    checks.append(_check_mutation("signature-single-byte", entry, key, lambda value: _mutate_signature(value)))
    checks.append(_check_mutation("timestamp-token-single-byte", entry, key, lambda value: _mutate_timestamp(value)))

    mutated_id = copy.deepcopy(entry)
    mutated_id["entry_id"] = _flip_hex(mutated_id["entry_id"])
    errors = verify_entry(mutated_id, key)
    checks.append(
        {
            "id": "entry-id-single-byte",
            "target_index": entry.get("index"),
            "mutation": "entry_id hex nibble changed",
            "detected": bool(errors) and not verify_inclusion(mutated_id.get("entry_id", ""), proof, root),
            "errors": errors,
            "inclusion_ok_after_tamper": verify_inclusion(mutated_id.get("entry_id", ""), proof, root),
            "mutated_entry": mutated_id,
        }
    )
    return checks


def _check_mutation(check_id: str, entry: dict[str, Any], key: str | None, mutator: Any) -> dict[str, Any]:
    mutated = copy.deepcopy(entry)
    mutation = mutator(mutated)
    errors = verify_entry(mutated, key)
    return {
        "id": check_id,
        "target_index": entry.get("index"),
        "mutation": mutation,
        "detected": bool(errors),
        "errors": errors,
        "mutated_entry": mutated,
    }


def _mutate_payload_digest(entry: dict[str, Any]) -> str:
    entry.setdefault("payload", {})["digest"] = _flip_hex(str(entry.get("payload", {}).get("digest", "0")))
    return "payload.digest hex nibble changed"


def _mutate_signature(entry: dict[str, Any]) -> str:
    entry.setdefault("signature", {})["value"] = _flip_hex(str(entry.get("signature", {}).get("value", "0")))
    return "signature.value hex nibble changed"


def _mutate_timestamp(entry: dict[str, Any]) -> str:
    entry.setdefault("timestamp_token", {})["message_hash"] = _flip_hex(str(entry.get("timestamp_token", {}).get("message_hash", "0")))
    return "timestamp_token.message_hash hex nibble changed"


def _flip_hex(value: str) -> str:
    if not value:
        return "1"
    replacement = "0" if value[0] != "0" else "1"
    return replacement + value[1:]
