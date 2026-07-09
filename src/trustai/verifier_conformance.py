from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .canonical import content_hash, utc_now, without_keys
from .verifier import verify_proof_pack

VERIFIER_CONFORMANCE_SCHEMA = "trustai.verifier-conformance/0.1"


@dataclass
class VerifierConformanceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    passed_count: int = 0
    case_count: int = 0


def build_verifier_conformance_report(
    proof_pack: dict[str, Any],
    *,
    key: str | None = None,
    verifier_command: str = "python -m trustai verify",
) -> dict[str, Any]:
    cases = [
        _case("valid-proof-pack", "Valid proof pack is accepted.", proof_pack, True, key),
        _case(
            "pack-signature-tamper",
            "Changing the proof-pack signature is rejected.",
            _tamper_signature(proof_pack),
            False,
            key,
        ),
        _case(
            "chain-entry-payload-tamper",
            "Changing a selected evidence entry payload is rejected.",
            _tamper_entry_payload(proof_pack),
            False,
            key,
        ),
        _case(
            "inclusion-proof-tamper",
            "Changing a Merkle inclusion proof is rejected.",
            _tamper_inclusion_proof(proof_pack),
            False,
            key,
        ),
        _case(
            "packed-contract-body-tamper",
            "Changing the packed verification contract body is rejected.",
            _tamper_contract_body(proof_pack),
            False,
            key,
        ),
    ]
    body = {
        "schema": VERIFIER_CONFORMANCE_SCHEMA,
        "generated_at": utc_now(),
        "verifier": {
            "command": verifier_command,
            "mode": "offline-accountless",
        },
        "source_proof_pack": {
            "pack_id": proof_pack.get("pack_id"),
            "content_hash": content_hash(proof_pack),
            "spec_version": proof_pack.get("spec_version"),
            "chain_root": proof_pack.get("chain", {}).get("tree", {}).get("root"),
            "chain_size": proof_pack.get("chain", {}).get("tree", {}).get("size"),
        },
        "test_cases": cases,
        "summary": {
            "case_count": len(cases),
            "passed_count": sum(1 for case in cases if case["passed"]),
            "failed_count": sum(1 for case in cases if not case["passed"]),
        },
        "limitations": [
            "This report proves the local verifier behavior against generated vectors; it is not a compiled Go verifier binary.",
            "Production conformance should be rerun for each independently implemented verifier release.",
        ],
    }
    return {**body, "report_id": content_hash(body)}


def verify_verifier_conformance_report(report: dict[str, Any]) -> VerifierConformanceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if report.get("schema") != VERIFIER_CONFORMANCE_SCHEMA:
        errors.append(f"unsupported verifier conformance schema: {report.get('schema')}")
    body = without_keys(report, "report_id")
    if report.get("report_id") != content_hash(body):
        errors.append("report_id does not match canonical report body")

    cases = report.get("test_cases", [])
    if not isinstance(cases, list) or not cases:
        errors.append("verifier conformance report must include test cases")
        cases = []
    for case in cases:
        if not isinstance(case, dict):
            errors.append("verifier conformance test case must be an object")
            continue
        if not case.get("id"):
            errors.append("verifier conformance test case missing id")
        if case.get("actual_ok") != case.get("expected_ok"):
            errors.append(f"test case {case.get('id')} actual_ok does not match expected_ok")
        if case.get("passed") != (case.get("actual_ok") == case.get("expected_ok")):
            errors.append(f"test case {case.get('id')} passed flag inconsistent")

    summary = report.get("summary", {})
    expected_summary = {
        "case_count": len(cases),
        "passed_count": sum(1 for case in cases if isinstance(case, dict) and case.get("passed")),
        "failed_count": sum(1 for case in cases if isinstance(case, dict) and not case.get("passed")),
    }
    if summary != expected_summary:
        errors.append("summary does not match test cases")
    if expected_summary["failed_count"]:
        errors.append("one or more verifier conformance cases failed")

    if report.get("verifier", {}).get("mode") != "offline-accountless":
        warnings.append("verifier mode is not offline-accountless")

    return VerifierConformanceVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        passed_count=expected_summary["passed_count"],
        case_count=expected_summary["case_count"],
    )


def write_verifier_conformance_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def write_verifier_conformance_markdown(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_verifier_conformance_markdown(report), encoding="utf-8")


def render_verifier_conformance_markdown(report: dict[str, Any]) -> str:
    cases = "\n".join(
        f"- `{case.get('id')}`: {'PASS' if case.get('passed') else 'FAIL'} "
        f"(expected={case.get('expected_ok')}, actual={case.get('actual_ok')})"
        for case in report.get("test_cases", [])
    )
    source = report.get("source_proof_pack", {})
    return f"""# TrustAI Verifier Conformance Report

Report ID: `{report.get('report_id', '')}`

Verifier: `{report.get('verifier', {}).get('command', '')}`

Source proof pack: `{source.get('pack_id', '')}`

## Test Cases

{cases}

## Summary

Passed: {report.get('summary', {}).get('passed_count')}/{report.get('summary', {}).get('case_count')}
"""


def load_verifier_conformance_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _case(
    case_id: str,
    description: str,
    pack: dict[str, Any],
    expected_ok: bool,
    key: str | None,
) -> dict[str, Any]:
    result = verify_proof_pack(pack, key=key)
    actual_ok = result.ok
    return {
        "id": case_id,
        "description": description,
        "expected_ok": expected_ok,
        "actual_ok": actual_ok,
        "passed": actual_ok == expected_ok,
        "decision": result.decision,
        "errors": result.errors,
        "warnings": result.warnings,
        "pack_content_hash": content_hash(pack),
    }


def _tampered_pack(proof_pack: dict[str, Any], mutator: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    tampered = copy.deepcopy(proof_pack)
    mutator(tampered)
    return tampered


def _tamper_signature(proof_pack: dict[str, Any]) -> dict[str, Any]:
    def mutate(pack: dict[str, Any]) -> None:
        signatures = pack.setdefault("signatures", [{}])
        if not signatures:
            signatures.append({})
        signatures[0]["value"] = "0" * 64

    return _tampered_pack(proof_pack, mutate)


def _tamper_entry_payload(proof_pack: dict[str, Any]) -> dict[str, Any]:
    def mutate(pack: dict[str, Any]) -> None:
        entries = pack.get("chain", {}).get("entries", [])
        if not entries:
            pack.setdefault("chain", {})["entries"] = [{"payload": {"tampered": True}}]
            return
        payload = entries[0].setdefault("payload", {})
        payload["trustai_conformance_tamper"] = True

    return _tampered_pack(proof_pack, mutate)


def _tamper_inclusion_proof(proof_pack: dict[str, Any]) -> dict[str, Any]:
    def mutate(pack: dict[str, Any]) -> None:
        proofs = pack.get("chain", {}).get("inclusion_proofs", {})
        if not proofs:
            pack.setdefault("chain", {}).setdefault("inclusion_proofs", {})["missing"] = {"tree_root": "0" * 64}
            return
        first_proof = next(iter(proofs.values()))
        audit_path = first_proof.get("audit_path", [])
        if audit_path:
            audit_path[0]["hash"] = "0" * 64
        else:
            first_proof["tree_root"] = "0" * 64

    return _tampered_pack(proof_pack, mutate)


def _tamper_contract_body(proof_pack: dict[str, Any]) -> dict[str, Any]:
    def mutate(pack: dict[str, Any]) -> None:
        body = pack.setdefault("contract", {}).setdefault("body", {})
        current = body.get("id", "contract")
        body["id"] = f"{current}-tampered"

    return _tampered_pack(proof_pack, mutate)
