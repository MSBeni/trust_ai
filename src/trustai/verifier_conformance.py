from __future__ import annotations

import base64
import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .canonical import content_hash, utc_now, without_keys
from .framework_runtime_service_authority_recorded_export_provider_bundle import (
    verify_framework_runtime_service_authority_recorded_export_provider_bundle,
)
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
    provider_bundle: dict[str, Any] | None = None,
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
    if _has_delegation_graph_entry(proof_pack):
        cases.append(
            _case(
                "delegation-graph-tamper",
                "Changing an embedded delegation graph edge is rejected.",
                _tamper_delegation_graph(proof_pack),
                False,
                key,
            )
        )
    if provider_bundle is not None:
        cases.extend(_provider_bundle_cases(provider_bundle, key))
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
            "delegation_graph_entry_count": _delegation_graph_entry_count(proof_pack),
        },
        "source_provider_bundle": _provider_bundle_reference(provider_bundle),
        "test_cases": cases,
        "summary": {
            "case_count": len(cases),
            "passed_count": sum(1 for case in cases if case["passed"]),
            "failed_count": sum(1 for case in cases if not case["passed"]),
        },
        "limitations": [
            "This report proves the local verifier behavior against generated proof-pack and optional provider-bundle vectors; it is not a compiled Go verifier binary.",
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
    provider_bundle = report.get("source_provider_bundle", {}) if isinstance(report.get("source_provider_bundle"), dict) else {}
    provider_line = ""
    if provider_bundle:
        provider_line = f"\nSource provider bundle: `{provider_bundle.get('bundle_id', '')}`"
    return f"""# TrustAI Verifier Conformance Report

Report ID: `{report.get('report_id', '')}`

Verifier: `{report.get('verifier', {}).get('command', '')}`

Source proof pack: `{source.get('pack_id', '')}`{provider_line}

## Test Cases

{cases}

## Summary

Passed: {report.get('summary', {}).get('passed_count')}/{report.get('summary', {}).get('case_count')}
"""


def load_verifier_conformance_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))



def _delegation_graph_entries(proof_pack: dict[str, Any]) -> list[dict[str, Any]]:
    entries = proof_pack.get("chain", {}).get("entries", [])
    if not isinstance(entries, list):
        return []
    return [
        entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("entry_type") == "agent.delegation_graph.exported"
    ]


def _delegation_graph_entry_count(proof_pack: dict[str, Any]) -> int:
    return len(_delegation_graph_entries(proof_pack))


def _has_delegation_graph_entry(proof_pack: dict[str, Any]) -> bool:
    return bool(_delegation_graph_entries(proof_pack))

def _provider_bundle_reference(provider_bundle: dict[str, Any] | None) -> dict[str, Any] | None:
    if provider_bundle is None:
        return None
    source = provider_bundle.get("source", {}) if isinstance(provider_bundle.get("source"), dict) else {}
    summary = provider_bundle.get("summary", {}) if isinstance(provider_bundle.get("summary"), dict) else {}
    return {
        "bundle_id": provider_bundle.get("bundle_id"),
        "content_hash": content_hash(provider_bundle),
        "schema": provider_bundle.get("schema"),
        "provider_receipt_id": source.get("provider_receipt_id"),
        "provider_export_hash": source.get("provider_export_hash"),
        "recorded_export_id": source.get("recorded_export_id"),
        "source_artifact_count": summary.get("source_artifact_count"),
        "source_artifact_sha256_root": summary.get("source_artifact_sha256_root"),
    }


def _provider_bundle_cases(provider_bundle: dict[str, Any], key: str | None) -> list[dict[str, Any]]:
    return [
        _provider_bundle_case(
            "valid-provider-bundle",
            "Valid recorded-export provider bundle is accepted.",
            provider_bundle,
            True,
            key,
        ),
        _provider_bundle_case(
            "provider-bundle-signature-tamper",
            "Changing the provider bundle signature is rejected.",
            _tamper_provider_bundle_signature(provider_bundle),
            False,
            key,
        ),
        _provider_bundle_case(
            "provider-bundle-source-tamper",
            "Changing an embedded provider export source object is rejected.",
            _tamper_provider_bundle_source(provider_bundle),
            False,
            key,
        ),
        _provider_bundle_case(
            "provider-bundle-artifact-byte-tamper",
            "Changing embedded provider bundle source artifact bytes is rejected.",
            _tamper_provider_bundle_artifact_bytes(provider_bundle),
            False,
            key,
        ),
    ]


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
        "target": "proof-pack",
        "description": description,
        "expected_ok": expected_ok,
        "actual_ok": actual_ok,
        "passed": actual_ok == expected_ok,
        "decision": result.decision,
        "errors": result.errors,
        "warnings": result.warnings,
        "pack_content_hash": content_hash(pack),
    }


def _provider_bundle_case(
    case_id: str,
    description: str,
    bundle: dict[str, Any],
    expected_ok: bool,
    key: str | None,
) -> dict[str, Any]:
    result = verify_framework_runtime_service_authority_recorded_export_provider_bundle(bundle, key=key)
    actual_ok = result.ok
    return {
        "id": case_id,
        "target": "framework-runtime-service-authority-recorded-export-provider-bundle",
        "description": description,
        "expected_ok": expected_ok,
        "actual_ok": actual_ok,
        "passed": actual_ok == expected_ok,
        "decision": "accepted" if actual_ok else "rejected",
        "errors": result.errors,
        "warnings": result.warnings,
        "bundle_content_hash": content_hash(bundle),
    }


def _tampered_provider_bundle(bundle: dict[str, Any], mutator: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    tampered = copy.deepcopy(bundle)
    mutator(tampered)
    return tampered


def _tamper_provider_bundle_signature(bundle: dict[str, Any]) -> dict[str, Any]:
    def mutate(value: dict[str, Any]) -> None:
        signatures = value.setdefault("signatures", [{}])
        if not signatures:
            signatures.append({})
        signatures[0]["value"] = "0" * 64

    return _tampered_provider_bundle(bundle, mutate)


def _tamper_provider_bundle_source(bundle: dict[str, Any]) -> dict[str, Any]:
    def mutate(value: dict[str, Any]) -> None:
        provider_export = value.setdefault("sources", {}).setdefault("provider_export", {})
        records = provider_export.setdefault("request_records", [{}])
        if not records:
            records.append({})
        records[0]["response_hash"] = "sha256:trustai-conformance-provider-bundle-source-tamper"

    return _tampered_provider_bundle(bundle, mutate)


def _tamper_provider_bundle_artifact_bytes(bundle: dict[str, Any]) -> dict[str, Any]:
    def mutate(value: dict[str, Any]) -> None:
        artifacts = value.setdefault("source_artifacts", [{}])
        if not artifacts:
            artifacts.append({})
        artifacts[0]["content_b64"] = base64.b64encode(b"{}").decode("ascii")

    return _tampered_provider_bundle(bundle, mutate)


def _tampered_pack(proof_pack: dict[str, Any], mutator: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    tampered = copy.deepcopy(proof_pack)
    mutator(tampered)
    return tampered



def _tamper_delegation_graph(proof_pack: dict[str, Any]) -> dict[str, Any]:
    def mutate(pack: dict[str, Any]) -> None:
        entries = pack.get("chain", {}).get("entries", [])
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("entry_type") != "agent.delegation_graph.exported":
                continue
            graph = entry.setdefault("payload", {}).setdefault("delegation_graph", {})
            edges = graph.setdefault("edges", [{}])
            if not edges:
                edges.append({})
            delegation = edges[0].setdefault("delegation", {})
            delegation["reason"] = "trustai verifier conformance graph tamper"
            return
        pack.setdefault("chain", {}).setdefault("entries", []).append(
            {
                "entry_type": "agent.delegation_graph.exported",
                "payload": {"delegation_graph": {"edges": [{"delegation": {"reason": "trustai verifier conformance graph tamper"}}]}},
            }
        )

    return _tampered_pack(proof_pack, mutate)

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
