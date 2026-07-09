from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .regulator import verify_regulator_disclosure
from .standards import verify_standards_submission
from .verifier import verify_proof_pack

AUDITOR_CERTIFICATION_SCHEMA = "trustai.auditor-certification-kit/0.1"

REQUIRED_MODULE_IDS = {
    "proof-pack-verification",
    "evidence-chain-forensics",
    "selective-disclosure-review",
    "policy-and-lifecycle-review",
}


def build_auditor_certification_kit(
    proof_pack: dict[str, Any],
    *,
    regulator_disclosure: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    program_version: str = "0.1.0",
) -> dict[str, Any]:
    decision = proof_pack.get("gate_decision", {})
    source_artifacts = {
        "proof_pack": {
            "pack_id": proof_pack.get("pack_id"),
            "contract_id": decision.get("contract_id"),
            "gate_outcome": decision.get("outcome"),
            "chain_root": proof_pack.get("chain", {}).get("tree", {}).get("root"),
            "content_hash": content_hash(proof_pack),
        }
    }
    if regulator_disclosure is not None:
        source_artifacts["regulator_disclosure"] = {
            "disclosure_id": regulator_disclosure.get("disclosure_id"),
            "disclosed_entry_count": regulator_disclosure.get("selection", {}).get("disclosed_entry_count"),
            "content_hash": content_hash(regulator_disclosure),
        }
    if standards_package is not None:
        source_artifacts["standards_submission"] = {
            "package_id": standards_package.get("package_id"),
            "spec_count": len(standards_package.get("specs", [])),
            "content_hash": content_hash(standards_package),
        }

    body = {
        "schema": AUDITOR_CERTIFICATION_SCHEMA,
        "generated_at": utc_now(),
        "program_version": program_version,
        "source_artifacts": source_artifacts,
        "training_modules": _training_modules(),
        "practical_exercises": _practical_exercises(
            has_disclosure=regulator_disclosure is not None,
            has_standards=standards_package is not None,
        ),
        "rubric": {
            "minimum_score_percent": 80,
            "required_module_ids": sorted(REQUIRED_MODULE_IDS),
            "required_exercise_ids": [
                "verify-proof-pack",
                "detect-tamper",
                "review-disclosure",
                "verify-standards-package",
            ],
            "certification_scope": "TrustAI proof-pack verification, selective disclosure, and lifecycle evidence review",
        },
        "limitations": [
            "Local kit only; external auditor certification requires independent program governance.",
            "Exercise commands reference local demo artifacts and should be adapted for production cases.",
        ],
    }
    return {**body, "kit_id": content_hash(body)}


def verify_auditor_certification_kit(
    kit: dict[str, Any],
    *,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    if kit.get("schema") != AUDITOR_CERTIFICATION_SCHEMA:
        errors.append(f"unsupported auditor certification schema: {kit.get('schema')}")
    body = without_keys(kit, "kit_id")
    if kit.get("kit_id") != content_hash(body):
        errors.append("kit_id does not match canonical kit body")

    module_ids = {module.get("id") for module in kit.get("training_modules", []) if isinstance(module, dict)}
    missing_modules = REQUIRED_MODULE_IDS - module_ids
    if missing_modules:
        errors.append(f"required training modules missing: {', '.join(sorted(missing_modules))}")

    exercise_ids = {exercise.get("id") for exercise in kit.get("practical_exercises", []) if isinstance(exercise, dict)}
    for exercise_id in kit.get("rubric", {}).get("required_exercise_ids", []):
        if exercise_id not in exercise_ids:
            errors.append(f"required exercise missing: {exercise_id}")

    sources = kit.get("source_artifacts", {})
    if proof_pack is not None:
        source = sources.get("proof_pack", {})
        if source.get("content_hash") != content_hash(proof_pack):
            errors.append("proof pack source hash mismatch")
        pack_result = verify_proof_pack(proof_pack, key=key)
        if not pack_result.ok:
            errors.extend(f"proof pack invalid: {error}" for error in pack_result.errors)
    else:
        warnings.append("proof pack not supplied for deep verification")

    if regulator_disclosure is not None:
        source = sources.get("regulator_disclosure", {})
        if source.get("content_hash") != content_hash(regulator_disclosure):
            errors.append("regulator disclosure source hash mismatch")
        disclosure_result = verify_regulator_disclosure(regulator_disclosure, key=key)
        if not disclosure_result.ok:
            errors.extend(f"regulator disclosure invalid: {error}" for error in disclosure_result.errors)
    elif "review-disclosure" in exercise_ids:
        warnings.append("regulator disclosure not supplied for deep verification")

    if standards_package is not None:
        source = sources.get("standards_submission", {})
        if source.get("content_hash") != content_hash(standards_package):
            errors.append("standards package source hash mismatch")
        standards_result = verify_standards_submission(standards_package, root=root)
        if not standards_result.ok:
            errors.extend(f"standards package invalid: {error}" for error in standards_result.errors)
    elif "verify-standards-package" in exercise_ids:
        warnings.append("standards package not supplied for deep verification")

    return {"ok": not errors, "errors": errors, "warnings": warnings}


def write_auditor_certification_kit(path: str | Path, kit: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(kit, indent=2, sort_keys=True), encoding="utf-8")


def write_auditor_certification_markdown(path: str | Path, kit: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_auditor_certification_markdown(kit), encoding="utf-8")


def render_auditor_certification_markdown(kit: dict[str, Any]) -> str:
    modules = "\n".join(
        f"- `{module['id']}`: {module['title']}"
        for module in kit.get("training_modules", [])
    )
    exercises = "\n".join(
        f"- `{exercise['id']}`: {exercise['objective']}"
        for exercise in kit.get("practical_exercises", [])
    )
    sources = json.dumps(kit.get("source_artifacts", {}), indent=2, sort_keys=True)
    return f"""# TrustAI Auditor Certification Kit

Kit ID: `{kit.get('kit_id', '')}`

Program version: {kit.get('program_version', '')}

## Source Artifacts

```json
{sources}
```

## Training Modules

{modules}

## Practical Exercises

{exercises}

## Rubric

Minimum score: {kit.get('rubric', {}).get('minimum_score_percent')}%

Scope: {kit.get('rubric', {}).get('certification_scope', '')}
"""


def load_auditor_certification_kit(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _training_modules() -> list[dict[str, Any]]:
    return [
        {
            "id": "proof-pack-verification",
            "title": "Offline Proof Pack Verification",
            "outcomes": [
                "Explain pack ids, signatures, and canonical body hashes.",
                "Run the verifier and interpret warnings versus hard failures.",
            ],
        },
        {
            "id": "evidence-chain-forensics",
            "title": "Evidence Chain and Merkle Inclusion Review",
            "outcomes": [
                "Trace contract, eval, gate, and approval ordering.",
                "Identify payload-hash, entry-id, and inclusion-proof failures.",
            ],
        },
        {
            "id": "selective-disclosure-review",
            "title": "Regulator Selective Disclosure Review",
            "outcomes": [
                "Verify disclosed entries without access to undisclosed tenant log entries.",
                "Check disclosure scope, audience, purpose, and source proof-pack linkage.",
            ],
        },
        {
            "id": "policy-and-lifecycle-review",
            "title": "Runtime Policy and Lifecycle Evidence Review",
            "outcomes": [
                "Assess proof decay, runtime policy decisions, incidents, demotions, and rollbacks.",
                "Separate cryptographic validity from operational freshness.",
            ],
        },
    ]


def _practical_exercises(*, has_disclosure: bool, has_standards: bool) -> list[dict[str, Any]]:
    exercises = [
        {
            "id": "verify-proof-pack",
            "objective": "Verify a proof pack offline and record the gate outcome.",
            "command": "python -m trustai verify artifacts/aitrade-proof-pack.json",
            "expected": "exit 0 and gate outcome passed",
        },
        {
            "id": "detect-tamper",
            "objective": "Demonstrate tamper-evident chain behavior.",
            "command": "python -m trustai tamper-stress-verify artifacts/tamper-stress-report.json",
            "expected": "tamper stress report verifies sampled inclusion proofs and tampered chain entries are rejected",
        },
    ]
    exercises.append(
        {
            "id": "review-disclosure",
            "objective": "Verify a selective-disclosure regulator package.",
            "command": "python -m trustai regulator-verify artifacts/regulator-disclosure.json",
            "expected": "exit 0" if has_disclosure else "requires a regulator disclosure artifact",
        }
    )
    exercises.append(
        {
            "id": "verify-standards-package",
            "objective": "Verify the spec manifest submitted for standards review.",
            "command": "python -m trustai standards-verify artifacts/standards-submission.json",
            "expected": "exit 0" if has_standards else "requires a standards submission artifact",
        }
    )
    return exercises

