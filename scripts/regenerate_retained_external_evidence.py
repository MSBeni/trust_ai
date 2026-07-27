#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from trustai.canonical import content_hash, without_keys
from trustai.external_evidence import (
    build_external_evidence_manifest,
    build_external_evidence_source_map_template,
    build_external_evidence_source_snapshot,
    load_external_evidence_collection_plan,
    parse_evidence_arg,
    verify_external_evidence_manifest,
    verify_external_evidence_source_snapshot,
    write_external_evidence_markdown,
    write_external_evidence_manifest,
    write_external_evidence_source_snapshot,
)
from trustai.roadmap_audit import (
    build_roadmap_audit,
    verify_roadmap_audit,
    write_roadmap_audit,
)

DIR = Path("examples/aitrade/external-evidence")
NOW = "2026-07-12T00:00:00Z"
AUDIT_TIME = "2026-07-12T00:00:00Z"
COLLECTION_TIME = "2026-07-12T00:01:00Z"
MAP_TIME = "2026-07-12T01:00:00Z"

RETAINED_SOURCES: dict[str, dict[str, str]] = {
    "oss-verifier-and-public-spec:ci-run": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions",
        "description": "Snapshot of recorded verifier workflow run export",
        "artifact": "examples/aitrade/external-evidence/github-actions-workflow-run-source-snapshot.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Actions",
        "subject": "trustai go verifier release workflow",
        "issued_at": "2026-07-08T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/github-actions-workflow-run-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/oss-verifier-ci-run.json",
    },
    "oss-verifier-and-public-spec:provider-api": {
        "source_uri": "git+https://github.com/MSBeni/trust_ai.git#refs/heads/main",
        "description": "GitHub remote main ref advertisement for pushed TrustAI checkpoint",
        "artifact": "examples/aitrade/external-evidence/github-main-ref-source-snapshot.json",
        "retrieval_method": "git-ls-remote",
        "content_type": "application/json",
        "issuer": "GitHub Git",
        "subject": "MSBeni/trust_ai main branch",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/github-main-ref-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/oss-verifier-provider-api.json",
    },
    "oss-verifier-and-public-spec:hosted-service": {
        "source_uri": "git+https://github.com/MSBeni/trust_ai.git#HEAD",
        "description": "GitHub hosted git service remote advertisement for TrustAI verifier and spec repository",
        "artifact": "examples/aitrade/external-evidence/github-hosted-service-source-snapshot.json",
        "retrieval_method": "git-ls-remote",
        "content_type": "application/json",
        "issuer": "GitHub Git",
        "subject": "MSBeni/trust_ai hosted repository service",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/github-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/oss-verifier-hosted-service.json",
    },
    "cicd-provider-approvals:ci-run": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions",
        "description": "Retained GitHub check-suite callback export for CI/CD promotion provider evidence",
        "artifact": "examples/aitrade/external-evidence/github-check-suite-source-snapshot.json",
        "source_file": "examples/webhooks/github-check-suite.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Checks",
        "subject": "trustai GitHub check-suite promotion callback",
        "issued_at": "2026-07-08T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/github-check-suite-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/cicd-provider-approvals-ci-run.json",
    },
    "cicd-provider-approvals:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/actions/runs",
        "description": "Retained GitHub audit-log export for CI/CD promotion provider API evidence",
        "artifact": "examples/aitrade/external-evidence/github-audit-log-source-snapshot.json",
        "source_file": "examples/webhooks/github-audit-log.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Audit Log",
        "subject": "trustai GitHub provider audit-log export",
        "issued_at": "2026-07-08T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/github-audit-log-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/cicd-provider-approvals-provider-api.json",
    },
    "framework-adapters:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/contents/examples/aitrade/framework-hook-release.json?ref=main",
        "description": "Retained GitHub contents API export for framework adapter hook release evidence",
        "artifact": "examples/aitrade/external-evidence/framework-hook-release-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/framework-hook-release.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Contents API",
        "subject": "trustai framework hook release export",
        "issued_at": "2026-07-09T00:30:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/framework-hook-release-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/framework-adapters-provider-api.json",
    },
    "framework-adapters:hosted-service": {
        "source_uri": "https://github.com/MSBeni/trust_ai/blob/main/examples/aitrade/framework-hook-release.json",
        "description": "Retained GitHub hosted file export for framework adapter hook release evidence",
        "artifact": "examples/aitrade/external-evidence/framework-hook-release-hosted-service-source-snapshot.json",
        "source_file": "examples/aitrade/framework-hook-release.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Hosted Repository",
        "subject": "trustai framework hook release export",
        "issued_at": "2026-07-09T00:30:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/framework-hook-release-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/framework-adapters-hosted-service.json",
    },
    "agent-inventory-and-identity:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/contents/examples/aitrade/agent-inventory.json?ref=main",
        "description": "Retained GitHub contents API export for agent registry inventory evidence",
        "artifact": "examples/aitrade/external-evidence/agent-inventory-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/agent-inventory.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Contents API",
        "subject": "trustai agent registry inventory export",
        "issued_at": "2026-07-03T11:55:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/agent-inventory-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/agent-inventory-and-identity-provider-api.json",
    },
    "agent-inventory-and-identity:identity-provider": {
        "source_uri": "https://idp.example/exports/aitrade/identity-inventory",
        "description": "Retained identity-provider export for governed agent inventory reconciliation evidence",
        "artifact": "examples/aitrade/external-evidence/identity-inventory-provider-source-snapshot.json",
        "source_file": "examples/aitrade/identity-inventory.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Identity Provider Export",
        "subject": "aitrade governed agent identity inventory",
        "issued_at": "2026-07-03T11:57:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/identity-inventory-provider-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/agent-inventory-and-identity-identity-provider.json",
    },
    "mcp-gateway:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/contents/examples/aitrade/mcp-proxy-events.json?ref=main",
        "description": "Retained GitHub contents API export for MCP gateway proxy event evidence",
        "artifact": "examples/aitrade/external-evidence/mcp-proxy-events-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/mcp-proxy-events.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Contents API",
        "subject": "trustai MCP proxy event export",
        "issued_at": "2026-07-03T12:05:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/mcp-proxy-events-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/mcp-gateway-provider-api.json",
    },
    "mcp-gateway:hosted-service": {
        "source_uri": "https://github.com/MSBeni/trust_ai/blob/main/examples/aitrade/mcp-proxy-events.json",
        "description": "Retained GitHub hosted file export for MCP gateway proxy event evidence",
        "artifact": "examples/aitrade/external-evidence/mcp-proxy-events-hosted-service-source-snapshot.json",
        "source_file": "examples/aitrade/mcp-proxy-events.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Hosted Repository",
        "subject": "trustai MCP proxy event export",
        "issued_at": "2026-07-03T12:05:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/mcp-proxy-events-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/mcp-gateway-hosted-service.json",
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh or verify retained external evidence artifacts.")
    parser.add_argument("--verify-only", action="store_true", help="verify retained artifacts without rewriting them")
    args = parser.parse_args()

    if not args.verify_only:
        refresh_retained_artifacts()
    verify_retained_artifacts()
    print("retained external evidence artifacts verified")
    return 0


def refresh_retained_artifacts() -> None:
    write_deterministic_source_roadmap_audit()
    write_deterministic_source_manifest()
    run(
        "external-evidence-plan",
        path("source-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--status-filter",
        "all",
        "--generated-at",
        MAP_TIME,
        "--out",
        path("source-external-evidence-plan-all.json"),
    )
    write_retained_source_map()
    rebuild_retained_source_snapshots()
    rebuild_retained_intakes()
    write_collection_run_from_retained_intakes()
    run(
        "external-evidence-collect-batch-verify",
        path("retained-external-evidence-collection-run.json"),
        path("source-external-evidence-plan-all.json"),
        path("source-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--source-map",
        path("retained-external-evidence-collected-source-map.json"),
        "--require-fresh",
        "--require-live-source-uris",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
    )
    run(
        "external-evidence-manifest-from-intakes",
        path("source-external-evidence-plan-all.json"),
        path("source-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--intake-dir",
        str(DIR / "intakes"),
        "--require-fresh",
        "--require-live-source-uris",
        "--require-source-snapshot-artifacts",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-manifest.json"),
        "--markdown",
        path("retained-external-evidence-manifest.md"),
    )
    run(
        "external-evidence-plan",
        path("retained-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--generated-at",
        MAP_TIME,
        "--out",
        path("remaining-external-evidence-plan.json"),
        "--markdown",
        path("remaining-external-evidence-plan.md"),
    )
    run(
        "external-evidence-source-map-template",
        path("remaining-external-evidence-plan.json"),
        "--status-filter",
        "missing",
        "--generated-at",
        MAP_TIME,
        "--out",
        path("remaining-external-evidence-source-map-template.json"),
    )
    run(
        "external-evidence-gap-report",
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--require-fresh",
        "--now",
        NOW,
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-gap-report.json"),
        "--markdown",
        path("retained-external-evidence-gap-report.md"),
    )
    run(
        "external-evidence-work-package",
        path("retained-external-evidence-gap-report.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-work-package.json"),
        "--markdown",
        path("remaining-external-evidence-work-package.md"),
    )
    run(
        "external-evidence-owner-packets",
        path("remaining-external-evidence-work-package.json"),
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-owner-packets.json"),
        "--markdown",
        path("remaining-external-evidence-owner-packets.md"),
    )
    run(
        "external-evidence-owner-packet-status",
        path("remaining-external-evidence-owner-packets.json"),
        path("remaining-external-evidence-work-package.json"),
        path("remaining-external-evidence-source-map-template.json"),
        "--root",
        ".",
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-owner-packet-status.json"),
        "--markdown",
        path("remaining-external-evidence-owner-packet-status.md"),
    )
    run(
        "external-evidence-owner-fulfillment-template",
        path("remaining-external-evidence-owner-packet-status.json"),
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-owner-fulfillment-template.json"),
        "--markdown",
        path("remaining-external-evidence-owner-fulfillment-template.md"),
    )
    run(
        "external-evidence-owner-fulfillment-review",
        path("remaining-external-evidence-owner-fulfillment-template.json"),
        path("remaining-external-evidence-owner-packet-status.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("remaining-external-evidence-plan.json"),
        "--root",
        ".",
        "--require-live-source-uris",
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-owner-fulfillment-review.json"),
        "--markdown",
        path("remaining-external-evidence-owner-fulfillment-review.md"),
        "--fulfilled-source-map-out",
        path("remaining-external-evidence-owner-fulfilled-source-map.json"),
    )
    run(
        "external-evidence-owner-fulfillment-closure",
        path("remaining-external-evidence-owner-fulfillment-review.json"),
        path("remaining-external-evidence-owner-packet-status.json"),
        path("retained-external-evidence-manifest.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--require-fresh",
        "--require-live-source-uris",
        "--require-source-snapshot-artifacts",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-owner-fulfillment-closure.json"),
        "--markdown",
        path("remaining-external-evidence-owner-fulfillment-closure.md"),
    )
    run(
        "external-evidence-readiness",
        path("retained-external-evidence-gap-report.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--work-package",
        path("remaining-external-evidence-work-package.json"),
        "--root",
        ".",
        "--require-fresh",
        "--now",
        NOW,
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-readiness.json"),
        "--markdown",
        path("retained-external-evidence-readiness.md"),
    )


def write_deterministic_source_roadmap_audit() -> None:
    audit = build_roadmap_audit(ROOT)
    audit["generated_at"] = AUDIT_TIME
    audit["audit_id"] = content_hash(without_keys(audit, "audit_id"))
    result = verify_roadmap_audit(audit, root=ROOT)
    if not result.ok:
        raise SystemExit("invalid deterministic roadmap audit: " + "; ".join(result.errors))
    write_roadmap_audit(ROOT / DIR / "source-roadmap-audit.json", audit)


def write_deterministic_source_manifest() -> None:
    audit = json_load(DIR / "source-roadmap-audit.json")
    evidence = [
        parse_evidence_arg(
            "oss-verifier-and-public-spec,ci-run,"
            "examples/aitrade/external-evidence/go-verifier-workflow-run.json,"
            "Recorded Go verifier workflow export;"
            "issuer=GitHub Actions;"
            "subject=trustai go verifier release workflow;"
            "source_uri=https://github.com/MSBeni/trust_ai/actions;"
            "issued_at=2026-07-08T00:00:00Z;"
            "expires_at=2026-12-31T00:00:00Z"
        )
    ]
    manifest = build_external_evidence_manifest(
        audit,
        root=ROOT,
        evidence=evidence,
        generated_at=COLLECTION_TIME,
    )
    result = verify_external_evidence_manifest(
        manifest,
        audit,
        root=ROOT,
        require_fresh=True,
        require_live_source_uris=True,
        now=NOW,
    )
    if not result.ok:
        raise SystemExit("invalid deterministic external evidence manifest: " + "; ".join(result.errors))
    write_external_evidence_manifest(ROOT / DIR / "source-external-evidence-manifest.json", manifest)
    write_external_evidence_markdown(ROOT / DIR / "source-external-evidence-manifest.md", manifest)


def write_retained_source_map() -> None:
    plan = load_external_evidence_collection_plan(ROOT / DIR / "source-external-evidence-plan-all.json")
    source_map = build_external_evidence_source_map_template(
        plan,
        status_filter="all",
        limit=None,
        source_uri_template="TODO://authority/{requirement_id}/{authority_kind}",
        description_template="{authority_kind} evidence for {requirement_id}",
        snapshot_dir=str(DIR),
        intake_dir=str(DIR / "intakes"),
        generated_at=MAP_TIME,
    )
    source_map["entries"] = [
        entry for entry in source_map["entries"] if entry.get("unit_ref") in RETAINED_SOURCES
    ]
    for entry in source_map["entries"]:
        unit_ref = entry["unit_ref"]
        retained = RETAINED_SOURCES[unit_ref]
        entry.update(
            {
                "source_uri": retained["source_uri"],
                "description": retained["description"],
                "retrieval_method": retained["retrieval_method"],
                "content_type": retained["content_type"],
                "issuer": retained["issuer"],
                "subject": retained["subject"],
                "issued_at": retained["issued_at"],
                "expires_at": retained["expires_at"],
                "snapshot_out": retained["snapshot_out"],
                "intake_out": retained["intake_out"],
            }
        )
    source_map["summary"]["snapshot_dir"] = str(DIR)
    source_map["summary"]["intake_dir"] = str(DIR / "intakes")
    source_map["summary"]["entry_count"] = len(source_map["entries"])
    source_map["summary"]["placeholder_source_uri_count"] = 0
    source_map["summary"]["live_source_uri_count"] = len(source_map["entries"])
    source_map["source_map_id"] = content_hash(without_keys(source_map, "source_map_id"))
    json_write(DIR / "retained-external-evidence-collected-source-map.json", source_map)


def rebuild_retained_source_snapshots() -> None:
    for retained in RETAINED_SOURCES.values():
        source_file = retained.get("source_file")
        if not source_file:
            continue
        body = (ROOT / source_file).read_bytes()
        snapshot = build_external_evidence_source_snapshot(
            source_uri=retained["source_uri"],
            body=body,
            retrieval_method=retained["retrieval_method"],
            issuer=retained["issuer"],
            subject=retained["subject"],
            content_type=retained["content_type"],
            issued_at=retained["issued_at"],
            expires_at=retained["expires_at"],
            generated_at=COLLECTION_TIME,
        )
        result = verify_external_evidence_source_snapshot(snapshot, require_fresh=True, now=NOW)
        if not result.ok:
            raise SystemExit("invalid retained source snapshot: " + "; ".join(result.errors))
        write_external_evidence_source_snapshot(ROOT / retained["snapshot_out"], snapshot)


def rebuild_retained_intakes() -> None:
    for unit_ref, retained in RETAINED_SOURCES.items():
        run(
            "external-evidence-intake",
            path("source-external-evidence-plan-all.json"),
            path("source-external-evidence-manifest.json"),
            path("source-roadmap-audit.json"),
            "--root",
            ".",
            "--task",
            unit_ref,
            "--artifact",
            retained["artifact"],
            "--description",
            retained["description"],
            "--issuer",
            retained["issuer"],
            "--subject",
            retained["subject"],
            "--source-uri",
            retained["source_uri"],
            "--issued-at",
            retained["issued_at"],
            "--expires-at",
            retained["expires_at"],
            "--require-fresh",
            "--require-live-source-uris",
            "--require-source-snapshot-artifact",
            "--require-fresh-source-snapshot-artifact",
            "--now",
            NOW,
            "--generated-at",
            COLLECTION_TIME,
            "--out",
            retained["intake_out"],
        )


def write_collection_run_from_retained_intakes() -> None:
    source_map_path = DIR / "retained-external-evidence-collected-source-map.json"
    source_map = json_load(source_map_path)
    collected = []
    for entry in source_map["entries"]:
        intake_path = Path(entry["intake_out"])
        snapshot_path = Path(entry["snapshot_out"])
        intake = json_load(intake_path)
        snapshot = json_load(snapshot_path)
        collected.append(
            {
                "evidence_argument": intake["evidence_argument"],
                "intake_id": intake["intake_id"],
                "intake_path": intake_path.as_posix(),
                "snapshot_artifact_path": snapshot_path.as_posix(),
                "snapshot_id": snapshot["snapshot_id"],
                "snapshot_path": snapshot_path.as_posix(),
                "source_uri": entry["source_uri"],
                "task": entry["unit_ref"],
                "warnings": [],
            }
        )
    body = {
        "schema": "trustai.external-evidence-collection-run/0.1",
        "generated_at": COLLECTION_TIME,
        "source_map": {
            "path": source_map_path.as_posix(),
            "source_map_hash": content_hash(source_map),
        },
        "summary": {
            "collected_count": len(collected),
            "task_count": len({item["task"] for item in collected}),
            "require_fresh": True,
        },
        "collected": collected,
    }
    json_write(DIR / "retained-external-evidence-collection-run.json", {**body, "run_id": content_hash(body)})


def verify_retained_artifacts() -> None:
    run(
        "external-evidence-verify",
        path("retained-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--require-fresh",
        "--require-live-source-uris",
        "--require-source-snapshot-artifacts",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
    )
    run(
        "external-evidence-plan-verify",
        path("remaining-external-evidence-plan.json"),
        path("retained-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
    )
    run(
        "external-evidence-source-map-verify",
        path("remaining-external-evidence-source-map-template.json"),
        path("remaining-external-evidence-plan.json"),
    )
    run(
        "external-evidence-collect-batch-verify",
        path("retained-external-evidence-collection-run.json"),
        path("source-external-evidence-plan-all.json"),
        path("source-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--source-map",
        path("retained-external-evidence-collected-source-map.json"),
        "--require-fresh",
        "--require-live-source-uris",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
    )
    run(
        "external-evidence-gap-report-verify",
        path("retained-external-evidence-gap-report.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--require-fresh",
        "--now",
        NOW,
    )
    run(
        "external-evidence-work-package-verify",
        path("remaining-external-evidence-work-package.json"),
        path("retained-external-evidence-gap-report.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
    )
    run(
        "external-evidence-owner-packets-verify",
        path("remaining-external-evidence-owner-packets.json"),
        path("remaining-external-evidence-work-package.json"),
    )
    run(
        "external-evidence-owner-packet-status-verify",
        path("remaining-external-evidence-owner-packet-status.json"),
        path("remaining-external-evidence-owner-packets.json"),
        path("remaining-external-evidence-work-package.json"),
        path("remaining-external-evidence-source-map-template.json"),
        "--root",
        ".",
    )
    run(
        "external-evidence-owner-fulfillment-template-verify",
        path("remaining-external-evidence-owner-fulfillment-template.json"),
        path("remaining-external-evidence-owner-packet-status.json"),
    )
    run(
        "external-evidence-owner-fulfillment-review-verify",
        path("remaining-external-evidence-owner-fulfillment-review.json"),
        path("remaining-external-evidence-owner-fulfillment-template.json"),
        path("remaining-external-evidence-owner-packet-status.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("remaining-external-evidence-plan.json"),
        "--root",
        ".",
        "--require-live-source-uris",
    )
    run(
        "external-evidence-owner-fulfillment-closure-verify",
        path("remaining-external-evidence-owner-fulfillment-closure.json"),
        path("remaining-external-evidence-owner-fulfillment-review.json"),
        path("remaining-external-evidence-owner-packet-status.json"),
        path("retained-external-evidence-manifest.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--require-fresh",
        "--require-live-source-uris",
        "--require-source-snapshot-artifacts",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
    )
    run(
        "external-evidence-readiness-verify",
        path("retained-external-evidence-readiness.json"),
        path("retained-external-evidence-gap-report.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--work-package",
        path("remaining-external-evidence-work-package.json"),
        "--root",
        ".",
    )
    assert_retained_counts()
    verify_retained_collection_chain()


def assert_retained_counts() -> None:
    retained_count = len(RETAINED_SOURCES)
    remaining_count = 71 - retained_count
    manifest = json_load(DIR / "retained-external-evidence-manifest.json")
    plan = json_load(DIR / "remaining-external-evidence-plan.json")
    source_map = json_load(DIR / "remaining-external-evidence-source-map-template.json")
    gap_report = json_load(DIR / "retained-external-evidence-gap-report.json")
    work_package = json_load(DIR / "remaining-external-evidence-work-package.json")
    owner_packets = json_load(DIR / "remaining-external-evidence-owner-packets.json")
    owner_packet_status = json_load(DIR / "remaining-external-evidence-owner-packet-status.json")
    owner_fulfillment_template = json_load(DIR / "remaining-external-evidence-owner-fulfillment-template.json")
    owner_fulfillment_review = json_load(DIR / "remaining-external-evidence-owner-fulfillment-review.json")
    owner_fulfillment_closure = json_load(DIR / "remaining-external-evidence-owner-fulfillment-closure.json")
    owner_fulfilled_source_map = json_load(DIR / "remaining-external-evidence-owner-fulfilled-source-map.json")
    readiness = json_load(DIR / "retained-external-evidence-readiness.json")
    checks = [
        (manifest["summary"]["covered_authority_kind_count"], retained_count, "manifest covered authority kind count"),
        (manifest["summary"]["missing_authority_kind_count"], remaining_count, "manifest missing authority kind count"),
        (plan["summary"]["selected_task_count"], remaining_count, "remaining plan task count"),
        (source_map["summary"]["entry_count"], remaining_count, "source-map entry count"),
        (source_map["summary"]["placeholder_source_uri_count"], remaining_count, "source-map placeholder URI count"),
        (gap_report["summary"]["remaining_task_count"], remaining_count, "gap remaining task count"),
        (work_package["summary"]["task_count"], remaining_count, "work-package task count"),
        (work_package["summary"]["package_count"], 10, "work-package package count"),
        (owner_packets["summary"]["packet_count"], 10, "owner packet count"),
        (owner_packets["summary"]["task_count"], remaining_count, "owner packet task count"),
        (owner_packet_status["summary"]["packet_count"], 10, "owner packet status packet count"),
        (owner_packet_status["summary"]["task_count"], remaining_count, "owner packet status task count"),
        (owner_packet_status["summary"]["closed_task_count"], 0, "owner packet status closed task count"),
        (owner_packet_status["summary"]["blocked_task_count"], remaining_count, "owner packet status blocked task count"),
        (owner_fulfillment_template["summary"]["fulfillment_count"], remaining_count, "owner fulfillment template count"),
        (owner_fulfillment_template["summary"]["placeholder_source_uri_count"], remaining_count, "owner fulfillment template placeholder URI count"),
        (owner_fulfillment_review["summary"]["review_status"], "blocked", "owner fulfillment review status"),
        (owner_fulfillment_review["summary"]["blocked_task_count"], remaining_count, "owner fulfillment review blocked task count"),
        (owner_fulfillment_review["summary"]["placeholder_source_uri_count"], remaining_count, "owner fulfillment review placeholder URI count"),
        (owner_fulfillment_review["summary"]["fulfilled_source_map_verification_ok"], False, "owner fulfillment review source-map verification status"),
        (owner_fulfilled_source_map["summary"]["placeholder_source_uri_count"], remaining_count, "owner fulfilled source-map placeholder URI count"),
        (owner_fulfillment_closure["summary"]["closure_status"], "blocked", "owner fulfillment closure status"),
        (owner_fulfillment_closure["summary"]["task_count"], remaining_count, "owner fulfillment closure task count"),
        (owner_fulfillment_closure["summary"]["closed_task_count"], 0, "owner fulfillment closure closed task count"),
        (owner_fulfillment_closure["summary"]["missing_intake_count"], remaining_count, "owner fulfillment closure missing intake count"),
        (owner_fulfillment_closure["summary"]["missing_manifest_coverage_count"], remaining_count, "owner fulfillment closure missing manifest coverage count"),
        (owner_fulfillment_closure["summary"]["placeholder_source_uri_count"], remaining_count, "owner fulfillment closure placeholder URI count"),
        (readiness["summary"]["readiness_status"], "not-ready", "readiness status"),
    ]
    for actual, expected, label in checks:
        if actual != expected:
            raise SystemExit(f"{label} expected {expected!r}, got {actual!r}")


def verify_retained_collection_chain() -> None:
    with tempfile.TemporaryDirectory(prefix="trustai-retained-chain-") as tmp:
        tmp_path = Path(tmp)
        state = tmp_path / "evidence-chain.json"
        tenant = "retained-collection-run-script-check"
        run(
            "roadmap-audit-append",
            path("source-roadmap-audit.json"),
            "--state",
            str(state),
            "--tenant",
            tenant,
            "--out",
            str(tmp_path / "roadmap-audit-entry.json"),
        )
        collection_entry = tmp_path / "collection-run-entry.json"
        run(
            "external-evidence-collect-batch-append",
            path("retained-external-evidence-collection-run.json"),
            path("source-external-evidence-plan-all.json"),
            path("source-external-evidence-manifest.json"),
            path("source-roadmap-audit.json"),
            "--root",
            ".",
            "--source-map",
            path("retained-external-evidence-collected-source-map.json"),
            "--require-fresh",
            "--require-live-source-uris",
            "--require-fresh-source-snapshot-artifacts",
            "--now",
            NOW,
            "--state",
            str(state),
            "--tenant",
            tenant,
            "--out",
            str(collection_entry),
        )
        run("roadmap-evidence-verify", "--state", str(state), "--tenant", tenant)
        report = tmp_path / "roadmap-evidence-report.json"
        run(
            "roadmap-evidence-report",
            "--state",
            str(state),
            "--tenant",
            tenant,
            "--out",
            str(report),
            "--markdown",
            str(tmp_path / "roadmap-evidence-report.md"),
        )
        bundle = tmp_path / "roadmap-evidence-bundle.json"
        run(
            "roadmap-evidence-bundle",
            "--state",
            str(state),
            "--tenant",
            tenant,
            "--report",
            str(report),
            "--root",
            ".",
            "--source-artifact",
            "roadmap-audit,examples/aitrade/external-evidence/source-roadmap-audit.json,Retained source roadmap audit JSON",
            "--source-artifact",
            "external-evidence-collection-run,examples/aitrade/external-evidence/retained-external-evidence-collection-run.json,Retained collection-run report JSON",
            "--include-collection-run-artifacts",
            "--require-source-artifacts",
            "--out",
            str(bundle),
            "--markdown",
            str(tmp_path / "roadmap-evidence-bundle.md"),
        )
        run("roadmap-evidence-bundle-verify", str(bundle), "--require-source-artifacts")
        entry = json_load(collection_entry)
        bundle_value = json_load(bundle)
        retained_count = len(RETAINED_SOURCES)
        expected_source_artifacts = 3 + (2 * retained_count)
        if entry["payload"]["collected_count"] != retained_count:
            raise SystemExit(f"retained collection-run chain entry did not record {retained_count} collected receipts")
        if bundle_value["summary"]["source_artifact_count"] != expected_source_artifacts:
            raise SystemExit(f"retained collection-run bundle did not include {expected_source_artifacts} source artifacts")


def run(*args: str) -> None:
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    subprocess.run([sys.executable, "-m", "trustai", *args], cwd=ROOT, env=env, check=True)


def path(name: str) -> str:
    return (DIR / name).as_posix()


def json_load(path_value: str | Path) -> dict[str, Any]:
    return json.loads((ROOT / path_value).read_text(encoding="utf-8"))


def json_write(path_value: str | Path, value: dict[str, Any]) -> None:
    target = ROOT / path_value
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
