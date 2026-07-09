from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any


def render_auditor_html(proof_pack: dict[str, Any]) -> str:
    decision = proof_pack.get("gate_decision", {})
    rows = []
    for check in decision.get("checks", []):
        status = "PASS" if check.get("passed") else "FAIL"
        rows.append(
            "<tr>"
            f"<td>{escape(check.get('name', ''))}</td>"
            f"<td>{escape(status)}</td>"
            f"<td>{escape(str(check.get('actual')))}</td>"
            f"<td>{escape(check.get('operator', ''))} {escape(str(check.get('threshold')))}</td>"
            "</tr>"
        )

    evidence_rows = []
    for entry in proof_pack.get("chain", {}).get("entries", []):
        evidence_rows.append(
            "<tr>"
            f"<td>{escape(str(entry.get('index')))}</td>"
            f"<td>{escape(entry.get('entry_type', ''))}</td>"
            f"<td><code>{escape(entry.get('entry_id', ''))}</code></td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>TrustAI Auditor View</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2933; }}
    h1, h2 {{ margin-bottom: 8px; }}
    code {{ font-size: 12px; word-break: break-all; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0 28px; }}
    th, td {{ border: 1px solid #d8dee4; padding: 8px; text-align: left; }}
    th {{ background: #f5f7fa; }}
    .status {{ font-weight: 700; }}
  </style>
</head>
<body>
  <h1>TrustAI Proof Pack Auditor View</h1>
  <p><strong>Pack ID:</strong> <code>{escape(proof_pack.get('pack_id', ''))}</code></p>
  <p><strong>Agent:</strong> {escape(decision.get('agent', {}).get('name', ''))}</p>
  <p><strong>Contract:</strong> {escape(decision.get('contract_id', ''))}</p>
  <p><strong>Gate outcome:</strong> <span class=\"status\">{escape(decision.get('outcome', 'unknown').upper())}</span></p>
  <p><strong>Chain root:</strong> <code>{escape(proof_pack.get('chain', {}).get('tree', {}).get('root', ''))}</code></p>

  <h2>Metric Checks</h2>
  <table>
    <thead><tr><th>Metric</th><th>Status</th><th>Actual</th><th>Threshold</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>

  <h2>Evidence Entries</h2>
  <table>
    <thead><tr><th>Index</th><th>Type</th><th>Entry ID</th></tr></thead>
    <tbody>{''.join(evidence_rows)}</tbody>
  </table>
</body>
</html>
"""


def write_auditor_html(path: str | Path, proof_pack: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_auditor_html(proof_pack), encoding="utf-8")
