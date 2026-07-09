from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from .regulator import RegulatorVerification, verify_regulator_disclosure


def render_regulator_html(
    disclosure: dict[str, Any],
    verification: RegulatorVerification | None = None,
) -> str:
    verification = verification or verify_regulator_disclosure(disclosure)
    source = disclosure.get("source_proof_pack", {})
    agent = source.get("agent", {})
    selection = disclosure.get("selection", {})
    tree = disclosure.get("chain", {}).get("tree", {})

    entry_rows = []
    for entry in disclosure.get("chain", {}).get("entries", []):
        entry_rows.append(
            "<tr>"
            f"<td>{escape(str(entry.get('index')))}</td>"
            f"<td>{escape(entry.get('entry_type', ''))}</td>"
            f"<td>{escape(entry.get('timestamp', ''))}</td>"
            f"<td><code>{escape(entry.get('entry_id', ''))}</code></td>"
            f"<td><code>{escape(entry.get('payload_hash', ''))}</code></td>"
            "</tr>"
        )

    error_items = "".join(f"<li>{escape(error)}</li>" for error in verification.errors)
    warning_items = "".join(f"<li>{escape(warning)}</li>" for warning in verification.warnings)
    status = "VERIFIED" if verification.ok else "FAILED"

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>TrustAI Regulator Disclosure View</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2933; }}
    h1, h2 {{ margin-bottom: 8px; }}
    code {{ font-size: 12px; word-break: break-all; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0 28px; }}
    th, td {{ border: 1px solid #d8dee4; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f5f7fa; }}
    .status {{ font-weight: 700; }}
    .verified {{ color: #176f3d; }}
    .failed {{ color: #b42318; }}
  </style>
</head>
<body>
  <h1>TrustAI Regulator Disclosure View</h1>
  <p><strong>Status:</strong> <span class=\"status {'verified' if verification.ok else 'failed'}\">{escape(status)}</span></p>
  <p><strong>Disclosure ID:</strong> <code>{escape(disclosure.get('disclosure_id', ''))}</code></p>
  <p><strong>Audience:</strong> {escape(disclosure.get('audience', ''))}</p>
  <p><strong>Purpose:</strong> {escape(disclosure.get('purpose', ''))}</p>
  <p><strong>Issued at:</strong> {escape(disclosure.get('issued_at', ''))}</p>

  <h2>Source Proof Pack</h2>
  <p><strong>Pack ID:</strong> <code>{escape(source.get('pack_id', ''))}</code></p>
  <p><strong>Contract:</strong> {escape(source.get('contract_id', ''))}</p>
  <p><strong>Agent:</strong> {escape(agent.get('name', ''))}</p>
  <p><strong>Gate outcome:</strong> {escape(source.get('gate_outcome', ''))}</p>

  <h2>Disclosure Scope</h2>
  <p><strong>Disclosed entries:</strong> {escape(str(selection.get('disclosed_entry_count', '')))}</p>
  <p><strong>Omitted entries:</strong> {escape(str(selection.get('omitted_entry_count', '')))}</p>
  <p><strong>Chain root:</strong> <code>{escape(tree.get('root', ''))}</code></p>
  <p><strong>Tree size:</strong> {escape(str(tree.get('size', '')))}</p>

  <h2>Verification Messages</h2>
  <p><strong>Errors:</strong></p>
  <ul>{error_items or '<li>None</li>'}</ul>
  <p><strong>Warnings:</strong></p>
  <ul>{warning_items or '<li>None</li>'}</ul>

  <h2>Disclosed Evidence Entries</h2>
  <table>
    <thead><tr><th>Index</th><th>Type</th><th>Timestamp</th><th>Entry ID</th><th>Payload Hash</th></tr></thead>
    <tbody>{''.join(entry_rows)}</tbody>
  </table>
</body>
</html>
"""


def write_regulator_html(
    path: str | Path,
    disclosure: dict[str, Any],
    verification: RegulatorVerification | None = None,
) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_regulator_html(disclosure, verification), encoding="utf-8")
