from __future__ import annotations

from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract
from trustai.sdk import TrustAIClient


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
STATE = ROOT / ".trustai" / "sdk-demo" / "evidence-chain.json"


def main() -> None:
    contract = load_contract(CONTRACT)
    client = TrustAIClient.from_contract(contract, state_path=STATE, tenant_id="aitrade-sdk")

    with client.trace("sdk-demo-trace-001") as trace:
        trace.decision(
            "allow_shadow_order",
            attributes={"symbol": "BTCUSDT", "gen_ai.request.model": "gpt-5-mini"},
            span_id="sdkdecis00112233",
            timestamp="2026-07-03T12:00:10Z",
        )
        trace.tool_call(
            "place_shadow_order",
            attributes={"tool.mode": "shadow", "notional_usd": 7500},
            span_id="sdktool00112233",
            timestamp="2026-07-03T12:00:11Z",
        )

    chain = EvidenceChain.load(STATE, tenant_id="aitrade-sdk")
    print(f"sdk evidence chain: {STATE}")
    print(f"entries: {len(chain.entries)}")
    print(f"chain root: {chain.tree()['root']}")


if __name__ == "__main__":
    main()
