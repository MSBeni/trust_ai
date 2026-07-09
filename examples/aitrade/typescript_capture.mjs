import { TrustAIClient } from "../../sdk/typescript/src/index.mjs";

const endpoint = process.env.TRUSTAI_ENDPOINT ?? "http://127.0.0.1:8080";

const client = new TrustAIClient({
  endpoint,
  contractHash: "22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2",
  agent: {
    name: "aitrade-risk-agent",
    version: "sha256:0d5bbd8d2357b7d36e0f3f7c5e9a0a3e1f5b7a0d2c4e6f8a9b1c3d5e7f901234",
    risk_class: "trading-prod-write",
  },
});

const decision = await client.recordDecision("allow_shadow_order", {
  attributes: { symbol: "BTCUSDT" },
  traceId: "4f0c98cf84fa44df9b8ad8f354d2f0a1",
  spanId: "7b1c4d2e9f001122",
  timestamp: "2026-07-03T12:00:10Z",
});

const trace = client.trace("4f0c98cf84fa44df9b8ad8f354d2f0a1");
const tool = await trace.toolCall("place_shadow_order", {
  attributes: { "tool.mode": "shadow", notional_usd: 7500 },
  spanId: "8c2d5e3f00112233",
  timestamp: "2026-07-03T12:00:11Z",
});

console.log(
  JSON.stringify(
    {
      endpoint,
      entries: [...decision.response.entries, ...tool.response.entries],
    },
    null,
    2,
  ),
);
