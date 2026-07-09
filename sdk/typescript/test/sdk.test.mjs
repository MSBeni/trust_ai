import assert from "node:assert/strict";
import { test } from "node:test";

import { TrustAIClient, contentHash, normalizeEvent } from "../src/index.mjs";

const endpoint = process.env.TRUSTAI_ENDPOINT;
assert.ok(endpoint, "TRUSTAI_ENDPOINT is required");

const agent = {
  name: "aitrade-risk-agent",
  version: "sha256:0d5bbd8d2357b7d36e0f3f7c5e9a0a3e1f5b7a0d2c4e6f8a9b1c3d5e7f901234",
  risk_class: "trading-prod-write",
};
const contractHash = "22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2";

test("normalizes TrustAI event shape", () => {
  const event = normalizeEvent({
    trace_id: "4f0c98cf84fa44df9b8ad8f354d2f0a1",
    span_id: "7b1c4d2e9f001122",
    timestamp: "2026-07-03T12:00:10Z",
    event_name: "gen_ai.agent.decision",
    contract_hash: contractHash,
    agent,
  });

  assert.equal(event.schema_url, "opentelemetry.semconv.gen_ai/1.0");
  assert.deepEqual(event.attributes, {});
});

test("computes canonical content hashes for JSON objects", () => {
  assert.equal(contentHash({ b: 2, a: 1 }), contentHash({ a: 1, b: 2 }));
});

test("posts decision and tool events to TrustAI ingest API", async () => {
  const client = new TrustAIClient({ agent, contractHash, endpoint });

  const decision = await client.recordDecision("allow_shadow_order", {
    attributes: { symbol: "BTCUSDT" },
    traceId: "4f0c98cf84fa44df9b8ad8f354d2f0a1",
    spanId: "7b1c4d2e9f001122",
    timestamp: "2026-07-03T12:00:10Z",
  });
  assert.equal(decision.event.event_name, "gen_ai.agent.decision");
  assert.equal(decision.response.entries.length, 1);

  const trace = client.trace("trace-ts-001");
  const tool = await trace.toolCall("place_shadow_order", {
    attributes: { "tool.mode": "shadow", notional_usd: 7500 },
    spanId: "8c2d5e3f00112233",
    timestamp: "2026-07-03T12:00:11Z",
  });
  assert.equal(tool.event.attributes["tool.name"], "place_shadow_order");
  assert.equal(tool.response.entries.length, 1);

  const wrapped = client.instrumentTool(
    "risk_limit_check",
    async (notionalUsd) => notionalUsd < 10000,
    {
      traceId: "trace-ts-001",
      spanId: "span-ts-003",
      timestamp: "2026-07-03T12:00:12Z",
    },
  );
  assert.equal(await wrapped(7500), true);
});
