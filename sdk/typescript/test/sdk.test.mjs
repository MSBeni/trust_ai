import assert from "node:assert/strict";
import { test } from "node:test";

import { TrustAIClient, contentHash, normalizeEvent, normalizeEvents } from "../src/index.mjs";

const endpoint = process.env.TRUSTAI_ENDPOINT ?? process.argv[2];
assert.ok(endpoint, "TRUSTAI_ENDPOINT or endpoint CLI argument is required");

const agent = {
  name: "aitrade-risk-agent",
  version: "sha256:0d5bbd8d2357b7d36e0f3f7c5e9a0a3e1f5b7a0d2c4e6f8a9b1c3d5e7f901234",
  risk_class: "trading-prod-write",
};
const contractHash = "22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2";

test("normalizes TrustAI event shape", () => {
  const event = normalizeEvent({
    trace_id: "4F0C98CF84FA44DF9B8AD8F354D2F0A1",
    span_id: "7B1C4D2E9F001122",
    timestamp: "2026-07-03T12:00:10Z",
    event_name: "gen_ai.agent.decision",
    contract_hash: contractHash.toUpperCase(),
    agent,
  });

  assert.equal(event.schema_url, "opentelemetry.semconv.gen_ai/1.0");
  assert.deepEqual(event.attributes, {});
  assert.equal(event.trace_id, "4f0c98cf84fa44df9b8ad8f354d2f0a1");
  assert.equal(event.span_id, "7b1c4d2e9f001122");
  assert.equal(event.contract_hash, contractHash);
});

test("normalizes event batches", () => {
  const events = normalizeEvents([
    {
      trace_id: "4F0C98CF84FA44DF9B8AD8F354D2F0A1",
      span_id: "7B1C4D2E9F001122",
      parent_span_id: "8C2D5E3F00112233",
      timestamp: "2026-07-03T12:00:10Z",
      event_name: "gen_ai.agent.decision",
      contract_hash: contractHash.toUpperCase(),
      agent,
      attributes: { decision: "allow_shadow_order" },
    },
    {
      trace_id: "4F0C98CF84FA44DF9B8AD8F354D2F0A1",
      span_id: "9D3E6F4011223344",
      timestamp: "2026-07-03T12:00:11Z",
      event_name: "gen_ai.tool.call",
      contract_hash: contractHash,
      agent,
      attributes: { "tool.name": "risk_limit_check" },
    },
  ]);

  assert.equal(events.length, 2);
  assert.equal(events[0].parent_span_id, "8c2d5e3f00112233");
  assert.equal(events[1].trace_id, "4f0c98cf84fa44df9b8ad8f354d2f0a1");
  assert.throws(() => normalizeEvents([]), /non-empty array/);
  assert.throws(() => normalizeEvents({}), /non-empty array/);
});

test("rejects malformed evidence identifiers", () => {
  assert.throws(
    () =>
      normalizeEvent({
        trace_id: "trace-ts-001",
        span_id: "7b1c4d2e9f001122",
        timestamp: "2026-07-03T12:00:10Z",
        event_name: "gen_ai.agent.decision",
        contract_hash: contractHash,
        agent,
      }),
    /trace_id/,
  );
  assert.throws(
    () =>
      normalizeEvent({
        trace_id: "00000000000000000000000000000000",
        span_id: "7b1c4d2e9f001122",
        timestamp: "2026-07-03T12:00:10Z",
        event_name: "gen_ai.agent.decision",
        contract_hash: contractHash,
        agent,
      }),
    /trace_id.*all zeros/,
  );
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

  const trace = client.trace("4f0c98cf84fa44df9b8ad8f354d2f0a1");
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
      traceId: "4f0c98cf84fa44df9b8ad8f354d2f0a1",
      spanId: "9d3e6f4011223344",
      timestamp: "2026-07-03T12:00:12Z",
    },
  );
  assert.equal(await wrapped(7500), true);

  const batch = await trace.events([
    {
      eventName: "gen_ai.agent.decision",
      options: {
        attributes: { decision: "batch_allow_shadow_order" },
        spanId: "ae4f701122334455",
        timestamp: "2026-07-03T12:00:13Z",
      },
    },
    {
      eventName: "gen_ai.tool.call",
      options: {
        attributes: { "tool.name": "batch_place_shadow_order", "tool.mode": "shadow" },
        spanId: "bf50812233445566",
        timestamp: "2026-07-03T12:00:14Z",
      },
    },
  ]);
  assert.equal(batch.events.length, 2);
  assert.equal(batch.response.entries.length, 2);
  assert.ok(batch.events.every((event) => event.trace_id === "4f0c98cf84fa44df9b8ad8f354d2f0a1"));
});
