import { createHash, randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";

export const DEFAULT_SCHEMA_URL = "opentelemetry.semconv.gen_ai/1.0";
const HEX_PATTERN = /^[0-9a-f]+$/i;

export function newTraceId() {
  return randomBytes(16).toString("hex");
}

export function newSpanId() {
  return randomBytes(8).toString("hex");
}

export function utcNow() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .filter((key) => value[key] !== undefined)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export function canonicalStringify(value) {
  return JSON.stringify(canonicalize(value));
}

export function contentHash(value) {
  return createHash("sha256").update(canonicalStringify(value), "utf8").digest("hex");
}

export function normalizeEvent(event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    throw new Error("event must be an object");
  }
  const required = ["trace_id", "span_id", "timestamp", "event_name", "agent", "contract_hash"];
  const missing = required.filter((field) => !event[field]);
  if (missing.length) {
    throw new Error(`event missing required fields: ${missing.join(", ")}`);
  }
  if (Number.isNaN(Date.parse(event.timestamp))) {
    throw new Error("event timestamp must be RFC3339-compatible");
  }
  const traceId = canonicalHex(event.trace_id, "trace_id", 32);
  const spanId = canonicalHex(event.span_id, "span_id", 16);
  const parentSpanId =
    event.parent_span_id === undefined || event.parent_span_id === null || event.parent_span_id === ""
      ? undefined
      : canonicalHex(event.parent_span_id, "parent_span_id", 16);
  const contractHash = canonicalHex(event.contract_hash, "contract_hash", 64);
  if (typeof event.event_name !== "string" || !event.event_name.trim()) {
    throw new Error("event.event_name must be a non-empty string");
  }
  if (!event.agent?.name || !event.agent?.version) {
    throw new Error("event.agent must include name and version");
  }
  const normalized = {
    ...JSON.parse(JSON.stringify(event)),
    trace_id: traceId,
    span_id: spanId,
    contract_hash: contractHash,
    schema_url: event.schema_url ?? DEFAULT_SCHEMA_URL,
    attributes: event.attributes ?? {},
  };
  if (parentSpanId) {
    normalized.parent_span_id = parentSpanId;
  }
  return normalized;
}

export function normalizeEvents(events) {
  if (!Array.isArray(events) || events.length === 0) {
    throw new Error("events must be a non-empty array");
  }
  return events.map((event) => normalizeEvent(event));
}

function canonicalHex(value, field, length) {
  if (typeof value !== "string" || value.length !== length || !HEX_PATTERN.test(value)) {
    throw new Error(`event.${field} must be a ${length}-character hexadecimal string`);
  }
  if (/^0+$/.test(value)) {
    throw new Error(`event.${field} must not be all zeros`);
  }
  return value.toLowerCase();
}

export class TrustAIClient {
  constructor(options) {
    const {
      agent,
      contractHash,
      endpoint,
      riskClass,
      schemaUrl = DEFAULT_SCHEMA_URL,
      timeoutMs = 5000,
      fetchImpl = globalThis.fetch,
    } = options ?? {};
    if (!agent?.name || !agent?.version) {
      throw new Error("agent must include name and version");
    }
    if (!contractHash) {
      throw new Error("contractHash is required");
    }
    if (typeof endpoint !== "string" || !endpoint) {
      throw new Error("endpoint is required");
    }
    if (typeof fetchImpl !== "function") {
      throw new Error("fetch implementation is required");
    }
    this.agent = JSON.parse(JSON.stringify(agent));
    this.contractHash = contractHash;
    let end = endpoint.length;
    while (end > 0 && endpoint.charCodeAt(end - 1) === 47) {
      end -= 1;
    }
    this.endpoint = endpoint.slice(0, end);
    this.riskClass = riskClass ?? agent.risk_class;
    this.schemaUrl = schemaUrl;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
  }

  static fromContract(contract, options = {}) {
    if (!contract?.agent) {
      throw new Error("contract must include agent");
    }
    return new TrustAIClient({
      ...options,
      agent: contract.agent,
      contractHash: options.contractHash ?? contentHash(contract),
      riskClass: options.riskClass ?? contract.agent.risk_class,
    });
  }

  buildEvent(eventName, options = {}) {
    return normalizeEvent({
      trace_id: options.traceId ?? newTraceId(),
      span_id: options.spanId ?? newSpanId(),
      timestamp: options.timestamp ?? utcNow(),
      event_name: eventName,
      schema_url: this.schemaUrl,
      contract_hash: this.contractHash,
      agent: this.agent,
      risk_class: options.riskClass ?? this.riskClass,
      attributes: options.attributes ?? {},
    });
  }

  buildEvents(eventDefinitions) {
    if (!Array.isArray(eventDefinitions) || eventDefinitions.length === 0) {
      throw new Error("eventDefinitions must be a non-empty array");
    }
    return eventDefinitions.map((definition) => {
      if (!definition || typeof definition !== "object" || Array.isArray(definition)) {
        throw new Error("event definition must be an object");
      }
      const { eventName, options = {} } = definition;
      if (typeof eventName !== "string" || !eventName.trim()) {
        throw new Error("event definition eventName is required");
      }
      return this.buildEvent(eventName, options);
    });
  }

  async emitEvent(eventName, options = {}) {
    const event = this.buildEvent(eventName, options);
    const response = await this.postEvent(event);
    return { event, response };
  }

  async emitEvents(eventDefinitions) {
    const events = this.buildEvents(eventDefinitions);
    const response = await this.postEvents(events);
    return { events, response };
  }

  async recordDecision(decision, options = {}) {
    return this.emitEvent("gen_ai.agent.decision", {
      ...options,
      attributes: { decision, ...(options.attributes ?? {}) },
    });
  }

  async recordToolCall(toolName, options = {}) {
    return this.emitEvent("gen_ai.tool.call", {
      ...options,
      attributes: { "tool.name": toolName, ...(options.attributes ?? {}) },
    });
  }

  trace(traceId = newTraceId()) {
    return new TraceCapture(this, traceId);
  }

  instrumentTool(toolName, fn, options = {}) {
    return async (...args) => {
      const started = performance.now();
      try {
        const result = await fn(...args);
        await this.recordToolCall(toolName, {
          ...options,
          attributes: {
            "tool.status": "ok",
            latency_ms: Number((performance.now() - started).toFixed(3)),
            ...(options.attributes ?? {}),
          },
        });
        return result;
      } catch (error) {
        await this.recordToolCall(toolName, {
          ...options,
          attributes: {
            "tool.status": "error",
            "error.type": error?.constructor?.name ?? "Error",
            latency_ms: Number((performance.now() - started).toFixed(3)),
            ...(options.attributes ?? {}),
          },
        });
        throw error;
      }
    };
  }

  async postEvent(event) {
    return this.postEvents([event]);
  }

  async postEvents(events) {
    const normalizedEvents = normalizeEvents(events);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.endpoint}/v0/ingest`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ events: normalizedEvents }),
        signal: controller.signal,
      });
      const text = await response.text();
      const body = text ? JSON.parse(text) : {};
      if (!response.ok) {
        throw new Error(`TrustAI ingest failed with HTTP ${response.status}: ${text}`);
      }
      return body;
    } finally {
      clearTimeout(timer);
    }
  }
}

export class TraceCapture {
  constructor(client, traceId) {
    this.client = client;
    this.traceId = traceId;
  }

  event(eventName, options = {}) {
    return this.client.emitEvent(eventName, { ...options, traceId: this.traceId });
  }

  events(eventDefinitions) {
    if (!Array.isArray(eventDefinitions)) {
      throw new Error("eventDefinitions must be an array");
    }
    return this.client.emitEvents(
      eventDefinitions.map((definition) => ({
        ...definition,
        options: { ...(definition.options ?? {}), traceId: this.traceId },
      })),
    );
  }

  decision(decision, options = {}) {
    return this.client.recordDecision(decision, { ...options, traceId: this.traceId });
  }

  toolCall(toolName, options = {}) {
    return this.client.recordToolCall(toolName, { ...options, traceId: this.traceId });
  }
}
