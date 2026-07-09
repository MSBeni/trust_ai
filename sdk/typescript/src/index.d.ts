export interface TrustAIAgent {
  name: string;
  version: string;
  risk_class?: string;
  [key: string]: unknown;
}

export interface TrustAIEvent {
  trace_id: string;
  span_id: string;
  timestamp: string;
  event_name: string;
  schema_url: string;
  contract_hash: string;
  agent: TrustAIAgent;
  risk_class?: string;
  attributes: Record<string, unknown>;
}

export interface CaptureResult {
  event: TrustAIEvent;
  response: Record<string, unknown>;
}

export interface ClientOptions {
  agent: TrustAIAgent;
  contractHash: string;
  endpoint: string;
  riskClass?: string;
  schemaUrl?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export interface FromContractOptions extends Omit<ClientOptions, "agent" | "contractHash"> {
  contractHash?: string;
}

export interface BuildEventOptions {
  attributes?: Record<string, unknown>;
  traceId?: string;
  spanId?: string;
  timestamp?: string;
  riskClass?: string;
}

export interface InstrumentOptions extends BuildEventOptions {}

export const DEFAULT_SCHEMA_URL: string;

export function newTraceId(): string;
export function newSpanId(): string;
export function utcNow(): string;
export function canonicalStringify(value: unknown): string;
export function contentHash(value: unknown): string;
export function normalizeEvent(event: Partial<TrustAIEvent>): TrustAIEvent;

export class TrustAIClient {
  constructor(options: ClientOptions);
  static fromContract(contract: { agent: TrustAIAgent; [key: string]: unknown }, options: FromContractOptions): TrustAIClient;
  buildEvent(eventName: string, options?: BuildEventOptions): TrustAIEvent;
  emitEvent(eventName: string, options?: BuildEventOptions): Promise<CaptureResult>;
  recordDecision(decision: string, options?: BuildEventOptions): Promise<CaptureResult>;
  recordToolCall(toolName: string, options?: BuildEventOptions): Promise<CaptureResult>;
  trace(traceId?: string): TraceCapture;
  instrumentTool<TArgs extends unknown[], TResult>(
    toolName: string,
    fn: (...args: TArgs) => TResult | Promise<TResult>,
    options?: InstrumentOptions,
  ): (...args: TArgs) => Promise<TResult>;
  postEvent(event: TrustAIEvent): Promise<Record<string, unknown>>;
}

export class TraceCapture {
  constructor(client: TrustAIClient, traceId: string);
  readonly traceId: string;
  event(eventName: string, options?: BuildEventOptions): Promise<CaptureResult>;
  decision(decision: string, options?: BuildEventOptions): Promise<CaptureResult>;
  toolCall(toolName: string, options?: BuildEventOptions): Promise<CaptureResult>;
}
