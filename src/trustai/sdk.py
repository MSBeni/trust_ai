from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from secrets import token_hex
from typing import Any, Callable, Iterator

from .canonical import utc_now
from .chain import EvidenceChain
from .contracts import contract_hash
from .ingest import append_events, normalize_event


def new_trace_id() -> str:
    return token_hex(16)


def new_span_id() -> str:
    return token_hex(8)


@dataclass
class CaptureResult:
    event: dict[str, Any]
    entry: dict[str, Any] | None = None
    response: dict[str, Any] | None = None


class TrustAIClient:
    def __init__(
        self,
        agent: dict[str, Any],
        contract_hash: str,
        *,
        state_path: str | Path | None = None,
        endpoint: str | None = None,
        tenant_id: str = "local",
        key: str | None = None,
        risk_class: str | None = None,
        schema_url: str = "opentelemetry.semconv.gen_ai/1.0",
        timeout: float = 5.0,
    ):
        if not agent.get("name") or not agent.get("version"):
            raise ValueError("agent must include name and version")
        if not contract_hash:
            raise ValueError("contract_hash is required")
        if not state_path and not endpoint:
            raise ValueError("state_path or endpoint is required")
        self.agent = json.loads(json.dumps(agent, sort_keys=True))
        self.contract_hash = contract_hash
        self.state_path = Path(state_path) if state_path else None
        self.endpoint = endpoint.rstrip("/") if endpoint else None
        self.tenant_id = tenant_id
        self.key = key
        self.risk_class = risk_class or agent.get("risk_class")
        self.schema_url = schema_url
        self.timeout = timeout

    @classmethod
    def from_contract(
        cls,
        contract: dict[str, Any],
        *,
        state_path: str | Path | None = None,
        endpoint: str | None = None,
        tenant_id: str = "local",
        key: str | None = None,
        timeout: float = 5.0,
    ) -> "TrustAIClient":
        return cls(
            contract["agent"],
            contract_hash(contract),
            state_path=state_path,
            endpoint=endpoint,
            tenant_id=tenant_id,
            key=key,
            risk_class=contract["agent"].get("risk_class"),
            timeout=timeout,
        )

    def build_event(
        self,
        event_name: str,
        *,
        attributes: dict[str, Any] | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
        timestamp: str | None = None,
        risk_class: str | None = None,
    ) -> dict[str, Any]:
        return normalize_event(
            {
                "trace_id": trace_id or new_trace_id(),
                "span_id": span_id or new_span_id(),
                "timestamp": timestamp or utc_now(),
                "event_name": event_name,
                "schema_url": self.schema_url,
                "contract_hash": self.contract_hash,
                "agent": self.agent,
                "risk_class": risk_class or self.risk_class,
                "attributes": attributes or {},
            }
        )

    def emit_event(
        self,
        event_name: str,
        *,
        attributes: dict[str, Any] | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
        timestamp: str | None = None,
        risk_class: str | None = None,
    ) -> CaptureResult:
        event = self.build_event(
            event_name,
            attributes=attributes,
            trace_id=trace_id,
            span_id=span_id,
            timestamp=timestamp,
            risk_class=risk_class,
        )
        entry = self._append_local(event) if self.state_path else None
        response = self._post_remote(event) if self.endpoint else None
        return CaptureResult(event=event, entry=entry, response=response)

    def record_decision(
        self,
        decision: str,
        *,
        attributes: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> CaptureResult:
        payload = {"decision": decision, **(attributes or {})}
        return self.emit_event("gen_ai.agent.decision", attributes=payload, **kwargs)

    def record_tool_call(
        self,
        tool_name: str,
        *,
        attributes: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> CaptureResult:
        payload = {"tool.name": tool_name, **(attributes or {})}
        return self.emit_event("gen_ai.tool.call", attributes=payload, **kwargs)

    @contextmanager
    def trace(self, trace_id: str | None = None) -> Iterator["TraceCapture"]:
        capture = TraceCapture(self, trace_id or new_trace_id())
        yield capture

    def instrument_tool(self, tool_name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                started = time.perf_counter()
                trace_id = kwargs.pop("trustai_trace_id", None)
                span_id = kwargs.pop("trustai_span_id", None)
                try:
                    result = func(*args, **kwargs)
                except Exception as exc:
                    self.record_tool_call(
                        tool_name,
                        attributes={
                            "tool.status": "error",
                            "error.type": exc.__class__.__name__,
                            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                        },
                        trace_id=trace_id,
                        span_id=span_id,
                    )
                    raise
                self.record_tool_call(
                    tool_name,
                    attributes={
                        "tool.status": "ok",
                        "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                    },
                    trace_id=trace_id,
                    span_id=span_id,
                )
                return result

            return wrapper

        return decorator

    def _append_local(self, event: dict[str, Any]) -> dict[str, Any]:
        if self.state_path is None:
            raise ValueError("state_path is not configured")
        chain = EvidenceChain.load(self.state_path, tenant_id=self.tenant_id)
        entry = append_events(chain, [event], key=self.key)[0]
        chain.save()
        return entry

    def _post_remote(self, event: dict[str, Any]) -> dict[str, Any]:
        if self.endpoint is None:
            raise ValueError("endpoint is not configured")
        body = json.dumps({"events": [event]}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.endpoint}/v0/ingest",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8")
            raise RuntimeError(f"TrustAI ingest failed with HTTP {exc.code}: {detail}") from exc


class TraceCapture:
    def __init__(self, client: TrustAIClient, trace_id: str):
        self.client = client
        self.trace_id = trace_id

    def event(self, event_name: str, *, attributes: dict[str, Any] | None = None, **kwargs: Any) -> CaptureResult:
        return self.client.emit_event(event_name, attributes=attributes, trace_id=self.trace_id, **kwargs)

    def decision(self, decision: str, *, attributes: dict[str, Any] | None = None, **kwargs: Any) -> CaptureResult:
        return self.client.record_decision(decision, attributes=attributes, trace_id=self.trace_id, **kwargs)

    def tool_call(self, tool_name: str, *, attributes: dict[str, Any] | None = None, **kwargs: Any) -> CaptureResult:
        return self.client.record_tool_call(tool_name, attributes=attributes, trace_id=self.trace_id, **kwargs)
