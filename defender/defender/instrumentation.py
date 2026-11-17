"""B.3 — instrumentation of the defender: the agent's view, captured from inside.

Framework-agnostic: any driver (Claude Agent SDK hooks, the scripted stand-in, a future
OpenHands adapter) calls the four methods below. Each produces one OpenTelemetry span that
follows the pinned GenAI conventions and carries the spec 1.3 event in lab.event.* attributes.
The spans go to Langfuse; the observer later pulls them from there into C3.

What is captured, and nothing else:
    tool_call        {tool, args, result_summary}     args and results are size-capped
    decision         short form of the intent
    incident_report  the fixed schema
    state_snapshot   dump of the agent's notes

This module has no method that accepts a prompt, a message or a transcript, so the model's
context cannot be logged through it. This is the agent's SELF-REPORT — never ground truth.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from typing import Any

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from labcontracts import telemetry

from . import semconv as sc

log = logging.getLogger("defender.telemetry")

MAX_ARG_CHARS = 500            # per string argument
MAX_RESULT_CHARS = 400         # result_summary
MAX_INTENT_CHARS = 300
MAX_NOTES_CHARS = 200_000
AGENT_NAME = "defender"


def clip(value: Any, limit: int) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"… [{len(value) - limit} more chars]"
    return value


def summarise_args(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Arguments as logged: strings clipped; file bodies and notes reduced to size + hash."""
    out: dict[str, Any] = {}
    for key, value in args.items():
        if key == "intent":
            continue                                    # logged separately as the decision
        if key in ("content", "text") and isinstance(value, str):
            out[key] = {"chars": len(value), "sha256": hashlib.sha256(value.encode()).hexdigest()[:16]}
        elif isinstance(value, (dict, list)):
            out[key] = clip(json.dumps(value, ensure_ascii=False), MAX_ARG_CHARS)
        else:
            out[key] = clip(value, MAX_ARG_CHARS)
    return out


class Telemetry:
    def __init__(self, run_id: str, langfuse_host: str, public_key: str, secret_key: str, model: str) -> None:
        self.run_id, self.model = run_id, model
        self.seq = telemetry.SeqCounter()
        self.counts: dict[str, int] = {}
        auth = base64.b64encode(f"{public_key}:{secret_key}".encode()).decode()
        self.provider = TracerProvider(resource=Resource.create(
            {"service.name": AGENT_NAME, "service.namespace": "agent-ops-lab"}))
        self.provider.add_span_processor(BatchSpanProcessor(
            OTLPSpanExporter(endpoint=f"{langfuse_host}/api/public/otel/v1/traces",
                             headers={"Authorization": f"Basic {auth}"}, timeout=15),
            schedule_delay_millis=2000, max_queue_size=8192))
        self.tracer = self.provider.get_tracer("agent-ops-lab.defender", "0.1.0", schema_url=sc.SCHEMA_URL)

    # ------------------------------------------------------------------ plumbing
    def _emit(self, type_: str, payload: dict[str, Any], span_name: str, attributes: dict[str, Any],
              start: float | None = None, end: float | None = None) -> None:
        now = time.time()
        end = end or now
        start = start or end
        event = telemetry.make_event(self.run_id, "defender", type_, self.seq.next(), payload,
                                     ts=telemetry.utc_now())      # validates against the 1.3 contract
        attrs = {sc.GEN_AI_PROVIDER_NAME: sc.PROVIDER_ANTHROPIC, sc.GEN_AI_AGENT_NAME: AGENT_NAME,
                 sc.GEN_AI_CONVERSATION_ID: self.run_id, sc.LANGFUSE_SESSION_ID: self.run_id,
                 sc.LAB_RUN_ID: self.run_id, sc.LAB_EVENT_TYPE: type_, sc.LAB_EVENT_SEQ: event["seq"],
                 sc.LAB_EVENT_TS: event["ts"],
                 sc.LAB_EVENT_PAYLOAD: json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                 **attributes}
        span = self.tracer.start_span(span_name, start_time=int(start * 1e9), attributes=attrs)
        span.end(end_time=int(end * 1e9))
        self.counts[type_] = self.counts.get(type_, 0) + 1

    # ------------------------------------------------------------------ the four event types
    def decision(self, intent: str, tool: str | None = None, tool_call_id: str | None = None) -> None:
        payload = {"intent": clip((intent or "").strip() or "(no intent stated)", MAX_INTENT_CHARS)}
        if tool:
            payload["tool"] = tool
        if tool_call_id:
            payload["tool_call_id"] = tool_call_id
        self._emit("decision", payload, "decision", {})

    def tool_call(self, tool: str, args: dict[str, Any], result_summary: str, ok: bool,
                  started: float | None = None, tool_call_id: str | None = None) -> None:
        payload = {"tool": tool, "args": summarise_args(tool, args),
                   "result_summary": clip(result_summary or "", MAX_RESULT_CHARS), "ok": bool(ok)}
        if tool_call_id:
            payload["tool_call_id"] = tool_call_id
        attrs = {sc.GEN_AI_OPERATION_NAME: sc.OPERATION_EXECUTE_TOOL, sc.GEN_AI_TOOL_NAME: tool,
                 sc.GEN_AI_TOOL_TYPE: sc.TOOL_TYPE_FUNCTION}
        if tool_call_id:
            attrs[sc.GEN_AI_TOOL_CALL_ID] = tool_call_id
        if not ok:
            attrs[sc.ERROR_TYPE] = "tool_error"
        self._emit("tool_call", payload, f"{sc.OPERATION_EXECUTE_TOOL} {tool}", attrs, start=started)

    def incident_report(self, report: dict[str, Any]) -> None:
        payload = {k: report[k] for k in ("incident_id", "detected", "root_cause", "action_taken",
                                          "status", "confidence")}
        payload["root_cause"] = clip(payload["root_cause"], 2000)
        payload["action_taken"] = clip(payload["action_taken"], 2000)
        self._emit("incident_report", payload, "incident_report", {})

    def state_snapshot(self, notes: str, trigger: str, **extra: Any) -> None:
        payload = {"notes": notes[:MAX_NOTES_CHARS], "trigger": trigger, "notes_chars": len(notes),
                   **{k: v for k, v in extra.items() if isinstance(v, (str, int, float, bool))}}
        self._emit("state_snapshot", payload, "state_snapshot", {})

    # ------------------------------------------------------------------ usage (Langfuse only, no content)
    def agent_turn(self, started: float, usage: dict[str, Any] | None, cost_usd: float | None,
                   num_turns: int | None, is_error: bool) -> None:
        """One invoke_agent span per agent turn with token counts and cost — no text of any kind.
        It carries no lab.event.type, so it is not mirrored into C3."""
        usage = usage or {}
        attrs = {sc.GEN_AI_OPERATION_NAME: sc.OPERATION_INVOKE_AGENT, sc.GEN_AI_PROVIDER_NAME: sc.PROVIDER_ANTHROPIC,
                 sc.GEN_AI_AGENT_NAME: AGENT_NAME, sc.GEN_AI_REQUEST_MODEL: self.model,
                 sc.GEN_AI_CONVERSATION_ID: self.run_id, sc.LANGFUSE_SESSION_ID: self.run_id,
                 sc.LAB_RUN_ID: self.run_id,
                 sc.GEN_AI_USAGE_INPUT_TOKENS: int(usage.get("input_tokens") or 0),
                 sc.GEN_AI_USAGE_OUTPUT_TOKENS: int(usage.get("output_tokens") or 0),
                 "lab.agent.turns": int(num_turns or 0), "lab.agent.cost_usd": float(cost_usd or 0.0)}
        if is_error:
            attrs[sc.ERROR_TYPE] = "agent_turn_error"
        span = self.tracer.start_span(f"{sc.OPERATION_INVOKE_AGENT} {AGENT_NAME}",
                                      start_time=int(started * 1e9), attributes=attrs)
        span.end()

    def flush(self) -> None:
        try:
            self.provider.force_flush(timeout_millis=20000)
        except Exception as exc:      # a telemetry problem must not take the agent down
            log.warning("flush failed: %s", exc)

    def shutdown(self) -> None:
        self.flush()
        try:
            self.provider.shutdown()
        except Exception:
            pass
