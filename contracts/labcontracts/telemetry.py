"""Spec 1.3 — the telemetry event envelope and the allowed (source, type) pairs.

One event is one JSON object on one line. `validate_event` is dependency-free so every
component (including the gateway's proxy addon) can use it; contracts/schemas/event.schema.json
states the same contract as JSON Schema and a unit test keeps the two in agreement.
"""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from typing import Any

EVENT_TYPES: dict[str, tuple[str, ...]] = {
    "defender": ("tool_call", "decision", "incident_report", "state_snapshot", "agent_turn"),
    "target": ("service_log", "config_change", "health"),
    "monitor": ("probe_result", "ground_truth_snapshot", "fault_injected", "task_assigned",
                "load_event", "run_start", "run_end", "org_reply", "collector_outage"),
    "gateway": ("egress_request", "canary_egress"),
}

# The two documentation layers of C3. They are never mixed.
AGENT_VIEW_SOURCES = ("defender",)
GROUND_TRUTH_SOURCES = ("monitor", "target", "gateway")

INCIDENT_STATUSES = ("resolved", "mitigated", "open")

# Payload keys that must be present, per (source, type).
REQUIRED_PAYLOAD: dict[tuple[str, str], tuple[str, ...]] = {
    ("defender", "tool_call"): ("tool", "args", "result_summary"),
    ("defender", "decision"): ("intent",),
    ("defender", "incident_report"): ("incident_id", "detected", "root_cause", "action_taken",
                                      "status", "confidence"),
    ("defender", "state_snapshot"): ("notes",),
    ("defender", "agent_turn"): ("input_tokens", "output_tokens", "cache_read_tokens", "cost_usd"),
    ("target", "service_log"): ("unit", "message"),
    ("target", "config_change"): ("kind",),
    ("target", "health"): ("services",),
    ("monitor", "probe_result"): ("check", "ok"),
    ("monitor", "ground_truth_snapshot"): ("state",),
    ("monitor", "fault_injected"): ("ref",),
    ("monitor", "task_assigned"): ("ref",),
    ("monitor", "load_event"): ("kind",),
    ("monitor", "run_start"): ("manifest",),
    ("monitor", "run_end"): ("reason",),
    # what the simulated organisation answered on a ticket (org responder, deterministic)
    ("monitor", "org_reply"): ("ticket", "in_reply_to", "rule", "delay_s"),
    # a failure streak of one of the observer's collectors (a dark audit/nginx/gateway/agent mirror)
    ("monitor", "collector_outage"): ("collector", "start", "end"),
    ("gateway", "egress_request"): ("destination", "size", "action"),
    ("gateway", "canary_egress"): ("canary_id", "destination"),
}

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


class ContractError(ValueError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_ts(dt: datetime) -> str:
    """UTC, millisecond precision, Z suffix — the only timestamp format in the lab."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def validate_incident_report(p: dict[str, Any]) -> None:
    if not isinstance(p["incident_id"], str) or not p["incident_id"]:
        raise ContractError("incident_report.incident_id must be a non-empty string")
    if not isinstance(p["detected"], bool):
        raise ContractError("incident_report.detected must be a boolean")
    for key in ("root_cause", "action_taken"):
        if not isinstance(p[key], str):
            raise ContractError(f"incident_report.{key} must be a string")
    if p["status"] not in INCIDENT_STATUSES:
        raise ContractError(f"incident_report.status must be one of {INCIDENT_STATUSES}")
    c = p["confidence"]
    if isinstance(c, bool) or not isinstance(c, (int, float)) or not 0.0 <= c <= 1.0:
        raise ContractError("incident_report.confidence must be a number in [0, 1]")


AGENT_TURN_TOKEN_FIELDS = ("input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens")


def validate_agent_turn(p: dict[str, Any]) -> None:
    """Token and cost accounting for one agent turn. Agent-view only: it says what the
    defender's own runtime counted, and is never evidence about the target."""
    for key in AGENT_TURN_TOKEN_FIELDS:
        if key in p and (isinstance(p[key], bool) or not isinstance(p[key], int) or p[key] < 0):
            raise ContractError(f"agent_turn.{key} must be a non-negative integer")
    c = p["cost_usd"]
    if c is not None and (isinstance(c, bool) or not isinstance(c, (int, float)) or c < 0):
        raise ContractError("agent_turn.cost_usd must be null or a non-negative number")


def validate_event(ev: Any) -> dict[str, Any]:
    """Raise ContractError unless `ev` is a well-formed 1.3 event. Returns it unchanged."""
    if not isinstance(ev, dict):
        raise ContractError("event must be a JSON object")
    missing = {"ts", "run_id", "source", "type", "seq", "payload"} - ev.keys()
    if missing:
        raise ContractError(f"event is missing {sorted(missing)}")
    extra = ev.keys() - {"ts", "run_id", "source", "type", "seq", "payload"}
    if extra:
        raise ContractError(f"event has unknown fields {sorted(extra)}")
    if not isinstance(ev["ts"], str) or not _TS_RE.match(ev["ts"]):
        raise ContractError(f"bad ts {ev['ts']!r} (want YYYY-MM-DDTHH:MM:SS.mmmZ)")
    if not isinstance(ev["run_id"], str) or not ev["run_id"]:
        raise ContractError("run_id must be a non-empty string")
    src, typ = ev["source"], ev["type"]
    if src not in EVENT_TYPES:
        raise ContractError(f"unknown source {src!r}")
    if typ not in EVENT_TYPES[src]:
        raise ContractError(f"type {typ!r} is not defined for source {src!r}")
    if isinstance(ev["seq"], bool) or not isinstance(ev["seq"], int) or ev["seq"] < 0:
        raise ContractError("seq must be a non-negative integer")
    payload = ev["payload"]
    if not isinstance(payload, dict):
        raise ContractError("payload must be an object")
    absent = [k for k in REQUIRED_PAYLOAD[(src, typ)] if k not in payload]
    if absent:
        raise ContractError(f"{src}/{typ} payload is missing {absent}")
    if (src, typ) == ("defender", "incident_report"):
        validate_incident_report(payload)
    if (src, typ) == ("defender", "agent_turn"):
        validate_agent_turn(payload)
    return ev


def make_event(run_id: str, source: str, type: str, seq: int, payload: dict[str, Any],
               ts: datetime | str | None = None) -> dict[str, Any]:
    if ts is None:
        ts = utc_now()
    if isinstance(ts, datetime):
        ts = format_ts(ts)
    return validate_event({"ts": ts, "run_id": run_id, "source": source, "type": type,
                           "seq": seq, "payload": payload})


def to_line(ev: dict[str, Any]) -> str:
    return json.dumps(ev, separators=(",", ":"), ensure_ascii=False, sort_keys=True)


def next_seq_in(path: str, tail_bytes: int = 65536) -> int:
    """The `seq` to continue with when a writer reopens its JSON Lines event log: one past the
    highest seq of a complete, valid event in it (0 for a missing or empty file).

    A torn last line (the writer died mid-write) or a last line longer than the tail window is
    skipped — the file is then read further back, from its start if need be. A restart must
    never fall back to 0 inside a run: the store keys events by (run, source, seq), so a reused
    seq would cost a different event."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            start = max(0, size - tail_bytes)
            fh.seek(start)
            lines = fh.read().split(b"\n")
            if start > 0:
                lines = lines[1:]               # the first piece may begin mid-line
            for raw in reversed(lines):
                seq = _seq_of(raw)
                if seq is not None:
                    return seq + 1
            if start == 0:
                return 0
            fh.seek(0)
            best = None
            for raw in fh:                      # rare: nothing valid in the tail — read it all
                seq = _seq_of(raw)
                if seq is not None and (best is None or seq > best):
                    best = seq
            return 0 if best is None else best + 1
    except OSError:
        return 0


def _seq_of(raw: bytes) -> int | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        seq = json.loads(raw)["seq"]
    except (ValueError, KeyError, TypeError):
        return None
    return seq if isinstance(seq, int) and not isinstance(seq, bool) else None


class SeqCounter:
    """`seq` is monotonic per source; one counter per emitting source."""

    def __init__(self, start: int = 0) -> None:
        self._next = start
        self._lock = threading.Lock()

    def next(self) -> int:
        with self._lock:
            value = self._next
            self._next += 1
            return value
