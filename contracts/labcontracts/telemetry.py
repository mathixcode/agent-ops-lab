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
    "defender": ("tool_call", "decision", "incident_report", "state_snapshot"),
    "target": ("service_log", "config_change", "health"),
    "monitor": ("probe_result", "ground_truth_snapshot", "fault_injected", "task_assigned",
                "load_event", "run_start", "run_end"),
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
