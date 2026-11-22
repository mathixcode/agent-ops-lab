"""Scoring inputs. The two documentation layers are loaded into two different types and
stay apart: metric functions state in their signature which layer(s) they read."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from labcontracts import telemetry

from ..store import Store


@dataclass(frozen=True)
class Event:
    ts: dt.datetime
    source: str
    type: str
    seq: int
    payload: dict[str, Any]


def _load(store: Store, layer: str, run_id: str) -> list[Event]:
    return [Event(telemetry.parse_ts(e["ts"]), e["source"], e["type"], e["seq"], e["payload"])
            for e in store.events(layer, run_id)]


@dataclass
class GroundTruth:
    """monitor + target + gateway: measured independently of the agent."""
    events: list[Event] = field(default_factory=list)

    def of(self, source: str, type_: str) -> list[Event]:
        return [e for e in self.events if e.source == source and e.type == type_]

    def probes(self, check: str) -> list[Event]:
        return [e for e in self.of("monitor", "probe_result") if e.payload["check"] == check]

    def probes_prefixed(self, prefix: str) -> list[Event]:
        return [e for e in self.of("monitor", "probe_result") if e.payload["check"].startswith(prefix)]

    @property
    def run_start(self) -> Event | None:
        return next(iter(self.of("monitor", "run_start")), None)

    @property
    def run_end(self) -> Event | None:
        return next(iter(self.of("monitor", "run_end")), None)


@dataclass
class AgentView:
    """defender: what the agent reported about itself."""
    events: list[Event] = field(default_factory=list)

    def of(self, type_: str) -> list[Event]:
        return [e for e in self.events if e.type == type_]


def events_from_jsonl(path, layer: str) -> list[Event]:
    """Events of one layer from an exported JSON Lines file (gzip allowed), validated against the
    1.3 contract and the layer's sources — the same guarantees the datastore gives."""
    import gzip
    import json
    path = str(path)
    opener = gzip.open if path.endswith(".gz") else open
    allowed = telemetry.AGENT_VIEW_SOURCES if layer == "agent_view" else telemetry.GROUND_TRUTH_SOURCES
    out = []
    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            e = telemetry.validate_event(json.loads(line))
            if e["source"] not in allowed:
                raise ValueError(f"{path}: {e['source']}/{e['type']} does not belong in the {layer} layer")
            out.append(Event(telemetry.parse_ts(e["ts"]), e["source"], e["type"], e["seq"], e["payload"]))
    out.sort(key=lambda e: (e.ts, e.source, e.seq))
    return out


def load_export(truth_path, agent_path) -> tuple[GroundTruth, AgentView]:
    """A run as exported by the observer (events/ground_truth.jsonl, events/agent_view.jsonl),
    read-only: scoring an exported run never needs the datastore."""
    return GroundTruth(events_from_jsonl(truth_path, "ground_truth")),         AgentView(events_from_jsonl(agent_path, "agent_view"))


def load(store: Store, run_id: str) -> tuple[GroundTruth, AgentView]:
    truth = GroundTruth(_load(store, "ground_truth", run_id))
    agent = AgentView(_load(store, "agent_view", run_id))
    assert all(e.source != "defender" for e in truth.events)
    assert all(e.source == "defender" for e in agent.events)
    return truth, agent
