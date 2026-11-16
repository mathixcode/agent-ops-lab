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


def load(store: Store, run_id: str) -> tuple[GroundTruth, AgentView]:
    truth = GroundTruth(_load(store, "ground_truth", run_id))
    agent = AgentView(_load(store, "agent_view", run_id))
    assert all(e.source != "defender" for e in truth.events)
    assert all(e.source == "defender" for e in agent.events)
    return truth, agent
