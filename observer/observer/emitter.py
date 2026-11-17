"""Writes the observer's own measurements (source = monitor) into the ground-truth layer."""
from __future__ import annotations

import datetime as dt
import logging
import threading
from typing import Any

from labcontracts import telemetry

from .store import Store

log = logging.getLogger("observer")


class Emitter:
    def __init__(self, store: Store, run_id: str, source: str = "monitor") -> None:
        self.store = store
        self.run_id = run_id
        self.source = source
        self.seq = telemetry.SeqCounter(store.max_seq("ground_truth", run_id, source) + 1)
        self._lock = threading.Lock()

    def emit(self, type_: str, payload: dict[str, Any], ts: dt.datetime | None = None) -> dict[str, Any]:
        with self._lock:        # several loops emit concurrently: seq order must be time order
            ev = telemetry.make_event(self.run_id, self.source, type_, self.seq.next(), payload, ts=ts)
            self.store.append_ground_truth(ev)
        return ev
