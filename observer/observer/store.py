"""C3 — the append-only datastore with its two documentation layers.

    agent_view_events     what the defender reports about itself (source = defender)
    ground_truth_events   what was measured independently (source = monitor | target | gateway)

The layers are separate tables with source CHECK constraints, and both reject UPDATE and
DELETE through triggers. There is no API that writes an event into "whichever table fits":
a writer is created for one layer and refuses events of the other. Scoring opens the file
read-only.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterator

from labcontracts import telemetry

log = logging.getLogger("observer.store")

LAYERS = {
    "agent_view": ("agent_view_events", telemetry.AGENT_VIEW_SOURCES),
    "ground_truth": ("ground_truth_events", telemetry.GROUND_TRUTH_SOURCES),
}


def _schema() -> str:
    parts = []
    for table, sources in LAYERS.values():
        allowed = ", ".join(f"'{s}'" for s in sources)
        parts.append(f"""
CREATE TABLE IF NOT EXISTS {table} (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    ts          TEXT NOT NULL,
    source      TEXT NOT NULL CHECK (source IN ({allowed})),
    type        TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    payload     TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    UNIQUE (run_id, source, seq)
);
CREATE INDEX IF NOT EXISTS {table}_run_ts ON {table} (run_id, ts);
CREATE TRIGGER IF NOT EXISTS {table}_no_update BEFORE UPDATE ON {table}
BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END;
CREATE TRIGGER IF NOT EXISTS {table}_no_delete BEFORE DELETE ON {table}
BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END;
""")
    # bookkeeping (collector cursors, run registry) — not telemetry, therefore mutable
    parts.append("""
CREATE TABLE IF NOT EXISTS collector_state (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, manifest TEXT NOT NULL, started_at TEXT NOT NULL,
    ended_at TEXT, status TEXT NOT NULL);
""")
    return "\n".join(parts)


class LayerViolation(ValueError):
    """An event was offered to the wrong documentation layer."""


class Store:
    def __init__(self, path: str | Path, readonly: bool = False) -> None:
        self.path = Path(path)
        self.readonly = readonly
        self._lock = threading.RLock()
        self.collisions: dict[tuple[str, str], int] = {}        # (run_id, source) -> events not stored
        if readonly:
            self._db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.executescript(_schema())
        self._db.row_factory = sqlite3.Row

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------------ writing
    def _append(self, layer: str, events: list[dict[str, Any]]) -> int:
        table, sources = LAYERS[layer]
        rows = []
        for ev in events:
            telemetry.validate_event(ev)
            if ev["source"] not in sources:
                raise LayerViolation(f"{ev['source']}/{ev['type']} does not belong in the {layer} layer")
            rows.append((ev["run_id"], ev["ts"], ev["source"], ev["type"], ev["seq"],
                         json.dumps(ev["payload"], separators=(",", ":"), ensure_ascii=False),
                         telemetry.format_ts(telemetry.utc_now())))
        with self._lock:
            before = self._db.total_changes
            self._db.executemany(
                f"INSERT OR IGNORE INTO {table} (run_id, ts, source, type, seq, payload, ingested_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
            inserted = self._db.total_changes - before
            if inserted < len(rows):
                self._check_ignored(table, rows)
            return inserted

    def _check_ignored(self, table: str, rows: list[tuple]) -> None:
        """INSERT OR IGNORE is how re-pulled events (overlapping collector windows) are made
        idempotent. An ignored row whose content differs from the stored one is not a re-pull
        but a sequence-number collision — a different event lost. Never silent: logged and
        counted per (run, source); the orchestrator reports the count in run_end."""
        for run_id, ts, source, type_, seq, payload, _ in rows:
            row = self._db.execute(f"SELECT ts, type, payload FROM {table} WHERE run_id = ? AND source = ? AND seq = ?",
                                   (run_id, source, seq)).fetchone()
            if row is None or (row["ts"], row["type"], row["payload"]) == (ts, type_, payload):
                continue
            key = (run_id, source)
            self.collisions[key] = self.collisions.get(key, 0) + 1
            log.warning("seq collision in %s: %s/%s seq %d already holds a different %s event; the new %s "
                        "event was not stored", table, run_id, source, seq, row["type"], type_)

    def append_ground_truth(self, *events: dict[str, Any]) -> int:
        """Independent record: prober, orchestrator, auditd/journal, gateway."""
        return self._append("ground_truth", list(events))

    def append_agent_view(self, *events: dict[str, Any]) -> int:
        """The defender's self-report. Only the Langfuse collector calls this."""
        return self._append("agent_view", list(events))

    # ------------------------------------------------------------------ reading
    def events(self, layer: str, run_id: str, source: str | None = None,
               type: str | None = None, min_seq: int | None = None) -> Iterator[dict[str, Any]]:
        """Events of one run in time order. `min_seq` (with `source`: seq is per source) reads
        only events after a point already seen — for consumers that poll during a run."""
        table, _ = LAYERS[layer]
        sql, args = f"SELECT ts, run_id, source, type, seq, payload FROM {table} WHERE run_id = ?", [run_id]
        if source:
            sql, args = sql + " AND source = ?", args + [source]
        if type:
            sql, args = sql + " AND type = ?", args + [type]
        if min_seq is not None:
            if not source:
                raise ValueError("min_seq needs a source (seq is per source)")
            sql, args = sql + " AND seq >= ?", args + [min_seq]
        with self._lock:
            rows = self._db.execute(sql + " ORDER BY ts, source, seq", args).fetchall()
        for row in rows:
            yield {"ts": row["ts"], "run_id": row["run_id"], "source": row["source"], "type": row["type"],
                   "seq": row["seq"], "payload": json.loads(row["payload"])}

    def counts(self, run_id: str) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        with self._lock:
            for layer, (table, _) in LAYERS.items():
                rows = self._db.execute(f"SELECT source, type, COUNT(*) AS n FROM {table} WHERE run_id = ? "
                                        "GROUP BY source, type", (run_id,)).fetchall()
                out[layer] = {f"{r['source']}/{r['type']}": r["n"] for r in rows}
        return out

    def max_seq(self, layer: str, run_id: str, source: str) -> int:
        table, _ = LAYERS[layer]
        with self._lock:
            row = self._db.execute(f"SELECT MAX(seq) AS m FROM {table} WHERE run_id = ? AND source = ?",
                                   (run_id, source)).fetchone()
        return -1 if row["m"] is None else row["m"]

    def export_jsonl(self, run_id: str, directory: Path) -> dict[str, int]:
        """One JSON Lines file per layer — the 1.3 wire format, still kept apart."""
        directory.mkdir(parents=True, exist_ok=True)
        written = {}
        for layer in LAYERS:
            n = 0
            with open(directory / f"{layer}.jsonl", "w", encoding="utf-8") as fh:
                for ev in self.events(layer, run_id):
                    fh.write(telemetry.to_line(ev) + "\n")
                    n += 1
            written[layer] = n
        return written

    # ------------------------------------------------------------------ bookkeeping
    def get_state(self, name: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM collector_state WHERE name = ?", (name,)).fetchone()
        return row["value"] if row else default

    def set_state(self, name: str, value: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO collector_state (name, value) VALUES (?, ?) "
                             "ON CONFLICT(name) DO UPDATE SET value = excluded.value", (name, value))

    def run_started(self, run_id: str, manifest: dict[str, Any], started_at: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO runs (run_id, manifest, started_at, status) VALUES (?, ?, ?, 'running')",
                             (run_id, json.dumps(manifest), started_at))

    def run_finished(self, run_id: str, ended_at: str, status: str) -> None:
        with self._lock:
            self._db.execute("UPDATE runs SET ended_at = ?, status = ? WHERE run_id = ?",
                             (ended_at, status, run_id))

    def run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return dict(row, manifest=json.loads(row["manifest"])) if row else None

    def latest_run(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()
        return self.run(row["run_id"]) if row else None
