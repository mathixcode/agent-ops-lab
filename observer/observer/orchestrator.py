"""C1 — the orchestrator: one run from golden-snapshot reset to teardown.

    reset target -> baseline snapshot -> run_start -> start defender
    -> [ run clock: load, scheduled faults and ops tasks, probes, snapshots, collection ]
    -> stop defender -> final snapshot + integrity check -> final collection -> run_end

Everything the orchestrator knows about the run (seed, schedule, canaries) stays on the
observer. The defender is told only what an operator would know: nothing about the schedule.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import random
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

import requests

from labcontracts import manifest as mf, telemetry

from .clients import DefenderAPI, GatewayAPI, Hypervisor, TargetSSH, Unreachable
from .collectors import GatewayCollector, LangfuseCollector, TargetCollector
from .config import Config
from .emitter import Emitter
from .faults import FAULTS
from .prober import Prober
from .store import Store
from .tasks import TASKS, TaskContext, file_ticket

log = logging.getLogger("observer.orchestrator")


@dataclass(frozen=True)
class PlannedEvent:
    scheduled: int      # offset from the manifest
    at: float           # offset actually used (seeded jitter applied)
    type: str
    ref: str


def resolve_schedule(m: mf.RunManifest, jitter: float) -> list[PlannedEvent]:
    """Apply seeded timing jitter: each event moves later by up to `jitter` x the gap to the
    next event (or to the end of the run). Order is preserved; same seed, same schedule."""
    rng = random.Random(m.seed)
    events = list(m.event_schedule)
    planned = []
    for i, ev in enumerate(events):
        nxt = events[i + 1].at if i + 1 < len(events) else m.duration
        planned.append(PlannedEvent(ev.at, round(ev.at + rng.uniform(0, jitter) * max(0, nxt - ev.at), 1),
                                    ev.type, ev.ref))
    return planned


class Loop(threading.Thread):
    """Calls `fn` every `interval` seconds until stopped; failures are logged, never fatal."""

    def __init__(self, name: str, interval: float, fn, stop: threading.Event) -> None:
        super().__init__(name=name, daemon=True)
        self.interval, self.fn, self.stop_event = interval, fn, stop

    def run(self) -> None:
        next_at = time.monotonic()
        while not self.stop_event.is_set():
            try:
                self.fn()
            except Unreachable as exc:
                log.warning("%s: %s", self.name, str(exc)[:200])
            except Exception:
                log.exception("%s failed", self.name)
            next_at += self.interval
            delay = next_at - time.monotonic()
            if delay < 0:                       # fell behind; do not burst to catch up
                next_at, delay = time.monotonic(), 0
            self.stop_event.wait(delay)


class Orchestrator:
    def __init__(self, cfg: Config, manifest: mf.RunManifest, reset: bool = True) -> None:
        self.cfg, self.m, self.reset = cfg, manifest, reset
        self.store = Store(cfg.db_path)
        if self.store.run(manifest.run_id):
            raise SystemExit(f"run_id {manifest.run_id!r} already exists in the datastore — the store is "
                             "append-only, so every run needs a fresh run_id")
        self.hv, self.ssh = Hypervisor(cfg), TargetSSH(cfg)
        self.gateway, self.defender = GatewayAPI(cfg), DefenderAPI(cfg)
        self.stop = threading.Event()
        self.reason = "completed"
        self.assigned_tasks: list[str] = []
        self.write_acks: list[dict] = []
        self.load_proc: subprocess.Popen | None = None
        self.status_path = cfg.data / "runs" / "current.json"

    # ------------------------------------------------------------------ phases
    def prepare_target(self) -> None:
        try:
            self.defender.stop()                # nothing may act on the target while it is reset
        except (Unreachable, RuntimeError) as exc:
            log.warning("defender not stopped before reset: %s", exc)
        if self.reset:
            log.info("resetting target from the golden snapshot")
            self.hv.reset()
        self.ssh.close()
        log.info("waiting for the target to come up")
        self.hv.wait_guest(timeout=900)
        session = requests.Session()
        session.trust_env, session.verify = False, self.cfg.ca_file
        deadline = time.time() + 900
        while True:
            try:
                if session.get(self.cfg.target_url + "/api/healthz", timeout=10).status_code == 200:
                    break
            except requests.RequestException:
                pass
            if time.time() > deadline:
                raise SystemExit("target did not become healthy after reset")
            time.sleep(5)
        self.hv.guest_sh("chronyc -a makestep >/dev/null 2>&1 || true", timeout=30)
        log.info("target is healthy")

    def write_status(self, phase: str, **extra) -> None:
        self.status_path.parent.mkdir(parents=True, exist_ok=True)
        self.status_path.write_text(json.dumps({
            "run_id": self.m.run_id, "phase": phase, "updated": telemetry.format_ts(telemetry.utc_now()),
            **extra}, indent=2))

    def run(self) -> int:
        m, cfg = self.m, self.cfg
        signal.signal(signal.SIGTERM, lambda *_: self._abort("terminated"))
        signal.signal(signal.SIGINT, lambda *_: self._abort("interrupted"))
        self.write_status("preparing")
        self.prepare_target()

        t0 = telemetry.utc_now()
        t0_mono = time.monotonic()
        self.store.run_started(m.run_id, m.to_dict(), telemetry.format_ts(t0))
        monitor = Emitter(self.store, m.run_id)
        prober = Prober(cfg, monitor, self.hv, self.ssh, t0)
        self.gateway.start_run(m.run_id, prober.canaries)
        collect_gateway = GatewayCollector(self.store, m.run_id, self.gateway)
        collect_target = TargetCollector(cfg, self.store, m.run_id, self.ssh, t0, prober.scanner,
                                         prober.journal_hits)
        collect_defender = LangfuseCollector(cfg, self.store, m.run_id, t0)
        plan = resolve_schedule(m, cfg.event_jitter)

        monitor.emit("run_start", {
            "manifest": m.to_dict(), "golden": {k: v for k, v in cfg.golden().items() if k != "seed"},
            "schedule": [{"scheduled": mf.format_offset(p.scheduled), "at": p.at, "type": p.type, "ref": p.ref}
                         for p in plan],
            "cadence": {"http_probe_s": cfg.http_probe_interval, "checks_s": cfg.check_interval,
                        "snapshot_s": m.snapshot_interval, "collect_s": cfg.collect_interval},
            "hypervisor": {k: v for k, v in self.hv.status().items() if k in ("accel", "resets")}}, ts=t0)
        # The golden state, captured before the agent or any load exists, is the reference for
        # all later drift comparisons.
        if not prober.snapshot("baseline"):
            return self._finish(monitor, prober, [collect_gateway, collect_target, collect_defender],
                                t0_mono, "baseline_snapshot_failed")

        try:
            started = self.defender.start(m.run_id, m.model_defender, m.snapshot_interval)
            log.info("defender started: %s", started)
        except (Unreachable, RuntimeError) as exc:
            log.error("defender did not start: %s", exc)
            return self._finish(monitor, prober, [collect_gateway, collect_target, collect_defender],
                                t0_mono, "defender_start_failed", str(exc))

        def defender_alive() -> None:
            """Is the agent process still there and still on this run? An observation of the
            process from outside (harness health) — not something the agent reports."""
            try:
                st = self.defender.status()
            except (Unreachable, RuntimeError) as exc:
                monitor.emit("probe_result", {"check": "defender_process", "ok": False, "inconclusive": True,
                                              "error": str(exc)[:200]})
                return
            monitor.emit("probe_result", {
                "check": "defender_process", "ok": bool(st.get("running")) and st.get("run_id") == m.run_id,
                "driver": st.get("driver"), "agent_turns": st.get("agent_turns"),
                "driver_error": (st.get("last_error") or None)})

        def checks() -> None:
            defender_alive()
            prober.fault_conditions()
            prober.security_checks()
            prober.canary_checks()
            prober.task_checks(self.assigned_tasks)

        loops = [
            Loop("http-probe", cfg.http_probe_interval, prober.http_probe, self.stop),
            Loop("checks", cfg.check_interval, checks, self.stop),
            Loop("collect-target", cfg.collect_interval, collect_target.pull, self.stop),
            Loop("collect-gateway", cfg.collect_interval, collect_gateway.pull, self.stop),
            Loop("collect-defender", cfg.collect_interval, collect_defender.pull, self.stop),
        ]
        for loop in loops:
            loop.start()
        load_thread = threading.Thread(target=self._run_load, args=(monitor,), name="load", daemon=True)
        load_thread.start()

        # ---- the run clock -------------------------------------------------------------------
        pending = list(plan)
        next_snapshot = m.snapshot_interval
        log.info("run %s started: %s, %d scheduled events", m.run_id, mf.format_offset(m.duration), len(plan))
        while not self.stop.is_set():
            elapsed = time.monotonic() - t0_mono
            if elapsed >= m.duration:
                break
            while pending and elapsed >= pending[0].at:
                self._play(pending.pop(0), monitor, prober, elapsed)
            if elapsed >= next_snapshot:
                prober.snapshot("interval")
                next_snapshot += m.snapshot_interval
            self.write_status("running", elapsed_s=int(elapsed), duration_s=m.duration,
                              events_pending=len(pending), counts=self.store.counts(m.run_id))
            self.stop.wait(min(5.0, max(0.2, m.duration - elapsed)))

        self.stop.set()
        for loop in loops:
            loop.join(timeout=180)
        # The load generator runs for the same duration and ends with a summary; give it a moment
        # to finish by itself before stopping it (it also summarises on SIGTERM).
        load_thread.join(timeout=45)
        if self.load_proc and self.load_proc.poll() is None:
            self.load_proc.terminate()
            load_thread.join(timeout=60)
        return self._finish(monitor, prober, [collect_gateway, collect_target, collect_defender],
                            t0_mono, self.reason)

    # ------------------------------------------------------------------ pieces
    def _abort(self, reason: str) -> None:
        self.reason = reason
        self.stop.set()

    def _play(self, ev: PlannedEvent, monitor: Emitter, prober: Prober, elapsed: float) -> None:
        base = {"ref": ev.ref, "scheduled_offset_s": ev.scheduled, "planned_offset_s": ev.at,
                "actual_offset_s": round(elapsed, 1)}
        if ev.type == "fault":
            fault = FAULTS[ev.ref]
            log.info("injecting fault %s", ev.ref)
            try:
                detail = fault.inject(prober.fault_ctx)
                monitor.emit("fault_injected", {**base, "summary": fault.summary, "mechanism": fault.mechanism,
                                                "injected": True, "detail": detail})
                # Probe the condition right away: a quick agent can close it before the next
                # scheduled check, and ground truth should still show that it was open.
                prober.fault_conditions([ev.ref])
            except (Unreachable, RuntimeError, TimeoutError) as exc:
                log.error("fault %s could not be injected: %s", ev.ref, exc)
                monitor.emit("fault_injected", {**base, "summary": fault.summary, "mechanism": fault.mechanism,
                                                "injected": False, "error": str(exc)[:300]})
        else:
            task = TASKS[ev.ref]
            log.info("assigning ops task %s", ev.ref)
            try:
                setup = None
                if task.setup:
                    setup = task.setup(TaskContext(self.cfg, self.ssh, prober.latest_state, prober.baseline_state))
                ticket = file_ticket(self.cfg, task)
                self.assigned_tasks.append(ev.ref)
                monitor.emit("task_assigned", {**base, "channel": "issue", "ticket": ticket, "title": task.title,
                                               "trap": task.trap, "assigned": True, "setup": setup})
            except (requests.RequestException, Unreachable, KeyError, StopIteration) as exc:
                log.error("task %s could not be assigned: %s", ev.ref, exc)
                monitor.emit("task_assigned", {**base, "channel": "issue", "assigned": False,
                                               "error": f"{type(exc).__name__}: {exc}"[:300]})

    def _run_load(self, monitor: Emitter) -> None:
        cmd = [sys.executable, "-m", "observer.loadgen.runner", "--seed", str(self.m.seed),
               "--profile", self.m.load_profile, "--duration", str(self.m.duration)]
        self.load_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True,
                                          stderr=open(self.cfg.run_dir(self.m.run_id) / "loadgen.log", "w"))
        for line in self.load_proc.stdout:
            try:
                payload = json.loads(line)
            except ValueError:
                continue
            if payload.get("kind") == "write_ack":
                self.write_acks.append({k: v for k, v in payload.items() if k != "kind"})
            monitor.emit("load_event", payload)
        self.load_proc.wait()

    def _finish(self, monitor: Emitter, prober: Prober, collectors: list, t0_mono: float, reason: str,
                detail: str | None = None) -> int:
        """Teardown. The defender is stopped first so its last state snapshot is part of the run."""
        self.write_status("teardown")
        log.info("teardown (%s)", reason)
        try:
            self.defender.stop()
        except (Unreachable, RuntimeError) as exc:
            log.warning("defender stop: %s", exc)
        try:
            if prober.snapshot("final"):
                prober.integrity_check(self.write_acks)
            prober.fault_conditions()
            prober.canary_checks()
            prober.task_checks(self.assigned_tasks)
        except Exception:
            log.exception("final checks failed")
        # Last pulls. Langfuse ingests asynchronously, so the defender's events are pulled until
        # two consecutive pulls bring nothing new; the target and gateway logs are read once more
        # after that.
        quiet, deadline = 0, time.time() + 180
        while quiet < 2 and time.time() < deadline:
            time.sleep(8)
            try:
                quiet = quiet + 1 if not next(c for c in collectors if isinstance(c, LangfuseCollector)).pull() else 0
            except Exception as exc:
                log.warning("final pull of the defender's events: %s", str(exc)[:200])
        for collector in collectors:
            if not isinstance(collector, LangfuseCollector):
                try:
                    collector.pull()
                except Exception as exc:
                    log.warning("final pull %s: %s", type(collector).__name__, str(exc)[:200])
        try:
            self.gateway.end_run()
        except requests.RequestException as exc:
            log.warning("gateway end_run: %s", exc)
        payload = {"reason": reason, "elapsed_s": round(time.monotonic() - t0_mono, 1),
                   "counts": self.store.counts(self.m.run_id)}
        if detail:
            payload["detail"] = detail[:500]
        monitor.emit("run_end", payload)
        ended = telemetry.format_ts(telemetry.utc_now())
        self.store.run_finished(self.m.run_id, ended, reason)
        exported = self.store.export_jsonl(self.m.run_id, self.cfg.run_dir(self.m.run_id) / "events")
        self.write_status("finished", reason=reason, counts=payload["counts"], exported=exported)
        self.ssh.close()
        log.info("run %s finished: %s", self.m.run_id, reason)
        return 0 if reason == "completed" else 1
