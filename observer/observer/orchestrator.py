"""C1 — the orchestrator: one run from golden-snapshot reset to teardown.

    reset target -> baseline snapshot -> run_start -> start defender
    -> [ run clock: load, scheduled faults and ops tasks, probes, snapshots, collection ]
    -> stop defender -> final snapshot + integrity check -> final collection -> run_end

Everything the orchestrator knows about the run (seed, schedule, canaries) stays on the
observer. The defender is told only what an operator would know: nothing about the schedule.

Control plane (things the harness does to the target, as opposed to measuring it) never
fails silently: ticket delivery retries and falls back to the guest agent, and its attempts
are recorded in task_assigned; a fault is only applied if its precondition holds and its
effect is checked afterwards (fault_injected.applied); a fault whose earlier injection of the
same type is still open is skipped, delayed or stacked per the manifest's `on_conflict`.

Failure isolation: everything that needs another service (hypervisor status, gateway, log
collectors) is set up before the run is registered in the store, so a setup failure never
leaves a run without run_end. Once registered, the run gets exactly one teardown whatever
happens: a scheduled event that fails is recorded and the clock goes on; an unexpected error
in the clock itself ends the run as `orchestrator_error` and still tears down; every check of
a round and every teardown step runs on its own.
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

from labcontracts import manifest as mf, network, telemetry

from . import identities
from .clients import DefenderAPI, GatewayAPI, Hypervisor, TargetSSH, Unreachable
from .collectors import GatewayCollector, LangfuseCollector, TargetCollector
from .config import Config
from .emitter import Emitter
from .faults import FAULTS, await_effect
from .org import OrgResponder
from .prober import Prober
from .store import Store
from .tasks import TASKS, DeliveryFailed, OrgChannel, TaskContext, deliver_ticket

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
        # Retries wait on the run's stop flag and end with it: nothing is delivered after the run.
        self.org_channel = OrgChannel(cfg, self.hv, sleep=self.stop.wait, cancelled=self.stop.is_set)
        self.responder: OrgResponder | None = None
        self.fault_open_until: dict[str, list[float]] = {}      # ref -> transient windows (monotonic end)
        self.deliveries: list[threading.Thread] = []
        self.loops: list[Loop] = []
        self.load_thread: threading.Thread | None = None
        self._config_seq_seen = -1

    # ------------------------------------------------------------------ phases
    def prepare_target(self) -> None:
        try:
            self.defender.stop()                # nothing may act on the target while it is reset
        except (Unreachable, RuntimeError) as exc:
            log.warning("defender not stopped before reset: %s", exc)
        if self.reset:
            log.info("resetting target from the golden snapshot")
            for attempt in (1, 2):              # one hiccup of the hypervisor should not cost the run
                try:
                    self.hv.reset()
                    break
                except (Unreachable, RuntimeError) as exc:
                    if attempt == 2:
                        raise SystemExit(f"target reset failed twice: {exc}") from exc
                    log.warning("target reset failed (%s); retrying once", exc)
                    time.sleep(10)
        self.ssh.close()
        log.info("waiting for the target to come up")
        self.hv.wait_guest(timeout=900)
        session = identities.session_for("probe", self.cfg.ca_file)
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
        try:
            self.hv.guest_sh("chronyc -a makestep >/dev/null 2>&1 || true", timeout=30)
        except (Unreachable, RuntimeError, TimeoutError) as exc:      # best effort: chrony steps on its own
            log.warning("clock step on the target failed (continuing): %s", exc)
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
        if self.stop.is_set():                  # stopped during the reset: nothing to put on record
            raise SystemExit(f"run {m.run_id} {self.reason} before it started")

        # Everything that needs another service happens before the run is registered: if any of
        # it fails, the run aborts here — never as a half-registered run (no run_end) in the
        # append-only store.
        t0 = telemetry.utc_now()
        t0_mono = time.monotonic()
        hv_status = self.hv.status()
        monitor = Emitter(self.store, m.run_id)
        prober = Prober(cfg, monitor, self.hv, self.ssh, t0)
        self.gateway.start_run(m.run_id, prober.canaries)
        try:
            collectors = [GatewayCollector(self.store, m.run_id, self.gateway),
                          TargetCollector(cfg, self.store, m.run_id, self.ssh, t0, prober.scanner,
                                          prober.journal_hits),
                          LangfuseCollector(cfg, self.store, m.run_id, t0)]
            plan = resolve_schedule(m, cfg.event_jitter)
            self.store.run_started(m.run_id, m.to_dict(), telemetry.format_ts(t0))
        except Exception:
            self._quietly("gateway end_run", self.gateway.end_run)
            raise

        # From here on the run is on record: whatever happens, it gets exactly one teardown.
        try:
            reason, detail = self._execute(monitor, prober, collectors, plan, t0, t0_mono, hv_status)
        except Exception as exc:
            log.exception("the run was aborted by an unexpected error")
            reason, detail = "orchestrator_error", f"{type(exc).__name__}: {exc}"
        self.stop.set()
        self._stop_background(reason)
        return self._finish(monitor, prober, collectors, t0_mono, reason, detail)

    def _execute(self, monitor: Emitter, prober: Prober, collectors: list, plan: list[PlannedEvent],
                 t0: dt.datetime, t0_mono: float, hv_status: dict) -> tuple[str, str | None]:
        """run_start, baseline, defender start, then the run clock. -> (reason, detail)."""
        m, cfg = self.m, self.cfg
        monitor.emit("run_start", {
            "manifest": m.to_dict(), "golden": {k: v for k, v in cfg.golden().items() if k != "seed"},
            "schedule": [{"scheduled": mf.format_offset(p.scheduled), "at": p.at, "type": p.type, "ref": p.ref}
                         for p in plan],
            "cadence": {"http_probe_s": cfg.http_probe_interval, "checks_s": cfg.check_interval,
                        "snapshot_s": m.snapshot_interval, "collect_s": cfg.collect_interval,
                        "org_poll_s": 60},
            "identities": {"users": list(network.USER_IPS), **network.IDENTITY_IPS,
                           "org_accounts": identities.ORG_ACCOUNTS},
            "org": {"policy": m.org_policy, "pressure": list(m.org_pressure),
                    "facts": [f["topic"] for f in m.org_facts]},
            "faults": {ref: {"symptoms": list(f.symptoms), "transient": f.transient} for ref, f in FAULTS.items()},
            "hypervisor": {k: v for k, v in hv_status.items() if k in ("accel", "resets")}}, ts=t0)
        # The golden state, captured before the agent or any load exists, is the reference for
        # all later drift comparisons.
        if not prober.snapshot("baseline"):
            return "baseline_snapshot_failed", None
        if self.stop.is_set():                  # stopped meanwhile: do not start the agent at all
            return self.reason, None

        try:
            started = self.defender.start(m.run_id, m.model_defender, m.snapshot_interval)
            log.info("defender started: %s", started)
        except (Unreachable, RuntimeError) as exc:
            log.error("defender did not start: %s", exc)
            return "defender_start_failed", str(exc)

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
            # Every step on its own: one that fails never costs the round's other measurements.
            facts: dict = {}
            steps = (("defender_process", defender_alive),
                     ("guest_cycle", lambda: facts.update(prober.cycle())),     # health, fault facts, text
                     ("service_health", lambda: prober.service_health(facts)),
                     ("fault_conditions", lambda: prober.fault_conditions(facts=facts)),
                     ("security", prober.security_checks),
                     ("canaries", lambda: prober.canary_checks(facts)),
                     ("tasks", lambda: prober.task_checks(list(self.assigned_tasks))))
            for name, step in steps:
                try:
                    step()
                except Unreachable as exc:
                    log.warning("check %s: %s", name, str(exc)[:200])
                except Exception:
                    log.exception("check %s failed", name)

        self.responder = OrgResponder(cfg, monitor.emit, self.org_channel, m.seed, m.org_policy, m.org_facts,
                                      t0, pressure_tasks=m.org_pressure,
                                      repo=cfg.golden()["seed"]["ticket_repo"])

        collect_gateway, collect_target, collect_defender = collectors
        self.loops = [
            Loop("http-probe", cfg.http_probe_interval, prober.http_probe, self.stop),
            Loop("checks", cfg.check_interval, checks, self.stop),
            Loop("collect-target", cfg.collect_interval, collect_target.pull, self.stop),
            Loop("collect-gateway", cfg.collect_interval, collect_gateway.pull, self.stop),
            Loop("collect-defender", cfg.collect_interval, collect_defender.pull, self.stop),
            Loop("org-responder", 60, self.responder.poll, self.stop),
        ]
        for loop in self.loops:
            loop.start()
        # Started here, not in the reader thread: the handle exists before anything can stop the run.
        self.load_proc = self._start_load()
        self.load_thread = threading.Thread(target=self._read_load, args=(monitor,), name="load", daemon=True)
        self.load_thread.start()

        # ---- the run clock -------------------------------------------------------------------
        pending = list(plan)
        next_snapshot = m.snapshot_interval
        log.info("run %s started: %s, %d scheduled events", m.run_id, mf.format_offset(m.duration), len(plan))
        while not self.stop.is_set():
            elapsed = time.monotonic() - t0_mono
            if elapsed >= m.duration:
                break
            while pending and elapsed >= pending[0].at:
                ev = pending.pop(0)
                try:
                    again = self._play(ev, monitor, prober, elapsed)
                except Exception as exc:        # recorded; one bad event never ends the run
                    log.exception("scheduled %s %s failed", ev.type, ev.ref)
                    self._record_play_error(ev, monitor, elapsed, exc)
                    again = None
                if again is not None:           # on_conflict: delay -> try again a minute later
                    pending.append(again)
                    pending.sort(key=lambda e: e.at)
                    break
            if elapsed >= next_snapshot:
                self._quietly("operator paths", lambda: self._refresh_operator_paths(prober))
                prober.snapshot("interval")     # records a failed capture itself, never raises
                next_snapshot += m.snapshot_interval
            self._quietly("status file", lambda: self.write_status(
                "running", elapsed_s=int(elapsed), duration_s=m.duration, events_pending=len(pending),
                counts=self.store.counts(m.run_id)))
            self.stop.wait(min(5.0, max(0.2, m.duration - elapsed)))
        return self.reason, None

    # ------------------------------------------------------------------ pieces
    def _abort(self, reason: str) -> None:
        self.reason = reason
        self.stop.set()

    @staticmethod
    def _quietly(what: str, fn) -> None:
        """Teardown and bookkeeping steps: a failure is logged, never fatal."""
        try:
            fn()
        except Exception as exc:
            log.warning("%s: %s: %s", what, type(exc).__name__, str(exc)[:300])

    def _stop_background(self, reason: str) -> None:
        """After the run clock (the stop flag is set): the loops, the load generator and any
        ticket still being delivered come to an end."""
        for loop in self.loops:
            loop.join(timeout=180)
        if self.load_thread is not None:
            # The load generator runs for the same duration and ends with a summary; give it a
            # moment to finish by itself (it also summarises on SIGTERM). A run that ended early
            # stops it at once.
            if reason == "completed":
                self.load_thread.join(timeout=45)
            if self.load_proc and self.load_proc.poll() is None:
                self.load_proc.terminate()
                self.load_thread.join(timeout=60)
                if self.load_proc.poll() is None:
                    self.load_proc.kill()
        for delivery in self.deliveries:        # retries end with the stop flag; an attempt in flight finishes
            delivery.join(timeout=150)

    def _still_open(self, ref: str, prober: Prober) -> bool:
        """Is an earlier injection of this fault type still open? Transient faults: inside their
        observation window; the others: their own detector's latest verdict."""
        if FAULTS[ref].transient:
            return any(time.monotonic() < end for end in self.fault_open_until.get(ref, []))
        return ref in self.fault_open_until and prober.fault_state.get(ref) == "open"

    def _play(self, ev: PlannedEvent, monitor: Emitter, prober: Prober, elapsed: float) -> PlannedEvent | None:
        """Play one scheduled event. Returns a re-planned event if it has to wait (on_conflict: delay)."""
        base = self._base(ev, elapsed)
        if ev.type == "fault":
            return self._play_fault(ev, base, monitor, prober, elapsed)
        task = TASKS[ev.ref]
        log.info("assigning ops task %s", ev.ref)
        thread = threading.Thread(target=self._deliver, args=(task, base, monitor, prober),
                                  name=f"deliver-{ev.ref}", daemon=True)
        thread.start()
        self.deliveries.append(thread)
        return None

    @staticmethod
    def _base(ev: PlannedEvent, elapsed: float) -> dict:
        return {"ref": ev.ref, "scheduled_offset_s": ev.scheduled, "planned_offset_s": ev.at,
                "actual_offset_s": round(elapsed, 1)}

    def _record_play_error(self, ev: PlannedEvent, monitor: Emitter, elapsed: float, exc: Exception) -> None:
        error = f"{type(exc).__name__}: {exc}"[:300]
        kind = "fault_injected" if ev.type == "fault" else "task_assigned"
        extra = {"injected": False, "applied": False} if ev.type == "fault" else {"channel": "issue", "assigned": False}
        self._quietly("record failed event", lambda: monitor.emit(kind, {**self._base(ev, elapsed), **extra,
                                                                          "error": error}))

    def _play_fault(self, ev: PlannedEvent, base: dict, monitor: Emitter, prober: Prober,
                    elapsed: float) -> PlannedEvent | None:
        """Precondition -> inject -> effect (polled, see faults.await_effect) -> one fault_injected
        record. An injection that reports an error is still checked for its effect: a command that
        timed out on a slow guest may have done its work. `injected_at` is when the fault was put
        in place (the record itself is written once the effect is known)."""
        fault = FAULTS[ev.ref]
        common = {**base, "summary": fault.summary, "mechanism": fault.mechanism, "transient": fault.transient,
                  "symptoms": list(fault.symptoms)}
        if fault.transient:
            common["window_s"] = self.m.transient_window
        if self._still_open(ev.ref, prober):
            policy = self.m.on_conflict
            if policy == "delay" and elapsed + 60 < self.m.duration:
                log.info("fault %s: an earlier one is still open, retrying in 60 s", ev.ref)
                return PlannedEvent(ev.scheduled, round(elapsed + 60, 1), ev.type, ev.ref)
            if policy != "stack":
                log.info("fault %s skipped: an earlier injection is still open", ev.ref)
                monitor.emit("fault_injected", {**common, "injected": False, "applied": False,
                                                "skipped": "conflict: an earlier injection of this fault is still open",
                                                "on_conflict": policy})
                return None
        log.info("injecting fault %s", ev.ref)
        try:
            before = prober.fault_facts()
            may, why = fault.precondition(before)
        except Exception as exc:
            log.error("fault %s not injected: its precondition could not be checked: %s", ev.ref, exc)
            monitor.emit("fault_injected", {**common, "injected": False, "applied": False,
                                            "error": f"precondition not checkable: {type(exc).__name__}: {exc}"[:300]})
            return None
        if not may:
            log.warning("fault %s not applied: precondition failed (%s)", ev.ref, why)
            monitor.emit("fault_injected", {**common, "injected": False, "applied": False,
                                            "precondition": {"ok": False, "detail": why}})
            return None
        injected_at = telemetry.utc_now()
        detail, inject_error = None, None
        try:
            detail = fault.inject(prober.fault_ctx)
        except Exception as exc:
            inject_error = f"{type(exc).__name__}: {exc}"[:300]
            log.error("fault %s: the injection reported an error (checking its effect anyway): %s",
                      ev.ref, inject_error)
        polled = time.monotonic()
        took, effect, after = await_effect(fault, before, prober.fault_facts, sleep=self.stop.wait,
                                           cancelled=self.stop.is_set)
        waited = round(time.monotonic() - polled, 1)
        if took is None:            # no facts at all afterwards: unverified, trust the injection itself
            applied = injected = inject_error is None
        else:
            applied, injected = bool(took), bool(took) or inject_error is None
        payload = {**common, "injected": injected, "applied": applied, "detail": detail,
                   "injected_at": telemetry.format_ts(injected_at),
                   "precondition": {"ok": True, "detail": why},
                   "effect": {"ok": took, "detail": effect, "waited_s": waited,
                              **({"unverified": True} if took is None else {})}}
        if inject_error:
            payload["error"] = inject_error
        monitor.emit("fault_injected", payload)
        if applied:
            end = time.monotonic() + (self.m.transient_window if fault.transient else 0)
            self.fault_open_until.setdefault(ev.ref, []).append(end)
        else:
            log.warning("fault %s not applied: %s", ev.ref, inject_error or effect)
        # Judge the condition right away: a quick agent can close it before the next scheduled
        # check, and ground truth should still show that it was open.
        if after is not None:
            prober.fault_conditions([ev.ref], facts={"faults": after})
        return None

    def _deliver(self, task, base: dict, monitor: Emitter, prober: Prober) -> None:
        """Deliver one ticket (background: retries can take minutes) and record how it went."""
        setup = None
        try:
            if task.setup:
                setup = task.setup(TaskContext(self.cfg, self.ssh, prober.latest_state, prober.baseline_state,
                                               identity="org", org_channel=self.org_channel))
            ticket = deliver_ticket(self.cfg, task, self.org_channel)
        except DeliveryFailed as exc:
            log.error("task %s could not be delivered: %s", task.ref, exc)
            monitor.emit("task_assigned", {**base, "channel": "issue", "assigned": False, "setup": setup,
                                           "error": str(exc)[:300], "attempts": exc.attempts,
                                           "failure_reasons": [a.get("error") or f"HTTP {a.get('status')}"
                                                               for a in exc.attempts]})
            return
        except Exception as exc:                # whatever it was, the ticket is on record as not delivered
            log.error("task %s could not be assigned: %s", task.ref, exc)
            monitor.emit("task_assigned", {**base, "channel": "issue", "assigned": False, "setup": setup,
                                           "error": f"{type(exc).__name__}: {exc}"[:300]})
            return
        delivered = telemetry.utc_now()
        self.assigned_tasks.append(task.ref)
        monitor.emit("task_assigned", {**base, "channel": "issue", "ticket": {k: ticket[k] for k in ("repo", "number", "url")},
                                       "title": task.title, "trap": task.trap, "assigned": True, "setup": setup,
                                       "delivery_channel": ticket["delivery_channel"], "attempts": ticket["attempts"],
                                       "failure_reasons": ticket["failure_reasons"],
                                       "org": {"requester": task.org.requester, "approver": task.org.approver,
                                               "scope": task.org.scope} if task.org else None})
        if self.responder is not None:
            self.responder.register_ticket(ticket["number"], task.ref, delivered)

    def _refresh_operator_paths(self, prober: Prober) -> None:
        """Every path the operator account touched so far (audit mirror) is added to the
        ground-truth snapshot, so the scorer can see it return to its golden content."""
        for ev in self.store.events("ground_truth", self.m.run_id, source="target", type="config_change",
                                    min_seq=self._config_seq_seen + 1):
            self._config_seq_seen = max(self._config_seq_seen, ev["seq"])
            p = ev["payload"]
            if p.get("actor") == "operator" and p.get("kind") in ("file_change", "perm_change"):
                prober.operator_paths.update(x for x in p.get("paths", []) if x.startswith("/"))

    def _start_load(self) -> subprocess.Popen:
        # The load generator stops by itself when this process goes away (it watches its parent
        # and its stdout), so a crashed orchestrator never leaves it loading the target.
        cmd = [sys.executable, "-m", "observer.loadgen.runner", "--seed", str(self.m.seed),
               "--profile", self.m.load_profile, "--duration", str(self.m.duration)]
        with open(self.cfg.run_dir(self.m.run_id) / "loadgen.log", "w") as err:
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, stderr=err)

    def _read_load(self, monitor: Emitter) -> None:
        for line in self.load_proc.stdout:
            try:
                payload = json.loads(line)
            except ValueError:
                continue
            if payload.get("kind") == "write_ack":
                self.write_acks.append({k: v for k, v in payload.items() if k != "kind"})
            try:
                monitor.emit("load_event", payload)
            except Exception as exc:            # keep reading: a stalled pipe would block the load generator
                log.warning("load event not recorded: %s", exc)
        self.load_proc.wait()

    def _finish(self, monitor: Emitter, prober: Prober, collectors: list, t0_mono: float, reason: str,
                detail: str | None = None) -> int:
        """Teardown. The defender is stopped first so its last state snapshot is part of the run.
        Every step is on its own: none of them can keep run_end from being written."""
        self._quietly("status file", lambda: self.write_status("teardown"))
        log.info("teardown (%s)", reason)
        self._quietly("defender stop", self.defender.stop)

        def final_snapshot() -> None:
            self._refresh_operator_paths(prober)
            if prober.snapshot("final"):
                prober.integrity_check(self.write_acks)

        for what, step in (("final snapshot", final_snapshot), ("fault conditions", prober.fault_conditions),
                           ("canary checks", prober.canary_checks),
                           ("task checks", lambda: prober.task_checks(self.assigned_tasks))):
            self._quietly(f"final {what}", step)
        # Last pulls. Langfuse ingests asynchronously, so the defender's events are pulled until
        # two consecutive pulls bring nothing new, then once more from the run's start (a span
        # that started long before it was ingested — a long tool call — falls outside the
        # rolling window). The target and gateway logs are read once more after that.
        langfuse = next((c for c in collectors if isinstance(c, LangfuseCollector)), None)
        if langfuse is not None:
            quiet, deadline = 0, time.time() + 180
            while quiet < 2 and time.time() < deadline:
                time.sleep(8)
                try:
                    quiet = quiet + 1 if not langfuse.pull() else 0
                except Exception as exc:
                    log.warning("final pull of the defender's events: %s", str(exc)[:200])
            self._quietly("full pull of the defender's events", lambda: langfuse.pull(full=True))
        for collector in collectors:
            if not isinstance(collector, LangfuseCollector):
                self._quietly(f"final pull {type(collector).__name__}", collector.pull)
        self._quietly("gateway end_run", self.gateway.end_run)
        payload = {"reason": reason, "elapsed_s": round(time.monotonic() - t0_mono, 1),
                   "counts": self.store.counts(self.m.run_id)}
        if detail:
            payload["detail"] = detail[:500]
        collisions = {source: n for (run_id, source), n in self.store.collisions.items() if run_id == self.m.run_id}
        if collisions:
            payload["seq_collisions"] = collisions
        monitor.emit("run_end", payload)
        ended = telemetry.format_ts(telemetry.utc_now())
        self.store.run_finished(self.m.run_id, ended, reason)
        exported = None
        try:
            exported = self.store.export_jsonl(self.m.run_id, self.cfg.run_dir(self.m.run_id) / "events")
        except OSError as exc:
            log.error("export of run %s failed: %s", self.m.run_id, exc)
        self._quietly("status file", lambda: self.write_status("finished", reason=reason, counts=payload["counts"],
                                                               exported=exported))
        self.ssh.close()
        log.info("run %s finished: %s", self.m.run_id, reason)
        return 0 if reason == "completed" else 1
