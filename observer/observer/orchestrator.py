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
from .faults import FAULTS
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
        self.org_channel = OrgChannel(cfg, self.hv)
        self.responder: OrgResponder | None = None
        self.fault_open_until: dict[str, list[float]] = {}      # ref -> transient windows (monotonic end)
        self.deliveries: list[threading.Thread] = []

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
                        "snapshot_s": m.snapshot_interval, "collect_s": cfg.collect_interval,
                        "org_poll_s": 60},
            "identities": {"users": list(network.USER_IPS), **network.IDENTITY_IPS,
                           "org_accounts": identities.ORG_ACCOUNTS},
            "org": {"policy": m.org_policy, "pressure": list(m.org_pressure),
                    "facts": [f["topic"] for f in m.org_facts]},
            "faults": {ref: {"symptoms": list(f.symptoms), "transient": f.transient} for ref, f in FAULTS.items()},
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
            facts = prober.cycle()              # one guest-agent call: health, fault facts, recent text
            prober.service_health(facts)
            prober.fault_conditions(facts=facts)
            prober.security_checks()
            prober.canary_checks(facts)
            prober.task_checks(list(self.assigned_tasks))

        self.responder = OrgResponder(cfg, monitor.emit, self.org_channel, m.seed, m.org_policy, m.org_facts,
                                      t0, pressure_tasks=m.org_pressure,
                                      repo=cfg.golden()["seed"]["ticket_repo"])

        loops = [
            Loop("http-probe", cfg.http_probe_interval, prober.http_probe, self.stop),
            Loop("checks", cfg.check_interval, checks, self.stop),
            Loop("collect-target", cfg.collect_interval, collect_target.pull, self.stop),
            Loop("collect-gateway", cfg.collect_interval, collect_gateway.pull, self.stop),
            Loop("collect-defender", cfg.collect_interval, collect_defender.pull, self.stop),
            Loop("org-responder", 60, self.responder.poll, self.stop),
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
                again = self._play(pending.pop(0), monitor, prober, elapsed)
                if again is not None:           # on_conflict: delay -> try again a minute later
                    pending.append(again)
                    pending.sort(key=lambda e: e.at)
                    break
            if elapsed >= next_snapshot:
                self._refresh_operator_paths(prober)
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
        for delivery in self.deliveries:        # a ticket still retrying finishes (or fails) on record
            delivery.join(timeout=420)
        return self._finish(monitor, prober, [collect_gateway, collect_target, collect_defender],
                            t0_mono, self.reason)

    # ------------------------------------------------------------------ pieces
    def _abort(self, reason: str) -> None:
        self.reason = reason
        self.stop.set()

    def _still_open(self, ref: str, prober: Prober) -> bool:
        """Is an earlier injection of this fault type still open? Transient faults: inside their
        observation window; the others: their own detector's latest verdict."""
        if FAULTS[ref].transient:
            return any(time.monotonic() < end for end in self.fault_open_until.get(ref, []))
        return ref in self.fault_open_until and prober.fault_state.get(ref) == "open"

    def _play(self, ev: PlannedEvent, monitor: Emitter, prober: Prober, elapsed: float) -> PlannedEvent | None:
        """Play one scheduled event. Returns a re-planned event if it has to wait (on_conflict: delay)."""
        base = {"ref": ev.ref, "scheduled_offset_s": ev.scheduled, "planned_offset_s": ev.at,
                "actual_offset_s": round(elapsed, 1)}
        if ev.type == "fault":
            return self._play_fault(ev, base, monitor, prober, elapsed)
        task = TASKS[ev.ref]
        log.info("assigning ops task %s", ev.ref)
        thread = threading.Thread(target=self._deliver, args=(task, base, monitor, prober),
                                  name=f"deliver-{ev.ref}", daemon=True)
        thread.start()
        self.deliveries.append(thread)
        return None

    def _play_fault(self, ev: PlannedEvent, base: dict, monitor: Emitter, prober: Prober,
                    elapsed: float) -> PlannedEvent | None:
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
            if not may:
                log.warning("fault %s not applied: precondition failed (%s)", ev.ref, why)
                monitor.emit("fault_injected", {**common, "injected": False, "applied": False,
                                                "precondition": {"ok": False, "detail": why}})
                return None
            detail = fault.inject(prober.fault_ctx)
            after = prober.fault_facts()
            took, effect = fault.effect(before, after)
        except (Unreachable, RuntimeError, TimeoutError, KeyError, ValueError) as exc:
            log.error("fault %s could not be injected: %s", ev.ref, exc)
            monitor.emit("fault_injected", {**common, "injected": False, "applied": False, "error": str(exc)[:300]})
            return None
        monitor.emit("fault_injected", {**common, "injected": True, "applied": took, "detail": detail,
                                        "precondition": {"ok": True, "detail": why},
                                        "effect": {"ok": took, "detail": effect}})
        if took:
            end = time.monotonic() + (self.m.transient_window if fault.transient else 0)
            self.fault_open_until.setdefault(ev.ref, []).append(end)
        else:
            log.warning("fault %s injected but its effect was not observed: %s", ev.ref, effect)
        # Judge the condition right away: a quick agent can close it before the next scheduled
        # check, and ground truth should still show that it was open.
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
        except (requests.RequestException, Unreachable, KeyError, StopIteration, ValueError) as exc:
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
        for ev in self.store.events("ground_truth", self.m.run_id, source="target", type="config_change"):
            p = ev["payload"]
            if p.get("actor") == "operator" and p.get("kind") in ("file_change", "perm_change"):
                prober.operator_paths.update(x for x in p.get("paths", []) if x.startswith("/"))

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
            self._refresh_operator_paths(prober)
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
