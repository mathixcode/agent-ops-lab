"""Read-only interim digest of a run in progress (`lab-observer summary`, `labctl.py status --summary`).

It reads exactly two things: the C3 datastore, opened READ-ONLY, and the orchestrator's
current.json. It writes nothing, talks to no lab component, opens no connection of any kind
(it is started with `docker compose exec`, inside the observer), and does not interfere with
the run. What can only be known at teardown — the final snapshot, the data-integrity check and
the state-divergence verdicts that depend on them — is reported as "pending".

Layers stay labelled: everything under `ground_truth` is measured independently; everything
under `agent_view` is what the defender said about itself.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

from labcontracts import manifest as mf, telemetry

from .scoring import metrics
from .scoring.model import AgentView, GroundTruth, load
from .store import Store

PENDING = "pending (needs teardown: final snapshot and integrity check)"


def _iso(ts: dt.datetime | None) -> str | None:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def read_current(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def schedule_position(truth: GroundTruth, elapsed_s: float | None) -> dict[str, Any]:
    rs = truth.run_start
    plan = (rs.payload.get("schedule") or []) if rs else []
    played = len(truth.of("monitor", "fault_injected")) + len(truth.of("monitor", "task_assigned"))
    upcoming = [e for e in plan if elapsed_s is None or e.get("at", 0) > elapsed_s]
    nxt = upcoming[0] if upcoming else None
    return {"events_planned": len(plan), "events_played": played,
            "next": ({"type": nxt["type"], "ref": nxt["ref"], "at": mf.format_offset(nxt["at"]),
                      "in": mf.format_offset(max(0, int(nxt["at"] - elapsed_s)))}
                     if nxt and elapsed_s is not None else None)}


def incidents(truth: GroundTruth, agent: AgentView) -> dict[str, Any]:
    """Injected faults with the LATEST fault_condition probe (ground truth), next to what the
    agent has reported (agent view). The two are shown side by side, never merged."""
    rows = []
    for w in metrics.fault_windows(truth):
        probes = [p for p in truth.probes(f"fault_condition:{w.ref}") if p.ts >= w.injected]
        latest = probes[-1] if probes else None
        rows.append({"ref": w.ref, "injected": _iso(w.injected),
                     "latest_probe_state": latest.payload.get("state") if latest else "not probed yet",
                     "latest_probe_at": _iso(latest.ts) if latest else None})
    reports = agent.of("incident_report")
    by_status: dict[str, int] = {}
    for r in reports:
        by_status[r.payload["status"]] = by_status.get(r.payload["status"], 0) + 1
    return {"ground_truth": {"injected": len(rows),
                             "still_open": sum(1 for r in rows if r["latest_probe_state"] == "open"),
                             "faults": rows},
            "agent_view": {"reports": len(reports), "by_status": by_status,
                           "last_report": ({"ts": _iso(reports[-1].ts), "incident_id": reports[-1].payload["incident_id"],
                                            "status": reports[-1].payload["status"]} if reports else None)}}


def summarize(store: Store, run_id: str, current: dict[str, Any] | None,
              now: dt.datetime | None = None) -> dict[str, Any]:
    now = now or telemetry.utc_now()
    run = store.run(run_id)
    truth, agent = load(store, run_id)
    live = bool(current and current.get("run_id") == run_id)
    phase = current.get("phase") if live else (run or {}).get("status")
    rs = truth.run_start
    if truth.run_end:
        elapsed = truth.run_end.payload.get("elapsed_s")
    elif live and current.get("elapsed_s") is not None:
        elapsed = current["elapsed_s"]
    else:
        elapsed = (now - rs.ts).total_seconds() if rs else None
    duration = (rs.payload.get("manifest") or {}).get("duration") if rs else None

    g = metrics.ground_truth(truth)
    changes = truth.of("target", "config_change")
    actors: dict[str, int] = {}
    for c in changes:
        actors[c.payload.get("actor") or "?"] = actors.get(c.payload.get("actor") or "?", 0) + 1
    sup = metrics.supporting(truth)
    alive = [e for e in truth.probes("defender_process") if not e.payload.get("inconclusive")]
    last_alive = alive[-1] if alive else None
    tools = agent.of("tool_call")
    decisions = agent.of("decision")
    last_tool = tools[-1] if tools else None
    last_decision = decisions[-1] if decisions else None
    finished = truth.run_end is not None

    return {
        "run_id": run_id, "phase": phase, "as_of": _iso(now),
        "elapsed": mf.format_offset(int(elapsed)) if elapsed is not None else None,
        "duration": mf.format_offset(duration) if duration else None,
        "schedule": schedule_position(truth, elapsed),
        "ground_truth": {
            "availability_so_far": {**g["availability"], "latency_ms": g["latency_ms"]},
            "incidents": incidents(truth, agent)["ground_truth"],
            "config_changes": {"total": len(changes), "by_actor": actors},
            "canaries": {"egress_events": sup["canary_egress"]["events"],
                         "external": sup["canary_egress"]["external"],
                         "to_model_provider": sup["canary_egress"]["to_model_provider"],
                         "exposures_on_target": len(sup["canary_exposure"])},
            "defender_process": ({"running": bool(last_alive.payload["ok"]), "checked_at": _iso(last_alive.ts),
                                  "driver": last_alive.payload.get("driver"),
                                  "agent_turns": last_alive.payload.get("agent_turns"),
                                  "driver_error": last_alive.payload.get("driver_error")}
                                 if last_alive else "no liveness check yet"),
            "data_integrity": g["data_integrity"] if finished else PENDING,
            "final_snapshot": "taken" if finished else PENDING,
        },
        "agent_view": {
            "incident_reports": incidents(truth, agent)["agent_view"],
            "last_action": ({"ts": _iso(last_tool.ts), "tool": last_tool.payload["tool"],
                             "ok": last_tool.payload.get("ok"),
                             "args": json.dumps(last_tool.payload.get("args"), ensure_ascii=False)[:200]}
                            if last_tool else None),
            "last_intent": ({"ts": _iso(last_decision.ts), "intent": last_decision.payload["intent"][:200]}
                            if last_decision else None),
            "state_snapshots": len(agent.of("state_snapshot")),
            "usage": metrics.usage(truth, agent, now=now),
        },
        "not_yet_scored": ([] if finished else
                           ["false-resolution rate and state divergence (scored offline: labctl.py score)",
                            "data integrity", "final snapshot"]),
    }


def text(s: dict[str, Any]) -> str:
    gt, av = s["ground_truth"], s["agent_view"]
    a = gt["availability_so_far"]
    u = av["usage"]
    lines = [f"run {s['run_id']} — {s['phase']}, {s['elapsed'] or '?'} of {s['duration'] or '?'} (as of {s['as_of']})"]
    sch = s["schedule"]
    nxt = sch["next"]
    lines.append(f"schedule: {sch['events_played']}/{sch['events_planned']} events played"
                 + (f"; next {nxt['type']} {nxt['ref']} at {nxt['at']} (in {nxt['in']})" if nxt else ""))
    lines += ["", "GROUND TRUTH (measured independently)",
              f"  availability so far: {a['availability_pct'] if a['availability_pct'] is not None else 'n/a'}% "
              f"({a['probes_ok']}/{a['probes']} probes), {a['outages']} outage(s), {a['downtime_s']} s down; "
              f"latency p50 {a['latency_ms']['p50']} ms, p95 {a['latency_ms']['p95']} ms"]
    inc = gt["incidents"]
    lines.append(f"  incidents injected: {inc['injected']}, still open at the latest probe: {inc['still_open']}")
    for f in inc["faults"]:
        lines.append(f"    - {f['ref']} injected {f['injected']}: {f['latest_probe_state']}"
                     + (f" (probe {f['latest_probe_at']})" if f["latest_probe_at"] else ""))
    cc = gt["config_changes"]
    lines.append(f"  config changes (audit trail): {cc['total']}"
                 + (" — " + ", ".join(f"{k} {v}" for k, v in sorted(cc["by_actor"].items())) if cc["by_actor"] else ""))
    c = gt["canaries"]
    lines.append(f"  canary hits: egress {c['egress_events']} (external {c['external']}, to model provider "
                 f"{c['to_model_provider']}), exposures on the target {c['exposures_on_target']}")
    dp = gt["defender_process"]
    lines.append("  defender process: " + (dp if isinstance(dp, str) else
                 f"{'running' if dp['running'] else 'NOT RUNNING'} (checked {dp['checked_at']}), driver {dp['driver']}, "
                 f"{dp['agent_turns']} agent turn(s)" + (f", last error: {dp['driver_error']}" if dp["driver_error"] else "")))
    lines.append(f"  data integrity: {gt['data_integrity'] if isinstance(gt['data_integrity'], str) else ('ok' if gt['data_integrity']['ok'] else 'see report')}")
    r = av["incident_reports"]
    lines += ["", "AGENT VIEW (what the defender reported about itself)",
              f"  incident reports: {r['reports']}" + (" — " + ", ".join(f"{k} {v}" for k, v in sorted(r["by_status"].items()))
                                                       if r["by_status"] else "")]
    if av["last_action"]:
        la = av["last_action"]
        lines.append(f"  last action: {la['ts']} {la['tool']} {'ok' if la['ok'] else 'failed'} {la['args']}")
    if av["last_intent"]:
        lines.append(f"  last stated intent: {av['last_intent']['intent']}")
    t = u["totals"]
    est = u["cost"]["estimate_usd"]
    lines.append(f"  usage: {u['turns']} turn(s), {t['total_tokens']:,} tokens (in {t['input_tokens']:,}, "
                 f"out {t['output_tokens']:,}, cache read {t['cache_read_tokens']:,}), "
                 f"est. cost {('~$' + format(est, '.4f')) if est is not None else 'n/a'}"
                 + (" — not billed (subscription)" if u["cost"]["billed"] is False else ""))
    for i in u["per_incident"]:
        lines.append(f"    - {i['ref']}: {i['turns']} turn(s), {i['total_tokens']:,} tokens")
    if s["not_yet_scored"]:
        lines += ["", "pending until teardown: " + "; ".join(s["not_yet_scored"])]
    return "\n".join(lines)


def main(db_path: Path, current_path: Path, run_id: str | None, as_json: bool) -> int:
    current = read_current(current_path)
    if not db_path.exists():
        print("no datastore yet — no run has started")
        return 1
    store = Store(db_path, readonly=True)          # C3 cannot be written through this handle
    try:
        rid = run_id or (current or {}).get("run_id") or ((store.latest_run() or {}).get("run_id"))
        if not rid or store.run(rid) is None:
            print(f"no run {rid!r} in the datastore" if rid else "no run yet")
            return 1
        digest = summarize(store, rid, current)
    finally:
        store.close()
    print(json.dumps(digest, indent=2, default=str) if as_json else text(digest))
    return 0
