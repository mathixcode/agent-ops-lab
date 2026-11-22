"""Build the trimmed long-20h-003 regression fixture from the run export (read-only).

    python tests/fixtures/build_long_20h_003.py [runs/long-20h-003]

Keeps only what the attribution scorer needs, with payloads reduced to the fields it reads:

    monitor/run_start            manifest and schedule (golden metadata dropped)
    monitor/run_end
    monitor/fault_injected       complete
    monitor/task_assigned        complete
    monitor/probe_result         http_availability (statuses, errors, timings), and the
                                 fault_condition probes where a fault's state changed
    monitor/ground_truth_snapshot  trigger + the snapshot's files under /etc/nginx, /etc/ssl,
                                 /etc/systemd and /run/systemd (for the change timeline)
    target/config_change         everything by the operator except plain read-only commands
    target/health                the SSH collector's gitea_healthz (out-of-band fallback)

The export in runs/ is only read. Output: tests/fixtures/long-20h-003/ground_truth.trimmed.jsonl.gz
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "long-20h-003" / "ground_truth.trimmed.jsonl.gz"
SNAPSHOT_PREFIXES = ("/etc/nginx", "/etc/ssl", "/etc/systemd", "/run/systemd")


def trim(ev: dict, last_state: dict) -> dict | None:
    src, typ, p = ev["source"], ev["type"], ev["payload"]
    if typ in ("fault_injected", "task_assigned", "run_end"):
        return ev
    if typ == "run_start":
        return {**ev, "payload": {k: v for k, v in p.items() if k in ("manifest", "schedule", "cadence")}}
    if typ == "probe_result":
        check = p["check"]
        if check == "http_availability":
            keep = {"check": check, "ok": p["ok"]}
            for part in ("healthz", "api"):
                if part in p:
                    keep[part] = {k: v for k, v in p[part].items() if k in ("status", "error", "ms", "signature",
                                                                             "component")}
            return {**ev, "payload": keep}
        if check.startswith("fault_condition:"):
            if last_state.get(check) == p.get("state"):
                return None
            last_state[check] = p.get("state")
            return {**ev, "payload": {k: v for k, v in p.items() if k in ("check", "ok", "state", "detail", "detector")}}
        return None
    if typ == "ground_truth_snapshot":
        state = p.get("state") or {}
        files = {k: v for k, v in (state.get("files") or {}).items() if k.startswith(SNAPSHOT_PREFIXES)}
        return {**ev, "payload": {"trigger": p.get("trigger"), "captured": p.get("captured"),
                                  "state": {"files": files, "services": state.get("services", {})}}}
    if src == "target" and typ == "config_change":
        if p.get("actor") == "operator" and p.get("kind") == "exec":
            argv = " ".join(p.get("argv") or [])
            if not any(t in argv for t in ("nft ", "iptables", "ufw ", "tc ")):
                return None
        return ev
    if src == "target" and typ == "health":
        return {**ev, "payload": {"services": {}, "gitea_healthz": p.get("gitea_healthz")}}
    return None


def main() -> None:
    run = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "runs" / "long-20h-003"
    kept, total, last_state = [], 0, {}
    with open(run / "events" / "ground_truth.jsonl", encoding="utf-8") as fh:
        for line in fh:
            total += 1
            ev = trim(json.loads(line), last_state)
            if ev is not None:
                kept.append(ev)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(OUT, "wb", mtime=0) as gz:           # mtime=0: byte-identical rebuilds
        for ev in kept:
            gz.write((json.dumps(ev, separators=(",", ":"), sort_keys=True) + "\n").encode())
    print(f"{OUT}: {len(kept)} of {total} events, {OUT.stat().st_size // 1024} KiB")


if __name__ == "__main__":
    main()
