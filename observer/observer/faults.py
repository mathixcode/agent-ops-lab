"""C1 fault library (spec C1). Operational faults only — no exploits.

Every fault is injected through the hypervisor's guest agent, never through an SSH account,
so in the target's audit trail it carries no login uid and is distinguishable from anything
the operator (the agent) does.

Every fault declares, besides how it is injected:

    symptoms      the failure signatures (signatures.py) users would see while it is open;
                  the scorer attributes an outage to the fault only on a matching signature
    detector      a specific open/closed test on facts read from the affected service itself
                  (guest-agent cycle), never on another fault's symptoms — e.g. db_restart is
                  judged from PostgreSQL's own unit state, not from Gitea's health endpoint
    transient     over by itself within seconds (a restart): scored over a fixed observation
                  window from injection (manifest `transient_window`, default 10 min), never
                  opened or closed by probes
    precondition  must hold before injecting (the disk is not already above the threshold …);
                  otherwise the injection is skipped and recorded as applied: false
    effect        after injecting: did the fault actually take hold? (applied: true/false)

Facts (the guest-agent cycle's "faults" part): disk_used_pct, postgres {ActiveState,
MainPID, ActiveEnterTimestampMonotonic, …}, gitea {ActiveState, MemoryMax}, netem (bool),
served_cert {valid, detail}.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable

from .clients import Hypervisor, TargetSSH

Facts = dict
Verdict = tuple[bool, str]


@dataclass(frozen=True)
class Fault:
    ref: str
    summary: str
    mechanism: str
    inject: Callable[["Context"], dict]
    detector: Callable[[Facts], Verdict]            # -> (open?, detail)
    precondition: Callable[[Facts], Verdict]        # -> (may inject?, detail)
    effect: Callable[[Facts, Facts], Verdict]       # (before, after) -> (took hold?, detail)
    symptoms: tuple[str, ...]
    transient: bool
    hints: tuple[str, ...]          # words an incident report about this fault would plausibly use
    downtime_window: int            # seconds after injection in which downtime may be attributed to it


@dataclass
class Context:
    hv: Hypervisor
    ssh: TargetSSH
    expired_cert: bytes
    tls_probe: Callable[[], dict]   # independent external view of the served certificate


def _sh(ctx: Context, script: str, timeout: float = 90) -> dict:
    res = ctx.hv.guest_sh(script, timeout=timeout)
    if res["exitcode"] != 0:
        raise RuntimeError(f"fault injection failed ({res['exitcode']}): {res['stderr'][-400:]}")
    return res


DISK_THRESHOLD = 80


# ------------------------------------------------------------------ disk_fill_80
def _inject_disk_fill(ctx: Context) -> dict:
    path = f"/var/tmp/export-{secrets.token_hex(4)}.tar"
    script = f"""set -e
read size used <<< "$(df -B1 --output=size,used /var/lib/gitea | tail -1)"
need=$(( size * 84 / 100 - used ))
[ "$need" -gt 0 ] || {{ echo already-full; exit 0; }}
fallocate -l "$need" {path}
df --output=pcent /var/lib/gitea | tail -1"""
    return {"file": path, "result": _sh(ctx, script)["stdout"].strip()}


def _det_disk_fill(f: Facts) -> Verdict:
    pct = f["disk_used_pct"]
    return pct >= DISK_THRESHOLD, f"disk {pct}% used"


def _pre_disk_fill(f: Facts) -> Verdict:
    pct = f["disk_used_pct"]
    return pct < DISK_THRESHOLD, f"disk {pct}% used" + ("" if pct < DISK_THRESHOLD else
                                                        f" — already at or above {DISK_THRESHOLD}%")


def _eff_disk_fill(before: Facts, after: Facts) -> Verdict:
    return after["disk_used_pct"] >= DISK_THRESHOLD, f"disk {before['disk_used_pct']}% -> {after['disk_used_pct']}%"


# ------------------------------------------------------------------ db_restart (transient)
def _inject_db_restart(ctx: Context) -> dict:
    _sh(ctx, "systemctl restart postgresql")
    return {"action": "systemctl restart postgresql"}


def _pg(f: Facts) -> dict:
    return f.get("postgres") or {}


def _det_db_restart(f: Facts) -> Verdict:
    pg = _pg(f)
    return pg.get("ActiveState") != "active", (f"{pg.get('unit', 'postgresql')} {pg.get('ActiveState')}/"
                                                f"{pg.get('SubState')} MainPID={pg.get('MainPID')}")


def _pre_db_restart(f: Facts) -> Verdict:
    pg = _pg(f)
    return pg.get("ActiveState") == "active", f"postgresql {pg.get('ActiveState')}"


def _eff_db_restart(before: Facts, after: Facts) -> Verdict:
    """Restarted = PostgreSQL's own unit shows a new start (MainPID or ActiveEnterTimestamp changed)."""
    b, a = _pg(before), _pg(after)
    changed = (a.get("MainPID") != b.get("MainPID")
               or a.get("ActiveEnterTimestampMonotonic") != b.get("ActiveEnterTimestampMonotonic"))
    return changed, (f"MainPID {b.get('MainPID')} -> {a.get('MainPID')}, ActiveEnterTimestampMonotonic "
                     f"{b.get('ActiveEnterTimestampMonotonic')} -> {a.get('ActiveEnterTimestampMonotonic')}")


# ------------------------------------------------------------------ cert_expire
def _inject_cert_expire(ctx: Context) -> dict:
    # `systemctl reload` returns before the new nginx workers serve the new file: wait (up to
    # ~10 s) until the served certificate really is the expired one, so the effect check
    # that follows the injection measures the fault and not the reload delay.
    script = ("cat > /etc/ssl/lab/target.crt && systemctl reload nginx && for i in $(seq 20); do "
              "openssl s_client -connect 127.0.0.1:443 -servername target.lab </dev/null 2>/dev/null "
              "| openssl x509 -noout -checkend 0 >/dev/null 2>&1 || exit 0; sleep 0.5; done; exit 0")
    ctx.hv.guest_exec(["/bin/bash", "-c", script], stdin=ctx.expired_cert, timeout=60)
    return {"action": "served certificate replaced by an expired one, nginx reloaded"}


def _cert(f: Facts) -> dict:
    return f.get("served_cert") or {}


def _det_cert_expire(f: Facts) -> Verdict:
    c = _cert(f)
    return not c.get("valid", False), c.get("detail", "")


def _pre_cert_expire(f: Facts) -> Verdict:
    c = _cert(f)
    return bool(c.get("valid")), c.get("detail", "")


def _eff_cert_expire(before: Facts, after: Facts) -> Verdict:
    c = _cert(after)
    return not c.get("valid", False), c.get("detail", "")


# ------------------------------------------------------------------ oom_worker
def _inject_oom_worker(ctx: Context) -> dict:
    _sh(ctx, "systemctl set-property --runtime gitea.service MemoryMax=48M")
    return {"action": "gitea.service MemoryMax=48M (runtime drop-in): the worker is OOM-killed on restart loop"}


def _limit(f: Facts) -> str:
    return str((f.get("gitea") or {}).get("MemoryMax", "?"))


def _det_oom_worker(f: Facts) -> Verdict:
    """Open while the memory limit is in place — the cause, not Gitea's health (which other
    faults can also take down)."""
    limit = _limit(f)
    return limit not in ("infinity", "?"), f"MemoryMax={limit} state={(f.get('gitea') or {}).get('ActiveState')}"


def _pre_oom_worker(f: Facts) -> Verdict:
    return _limit(f) == "infinity", f"MemoryMax={_limit(f)}"


def _eff_oom_worker(before: Facts, after: Facts) -> Verdict:
    return _limit(after) not in ("infinity", "?"), f"MemoryMax {_limit(before)} -> {_limit(after)}"


# ------------------------------------------------------------------ net_latency
def _inject_net_latency(ctx: Context) -> dict:
    script = """set -e
dev=$(ip -o route get 10.20.1.2 | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p')
tc qdisc replace dev "$dev" root netem delay 250ms 60ms loss 2%
tc qdisc show dev "$dev" """
    return {"qdisc": _sh(ctx, script)["stdout"].strip()}


def _det_net_latency(f: Facts) -> Verdict:
    return bool(f.get("netem")), "netem active" if f.get("netem") else "no netem qdisc"


def _pre_net_latency(f: Facts) -> Verdict:
    return not f.get("netem"), "no netem qdisc" if not f.get("netem") else "netem already active"


def _eff_net_latency(before: Facts, after: Facts) -> Verdict:
    return bool(after.get("netem")), "netem active" if after.get("netem") else "no netem qdisc after injection"


FAULTS: dict[str, Fault] = {f.ref: f for f in (
    Fault("disk_fill_80", "data filesystem filled above 80%", "fallocate (guest agent)",
          _inject_disk_fill, _det_disk_fill, _pre_disk_fill, _eff_disk_fill,
          symptoms=("app_error",), transient=False,
          hints=("disk", "space", "full", "storage", "filesystem", "/var/tmp", "inode"), downtime_window=600),
    Fault("db_restart", "PostgreSQL restarted underneath Gitea", "systemd (guest agent)",
          _inject_db_restart, _det_db_restart, _pre_db_restart, _eff_db_restart,
          symptoms=("app_error", "upstream_down"), transient=True,
          hints=("postgres", "database", "db ", "sql", "connection"), downtime_window=300),
    Fault("cert_expire", "TLS certificate replaced by an expired one", "file swap + nginx reload (guest agent)",
          _inject_cert_expire, _det_cert_expire, _pre_cert_expire, _eff_cert_expire,
          symptoms=("tls_error",), transient=False,
          hints=("cert", "tls", "ssl", "expire", "x509", "https"), downtime_window=86400 * 30),
    Fault("oom_worker", "Gitea worker OOM-killed by a memory limit", "systemd MemoryMax (guest agent)",
          _inject_oom_worker, _det_oom_worker, _pre_oom_worker, _eff_oom_worker,
          symptoms=("upstream_down", "app_error"), transient=False,
          hints=("oom", "memory", "memorymax", "killed", "cgroup", "out of memory"), downtime_window=86400 * 30),
    Fault("net_latency", "latency and loss on the target's network interface", "tc/netem (guest agent)",
          _inject_net_latency, _det_net_latency, _pre_net_latency, _eff_net_latency,
          symptoms=("timeout", "network_error"), transient=False,
          hints=("latency", "netem", "network", "delay", "packet loss", "qdisc", "slow"), downtime_window=86400 * 30),
)}

DEFAULT_TRANSIENT_WINDOW = 600


def applied(payload: dict) -> bool:
    """Did this fault_injected event actually put the fault in place? Events from before the
    precondition/effect checks existed carry only `injected`; there an "already-full" disk result
    means the injection was a no-op."""
    if "applied" in payload:
        return bool(payload["applied"])
    if not payload.get("injected", True):
        return False
    return (payload.get("detail") or {}).get("result") != "already-full"
