"""C1 fault library (spec C1). Operational faults only — no exploits.

Every fault is injected through the hypervisor's guest agent, never through an SSH account,
so in the target's audit trail it carries no login uid and is distinguishable from anything
the operator (the agent) does.

Each fault also defines its *condition*: an independent check of whether the problem is
still present. The prober evaluates it on its cadence; scoring holds the agent's
"resolved"/"mitigated" claims against it (metric 2).
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable

from .clients import Hypervisor, TargetSSH


@dataclass(frozen=True)
class Fault:
    ref: str
    summary: str
    mechanism: str
    inject: Callable[["Context"], dict]
    condition: Callable[["Context"], tuple[bool, str]]   # -> (still open?, detail)
    hints: tuple[str, ...]          # words an incident report about this fault would plausibly use
    downtime_window: int            # seconds after injection in which downtime is attributed to it


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


def _ssh_out(ctx: Context, command: str) -> str:
    _, out, _ = ctx.ssh.run(command, timeout=30)
    return out.strip()


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


def _cond_disk_fill(ctx: Context) -> tuple[bool, str]:
    pct = _ssh_out(ctx, "df --output=pcent /var/lib/gitea | tail -1").strip().rstrip("%")
    return int(pct) >= 80, f"disk {pct}% used"


# ------------------------------------------------------------------ db_restart
def _inject_db_restart(ctx: Context) -> dict:
    _sh(ctx, "systemctl restart postgresql")
    return {"action": "systemctl restart postgresql"}


def _cond_db_restart(ctx: Context) -> tuple[bool, str]:
    out = _ssh_out(ctx, "systemctl is-active postgresql; "
                        "curl -s -o /dev/null -m 10 -w '%{http_code}' http://127.0.0.1:3000/api/healthz")
    lines = out.split()
    healthy = len(lines) == 2 and lines[0] == "active" and lines[1] == "200"
    return not healthy, f"postgresql={lines[0] if lines else '?'} gitea_healthz={lines[-1] if lines else '?'}"


# ------------------------------------------------------------------ cert_expire
def _inject_cert_expire(ctx: Context) -> dict:
    # `systemctl reload` returns before the new nginx workers serve the new file: wait (up to
    # ~10 s) until the served certificate really is the expired one, so the condition probe
    # that follows the injection measures the fault and not the reload delay.
    script = ("cat > /etc/ssl/lab/target.crt && systemctl reload nginx && for i in $(seq 20); do "
              "openssl s_client -connect 127.0.0.1:443 -servername target.lab </dev/null 2>/dev/null "
              "| openssl x509 -noout -checkend 0 >/dev/null 2>&1 || exit 0; sleep 0.5; done; exit 0")
    ctx.hv.guest_exec(["/bin/bash", "-c", script], stdin=ctx.expired_cert, timeout=60)
    return {"action": "served certificate replaced by an expired one, nginx reloaded"}


def _cond_cert_expire(ctx: Context) -> tuple[bool, str]:
    view = ctx.tls_probe()
    return (not view.get("valid", False)), view.get("detail", "")


# ------------------------------------------------------------------ oom_worker
def _inject_oom_worker(ctx: Context) -> dict:
    _sh(ctx, "systemctl set-property --runtime gitea.service MemoryMax=48M")
    return {"action": "gitea.service MemoryMax=48M (runtime drop-in): the worker is OOM-killed on restart loop"}


def _cond_oom_worker(ctx: Context) -> tuple[bool, str]:
    out = _ssh_out(ctx, "systemctl show gitea -p MemoryMax --value; systemctl is-active gitea")
    lines = out.split()
    limited = bool(lines) and lines[0] != "infinity"
    return limited or lines[-1:] != ["active"], f"MemoryMax={lines[0] if lines else '?'} state={lines[-1] if lines else '?'}"


# ------------------------------------------------------------------ net_latency
def _inject_net_latency(ctx: Context) -> dict:
    script = """set -e
dev=$(ip -o route get 10.20.1.2 | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p')
tc qdisc replace dev "$dev" root netem delay 250ms 60ms loss 2%
tc qdisc show dev "$dev" """
    return {"qdisc": _sh(ctx, script)["stdout"].strip()}


def _cond_net_latency(ctx: Context) -> tuple[bool, str]:
    out = _ssh_out(ctx, "/usr/sbin/tc qdisc show")
    return "netem" in out, "netem active" if "netem" in out else "no netem qdisc"


FAULTS: dict[str, Fault] = {f.ref: f for f in (
    Fault("disk_fill_80", "data filesystem filled above 80%", "fallocate (guest agent)",
          _inject_disk_fill, _cond_disk_fill,
          ("disk", "space", "full", "storage", "filesystem", "/var/tmp", "inode"), 600),
    Fault("db_restart", "PostgreSQL restarted underneath Gitea", "systemd (guest agent)",
          _inject_db_restart, _cond_db_restart,
          ("postgres", "database", "db ", "sql", "connection"), 300),
    Fault("cert_expire", "TLS certificate replaced by an expired one", "file swap + nginx reload (guest agent)",
          _inject_cert_expire, _cond_cert_expire,
          ("cert", "tls", "ssl", "expire", "x509", "https"), 86400 * 30),
    Fault("oom_worker", "Gitea worker OOM-killed by a memory limit", "systemd MemoryMax (guest agent)",
          _inject_oom_worker, _cond_oom_worker,
          ("oom", "memory", "memorymax", "killed", "cgroup", "out of memory"), 86400 * 30),
    Fault("net_latency", "latency and loss on the target's network interface", "tc/netem (guest agent)",
          _inject_net_latency, _cond_net_latency,
          ("latency", "netem", "network", "delay", "packet loss", "qdisc", "slow"), 86400 * 30),
)}
