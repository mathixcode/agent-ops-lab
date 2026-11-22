"""The active operator-change timeline — which persistent changes the operator account had in
place at any moment of the run, built only from the boundary record (auditd with the
operator's login uid) and the ground-truth snapshots. Nothing the agent reported is used.

A change is one of

    file           a write, create, rename onto, or delete of a path by the operator (auditd
                   file watches; `perm_change` counts as a write of the path's attributes)
    unit_property  `systemctl set-property <unit> <Prop>=<value>` (persists for the unit)
    firewall       nft / iptables / ip6tables / ufw commands that change rules
    tc             tc qdisc/class/filter commands that change traffic control

and stays *active* until

    golden_hash    a later ground-truth snapshot shows the path back at its golden content
                   (or the firewall ruleset / qdiscs / unit property back at their baseline)
    deleted        the path was deleted and it did not exist in the golden state
    overwritten    a newer change to the same path replaced it (the path stays changed; the
                   newer change is a new entry that starts at the same moment)
    reset          a command that clears what it changed (`nft flush ruleset`, `iptables -F`,
                   `ufw reset|disable`, `tc qdisc del`, `set-property Prop=` back to the default)
    —              otherwise it is still active at the end of the run (end = None)

Point actions (reload, restart, stop, start, kill, daemon-reload, set-property …) are kept
separately: they are what "a disruptive operator action just before an outage" refers to.

Every change carries an `area` (nginx, firewall, tc, systemd, tls, gitea, other) so attribution
can ask "was a front-end change (nginx or firewall) active at this moment?".
"""
from __future__ import annotations

import datetime as dt
import posixpath
from dataclasses import dataclass, field

from .model import Event, GroundTruth

WRITE_SYSCALLS = {"open", "openat", "openat2", "creat", "truncate", "ftruncate", "write", "pwrite64", "link",
                  "linkat", "symlink", "symlinkat", "mknod", "mknodat", "mkdir", "mkdirat", "utimensat",
                  "2", "257", "437", "85", "76", "77", "86", "265", "88", "266", "133", "259", "83", "258", "280"}
DELETE_SYSCALLS = {"unlink", "unlinkat", "rmdir", "87", "263", "84"}
RENAME_SYSCALLS = {"rename", "renameat", "renameat2", "82", "264", "316"}
FIREWALL_TOOLS = {"nft", "iptables", "ip6tables", "iptables-nft", "iptables-legacy", "ip6tables-nft",
                  "iptables-restore", "ip6tables-restore", "ufw", "firewall-cmd"}
SERVICE_ACTIONS = {"reload", "restart", "try-restart", "reload-or-restart", "try-reload-or-restart", "stop", "start",
                   "kill", "set-property", "daemon-reload", "mask", "unmask", "enable", "disable", "isolate",
                   "force-reload", "condrestart"}
FRONT_END_AREAS = ("nginx", "firewall")
VOLATILE = ("/sys/", "/proc/", "/dev/", "/run/user/", "/tmp/", "/var/tmp/")   # not configuration


@dataclass
class Change:
    kind: str                       # file | unit_property | firewall | tc
    key: str                        # path, "firewall", "tc", "systemd:<unit>:<Prop>"
    area: str
    start: dt.datetime
    end: dt.datetime | None = None  # None: still active at the end of the run
    ended_by: str | None = None
    evidence: list[str] = field(default_factory=list)

    def active_at(self, t: dt.datetime) -> bool:
        return self.start <= t and (self.end is None or t < self.end)

    def overlaps(self, start: dt.datetime, end: dt.datetime) -> bool:
        return self.start <= end and (self.end is None or self.end > start)

    def as_dict(self) -> dict:
        iso = (lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ") if t else None)  # noqa: E731
        return {"kind": self.kind, "key": self.key, "area": self.area, "start": iso(self.start),
                "end": iso(self.end), "ended_by": self.ended_by, "evidence": self.evidence[:4]}


@dataclass
class Timeline:
    changes: list[Change]
    actions: list[Event]

    def active(self, t: dt.datetime, areas: tuple[str, ...] | None = None) -> list[Change]:
        return [c for c in self.changes if c.active_at(t) and (areas is None or c.area in areas)]

    def active_between(self, start: dt.datetime, end: dt.datetime,
                       areas: tuple[str, ...] | None = None) -> list[Change]:
        return [c for c in self.changes if c.overlaps(start, end) and (areas is None or c.area in areas)]


def area_of(path: str) -> str:
    if path.startswith("/etc/nginx"):
        return "nginx"
    if path.startswith(("/etc/nftables", "/etc/iptables", "/etc/ufw")):
        return "firewall"
    if path.startswith(("/etc/systemd", "/run/systemd", "/lib/systemd")):
        return "systemd"
    if path.startswith("/etc/ssl"):
        return "tls"
    if path.startswith("/etc/gitea"):
        return "gitea"
    return "other"


def _tool(argv: list[str]) -> tuple[str, list[str]]:
    if not argv:
        return "", []
    tool, rest = posixpath.basename(argv[0]), argv[1:]
    if tool in ("sudo", "env", "nohup", "timeout"):
        while rest and (rest[0].startswith("-") or (tool == "timeout" and rest[0][:1].isdigit())
                        or (tool == "env" and "=" in rest[0])):
            rest = rest[1:]
        return _tool(rest)
    return tool, rest


def firewall_effect(argv: list[str]) -> str | None:
    """"change" or "reset" for a rule-changing firewall/tc command, None for a read."""
    tool, args = _tool(argv)
    words = [a.lower() for a in args]
    if tool == "tc":
        if not {"qdisc", "class", "filter"} & set(words):
            return None
        if {"del", "delete"} & set(words):
            return "reset"
        return "change" if {"add", "replace", "change", "link"} & set(words) else None
    if tool not in FIREWALL_TOOLS:
        return None
    if tool == "nft":
        if "flush" in words and "ruleset" in words:
            return "reset"
        return "change" if {"add", "insert", "delete", "replace", "create", "flush", "-f", "destroy"} & set(words) else None
    if tool == "ufw":
        if {"reset", "disable"} & set(words):
            return "reset"
        return "change" if {"allow", "deny", "reject", "limit", "enable", "delete", "insert", "route"} & set(words) else None
    if tool.endswith("-restore") or tool == "firewall-cmd":
        return "change"
    flags = {"-A", "--append", "-I", "--insert", "-D", "--delete", "-R", "--replace", "-N", "--new-chain", "-X",
             "--delete-chain", "-P", "--policy", "-F", "--flush", "-Z"}
    used = flags & set(args)
    if not used or used == {"-Z"}:
        return None
    if used <= {"-F", "--flush", "-X", "--delete-chain", "-Z"} and len([a for a in args if not a.startswith("-")]) <= 1:
        return "reset"                     # flush everything (optionally one table)
    return "change"


def _unit_property(args: list[str]) -> list[tuple[str, str, str]]:
    """systemctl set-property [--runtime] <unit> Prop=value … -> [(unit, Prop, value)]"""
    rest = [a for a in args if not a.startswith("-")]
    if "set-property" not in rest:
        return []
    rest = rest[rest.index("set-property") + 1:]
    if not rest:
        return []
    unit = rest[0] if rest[0].endswith((".service", ".slice", ".scope")) else rest[0] + ".service"
    return [(unit.rsplit(".", 1)[0], *a.split("=", 1)) for a in rest[1:] if "=" in a]


def build(truth: GroundTruth) -> Timeline:
    snapshots = [e for e in truth.of("monitor", "ground_truth_snapshot") if e.payload.get("captured")]
    baseline = next((s.payload["state"] for s in snapshots if s.payload.get("trigger") == "baseline"),
                    snapshots[0].payload["state"] if snapshots else {})
    golden_files = baseline.get("files", {})
    changes: list[Change] = []
    open_by_key: dict[str, Change] = {}
    actions: list[Event] = []

    def start(kind: str, key: str, area: str, t: dt.datetime, evidence: str) -> None:
        prev = open_by_key.get(key)
        if prev is not None:
            prev.end, prev.ended_by = t, "overwritten"
        c = Change(kind, key, area, t, evidence=[evidence])
        changes.append(c)
        open_by_key[key] = c

    def end(key: str, t: dt.datetime, why: str) -> None:
        prev = open_by_key.pop(key, None)
        if prev is not None:
            prev.end, prev.ended_by = t, why

    def end_area(prefix: str, t: dt.datetime, why: str) -> None:
        for key in [k for k in open_by_key if k == prefix or k.startswith(prefix + ":")]:
            end(key, t, why)

    events = sorted(truth.of("target", "config_change") + snapshots, key=lambda e: e.ts)
    last_action_sig: tuple | None = None
    for ev in events:
        if ev.type == "ground_truth_snapshot":
            _close_by_snapshot(ev, open_by_key, golden_files, baseline, end)
            continue
        p = ev.payload
        if p.get("actor") != "operator" or p.get("success") is False:
            continue
        ref = f"{p.get('audit_id', '?')} {p.get('syscall') or ''} {' '.join((p.get('argv') or [])[:8])}".strip()[:200]
        kind, syscall = p.get("kind"), str(p.get("syscall") or "")
        paths = [x for x in p.get("paths") or [] if not x.startswith(VOLATILE)]
        if kind in ("file_change", "perm_change") and paths:
            if syscall in RENAME_SYSCALLS and len(paths) >= 2:
                src, dst = paths[0], paths[-1]
                if src in golden_files:
                    start("file", src, area_of(src), ev.ts, ref)
                else:
                    end(src, ev.ts, "deleted")
                start("file", dst, area_of(dst), ev.ts, ref)
            elif syscall in DELETE_SYSCALLS:
                for path in paths:
                    if path in golden_files:
                        start("file", path, area_of(path), ev.ts, ref)
                    else:
                        end(path, ev.ts, "deleted")
            elif kind == "perm_change" or syscall in WRITE_SYSCALLS or not syscall:
                for path in paths:
                    start("file", path, area_of(path), ev.ts, ref)
            continue
        argv = p.get("argv") or []
        effect = firewall_effect(argv)
        if effect is not None:
            tool, _ = _tool(argv)
            key = "tc" if tool == "tc" else "firewall"
            if effect == "reset":
                end_area(key, ev.ts, "reset")
            elif key not in open_by_key:
                start(key, key, key, ev.ts, ref)
            else:
                open_by_key[key].evidence.append(ref)
            continue
        if kind == "service_mgmt":
            tool, args = _tool(argv)
            verbs = SERVICE_ACTIONS & set(args)
            sig = (tool, tuple(args))
            if verbs and not (last_action_sig == sig and actions and (ev.ts - actions[-1].ts).total_seconds() < 3):
                actions.append(ev)          # `sudo systemctl …` and `systemctl …` are one action
            last_action_sig = sig
            for unit, prop, value in _unit_property(args):
                key = f"systemd:{unit}:{prop}"
                if value in ("", "infinity"):
                    end(key, ev.ts, "reset")
                else:
                    start("unit_property", key, "systemd", ev.ts, ref)
    return Timeline(changes, actions)


def _close_by_snapshot(snap: Event, open_by_key: dict, golden_files: dict, baseline: dict, end) -> None:
    state = snap.payload.get("state") or {}
    files = state.get("files", {})
    full_coverage = "firewall" in state          # snapshots that also capture operator-touched paths
    for key, change in list(open_by_key.items()):
        if change.start >= snap.ts:
            continue
        if change.kind == "file":
            golden = golden_files.get(key)
            now = files.get(key)
            if golden is not None and now is not None and all(now.get(a) == golden.get(a) for a in
                                                              ("content", "mode", "owner", "group", "link")):
                end(key, snap.ts, "golden_hash")
            elif golden is None and now is None and full_coverage:
                end(key, snap.ts, "deleted")
        elif change.kind in ("firewall", "tc") and full_coverage:
            if change.kind == "firewall" and state.get("firewall") == baseline.get("firewall"):
                end(key, snap.ts, "golden_hash")
            if change.kind == "tc" and state.get("qdisc") == baseline.get("qdisc"):
                end(key, snap.ts, "golden_hash")
        elif change.kind == "unit_property":
            _, unit, prop = key.split(":", 2)
            now = (state.get("services", {}).get(unit) or {}).get(prop)
            was = (baseline.get("services", {}).get(unit) or {}).get(prop)
            if now is not None and now == was:
                end(key, snap.ts, "golden_hash")
