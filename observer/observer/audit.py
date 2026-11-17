"""Parse raw auditd log lines into target/config_change payloads (spec A.4).

auditd writes several records per kernel event (SYSCALL, PATH, CWD, EXECVE, PROCTITLE …)
that share one `msg=audit(<epoch>:<serial>)` id. Each event with a rule key becomes one
config_change payload. The login uid (auid) says who did it: the operator's sessions carry
the operator's uid, anything done by the system or injected through the hypervisor has none.
"""
from __future__ import annotations

import datetime as dt
import posixpath
import re
from typing import Iterable, Iterator

UNSET_AUID = 4294967295
_HEAD = re.compile(r"^type=(\S+) msg=audit\((\d+)\.(\d+):(\d+)\): ?(.*)$")
_FIELD = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
_HEXISH = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
SERVICE_TOOLS = {"systemctl", "service", "kill", "pkill", "killall", "reboot", "shutdown", "poweroff"}
PACKAGE_TOOLS = {"apt", "apt-get", "dpkg", "aptitude", "pip", "pip3"}
# Looking is not managing: `systemctl is-active` or `dpkg -l` change nothing.
SERVICE_VERBS = {"start", "stop", "restart", "reload", "try-restart", "reload-or-restart", "try-reload-or-restart",
                 "enable", "disable", "reenable", "mask", "unmask", "kill", "isolate", "daemon-reload",
                 "daemon-reexec", "set-property", "edit", "revert", "reset-failed", "reboot", "poweroff", "halt",
                 "condrestart", "force-reload"}
PACKAGE_VERBS = {"install", "remove", "purge", "upgrade", "full-upgrade", "dist-upgrade", "autoremove", "reinstall",
                 "uninstall", "-i", "--install", "-r", "--remove", "-P", "--purge", "--configure"}
ALWAYS_DISRUPTIVE = {"kill", "pkill", "killall", "reboot", "shutdown", "poweroff"}
# The kernel reports one rule key per event (the first rule that matched), so a chmod inside a
# watched directory arrives under the directory's key. The syscall says what really happened.
PERMISSION_SYSCALLS = {"chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "fchown", "lchown", "fchownat",
                       "setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr",
                       # x86_64 numbers, for logs written without the ENRICHED names
                       "90", "91", "268", "452", "92", "93", "94", "260", "188", "189", "190", "197", "198", "199"}


def _command(argv: list[str]) -> tuple[str, list[str]]:
    """(tool, its arguments), looking through a leading `sudo [options]`."""
    if not argv:
        return "", []
    tool, rest = posixpath.basename(argv[0]), argv[1:]
    if tool == "sudo":
        while rest and rest[0].startswith("-"):
            rest = rest[1:]
        return _command(rest)
    return tool, rest


def _fields(text: str) -> dict[str, str]:
    # ENRICHED format appends resolved names (SYSCALL=openat AUID="operator" …) after \x1d;
    # those keys are upper-case, so they never collide with the raw ones.
    return {k: v for k, v in _FIELD.findall(text.replace("\x1d", " "))}


def _text(value: str | None) -> str | None:
    """auditd quotes plain strings and hex-encodes anything containing spaces or specials."""
    if value is None or value == "(null)":
        return None
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if _HEXISH.match(value) and len(value) >= 2:
        try:
            return bytes.fromhex(value).replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except ValueError:
            return value
    return value


def _kind(keys: list[str], argv: list[str], syscall: str | None = None) -> str:
    if "audit_tamper" in keys or "cfg_audit" in keys:
        return "audit_config"
    if "perm_change" in keys or syscall in PERMISSION_SYSCALLS:
        return "perm_change"
    if any(k.startswith("cfg_") or k == "backups" for k in keys):
        return "file_change"
    if "operator_exec" in keys:
        tool, args = _command(argv)
        if tool in ALWAYS_DISRUPTIVE:
            return "service_mgmt"
        if tool == "systemctl" and SERVICE_VERBS & set(args):
            return "service_mgmt"
        if tool == "service" and len(args) >= 2 and args[1] in SERVICE_VERBS:
            return "service_mgmt"
        if tool in PACKAGE_TOOLS and PACKAGE_VERBS & set(args):
            return "package_mgmt"
        return "exec"
    return "other"


def parse(lines: Iterable[str], uid_names: dict[int, str] | None = None) -> Iterator[tuple[dt.datetime, dict]]:
    """Yield (timestamp, config_change payload) for every keyed audit event in `lines`."""
    uid_names = uid_names or {}
    groups: dict[str, dict] = {}
    order: list[str] = []
    for line in lines:
        m = _HEAD.match(line.rstrip("\n"))
        if not m:
            continue
        rtype, sec, ms, serial, rest = m.groups()
        gid = f"{sec}.{ms}:{serial}"
        if gid not in groups:
            groups[gid] = {"ts": int(sec) + int(ms) / 1000.0, "records": []}
            order.append(gid)
        groups[gid]["records"].append((rtype, _fields(rest)))

    for gid in order:
        group = groups[gid]
        syscall = next((f for t, f in group["records"] if t == "SYSCALL"), None)
        if syscall is None:
            continue
        raw_key = syscall.get("key", "(null)")
        if raw_key == "(null)":
            continue
        keys = [k for k in (_text(raw_key) or "").replace("\x01", " ").split() if k]
        cwd = next((_text(f.get("cwd")) for t, f in group["records"] if t == "CWD"), None)
        paths = []
        for t, f in group["records"]:
            if t != "PATH" or f.get("nametype") == "PARENT":
                continue
            name = _text(f.get("name"))
            if not name:
                continue
            if not name.startswith("/") and cwd:
                name = posixpath.normpath(posixpath.join(cwd, name))
            if name not in paths:
                paths.append(name)
        argv: list[str] = []
        for t, f in group["records"]:
            if t == "EXECVE":
                for i in range(int(f.get("argc", "0") or 0)):
                    arg = _text(f.get(f"a{i}"))
                    if arg is not None:
                        argv.append(arg)
        auid = int(syscall.get("auid", UNSET_AUID))
        uid = int(syscall.get("uid", -1))
        if auid == UNSET_AUID:
            actor = "system"                    # daemons, cron, hypervisor-injected faults
        else:
            actor = uid_names.get(auid) or _text(syscall.get("AUID")) or f"uid:{auid}"
        name = syscall.get("SYSCALL") or syscall.get("syscall")
        payload = {
            "kind": _kind(keys, argv, name), "keys": keys, "audit_id": gid, "actor": actor,
            "auid": None if auid == UNSET_AUID else auid, "uid": uid,
            "exe": _text(syscall.get("exe")), "comm": _text(syscall.get("comm")),
            "syscall": name,
            "success": syscall.get("success") == "yes",
            "paths": paths,
        }
        if argv:
            payload["argv"] = [a[:300] for a in argv[:40]]
        yield dt.datetime.fromtimestamp(group["ts"], dt.timezone.utc), payload
