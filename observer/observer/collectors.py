"""Collectors — how telemetry from A, B and D reaches C3 without anything ever connecting
*to* the observer. Each collector pulls on the observer's cadence.

    TargetCollector    -> ground truth   target/config_change (auditd), service_log, health
                                         (incl. the nginx boundary record: every access line with
                                         status >= 400 and every error.log line about limit_req,
                                         limit_conn, access rules or upstreams, per client)
    GatewayCollector   -> ground truth   gateway/egress_request, canary_egress
    LangfuseCollector  -> agent view     defender/* (the agent's self-report, via Langfuse)

Only LangfuseCollector may write to the agent-view layer, and it can write nowhere else.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import re
import shlex

import requests

from labcontracts import canary, network, telemetry

from . import audit
from .clients import GatewayAPI, TargetSSH, Unreachable
from .config import Config
from .emitter import Emitter
from .store import Store

log = logging.getLogger("observer.collect")

JOURNAL_UNITS = ("gitea", "nginx", "postgresql", "ssh", "auditd", "chrony")
HEALTH_UNITS = ("gitea", "nginx", "postgresql", "auditd", "ssh", "chrony")
MAX_LOG_EVENTS = 400
MAX_LINES_PER_PULL = 200_000        # per log file and pull; the rest is read on the next pull
MAX_JOURNAL_PER_PULL = 4000

# Runs on the target as the unprivileged observer account. Line-based cursors: only complete
# lines are ever read, and nothing is skipped:
#   - at most MAX_LINES_PER_PULL lines per pull, and the cursor advances by exactly what was
#     read (a backlog after an outage is drained over the next pulls, not dropped);
#   - a changed inode means the file was rotated: the rest of the old file (still there as
#     <file>.1 — logrotate's delaycompress, auditd's own rotation) is read first, then the new
#     file from its start;
#   - the journal is read oldest-first after the cursor (journalctl -n would keep the newest
#     and skip the rest).
TARGET_SCRIPT = r'''
tail_new() {  # file saved_inode saved_lines max_lines
    file=$1; saved_inode=$2; saved_lines=$3; max=$4
    inode=$(stat -c %%i "$file" 2>/dev/null) || { echo "@@CURSOR missing 0"; return; }
    total=$(wc -l < "$file")
    old=""
    if [ -n "$saved_inode" ] && [ "$inode" != "$saved_inode" ] \
            && [ "$(stat -c %%i "$file.1" 2>/dev/null)" = "$saved_inode" ]; then
        old="$file.1"
    fi
    if [ "$inode" != "$saved_inode" ] || [ "$total" -lt "$saved_lines" ]; then start=0; else start=$saved_lines; fi
    n=$((total - start)); [ "$n" -gt "$max" ] && n=$max
    echo "@@CURSOR $inode $((start + n))"
    [ -n "$old" ] && tail -n +$((saved_lines + 1)) "$old" | head -n "$max"
    [ "$n" -gt 0 ] && tail -n +$((start + 1)) "$file" | head -n "$n"
    return 0
}
echo "@@AUDIT"
tail_new /var/log/audit/audit.log "%(audit_inode)s" %(audit_lines)d %(max_lines)d
echo "@@NGINX"
tail_new /var/log/nginx/access.log "%(nginx_inode)s" %(nginx_lines)d %(max_lines)d
echo "@@NGINXERR"
tail_new /var/log/nginx/error.log "%(err_inode)s" %(err_lines)d %(max_lines)d | grep -E '^@@CURSOR|limiting (requests|connections)|access forbidden by rule|upstream|connect\(\) failed'
echo "@@JOURNAL"
journalctl -o json --no-pager %(journal_from)s %(journal_units)s 2>/dev/null | head -n %(max_journal)d
echo "@@HEALTH"
systemctl is-active %(health_units)s | tr '\n' ' '; echo
curl -s -o /dev/null -m 8 -w '%%{http_code}\n' http://127.0.0.1:3000/api/healthz
cut -d' ' -f1 /proc/loadavg
df --output=pcent /var/lib/gitea | tail -1
awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo
echo "@@END"
'''

_NGINX = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) ')
_NGINX_ERR = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(\w+)\] [^:]*: (?:\*\d+ )?(.*)$")
_CLIENT = re.compile(r"client: ([0-9a-fA-F.:]+)")
MAX_SAMPLES = 3


def nginx_error_kind(message: str) -> str:
    """What an nginx error.log line says happened to a client's request."""
    if "limiting requests" in message:
        return "limit_req"
    if "limiting connections" in message:
        return "limit_conn"
    if "access forbidden by rule" in message:
        return "access_rule"
    return "upstream"


def aggregate_access(lines, run_start, defender_prefix):
    """nginx access lines -> (individual events, error aggregates, routine counts).

    individual: state-changing API calls from the defender segment (authorship evidence)
    errors:     {(minute, status, client): {count, first, methods, sample_paths}}  — every line >= 400
    routine:    {minute: {client: {"2xx": n, "3xx": n}}}"""
    individual, errors, routine = [], {}, {}
    for line in lines:
        m = _NGINX.match(line)
        if not m:
            continue
        remote, when, method, path, status = m.groups()
        try:
            ts = dt.datetime.strptime(when, "%d/%b/%Y:%H:%M:%S %z").astimezone(dt.timezone.utc)
        except ValueError:
            continue
        if ts < run_start:
            continue
        code = int(status)
        if remote.startswith(defender_prefix) and method not in ("GET", "HEAD", "OPTIONS"):
            individual.append((ts, line, remote, method, path, code))
        minute = ts.replace(second=0, microsecond=0)
        if code >= 400:
            agg = errors.setdefault((minute, code, remote), {"count": 0, "first": ts, "methods": {}, "sample_paths": []})
            agg["count"] += 1
            agg["methods"][method] = agg["methods"].get(method, 0) + 1
            short = path.split("?", 1)[0][:200]
            if short not in agg["sample_paths"] and len(agg["sample_paths"]) < MAX_SAMPLES:
                agg["sample_paths"].append(short)
        else:
            cls = f"{code // 100}xx"
            per = routine.setdefault(minute, {}).setdefault(remote, {})
            per[cls] = per.get(cls, 0) + 1
    return individual, errors, routine


def aggregate_errors(lines, run_start):
    """nginx error.log lines -> {(minute, kind, client): {count, first, level, sample}}"""
    out = {}
    for line in lines:
        m = _NGINX_ERR.match(line)
        if not m:
            continue
        when, level, message = m.groups()
        try:
            ts = dt.datetime.strptime(when, "%Y/%m/%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
        if ts < run_start:
            continue
        client = (_CLIENT.search(message) or [None, "?"])[1]
        kind = nginx_error_kind(message)
        agg = out.setdefault((ts.replace(second=0, microsecond=0), kind, client),
                             {"count": 0, "first": ts, "level": level, "sample": message[:300]})
        agg["count"] += 1
    return out


class TargetCollector:
    """Mirrors the target's own records over the read-only SSH account."""

    def __init__(self, cfg: Config, store: Store, run_id: str, ssh: TargetSSH, run_start: dt.datetime,
                 scanner: canary.Scanner, journal_hits: list[dict]) -> None:
        self.ssh = ssh
        self.out = Emitter(store, run_id, source="target")
        self.run_start = run_start
        self.scanner = scanner
        self.journal_hits = journal_hits
        uids = cfg.golden().get("uids", {})
        self.uid_names = {int(uid): name for name, uid in uids.items()}
        self.cursor = {"audit_inode": "", "audit_lines": 0, "nginx_inode": "", "nginx_lines": 0,
                       "err_inode": "", "err_lines": 0, "journal": ""}
        self.unreachable_since: dt.datetime | None = None

    def pull(self) -> dict[str, int]:
        journal_from = (f"--after-cursor={shlex.quote(self.cursor['journal'])}" if self.cursor["journal"]
                        else f"--since=@{int(self.run_start.timestamp())}")
        script = TARGET_SCRIPT % {
            "audit_inode": self.cursor["audit_inode"], "audit_lines": self.cursor["audit_lines"],
            "nginx_inode": self.cursor["nginx_inode"], "nginx_lines": self.cursor["nginx_lines"],
            "err_inode": self.cursor["err_inode"], "err_lines": self.cursor["err_lines"],
            "max_lines": MAX_LINES_PER_PULL, "max_journal": MAX_JOURNAL_PER_PULL,
            "journal_from": journal_from, "journal_units": " ".join(f"-u {u}" for u in JOURNAL_UNITS),
            "health_units": " ".join(HEALTH_UNITS)}
        _, out, _ = self.ssh.run("bash -s", stdin=script, timeout=120)
        sections: dict[str, list[str]] = {}
        current = None
        for line in out.split("\n"):       # not splitlines(): it also splits on the \x1d inside audit records
            if line in ("@@AUDIT", "@@NGINX", "@@NGINXERR", "@@JOURNAL", "@@HEALTH", "@@END"):
                current = line[2:]
                sections[current] = []
            elif current:
                sections[current].append(line)
        if "END" not in sections:
            raise Unreachable("target collection script did not complete")
        counts = {"config_change": self._audit(sections["AUDIT"]),
                  "service_log": self._nginx(sections["NGINX"]) + self._nginx_errors(sections.get("NGINXERR", []))
                  + self._journal(sections["JOURNAL"]),
                  "health": self._health(sections["HEALTH"])}
        return counts

    def _take_cursor(self, lines: list[str], prefix: str) -> list[str]:
        if lines and lines[0].startswith("@@CURSOR"):
            _, inode, total = lines[0].split()
            if inode != "missing":
                self.cursor[f"{prefix}_inode"], self.cursor[f"{prefix}_lines"] = inode, int(total)
            return lines[1:]
        return lines

    def _audit(self, lines: list[str]) -> int:
        n = 0
        for ts, payload in audit.parse(self._take_cursor(lines, "audit"), self.uid_names):
            if ts >= self.run_start:
                self.out.emit("config_change", payload, ts=ts)
                n += 1
        return n

    def _nginx(self, lines: list[str]) -> int:
        """The nginx access log as boundary record:
        - state-changing API calls from the defender segment, one event each (what the agent did
          through the Gitea API — auditd cannot see those);
        - every request answered with status >= 400, aggregated per minute x status x client
          (who was rejected, by what status — the evidence for attribution);
        - routine 2xx/3xx traffic as per-minute counts per client."""
        lines = self._take_cursor(lines, "nginx")
        for line in lines:
            self._note_canaries(line, "nginx-access")
        prefix = network.SEGMENTS["defender"].rsplit(".", 1)[0] + "."
        individual, errors, routine = aggregate_access(lines, self.run_start, prefix)
        n = 0
        for ts, line, remote, method, path, status in individual:
            self.out.emit("service_log", {"unit": "nginx-access", "message": self.scanner.redact(line)[:600],
                                          "remote_addr": remote, "method": method,
                                          "path": self.scanner.redact(path.split("?", 1)[0])[:300],
                                          "status": status}, ts=ts)
            n += 1
        for (minute, status, client), agg in sorted(errors.items(), key=lambda kv: kv[1]["first"]):
            self.out.emit("service_log", {
                "unit": "nginx-access-errors", "client_ip": client, "identity": network.identity_of(client),
                "status": status, "count": agg["count"], "minute": telemetry.format_ts(minute),
                "methods": agg["methods"], "sample_paths": [self.scanner.redact(p) for p in agg["sample_paths"]],
                "message": f"{agg['count']} request(s) from {client} answered HTTP {status}"}, ts=agg["first"])
            n += 1
        for minute, per_client in sorted(routine.items()):
            self.out.emit("service_log", {"unit": "nginx-access-summary", "minute": telemetry.format_ts(minute),
                                          "by_client": per_client,
                                          "message": f"routine requests in {minute:%H:%M} by client"}, ts=minute)
            n += 1
        return n

    def _nginx_errors(self, lines: list[str]) -> int:
        """nginx error.log lines about rejected or failed requests (limit_req, limit_conn, access
        rules, upstreams), aggregated per minute x kind x client — the corroboration that a
        rejection was nginx's doing, and for which client."""
        n = 0
        aggregated = aggregate_errors(self._take_cursor(lines, "err"), self.run_start)
        for (minute, kind, client), agg in sorted(aggregated.items(), key=lambda kv: kv[1]["first"]):
            self.out.emit("service_log", {
                "unit": "nginx-error", "kind": kind, "client_ip": client, "identity": network.identity_of(client),
                "count": agg["count"], "level": agg["level"], "minute": telemetry.format_ts(minute),
                "message": self.scanner.redact(agg["sample"])}, ts=agg["first"])
            n += 1
        return n

    def _journal(self, lines: list[str]) -> int:
        n = suppressed = 0
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            self.cursor["journal"] = rec.get("__CURSOR", self.cursor["journal"])
            message = rec.get("MESSAGE")
            if not isinstance(message, str):
                continue
            self._note_canaries(message, rec.get("_SYSTEMD_UNIT", "?"))
            if "router: " in message or n >= MAX_LOG_EVENTS:      # per-request access noise
                suppressed += 1
                continue
            ts = dt.datetime.fromtimestamp(int(rec.get("__REALTIME_TIMESTAMP", "0")) / 1e6, dt.timezone.utc)
            self.out.emit("service_log", {"unit": rec.get("_SYSTEMD_UNIT") or rec.get("SYSLOG_IDENTIFIER", "?"),
                                          "message": self.scanner.redact(message)[:1000],
                                          "priority": int(rec.get("PRIORITY", 6))}, ts=ts)
            n += 1
        if suppressed:
            self.out.emit("service_log", {"unit": "collector", "priority": 7,
                                          "message": f"{suppressed} routine log lines not mirrored"})
            n += 1
        return n

    def _note_canaries(self, text: str, unit: str) -> None:
        for cid, encoding in self.scanner.scan(text):
            self.journal_hits.append({"canary_id": cid, "unit": unit, "encoding": encoding})

    def _health(self, lines: list[str]) -> int:
        if len(lines) < 5:
            return 0
        states = lines[0].split()
        self.out.emit("health", {
            "services": dict(zip(HEALTH_UNITS, states)),
            "gitea_healthz": int(lines[1]) if lines[1].isdigit() else None,
            "load1": float(lines[2]) if lines[2].replace(".", "").isdigit() else None,
            "disk_used_pct": int(lines[3].strip().rstrip("%")) if lines[3].strip().rstrip("%").isdigit() else None,
            "mem_available_mb": int(lines[4]) if lines[4].isdigit() else None})
        return 1


class GatewayCollector:
    def __init__(self, store: Store, run_id: str, api: GatewayAPI) -> None:
        self.store, self.run_id, self.api = store, run_id, api
        self.offset = api.end_offset()      # only what happens from now on belongs to this run

    def pull(self) -> int:
        n = 0
        while True:
            raw, nxt = self.api.events(self.offset)
            if not raw:
                return n
            events = []
            for line in raw.splitlines():
                try:
                    ev = telemetry.validate_event(json.loads(line))
                except (ValueError, telemetry.ContractError) as exc:
                    log.warning("gateway sent an invalid event: %s", exc)
                    continue
                if ev["run_id"] == self.run_id and ev["source"] == "gateway":
                    events.append(ev)
            n += self.store.append_ground_truth(*events)
            self.offset = nxt


class LangfuseCollector:
    """Reads the defender's traces back out of Langfuse and stores them as the agent's view.

    The defender tags every lab event span with lab.event.* attributes (see
    defender/instrumentation.py); everything else in Langfuse is ignored here."""

    def __init__(self, cfg: Config, store: Store, run_id: str, run_start: dt.datetime) -> None:
        self.store, self.run_id, self.run_start = store, run_id, run_start
        self.base = cfg.langfuse_url
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.auth = (cfg.langfuse_public_key, cfg.langfuse_secret_key)
        self.high_water = run_start

    def _observations(self, since: dt.datetime) -> list[dict]:
        """Langfuse v4 observations API (v2): cursor-paginated, span attributes under `metadata`."""
        out: list[dict] = []
        # Without expandMetadata Langfuse cuts every metadata value to 200 characters.
        params = {"fields": "core,metadata", "limit": 500, "expandMetadata": "attributes.lab.event.payload",
                  "fromStartTime": since.strftime("%Y-%m-%dT%H:%M:%S.000Z")}
        while True:
            resp = self.session.get(self.base + "/api/public/v2/observations", timeout=60, params=params)
            resp.raise_for_status()
            doc = resp.json()
            out += doc.get("data", [])
            cursor = (doc.get("meta") or {}).get("cursor")
            if not cursor or not doc.get("data"):
                return out
            params = {**params, "cursor": cursor}

    @staticmethod
    def to_event(obs: dict) -> dict | None:
        """Span attributes arrive flattened as `attributes.<name>`; string values holding JSON
        come back already parsed."""
        meta = obs.get("metadata") or {}
        nested = meta.get("attributes") if isinstance(meta.get("attributes"), dict) else {}

        def attr(name: str):
            return meta.get(f"attributes.{name}", nested.get(name))

        if attr("lab.event.type") is None:
            return None
        payload = attr("lab.event.payload")
        return {"ts": attr("lab.event.ts"), "run_id": attr("lab.run_id"), "source": "defender",
                "type": attr("lab.event.type"), "seq": int(attr("lab.event.seq")),
                "payload": json.loads(payload) if isinstance(payload, str) else payload}

    def pull(self, full: bool = False) -> int:
        """New defender events. The rolling window reaches 5 minutes behind the newest event seen
        (Langfuse ingests asynchronously); `full` reads from the run's start — the teardown does
        that once, for spans that started long before they arrived (a long tool call)."""
        since = self.run_start if full else self.high_water - dt.timedelta(minutes=5)
        n = 0
        for obs in self._observations(since):
            try:
                ev = self.to_event(obs)
                if ev is None or ev["run_id"] != self.run_id:
                    continue
                n += self.store.append_agent_view(telemetry.validate_event(ev))
                self.high_water = max(self.high_water, telemetry.parse_ts(ev["ts"]))
            except (KeyError, ValueError, TypeError, telemetry.ContractError) as exc:
                log.warning("skipping malformed defender observation %s: %s", obs.get("id"), exc)
        return n
