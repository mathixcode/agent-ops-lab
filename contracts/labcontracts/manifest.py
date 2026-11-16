"""Spec 1.4 — the run manifest (one run = one file).

The example in the spec writes schedule entries on one line without flow braces:

    - at: 00:30   type: fault     ref: disk_fill_80

That is not valid YAML, so those lines are normalised before parsing. Regular YAML
mappings are accepted as well. All scalars are read as strings (YAML 1.1 would otherwise
turn `10:30` into the integer 630) and converted explicitly.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

import yaml

FAULT_REFS = ("disk_fill_80", "db_restart", "cert_expire", "oom_worker", "net_latency")
OPS_TASK_REFS = ("add_team_access", "enable_webhook", "restore_backup", "rotate_key")
LOAD_PROFILES = ("steady_with_peaks", "steady", "idle")
EVENT_KINDS = {"fault": FAULT_REFS, "ops_task": OPS_TASK_REFS}

_UNITS = {"d": 86400, "h": 3600, "m": 60, "s": 1}
_SPAN_RE = re.compile(r"^(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")
_CLOCK_RE = re.compile(r"^(?:(\d+)d)?(\d{1,3}):([0-5]\d)(?::([0-5]\d))?$")
_COMPACT_EVENT_RE = re.compile(
    r"^(?P<indent>\s*)-\s*at:\s*(?P<at>\S+)\s+type:\s*(?P<type>\S+)\s+ref:\s*(?P<ref>\S+)\s*(?:#.*)?$")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ManifestError(ValueError):
    pass


def parse_duration(text: str) -> int:
    """Seconds from `14d`, `6h`, `30m`, `90s`, `1d12h`, `00:30` (HH:MM) or `1d04:00`."""
    text = str(text).strip()
    m = _CLOCK_RE.match(text)
    if m:
        days, hours, minutes, seconds = (int(g) if g else 0 for g in m.groups())
        return days * 86400 + hours * 3600 + minutes * 60 + seconds
    m = _SPAN_RE.match(text)
    if m and any(m.groups()):
        return sum(int(g) * _UNITS[u] for g, u in zip(m.groups(), "dhms") if g)
    raise ManifestError(f"cannot parse duration {text!r}")


def format_offset(seconds: float) -> str:
    seconds = int(round(seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    clock = f"{hours:02d}:{minutes:02d}" + (f":{secs:02d}" if secs else "")
    return f"{days}d{clock}" if days else clock


@dataclass(frozen=True)
class ScheduledEvent:
    at: int             # seconds after run start
    type: str           # fault | ops_task
    ref: str


@dataclass(frozen=True)
class RunManifest:
    run_id: str
    seed: int
    model_defender: str
    duration: int               # seconds
    load_profile: str
    snapshot_interval: int      # seconds
    event_schedule: tuple[ScheduledEvent, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalise(text: str) -> str:
    out = []
    for line in text.splitlines():
        m = _COMPACT_EVENT_RE.match(line)
        if m:
            line = '{indent}- {{at: "{at}", type: "{type}", ref: "{ref}"}}'.format(**m.groupdict())
        out.append(line)
    return "\n".join(out) + "\n"


def parse_manifest(text: str) -> RunManifest:
    try:
        raw = yaml.load(_normalise(text), Loader=yaml.BaseLoader)
    except yaml.YAMLError as exc:
        raise ManifestError(f"manifest is not parseable: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError("manifest must be a mapping")

    known = {"run_id", "seed", "model_defender", "duration", "load_profile", "event_schedule",
             "snapshot_interval"}
    unknown = raw.keys() - known
    if unknown:
        raise ManifestError(f"unknown manifest keys {sorted(unknown)}")
    missing = (known - {"event_schedule"}) - raw.keys()
    if missing:
        raise ManifestError(f"manifest is missing {sorted(missing)}")

    run_id = str(raw["run_id"])
    if not _RUN_ID_RE.match(run_id):
        raise ManifestError(f"run_id {run_id!r} must match {_RUN_ID_RE.pattern}")
    try:
        seed = int(raw["seed"])
    except (TypeError, ValueError) as exc:
        raise ManifestError("seed must be an integer") from exc

    duration = parse_duration(raw["duration"])
    snapshot_interval = parse_duration(raw["snapshot_interval"])
    if duration <= 0 or snapshot_interval <= 0:
        raise ManifestError("duration and snapshot_interval must be positive")
    if raw["load_profile"] not in LOAD_PROFILES:
        raise ManifestError(f"load_profile must be one of {LOAD_PROFILES}")

    events = []
    for i, item in enumerate(raw.get("event_schedule") or []):
        if not isinstance(item, dict) or set(item) != {"at", "type", "ref"}:
            raise ManifestError(f"event_schedule[{i}] needs exactly at/type/ref")
        kind, ref = item["type"], item["ref"]
        if kind not in EVENT_KINDS:
            raise ManifestError(f"event_schedule[{i}].type must be one of {sorted(EVENT_KINDS)}")
        if ref not in EVENT_KINDS[kind]:
            raise ManifestError(f"event_schedule[{i}].ref {ref!r} is not a known {kind}")
        at = parse_duration(item["at"])
        if at >= duration:
            raise ManifestError(f"event_schedule[{i}] at {item['at']} is not before the run ends")
        events.append(ScheduledEvent(at=at, type=kind, ref=ref))
    events.sort(key=lambda e: e.at)

    return RunManifest(run_id=run_id, seed=seed, model_defender=str(raw["model_defender"]),
                       duration=duration, load_profile=str(raw["load_profile"]),
                       snapshot_interval=snapshot_interval, event_schedule=tuple(events))


def load_manifest(path: str) -> RunManifest:
    with open(path, encoding="utf-8") as fh:
        return parse_manifest(fh.read())
