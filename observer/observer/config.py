"""Observer configuration — everything comes from the environment and /secrets (spec 1.2:
the observer holds the read-only target key, the canary registry, hypervisor access and
the run seed; it never holds the operator key or the Gitea admin token)."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from labcontracts import canary, network


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"observer: environment variable {name} is not set")
    return value


@dataclass
class Config:
    secrets: Path = Path(os.environ.get("OBSERVER_SECRETS", "/secrets"))
    data: Path = Path(os.environ.get("OBSERVER_DATA", "/data"))
    target_host: str = network.TARGET_HOSTNAME
    target_ip: str = network.ADDR["target"]
    hv_url: str = field(default_factory=lambda: _env("HV_URL"))
    gateway_url: str = field(default_factory=lambda: _env("GATEWAY_URL"))
    defender_url: str = field(default_factory=lambda: _env("DEFENDER_URL"))
    langfuse_url: str = field(default_factory=lambda: _env("LANGFUSE_URL"))
    hv_token: str = field(default_factory=lambda: _env("LAB_HV_TOKEN"))
    gateway_token: str = field(default_factory=lambda: _env("LAB_GATEWAY_TOKEN"))
    defender_token: str = field(default_factory=lambda: _env("LAB_DEFENDER_TOKEN"))
    langfuse_public_key: str = field(default_factory=lambda: _env("LANGFUSE_PUBLIC_KEY"))
    langfuse_secret_key: str = field(default_factory=lambda: _env("LANGFUSE_SECRET_KEY"))

    # cadences (seconds)
    http_probe_interval: float = float(os.environ.get("PROBE_INTERVAL", "15"))
    check_interval: float = float(os.environ.get("CHECK_INTERVAL", "60"))
    collect_interval: float = float(os.environ.get("COLLECT_INTERVAL", "20"))
    event_jitter: float = float(os.environ.get("EVENT_JITTER", "0.05"))   # fraction of the gap to the next event

    @property
    def db_path(self) -> Path:
        return self.data / "c3" / "lab.sqlite"

    @property
    def target_url(self) -> str:
        return f"https://{self.target_host}"

    @property
    def ca_file(self) -> str:
        return str(self.secrets / "ca.crt")

    def run_dir(self, run_id: str) -> Path:
        path = self.data / "runs" / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def canaries(self) -> list[canary.Canary]:
        return canary.load_registry((self.secrets / "canary_registry.json").read_text())

    def seed_users(self) -> list[dict]:
        return json.loads((self.secrets / "seed_users.json").read_text())["users"]

    def golden(self) -> dict:
        return json.loads((self.secrets / "golden.json").read_text())

    def user(self, role: str) -> dict:
        return next(u for u in self.seed_users() if u["role"] == role)
