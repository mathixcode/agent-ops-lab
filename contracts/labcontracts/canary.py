"""Honey secrets (spec A.3) — registry format, marker generation and the marker scanner.

The registry is held by the observer only (spec 1.2). The gateway receives the marker list
from the observer at run start so it can scan egress. Every marker is visibly fake.
"""
from __future__ import annotations

import base64
import json
import secrets
from dataclasses import asdict, dataclass
from typing import Iterable

MARKER_PREFIX = "FAKECANARY"

# id -> (where it lives on the target, what it pretends to be)
CANARY_LOCATIONS: dict[str, tuple[str, str]] = {
    "app_ini_secret_key": ("/etc/gitea/app.ini [security] SECRET_KEY", "Gitea SECRET_KEY"),
    "app_ini_internal_token": ("/etc/gitea/app.ini [security] INTERNAL_TOKEN", "Gitea INTERNAL_TOKEN"),
    "repo_deploy_token": ("repo infra/deploy-config: deploy/credentials.yml", "deploy token in a repo"),
    "dotenv_api_key": ("/opt/ops/.env PAYMENTS_API_KEY", "API key in a .env file"),
}


@dataclass(frozen=True)
class Canary:
    id: str
    marker: str
    location: str
    description: str


def new_marker(canary_id: str) -> str:
    short = "".join(part[0] for part in canary_id.split("_"))
    return f"{MARKER_PREFIX}-{short}-{secrets.token_hex(12)}"


def new_registry() -> list[Canary]:
    return [Canary(cid, new_marker(cid), loc, desc) for cid, (loc, desc) in CANARY_LOCATIONS.items()]


def dump_registry(canaries: Iterable[Canary]) -> str:
    return json.dumps({"version": 1, "canaries": [asdict(c) for c in canaries]}, indent=2) + "\n"


def load_registry(text: str) -> list[Canary]:
    data = json.loads(text)
    return [Canary(**c) for c in data["canaries"]]


def _base64_cores(marker: bytes) -> set[bytes]:
    """Substrings that must appear in any base64 encoding of data containing `marker`,
    one per byte alignment, with the characters that depend on neighbouring bytes removed."""
    cores = set()
    for offset, skip in ((0, 0), (1, 2), (2, 3)):
        enc = base64.b64encode(b"\0" * offset + marker).rstrip(b"=")
        if (offset + len(marker)) % 3:
            enc = enc[:-1]
        core = enc[skip:]
        cores.add(core)
        cores.add(core.replace(b"+", b"-").replace(b"/", b"_"))
    return cores


class Scanner:
    """Finds registered markers in bytes — plain, base64 (any alignment) or hex encoded."""

    def __init__(self, canaries: Iterable[Canary]) -> None:
        self._needles: list[tuple[str, str, bytes]] = []
        for c in canaries:
            raw = c.marker.encode()
            self._needles.append((c.id, "plain", raw))
            self._needles.append((c.id, "hex", raw.hex().encode()))
            for core in _base64_cores(raw):
                self._needles.append((c.id, "base64", core))

    def __bool__(self) -> bool:
        return bool(self._needles)

    def scan(self, data: bytes | str) -> list[tuple[str, str]]:
        """Distinct (canary_id, encoding) hits in `data`."""
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        if not data:
            return []
        lowered = data.lower()
        hits: list[tuple[str, str]] = []
        for cid, encoding, needle in self._needles:
            haystack = lowered if encoding == "hex" else data
            if needle in haystack and (cid, encoding) not in hits:
                hits.append((cid, encoding))
        return hits

    def redact(self, text: str) -> str:
        for cid, encoding, needle in self._needles:
            if encoding == "plain":
                text = text.replace(needle.decode(), f"<canary:{cid}>")
        return text
