"""The observer's outbound channels. Every connection in the lab that involves the observer
is opened from here — the observer listens on nothing.

    Hypervisor   snapshot reset, out-of-band guest commands (fault injection, state capture)
    TargetSSH    the read-only observer account on the target (no sudo)
    GatewayAPI   pull egress logs, push the canary registry
    DefenderAPI  start/stop the agent for a run
    Gitea        the target's public API on 443, as ordinary seeded users
"""
from __future__ import annotations

import base64
import threading
import time
from typing import Any

import paramiko
import requests

from .config import Config


class Unreachable(RuntimeError):
    pass


class Hypervisor:
    def __init__(self, cfg: Config) -> None:
        self.url = cfg.hv_url
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers["Authorization"] = f"Bearer {cfg.hv_token}"

    def _call(self, method: str, path: str, body: dict | None = None, timeout: float = 60) -> dict:
        try:
            resp = self.session.request(method, self.url + path, json=body, timeout=timeout)
        except requests.RequestException as exc:
            raise Unreachable(f"hypervisor {path}: {exc}") from exc
        data = resp.json()
        if resp.status_code != 200:
            raise RuntimeError(f"hypervisor {path}: {data.get('error', resp.status_code)}")
        return data

    def status(self) -> dict:
        return self._call("GET", "/status", timeout=15)

    def reset(self) -> dict:
        return self._call("POST", "/reset", timeout=120)

    def guest_exec(self, argv: list[str], stdin: bytes | str | None = None, timeout: float = 60) -> dict:
        body: dict[str, Any] = {"argv": argv, "timeout": timeout}
        if stdin is not None:
            if isinstance(stdin, str):
                stdin = stdin.encode()
            body["stdin_b64"] = base64.b64encode(stdin).decode()
        return self._call("POST", "/guest-exec", body, timeout=timeout + 30)

    def guest_sh(self, script: str, timeout: float = 60) -> dict:
        return self.guest_exec(["/bin/bash", "-c", script], timeout=timeout)

    def wait_guest(self, timeout: float = 600) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if self.status().get("guest_agent"):
                    return
            except (Unreachable, RuntimeError):
                pass
            time.sleep(5)
        raise TimeoutError("target guest agent did not come up")


class TargetSSH:
    """Persistent SSH session as the read-only `observer` account. Host key is pinned."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._client: paramiko.SSHClient | None = None
        self._lock = threading.Lock()

    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.load_host_keys(str(self.cfg.secrets / "known_hosts"))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(self.cfg.target_host, port=22, username="observer",
                       key_filename=str(self.cfg.secrets / "observer_key"),
                       allow_agent=False, look_for_keys=False, timeout=20, banner_timeout=60,
                       auth_timeout=60)
        client.get_transport().set_keepalive(30)
        return client

    def run(self, command: str, stdin: bytes | str | None = None, timeout: float = 60) -> tuple[int, str, str]:
        """-> (exit status, stdout, stderr). Raises Unreachable if the target cannot be reached."""
        with self._lock:
            for attempt in (1, 2):
                try:
                    if self._client is None or not self._client.get_transport() or \
                            not self._client.get_transport().is_active():
                        self._client = self._connect()
                    chan_in, chan_out, chan_err = self._client.exec_command(command, timeout=timeout)
                    if stdin is not None:
                        chan_in.write(stdin if isinstance(stdin, bytes) else stdin.encode())
                    chan_in.channel.shutdown_write()
                    out = chan_out.read().decode("utf-8", "replace")
                    err = chan_err.read().decode("utf-8", "replace")
                    return chan_out.channel.recv_exit_status(), out, err
                except Exception as exc:  # paramiko raises a wide range of things
                    self.close_locked()
                    if attempt == 2:
                        raise Unreachable(f"target ssh: {type(exc).__name__}: {exc}") from exc
        raise Unreachable("target ssh")

    def close_locked(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def close(self) -> None:
        with self._lock:
            self.close_locked()


class GatewayAPI:
    def __init__(self, cfg: Config) -> None:
        self.url = cfg.gateway_url
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers["Authorization"] = f"Bearer {cfg.gateway_token}"

    def start_run(self, run_id: str, canaries: list) -> None:
        body = {"run_id": run_id, "canaries": [{"id": c.id, "marker": c.marker} for c in canaries]}
        self.session.put(self.url + "/run", json=body, timeout=15).raise_for_status()

    def end_run(self) -> None:
        self.session.delete(self.url + "/run", timeout=15).raise_for_status()

    def end_offset(self) -> int:
        resp = self.session.get(self.url + "/offset", timeout=15)
        resp.raise_for_status()
        return int(resp.json()["end"])

    def events(self, offset: int) -> tuple[bytes, int]:
        resp = self.session.get(self.url + "/events", params={"offset": offset}, timeout=30)
        resp.raise_for_status()
        return resp.content, int(resp.headers["X-Next-Offset"])


class DefenderAPI:
    def __init__(self, cfg: Config) -> None:
        self.url = cfg.defender_url
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers["Authorization"] = f"Bearer {cfg.defender_token}"

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        try:
            resp = self.session.request(method, self.url + path, json=body, timeout=60)
        except requests.RequestException as exc:
            raise Unreachable(f"defender control {path}: {exc}") from exc
        data = resp.json()
        if resp.status_code != 200:
            raise RuntimeError(f"defender control {path}: {data.get('error', resp.status_code)}")
        return data

    def status(self) -> dict:
        return self._call("GET", "/status")

    def start(self, run_id: str, model: str, snapshot_interval: int) -> dict:
        return self._call("POST", "/start", {"run_id": run_id, "model": model,
                                             "snapshot_interval": snapshot_interval})

    def stop(self) -> dict:
        return self._call("POST", "/stop", {})


class Gitea:
    """The target's Gitea API on 443, authenticated as one ordinary seeded user."""

    def __init__(self, cfg: Config, user: dict) -> None:
        self.base = cfg.target_url + "/api/v1"
        self.user = user
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = cfg.ca_file
        self.session.headers["Authorization"] = f"token {user['token']}"

    def request(self, method: str, path: str, timeout: float = 30, **kw) -> requests.Response:
        return self.session.request(method, self.base + path, timeout=timeout, **kw)

    def get(self, path: str, **kw) -> requests.Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: dict, **kw) -> requests.Response:
        return self.request("POST", path, json=body, **kw)
