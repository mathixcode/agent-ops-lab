"""B.2 — the operator toolkit, independent of any agent framework.

    ssh_exec        shell on the target over SSH (operator account, sudo available)
    read_file       read a file on the target
    write_file      write a file on the target
    gitea_api       the Gitea API on the target, with the admin token
    notes_*         the agent's own persistent notes (the "agent's view" metric 3 examines)
    report_incident the structured incident report

Every tool returns (ok, text). The SSH key and the admin token live here and are used on the
agent's behalf; they are never part of a tool result.
"""
from __future__ import annotations

import json
import shlex
import threading
from pathlib import Path
from typing import Any

import paramiko
import requests

from labcontracts import network, telemetry

MAX_OUTPUT = 20_000
NOTES_TEMPLATE = "# Operator notes\n\n(nothing recorded yet)\n"


def _cap(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + f"\n… [{len(text) - limit} characters omitted] …\n" + text[-half:]


class Toolkit:
    def __init__(self, secrets: Path, notes_path: Path) -> None:
        self.secrets, self.notes_path = secrets, notes_path
        self._ssh: paramiko.SSHClient | None = None
        self._lock = threading.Lock()
        self.incidents: list[dict[str, Any]] = []
        self.http = requests.Session()
        self.http.trust_env = False                       # the target is reached directly, not via the proxy
        self.http.verify = str(secrets / "ca.crt")
        self.http.headers["Authorization"] = "token " + (secrets / "gitea_admin_token").read_text().strip()
        if not notes_path.exists():
            notes_path.parent.mkdir(parents=True, exist_ok=True)
            notes_path.write_text(NOTES_TEMPLATE, encoding="utf-8")

    # ------------------------------------------------------------------ SSH
    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.load_host_keys(str(self.secrets / "known_hosts"))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(network.TARGET_HOSTNAME, port=22, username="operator",
                       key_filename=str(self.secrets / "operator_key"), allow_agent=False,
                       look_for_keys=False, timeout=20, banner_timeout=60, auth_timeout=60)
        client.get_transport().set_keepalive(30)
        return client

    def _run(self, command: str, stdin: bytes | None = None, timeout: float = 120) -> tuple[int, str, str]:
        with self._lock:
            for attempt in (1, 2):
                try:
                    if self._ssh is None or not self._ssh.get_transport() or not self._ssh.get_transport().is_active():
                        self._ssh = self._connect()
                    chan_in, chan_out, chan_err = self._ssh.exec_command(command, timeout=timeout)
                    if stdin is not None:
                        chan_in.write(stdin)
                    chan_in.channel.shutdown_write()
                    out = chan_out.read().decode("utf-8", "replace")
                    err = chan_err.read().decode("utf-8", "replace")
                    return chan_out.channel.recv_exit_status(), out, err
                except Exception as exc:
                    if self._ssh is not None:
                        try:
                            self._ssh.close()
                        except Exception:
                            pass
                        self._ssh = None
                    if attempt == 2:
                        return 255, "", f"ssh failed: {type(exc).__name__}: {exc}"
        return 255, "", "ssh failed"

    def ssh_exec(self, command: str, timeout: int = 120) -> tuple[bool, str]:
        timeout = max(5, min(int(timeout or 120), 900))
        rc, out, err = self._run(command, timeout=timeout)
        text = f"exit status: {rc}\n--- stdout ---\n{_cap(out)}"
        if err.strip():
            text += f"\n--- stderr ---\n{_cap(err, 5000)}"
        return rc == 0, text

    def read_file(self, path: str) -> tuple[bool, str]:
        rc, out, err = self._run(f"sudo cat -- {shlex.quote(path)}")
        return (True, _cap(out, 100_000)) if rc == 0 else (False, f"cannot read {path}: {err.strip()[:500]}")

    def write_file(self, path: str, content: str) -> tuple[bool, str]:
        rc, _, err = self._run(f"sudo tee -- {shlex.quote(path)} >/dev/null", stdin=content.encode())
        return (True, f"wrote {len(content)} characters to {path}") if rc == 0 else \
            (False, f"cannot write {path}: {err.strip()[:500]}")

    # ------------------------------------------------------------------ Gitea API
    def gitea_api(self, method: str, path: str, body: Any = None) -> tuple[bool, str]:
        method = (method or "GET").upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            return False, f"unsupported method {method}"
        if not path.startswith("/"):
            path = "/" + path
        url = f"https://{network.TARGET_HOSTNAME}/api/v1{path}"
        try:
            resp = self.http.request(method, url, json=body if body not in (None, "") else None, timeout=60)
        except requests.RequestException as exc:
            return False, f"request failed: {type(exc).__name__}: {str(exc)[:300]}"
        return resp.status_code < 400, f"HTTP {resp.status_code}\n{_cap(resp.text)}"

    # ------------------------------------------------------------------ notes
    def notes_read(self) -> tuple[bool, str]:
        return True, self.notes_path.read_text(encoding="utf-8")

    def notes_write(self, content: str) -> tuple[bool, str]:
        self.notes_path.write_text(content, encoding="utf-8")
        return True, f"notes replaced ({len(content)} characters)"

    def notes_append(self, text: str) -> tuple[bool, str]:
        with open(self.notes_path, "a", encoding="utf-8") as fh:
            fh.write(("" if text.startswith("\n") else "\n") + text.rstrip("\n") + "\n")
        return True, f"appended {len(text)} characters to the notes"

    def notes_text(self) -> str:
        return self.notes_path.read_text(encoding="utf-8") if self.notes_path.exists() else ""

    # ------------------------------------------------------------------ incident report
    def report_incident(self, report: dict[str, Any]) -> tuple[bool, str]:
        fields = ("incident_id", "detected", "root_cause", "action_taken", "status", "confidence")
        missing = [f for f in fields if f not in report]
        if missing:
            return False, f"incident report is missing {missing}"
        clean = {f: report[f] for f in fields}
        try:
            clean["confidence"] = float(clean["confidence"])
            telemetry.validate_incident_report(clean)
        except (telemetry.ContractError, TypeError, ValueError) as exc:
            return False, f"invalid incident report: {exc}"
        self.incidents.append(clean)
        return True, f"incident report {clean['incident_id']} recorded with status {clean['status']}"

    def close(self) -> None:
        with self._lock:
            if self._ssh is not None:
                try:
                    self._ssh.close()
                except Exception:
                    pass
                self._ssh = None


def parse_json_arg(value: Any) -> Any:
    """Tool arguments that are JSON documents may arrive as text."""
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value
