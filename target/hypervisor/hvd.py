#!/usr/bin/env python3
"""Hypervisor daemon: runs the target VM and exposes the control API the observer uses.

This is the "hypervisor/snapshot access" of spec 1.2 — held by the observer only.

    GET  /status       VM state, accelerator, golden image metadata
    POST /reset        discard the run overlay and boot fresh from the golden snapshot
    POST /stop         power the VM off
    POST /guest-exec   run a command inside the guest through the QEMU guest agent
                       (out-of-band channel used for fault injection)

Every request needs `Authorization: Bearer $LAB_HV_TOKEN`; the port is additionally
firewalled to the observer's address.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import signal
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import qemu

TOKEN = os.environ["LAB_HV_TOKEN"]
PORT = int(os.environ["HV_CONTROL_PORT"])
OVERLAY = f"{qemu.IMAGES}/run-overlay.qcow2"
CONSOLE_LOG = "/var/log/hv/console.log"


class VM:
    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None
        self.started_at: float | None = None
        self.resets = 0
        self.lock = threading.RLock()
        self.qga_lock = threading.Lock()

    # ------------------------------------------------------------- lifecycle
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, fresh: bool) -> None:
        with self.lock:
            if self.running():
                return
            if not os.path.exists(qemu.GOLDEN):
                raise RuntimeError("no golden image — run `labctl.py build` first")
            if fresh or not os.path.exists(OVERLAY):
                if os.path.exists(OVERLAY):
                    os.unlink(OVERLAY)
                subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", qemu.GOLDEN,
                                "-F", "qcow2", OVERLAY], check=True)
            for sock in (qemu.QGA_SOCK, qemu.QMP_SOCK):
                if os.path.exists(sock):
                    os.unlink(sock)
            cmd = qemu.command(OVERLAY, "tap,id=n0,ifname=tap0,script=no,downscript=no", CONSOLE_LOG)
            self.proc = subprocess.Popen(cmd)
            self.started_at = time.time()
            print(f"hvd: VM started (pid {self.proc.pid}, accel {qemu.accel()}, fresh={fresh})", flush=True)

    def stop(self, timeout: float = 90.0) -> None:
        with self.lock:
            if not self.running():
                self.proc = None
                return
            try:
                self.guest_exec(["systemctl", "poweroff"], timeout=10)
            except Exception:
                pass
            deadline = time.time() + timeout
            while self.proc.poll() is None and time.time() < deadline:
                time.sleep(1)
            if self.proc.poll() is None:
                self.proc.send_signal(signal.SIGTERM)
                try:
                    self.proc.wait(15)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait()
            self.proc = None
            self.started_at = None

    def reset(self) -> None:
        """Golden-snapshot restore: the overlay holding every change of the last run is
        thrown away. Stopping does not need to be graceful — nothing is kept."""
        with self.lock:
            if self.running():
                self.proc.send_signal(signal.SIGTERM)
                try:
                    self.proc.wait(20)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait()
            self.proc = None
            self.resets += 1
            self.start(fresh=True)

    # ------------------------------------------------------------- guest agent
    def _qga(self, request: dict, timeout: float) -> dict:
        with self.qga_lock:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect(qemu.QGA_SOCK)
                sync_id = int(time.time() * 1000) % 2_000_000_000
                s.sendall(json.dumps({"execute": "guest-sync", "arguments": {"id": sync_id}}).encode() + b"\n")
                buf = b""

                def read_reply() -> dict:
                    nonlocal buf
                    while True:
                        while b"\n" not in buf:
                            chunk = s.recv(65536)
                            if not chunk:
                                raise ConnectionError("guest agent closed the channel")
                            buf += chunk
                        line, buf = buf.split(b"\n", 1)
                        line = line.strip(b"\xff \r")
                        if line:
                            return json.loads(line)

                while read_reply().get("return") != sync_id:    # drop stale replies
                    pass
                s.sendall(json.dumps(request).encode() + b"\n")
                reply = read_reply()
            finally:
                s.close()
        if "error" in reply:
            raise RuntimeError(f"guest agent: {reply['error'].get('desc', reply['error'])}")
        return reply["return"]

    def guest_ping(self) -> bool:
        if not self.running():
            return False
        try:
            self._qga({"execute": "guest-ping"}, timeout=3)
            return True
        except Exception:
            return False

    def guest_exec(self, argv: list[str], stdin: bytes | None = None, timeout: float = 60) -> dict:
        """Run a command in the guest and wait for it (at most `timeout` seconds).

        A slow or garbled guest-agent reply while polling is retried until the deadline — one
        slow poll on a busy guest is not a failed command. At the deadline the command and
        everything it started are killed inside the guest, so timed-out commands never pile up
        there. `truncated` says whether the guest agent cut the captured output short."""
        args = {"path": argv[0], "arg": argv[1:], "capture-output": True}
        if stdin is not None:
            args["input-data"] = base64.b64encode(stdin).decode()
        pid = self._qga({"execute": "guest-exec", "arguments": args}, timeout=15)["pid"]
        deadline = time.time() + timeout
        while True:
            try:
                st = self._qga({"execute": "guest-exec-status", "arguments": {"pid": pid}}, timeout=10)
            except (OSError, ValueError) as exc:        # timeout, closed channel, garbled reply line
                if time.time() > deadline:
                    self._kill_guest(pid)
                    raise TimeoutError(f"guest command {argv[0]}: no status within {timeout}s "
                                       f"({type(exc).__name__}); killed") from exc
                time.sleep(1)
                continue
            if st.get("exited"):
                return {"exitcode": st.get("exitcode", -1),
                        "stdout": base64.b64decode(st.get("out-data", "")).decode("utf-8", "replace"),
                        "stderr": base64.b64decode(st.get("err-data", "")).decode("utf-8", "replace"),
                        "truncated": bool(st.get("out-truncated") or st.get("err-truncated"))}
            if time.time() > deadline:
                self._kill_guest(pid)
                raise TimeoutError(f"guest command still running after {timeout}s: {argv[0]} (killed)")
            time.sleep(0.5)

    # Kills a process and all its descendants, children first (argv: kill-tree <pid>).
    KILL_TREE = ('kill_tree() { local c; for c in $(pgrep -P "$1"); do kill_tree "$c"; done; '
                 'kill -KILL "$1" 2>/dev/null; }; kill_tree "$1"')

    def _kill_guest(self, pid: int) -> None:
        """Best effort: kill a timed-out guest command and what it started, then collect its
        status so the guest agent forgets it."""
        try:
            killer = self._qga({"execute": "guest-exec", "arguments": {
                "path": "/bin/bash", "arg": ["-c", self.KILL_TREE, "kill-tree", str(pid)]}}, timeout=10)["pid"]
            for target in (killer, pid):
                for _ in range(20):
                    if self._qga({"execute": "guest-exec-status", "arguments": {"pid": target}},
                                 timeout=10).get("exited"):
                        break
                    time.sleep(0.25)
        except Exception as exc:
            print(f"hvd: could not kill guest pid {pid}: {type(exc).__name__}: {exc}", flush=True)

    def status(self) -> dict:
        meta = {}
        if os.path.exists(qemu.GOLDEN_META):
            with open(qemu.GOLDEN_META) as fh:
                meta = json.load(fh)
        return {"vm": "running" if self.running() else "stopped", "accel": qemu.accel(),
                "uptime_s": round(time.time() - self.started_at, 1) if self.started_at and self.running() else None,
                "guest_agent": self.guest_ping(), "resets": self.resets,
                "golden_present": os.path.exists(qemu.GOLDEN), "golden": meta}


vm = VM()


class Handler(BaseHTTPRequestHandler):
    server_version = "hvd"

    def log_message(self, fmt, *args):
        print(f"hvd: {self.address_string()} {fmt % args}", flush=True)

    def _reply(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        given = self.headers.get("Authorization", "")
        if hmac.compare_digest(given, f"Bearer {TOKEN}"):
            return True
        self._reply(401, {"error": "unauthorized"})
        return False

    def do_GET(self):
        if not self._authorized():
            return
        if self.path == "/status":
            self._reply(200, vm.status())
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorized():
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/reset":
                vm.reset()
                self._reply(200, vm.status())
            elif self.path == "/stop":
                vm.stop()
                self._reply(200, vm.status())
            elif self.path == "/guest-exec":
                stdin = base64.b64decode(body["stdin_b64"]) if body.get("stdin_b64") else None
                self._reply(200, vm.guest_exec(list(body["argv"]), stdin, float(body.get("timeout", 60))))
            else:
                self._reply(404, {"error": "not found"})
        except Exception as exc:  # report, never crash the daemon
            self._reply(500, {"error": f"{type(exc).__name__}: {exc}"})


def main() -> None:
    def shutdown(*_):
        threading.Thread(target=lambda: (vm.stop(30), os._exit(0)), daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    if os.path.exists(qemu.GOLDEN):
        vm.start(fresh=False)
    else:
        print("hvd: no golden image yet; waiting for a build", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
