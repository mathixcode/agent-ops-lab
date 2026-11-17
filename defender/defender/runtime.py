"""The defender's long-running process (spec B.1: persistent process in its own container).

It idles until the observer's orchestrator starts a run through the control port, then runs
one agent for that run: fresh notes, fresh session, state snapshots on the manifest's cadence.

Control API (bearer token; only the observer is routed to this port):
    GET  /status
    POST /start   {run_id, model, snapshot_interval}
    POST /stop    final state snapshot, flush telemetry, stop the agent

The agent itself has no access to this API and does not know it exists.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .instrumentation import Telemetry
from .toolkit import Toolkit

log = logging.getLogger("defender")
SECRETS = Path(os.environ.get("DEFENDER_SECRETS", "/secrets"))
STATE = Path(os.environ.get("DEFENDER_STATE", "/state"))
TOKEN = os.environ["LAB_DEFENDER_TOKEN"]
DRIVER = os.environ.get("DEFENDER_DRIVER", "sdk")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class StartError(RuntimeError):
    pass


class Run:
    def __init__(self, run_id: str, model: str, snapshot_interval: int) -> None:
        self.run_id, self.snapshot_interval = run_id, snapshot_interval
        self.model = os.environ.get("DEFENDER_MODEL_ID", "claude-opus-5-5") if model in ("claude", "") else model
        self.dir = STATE / "runs" / run_id
        if self.dir.exists():
            raise StartError(f"state for run {run_id!r} already exists; every run needs a fresh run_id")
        self.dir.mkdir(parents=True)
        self.kit = Toolkit(SECRETS, self.dir / "notes.md")
        self.tel = Telemetry(run_id, os.environ["LANGFUSE_HOST"], os.environ["LANGFUSE_PUBLIC_KEY"],
                             os.environ["LANGFUSE_SECRET_KEY"], self.model)
        if DRIVER == "scripted":
            from .scripted_driver import ScriptedDriver
            self.driver = ScriptedDriver(self.kit, self.tel)
        elif DRIVER == "sdk":
            if not os.environ.get("ANTHROPIC_API_KEY"):
                raise StartError("ANTHROPIC_API_KEY is not set in the defender's environment "
                                 "(or set DEFENDER_DRIVER=scripted for a harness test without a model)")
            from .sdk_driver import SdkDriver
            self.driver = SdkDriver(self.kit, self.tel, self.model, self.dir,
                                    os.environ.get("LAB_CONTEXT_SENTINEL", ""))
        else:
            raise StartError(f"unknown DEFENDER_DRIVER {DRIVER!r}")
        self.stop_event = asyncio.Event()
        self.tasks: list[asyncio.Task] = []
        self.snapshots = 0

    async def _snapshots(self) -> None:
        """state_snapshot every snapshot_interval: a dump of the notes, taken by the runtime —
        the agent cannot skip it or dress it up."""
        while True:
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=self.snapshot_interval)
                return
            except asyncio.TimeoutError:
                self.tel.state_snapshot(self.kit.notes_text(), "interval",
                                        incidents_reported=len(self.kit.incidents))
                self.snapshots += 1

    def start(self) -> None:
        self.tasks = [asyncio.create_task(self.driver.run(self.stop_event), name="agent"),
                      asyncio.create_task(self._snapshots(), name="snapshots")]

    async def stop(self) -> None:
        self.stop_event.set()
        for task in self.tasks:
            try:
                await asyncio.wait_for(task, timeout=45)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                task.cancel()
            except Exception:
                log.exception("task %s ended with an error", task.get_name())
        self.tel.state_snapshot(self.kit.notes_text(), "final", incidents_reported=len(self.kit.incidents))
        self.snapshots += 1
        await asyncio.to_thread(self.tel.shutdown)
        self.kit.close()

    def status(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "snapshot_interval": self.snapshot_interval,
                "events_emitted": dict(self.tel.counts), **self.driver.status()}


class Runtime:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.run: Run | None = None

    async def start(self, run_id: str, model: str, snapshot_interval: int) -> dict[str, Any]:
        if not RUN_ID.match(run_id):
            raise StartError("invalid run_id")
        if self.run is not None:
            await self.stop()
        self.run = Run(run_id, model, max(5, int(snapshot_interval)))
        self.run.start()
        log.info("run %s started (driver=%s, model=%s)", run_id, DRIVER, self.run.model)
        return {"running": True, **self.run.status()}

    async def stop(self) -> dict[str, Any]:
        if self.run is None:
            return {"running": False}
        run, self.run = self.run, None
        await run.stop()
        log.info("run %s stopped: %s", run.run_id, run.tel.counts)
        return {"running": False, "stopped": run.status()}

    def status(self) -> dict[str, Any]:
        return {"running": self.run is not None, "driver": DRIVER, **(self.run.status() if self.run else {})}

    def call(self, coro, timeout: float = 120):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)


def make_handler(rt: Runtime):
    class Handler(BaseHTTPRequestHandler):
        server_version = "defender-control"

        def log_message(self, fmt, *args):
            log.info("control %s", fmt % args)

        def _reply(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            if hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {TOKEN}"):
                return True
            self._reply(401, {"error": "unauthorized"})
            return False

        def do_GET(self):
            if self._authorized():
                self._reply(200, rt.status()) if self.path == "/status" else self._reply(404, {"error": "not found"})

        def do_POST(self):
            if not self._authorized():
                return
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                if self.path == "/start":
                    self._reply(200, rt.call(rt.start(str(body["run_id"]), str(body.get("model", "claude")),
                                                      int(body.get("snapshot_interval", 1800)))))
                elif self.path == "/stop":
                    self._reply(200, rt.call(rt.stop()))
                else:
                    self._reply(404, {"error": "not found"})
            except StartError as exc:
                self._reply(400, {"error": str(exc)})
            except Exception as exc:
                log.exception("control request failed")
                self._reply(500, {"error": f"{type(exc).__name__}: {exc}"})

    return Handler


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    rt = Runtime()
    port = int(os.environ.get("DEFENDER_CONTROL_PORT", "8090"))
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(rt))
    threading.Thread(target=server.serve_forever, daemon=True, name="control").start()
    log.info("defender idle; waiting for a run (driver=%s)", DRIVER)
    asyncio.set_event_loop(rt.loop)
    rt.loop.run_forever()


if __name__ == "__main__":
    main()
