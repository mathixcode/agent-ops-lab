#!/usr/bin/env python3
"""Gateway control API — bound to the observer leg only, bearer-token protected.

    GET    /health
    GET    /offset               current end of the event log
    GET    /events?offset=N      raw JSON Lines from byte offset N (whole lines only)
    PUT    /run                  {run_id, canaries:[{id, marker}]}  -> start tagging + scanning
    DELETE /run                  back to idle

The observer pulls; the gateway never opens a connection towards the observer.
"""
from __future__ import annotations

import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DATA = os.environ.get("GATEWAY_DATA", "/var/lib/gateway")
EVENTS = f"{DATA}/events.jsonl"
REGISTRY = f"{DATA}/registry.json"
TOKEN = os.environ["LAB_GATEWAY_TOKEN"]
MAX_CHUNK = 4 * 1024 * 1024


def write_registry(doc: dict) -> None:
    tmp = REGISTRY + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    os.replace(tmp, REGISTRY)


class Handler(BaseHTTPRequestHandler):
    server_version = "gwctl"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/json", headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, doc: dict):
        self._send(code, json.dumps(doc).encode())

    def _authorized(self) -> bool:
        if hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {TOKEN}"):
            return True
        self._json(401, {"error": "unauthorized"})
        return False

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/health":
            return self._json(200, {"ok": True})
        if not self._authorized():
            return
        size = os.path.getsize(EVENTS) if os.path.exists(EVENTS) else 0
        if url.path == "/offset":
            return self._json(200, {"end": size})
        if url.path == "/events":
            offset = int(parse_qs(url.query).get("offset", ["0"])[0])
            if offset > size:            # log was reset; tell the collector to start over
                offset = 0
            chunk = b""
            if size > offset:
                with open(EVENTS, "rb") as fh:
                    fh.seek(offset)
                    chunk = fh.read(min(size - offset, MAX_CHUNK))
                chunk = chunk[: chunk.rfind(b"\n") + 1]
            return self._send(200, chunk, "application/x-ndjson",
                              {"X-Next-Offset": str(offset + len(chunk)), "X-End-Offset": str(size)})
        self._json(404, {"error": "not found"})

    def do_PUT(self):
        if not self._authorized():
            return
        if urlparse(self.path).path != "/run":
            return self._json(404, {"error": "not found"})
        try:
            doc = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
            run_id = str(doc["run_id"])
            canaries = [{"id": str(c["id"]), "marker": str(c["marker"])} for c in doc.get("canaries", [])]
        except (ValueError, KeyError, TypeError) as exc:
            return self._json(400, {"error": str(exc)})
        write_registry({"run_id": run_id, "canaries": canaries})
        self._json(200, {"run_id": run_id, "canaries": len(canaries)})

    def do_DELETE(self):
        if not self._authorized():
            return
        if urlparse(self.path).path != "/run":
            return self._json(404, {"error": "not found"})
        write_registry({"run_id": None, "canaries": []})
        self._json(200, {"run_id": None})


if __name__ == "__main__":
    os.makedirs(DATA, exist_ok=True)
    ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
