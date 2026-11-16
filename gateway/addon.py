"""mitmproxy addon for the egress gateway (component D).

Emits spec 1.3 events to /var/lib/gateway/events.jsonl:

  gateway/egress_request   one per outbound request: destination, size, time, outcome
  gateway/canary_egress    a registered honey-secret marker was seen leaving the lab

What is logged is deliberately narrow: destination, sizes, timing and canary *ids*.
Bodies, header values and the markers themselves never reach the log.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import time
import urllib.parse

from mitmproxy import http, tcp, tls

from labcontracts import canary, network, telemetry

DATA = os.environ.get("GATEWAY_DATA", "/var/lib/gateway")
EVENTS = f"{DATA}/events.jsonl"
REGISTRY = f"{DATA}/registry.json"
COUNTERS = "/run/gateway/counters.json"
MODEL_HOSTS = tuple(h.strip().lower() for h in os.environ.get("MODEL_PROVIDER_HOSTS", "").split(",") if h.strip())
IDLE_RUN = "idle"

# nft counter name -> (src_role, what the dropped traffic was trying to reach)
BLOCK_COUNTERS = {
    "to_observer_from_target": ("target", "observer_segment"),
    "to_observer_from_defender": ("defender", "observer_segment"),
    "direct_from_target": ("target", "direct_bypassing_proxy"),
    "direct_from_defender": ("defender", "direct_bypassing_proxy"),
    "proxy_to_internal": ("proxy", "lab_internal_via_proxy"),
}


def last_seq(path: str) -> int:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 65536))
            lines = fh.read().splitlines()
        return json.loads(lines[-1])["seq"] + 1 if lines else 0
    except (OSError, ValueError, KeyError, IndexError):
        return 0


class EgressLog:
    def __init__(self) -> None:
        os.makedirs(DATA, exist_ok=True)
        self.seq = telemetry.SeqCounter(last_seq(EVENTS))
        self.out = open(EVENTS, "a", buffering=1, encoding="utf-8")
        self.run_id = IDLE_RUN
        self.scanner = canary.Scanner([])
        self._registry_mtime = 0.0
        self._counters: dict[str, int] = {}
        self._poller: asyncio.Task | None = None

    # ------------------------------------------------------------------ plumbing
    def _reload_registry(self) -> None:
        try:
            mtime = os.stat(REGISTRY).st_mtime
        except OSError:
            return
        if mtime == self._registry_mtime:
            return
        self._registry_mtime = mtime
        try:
            with open(REGISTRY, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        self.run_id = data.get("run_id") or IDLE_RUN
        self.scanner = canary.Scanner([canary.Canary(c["id"], c["marker"], "", "")
                                       for c in data.get("canaries", [])])

    def emit(self, type_: str, payload: dict, ts: float | None = None) -> None:
        self._reload_registry()
        when = telemetry.utc_now() if ts is None else dt.datetime.fromtimestamp(ts, dt.timezone.utc)
        ev = telemetry.make_event(self.run_id, "gateway", type_, self.seq.next(), payload, ts=when)
        self.out.write(telemetry.to_line(ev) + "\n")

    @staticmethod
    def _client(conn) -> tuple[str, str]:
        ip = conn.peername[0] if conn and conn.peername else "unknown"
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        try:
            role = network.segment_of(ip) or "outside"
        except ValueError:
            role = "outside"
        return ip, role

    @staticmethod
    def _channel(host: str) -> str:
        host = host.lower()
        return "model_provider" if any(host == h or host.endswith("." + h) for h in MODEL_HOSTS) else "external"

    def _report_canaries(self, hits: dict[tuple[str, str], str], destination: str, src_ip: str,
                         src_role: str, channel: str) -> None:
        for (canary_id, encoding), where in hits.items():
            self.emit("canary_egress", {"canary_id": canary_id, "encoding": encoding, "where": where,
                                        "destination": destination, "src_ip": src_ip,
                                        "src_role": src_role, "channel": channel})

    # ------------------------------------------------------------------ HTTP(S)
    def request(self, flow: http.HTTPFlow) -> None:
        self._reload_registry()
        req = flow.request
        src_ip, src_role = self._client(flow.client_conn)
        destination = f"{req.pretty_host}:{req.port}"
        channel = self._channel(req.pretty_host)
        flow.metadata["lab"] = {"src_ip": src_ip, "src_role": src_role, "destination": destination,
                                "channel": channel, "response_bytes": 0}
        if not self.scanner:
            return
        hits: dict[tuple[str, str], str] = {}
        url = req.pretty_url
        for hit in self.scanner.scan(url) + self.scanner.scan(urllib.parse.unquote(url)):
            hits.setdefault(hit, "url")
        header_blob = b"\n".join(k + b": " + v for k, v in req.headers.fields)
        for hit in self.scanner.scan(header_blob):
            hits.setdefault(hit, "headers")
        bodies = [req.raw_content or b""]
        try:
            decoded = req.get_content(strict=False) or b""
            if decoded != bodies[0]:
                bodies.append(decoded)
        except ValueError:
            pass
        for body in bodies:
            for hit in self.scanner.scan(body) + self.scanner.scan(urllib.parse.unquote_to_bytes(body)):
                hits.setdefault(hit, "body")
        self._report_canaries(hits, destination, src_ip, src_role, channel)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # Inbound data is not inspected; stream it (model responses are long-lived SSE)
        # and only count bytes.
        meta = flow.metadata.get("lab")

        def count(chunk: bytes) -> bytes:
            if meta is not None:
                meta["response_bytes"] += len(chunk)
            return chunk

        flow.response.stream = count

    def _log_http(self, flow: http.HTTPFlow, action: str, detail: str | None = None) -> None:
        meta = flow.metadata.get("lab")
        if meta is None or meta.get("logged"):
            return
        meta["logged"] = True
        req = flow.request
        header_bytes = sum(len(k) + len(v) + 4 for k, v in req.headers.fields)
        payload = {
            "destination": meta["destination"], "action": action,
            "size": len(req.raw_content or b"") + header_bytes + len(req.path),
            "response_size": meta["response_bytes"],
            "method": req.method, "scheme": req.scheme,
            "path": self.scanner.redact(req.path.split("?", 1)[0])[:200],
            "status": flow.response.status_code if flow.response else None,
            "duration_ms": int((time.time() - req.timestamp_start) * 1000),
            "src_ip": meta["src_ip"], "src_role": meta["src_role"], "channel": meta["channel"],
        }
        if detail:
            payload["detail"] = detail[:200]
        self.emit("egress_request", payload, ts=req.timestamp_start)

    def response(self, flow: http.HTTPFlow) -> None:
        self._log_http(flow, "allowed")

    def error(self, flow: http.HTTPFlow) -> None:
        self._log_http(flow, "failed", flow.error.msg if flow.error else None)

    def http_connect_error(self, flow: http.HTTPFlow) -> None:
        # CONNECT to a destination the gateway refuses or cannot reach (e.g. a lab-internal address)
        if "lab" not in flow.metadata:
            src_ip, src_role = self._client(flow.client_conn)
            flow.metadata["lab"] = {"src_ip": src_ip, "src_role": src_role, "response_bytes": 0,
                                    "destination": f"{flow.request.pretty_host}:{flow.request.port}",
                                    "channel": self._channel(flow.request.pretty_host)}
        self._log_http(flow, "failed", flow.error.msg if flow.error else "connect failed")

    def tls_failed_client(self, data: tls.TlsData) -> None:
        src_ip, src_role = self._client(data.context.client)
        host = data.context.client.sni or (data.context.server.address[0] if data.context.server.address else "unknown")
        port = data.context.server.address[1] if data.context.server.address else 443
        self.emit("egress_request", {"destination": f"{host}:{port}", "action": "failed", "size": 0,
                                     "detail": "client rejected the gateway certificate",
                                     "src_ip": src_ip, "src_role": src_role, "channel": self._channel(host)})

    # ------------------------------------------------------------------ raw TCP / WebSocket
    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        msg = flow.messages[-1]
        if not msg.from_client:
            return
        self._reload_registry()
        src_ip, src_role = self._client(flow.client_conn)
        host, port = flow.server_conn.address or ("unknown", 0)
        hits = {hit: "tcp" for hit in self.scanner.scan(msg.content)}
        self._report_canaries(hits, f"{host}:{port}", src_ip, src_role, self._channel(str(host)))

    def tcp_end(self, flow: tcp.TCPFlow) -> None:
        src_ip, src_role = self._client(flow.client_conn)
        host, port = flow.server_conn.address or ("unknown", 0)
        sent = sum(len(m.content) for m in flow.messages if m.from_client)
        received = sum(len(m.content) for m in flow.messages if not m.from_client)
        self.emit("egress_request", {"destination": f"{host}:{port}", "action": "allowed", "size": sent,
                                     "response_size": received, "scheme": "tcp", "src_ip": src_ip,
                                     "src_role": src_role, "channel": self._channel(str(host))},
                  ts=flow.timestamp_start)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        msg = flow.websocket.messages[-1]
        meta = flow.metadata.get("lab")
        if not msg.from_client or meta is None:
            return
        hits = {hit: "websocket" for hit in self.scanner.scan(msg.content)}
        self._report_canaries(hits, meta["destination"], meta["src_ip"], meta["src_role"], meta["channel"])

    # ------------------------------------------------------------------ firewall drops
    async def running(self) -> None:
        if self._poller is None:
            self._poller = asyncio.get_running_loop().create_task(self._poll_counters())

    async def _poll_counters(self) -> None:
        """Traffic that never reached the proxy (dropped by the firewall) is still egress
        worth recording. The root-side helper publishes the nft counters; deltas become events."""
        first = True
        while True:
            try:
                with open(COUNTERS, encoding="utf-8") as fh:
                    current = json.load(fh)
            except (OSError, ValueError):
                current = None
            if current is not None:
                for name, (src_role, tried) in BLOCK_COUNTERS.items():
                    packets, size = current.get(name, (0, 0))
                    before_packets, before_size = self._counters.get(name, (0, 0))
                    if not first and packets > before_packets:
                        self.emit("egress_request", {
                            "destination": tried, "action": "blocked", "size": size - before_size,
                            "packets": packets - before_packets, "src_role": src_role,
                            "channel": "none", "detail": "dropped by the gateway firewall"})
                    self._counters[name] = (packets, size)
                first = False
            await asyncio.sleep(5)


addons = [EgressLog()]
