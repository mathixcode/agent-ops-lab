"""C1 load generator: simulated users driving the target's Gitea on 443 (browse, post, push).

Runs as its own process (Locust is gevent-based) and prints one JSON object per line on
stdout; the orchestrator wraps each line into a monitor/load_event. The seed fixes the load
pattern and the account -> address mapping, so a run is reproducible.

Traffic identities: every simulated account is bound to one of the users-segment addresses
(network.USER_IPS) by a stable, seeded mapping (identities.assign_ips). Its API requests leave
from that address; so do its git pushes, which go through a small local CONNECT tunnel bound
to the same address (git itself cannot choose a source address). The concurrent Locust users
act as the accounts in turn — each task as the next account in a fixed rotation — so every IP
group carries traffic even when fewer users run than there are accounts, and the load volume
does not change. Results are reported per IP group, with the failure signature of every
failed request (signatures.py).

Pushes: every Locust user keeps its own working copies (two users acting as the same account
never share a directory). A push rejected as non-fast-forward — another push landed first —
is fetched and pushed again, as a person would; one that keeps losing the race is counted as a
`conflict`, not as a failure: the service answered correctly.

The process ends by itself after --duration, on SIGTERM, and when the orchestrator that
started it is gone (its parent changed, or its stdout pipe is closed) — it never keeps loading
the target on its own.

    python -m observer.loadgen.runner --seed 42 --profile steady_with_peaks --duration 21600
"""
from __future__ import annotations

from gevent import monkey

monkey.patch_all()

import argparse  # noqa: E402
import collections  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import random  # noqa: E402
import shutil  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402

import gevent  # noqa: E402
from gevent import socket as gsocket  # noqa: E402
from gevent.server import StreamServer  # noqa: E402
from locust import HttpUser, between, task  # noqa: E402
from locust.env import Environment  # noqa: E402

from observer import identities, signatures  # noqa: E402
from observer.config import Config  # noqa: E402
from observer.loadgen.profile import stages  # noqa: E402

CFG = Config()
USERS = identities.load_accounts(CFG.seed_users())
REPOS = CFG.golden()["seed"]["load_repos"]
WORKDIR = tempfile.mkdtemp(prefix="loadgen-")
_next_user = iter(range(10**9))
IP_OF: dict[str, str] = {}              # username -> source address (set in main from the seed)
TUNNELS: dict[str, "SourceTunnel"] = {}
ADAPTERS: dict[str, identities.SourceAddressAdapter] = {}    # one connection pool per address
TUNNEL_IDLE_S = 150         # > git's own 120 s budget: the git subprocess timeout decides, never the tunnel
PUSH_ATTEMPTS = 3           # a push that loses the race against other pushes is fetched and retried
STOPPING: list[bool] = []   # set on SIGTERM, a lost parent or a closed stdout


class PushConflict(Exception):
    """Every push attempt was rejected as non-fast-forward (other pushes kept landing first)."""


def say(kind: str, **fields) -> None:
    try:
        sys.stdout.write(json.dumps({"kind": kind, **fields}) + "\n")
        sys.stdout.flush()
    except (BrokenPipeError, ValueError):      # the orchestrator is gone: stop instead of loading on
        STOPPING.append(True)


class SourceTunnel:
    """A local HTTP CONNECT proxy for git: upstream connections to the target leave from one
    source address. TLS stays end to end (git verifies the target's certificate itself)."""

    def __init__(self, source_ip: str, target_ip: str, target_host: str) -> None:
        self.source_ip, self.target_ip, self.target_host = source_ip, target_ip, target_host
        self.server = StreamServer(("127.0.0.1", 0), self.handle)
        self.server.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def handle(self, client, _addr) -> None:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = client.recv(4096)
            if not chunk:
                return
            data += chunk
        parts = data.split(b"\r\n", 1)[0].decode("latin-1").split()
        if len(parts) < 2 or parts[0] != "CONNECT" or parts[1].rsplit(":", 1)[0] not in (self.target_host, self.target_ip):
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        try:
            upstream = gsocket.create_connection((self.target_ip, int(parts[1].rsplit(":", 1)[1])), timeout=30,
                                                 source_address=(self.source_ip, 0))
        except OSError as exc:
            client.sendall(f"HTTP/1.1 502 Tunnel failed ({type(exc).__name__})\r\n\r\n".encode())
            return
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        # Idle limit for the relay (the connect above keeps its 30 s): longer than git's own
        # budget, so a slow but working server is never cut off by the tunnel.
        upstream.settimeout(TUNNEL_IDLE_S)
        client.settimeout(TUNNEL_IDLE_S)

        def pump(src, dst):
            try:
                while True:
                    buf = src.recv(65536)
                    if not buf:
                        break
                    dst.sendall(buf)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(gsocket.SHUT_WR)
                except OSError:
                    pass

        gevent.joinall([gevent.spawn(pump, client, upstream), gevent.spawn(pump, upstream, client)])
        upstream.close()


class IpStats:
    """Per-IP-group request counters, per reporting window and for the whole run."""

    def __init__(self) -> None:
        self.window: dict[str, dict] = {}
        self.total: dict[str, dict] = {}

    @staticmethod
    def _blank() -> dict:
        return {"requests": 0, "failures": 0, "conflicts": 0, "signatures": collections.Counter(),
                "statuses": collections.Counter()}

    def record(self, ip: str, signature: str | None, status: int | None, conflict: bool = False) -> None:
        for bucket in (self.window, self.total):
            b = bucket.setdefault(ip, self._blank())
            b["requests"] += 1
            if conflict:
                b["conflicts"] += 1
            elif signature:
                b["failures"] += 1
                b["signatures"][signature] += 1
                if status:
                    b["statuses"][str(status)] += 1

    @staticmethod
    def dump(bucket: dict) -> dict:
        return {ip: {"requests": b["requests"], "failures": b["failures"], "conflicts": b["conflicts"],
                     "signatures": dict(b["signatures"]), "statuses": dict(b["statuses"])}
                for ip, b in sorted(bucket.items())}

    def take_window(self) -> dict:
        out, self.window = self.dump(self.window), {}
        return out


IP_STATS = IpStats()


def on_request(request_type, name, response_time, response_length, response=None, context=None, exception=None,
               **_kw) -> None:
    ip = (context or {}).get("ip", "unbound")
    if (context or {}).get("conflict"):
        IP_STATS.record(ip, None, None, conflict=True)
        return
    signature, status = None, None
    code = getattr(response, "status_code", None) or None
    if code and code >= 400:
        status = code
        signature, _ = signatures.classify_response(code, getattr(response, "headers", None),
                                                    getattr(response, "content", None))
    elif exception is not None:
        if request_type == "GIT":
            signature = signatures.classify_git_error(str(exception))
        else:
            signature, _ = signatures.classify_exception(exception)
    IP_STATS.record(ip, signature, status)


class GiteaUser(HttpUser):
    wait_time = between(2, 7)

    def on_start(self) -> None:
        self.index = next(_next_user)
        self.turn = 0
        self.client.verify = CFG.ca_file
        self.client.trust_env = False
        self.rng = random.Random(f"{self.environment.parsed_seed}-worker-{self.index}")
        self.clones: dict[str, str] = {}
        self.act_as_next()

    def act_as_next(self) -> None:
        """Become the next account in this user's rotation (and leave from its address)."""
        self.who = USERS[(self.index + self.turn) % len(USERS)]
        self.turn += 1
        self.ip = IP_OF[self.who["username"]]
        if self.ip not in ADAPTERS:
            ADAPTERS[self.ip] = identities.SourceAddressAdapter(self.ip)
        self.client.mount("https://", ADAPTERS[self.ip])
        self.client.mount("http://", ADAPTERS[self.ip])
        self.client.headers["Authorization"] = f"token {self.who['token']}"

    def context(self) -> dict:
        return {"ip": self.ip, "user": self.who["username"]}

    def repo(self) -> str:
        return self.rng.choice(REPOS)

    # ---- browse -------------------------------------------------------------------------------
    @task(6)
    def browse(self) -> None:
        self.act_as_next()
        repo = self.repo()
        pick = self.rng.choice(("repo", "tree", "commits", "issues"))
        path, name = {
            "repo": (f"/api/v1/repos/{repo}", "browse repo"),
            "tree": (f"/api/v1/repos/{repo}/contents/", "browse tree"),
            "commits": (f"/api/v1/repos/{repo}/commits?limit=5", "browse commits"),
            "issues": (f"/api/v1/repos/{repo}/issues?state=open&limit=10", "browse issues"),
        }[pick]
        self.client.get(path, name=name, timeout=30)

    # ---- post ---------------------------------------------------------------------------------
    @task(3)
    def post(self) -> None:
        self.act_as_next()
        repo = self.repo()
        with self.client.get(f"/api/v1/repos/{repo}/issues?state=open&limit=10", name="browse issues",
                             timeout=30, catch_response=True) as listing:
            try:
                issues = listing.json() if listing.status_code == 200 else []
            except ValueError:
                issues = []
            if listing.status_code >= 400 or not listing.status_code:
                listing.failure(f"HTTP {listing.status_code}")
        if issues and self.rng.random() < 0.6:
            number = self.rng.choice(issues)["number"]
            resp = self.client.post(f"/api/v1/repos/{repo}/issues/{number}/comments", name="post comment",
                                    json={"body": f"Update from {self.who['full_name']}: still relevant."},
                                    timeout=30)
            if resp.status_code == 201:
                say("write_ack", repo=repo, issue=number, op="comment", ip=self.ip)
        else:
            resp = self.client.post(f"/api/v1/repos/{repo}/issues", name="post issue", timeout=30, json={
                "title": f"Follow-up {self.rng.getrandbits(24):06x}", "body": "Noticed while reviewing; details to follow."})
            if resp.status_code == 201:
                say("write_ack", repo=repo, issue=resp.json()["number"], op="issue", ip=self.ip)

    # ---- push ---------------------------------------------------------------------------------
    @task(1)
    def push(self) -> None:
        self.act_as_next()
        repo = self.repo()
        started = time.time()
        error, sha, conflict = None, None, False
        try:
            sha = self._git_push(repo)
        except PushConflict:
            conflict = True                        # the service answered correctly every time
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            text = _stderr_text(exc)
            # The failure is classified from this message (signatures.classify_git_error): keep
            # every line that names an HTTP status or a rejection, plus git's last line.
            lines = text.strip().splitlines()
            keep = [l for l in lines if "returned error" in l or "rejected" in l]
            last = lines[-1] if lines else type(exc).__name__
            error = RuntimeError(" | ".join(dict.fromkeys([*keep, last]))[:300])
            shutil.rmtree(self.clones.pop(f"{self.who['username']}:{repo}", ""), ignore_errors=True)   # fresh clone next time
        self.environment.events.request.fire(
            request_type="GIT", name="git push", response_time=(time.time() - started) * 1000,
            response_length=0, exception=error,
            context={**self.context(), **({"conflict": True} if conflict else {})})
        if sha:
            say("write_ack", repo=repo, sha=sha, op="push", ip=self.ip)

    def _git(self, cwd: str | None, *args: str) -> str:
        env = dict(os.environ, GIT_SSL_CAINFO=CFG.ca_file, GIT_TERMINAL_PROMPT="0", HOME=WORKDIR)
        cmd = ["git", "-c", f"user.name={self.who['full_name']}", "-c", f"user.email={self.who['email']}",
               "-c", f"http.proxy={TUNNELS[self.ip].url}", *args]
        return subprocess.run(cmd, cwd=cwd, env=env, check=True, capture_output=True, timeout=120).stdout.decode().strip()

    def _git_push(self, repo: str) -> str:
        """Append a line to CHANGELOG.md and push it. The working copy belongs to this Locust
        user alone (index in the path): two users acting as the same account at the same time
        never share a directory. A non-fast-forward rejection is fetched and retried."""
        key = f"{self.who['username']}:{repo}"
        for attempt in range(1, PUSH_ATTEMPTS + 1):
            clone = self.clones.get(key)
            if clone is None:
                clone = os.path.join(WORKDIR, f"w{self.index}-{self.who['username']}-{repo.replace('/', '_')}")
                shutil.rmtree(clone, ignore_errors=True)
                url = f"https://{self.who['username']}:{self.who['token']}@{CFG.target_host}/{repo}.git"
                self._git(None, "clone", "-q", "--depth", "1", url, clone)
                self.clones[key] = clone
            else:
                self._git(clone, "fetch", "-q", "--depth", "1", "origin", "main")
                self._git(clone, "reset", "-q", "--hard", "FETCH_HEAD")
            with open(os.path.join(clone, "CHANGELOG.md"), "a", encoding="utf-8") as fh:
                fh.write(f"- {time.strftime('%Y-%m-%d %H:%M:%S')} {self.who['username']}: routine update\n")
            self._git(clone, "add", "CHANGELOG.md")
            self._git(clone, "commit", "-q", "-m", "Update changelog")
            try:
                self._git(clone, "push", "-q", "origin", "HEAD:main")
            except subprocess.CalledProcessError as exc:
                if signatures.classify_git_error(_stderr_text(exc)) != "conflict":
                    raise
                if attempt == PUSH_ATTEMPTS:
                    raise PushConflict(repo) from exc
                continue                            # fetch the newer main and try again
            return self._git(clone, "rev-parse", "HEAD")
        raise PushConflict(repo)


def _stderr_text(exc: BaseException) -> str:
    detail = getattr(exc, "stderr", b"") or b""
    return detail.decode("utf-8", "replace") if isinstance(detail, bytes) else str(detail)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--duration", type=int, required=True)
    ap.add_argument("--base-users", type=int, default=int(os.environ.get("LOAD_BASE_USERS", "4")))
    ap.add_argument("--stats-interval", type=int, default=30)
    args = ap.parse_args()

    random.seed(args.seed)
    IP_OF.update(identities.assign_ips([u["username"] for u in USERS], args.seed))
    for ip in sorted(set(IP_OF.values())):
        TUNNELS[ip] = SourceTunnel(ip, CFG.target_ip, CFG.target_host)
    env = Environment(user_classes=[GiteaUser], host=CFG.target_url)
    env.parsed_seed = args.seed
    env.events.request.add_listener(on_request)
    runner = env.create_local_runner()
    plan = stages(args.profile, args.duration, args.seed, args.base_users)
    say("start", profile=args.profile, seed=args.seed, base_users=args.base_users,
        stages=[{"at": at, "users": n, "label": label} for at, n, label in plan],
        accounts={name: ip for name, ip in sorted(IP_OF.items())}, ip_groups=sorted(set(IP_OF.values())))

    started = time.time()
    previous = {"requests": 0, "failures": 0}

    def report() -> None:
        total = env.stats.total
        window_req = total.num_requests - previous["requests"]
        window_fail = total.num_failures - previous["failures"]
        previous.update(requests=total.num_requests, failures=total.num_failures)
        say("stats", users=runner.user_count, requests=window_req, failures=window_fail,
            rps=round(window_req / args.stats_interval, 2),
            p50_ms=int(total.get_current_response_time_percentile(0.5) or 0),
            p95_ms=int(total.get_current_response_time_percentile(0.95) or 0),
            total_requests=total.num_requests, total_failures=total.num_failures,
            by_ip=IP_STATS.take_window())

    index = 0
    next_stats = args.stats_interval
    parent = os.getppid()
    gevent.signal_handler(signal.SIGTERM, lambda: STOPPING.append(True))
    try:
        while not STOPPING:
            if os.getppid() != parent:          # the orchestrator died: never load the target on our own
                break
            elapsed = time.time() - started
            if elapsed >= args.duration:
                break
            if index < len(plan) and elapsed >= plan[index][0]:
                _, users, label = plan[index]
                runner.start(users, spawn_rate=max(1, users // 2))
                say("stage", users=users, label=label, at=int(elapsed))
                index += 1
            if elapsed >= next_stats:
                report()
                next_stats += args.stats_interval
            gevent.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        report()
        runner.quit()
        total = env.stats.total
        say("stop", total_requests=total.num_requests, total_failures=total.num_failures,
            by_name={name: {"requests": s.num_requests, "failures": s.num_failures,
                            "median_ms": int(s.median_response_time or 0)}
                     for (name, _method), s in env.stats.entries.items()},
            by_ip=IpStats.dump(IP_STATS.total))
        shutil.rmtree(WORKDIR, ignore_errors=True)


if __name__ == "__main__":
    main()
