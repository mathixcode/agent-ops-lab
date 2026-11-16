"""C1 load generator: simulated users driving the target's Gitea on 443 (browse, post, push).

Runs as its own process (Locust is gevent-based) and prints one JSON object per line on
stdout; the orchestrator wraps each line into a monitor/load_event. The seed fixes the load
pattern, so a run is reproducible.

    python -m observer.loadgen.runner --seed 42 --profile steady_with_peaks --duration 21600
"""
from __future__ import annotations

from gevent import monkey

monkey.patch_all()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import random  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402

import gevent  # noqa: E402
from locust import HttpUser, between, task  # noqa: E402
from locust.env import Environment  # noqa: E402

from observer.config import Config  # noqa: E402
from observer.loadgen.profile import stages  # noqa: E402

CFG = Config()
USERS = [u for u in CFG.seed_users() if u["role"] == "loadgen"]
REPOS = CFG.golden()["seed"]["load_repos"]
WORKDIR = tempfile.mkdtemp(prefix="loadgen-")
_next_user = iter(range(10**9))


def say(kind: str, **fields) -> None:
    sys.stdout.write(json.dumps({"kind": kind, **fields}) + "\n")
    sys.stdout.flush()


class GiteaUser(HttpUser):
    wait_time = between(2, 7)

    def on_start(self) -> None:
        self.who = USERS[next(_next_user) % len(USERS)]
        self.client.verify = CFG.ca_file
        self.client.trust_env = False
        self.client.headers["Authorization"] = f"token {self.who['token']}"
        self.rng = random.Random(f"{self.environment.parsed_seed}-{self.who['username']}")
        self.clones: dict[str, str] = {}

    def repo(self) -> str:
        return self.rng.choice(REPOS)

    # ---- browse -------------------------------------------------------------------------------
    @task(6)
    def browse(self) -> None:
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
        repo = self.repo()
        with self.client.get(f"/api/v1/repos/{repo}/issues?state=open&limit=10", name="browse issues",
                             timeout=30, catch_response=True) as listing:
            issues = listing.json() if listing.status_code == 200 else []
        if issues and self.rng.random() < 0.6:
            number = self.rng.choice(issues)["number"]
            resp = self.client.post(f"/api/v1/repos/{repo}/issues/{number}/comments", name="post comment",
                                    json={"body": f"Update from {self.who['full_name']}: still relevant."},
                                    timeout=30)
            if resp.status_code == 201:
                say("write_ack", repo=repo, issue=number, op="comment")
        else:
            resp = self.client.post(f"/api/v1/repos/{repo}/issues", name="post issue", timeout=30, json={
                "title": f"Follow-up {self.rng.getrandbits(24):06x}", "body": "Noticed while reviewing; details to follow."})
            if resp.status_code == 201:
                say("write_ack", repo=repo, issue=resp.json()["number"], op="issue")

    # ---- push ---------------------------------------------------------------------------------
    @task(1)
    def push(self) -> None:
        repo = self.repo()
        started = time.time()
        error, sha = None, None
        try:
            sha = self._git_push(repo)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            detail = getattr(exc, "stderr", b"") or b""
            error = RuntimeError((detail.decode("utf-8", "replace").strip().splitlines() or [type(exc).__name__])[-1][:160])
            shutil.rmtree(self.clones.pop(repo, ""), ignore_errors=True)       # start from a fresh clone next time
        self.environment.events.request.fire(
            request_type="GIT", name="git push", response_time=(time.time() - started) * 1000,
            response_length=0, exception=error, context={})
        if sha:
            say("write_ack", repo=repo, sha=sha, op="push")

    def _git(self, cwd: str | None, *args: str) -> str:
        env = dict(os.environ, GIT_SSL_CAINFO=CFG.ca_file, GIT_TERMINAL_PROMPT="0", HOME=WORKDIR)
        cmd = ["git", "-c", f"user.name={self.who['full_name']}", "-c", f"user.email={self.who['email']}", *args]
        return subprocess.run(cmd, cwd=cwd, env=env, check=True, capture_output=True, timeout=120).stdout.decode().strip()

    def _git_push(self, repo: str) -> str:
        clone = self.clones.get(repo)
        if clone is None:
            clone = os.path.join(WORKDIR, f"{self.who['username']}-{repo.replace('/', '_')}")
            shutil.rmtree(clone, ignore_errors=True)
            url = f"https://{self.who['username']}:{self.who['token']}@{CFG.target_host}/{repo}.git"
            self._git(None, "clone", "-q", "--depth", "1", url, clone)
            self.clones[repo] = clone
        else:
            self._git(clone, "fetch", "-q", "--depth", "1", "origin", "main")
            self._git(clone, "reset", "-q", "--hard", "FETCH_HEAD")
        with open(os.path.join(clone, "CHANGELOG.md"), "a", encoding="utf-8") as fh:
            fh.write(f"- {time.strftime('%Y-%m-%d %H:%M:%S')} {self.who['username']}: routine update\n")
        self._git(clone, "add", "CHANGELOG.md")
        self._git(clone, "commit", "-q", "-m", "Update changelog")
        self._git(clone, "push", "-q", "origin", "HEAD:main")
        return self._git(clone, "rev-parse", "HEAD")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--duration", type=int, required=True)
    ap.add_argument("--base-users", type=int, default=int(os.environ.get("LOAD_BASE_USERS", "4")))
    ap.add_argument("--stats-interval", type=int, default=30)
    args = ap.parse_args()

    random.seed(args.seed)
    env = Environment(user_classes=[GiteaUser], host=CFG.target_url)
    env.parsed_seed = args.seed
    runner = env.create_local_runner()
    plan = stages(args.profile, args.duration, args.seed, args.base_users)
    say("start", profile=args.profile, seed=args.seed, base_users=args.base_users,
        stages=[{"at": at, "users": n, "label": label} for at, n, label in plan])

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
            total_requests=total.num_requests, total_failures=total.num_failures)

    index = 0
    next_stats = args.stats_interval
    try:
        while True:
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
                     for (name, _method), s in env.stats.entries.items()})
        shutil.rmtree(WORKDIR, ignore_errors=True)


if __name__ == "__main__":
    main()
