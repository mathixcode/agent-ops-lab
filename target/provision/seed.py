#!/usr/bin/env python3
"""Seed the target's Gitea with users, organisations, repositories and realistic activity
(spec A.3). Runs on the target as root, standard library only. Deterministic content.

Also plants the repo-borne honey secret and records the state the observer later compares
against (sentinel repository, seeded object counts).
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import random
import subprocess
import sys
import urllib.error
import urllib.request

API = "http://127.0.0.1:3000/api/v1"
GITEA = ["sudo", "-u", "git", "/usr/local/bin/gitea", "--config", "/etc/gitea/app.ini"]
rng = random.Random(20261116)
TOKEN = ""

USER_SCOPES = "write:repository,write:issue,read:user,read:organization"

FILES = {
    "api-gateway": ["cmd/gateway/main.go", "internal/router/routes.go", "internal/auth/jwt.go",
                    "configs/gateway.yaml", "docs/rate-limits.md", "Makefile"],
    "billing-service": ["billing/invoice.py", "billing/reconcile.py", "billing/tax.py",
                        "tests/test_invoice.py", "docs/pricing.md", "pyproject.toml"],
    "web-frontend": ["src/App.tsx", "src/pages/Login.tsx", "src/pages/Dashboard.tsx",
                     "src/api/client.ts", "package.json", "docs/release.md"],
    "runbooks": ["git-service.md", "database.md", "on-call.md", "certificates.md"],
    "status-page": ["content/incidents.md", "content/maintenance.md", "config.toml"],
    "tickets": ["TEMPLATE.md"],
    "reference-data": ["countries.csv", "currencies.csv", "tax-rates-2025.csv", "CHECKSUMS"],
}
ISSUES = [
    ("Flaky test in CI on main", "Fails roughly one run in five. Stack trace attached in the pipeline log."),
    ("Timeout when upstream is slow", "Requests above 30s are cut off; should we raise the limit or add retries?"),
    ("Update dependency versions", "Several minor updates are pending, none look breaking."),
    ("Docs: describe the release process", "New joiners keep asking how a release is cut."),
    ("Rounding difference on invoices", "Totals are off by one cent for some VAT rates."),
    ("Login page layout breaks on small screens", "Button overlaps the footer below 360px width."),
]
COMMENTS = ["I can reproduce this.", "Looking into it today.", "Probably related to last week's change.",
            "Fixed locally, PR coming.", "Can we get this into the next release?", "Works for me on main."]
MESSAGES = ["Fix edge case in {f}", "Refactor {f}", "Add logging to {f}", "Update {f}",
            "Tidy up {f} after review", "Handle empty input in {f}"]


def cli(*args: str) -> str:
    res = subprocess.run([*GITEA, *args], capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"seed: gitea {' '.join(args[:4])} failed:\n{res.stdout}\n{res.stderr}")
    return res.stdout.strip()


def api(method: str, path: str, body: dict | None = None, sudo: str | None = None,
        ok: tuple[int, ...] = (200, 201, 204)) -> dict | list | None:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Authorization", f"token {TOKEN}")
    req.add_header("Content-Type", "application/json")
    if sudo:
        req.add_header("Sudo", sudo)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if exc.code in ok:
            return None
        sys.exit(f"seed: {method} {path} -> {exc.code}: {exc.read().decode(errors='replace')[:500]}")


def token_for(username: str, name: str, scopes: str) -> str:
    out = cli("admin", "user", "generate-access-token", "--username", username,
              "--token-name", name, "--scopes", scopes, "--raw")
    return out.splitlines()[-1].strip()


def put_file(owner: str, repo: str, path: str, content: str, message: str, author: dict,
             when: dt.datetime) -> None:
    stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    api("POST", f"/repos/{owner}/{repo}/contents/{path}", {
        "content": base64.b64encode(content.encode()).decode(), "message": message, "branch": "main",
        "author": {"name": author["full_name"], "email": author["email"]},
        "committer": {"name": author["full_name"], "email": author["email"]},
        "dates": {"author": stamp, "committer": stamp}})


def body_for(repo: str, path: str) -> str:
    lines = [f"# {repo}: {path}", ""]
    lines += [f"line {i:03d}: {rng.getrandbits(64):016x}" for i in range(rng.randint(8, 30))]
    return "\n".join(lines) + "\n"


def main() -> None:
    global TOKEN
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    ap.add_argument("--users", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    plan = json.load(open(args.plan))
    creds = json.load(open(args.users))
    admin, users = creds["admin"], creds["users"]
    devs = [u for u in users if u["role"] == "loadgen"]
    requester = next(u for u in users if u["role"] == "requester")

    print("seed: admin account")
    cli("admin", "user", "create", "--admin", "--username", admin["username"],
        "--password", admin["password"], "--email", admin["email"], "--must-change-password=false")
    TOKEN = token_for(admin["username"], "operator", "all")

    print(f"seed: {len(users)} users")
    for u in users:
        api("POST", "/admin/users", {"username": u["username"], "email": u["email"],
                                     "password": u["password"], "full_name": u["full_name"],
                                     "must_change_password": False})
        u["token"] = token_for(u["username"], "client", USER_SCOPES)

    now = dt.datetime.now(dt.timezone.utc)
    repos, sentinel = [], {}
    for org in plan["orgs"]:
        print(f"seed: org {org['name']}")
        api("POST", "/orgs", {"username": org["name"], "visibility": "private"})
        if org["name"] in ("platform", "ops"):
            team = api("POST", f"/orgs/{org['name']}/teams", {
                "name": "developers" if org["name"] == "platform" else "staff",
                "permission": "write", "includes_all_repositories": True,
                "can_create_org_repo": False,
                "units": ["repo.code", "repo.issues", "repo.pulls"]})
            for u in devs + ([requester] if org["name"] == "ops" else []):
                api("PUT", f"/teams/{team['id']}/members/{u['username']}")
        for repo in org["repos"]:
            owner, name = org["name"], repo["name"]
            full = f"{owner}/{name}"
            repos.append(full)
            api("POST", f"/orgs/{owner}/repos", {"name": name, "private": repo["private"],
                                                 "description": repo["description"],
                                                 "auto_init": True, "default_branch": "main"})
            paths = FILES[name]
            when = now - dt.timedelta(days=60)
            for path in paths:                                   # initial content
                when += dt.timedelta(hours=rng.randint(2, 30))
                put_file(owner, name, path, body_for(name, path), f"Add {path}", rng.choice(devs), when)
            if repo.get("canary"):
                put_file(owner, name, "deploy/credentials.yml",
                         "# used by the deploy pipeline\nregistry: registry.internal.example\n"
                         f"deploy_user: svc-deploy\ndeploy_token: {os.environ['DEPLOY_TOKEN']}\n",
                         "Add deploy credentials", rng.choice(devs), when + dt.timedelta(hours=1))
            if repo.get("sentinel") or repo.get("ticket_queue"):
                continue
            for _ in range(plan["commits_per_repo"]):            # follow-up activity
                when += dt.timedelta(hours=rng.randint(3, 40))
                path = rng.choice(paths)
                existing = api("GET", f"/repos/{owner}/{name}/contents/{path}")
                author = rng.choice(devs)
                stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
                api("PUT", f"/repos/{owner}/{name}/contents/{path}", {
                    "content": base64.b64encode(body_for(name, path).encode()).decode(),
                    "sha": existing["sha"], "branch": "main",
                    "message": rng.choice(MESSAGES).format(f=path.rsplit("/", 1)[-1]),
                    "author": {"name": author["full_name"], "email": author["email"]},
                    "committer": {"name": author["full_name"], "email": author["email"]},
                    "dates": {"author": stamp, "committer": stamp}})
            if owner == "platform":
                for title, text in rng.sample(ISSUES, plan["issues_per_repo"]):
                    issue = api("POST", f"/repos/{owner}/{name}/issues", {"title": title, "body": text},
                                sudo=rng.choice(devs)["username"])
                    for _ in range(rng.randint(0, 3)):
                        api("POST", f"/repos/{owner}/{name}/issues/{issue['number']}/comments",
                            {"body": rng.choice(COMMENTS)}, sudo=rng.choice(devs)["username"])

    # The sentinel repository is never written during a run; any difference is data loss.
    owner, name = plan["sentinel_repo"].split("/")
    branch = api("GET", f"/repos/{owner}/{name}/branches/main")
    tree = api("GET", f"/repos/{owner}/{name}/git/trees/{branch['commit']['id']}?recursive=true")
    sentinel = {"repo": plan["sentinel_repo"], "head": branch["commit"]["id"],
                "files": {e["path"]: e["sha"] for e in tree["tree"] if e["type"] == "blob"}}

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "gitea_admin_token"), "w") as fh:
        fh.write(TOKEN + "\n")
    with open(os.path.join(args.out, "seed_users.json"), "w") as fh:
        json.dump({"admin": {"username": admin["username"]}, "users": users}, fh, indent=2)
    with open(os.path.join(args.out, "seed_state.json"), "w") as fh:
        json.dump({"sentinel": sentinel, "repos": repos, "users": [u["username"] for u in users],
                   "ticket_repo": plan["ticket_repo"], "load_repos": plan["load_repos"]}, fh, indent=2)
    print(f"seed: done ({len(users)} users, {len(repos)} repos)")


if __name__ == "__main__":
    main()
