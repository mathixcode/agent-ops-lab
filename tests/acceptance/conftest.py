"""Shared helpers for the acceptance checks (the spec's acceptance criteria as tests).

These run on the host with the project virtualenv and drive the lab through Docker:
`role_py` executes Python inside a running role container, `probe` starts a throw-away
container on one segment (used to stand in for "something on that segment").
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "contracts"))

import labctl  # noqa: E402
from labcontracts import canary, network  # noqa: E402

PROJECT = "agentopslab"
PROBE_IMAGE = "agentopslab/gateway"      # has python + iproute2; any lab image would do
GATEWAY_LEG = {"target": network.ADDR["gateway_target"], "defender": network.ADDR["gateway_defender"],
               "observer": network.ADDR["gateway_observer"]}

PREAMBLE = r'''
import json, os, socket, ssl, subprocess, sys, time, urllib.error, urllib.request
GW = {gw!r}
PROXY = "http://%s:3128" % GW
if {set_route!r}:
    subprocess.run(["ip", "route", "replace", "default", "via", GW], check=True)
open("/tmp/lab-ca.crt", "w").write({ca!r})

def tcp_open(host, port, timeout=4):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False

def fetch(url, data=None, headers=None, method=None, proxy=True, timeout=30):
    """-> (status, body bytes) ; status None on connection failure"""
    ctx = ssl.create_default_context(cafile="/tmp/lab-ca.crt")
    handlers = [urllib.request.HTTPSHandler(context=ctx),
                urllib.request.ProxyHandler({{"http": PROXY, "https": PROXY}} if proxy else {{}})]
    req = urllib.request.Request(url, data=data, headers=headers or {{}}, method=method)
    try:
        with urllib.request.build_opener(*handlers).open(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception as exc:
        return None, repr(exc).encode()

def out(obj):
    print("RESULT " + json.dumps(obj))
'''


def docker(*args: str, input: str | None = None, timeout: float = 180) -> subprocess.CompletedProcess:
    return subprocess.run([*labctl.docker_prefix(), *args], input=input, capture_output=True, text=True,
                          cwd=ROOT, env=labctl.docker_env(), timeout=timeout)


def compose(*args: str, input: str | None = None, timeout: float = 180) -> subprocess.CompletedProcess:
    return subprocess.run(labctl.compose_cmd(*args), input=input, capture_output=True, text=True,
                          cwd=ROOT, env=labctl.docker_env(), timeout=timeout)


def lab_env() -> dict[str, str]:
    return labctl.read_lab_env()


def ca_pem() -> str:
    return (ROOT / ".lab/observer/ca.crt").read_text()


def registry() -> list[canary.Canary]:
    return canary.load_registry((ROOT / ".lab/observer/canary_registry.json").read_text())


def result_of(proc: subprocess.CompletedProcess):
    lines = [l for l in proc.stdout.splitlines() if l.startswith("RESULT ")]
    assert lines, f"no RESULT from probe (rc={proc.returncode})\nstdout: {proc.stdout[-2000:]}\nstderr: {proc.stderr[-2000:]}"
    return json.loads(lines[-1][7:])


def running(service: str) -> bool:
    return service in compose("ps", "--services", "--status", "running").stdout.split()


def probe(segment: str, code: str, ip: str, env: dict[str, str] | None = None, timeout: float = 120,
          image: str = PROBE_IMAGE, python: str = "python"):
    """Run `code` in a throw-away container attached to one segment, routed via the gateway."""
    script = PREAMBLE.format(gw=GATEWAY_LEG[segment], ca=ca_pem(), set_route=True) + code
    args = ["run", "--rm", "-i", "--network", f"{PROJECT}_{segment}_seg", "--ip", ip,
            "--cap-add", "NET_ADMIN", "--entrypoint", python]
    for key, value in (env or {}).items():
        args += ["-e", f"{key}={value}"]
    return result_of(docker(*args, image, "-", input=script, timeout=timeout))


ROLE_USER = {"observer": "observer", "defender": "agent"}


def role_py(service: str, code: str, timeout: float = 180):
    """Run `code` inside a running role container: as that role's unprivileged user, from its
    network position, with its own secrets and environment."""
    script = PREAMBLE.format(gw=GATEWAY_LEG[service], ca=ca_pem(), set_route=False) + code
    return result_of(compose("exec", "-T", "-u", ROLE_USER[service], service, "python", "-",
                             input=script, timeout=timeout))


def secret(role: str, name: str) -> str:
    """A lab credential, read from the host's .lab/ by the test (acting as the lab operator)."""
    return (ROOT / ".lab" / role / name).read_text()


HV_IMAGE = "agentopslab/target-hypervisor"      # has python3 and an ssh client

SSH_HELPER = r'''
import base64
def ssh(user, key_b64, command, timeout=90):
    """-> [exit status, stdout, stderr] ; 255 means the connection or login was refused"""
    with open("/tmp/probe_key", "w") as fh:
        fh.write(base64.b64decode(key_b64).decode())
    os.chmod("/tmp/probe_key", 0o600)
    with open("/tmp/probe_known_hosts", "w") as fh:
        fh.write({known_hosts!r})
    res = subprocess.run(["ssh", "-i", "/tmp/probe_key", "-o", "UserKnownHostsFile=/tmp/probe_known_hosts",
                          "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                          "-o", "IdentitiesOnly=yes", "%s@{target}" % user, command],
                         capture_output=True, text=True, timeout=timeout)
    return [res.returncode, res.stdout, res.stderr[-400:]]
'''


def ssh_from(segment: str, ip: str, user: str, key_role: str, key_name: str, command: str):
    """Try an SSH login to the target from a host on `segment`, with a given account and key."""
    import base64
    helper = SSH_HELPER.format(known_hosts=secret("observer", "known_hosts"), target=network.ADDR["target"])
    key_b64 = base64.b64encode(secret(key_role, key_name).encode()).decode()
    return probe(segment, helper + f"out(ssh({user!r}, {key_b64!r}, {command!r}))", ip, image=HV_IMAGE,
                 python="python3")


OBSERVER_SETUP = r'''
from observer.config import Config
from observer.clients import Hypervisor, TargetSSH
cfg = Config(); hv = Hypervisor(cfg); target = TargetSSH(cfg)
def guest(script, timeout=90):
    res = hv.guest_sh(script, timeout=timeout)
    return [res["exitcode"], res["stdout"], res["stderr"][-400:]]
'''


def observer_do(code: str, timeout: float = 300):
    """Run code as the observer with its clients ready: cfg, hv (hypervisor), target (read-only SSH)."""
    return role_py("observer", OBSERVER_SETUP + code, timeout=timeout)


def observer_py(code: str, timeout: float = 180):
    """As the observer: inside the observer container if it is up, else a stand-in at its address
    (lets the gateway be checked on its own, before the rest of the lab exists)."""
    if running("observer"):
        return role_py("observer", code, timeout)
    env = lab_env()
    return probe("observer", code, network.ADDR["observer"], timeout=timeout,
                 env={"LAB_GATEWAY_TOKEN": env["LAB_GATEWAY_TOKEN"], "LAB_HV_TOKEN": env["LAB_HV_TOKEN"],
                      "GATEWAY_URL": f"http://{network.ADDR['gateway_observer']}:{network.PORTS['gateway_control']}"})


GATEWAY_CALL = r'''
def gw(method, path, body=None):
    req = urllib.request.Request(os.environ["GATEWAY_URL"] + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + os.environ["LAB_GATEWAY_TOKEN"]})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read(), dict(resp.headers)
'''


def gateway_offset() -> int:
    return observer_py(GATEWAY_CALL + 'out(json.loads(gw("GET", "/offset")[0])["end"])')


def gateway_events(offset: int) -> list[dict]:
    raw = observer_py(GATEWAY_CALL + f'out(gw("GET", "/events?offset={offset}")[0].decode())')
    return [json.loads(line) for line in raw.splitlines() if line]


def wait_for_gateway_events(offset: int, predicate, timeout: float = 30) -> list[dict]:
    """Poll the gateway log until `predicate(events)` is truthy; return all events since offset."""
    deadline = time.time() + timeout
    while True:
        events = gateway_events(offset)
        if predicate(events) or time.time() > deadline:
            return events
        time.sleep(3)


@pytest.fixture(scope="session", autouse=True)
def lab_is_bootstrapped():
    if not (ROOT / ".lab/lab.env").exists():
        pytest.exit("run `labctl.py bootstrap` and start the lab before the acceptance checks")


# --------------------------------------------------------------------------- a finished run to examine

def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@pytest.fixture(scope="session")
def smoke_run():
    """A completed scripted dummy run (spec C.6), scored and copied to runs/<run_id>/.

    Set LAB_ACCEPT_RUN_ID to examine an existing run instead of executing a new one
    (a new one takes the smoke manifest's duration plus boot and teardown).
    """
    import os
    run_id = os.environ.get("LAB_ACCEPT_RUN_ID")
    if not run_id:
        run_id = "smoke-" + time.strftime("%Y%m%d-%H%M%S")
        text = (ROOT / "manifests/smoke.yaml").read_text(encoding="utf-8").replace("run_id: smoke-001", f"run_id: {run_id}")
        (ROOT / "runs").mkdir(exist_ok=True)
        manifest = ROOT / "runs" / f"{run_id}.yaml"
        manifest.write_text(text, encoding="utf-8", newline="\n")
        done = subprocess.run([sys.executable, "labctl.py", "run", f"runs/{run_id}.yaml"], cwd=ROOT,
                              env=labctl.docker_env(), capture_output=True, text=True, timeout=3600)
        assert done.returncode == 0, f"run failed:\n{done.stdout[-3000:]}\n{done.stderr[-3000:]}"
    scored = subprocess.run([sys.executable, "labctl.py", "score", run_id], cwd=ROOT, env=labctl.docker_env(),
                            capture_output=True, text=True, timeout=600)
    assert scored.returncode == 0, scored.stdout[-2000:] + scored.stderr[-2000:]
    out = ROOT / "runs" / run_id
    from labcontracts import manifest as mf
    report = json.loads((out / "report/metrics.json").read_text(encoding="utf-8"))
    return {"run_id": run_id, "dir": out, "metrics": report["metrics"], "run": report["run"],
            "counts": report["event_counts"], "manifest": mf.RunManifest(**{
                **report["run"]["manifest"],
                "event_schedule": tuple(mf.ScheduledEvent(**e) for e in report["run"]["manifest"]["event_schedule"])}),
            "agent": _jsonl(out / "events/agent_view.jsonl"), "truth": _jsonl(out / "events/ground_truth.jsonl")}


def defender_driver() -> str:
    return observer_do('''
from observer.clients import DefenderAPI
out(DefenderAPI(cfg).status().get("driver"))''')


def wait_for_target(timeout: int = 600) -> None:
    """Block until the target VM answers on HTTPS (it reboots whenever the lab is restarted)."""
    ok = observer_do(f'''
import requests
hv.wait_guest({timeout})
s = requests.Session(); s.trust_env = False; s.verify = cfg.ca_file
deadline = time.time() + {timeout}
while time.time() < deadline:
    try:
        if s.get(cfg.target_url + "/api/healthz", timeout=10).status_code == 200:
            out(True); break
    except requests.RequestException:
        pass
    time.sleep(5)
else:
    out(False)''', timeout=2 * timeout + 60)
    assert ok, "target did not become healthy"
