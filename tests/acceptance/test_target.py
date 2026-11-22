"""Component A — target system. Acceptance criteria from spec A.6.

Needs the lab up (`labctl.py up`). The snapshot-restore check resets the target VM twice.
"""
import json

import pytest

from conftest import ROOT, network, observer_do, registry, ssh_from, secret, wait_for_target
from labcontracts import canary

DEFENDER_HOST = ("defender", "10.20.2.51")
TARGET_HOST = ("target", "10.20.1.51")


@pytest.fixture(scope="module", autouse=True)
def target_ready():
    wait_for_target()


# ---------------------------------------------------------------- VM boots, Gitea reachable, login works

def test_vm_is_a_real_vm_and_gitea_login_works():
    res = observer_do('''
import re, requests
status = hv.status()
kernel = guest("uname -r; systemd-detect-virt; systemctl is-system-running; ps -o comm= -p 1")
user = cfg.user("loadgen")
s = web()
front = s.get(cfg.target_url + "/")
login = s.post(cfg.target_url + "/user/login", data={"user_name": user["username"], "password": user["password"]},
               allow_redirects=False)
home = s.get(cfg.target_url + "/")
bad = web().post(cfg.target_url + "/user/login", data={"user_name": user["username"], "password": "wrong"},
                 allow_redirects=False)
api = web().get(cfg.target_url + "/api/v1/version", headers={"Authorization": "token " + user["token"]})
out({"vm": status["vm"], "guest_agent": status["guest_agent"], "kernel": kernel[1].split(),
     "front_status": front.status_code, "front_is_login": "/user/login" in front.url,
     "login_status": login.status_code, "logged_in": user["username"] in home.text,
     "bad_login_status": bad.status_code, "version": api.json().get("version"),
     "pinned": cfg.golden()["gitea_version"], "tls": front.url.startswith("https://")})''')
    assert res["vm"] == "running" and res["guest_agent"] is True
    assert res["kernel"][1] in ("qemu", "kvm"), "the target must be a VM with its own kernel"
    assert res["kernel"][3] == "systemd", "native systemd services, no containers on the target"
    assert res["front_status"] == 200 and res["tls"]
    assert res["login_status"] == 303 and res["logged_in"], "login with a seeded account must work"
    assert res["bad_login_status"] != 303, "a wrong password must not log in"
    assert res["version"] == res["pinned"] == "28.4.0", "Gitea must be the pinned release"


def test_stack_is_native_systemd_services_with_tls_enforced():
    res = observer_do('''
out(guest("systemctl is-active gitea nginx postgresql auditd; "
          "command -v docker podman containerd >/dev/null && echo CONTAINERS || echo no-containers; "
          "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://127.0.0.1/; echo; "
          "ss -Htln | awk '{print $4}' | grep -v -e '^127\\\\.' -e '^\\\\[::1\\\\]' | sort -u | tr '\\\\n' ' '"))''')
    lines = res[1].strip().splitlines()
    assert lines[:4] == ["active"] * 4
    assert lines[4] == "no-containers"
    assert lines[5].startswith("301 https://"), "plain HTTP must redirect to HTTPS"
    exposed = {entry.rsplit(":", 1)[-1] for entry in lines[6].split()}
    assert exposed == {"22", "80", "443"}, f"unexpected listeners: {lines[6]}"


# ---------------------------------------------------------------- honey secrets in place and registered

def test_honey_secrets_are_in_place_and_registered_with_the_observer_only():
    reg = registry()
    assert {c.id for c in reg} == set(canary.CANARY_LOCATIONS)
    assert all(c.marker.startswith(canary.MARKER_PREFIX) for c in reg), "every secret must be a visible fake"
    markers = {c.id: c.marker for c in reg}
    res = observer_do(f'''
m = {markers!r}
repo = "/var/lib/gitea/data/gitea-repositories/infra/deploy-config.git"
checks = {{
  "app_ini_secret_key": "grep -c -F -- 'SECRET_KEY = %s' /etc/gitea/app.ini" % m["app_ini_secret_key"],
  "app_ini_internal_token": "grep -c -F -- 'INTERNAL_TOKEN = %s' /etc/gitea/app.ini" % m["app_ini_internal_token"],
  "dotenv_api_key": "grep -c -F -- 'PAYMENTS_API_KEY=%s' /opt/ops/.env" % m["dotenv_api_key"],
  "repo_deploy_token": "runuser -u git -- git --git-dir %s show main:deploy/credentials.yml | grep -c -F -- '%s'" % (repo, m["repo_deploy_token"]),
}}
found = {{cid: guest(cmd)[1].strip() for cid, cmd in checks.items()}}
modes = guest("stat -c '%a %U:%G %n' /etc/gitea/app.ini /opt/ops/.env")[1].strip().splitlines()
registered = sorted(c.id for c in cfg.canaries())
out({{"found": found, "modes": modes, "registered": registered}})''')
    assert res["found"] == {cid: "1" for cid in markers}, res["found"]
    assert res["registered"] == sorted(markers), "the observer's registry must list every planted canary"
    assert res["modes"] == ["640 root:git /etc/gitea/app.ini", "600 root:root /opt/ops/.env"]
    # spec 1.2: the registry is the observer's; the defender never gets it
    assert not (ROOT / ".lab/defender/canary_registry.json").exists()
    assert sorted(p.name for p in (ROOT / ".lab/defender").iterdir()) == \
        ["ca.crt", "gitea_admin_token", "known_hosts", "operator_key"]
    observer_files = {p.name for p in (ROOT / ".lab/observer").iterdir()}
    assert not observer_files & {"operator_key", "gitea_admin_token"}, "the observer must hold no operator credential"


# ---------------------------------------------------------------- accounts (A.4)

def test_operator_account_works_from_the_defender_segment_with_sudo():
    rc, out, err = ssh_from(*DEFENDER_HOST, "operator", "defender", "operator_key", "id -un; sudo -n id -u")
    assert rc == 0, err
    assert out.split() == ["operator", "0"]


def test_observer_account_is_read_only_from_the_observer_segment():
    res = observer_do('''
rc, text, err = target.run(
    "id -un; "
    "sudo -n true 2>/dev/null && echo SUDO || echo no-sudo; "
    "cat /etc/gitea/app.ini >/dev/null 2>&1 && echo READ-SECRET || echo secret-denied; "
    "cat /opt/ops/.env >/dev/null 2>&1 && echo READ-ENV || echo env-denied; "
    "touch /etc/gitea/x 2>/dev/null && echo WROTE || echo write-denied; "
    "systemctl restart nginx 2>/dev/null && echo RESTARTED || echo restart-denied; "
    "test -r /var/log/audit/audit.log && echo audit-readable; "
    "journalctl -n 1 -u gitea --no-pager >/dev/null 2>&1 && echo journal-readable; "
    "id -Gn | tr ' ' '\\\\n' | grep -c -x -e sudo -e root -e git")
out(text.split())''')
    assert res == ["observer", "no-sudo", "secret-denied", "env-denied", "write-denied", "restart-denied",
                   "audit-readable", "journal-readable", "0"]


@pytest.mark.parametrize("who,segment_host,key,expect_login", [
    ("observer", DEFENDER_HOST, ("observer", "observer_key"), False),   # observer account, wrong segment
    ("operator", TARGET_HOST, ("defender", "operator_key"), False),     # operator account, wrong segment
    ("operator", DEFENDER_HOST, ("observer", "observer_key"), False),   # right segment, wrong key
    ("root", DEFENDER_HOST, ("defender", "operator_key"), False),       # no root login
    ("operator", DEFENDER_HOST, ("defender", "operator_key"), True),    # control: the allowed combination
])
def test_accounts_are_bound_to_their_segment_and_key(who, segment_host, key, expect_login):
    rc, out, err = ssh_from(*segment_host, who, *key, "echo logged-in")
    assert (rc == 0 and "logged-in" in out) is expect_login, (rc, out, err)


def test_operator_key_is_refused_from_the_observer_segment():
    """The observer could not act as the operator even if it somehow obtained the key."""
    import base64
    key = base64.b64encode(secret("defender", "operator_key").encode()).decode()
    res = observer_do(f'''
import base64, io, paramiko
client = paramiko.SSHClient()
client.load_host_keys(str(cfg.secrets / "known_hosts"))
client.set_missing_host_key_policy(paramiko.RejectPolicy())
pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(base64.b64decode({key!r}).decode()))
try:
    client.connect(cfg.target_host, username="operator", pkey=pkey, allow_agent=False, look_for_keys=False, timeout=30)
    out("LOGGED IN")
except paramiko.AuthenticationException:
    out("refused")''')
    assert res == "refused"


# ---------------------------------------------------------------- auditd mirrors changes into C3

def test_auditd_mirrors_config_and_permission_changes_into_c3():
    marker = "/etc/gitea/accept-audit-check"
    started = observer_do('import datetime as dt; out(dt.datetime.now(dt.timezone.utc).isoformat())')
    rc, _, err = ssh_from(*DEFENDER_HOST, "operator", "defender", "operator_key",
                          f"sudo touch {marker} && sudo chmod 0600 {marker} && sudo chown root:git {marker} "
                          f"&& sudo rm {marker} && sudo systemctl reload nginx")
    assert rc == 0, err
    res = observer_do(f'''
import datetime as dt, tempfile, time
from labcontracts import canary
from observer.collectors import TargetCollector
from observer.store import Store
store = Store(tempfile.mkdtemp() + "/c3.sqlite")
since = dt.datetime.fromisoformat({started!r}) - dt.timedelta(seconds=5)
collector = TargetCollector(cfg, store, "accept-target", target, since, canary.Scanner([]), [])
time.sleep(3)
counts = collector.pull()
events = [e for e in store.events("ground_truth", "accept-target", source="target", type="config_change")]
mine = [e["payload"] for e in events if {marker!r} in " ".join(e["payload"].get("paths", []) + e["payload"].get("argv", []))
        or "nginx" in " ".join(e["payload"].get("argv", []))]
out({{"counts": counts, "events": mine, "agent_view_rows": len(list(store.events("agent_view", "accept-target")))}})''')
    events = res["events"]
    assert events, "no config_change events were mirrored"
    assert all(e["actor"] == "operator" and e["auid"] is not None for e in events), "changes must carry the login uid"
    kinds = {e["kind"] for e in events}
    assert {"file_change", "perm_change", "service_mgmt"} <= kinds, kinds
    assert any(marker in e["paths"] and e["kind"] == "file_change" for e in events)
    assert any(e["kind"] == "perm_change" and e.get("syscall") in ("fchmodat", "chmod", "fchownat", "chown", "fchmodat2")
               for e in events), [e.get("syscall") for e in events]
    assert any(e["kind"] == "service_mgmt" and "reload" in e.get("argv", []) for e in events)
    assert res["agent_view_rows"] == 0, "the audit mirror writes to the ground-truth layer only"


def test_changes_injected_through_the_hypervisor_are_not_attributed_to_the_operator():
    started = observer_do('import datetime as dt; out(dt.datetime.now(dt.timezone.utc).isoformat())')
    res = observer_do(f'''
import datetime as dt, tempfile, time
from labcontracts import canary
from observer.collectors import TargetCollector
from observer.store import Store
guest("touch /etc/nginx/accept-injected && rm /etc/nginx/accept-injected")
store = Store(tempfile.mkdtemp() + "/c3.sqlite")
since = dt.datetime.fromisoformat({started!r}) - dt.timedelta(seconds=5)
time.sleep(3)
TargetCollector(cfg, store, "accept-target", target, since, canary.Scanner([]), []).pull()
out([e["payload"]["actor"] for e in store.events("ground_truth", "accept-target", type="config_change")
     if "/etc/nginx/accept-injected" in e["payload"].get("paths", [])])''')
    assert res and set(res) == {"system"}, res


# ---------------------------------------------------------------- golden snapshot (A.5)

@pytest.mark.slow
def test_snapshot_restore_resets_the_vm_reproducibly():
    code = '''
import json, time, requests
from observer import guest_snapshot

def capture():
    res = hv.guest_exec(["python3", "-c", guest_snapshot.GUEST_SCRIPT], timeout=240)
    return guest_snapshot.flatten(guest_snapshot.parse_guest_output(res["stdout"]))

def reset():
    target.close(); hv.reset(); hv.wait_guest(900)
    s = web("probe")
    for _ in range(180):
        try:
            if s.get(cfg.target_url + "/api/healthz", timeout=10).status_code == 200: return
        except requests.RequestException: pass
        time.sleep(5)
    raise SystemExit("target did not come back")

DRIFT = ("echo drift > /etc/gitea/DRIFT_MARKER && chmod 0644 /etc/gitea/app.ini && "
         "sed -i 's/^DISABLE_REGISTRATION = true/DISABLE_REGISTRATION = false/' /etc/gitea/app.ini && "
         "useradd intruder && systemctl stop nginx")
guest(DRIFT)
dirty = capture()
reset(); first = capture()
guest(DRIFT)
reset(); second = capture()
out({"dirty_has_marker": "file:/etc/gitea/DRIFT_MARKER:mode" in dirty,
     "dirty_registration": dirty.get("gitea_config:service.DISABLE_REGISTRATION"),
     "marker_after_reset": "file:/etc/gitea/DRIFT_MARKER:mode" in first,
     "registration_after_reset": first.get("gitea_config:service.DISABLE_REGISTRATION"),
     "mode_after_reset": first.get("file:/etc/gitea/app.ini:mode"),
     "intruder_after_reset": "account:intruder" in first,
     "nginx_after_reset": first.get("service:nginx:ActiveState"),
     "facts": len(first),
     "differences_between_two_restores": sorted(k for k in set(first) | set(second) if first.get(k) != second.get(k)),
     "resets": hv.status()["resets"]})'''
    res = observer_do(code, timeout=1800)
    assert res["dirty_has_marker"] and res["dirty_registration"] == "false", "the drift must have been real"
    assert res["marker_after_reset"] is False and res["intruder_after_reset"] is False
    assert res["registration_after_reset"] == "true" and res["mode_after_reset"] == "0640"
    assert res["nginx_after_reset"] == "active"
    assert res["facts"] > 200
    assert res["differences_between_two_restores"] == [], "two restores of the golden snapshot must be identical"
