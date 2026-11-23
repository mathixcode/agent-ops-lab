"""Cheap whole-repo checks: everything compiles, the compose file agrees with the network
contract, and the access boundaries of spec 1.2 hold in what each role gets mounted."""
import ast
import re
import subprocess
from pathlib import Path

import yaml

from labcontracts import network

ROOT = Path(__file__).resolve().parents[2]
SKIP = {".venv", ".git", ".lab", "runs", "node_modules"}
COMPOSE = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
ROLE_SECRETS = {"defender": "./.lab/defender", "observer": "./.lab/observer", "gateway": "./.lab/gateway"}


def python_files():
    for path in ROOT.rglob("*.py"):
        if not SKIP & set(path.relative_to(ROOT).parts):
            yield path


def test_every_python_file_parses():
    files = list(python_files())
    assert len(files) > 10
    for path in files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_scripts_embedded_for_the_guest_parse():
    import importlib.util
    spec = importlib.util.spec_from_file_location("guest_snapshot", ROOT / "observer/observer/guest_snapshot.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ast.parse(mod.GUEST_SCRIPT)
    ast.parse(mod.GUEST_CYCLE_SCRIPT)
    ast.parse(mod.GUEST_API_SCRIPT)
    ast.parse(mod.INTEGRITY_SCRIPT)


def test_shell_scripts_use_lf_line_endings():
    for path in list(ROOT.rglob("*.sh")) + [ROOT / "target/provision/files/audit-lab.rules"]:
        if not SKIP & set(path.relative_to(ROOT).parts):
            assert b"\r\n" not in path.read_bytes(), f"{path} has CRLF line endings"


def test_no_real_credentials_are_tracked():
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    assert not [f for f in tracked if f.startswith(".lab/") or f == ".env"]
    pattern = re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
    for name in tracked:
        path = ROOT / name
        if path.is_file() and path.suffix not in {".png", ".qcow2"}:
            assert not pattern.search(path.read_text(encoding="utf-8", errors="ignore")), name


# ---------------------------------------------------------------- compose vs. network contract

def test_segment_subnets_match_the_contract():
    for role, cidr in network.SEGMENTS.items():
        net = COMPOSE["networks"][f"{role}_seg"]
        assert net["driver"] == "macvlan" and net["internal"] is True
        assert net["ipam"]["config"][0]["subnet"] == cidr


def test_role_addresses_match_the_contract():
    def ip(service, net):
        return COMPOSE["services"][service]["networks"][net]["ipv4_address"]

    assert ip("target-hv", "target_seg") == network.ADDR["hypervisor"]
    assert ip("defender", "defender_seg") == network.ADDR["defender"]
    assert ip("langfuse-web", "defender_seg") == network.ADDR["langfuse"]
    assert ip("observer", "observer_seg") == network.ADDR["observer"]
    assert ip("observer", "users_seg") == network.ADDR["users"]
    for role in network.SEGMENTS:
        assert ip("gateway", f"{role}_seg") == network.ADDR[f"gateway_{role}"]


def test_only_observer_and_gateway_touch_the_observer_segment():
    attached = {name for name, svc in COMPOSE["services"].items() if "observer_seg" in (svc.get("networks") or {})}
    assert attached == {"observer", "gateway"}


def test_only_observer_and_gateway_touch_the_users_segment():
    """The users segment holds the observer's client identities and nothing the target or the
    defender could use: only the observer and the gateway are attached."""
    attached = {name for name, svc in COMPOSE["services"].items() if "users_seg" in (svc.get("networks") or {})}
    assert attached == {"observer", "gateway"}
    entrypoint = (ROOT / "observer/entrypoint.sh").read_text(encoding="utf-8")
    assert "lookup 103" in entrypoint and "IDENTITY_IPS" in entrypoint


def test_only_the_gateway_has_an_internet_leg_at_runtime():
    for name, svc in COMPOSE["services"].items():
        nets = svc.get("networks") or {}
        if "uplink" in nets:
            assert name == "gateway" or "build" in svc.get("profiles", []), name


def test_no_service_publishes_ports_or_mounts_the_docker_socket():
    for name, svc in COMPOSE["services"].items():
        assert "ports" not in svc, f"{name} publishes ports"
        assert not svc.get("privileged"), f"{name} is privileged"
        assert not any("docker.sock" in str(v) for v in svc.get("volumes", [])), name


# ---------------------------------------------------------------- access boundaries (spec 1.2)

def test_each_role_mounts_only_its_own_secrets():
    for name, svc in COMPOSE["services"].items():
        mounts = [str(v).split(":")[0] for v in svc.get("volumes", [])]
        lab_mounts = {m for m in mounts if m.startswith("./.lab")}
        if name in ROLE_SECRETS:
            assert lab_mounts == {ROLE_SECRETS[name]}, name
        elif name == "target-build":
            assert lab_mounts == {"./.lab/build", "./.lab/build-out"}
        else:
            assert not lab_mounts, name


def test_credentials_in_the_environment_follow_the_access_table():
    env = {name: set((svc.get("environment") or {}).keys()) for name, svc in COMPOSE["services"].items()}
    holders = {"ANTHROPIC_API_KEY": {"defender"}, "CLAUDE_CODE_OAUTH_TOKEN": {"defender"},
               "LAB_HV_TOKEN": {"observer", "target-hv"},
               "LAB_GATEWAY_TOKEN": {"observer", "gateway"},
               "LAB_DEFENDER_TOKEN": {"observer", "defender"}}
    for var, allowed in holders.items():
        assert {n for n, keys in env.items() if var in keys} == allowed, var


def test_model_credentials_have_no_default_so_an_absent_one_stays_unset():
    """compose.yaml passes the credentials through without a value: Compose then leaves a
    variable that labctl did not pass UNSET in the container (not set to an empty string)."""
    env = COMPOSE["services"]["defender"]["environment"]
    assert env["ANTHROPIC_API_KEY"] is None and env["CLAUDE_CODE_OAUTH_TOKEN"] is None


def test_defender_entrypoint_removes_the_api_key_under_oauth():
    script = (ROOT / "defender/entrypoint.sh").read_text(encoding="utf-8")
    oauth_branch = script.split('elif [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then', 1)[1].split("elif", 1)[0]
    assert "unset ANTHROPIC_API_KEY" in oauth_branch
    assert "exit 64" in script.split('elif [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]', 1)[0]


# ---------------------------------------------------------------- optional overlays

KVM_OVERLAY = yaml.safe_load((ROOT / "compose/kvm.yaml").read_text(encoding="utf-8"))
UI_OVERLAY = yaml.safe_load((ROOT / "compose/langfuse-ui.yaml").read_text(encoding="utf-8"))


def test_kvm_overlay_only_passes_the_kvm_device_to_the_hypervisor():
    assert set(KVM_OVERLAY) == {"services"}
    assert set(KVM_OVERLAY["services"]) == {"target-hv", "target-build"}
    for svc in KVM_OVERLAY["services"].values():
        assert svc == {"devices": ["/dev/kvm:/dev/kvm"]}


def test_langfuse_ui_overlay_binds_loopback_only_and_touches_nothing_else():
    assert set(UI_OVERLAY["services"]) == {"langfuse-web"}
    web = UI_OVERLAY["services"]["langfuse-web"]
    assert web["ports"] and all(str(p).startswith("127.0.0.1:") for p in web["ports"])
    assert not any(str(p).startswith(("0.0.0.0", ":")) or str(p).count(":") < 2 for p in web["ports"])
    assert set(web["networks"]) == {"langfuse_ui"}
    net = UI_OVERLAY["networks"]["langfuse_ui"]
    assert net["driver"] == "bridge"
    assert net["driver_opts"]["com.docker.network.bridge.enable_ip_masquerade"] == "false"
    assert "langfuse_ui" not in COMPOSE["networks"], "the UI network must not exist without the opt-in"
    for name, svc in COMPOSE["services"].items():
        assert "langfuse_ui" not in (svc.get("networks") or {}), name
