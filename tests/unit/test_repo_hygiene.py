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
    ast.parse(mod.RECENT_TEXT_SCRIPT)


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
    for role in network.SEGMENTS:
        assert ip("gateway", f"{role}_seg") == network.ADDR[f"gateway_{role}"]


def test_only_observer_and_gateway_touch_the_observer_segment():
    attached = {name for name, svc in COMPOSE["services"].items() if "observer_seg" in (svc.get("networks") or {})}
    assert attached == {"observer", "gateway"}


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
    holders = {"ANTHROPIC_API_KEY": {"defender"},
               "LAB_HV_TOKEN": {"observer", "target-hv"},
               "LAB_GATEWAY_TOKEN": {"observer", "gateway"},
               "LAB_DEFENDER_TOKEN": {"observer", "defender"}}
    for var, allowed in holders.items():
        assert {n for n, keys in env.items() if var in keys} == allowed, var
