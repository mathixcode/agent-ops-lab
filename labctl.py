#!/usr/bin/env python3
"""labctl — host-side control for the Agent Ops Lab pilot (one Docker host).

Run it with the project's virtualenv interpreter:

    .venv/bin/python labctl.py <command>              (Linux, including a remote VM over SSH)
    .venv/Scripts/python.exe labctl.py <command>      (Windows)

Docker is used directly when `docker` is on PATH (the normal case on Linux). Only when it is
not, and `wsl.exe` exists (Windows), is Docker reached through WSL.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LAB = ROOT / ".lab"
sys.path.insert(0, str(ROOT / "contracts"))

from labcontracts import canary, network  # noqa: E402

CREDENTIAL_VARS = ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN")
OVERLAY_KVM = "compose.kvm.yaml"
OVERLAY_LANGFUSE_UI = "compose.langfuse-ui.yaml"
TRUE = ("1", "true", "yes", "on")

# Host sizing for the full stack (target VM + gateway + defender + observer/load + Langfuse with
# ClickHouse/Postgres/Redis/MinIO). README "Host sizing" explains the numbers.
MIN_CPUS, REC_CPUS = 6, 8
MIN_MEM_GIB, REC_MEM_GIB = 16, 32
MIN_DISK_GIB = 60


# --------------------------------------------------------------------------- settings (.env)

def read_dotenv(path: Path | None = None) -> dict[str, str]:
    """KEY=VALUE lines of .env (git-ignored). Quotes around a value are removed."""
    path = path or ROOT / ".env"
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key] = value
    return out


def settings() -> dict[str, str]:
    """.env, overridden by the process environment (the same precedence Compose uses)."""
    merged = read_dotenv()
    merged.update({k: v for k, v in os.environ.items() if k in merged or k.startswith(("LAB_", "DEFENDER_",
                   "TARGET_", "LANGFUSE_UI")) or k in CREDENTIAL_VARS})
    return merged


def defender_auth(env: dict[str, str]) -> str:
    """"api_key", "oauth", "none" or "conflict" (both set) — mirrors defender/runtime.py."""
    key, oauth = bool(env.get("ANTHROPIC_API_KEY")), bool(env.get("CLAUDE_CODE_OAUTH_TOKEN"))
    if key and oauth:
        return "conflict"
    return "oauth" if oauth else "api_key" if key else "none"


# --------------------------------------------------------------------------- docker plumbing

def using_wsl() -> bool:
    return not shutil.which("docker") and bool(shutil.which("wsl.exe"))


def docker_prefix() -> list[str]:
    if shutil.which("docker"):
        return ["docker"]
    if shutil.which("wsl.exe"):
        distro = os.environ.get("LAB_WSL_DISTRO")
        return ["wsl.exe", *(["-d", distro] if distro else []), "--", "docker"]
    sys.exit("labctl: `docker` is not on PATH. On a fresh Debian/Ubuntu host run "
             "`sudo scripts/host-setup.sh` first (installs Docker Engine and the Compose plugin).")


def host_run(script: str, timeout: float = 120) -> subprocess.CompletedProcess:
    """Run a shell script on the Docker host (this machine, or the WSL distro). The script goes
    in on stdin: wsl.exe mangles multi-line command-line arguments."""
    prefix = docker_prefix()
    cmd = ["sh", "-s"] if prefix == ["docker"] else [*prefix[:-1], "sh", "-s"]
    # bytes, not text: on Windows, text-mode stdin would turn every LF into CRLF
    res = subprocess.run(cmd, input=script.encode(), capture_output=True, timeout=timeout)
    return subprocess.CompletedProcess(res.args, res.returncode, res.stdout.decode(errors="replace"),
                                       res.stderr.decode(errors="replace"))


def kvm_disabled() -> bool:
    return settings().get("LAB_KVM", "").lower() in ("0", "false", "no", "off")


def host_has_kvm() -> bool:
    try:
        return host_run("test -c /dev/kvm").returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def docker_env() -> dict[str, str]:
    """Environment for docker/compose: .env values (shell wins) plus the credential rule.

    Exactly one model credential reaches Compose. With CLAUDE_CODE_OAUTH_TOKEN the API key is
    removed, so the defender container has no ANTHROPIC_API_KEY at all and cannot fall back to
    API billing (compose.yaml passes both through without a default, which leaves an absent
    variable unset). If both are set, neither is passed and `up` refuses to start."""
    env = dict(os.environ)
    for key, value in read_dotenv().items():
        env.setdefault(key, value)
    auth = defender_auth(env)
    drop = {"oauth": ["ANTHROPIC_API_KEY"], "api_key": ["CLAUDE_CODE_OAUTH_TOKEN"],
            "none": list(CREDENTIAL_VARS), "conflict": list(CREDENTIAL_VARS)}[auth]
    for var in drop:
        env.pop(var, None)
    if using_wsl():
        # make the lab settings visible to `docker compose` inside WSL
        forward = sorted({*read_dotenv(), *CREDENTIAL_VARS, "LAB_KVM", "LAB_LANGFUSE_UI", "LANGFUSE_UI_PORT"}
                         & {k for k, v in env.items() if v})
        env["WSLENV"] = ":".join(filter(None, [os.environ.get("WSLENV"), *(f"{v}/u" for v in forward)]))
    return env


_KVM: bool | None = None


def compose_files() -> list[str]:
    """compose.yaml plus the overlays that apply on this host."""
    global _KVM
    if _KVM is None:
        _KVM = not kvm_disabled() and host_has_kvm()
    files = ["compose.yaml"]
    if _KVM:
        files.append(OVERLAY_KVM)
    if settings().get("LAB_LANGFUSE_UI", "").lower() in TRUE:
        files.append(OVERLAY_LANGFUSE_UI)
    return files


def compose_cmd(*args: str) -> list[str]:
    files = [x for f in compose_files() for x in ("-f", f)]
    return [*docker_prefix(), "compose", *files, "--env-file", ".lab/lab.env", *args]


def run(cmd: list[str], check: bool = True, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, env=docker_env(), check=check, **kw)


def compose(*args: str, check: bool = True, **kw) -> subprocess.CompletedProcess:
    if not (LAB / "lab.env").exists():
        sys.exit("labctl: .lab/lab.env not found — run `labctl.py bootstrap` first")
    return run(compose_cmd(*args), check=check, **kw)


def read_lab_env() -> dict[str, str]:
    out = {}
    for line in (LAB / "lab.env").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            out[key] = value
    return out


# --------------------------------------------------------------------------- bootstrap

def _write(path: Path, data: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)


def _ssh_keypair(comment: str) -> tuple[bytes, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                           serialization.PublicFormat.OpenSSH).decode()
    return private, f"{public} {comment}\n"


def _pki() -> dict[str, bytes]:
    """Lab CA plus the target's server certificates (current, renewed, expired)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = dt.datetime.now(dt.timezone.utc)
    day = dt.timedelta(days=1)
    pem = serialization.Encoding.PEM

    def key_pem(key) -> bytes:
        return key.private_bytes(pem, serialization.PrivateFormat.TraditionalOpenSSL,
                                 serialization.NoEncryption())

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Agent Ops Lab (FAKE, lab only)"),
                         x509.NameAttribute(NameOID.COMMON_NAME, "Agent Ops Lab CA")])
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - day).not_valid_after(now + 3650 * day)
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                            content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False,
                                            encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
               .sign(ca_key, hashes.SHA256()))

    srv_key = ec.generate_private_key(ec.SECP256R1())
    san = x509.SubjectAlternativeName([x509.DNSName(network.TARGET_HOSTNAME),
                                       x509.IPAddress(ipaddress.ip_address(network.ADDR["target"]))])

    def server_cert(not_before: dt.datetime, not_after: dt.datetime) -> bytes:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, network.TARGET_HOSTNAME)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                .public_key(srv_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(not_before).not_valid_after(not_after)
                .add_extension(san, critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        return cert.public_bytes(pem)

    return {
        "ca.crt": ca_cert.public_bytes(pem),
        "ca.key": key_pem(ca_key),
        "target.key": key_pem(srv_key),
        "target.crt": server_cert(now - day, now + 365 * day),
        "target-renewed.crt": server_cert(now - day, now + 730 * day),
        "target-expired.crt": server_cert(now - 400 * day, now - 2 * day),
    }


def cmd_bootstrap(args: argparse.Namespace) -> None:
    """Generate every lab-internal credential. All of it is fake/lab-only; nothing here is a
    real credential, and the per-role directories mirror the access table in spec 1.2."""
    if LAB.exists() and not args.force:
        sys.exit(".lab/ already exists. The golden image embeds these keys and canaries;\n"
                 "use --force only if you intend to rebuild it afterwards.")
    if LAB.exists():
        shutil.rmtree(LAB)

    pki = _pki()
    operator_key, operator_pub = _ssh_keypair("operator@defender")
    observer_key, observer_pub = _ssh_keypair("observer@observer")
    provision_key, provision_pub = _ssh_keypair("provision@build")
    registry = canary.new_registry()

    plan = json.loads((ROOT / "target/provision/seed_plan.json").read_text(encoding="utf-8"))
    seed_users = {"admin": {**plan["admin"], "password": f"FakePw-{secrets.token_hex(8)}"},
                  "users": [{**u, "email": f"{u['username']}@target.lab",
                             "password": f"FakePw-{secrets.token_hex(8)}"} for u in plan["users"]]}

    # build/ — consumed once by the golden-image build, never mounted into a running role
    _write(LAB / "build/provision_key", provision_key)
    _write(LAB / "build/provision_key.pub", provision_pub)
    _write(LAB / "build/operator.pub", operator_pub)
    _write(LAB / "build/observer.pub", observer_pub)
    for name in ("ca.crt", "target.key", "target.crt", "target-renewed.crt"):
        _write(LAB / "build" / name, pki[name])
    _write(LAB / "build/canaries.json", canary.dump_registry(registry))
    _write(LAB / "build/seed_users.json", json.dumps(seed_users, indent=2))

    # defender/ — operator SSH key (and, after the build, the Gitea admin token)
    _write(LAB / "defender/operator_key", operator_key)
    _write(LAB / "defender/ca.crt", pki["ca.crt"])

    # observer/ — read-only SSH key, canary registry, fault material, simulated-user logins
    _write(LAB / "observer/observer_key", observer_key)
    _write(LAB / "observer/ca.crt", pki["ca.crt"])
    _write(LAB / "observer/canary_registry.json", canary.dump_registry(registry))
    _write(LAB / "observer/target-expired.crt", pki["target-expired.crt"])

    # gateway/ — the CA it intercepts TLS with
    _write(LAB / "gateway/mitmproxy-ca.pem", pki["ca.key"] + pki["ca.crt"])
    _write(LAB / "gateway/ca.crt", pki["ca.crt"])

    env = {
        "LAB_HV_TOKEN": secrets.token_hex(24),
        "LAB_GATEWAY_TOKEN": secrets.token_hex(24),
        "LAB_DEFENDER_TOKEN": secrets.token_hex(24),
        "LAB_CONTEXT_SENTINEL": f"CTX-SENTINEL-{secrets.token_hex(12)}",
        "LANGFUSE_PUBLIC_KEY": f"pk-lf-lab-{secrets.token_hex(12)}",
        "LANGFUSE_SECRET_KEY": f"sk-lf-lab-{secrets.token_hex(16)}",
        "LANGFUSE_SALT": secrets.token_hex(16),
        "LANGFUSE_ENCRYPTION_KEY": secrets.token_hex(32),
        "LANGFUSE_NEXTAUTH_SECRET": secrets.token_hex(24),
        "LANGFUSE_DB_PASSWORD": secrets.token_hex(16),
        "LANGFUSE_CLICKHOUSE_PASSWORD": secrets.token_hex(16),
        "LANGFUSE_REDIS_AUTH": secrets.token_hex(16),
        "LANGFUSE_MINIO_PASSWORD": secrets.token_hex(16),
        "LANGFUSE_INIT_USER_PASSWORD": f"FakePw-{secrets.token_hex(8)}",
    }
    _write(LAB / "lab.env", "# generated by `labctl.py bootstrap` — lab-internal values only\n"
           + "".join(f"{k}={v}\n" for k, v in env.items()))
    print(f"bootstrap: wrote {LAB} ({len(registry)} canaries, {len(seed_users['users'])} seed users)")


def cmd_distribute(_args: argparse.Namespace | None = None) -> None:
    """Hand the golden build's outputs to the roles that may hold them (spec 1.2)."""
    out = LAB / "build-out"
    need = ["gitea_admin_token", "known_hosts", "seed_users.json", "golden.json"]
    missing = [n for n in need if not (out / n).exists()]
    if missing:
        sys.exit(f"distribute: build outputs missing {missing} — run `labctl.py build` first")
    shutil.copy(out / "gitea_admin_token", LAB / "defender/gitea_admin_token")
    shutil.copy(out / "known_hosts", LAB / "defender/known_hosts")
    shutil.copy(out / "known_hosts", LAB / "observer/known_hosts")
    # simulated-user logins and API tokens: observer only. The admin entry is stripped.
    users = json.loads((out / "seed_users.json").read_text(encoding="utf-8"))
    users.pop("admin", None)
    _write(LAB / "observer/seed_users.json", json.dumps(users, indent=2))
    shutil.copy(out / "golden.json", LAB / "observer/golden.json")
    print("distribute: defender <- admin token, known_hosts; observer <- known_hosts, user logins")


# --------------------------------------------------------------------------- lifecycle

HOST_PROBE = r"""
echo "kernel=$(uname -r)"
echo "arch=$(uname -m)"
( . /etc/os-release 2>/dev/null && echo "os=$PRETTY_NAME" ) || echo "os=unknown"
[ -c /dev/net/tun ] && echo tun=present || echo tun=missing
[ -c /dev/kvm ] && echo kvm=present || echo kvm=missing
echo "cpu_virt_flags=$(grep -c -E '(vmx|svm)' /proc/cpuinfo 2>/dev/null || echo 0)"
mod_state() {
    if [ -d "/sys/module/$1" ]; then echo loaded
    elif grep -qs "/$1.ko" "/lib/modules/$(uname -r)/modules.builtin"; then echo built-in
    elif find "/lib/modules/$(uname -r)" -name "$1.ko*" 2>/dev/null | grep -q .; then echo loadable
    else echo unknown; fi
}
echo "mod_nf_tables=$(mod_state nf_tables)"
cfg=$( (zcat /proc/config.gz 2>/dev/null || cat "/boot/config-$(uname -r)" 2>/dev/null) | grep -E '^CONFIG_NF_TABLES=')
echo "cfg_nf_tables=${cfg#CONFIG_NF_TABLES=}"
"""

# Runs inside the hypervisor container: which accelerator the running QEMU was started with.
QEMU_ACCEL = r"""import glob
for f in glob.glob('/proc/[0-9]*/cmdline'):
    try:
        a = open(f, 'rb').read().split(b'\0')
    except OSError:
        continue
    if a and a[0].endswith(b'qemu-system-x86_64') and b'-accel' in a:
        print(a[a.index(b'-accel') + 1].decode().split(',')[0])
        break
else:
    print('no-vm')
"""


# Runs inside the observer: can every traffic identity reach the target's web front end
# (through the gateway, from its own source address)?
IDENTITY_PROBE = r"""import json, socket
from labcontracts import network
out = {}
for name, addr in [("user", a) for a in network.USER_IPS] + list(network.IDENTITY_IPS.items()):
    try:
        socket.create_connection((network.ADDR["target"], 443), timeout=5, source_address=(addr, 0)).close()
        out[addr] = [name, "ok"]
    except OSError as exc:
        out[addr] = [name, type(exc).__name__]
print(json.dumps(out))
"""


def users_segment_verdict(compose_doc: dict) -> tuple[str, str, str]:
    """Static check: compose defines the users segment as the contract says, and only the
    observer and the gateway are attached to it."""
    seg = network.SEGMENTS["users"]
    net = (compose_doc.get("networks") or {}).get("users_seg") or {}
    subnet = ((net.get("ipam") or {}).get("config") or [{}])[0].get("subnet")
    attached = sorted(n for n, svc in (compose_doc.get("services") or {}).items()
                      if "users_seg" in (svc.get("networks") or {}))
    if net.get("driver") != "macvlan" or not net.get("internal") or subnet != seg:
        return "FAIL", "users segment", f"compose.yaml users_seg must be an internal macvlan network {seg} (found {subnet})"
    if attached != ["gateway", "observer"]:
        return "FAIL", "users segment", f"only gateway and observer may join users_seg (found {attached})"
    return "ok", "users segment", (f"{seg}: {len(network.USER_IPS)} user addresses, "
                                   + ", ".join(f"{k} {v}" for k, v in network.IDENTITY_IPS.items()))


def identities_verdict(result: dict[str, list[str]]) -> tuple[str, str, str]:
    bad = {ip: v for ip, v in result.items() if v[1] != "ok"}
    if not result:
        return "WARN", "identities", "could not be checked"
    if bad:
        return "FAIL", "identities", "no route to the web front end from " + ", ".join(
            f"{ip} ({v[0]}: {v[1]})" for ip, v in sorted(bad.items()))
    return "ok", "identities", f"all {len(result)} identity addresses reach the target on 443 through the gateway"


def parse_kv(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def assess_resources(cpus: int, mem_bytes: int, disk_free_bytes: int | None) -> list[tuple[str, str, str]]:
    """Host sizing verdicts for the full stack (see MIN_*/REC_* above)."""
    gib = 1024 ** 3
    mem = mem_bytes / gib
    out = []
    if cpus < MIN_CPUS:
        out.append(("WARN", "cpus", f"{cpus} - below the minimum of {MIN_CPUS}; lower TARGET_VCPUS, expect slow runs"))
    else:
        out.append(("ok" if cpus >= REC_CPUS else "WARN", "cpus",
                    f"{cpus}" + ("" if cpus >= REC_CPUS else f" - works; {REC_CPUS}+ recommended")))
    if mem < MIN_MEM_GIB - 1:      # MemTotal is a little under the nominal size
        out.append(("WARN", "memory", f"{mem:.1f} GiB - below the minimum of {MIN_MEM_GIB} GiB; set "
                                      "TARGET_MEMORY_MB=4096 or less (Langfuse alone needs ~4 GiB)"))
    else:
        out.append(("ok" if mem >= REC_MEM_GIB - 2 else "WARN", "memory",
                    f"{mem:.1f} GiB" + ("" if mem >= REC_MEM_GIB - 2 else
                                         f" - works with TARGET_MEMORY_MB=4096; {REC_MEM_GIB} GiB recommended")))
    if disk_free_bytes is None:
        out.append(("WARN", "disk", "free space of Docker's data directory could not be determined"))
    else:
        free = disk_free_bytes / gib
        out.append(("ok" if free >= MIN_DISK_GIB else "WARN", "disk",
                    f"{free:.0f} GiB free for Docker" + ("" if free >= MIN_DISK_GIB else
                                                         f" - {MIN_DISK_GIB}+ GiB recommended (images, VM disks, traces)")))
    return out


def nft_functional(prefix: list[str], env: dict[str, str]) -> bool | None:
    """Can a container program nftables? Tried with the gateway image if it is built (it ships
    `nft`); None if there is no image to try with yet."""
    image = "agentopslab/gateway"
    if subprocess.run([*prefix, "image", "inspect", image], capture_output=True, env=env).returncode != 0:
        return None
    res = subprocess.run([*prefix, "run", "--rm", "--network", "none", "--cap-add", "NET_ADMIN",
                          "--entrypoint", "nft", image, "list", "tables"], capture_output=True, env=env)
    return res.returncode == 0


def nftables_verdict(module: str, config: str, functional: bool | None) -> tuple[str, str, str]:
    if functional is True:
        return "ok", "nftables", "a container can program nftables (tested with the gateway image)"
    if functional is False:
        return "FAIL", "nftables", ("a container cannot program nftables - the gateway, hypervisor and observer "
                                    "firewalls need it (`sudo modprobe nf_tables`)")
    if module in ("loaded", "built-in", "loadable") or config in ("y", "m"):
        return "ok", "nftables", f"nf_tables kernel support present ({module if module != 'unknown' else 'config=' + config})"
    return "WARN", "nftables", ("could not determine nf_tables support; it is tested for real once the images are "
                                "built (run doctor again after `labctl.py build --images-only`)")


def kvm_verdict(host_kvm: bool, disabled: bool, cpu_flags: int, active: str | None) -> tuple[str, str]:
    """`active`: accelerator of the running target VM ("kvm"/"tcg"), "no-vm", or None (lab not up)."""
    slow = ("the target VM runs under TCG software emulation - a full VM, but several times slower "
            "(boot, API calls and probes take much longer; latency numbers are not comparable with KVM runs). "
            "Fine for smoke tests; long-horizon runs want a KVM-capable host, such as a dedicated/bare-metal "
            "server (e.g. a Hetzner dedicated server) or a VM type that exposes nested virtualisation")
    if active == "kvm":
        return "ok", "ACTIVE - the running target VM uses KVM"
    if active == "tcg":
        why = ("disabled by LAB_KVM=0" if disabled else
               "the VM was started without /dev/kvm; run `labctl.py up` again" if host_kvm else
               "/dev/kvm is missing on this host")
        return "WARN", f"NOT active ({why}): {slow}"
    if disabled:
        return "WARN", f"disabled by LAB_KVM=0: {slow}"
    if host_kvm:
        return "ok", "available (/dev/kvm) - the target VM will use KVM" + (
            "" if active is None else " (target VM not running right now)")
    hint = (" The CPU advertises vmx/svm: load the module (`sudo modprobe kvm_intel` or `kvm_amd`)."
            if cpu_flags else "")
    return "WARN", f"not available (no /dev/kvm): {slow}.{hint}"


def cmd_doctor(_args: argparse.Namespace) -> None:
    """Report, item by item, whether this host can run the lab. Exit 1 if anything is FAIL."""
    rows: list[tuple[str, str, str]] = []

    def add(status: str, item: str, detail: str) -> None:
        rows.append((status, item, detail))
        print(f"[{status:^4}] {item:<15} {detail}", flush=True)

    add("ok", "host", f"{platform.system()} {platform.release()}; docker reached "
        + ("through WSL (docker not on PATH)" if using_wsl() else "directly (on PATH)"))
    py_ok = sys.version_info >= (3, 10)
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    missing = []
    for mod in ("yaml", "cryptography", "pytest", "requests", "paramiko", "jsonschema"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    add("FAIL" if not py_ok or missing else "ok" if in_venv else "WARN", "python",
        f"{platform.python_version()} at {sys.executable}"
        + ("" if in_venv else " - not a virtualenv; use .venv/bin/python")
        + (f"; missing {', '.join(missing)}: pip install -r requirements-dev.txt" if missing else ""))

    prefix = docker_prefix()
    env = docker_env()
    info = subprocess.run([*prefix, "info", "--format", "{{json .}}"], capture_output=True, text=True, env=env)
    if info.returncode != 0:
        add("FAIL", "docker engine", ((info.stderr or "").strip().splitlines() or ["not reachable"])[-1]
            + " - is the daemon running, and is your user in the `docker` group?")
        sys.exit(1)
    d = json.loads(info.stdout)
    add("ok", "docker engine", f"{d.get('ServerVersion')} on {d.get('OperatingSystem')}, cgroup v{d.get('CgroupVersion')}")
    cv = subprocess.run([*prefix, "compose", "version", "--short"], capture_output=True, text=True, env=env)
    version = cv.stdout.strip().lstrip("v")
    major_ok = cv.returncode == 0 and version.split(".")[0].isdigit() and int(version.split(".")[0]) >= 2
    add("ok" if major_ok else "FAIL", "compose plugin", version or "missing - install docker-compose-plugin")

    host = parse_kv(host_run(HOST_PROBE).stdout)
    arch = host.get("arch", "?")
    add("ok" if arch in ("x86_64", "amd64") else "WARN", "architecture",
        arch + ("" if arch in ("x86_64", "amd64") else " - the target is an x86_64 VM: emulation only, no KVM"))
    add("ok", "kernel", f"{host.get('kernel', '?')} ({host.get('os', '?')})")
    add("ok" if host.get("tun") == "present" else "FAIL", "/dev/net/tun",
        "present" if host.get("tun") == "present" else "missing - `sudo modprobe tun` (the target VM's NIC needs it)")

    probe_net = "agentopslab-doctor-probe"
    subprocess.run([*prefix, "network", "rm", probe_net], capture_output=True, env=env)
    mv = subprocess.run([*prefix, "network", "create", "--driver", "macvlan", "--internal", probe_net],
                        capture_output=True, text=True, env=env)
    subprocess.run([*prefix, "network", "rm", probe_net], capture_output=True, env=env)
    add("ok" if mv.returncode == 0 else "FAIL", "macvlan",
        "an internal macvlan network can be created" if mv.returncode == 0
        else f"cannot create an internal macvlan network: {mv.stderr.strip()[-200:]} - `sudo modprobe macvlan`")
    add(*nftables_verdict(host.get("mod_nf_tables", "unknown"), host.get("cfg_nf_tables", ""),
                          nft_functional(prefix, env)))

    disk_free = None
    root_dir = d.get("DockerRootDir") or "/var/lib/docker"
    df = host_run(f"df -Pk '{root_dir}' 2>/dev/null | tail -1 | awk '{{print $4}}'")
    if df.stdout.strip().isdigit():
        disk_free = int(df.stdout.strip()) * 1024
    for row in assess_resources(int(d.get("NCPU") or 0), int(d.get("MemTotal") or 0), disk_free):
        add(*row)

    import yaml
    add(*users_segment_verdict(yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))))
    if (LAB / "lab.env").exists():
        ps = subprocess.run(compose_cmd("ps", "--status", "running", "--services"), cwd=ROOT,
                            capture_output=True, text=True, env=env)
        if "observer" in ps.stdout.split():
            res = subprocess.run(compose_cmd("exec", "-T", "observer", "python", "-"), input=IDENTITY_PROBE,
                                 cwd=ROOT, capture_output=True, text=True, env=env)
            try:
                add(*identities_verdict(json.loads(res.stdout.strip().splitlines()[-1])))
            except (ValueError, IndexError):
                add("WARN", "identities", f"check failed: {(res.stderr or res.stdout).strip()[-200:]}")
        else:
            add("ok", "identities", "lab not running; checked when the observer is up")

    cfg = settings()
    disabled = kvm_disabled()
    active = None
    if (LAB / "lab.env").exists():
        ps = subprocess.run(compose_cmd("ps", "--status", "running", "--services"), cwd=ROOT,
                            capture_output=True, text=True, env=env)
        if "target-hv" in ps.stdout.split():
            acc = subprocess.run(compose_cmd("exec", "-T", "target-hv", "python3", "-"), input=QEMU_ACCEL,
                                 cwd=ROOT, capture_output=True, text=True, env=env)
            active = acc.stdout.strip() or None
    status, detail = kvm_verdict(host.get("kvm") == "present", disabled, int(host.get("cpu_virt_flags") or 0), active)
    add(status, "kvm", detail)

    driver = cfg.get("DEFENDER_DRIVER", "sdk")
    auth = defender_auth(cfg)
    if driver == "scripted":
        add("ok", "defender auth", "DEFENDER_DRIVER=scripted - no model, no credential needed")
    else:
        add({"api_key": "ok", "oauth": "ok", "none": "WARN", "conflict": "FAIL"}[auth], "defender auth", {
            "api_key": "ANTHROPIC_API_KEY (API billing)",
            "oauth": "CLAUDE_CODE_OAUTH_TOKEN (subscription; usage limits apply to long runs, see README)",
            "none": "no model credential set - runs will refuse to start (or use DEFENDER_DRIVER=scripted)",
            "conflict": "both ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN are set - set exactly one"}[auth])
    ui = cfg.get("LAB_LANGFUSE_UI", "").lower() in TRUE
    add("ok", "langfuse ui", f"published on 127.0.0.1:{cfg.get('LANGFUSE_UI_PORT', '3000')} only (reach it by SSH tunnel)"
        if ui else "not published (default); set LAB_LANGFUSE_UI=1 to reach it through an SSH tunnel")
    failed = sum(1 for r in rows if r[0] == "FAIL")
    print(f"\ndoctor: {failed} problem(s), {sum(1 for r in rows if r[0] == 'WARN')} warning(s)")
    sys.exit(1 if failed else 0)


def cmd_build(args: argparse.Namespace) -> None:
    compose("build")
    if args.images_only:
        return
    golden = ["--profile", "build", "run", "--rm", "target-build"]
    if args.rebuild_golden:
        golden += ["build", "--force"]      # replaces the service's default command ("build")
    compose(*golden)
    cmd_distribute()


def cmd_up(_args: argparse.Namespace) -> None:
    if not (LAB / "defender/gitea_admin_token").exists():
        sys.exit("up: the golden image has not been built — run `labctl.py build` first")
    cfg = settings()
    auth = defender_auth(cfg)
    if auth == "conflict":
        sys.exit("up: both ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN are set (.env or environment); "
                 "set exactly one")
    if cfg.get("DEFENDER_DRIVER", "sdk") == "sdk":
        print(f"up: defender model credential: {auth}"
              + ("" if auth != "none" else " — runs will refuse to start until one is set in .env"))
    print(f"up: compose files: {', '.join(compose_files())}")
    compose("up", "-d", "--wait", "--remove-orphans")


def cmd_down(args: argparse.Namespace) -> None:
    compose("--profile", "build", "down", *(["-v"] if args.volumes else []))


def cmd_ps(_args: argparse.Namespace) -> None:
    compose("ps")


def cmd_logs(args: argparse.Namespace) -> None:
    compose("logs", "--tail", str(args.tail), *args.services, check=False)


def cmd_run(args: argparse.Namespace) -> None:
    manifest = Path(args.manifest)
    if not manifest.exists():
        sys.exit(f"run: {manifest} not found")
    # A path of its own per invocation: a second `run` (refused by the observer's run lock)
    # must not overwrite the manifest of the run in progress.
    inside = f"/tmp/manifest-{dt.datetime.now():%Y%m%d-%H%M%S}-{secrets.token_hex(3)}.yaml"
    compose("cp", str(manifest).replace("\\", "/"), f"observer:{inside}")
    exec_args = ["exec", "-T", *(["-d"] if args.detach else []), "observer",
                 "lab-observer", "run", inside]
    if args.no_reset:
        exec_args.append("--no-reset")
    result = compose(*exec_args, check=False)
    if args.detach:
        print("run started in the background; follow it with: labctl.py status")
    sys.exit(result.returncode)


def cmd_status(args: argparse.Namespace) -> None:
    """Phase of the current/last run; with --summary an interim digest read from C3 (read-only).
    Both go through `docker compose exec` — no network connection into the observer."""
    if args.summary:
        compose("exec", "-T", "observer", "lab-observer", "summary", *(["--json"] if args.json else []),
                *([args.run_id] if args.run_id else []), check=False)
    else:
        compose("exec", "-T", "observer", "lab-observer", "status", check=False)


def scorer_version() -> str:
    sys.path[:0] = [str(ROOT / "observer")]
    from observer.scoring.metrics import SCORER_VERSION
    return SCORER_VERSION


def cmd_score(args: argparse.Namespace) -> None:
    """Score a run. Nothing that already exists under runs/ is ever modified.

    - An exported run (runs/<run_id>/events/*.jsonl) is re-scored on this host, read-only; the
      report goes to scores/<run_id>/report-scorer-<version>/ (the original report stays as it is).
    - Otherwise the observer scores it from its datastore (read-only) into
      /data/runs/<run_id>/report-scorer-<version>/, and the run is exported to runs/<run_id>/
      (only if that directory does not exist yet; if it does, the report goes to scores/)."""
    version = scorer_version()
    name = f"report-scorer-{version}"
    exported = ROOT / "runs" / args.run_id / "events" / "ground_truth.jsonl"
    if exported.exists() and not args.from_c3:
        sys.path[:0] = [str(ROOT / "observer")]
        from observer.scoring.report import score_export
        out = ROOT / "scores" / args.run_id / name
        result = score_export(ROOT / "runs" / args.run_id, out)
        co = result["5_collateral"]
        print(json.dumps({"report": str(out), "scorer_version": version, "source": str(exported.parent.parent),
                          "defender_share_pct": co["defender_share_pct"], "downtime_s": co["downtime_s"],
                          "attribution_confidence": co["confidence"]["level"]}, indent=2))
        return
    compose("exec", "-T", "observer", "lab-observer", "score", args.run_id)
    dest = ROOT / "runs" / args.run_id
    if not dest.exists():
        dest.mkdir(parents=True)
        compose("cp", f"observer:/data/runs/{args.run_id}/.", f"runs/{args.run_id}")
        print(f"run exported and scored: {dest} (report in {dest / name})")
    else:
        out = ROOT / "scores" / args.run_id
        out.mkdir(parents=True, exist_ok=True)
        compose("cp", f"observer:/data/runs/{args.run_id}/{name}", f"scores/{args.run_id}/{name}")
        print(f"runs/{args.run_id} left untouched; report copied to {out / name}")


def cmd_reset_target(_args: argparse.Namespace) -> None:
    # Refused (exit 3) while a run holds the run lock; the observer says which run.
    sys.exit(compose("exec", "-T", "observer", "lab-observer", "reset-target", check=False).returncode)


def cmd_check(args: argparse.Namespace) -> None:
    targets = [f"tests/acceptance/test_{c}.py" for c in args.components] or ["tests/acceptance"]
    sys.exit(subprocess.run([sys.executable, "-m", "pytest", "-v", *targets, *args.pytest_args],
                            cwd=ROOT, env=docker_env()).returncode)


def main() -> None:
    parser = argparse.ArgumentParser(prog="labctl.py", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, fn, help: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help)
        p.set_defaults(fn=fn)
        return p

    add("doctor", cmd_doctor, "check that this host can run the lab")
    p = add("bootstrap", cmd_bootstrap, "generate lab keys, CA and fake canaries into .lab/")
    p.add_argument("--force", action="store_true")
    p = add("build", cmd_build, "build images and the target's golden snapshot")
    p.add_argument("--images-only", action="store_true")
    p.add_argument("--rebuild-golden", action="store_true")
    add("distribute", cmd_distribute, "re-copy golden build outputs into the role directories")
    add("up", cmd_up, "start the lab")
    p = add("down", cmd_down, "stop the lab")
    p.add_argument("-v", "--volumes", action="store_true", help="also delete images, datastore, traces")
    add("ps", cmd_ps, "show lab containers")
    p = add("logs", cmd_logs, "show container logs")
    p.add_argument("services", nargs="*")
    p.add_argument("--tail", type=int, default=100)
    p = add("run", cmd_run, "execute a run manifest")
    p.add_argument("manifest")
    p.add_argument("--detach", action="store_true")
    p.add_argument("--no-reset", action="store_true", help="do not reset the target from the golden snapshot")
    p = add("status", cmd_status, "show the current/last run")
    p.add_argument("--summary", action="store_true",
                   help="interim digest of the run so far, read-only from the datastore")
    p.add_argument("--json", action="store_true", help="with --summary: machine-readable output")
    p.add_argument("run_id", nargs="?", help="with --summary: a specific run (default: current/last)")
    p = add("score", cmd_score, "score a run (exported runs are re-scored read-only into scores/)")
    p.add_argument("run_id")
    p.add_argument("--from-c3", action="store_true",
                   help="score from the observer's datastore even if an export exists in runs/")
    add("reset-target", cmd_reset_target, "reset the target VM from the golden snapshot")
    p = add("check", cmd_check, "run acceptance checks (all, or: target gateway observer defender)")
    p.add_argument("components", nargs="*", metavar="component")

    # `check [component…] -- <pytest options>`: everything after "--" goes to pytest untouched
    argv = sys.argv[1:]
    extra = []
    if "--" in argv:
        split = argv.index("--")
        argv, extra = argv[:split], argv[split + 1:]
    args = parser.parse_args(argv)
    if args.command == "check":
        bad = [c for c in args.components if c not in ("target", "gateway", "observer", "defender")]
        if bad:
            parser.error(f"unknown component(s) {bad}")
        args.pytest_args = extra
    elif extra:
        parser.error(f"unrecognized arguments: {' '.join(extra)}")
    args.fn(args)


if __name__ == "__main__":
    main()
