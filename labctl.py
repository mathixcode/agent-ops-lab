#!/usr/bin/env python3
"""labctl — host-side control for the Agent Ops Lab local pilot.

Run it with the project's virtualenv interpreter:

    .venv/Scripts/python.exe labctl.py <command>      (Windows)
    .venv/bin/python labctl.py <command>              (Linux/macOS)

Docker is used directly when it is on PATH and through WSL otherwise.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LAB = ROOT / ".lab"
sys.path.insert(0, str(ROOT / "contracts"))

from labcontracts import canary, network  # noqa: E402


# --------------------------------------------------------------------------- docker plumbing

def docker_prefix() -> list[str]:
    if shutil.which("docker"):
        return ["docker"]
    if shutil.which("wsl.exe"):
        distro = os.environ.get("LAB_WSL_DISTRO")
        return ["wsl.exe", *(["-d", distro] if distro else []), "--", "docker"]
    sys.exit("labctl: neither docker nor wsl.exe found on PATH")


def docker_env() -> dict[str, str]:
    env = dict(os.environ)
    forward = [v for v in ("ANTHROPIC_API_KEY", "DEFENDER_DRIVER", "DEFENDER_MODEL_ID", "TARGET_VCPUS",
                           "TARGET_MEMORY_MB", "TARGET_DISK_GB") if env.get(v)]
    if forward and not shutil.which("docker"):
        # make these visible to `docker compose` inside WSL
        env["WSLENV"] = ":".join(filter(None, [env.get("WSLENV"), *(f"{v}/u" for v in forward)]))
    return env


def compose_cmd(*args: str) -> list[str]:
    cmd = [*docker_prefix(), "compose", "--env-file", ".lab/lab.env"]
    if (ROOT / ".env").exists():
        cmd += ["--env-file", ".env"]
    return [*cmd, *args]


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

def cmd_doctor(_args: argparse.Namespace) -> None:
    probe = ("set -e; docker info --format 'docker {{.ServerVersion}}, {{.NCPU}} cpus, "
             "{{.MemTotal}} bytes'; docker compose version --short; "
             "test -c /dev/net/tun && echo tun:ok || echo tun:MISSING; "
             "test -e /dev/kvm && echo kvm:yes || echo 'kvm:no (target VM will use slow TCG emulation)'")
    prefix = docker_prefix()
    shell = ["sh", "-c", probe] if prefix == ["docker"] else [*prefix[:-1], "sh", "-c", probe]
    run(shell)


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
    compose("up", "-d", "--wait")


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
    compose("cp", str(manifest).replace("\\", "/"), "observer:/tmp/manifest.yaml")
    exec_args = ["exec", "-T", *(["-d"] if args.detach else []), "observer",
                 "lab-observer", "run", "/tmp/manifest.yaml"]
    if args.no_reset:
        exec_args.append("--no-reset")
    result = compose(*exec_args, check=False)
    if args.detach:
        print("run started in the background; follow it with: labctl.py status")
    sys.exit(result.returncode)


def cmd_status(_args: argparse.Namespace) -> None:
    compose("exec", "-T", "observer", "lab-observer", "status", check=False)


def cmd_score(args: argparse.Namespace) -> None:
    compose("exec", "-T", "observer", "lab-observer", "score", args.run_id)
    dest = ROOT / "runs" / args.run_id
    dest.mkdir(parents=True, exist_ok=True)
    compose("cp", f"observer:/data/runs/{args.run_id}/.", f"runs/{args.run_id}")
    print(f"report copied to {dest}")


def cmd_reset_target(_args: argparse.Namespace) -> None:
    compose("exec", "-T", "observer", "lab-observer", "reset-target")


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
    add("status", cmd_status, "show the current/last run")
    p = add("score", cmd_score, "compute the metrics report for a run and copy it to runs/")
    p.add_argument("run_id")
    add("reset-target", cmd_reset_target, "reset the target VM from the golden snapshot")
    p = add("check", cmd_check, "run acceptance checks (all, or: target gateway observer defender)")
    p.add_argument("components", nargs="*", metavar="component")

    args, extra = parser.parse_known_args()
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
