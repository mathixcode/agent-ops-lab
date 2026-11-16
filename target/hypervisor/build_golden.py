#!/usr/bin/env python3
"""Build the target's golden snapshot (spec A.5).

    pinned Debian cloud image -> boot in QEMU -> provision over SSH -> seed -> power off
    -> /images/golden.qcow2 (read-only). Every run later boots a throw-away overlay of it.

Runs in the hypervisor image with plain Internet access (not on the lab segments): this is
build time, the only moment the target is not behind the egress gateway.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

import qemu

BUILD_IN = "/build-in"            # .lab/build       (read-only)
BUILD_OUT = "/build-out"          # .lab/build-out
PROVISION = "/opt/target/provision"
CACHE = f"{qemu.IMAGES}/cache"
WORK = f"{qemu.IMAGES}/build"
SSH_PORT = 2222
ENV_KEYS = ("LAB_TARGET_IP", "LAB_GATEWAY_IP", "LAB_PROXY_PORT", "DEFENDER_SEGMENT",
            "OBSERVER_SEGMENT", "TARGET_HOSTNAME")


def log(msg: str) -> None:
    print(f"[{dt.datetime.now(dt.timezone.utc):%H:%M:%S}] build: {msg}", flush=True)


def versions() -> dict[str, str]:
    out = {}
    for line in open("/opt/target/versions.env"):
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            out[key] = value
    return out


def fetch(url: str, dest: str, algo: str, digest: str) -> None:
    def ok() -> bool:
        h = hashlib.new(algo)
        with open(dest, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest() == digest

    if os.path.exists(dest) and ok():
        log(f"cached {os.path.basename(dest)}")
        return
    log(f"downloading {url}")
    subprocess.run(["curl", "-fsSL", "--retry", "3", "-o", dest + ".part", url], check=True)
    os.replace(dest + ".part", dest)
    if not ok():
        os.unlink(dest)
        sys.exit(f"build: {algo} mismatch for {url}")


def ssh_base(key: str) -> list[str]:
    return ["-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=30"]


def ssh(key: str, command: str, check: bool = True, capture: bool = False,
        timeout: float | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["ssh", *ssh_base(key), "-p", str(SSH_PORT), "provision@127.0.0.1", command],
                          check=check, capture_output=capture, text=True, timeout=timeout)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="rebuild even if a golden image exists")
    args = ap.parse_args()

    need = ["gitea_admin_token", "known_hosts", "seed_users.json", "golden.json"]
    if os.path.exists(qemu.GOLDEN) and not args.force:
        if all(os.path.exists(f"{BUILD_OUT}/{n}") for n in need):
            log("golden image already present (use --rebuild-golden to replace it)")
            return
        sys.exit("build: golden image exists but .lab/build-out is incomplete; rebuild with --rebuild-golden")

    v = versions()
    env = {k: os.environ[k] for k in ENV_KEYS}
    disk_gb = os.environ.get("TARGET_DISK_GB", "40")
    os.makedirs(CACHE, exist_ok=True)
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    os.makedirs(BUILD_OUT, exist_ok=True)

    base = f"{CACHE}/{os.path.basename(v['DEBIAN_IMAGE_URL'])}"
    gitea = f"{CACHE}/gitea-{v['GITEA_VERSION']}"
    fetch(v["DEBIAN_IMAGE_URL"], base, "sha512", v["DEBIAN_IMAGE_SHA512"])
    fetch(v["GITEA_URL"], gitea, "sha256", v["GITEA_SHA256"])

    disk = f"{WORK}/build.qcow2"
    subprocess.run(["qemu-img", "convert", "-O", "qcow2", base, disk], check=True)
    subprocess.run(["qemu-img", "resize", "-q", disk, f"{disk_gb}G"], check=True)

    # ssh refuses keys with open permissions; the bind mount may not preserve modes
    key = f"{WORK}/provision_key"
    shutil.copy(f"{BUILD_IN}/provision_key", key)
    os.chmod(key, 0o600)
    pub = open(f"{BUILD_IN}/provision_key.pub").read().strip()

    with open(f"{WORK}/user-data", "w") as fh:
        fh.write("#cloud-config\nhostname: target\nssh_pwauth: false\nusers:\n"
                 "  - name: provision\n    shell: /bin/bash\n    lock_passwd: true\n"
                 "    sudo: 'ALL=(ALL) NOPASSWD:ALL'\n"
                 f"    ssh_authorized_keys:\n      - {pub}\n")
    with open(f"{WORK}/meta-data", "w") as fh:
        fh.write("instance-id: target-golden\nlocal-hostname: target\n")
    subprocess.run(["genisoimage", "-quiet", "-output", f"{WORK}/seed.iso", "-volid", "cidata",
                    "-joliet", "-rock", f"{WORK}/user-data", f"{WORK}/meta-data"], check=True)

    accel = qemu.accel()
    log(f"booting build VM (accel={accel}"
        + (", software emulation: expect this to take a while)" if accel == "tcg" else ")"))
    console = f"{WORK}/console.log"
    cmd = qemu.command(disk, f"user,id=n0,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22", console,
                       extra_drives=(f"file={WORK}/seed.iso,if=virtio,format=raw,readonly=on",))
    vm = subprocess.Popen(cmd)
    try:
        deadline = time.time() + 1800
        while True:
            if vm.poll() is not None:
                sys.exit(f"build: QEMU exited early ({vm.returncode}); see {console}")
            try:
                if ssh(key, "true", check=False, capture=True, timeout=20).returncode == 0:
                    break
            except subprocess.TimeoutExpired:
                pass
            if time.time() > deadline:
                sys.exit(f"build: VM did not come up within 30 min; see {console}")
            time.sleep(10)
        log("VM is up; waiting for cloud-init to finish")
        # cloud-init restarts sshd while it runs, so a connection can be dropped mid-wait: retry
        for attempt in range(30):
            if ssh(key, "sudo cloud-init status --wait >/dev/null 2>&1 || true", check=False,
                   timeout=1800).returncode == 0:
                break
            time.sleep(5)
        else:
            sys.exit("build: could not confirm that cloud-init finished")

        log("copying provisioning files")
        stage = f"{WORK}/provision"
        shutil.copytree(PROVISION, stage)
        shutil.copy("/opt/target/versions.env", f"{stage}/versions.env")
        os.makedirs(f"{stage}/inputs")
        for name in ("operator.pub", "observer.pub", "ca.crt", "target.key", "target.crt",
                     "target-renewed.crt", "canaries.json", "seed_users.json"):
            shutil.copy(f"{BUILD_IN}/{name}", f"{stage}/inputs/{name}")
        shutil.copy(gitea, f"{stage}/inputs/gitea")
        subprocess.run(["scp", *ssh_base(key), "-P", str(SSH_PORT), "-q", "-r", stage,
                        "provision@127.0.0.1:/tmp/provision"], check=True)

        log("provisioning")
        envs = " ".join(f"{k}={v_}" for k, v_ in env.items())
        ssh(key, f"sudo env {envs} bash /tmp/provision/provision.sh")

        log("collecting outputs")
        def remote(path: str) -> str:
            return ssh(key, f"sudo cat {path}", capture=True).stdout

        for name in ("gitea_admin_token", "seed_users.json"):
            with open(f"{BUILD_OUT}/{name}", "w") as fh:
                fh.write(remote(f"/root/lab-build-out/{name}"))
        hostkey = remote("/etc/ssh/ssh_host_ed25519_key.pub").split()
        with open(f"{BUILD_OUT}/known_hosts", "w") as fh:
            fh.write(f"{env['TARGET_HOSTNAME']},{env['LAB_TARGET_IP']} {hostkey[0]} {hostkey[1]}\n")
        meta = {"built_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "debian_image": os.path.basename(v["DEBIAN_IMAGE_URL"]),
                "gitea_version": v["GITEA_VERSION"], "disk_gb": int(disk_gb), "built_with": accel,
                **json.loads(remote("/root/lab-build-out/accounts.json")),
                "seed": json.loads(remote("/root/lab-build-out/seed_state.json"))}

        log("finalising: removing build account and build inputs, powering off")
        ssh(key, "sudo rm -rf /tmp/provision /root/lab-build-out; "
                 "sudo sed -i 's/ provision$//' /etc/ssh/sshd_config.d/10-lab.conf; "
                 "sudo systemd-run --quiet --on-active=3 /bin/sh -c "
                 "'pkill -KILL -u provision; userdel -rf provision; "
                 "rm -f /etc/sudoers.d/90-cloud-init-users; sync; systemctl poweroff'")
        try:
            vm.wait(600)
        except subprocess.TimeoutExpired:
            sys.exit("build: VM did not power off; golden image not written")
    finally:
        if vm.poll() is None:
            vm.kill()

    if os.path.exists(qemu.GOLDEN):
        os.chmod(qemu.GOLDEN, 0o644)
        os.unlink(qemu.GOLDEN)
    overlay = f"{qemu.IMAGES}/run-overlay.qcow2"
    if os.path.exists(overlay):
        os.unlink(overlay)          # an overlay of the previous golden image is meaningless now
    os.replace(disk, qemu.GOLDEN)
    os.chmod(qemu.GOLDEN, 0o444)
    for dest in (qemu.GOLDEN_META, f"{BUILD_OUT}/golden.json"):
        with open(dest, "w") as fh:
            json.dump(meta, fh, indent=2)
    shutil.rmtree(WORK, ignore_errors=True)
    log(f"golden snapshot written: {qemu.GOLDEN}")


if __name__ == "__main__":
    main()
