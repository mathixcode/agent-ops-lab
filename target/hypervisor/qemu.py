"""QEMU command line shared by the golden build and the runtime hypervisor daemon.

The machine definition must be identical in both, so the guest sees the same hardware
(NIC name, disk) at build time and at run time.
"""
from __future__ import annotations

import os

IMAGES = "/images"
GOLDEN = f"{IMAGES}/golden.qcow2"
GOLDEN_META = f"{IMAGES}/golden.json"
RUN_DIR = "/run/hv"
QGA_SOCK = f"{RUN_DIR}/qga.sock"
QMP_SOCK = f"{RUN_DIR}/qmp.sock"
TARGET_MAC = "52:54:00:20:01:10"


def kvm_usable() -> bool:
    """True if /dev/kvm exists (or can be created) and opens. Otherwise QEMU falls back to
    TCG software emulation — slower, but still a full VM."""
    try:
        if not os.path.exists("/dev/kvm"):
            os.mknod("/dev/kvm", 0o660 | 0o020000, os.makedev(10, 232))
        fd = os.open("/dev/kvm", os.O_RDWR)
        os.close(fd)
        return True
    except OSError:
        try:
            os.unlink("/dev/kvm")
        except OSError:
            pass
        return False


def accel() -> str:
    return "kvm" if kvm_usable() else "tcg"


def command(disk: str, netdev: str, console_log: str, extra_drives: tuple[str, ...] = ()) -> list[str]:
    acc = accel()
    vcpus = os.environ.get("TARGET_VCPUS", "4")
    memory = os.environ.get("TARGET_MEMORY_MB", "8192")
    cmd = [
        "qemu-system-x86_64", "-name", "target",
        "-machine", "q35",
        "-accel", "kvm" if acc == "kvm" else "tcg,thread=multi",
        "-cpu", "host" if acc == "kvm" else "max",
        "-smp", vcpus, "-m", memory,
        "-drive", f"file={disk},if=virtio,format=qcow2,discard=unmap,cache=writeback",
        "-netdev", netdev,
        "-device", f"virtio-net-pci,netdev=n0,mac={TARGET_MAC}",
        "-device", "virtio-rng-pci",
        "-device", "virtio-serial",
        "-chardev", f"socket,path={QGA_SOCK},server=on,wait=off,id=qga0",
        "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
        "-qmp", f"unix:{QMP_SOCK},server=on,wait=off",
        "-rtc", "base=utc",
        "-display", "none",
        "-serial", f"file:{console_log}",
    ]
    for drive in extra_drives:
        cmd += ["-drive", drive]
    return cmd
