#!/bin/sh
# Prepare a fresh Debian/Ubuntu host (any Linux VPS or dedicated server) to run the lab.
#
#   sudo scripts/host-setup.sh            from the repository root
#
# It installs Docker Engine and the Compose plugin from Docker's apt repository, Python's venv
# support, loads the kernel modules the lab uses (tun, macvlan, nf_tables, and kvm where the CPU
# supports it) and persists them across reboots, adds the invoking user to the `docker` group,
# creates .venv/ with the host-side requirements, and finishes with `labctl.py doctor`.
#
# Idempotent: running it again changes nothing that is already in place. It opens no ports and
# changes no firewall: the lab publishes nothing (see README, "Running on a remote Linux host").
set -eu

die() { echo "host-setup: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root: sudo $0"
REPO=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$REPO/labctl.py" ] || die "cannot find labctl.py next to scripts/"
TARGET_USER=${SUDO_USER:-root}

. /etc/os-release
case "${ID:-}" in
    debian|ubuntu) ;;
    *) die "supported: Debian and Ubuntu (found ${PRETTY_NAME:-unknown}); install Docker + Compose v2 by hand, then run labctl.py doctor" ;;
esac

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q ca-certificates curl gnupg python3 python3-venv python3-pip git kmod

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    echo "== Docker Engine + Compose plugin (download.docker.com, $ID $VERSION_CODENAME)"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -q
    apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker >/dev/null

echo "== kernel modules"
MODULES="tun macvlan nf_tables"
if grep -q -E '(vmx)' /proc/cpuinfo; then MODULES="$MODULES kvm_intel"; fi
if grep -q -E '(svm)' /proc/cpuinfo; then MODULES="$MODULES kvm_amd"; fi
: > /etc/modules-load.d/agentopslab.conf
for m in $MODULES; do
    if modprobe "$m" 2>/dev/null; then
        echo "$m" >> /etc/modules-load.d/agentopslab.conf
        echo "   $m: loaded"
    else
        echo "   $m: not available (doctor will say whether that matters)"
    fi
done
if [ -c /dev/kvm ]; then
    echo "   /dev/kvm present: the target VM will run with KVM"
else
    echo "   no /dev/kvm: the target VM will run under slow TCG emulation."
    echo "   For long runs use a KVM-capable host (dedicated/bare-metal server, or a VM type with nested virtualisation)."
fi

if [ "$TARGET_USER" != root ]; then
    echo "== docker group for $TARGET_USER"
    usermod -aG docker "$TARGET_USER"
fi

echo "== Python virtualenv ($REPO/.venv)"
as_user() { if [ "$TARGET_USER" = root ]; then sh -c "$1"; else su "$TARGET_USER" -s /bin/sh -c "$1"; fi; }
as_user "cd '$REPO' && { [ -x .venv/bin/python ] || python3 -m venv .venv; } && .venv/bin/python -m pip install -q --upgrade pip && .venv/bin/python -m pip install -q -r requirements-dev.txt"

echo "== doctor"
# a fresh group membership is not active in this shell yet: run doctor through `sg docker`
if [ "$TARGET_USER" = root ]; then
    (cd "$REPO" && .venv/bin/python labctl.py doctor) || true
else
    su "$TARGET_USER" -s /bin/sh -c "cd '$REPO' && sg docker -c '.venv/bin/python labctl.py doctor'" || true
fi

cat <<EOF

host-setup: done. Log out and back in (or run \`newgrp docker\`) so your user can use Docker, then:

    cd $REPO
    .venv/bin/python labctl.py bootstrap
    .venv/bin/python labctl.py build
    .venv/bin/python labctl.py up
EOF
