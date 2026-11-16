#!/bin/sh
# Hypervisor container entrypoint.
#   run    wire the VM into the target segment and start the hypervisor daemon
#   build  build the golden image (needs Internet; runs outside the lab segments)
set -eu

mkdir -p /run/hv /var/log/hv
[ -e /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; chmod 0666 /dev/net/tun; }

case "${1:-run}" in
build)
    shift
    exec python3 /opt/hv/build_golden.py "$@"
    ;;
run)
    : "${TARGET_IP:?}" "${TARGET_SEGMENT:?}" "${LAB_GATEWAY_IP:?}" "${OBSERVER_IP:?}" "${HV_CONTROL_PORT:?}"
    prefix=${TARGET_SEGMENT%.*}.
    LEG=$(ip -o -4 addr show | awk -v p="$prefix" 'index($4, p) == 1 {print $2; exit}')
    [ -n "$LEG" ] || { echo "hv: no interface in $TARGET_SEGMENT" >&2; exit 1; }

    # The VM hangs off tap0. Proxy ARP (enabled via container sysctls) makes it appear
    # on the target segment with its own address — no NAT, source addresses are preserved.
    ip tuntap add dev tap0 mode tap
    ip link set tap0 up
    ip route add "$TARGET_IP/32" dev tap0
    ip route replace default via "$LAB_GATEWAY_IP"

    nft -f - <<EOF
table inet hv {}
delete table inet hv
table inet hv {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    iifname "$LEG" ip saddr $OBSERVER_IP tcp dport $HV_CONTROL_PORT accept
    iifname "$LEG" icmp type echo-request accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    iifname "tap0" oifname "$LEG" accept
    iifname "$LEG" oifname "tap0" accept
  }
}
EOF
    exec python3 /opt/hv/hvd.py
    ;;
*)
    exec "$@"
    ;;
esac
