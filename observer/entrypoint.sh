#!/bin/sh
# Observer container: routes via the gateway, client identities on the users segment,
# accept nothing inbound (on any leg), then idle.
# Runs are started from outside with `docker compose exec observer lab-observer ...`.
set -eu
: "${LAB_GATEWAY_IP:?}"

ip route replace default via "$LAB_GATEWAY_IP"

# Client identities on the users segment (contracts/labcontracts/network.py): one address per
# simulated-user IP group plus probe, scanner and org. Requests are bound to these addresses by
# the observer's HTTP clients; a policy route sends anything from the users segment out of the
# users leg, through the gateway, to the target's web front end.
: "${USERS_SEGMENT:?}" "${USERS_GATEWAY_IP:?}"
USERS_LEG=$(ip -o -4 addr show | awk -v p="${USERS_SEGMENT%.*}." 'index($4, p) == 1 {print $2; exit}')
[ -n "$USERS_LEG" ] || { echo "observer: no interface in $USERS_SEGMENT" >&2; exit 1; }
IDENTITY_ADDRS=$(python -c 'from labcontracts import network as n; print(" ".join((*n.USER_IPS, *n.IDENTITY_IPS.values())))')
for addr in $IDENTITY_ADDRS; do
    ip addr replace "$addr/32" dev "$USERS_LEG"
done
ip route replace "$USERS_SEGMENT" dev "$USERS_LEG" table 103
ip route replace default via "$USERS_GATEWAY_IP" dev "$USERS_LEG" table 103
ip rule del from "$USERS_SEGMENT" lookup 103 2>/dev/null || true
ip rule add from "$USERS_SEGMENT" lookup 103 priority 1000

# Default-deny on the observer itself (spec C.5), in addition to the gateway's firewall:
# even something that reached this segment could not open a connection to the observer.
nft -f - <<NFT
table inet observer {}
delete table inet observer
table inet observer {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
  }
}
NFT

mkdir -p /data/c3 /data/runs
chown -R observer:observer /data
echo "observer: ready (no inbound connections accepted)"
exec setpriv --reuid observer --regid observer --init-groups --inh-caps=-all --bounding-set=-all \
    sleep infinity
