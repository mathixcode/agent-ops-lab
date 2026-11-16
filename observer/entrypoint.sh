#!/bin/sh
# Observer container: route via the gateway, accept nothing inbound, then idle.
# Runs are started from outside with `docker compose exec observer lab-observer ...`.
set -eu
: "${LAB_GATEWAY_IP:?}"

ip route replace default via "$LAB_GATEWAY_IP"

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
