#!/bin/bash
# Egress gateway (component D): lab router + firewall, logging forward proxy, lab NTP.
set -eu

DATA=/var/lib/gateway
rm -rf /run/gateway                     # stale pidfiles/counters from a previous start
mkdir -p "$DATA" /run/gateway /home/mitm/.mitmproxy
install -m 0600 -o mitm -g mitm /secrets/mitmproxy-ca.pem /home/mitm/.mitmproxy/mitmproxy-ca.pem
chown -R mitm:mitm "$DATA" /home/mitm/.mitmproxy
chmod 0755 /run/gateway

addr() { python -c "from labcontracts import network; print(network.ADDR['$1'])"; }
port() { python -c "from labcontracts import network; print(network.PORTS['$1'])"; }

# 1. firewall first: nothing is forwarded before the policy is in place
python /opt/gateway/render_nft.py mitm > /run/gateway/lab.nft
nft -f /run/gateway/lab.nft
echo "gateway: firewall loaded"

declare -A NAMES
start() {  # name command...
    local name=$1; shift
    "$@" &
    NAMES[$!]=$name
}

# 2. publish drop counters for the proxy addon (which runs unprivileged)
start counters python /opt/gateway/publish_counters.py

# 3. NTP for the target segment (serves this host's clock; never adjusts it)
cat > /run/gateway/chrony.conf <<CONF
local stratum 8
allow ${TARGET_SEGMENT}
bindaddress $(addr gateway_target)
cmdport 0
pidfile /run/gateway/chronyd.pid
CONF
start ntp chronyd -x -d -f /run/gateway/chrony.conf -u root

# 4. control API (observer leg only) and the proxy, both unprivileged
drop="setpriv --reuid mitm --regid mitm --init-groups --inh-caps=-all --bounding-set=-all"
start control $drop python /opt/gateway/gwctl.py "$(addr gateway_observer)" "$(port gateway_control)"
start proxy $drop env HOME=/home/mitm mitmdump --mode regular --listen-host 0.0.0.0 \
    --listen-port "$(port proxy)" --set confdir=/home/mitm/.mitmproxy \
    --set termlog_verbosity=warn --set flow_detail=0 -s /opt/gateway/addon.py

# The gateway is only useful whole: if any part dies, say which and let Docker restart it.
status=0
wait -n -p exited || status=$?
echo "gateway: component '${NAMES[$exited]:-?}' exited with status $status; restarting" >&2
exit 1
