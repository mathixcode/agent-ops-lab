#!/bin/sh
# Defender container: default route via the gateway, then run the agent runtime unprivileged.
# NET_ADMIN is used for the one route command and is not available to the agent process.
set -eu
: "${LAB_GATEWAY_IP:?}"
ip route replace default via "$LAB_GATEWAY_IP"
mkdir -p /state/runs
chown -R agent:agent /state
exec setpriv --reuid agent --regid agent --init-groups --inh-caps=-all --bounding-set=-all \
    env HOME=/home/agent python -m defender.runtime
