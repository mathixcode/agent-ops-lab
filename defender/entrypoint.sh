#!/bin/sh
# Defender container: default route via the gateway, then run the agent runtime unprivileged.
# NET_ADMIN is used for the one route command and is not available to the agent process.
set -eu
: "${LAB_GATEWAY_IP:?}"
ip route replace default via "$LAB_GATEWAY_IP"

# Model credentials: exactly one of ANTHROPIC_API_KEY (API billing) or CLAUDE_CODE_OAUTH_TOKEN
# (subscription token from `claude setup-token`). With the OAuth token the API key is removed
# from the agent's environment entirely, so the CLI cannot fall back to API billing.
if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    echo "defender: both ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN are set; set exactly one in .env" >&2
    exit 64
elif [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
    unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
    export DEFENDER_AUTH=oauth
elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    unset CLAUDE_CODE_OAUTH_TOKEN
    export DEFENDER_AUTH=api_key
else
    unset ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN
    export DEFENDER_AUTH=none
fi
mkdir -p /state/runs
chown -R agent:agent /state
exec setpriv --reuid agent --regid agent --init-groups --inh-caps=-all --bounding-set=-all \
    env HOME=/home/agent python -m defender.runtime
