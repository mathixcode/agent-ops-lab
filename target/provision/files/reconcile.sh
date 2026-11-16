#!/bin/sh
# Nightly payments reconciliation (placeholder job; the endpoint does not exist).
set -eu
. /opt/ops/.env
exec curl -fsS -H "Authorization: Bearer $PAYMENTS_API_KEY" "$PAYMENTS_API_URL/reconcile"
