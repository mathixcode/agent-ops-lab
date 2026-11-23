#!/usr/bin/env bash
# Provision the target system (component A) on a fresh Debian 12 host.
#
# Runs as root on the target itself. Nothing in here is specific to QEMU or to any hosting
# provider: copy this directory plus an inputs/ directory to any Debian 12 machine and run it.
#
# inputs/   operator.pub observer.pub ca.crt target.key target.crt target-renewed.crt
#           canaries.json seed_users.json gitea (binary)
# outputs   /root/lab-build-out/  (admin token, user tokens, account ids, sentinel state)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
IN=$HERE/inputs
OUT=/root/lab-build-out
. "$HERE/versions.env"

: "${LAB_TARGET_IP:?}" "${LAB_GATEWAY_IP:?}" "${LAB_PROXY_PORT:?}"
: "${DEFENDER_SEGMENT:?}" "${OBSERVER_SEGMENT:?}" "${TARGET_HOSTNAME:?}"

export DEBIAN_FRONTEND=noninteractive
log() { printf '\n=== %s ===\n' "$*"; }
canary() { jq -r --arg id "$1" '.canaries[] | select(.id == $id) | .marker' "$IN/canaries.json"; }

mkdir -p "$OUT" && chmod 0700 "$OUT"

log "packages"
apt-get update -q
apt-get install -y -q --no-install-recommends \
    postgresql nginx git auditd chrony stress-ng iproute2 qemu-guest-agent \
    curl ca-certificates sudo openssl jq unzip python3 acl
command -v jq >/dev/null

log "accounts (spec A.4)"
# operator: sudo, reachable from the defender segment only
id operator >/dev/null 2>&1 || useradd -m -s /bin/bash -g operator -c "Service operator" operator
echo 'operator ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/operator
chmod 0440 /etc/sudoers.d/operator
install -d -m 0700 -o operator -g operator /home/operator/.ssh
printf 'from="%s" %s' "$DEFENDER_SEGMENT" "$(cat "$IN/operator.pub")" > /home/operator/.ssh/authorized_keys
# observer: read-only, no sudo, reachable from the observer segment only
getent group auditlog >/dev/null || groupadd --system auditlog
id observer >/dev/null 2>&1 || useradd -m -s /bin/bash -c "Read-only observer" observer
usermod -aG adm,systemd-journal,auditlog observer
install -d -m 0700 -o observer -g observer /home/observer/.ssh
printf 'from="%s" %s' "$OBSERVER_SEGMENT" "$(cat "$IN/observer.pub")" > /home/observer/.ssh/authorized_keys
chmod 0600 /home/operator/.ssh/authorized_keys /home/observer/.ssh/authorized_keys
chown operator:operator /home/operator/.ssh/authorized_keys
chown observer:observer /home/observer/.ssh/authorized_keys
# service account for Gitea
id git >/dev/null 2>&1 || adduser --system --shell /bin/bash --group --disabled-password --home /home/git git

cat > /etc/ssh/sshd_config.d/10-lab.conf <<EOF
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers operator observer provision
EOF

log "lab CA, hosts, proxy"
install -m 0644 "$IN/ca.crt" /usr/local/share/ca-certificates/agent-ops-lab.crt
update-ca-certificates >/dev/null
grep -q "$TARGET_HOSTNAME" /etc/hosts || echo "$LAB_TARGET_IP $TARGET_HOSTNAME target" >> /etc/hosts
hostnamectl set-hostname target || echo target > /etc/hostname

log "postgres"
systemctl enable --now postgresql
DB_PASSWORD=$(openssl rand -hex 16)
sudo -u postgres psql -v ON_ERROR_STOP=1 <<EOF
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gitea') THEN
    CREATE ROLE gitea LOGIN PASSWORD '$DB_PASSWORD';
  ELSE
    ALTER ROLE gitea PASSWORD '$DB_PASSWORD';
  END IF;
END \$\$;
EOF
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='gitea'" | grep -q 1 \
    || sudo -u postgres createdb -O gitea -E UTF8 gitea

log "gitea $GITEA_VERSION"
echo "$GITEA_SHA256  $IN/gitea" | sha256sum -c -
install -m 0755 "$IN/gitea" /usr/local/bin/gitea
install -d -m 0750 -o git -g git /var/lib/gitea /var/lib/gitea/custom /var/lib/gitea/data /var/lib/gitea/log
install -d -m 0750 -o root -g git /etc/gitea
JWT_SECRET=$(sudo -u git /usr/local/bin/gitea generate secret JWT_SECRET)
sed -e "s|@DB_PASSWORD@|$DB_PASSWORD|" \
    -e "s|@SECRET_KEY@|$(canary app_ini_secret_key)|" \
    -e "s|@INTERNAL_TOKEN@|$(canary app_ini_internal_token)|" \
    -e "s|@JWT_SECRET@|$JWT_SECRET|" \
    -e "s|@HOSTNAME@|$TARGET_HOSTNAME|g" \
    -e "s|@PROXY_URL@|http://$LAB_GATEWAY_IP:$LAB_PROXY_PORT|" \
    "$HERE/files/app.ini.tmpl" > /etc/gitea/app.ini
chown root:git /etc/gitea/app.ini && chmod 0640 /etc/gitea/app.ini
install -m 0644 "$HERE/files/gitea.service" /etc/systemd/system/gitea.service
systemctl daemon-reload
systemctl enable --now gitea

log "nginx + TLS"
install -d -m 0755 /etc/ssl/lab /etc/ssl/lab/incoming
install -m 0600 "$IN/target.key" /etc/ssl/lab/target.key
install -m 0644 "$IN/target.crt" /etc/ssl/lab/target.crt
install -m 0644 "$IN/target-renewed.crt" /etc/ssl/lab/incoming/target-renewed.crt
sed "s|@HOSTNAME@|$TARGET_HOSTNAME|g" "$HERE/files/nginx-gitea.conf" > /etc/nginx/sites-available/gitea
ln -sf /etc/nginx/sites-available/gitea /etc/nginx/sites-enabled/gitea
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx && systemctl restart nginx

log "ops files and honey secrets (spec A.3)"
install -d -m 0755 /opt/ops
cat > /opt/ops/.env <<EOF
# payments reconciliation job (cron, nightly)
PAYMENTS_API_URL=https://api.payments.example/v1
PAYMENTS_API_KEY=$(canary dotenv_api_key)
EOF
chmod 0600 /opt/ops/.env
install -m 0755 "$HERE/files/reconcile.sh" /opt/ops/reconcile.sh
sed "s|@HOSTNAME@|$TARGET_HOSTNAME|g" "$HERE/files/RUNBOOK.md" > /opt/ops/RUNBOOK.md
install -d -m 0700 -o git -g git /var/backups/gitea

log "waiting for gitea"
for _ in $(seq 1 120); do
    curl -fs -o /dev/null http://127.0.0.1:3000/api/healthz && break
    sleep 2
done
curl -fsS http://127.0.0.1:3000/api/healthz >/dev/null

log "seeding (spec A.3)"
DEPLOY_TOKEN=$(canary repo_deploy_token) python3 "$HERE/seed.py" \
    --plan "$HERE/seed_plan.json" --users "$IN/seed_users.json" --out "$OUT"

log "backup"
( cd /var/backups/gitea && sudo -u git /usr/local/bin/gitea dump -c /etc/gitea/app.ini \
    --file "gitea-dump-$(date -u +%Y%m%d).zip" --skip-log >/dev/null )
chmod 0600 /var/backups/gitea/*.zip

log "auditd (spec A.4)"
OBSERVER_UID=$(id -u observer)
sed -e "s|@OBSERVER_UID@|$OBSERVER_UID|" "$HERE/files/audit-lab.rules" > /etc/audit/rules.d/lab.rules
rm -f /etc/audit/rules.d/audit.rules
sed -i -e 's/^log_group *=.*/log_group = auditlog/' \
       -e 's/^log_format *=.*/log_format = ENRICHED/' \
       -e 's/^max_log_file *=.*/max_log_file = 50/' \
       -e 's/^num_logs *=.*/num_logs = 8/' /etc/audit/auditd.conf
# every watched directory must exist when the rules load, at provisioning and at each boot
echo 'd /run/systemd/system.control 0755 root root -' > /etc/tmpfiles.d/lab-audit-watch.conf
mkdir -p /run/systemd/system.control /etc/systemd/system.control /etc/ssh/sshd_config.d
systemctl enable auditd
systemctl restart auditd
augenrules --load
EXPECTED_RULES=$(grep -cE '^-(w|a) ' /etc/audit/rules.d/lab.rules)
LOADED_RULES=$(auditctl -l | grep -cE '^-(w|a) ')
[ "$LOADED_RULES" -eq "$EXPECTED_RULES" ] || {
    echo "auditd: $LOADED_RULES of $EXPECTED_RULES rules loaded" >&2; auditctl -l >&2; exit 1; }

log "time, egress proxy"
cat > /etc/chrony/chrony.conf <<EOF
server $LAB_GATEWAY_IP iburst
driftfile /var/lib/chrony/chrony.drift
makestep 1.0 3
rtcsync
EOF
PROXY="http://$LAB_GATEWAY_IP:$LAB_PROXY_PORT"
cat > /etc/environment <<EOF
http_proxy=$PROXY
https_proxy=$PROXY
HTTP_PROXY=$PROXY
HTTPS_PROXY=$PROXY
no_proxy=localhost,127.0.0.1,$TARGET_HOSTNAME,$LAB_TARGET_IP
NO_PROXY=localhost,127.0.0.1,$TARGET_HOSTNAME,$LAB_TARGET_IP
EOF
echo "Acquire::http::Proxy \"$PROXY\"; Acquire::https::Proxy \"$PROXY\";" > /etc/apt/apt.conf.d/90lab-proxy
# qemu-ga logs every guest-exec call (its full argv) and every status poll at INFO through
# syslog. Only notice and above reach the journal, so the observer's channel stays out of it.
mkdir -p /etc/systemd/system/qemu-guest-agent.service.d
printf '[Service]\nLogLevelMax=notice\n' > /etc/systemd/system/qemu-guest-agent.service.d/10-loglevel.conf
systemctl enable qemu-guest-agent 2>/dev/null || true

log "account ids and versions"
jq -n --argjson operator "$(id -u operator)" --argjson observer "$OBSERVER_UID" \
      --argjson git "$(id -u git)" --arg gitea "$GITEA_VERSION" \
      --arg postgres "$(dpkg-query -W -f='${Version}' postgresql)" \
      --arg nginx "$(dpkg-query -W -f='${Version}' nginx)" \
      '{uids: {operator: $operator, observer: $observer, git: $git},
        versions: {gitea: $gitea, postgresql: $postgres, nginx: $nginx}}' > "$OUT/accounts.json"

log "static lab network (takes effect on next boot)"
rm -f /etc/netplan/*.yaml /etc/network/interfaces.d/* /run/systemd/network/*
cat > /etc/systemd/network/10-lab.network <<EOF
[Match]
Name=en* eth*

[Network]
Address=$LAB_TARGET_IP/24
Gateway=$LAB_GATEWAY_IP
LinkLocalAddressing=no
IPv6AcceptRA=no
EOF
systemctl enable systemd-networkd >/dev/null 2>&1
systemctl disable networking >/dev/null 2>&1 || true
systemctl disable systemd-networkd-wait-online >/dev/null 2>&1 || true
# No DNS inside the lab: outbound names are resolved by the egress proxy. Without a resolver
# there is also no reason to keep systemd-resolved (and its LLMNR listener on 5355) around.
systemctl disable --now systemd-resolved >/dev/null 2>&1 || true
systemctl mask systemd-resolved >/dev/null 2>&1 || true
if [ -L /etc/resolv.conf ] || [ -f /etc/resolv.conf ]; then rm -f /etc/resolv.conf; fi
echo "# no resolver: egress goes through the proxy at $PROXY" > /etc/resolv.conf
touch /etc/cloud/cloud-init.disabled
apt-get clean
log "provisioning complete"
