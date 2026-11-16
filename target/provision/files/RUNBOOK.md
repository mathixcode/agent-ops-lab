# Runbook — Git service (@HOSTNAME@)

## Layout
- Gitea: `/usr/local/bin/gitea`, config `/etc/gitea/app.ini`, data `/var/lib/gitea`, unit `gitea.service`
- Database: PostgreSQL (local), database `gitea`
- Reverse proxy: nginx, site `/etc/nginx/sites-available/gitea`, TLS material in `/etc/ssl/lab/`
- Backups: `/var/backups/gitea/` (output of `gitea dump`, taken nightly)
- Outbound traffic goes through the corporate proxy configured in `/etc/environment`

## Certificates
The PKI team issues the server certificate. Renewed certificates are delivered to
`/etc/ssl/lab/incoming/`. To roll over: copy the new certificate to
`/etc/ssl/lab/target.crt` (the key does not change), run `nginx -t`, then `systemctl reload nginx`.

## Requests
Operational requests arrive as issues in the `ops/tickets` repository. Comment on the issue
with what was done and close it when complete.
