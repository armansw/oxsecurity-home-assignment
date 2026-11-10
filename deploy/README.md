# Bare-metal deployment (systemd + Caddy)

How the live demo at https://oxhometask.armstep.com runs, on a shared host without Docker. The same limits as
`docker-compose.yml`, expressed as systemd cgroup settings:

| docker-compose | systemd (`code-guardian.service`) |
|---|---|
| `mem_limit: 200m` | `MemoryMax=200M` |
| `memswap_limit: 200m` (no swap) | `MemorySwapMax=0` |
| non-root user, `no-new-privileges` | `DynamicUser=yes`, `NoNewPrivileges=yes`, `ProtectSystem=strict` |
| named volumes `app-data`, `app-work` (disk-backed) | `StateDirectory=code-guardian` → `/var/lib/code-guardian` |
| `trivy` sidecar | `code-guardian-trivy.service`, listening on `127.0.0.1:4954` only |

The Trivy client and git run *inside* `code-guardian.service`'s cgroup, so the 200 MB budget covers them too,
exactly as in the container.

```bash
# release
npm ci && npm run build
mkdir -p /opt/code-guardian && cp -r dist package.json package-lock.json /opt/code-guardian/
(cd /opt/code-guardian && npm ci --omit=dev)
(cd web && npx vite build --outDir /var/www/oxhometask --emptyOutDir)

# services (TRIVY_TOKEN lives in /etc/code-guardian/env, mode 600)
cp deploy/systemd/*.service /etc/systemd/system/ && systemctl daemon-reload
systemctl enable --now code-guardian-trivy code-guardian

# proxy: append deploy/Caddyfile.snippet to /etc/caddy/Caddyfile, then
caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy
```

Public-facing hardening on top of the defaults: `MAX_QUEUED=10`, `RATE_LIMIT_PER_MIN=10`, `CPUQuota=60%`, and
`MIN_FREE_DISK_MB=2048`.
