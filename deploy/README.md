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
| `scanner` container (git + Trivy) | `code-guardian-scanner.service` (`ROLE=scanner`, `127.0.0.1:8796`, `MemoryMax=1G`) |
| — | the service itself: `MemoryMax=150M` (hard, no swap), `OOMPolicy=continue` |

git and Trivy run in `code-guardian-scanner.service`, so the service's 150 MB budget covers only the service.
Both units run as the static `codeguardian` user and share `/var/lib/code-guardian/work`
(`useradd --system codeguardian`; `SCANNER_TOKEN` in `/etc/code-guardian/env`).

```bash
# release
npm ci && npm run build
mkdir -p /opt/code-guardian && cp -r dist package.json package-lock.json /opt/code-guardian/
(cd /opt/code-guardian && npm ci --omit=dev)
(cd web && npx vite build --outDir /var/www/oxhometask --emptyOutDir)

# services (TRIVY_TOKEN lives in /etc/code-guardian/env, mode 600)
cp deploy/systemd/*.service /etc/systemd/system/ && systemctl daemon-reload   # trivy, scanner, service
systemctl enable --now code-guardian-trivy code-guardian code-guardian-scanner

# proxy: append deploy/Caddyfile.snippet to /etc/caddy/Caddyfile, then
caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy
```

Public-facing hardening on top of the defaults: `MAX_QUEUED=10`, `RATE_LIMIT_PER_MIN=10`, `CPUQuota=60%`, and
`MIN_FREE_DISK_MB=2048`.
