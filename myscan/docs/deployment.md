# Deployment Guide — CodeWatch

## 1. Deployment options

| Option | Use case |
|---|---|
| **Docker Compose** | Recommended — runs API + web UI with one command |
| **Bare metal / VM** | When you want OS-level control (see §3) |
| **CLI in CI** | Pipe scanners into pipelines (no server required) |

## 2. Docker Compose (recommended)

Prerequisites: Docker Engine 20.10+ with Compose v2.

```bash
cd myscan
cp .env.example .env
# Edit .env: set MYSCAN_API_KEY, MYSCAN_ALLOWED_PATHS, provider keys as needed
docker compose up --build -d
docker compose ps
```

Services:

- **api** → `http://<host>:8443` (waitress; SQLite on the `myscan_data` volume at `/data/myscan.db`)
- **frontend** → `http://<host>:3000` (Next.js; proxies `/api/*` to `api:8443`)

Stop / logs:

```bash
docker compose down          # keep volume
docker compose down -v       # destroy data volume
docker compose logs -f api frontend
```

See [docker.md](docker.md) for the full image/Compose reference.

## 3. Bare-metal deployment

### Backend

```bash
# Python >= 3.11
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt  # or: pip install -e .
python run_api.py                # waitress on :8443
```

Systemd unit (`/etc/systemd/system/myscan-api.service`):

```ini
[Unit]
Description=CodeWatch API
After=network.target

[Service]
WorkingDirectory=/opt/myscan
ExecStart=/opt/myscan/.venv/bin/python run_api.py
EnvironmentFile=/opt/myscan/.env
Restart=always
User=myscan
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now myscan-api
```

### Frontend

```bash
cd frontend
npm ci
npm run build
# API_BASE_URL and MYSCAN_API_KEY must be set in the process environment
API_BASE_URL=http://localhost:8443 MYSCAN_API_KEY=... npm run start -- -p 3000
```

Use a process manager (systemd, PM2, or a container) for the frontend process. The Next.js build output is self-contained (`.next/` + `public/` + `next.config.ts`).

## 4. Reverse proxy

Place nginx (or Caddy/Traefik) in front for TLS + buffering.

nginx:

```nginx
server {
    listen 443 ssl;
    server_name scan.example.com;
    ssl_certificate     /etc/ssl/fullchain.pem;
    ssl_certificate_key /etc/ssl/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # SSE: disable buffering for the events endpoint
    location /api/v1/scan/ {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 300s;
    }
}
```

> If you proxy the API directly (not through the frontend), set `MYSCAN_TRUST_PROXY=1` so rate limiting uses the real client IP from `X-Forwarded-For`.

## 5. TLS

- Terminate TLS at the reverse proxy (nginx/Caddy/Traefik).
- CodeWatch itself does not serve TLS (plain HTTP on 8443); do not expose 8443 publicly without TLS or a proxy.

## 6. Data & persistence

- SQLite database: default `src/myscan.db`; in Docker at `/data/myscan.db` (named volume `myscan_data`).
- Backups: stop the API (or copy with SQLite's online backup) and copy the `.db`, `-wal`, and `-shm` files together.
- Retention: `max_history` setting prunes old scans; the in-memory job cache is capped at 200.
- Reports written by the CLI go to `myscan_reports/` (local) — gitignored.

## 7. Hardening checklist

- [ ] Set a strong `MYSCAN_API_KEY` (never leave it empty in production).
- [ ] Set `MYSCAN_ALLOWED_PATHS` to the directories that may be scanned.
- [ ] Set `MYSCAN_CORS_ORIGINS` to your exact UI origin (no `*` in production).
- [ ] Keep `MYSCAN_RATE_LIMIT`/`MYSCAN_RATE_LIMIT_BURST` sane (defaults fine).
- [ ] Terminate TLS at a reverse proxy; keep 8443 on a private network.
- [ ] If behind a proxy, set `MYSCAN_TRUST_PROXY=1` **and** ensure the proxy overwrites `X-Forwarded-For`.
- [ ] Run as a dedicated, unprivileged user (systemd `User=`/`NoNewPrivileges`).
- [ ] Configure `secret_display=smart` (default) or `masked`; avoid `full` unless required.
- [ ] If enabling LLM enrichment, use a scoped/rotatable provider key.

## 8. Verifying a deployment

```bash
curl -s http://localhost:8443/health
# {"status":"healthy","version":"3.0.0","timestamp":"…","auth":true}

curl -s -H "X-API-Key: $MYSCAN_API_KEY" http://localhost:3000/api/v1/history?limit=1

# E2E smoke: start a scan through the UI proxy
curl -s -X POST http://localhost:3000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"/data/targets/example-repo","threads":2}'
```

## 9. Upgrades

1. `git pull` (or pull new image tag).
2. Review [CHANGELOG.md](../CHANGELOG.md) for breaking changes.
3. Rebuild: `docker compose up --build -d`.
4. Schema is additive (`_migrate`) — the database is upgraded automatically on first request.
5. Verify `/health` and run a smoke scan.
