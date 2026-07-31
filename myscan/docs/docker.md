# Docker — MyScan

## 1. Images

### Backend (`myscan/Dockerfile`)

- Base: `python:3.13-slim`, `WORKDIR /app`
- Env: `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUNBUFFERED=1`
- Installs `requirements.txt` (`--no-cache-dir`), then `pip install -e .` (needs `pyproject.toml`, `src/`, `run_api.py`, `README.md`)
- `EXPOSE 8443`, `CMD ["python", "run_api.py"]` → waitress (16 threads), falls back to the Flask dev server

### Frontend (`myscan/frontend/Dockerfile`)

Two-stage:

- **builder** `node:22-alpine`: `npm ci` → copy app → `npm run build`
- **runner** `node:22-alpine`: `NODE_ENV=production`, `npm ci --omit=dev`, copy `.next`, `public`, `next.config.ts`, `next-env.d.ts`; `EXPOSE 3000`, `CMD ["npm", "run", "start", "--", "-p", "3000"]`

## 2. Compose (`docker-compose.yml`)

```yaml
services:
  api:
    build: .
    ports: ["8443:8443"]
    environment:
      MYSCAN_API_KEY: ${MYSCAN_API_KEY:-}
      MYSCAN_RATE_LIMIT: ${MYSCAN_RATE_LIMIT:-300}
      MYSCAN_RATE_LIMIT_BURST: ${MYSCAN_RATE_LIMIT_BURST:-60}
      MYSCAN_CORS_ORIGINS: ${MYSCAN_CORS_ORIGINS:-http://localhost:3000,http://127.0.0.1:3000}
      MYSCAN_ALLOWED_PATHS: ${MYSCAN_ALLOWED_PATHS:-/data/targets}
      MYSCAN_DB: /data/myscan.db
      MYSCAN_TRUST_PROXY: "0"
      OPENAI_API_KEY: ${OPENAI_API_KEY:-}
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY:-}
      MYSCAN_AI_PROVIDER: ${MYSCAN_AI_PROVIDER:-openai}
    volumes:
      - myscan_data:/data
    restart: unless-stopped

  frontend:
    build: ./frontend
    ports: ["3000:3000"]
    environment:
      API_BASE_URL: http://api:8443
      MYSCAN_API_KEY: ${MYSCAN_API_KEY:-}
    depends_on: [api]
    restart: unless-stopped

volumes:
  myscan_data:
```

Notes:

- `MYSCAN_DB=/data/myscan.db` persists on the `myscan_data` named volume.
- `MYSCAN_ALLOWED_PATHS` defaults to `/data/targets` in Compose — mount or copy repositories there so they can be scanned.
- The frontend injects `MYSCAN_API_KEY` into proxied API requests server-side.

## 3. Usage

```bash
# Build & start
docker compose up --build -d

# Rebuild after code changes
docker compose build api frontend && docker compose up -d

# Logs
docker compose logs -f api
docker compose logs -f frontend

# Shell into the API container (debugging)
docker compose exec api sh

# Reset everything (destroys the SQLite volume)
docker compose down -v
```

## 4. Volume & data

| Path in container | Purpose |
|---|---|
| `/data/myscan.db` | SQLite database (WAL; keep `-wal`/`-shm` alongside for backups) |
| `/data/targets` | Default scan root (override with `MYSCAN_ALLOWED_PATHS`) |

Backup the volume with:

```bash
docker run --rm -v myscan_data:/data -v "$PWD":/backup alpine tar czf /backup/myscan_data.tgz -C /data .
```

## 5. Environment quick reference

| Variable | Compose default | See |
|---|---|---|
| `MYSCAN_API_KEY` | empty (auth off!) | [security.md](security.md) |
| `MYSCAN_RATE_LIMIT` / `MYSCAN_RATE_LIMIT_BURST` | 300 / 60 | security.md |
| `MYSCAN_CORS_ORIGINS` | `http://localhost:3000,…` | security.md |
| `MYSCAN_ALLOWED_PATHS` | `/data/targets` | security.md |
| `MYSCAN_DB` | `/data/myscan.db` | [database-schema.md](database-schema.md) |
| `MYSCAN_TRUST_PROXY` | 0 | security.md |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `MYSCAN_AI_PROVIDER` | empty | [TRD.md](TRD.md) §9 |
| `API_BASE_URL` | `http://api:8443` | frontend proxy |

## 6. Troubleshooting images

- **Backend container won't start** → check `docker compose logs api`; verify the `pip install -e .` step completed (requires `README.md` present — it is in this repo).
- **Frontend proxy 502s** → ensure `api` is healthy and `API_BASE_URL=http://api:8443`; verify with `docker compose exec frontend wget -qO- http://api:8443/health`.
- **Auth required but UI shows 401** → the `api` and `frontend` containers must share the same `MYSCAN_API_KEY`.
