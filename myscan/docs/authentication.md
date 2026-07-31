# Authentication — MyScan

## 1. Overview

MyScan authenticates **API clients** with a single shared API key. There is no user database, no UI login, and no per-user roles (those are roadmap items).

- The key is configured via the `MYSCAN_API_KEY` environment variable.
- **Empty `MYSCAN_API_KEY` = authentication disabled** (local development only).
- When set, every `/api/*` route requires a valid key; `/health` stays public.

## 2. Sending the key

The API accepts four transports, in this order of preference:

```bash
# 1. Bearer
curl -H "Authorization: Bearer $MYSCAN_API_KEY" http://host:8443/api/v1/history

# 2. Basic auth (key as the password; username ignored)
curl -u "myscan:$MYSCAN_API_KEY" http://host:8443/api/v1/history

# 3. X-API-Key header
curl -H "X-API-Key: $MYSCAN_API_KEY" http://host:8443/api/v1/history

# 4. Query token
curl "http://host:8443/api/v1/history?token=$MYSCAN_API_KEY"
```

## 3. Behavior

- Valid key → `200`/`20x` as usual.
- Missing/invalid key → `401` with `WWW-Authenticate: Bearer realm="myscan"`.
- Rate limits still apply after authentication.
- Comparison uses constant-time `hmac.compare_digest`, so timing attacks do not leak key prefixes.

## 4. Frontend proxy

The web UI never holds the key in the browser:

1. The Next.js server reads `MYSCAN_API_KEY` from its environment.
2. `frontend/src/proxy.ts` rewrites `/api/*` and `/health` requests to the backend.
3. It injects the key as `?token=…` server-side on proxied requests.

This is why both `api` and `frontend` services must be configured with the **same** `MYSCAN_API_KEY` (see [docker.md](docker.md)).

## 5. Server launcher

The API server is launched with `run_api.py` (waitress, 16 threads). The key is read from the process environment:

```bash
MYSCAN_API_KEY=… python run_api.py
# MyScan API listening on http://0.0.0.0:8443 (waitress)
```

## 6. Operational guidance

- Use a long random value: `openssl rand -hex 32`.
- Rotate by updating the env var and restarting both services.
- Keep it out of version control — use your platform's secret store or the compose `.env` file (gitignored).
- `/health` is intentionally unauthenticated so load balancers can probe without the key.
