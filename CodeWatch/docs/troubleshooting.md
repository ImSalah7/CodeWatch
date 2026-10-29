# Troubleshooting — CodeWatch

## 1. Common problems

### UI shows `401` on every page

Both services must share the same key:

- The API rejects requests without a valid `MYSCAN_API_KEY`.
- The Next.js proxy injects the key server-side from the **frontend's** environment.
- Set the same value in both `api` and `frontend` (see [docker.md](docker.md) §5, [deployment.md](deployment.md) §7).

### Local scan path is refused

- If `MYSCAN_ALLOWED_PATHS` is set, the resolved path must sit inside one of the allowed bases.
- `/etc`, `/usr`, and `C:\Windows` are always refused (case-insensitive), even without the allowlist.
- Paths are capped at 4096 characters.

### Remote clone fails

- Allowed schemes: `http`, `https`, `git`, `ssh`. `file://`, `ftp://`, etc. are rejected.
- Private-network addresses are blocked (SSRF guard): RFC1918, loopback, link-local, CGNAT, ULA, IPv4-mapped, reserved ranges.
- If you *must* scan a private host, run the API on the same network as the target **without** exposing it publicly.

### `429 Rate limit exceeded`

- Defaults: 300 req/min and 60 req/s burst per client.
- Raise `MYSCAN_RATE_LIMIT`/`MYSCAN_RATE_LIMIT_BURST`, or reduce polling frequency (e.g. SSE clients should rely on events, not polling).

### Rate limits appear to target the wrong client

- Behind a reverse proxy, CodeWatch sees the proxy's IP unless `MYSCAN_TRUST_PROXY=1` is set **and** the proxy sets/overwrites `X-Forwarded-For`.

### Secrets are visible in reports

- `secret_display` defaults to `smart`. Set `masked` (always `prefix••••suffix`) or `full` explicitly via the CLI flag / config.
- HTML reports show a red banner when secrets are displayed in full.

### CORS errors in the browser

- The API must allow your exact origin. Set `MYSCAN_CORS_ORIGINS` to `http://localhost:3000,http://127.0.0.1:3000` (Compose default) or your production origin.
- The web UI normally avoids this by going through the Next proxy (`/api/*` same-origin).

### Scan hangs / no live progress

- SSE: clients should reconnect on `error` events; the API sends a 30s heartbeat.
- Check `GET /api/v1/scan/{id}` for current status; a crashed worker leaves a stale job (retry with a new scan).
- In-memory job cache is capped at 200 — very long-running scans may be evicted from the live view (results remain in history).

## 2. Backend

### API won't start (port in use)

```bash
# Windows
netstat -ano | findstr 8443
# macOS/Linux
lsof -i :8443
```

### Database errors

- SQLite uses WAL — keep `.db`, `-wal`, `-shm` together.
- If the file is corrupt: restore from backup, or move it aside (`codewatch.db` is regenerated empty) and re-run scans.
- Schema migrations are additive and run automatically (`_migrate`) on first request.

### Missing optional features (tree-sitter, waitress)

- The scanner gracefully falls back when tree-sitter grammars aren't installed (regex/pattern-based detection).
- Waitress is optional: without it, `run_api.py` falls back to the Flask dev server (not for production).

## 3. Frontend

### `npm run dev` cannot reach the API

- Set `API_BASE_URL=http://localhost:8443` in the frontend process environment.
- Verify the API is up: `curl http://localhost:8443/health`.

### Build fails

```bash
cd frontend
npm ci           # clean install (locks versions)
npm run build
```

Known: `results/page.tsx` must wrap the client component in `<Suspense>` and pass `initialJobId` via a prop (Next's `useSearchParams` constraint) — don't revert that pattern.

## 4. Tests / CI

### Local pytest failures but CI green

- Confirm you installed `requirements.txt` into the active virtualenv.
- The suite is hermetic — no network or external services needed.

### CI skips linting

- The workflow's `lint` and `frontend` jobs run `ruff check`/docs-sync and ESLint+`next build`. mypy is not yet wired in — see [ci-cd.md](ci-cd.md) §4. Run locally: `python -m ruff check src tests scripts && python scripts/check_docs_sync.py`.

## 5. LLM / AI explanations

- No explanations appear → `MYSCAN_LLM_ENHANCE=0`, missing provider key, or the provider env mismatch (`OPENAI_API_KEY` vs `ANTHROPIC_API_KEY` with `MYSCAN_AI_PROVIDER`).
- Enrichment is capped at `MYSCAN_LLM_MAX_FINDINGS` (default 20) per scan.
- Timeouts are bounded by `MYSCAN_LLM_TIMEOUT` (s) with `MYSCAN_LLM_CONCURRENCY` workers.

## 6. Getting help

- Open an issue at the repository (once the remote is configured).
- Include: CodeWatch version (`python -m src.cli --version`), OS, scan target type (local/git), the failing report format if relevant, and sanitized error output.
