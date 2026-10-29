# Admin Guide — CodeWatch

Operations guide for the person running CodeWatch in production.

## 1. Installation

- Docker: see [docker.md](docker.md) and [deployment.md](deployment.md) §2.
- Bare metal: see [deployment.md](deployment.md) §3.

## 2. First-run checklist

- [ ] Set `MYSCAN_API_KEY` (see [authentication.md](authentication.md)).
- [ ] Configure `MYSCAN_ALLOWED_PATHS` to the directories operators may scan.
- [ ] Configure `MYSCAN_CORS_ORIGINS` to the UI origin.
- [ ] Put TLS in front (reverse proxy) — see [deployment.md](deployment.md) §4–5.
- [ ] Optional: configure LLM provider keys for AI explanations.
- [ ] Verify: `curl http://localhost:8443/health` and a smoke scan from the UI.

## 3. Day-to-day operations

### Health

```bash
curl http://localhost:8443/health
# {"status":"healthy","version":"3.0.0","timestamp":"…","auth":true}
```

The endpoint is unauthenticated so load balancers/monitoring can probe it.

### Starting & stopping

```bash
# Docker
docker compose up -d
docker compose down

# Bare metal
python run_api.py
cd frontend && npm run start -- -p 3000
```

### Logs

- Compose: `docker compose logs -f api frontend`.
- Bare metal: journald (`journalctl -u myscan-api`) or your process manager.

## 4. Monitoring

- **Rate limiting:** clients that exceed `MYSCAN_RATE_LIMIT` get `429`; monitor for spikes.
- **Scan job cache:** in-memory, capped at 200 jobs; long-running or many concurrent scans will evict old entries (their results still live in the SQLite history).
- **Disk:** SQLite grows with scan history; set `max_history` to prune old scans.
- **LLM:** per-finding timeouts (`MYSCAN_LLM_TIMEOUT`) and concurrency (`MYSCAN_LLM_CONCURRENCY`) bound provider load.

## 5. Backups

The only state is the SQLite database (default `src/codewatch.db`, or `/data/codewatch.db` in Docker). Back it up with SQLite's online backup or by copying `.db` + `-wal` + `-shm` together while the API is stopped. See [deployment.md](deployment.md) §6.

## 6. Upgrading

1. Review [CHANGELOG.md](../CHANGELOG.md).
2. Pull new code / image, rebuild: `docker compose up --build -d`.
3. Schema migration is automatic (`_migrate`, additive only) on first request.
4. Smoke test: `/health` + one scan + one report export.

## 7. Config reference

Admin-relevant environment variables — full list in [security.md](security.md) §2:

| Variable | Default | Admin purpose |
|---|---|---|
| `MYSCAN_HOST` / `MYSCAN_PORT` | `0.0.0.0` / `8443` | API bind |
| `MYSCAN_DB` | `src/codewatch.db` | Database location |
| `MYSCAN_RATE_LIMIT` / `MYSCAN_RATE_LIMIT_BURST` | `300` / `60` | DoS protection |
| `MYSCAN_ALLOWED_PATHS` | *(empty)* | Which paths can be scanned |
| `MYSCAN_CORS_ORIGINS` | *(empty)* | Browser origin allowlist |
| `MYSCAN_TRUST_PROXY` | `0` | Trust `X-Forwarded-For` |
| `MYSCAN_LLM_ENHANCE` | `1` | Toggle AI explanations |
| `MYSCAN_LLM_MAX_FINDINGS` | `20` | Cap on enriched findings |
| `MYSCAN_LLM_TIMEOUT` / `MYSCAN_LLM_CONCURRENCY` | `30` / `4` | LLM limits |

### Triage / state management

Operators manage finding dispositions through the UI (bulk triage bar). The stored state includes:

- `status` (`open` / `suppressed` / `false_positive`),
- `assignee` (owner),
- `notes`, `resolved_at`, `resolved_by`.

Changes persist and are shown on re-scans.

## 8. Troubleshooting index

| Symptom | Fix |
|---|---|
| UI shows 401 | `api` and `frontend` must share the same `MYSCAN_API_KEY` |
| Scan of a path refused | Check `MYSCAN_ALLOWED_PATHS`; path must be inside an allowed base |
| Remote clone refused | Target is on a private-network address (SSRF guard) |
| 429s from automation | Raise `MYSCAN_RATE_LIMIT` or batch requests |
| Wrong client IP in rate limit | Set `MYSCAN_TRUST_PROXY=1` behind your proxy |
| Secrets shown in reports | Set `secret_display=masked` (or `smart`) |
| Slow scans | Reduce `--threads`; disable LLM enrichment |

Full list: [troubleshooting.md](troubleshooting.md).
