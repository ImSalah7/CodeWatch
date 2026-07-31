# Developer Guide — MyScan

## 1. Repository layout

```
myscan/
├── src/                      # Python backend
│   ├── api.py                # Flask app + REST API (20 routes)
│   ├── cli.py                # Click CLI (scan, quick, info, benchmark)
│   ├── scan.py               # Orchestrator
│   ├── models.py             # DB models (scan, finding, finding_state)
│   ├── database.py           # SQLite (WAL), migration (_migrate)
│   ├── exporters/            # markdown/json/sarif/html/csv + icsv
│   ├── core/                 # rules, engine, scanner, tree-sitter…
│   ├── security/             # secret & security analyzers
│   ├── ai/                   # LLM enrichment / explainer
│   └── utils.py
├── frontend/                 # Next.js 16 UI (React 19, Tailwind v4)
│   ├── src/app/              # pages (dashboard, scan, results, findings, …)
│   ├── src/components/       # findings table, filters, triage bar, charts
│   ├── src/lib/              # api client, types
│   └── src/proxy.ts          # server-side API proxy + key injection
├── config/patterns.yaml      # detection patterns (language/rule catalog)
├── tests/                    # pytest suite
├── scripts/check_docs_sync.py
├── run_api.py                # waitress launcher
├── Dockerfile, docker-compose.yml, .env.example
├── pyproject.toml, requirements.txt
├── README.md, CHANGELOG.md
└── docs/                     # this documentation suite
```

Full detail: [folder-structure.md](folder-structure.md), [architecture.md](architecture.md).

## 2. Local development

```bash
# Backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/ -q
python run_api.py                       # API on :8443

# Frontend (second terminal)
cd frontend
npm ci
API_BASE_URL=http://localhost:8443 MYSCAN_API_KEY=... npm run dev   # UI on :3000
```

No external services required. The 405-test suite is hermetic (tmp dirs, in-memory DB).

## 3. Code conventions

- **Backend:** Python 3.11+, type hints on public functions, no external deps beyond `flask`, `click`, `requests`, `waitress` (optional), tree-sitter (optional). Keep `src/` importable as a package; run the app via `run_api.py`.
- **Frontend:** React Server Components where possible; client components under `src/components/`; typed API client in `src/lib/`. Styling is Tailwind v4 (no custom CSS config needed).
- **Formatting/lint:** `ruff` (CI) and `mypy` for the backend; `eslint` (`npm run lint`) + `next build` (type-check) for the frontend.
- **Comments:** only where they explain *why*; match surrounding style.

## 4. Common tasks

### Add a detection rule

1. Add the pattern to `config/patterns.yaml` (or the appropriate module in `src/core/`).
2. Give it a `rule_id`, severity, CWE, OWASP code, CVSS base score, and a fix message.
3. Register it so the language router picks it up.
4. Add a fixture under `tests/` and assert detection + severity.

### Add an API endpoint

1. Define the route in `src/api.py` following the existing decorators (auth + rate-limit wrappers).
2. Document it in `docs/api.md` as `METHOD /api/…` (the docs-sync check enforces coverage).
3. Add an integration test in `tests/`.

### Add a new env var

1. Read it in `src/api.py` (or `run_api.py`) with a sane default.
2. Add it to `.env.example`.
3. Document it in `docs/security.md` §2 (and `docs/deployment.md`/`docs/admin-guide.md` if operationally relevant).
4. `scripts/check_docs_sync.py` will verify `.env.example` ↔ docs parity.

### Add a CLI subcommand

1. Add the Click command in `src/cli.py` and register it.
2. Document it in `docs/user-guide.md` §3 — the sync script checks documented subcommand names against `cli.py`.

## 5. Testing guidance

See [testing.md](testing.md). In short:

```bash
python -m pytest tests/ -q
cd frontend && npm run lint && npm run build
python scripts/check_docs_sync.py
```

## 6. The scan pipeline

`TargetResolver` (SSRF/path guards) → checkout/clone → `SecurityScanner` + `SecretsScanner` + quality rules → dedup + occurrence counting → scoring/severity → exporters (all five formats) → persistence + SSE progress events. Details: [system-design.md](system-design.md), [architecture.md](architecture.md).

## 7. Gotchas

- `MYSCAN_API_KEY` set on the API means **every** `/api/*` call needs it — including the Next proxy, which is why the frontend process needs the same key.
- `GET /api/v1/scan/{id}` must specify `?include_findings=true` (or `json=true`) to return findings — otherwise you get the summary only.
- The `finding_state` table (not `findings`) holds triage; rescanning merges prior dispositions by stable rule/path keys.
- The version lives in `src/__init__.py` and must match `pyproject.toml` (docs-sync enforces it).
- Additive schema changes: add to `_migrate`; don't edit existing column definitions.
