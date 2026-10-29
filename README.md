# CodeWatch

**Enterprise AI-Powered SAST Platform** — Static Application Security Testing, secrets detection, code-quality analysis, dependency vulnerability scanning, and SBOM generation.

CodeWatch scans local and remote (git) repositories with a multi-layered analysis engine: regex rule scanning, tree-sitter AST analysis, data-flow/taint tracking, call-graph reachability, and optional LLM-assisted enrichment. Results are exposed through a REST API, a rich Next.js web UI, a CLI, and portable reports (Markdown, HTML, JSON, SARIF, CSV).

- **Version:** 3.0.1
- **License:** MIT
- **Python:** >= 3.11
- **Web:** Next.js 16 / React 19 / Tailwind CSS v4

---

## Table of Contents

- [Features](#features)
- [Architecture at a glance](#architecture-at-a-glance)
- [Quick start](#quick-start)
- [CLI usage](#cli-usage)
- [Web UI](#web-ui)
- [Docker](#docker)
- [Environment variables](#environment-variables)
- [Project structure](#project-structure)
- [Documentation](#documentation)
- [Development](#development)
- [Testing](#testing)
- [CI/CD](#cicd)
- [Security](#security)
- [License](#license)

---

## Features

| Area | Capabilities |
|---|---|
| **Vulnerability scanning** | 47 security rules (SEC001–SEC047) mapped to OWASP Top 10 and CWE — injection, XSS, deserialization, crypto misuse, SSRF, path traversal, hardcoded secrets, insecure config, and more |
| **Enterprise analysis** | AST parsing (10 languages via tree-sitter), data-flow/taint tracking, call-graph construction with reachability, import resolution, type resolution, root-cause analysis |
| **Secrets detection** | 21+ regex patterns (AWS, GitHub, Slack, Stripe, JWT, private keys, high-entropy strings) with entropy analysis and smart display modes (`full`, `masked`, `smart`) |
| **Code quality** | 10 quality rules (QLT001–QLT010): long lines, TODOs, bare excepts, magic numbers, duplicate code, unused imports, commented-out code |
| **Dependency scanning** | requirements.txt, pyproject.toml, package.json, package-lock.json, go.sum, Cargo.lock, Gemfile.lock, Pipfile.lock, poetry.lock with CVE matching |
| **SBOM generation** | CycloneDX 1.5 and SPDX 2.3 output |
| **LLM enhancement** | Optional OpenAI / Anthropic / Gemini enrichment — per-finding explanations, root cause, impact, and secure-fix suggestions |
| **Triage** | Suppress findings, mark false positives, assign owners, link issue URLs — persisted per scan |
| **Deduplication** | Repeated findings grouped into a single primary with `occurrences` and per-location lists |
| **Reports** | Markdown, HTML, JSON, SARIF 2.1.0, CSV — with repository/branch/commit metadata |
| **Policy engine** | PCI-DSS, HIPAA, SOC2 presets with custom policy rules |
| **Benchmarking** | Precision/recall/F1 comparison against Semgrep and Bandit |

## Architecture at a glance

```
┌─────────────────────────────┐     ┌──────────────────────────────┐
│  Next.js web UI (:3000)     │     │  CLI  (codewatch ...)            │
│  proxy.ts injects API key   │     └──────────────┬───────────────┘
└──────────────┬──────────────┘                    │
               │ /api/*, /health                   │ direct
┌──────────────▼──────────────────────────────────▼───────────────┐
│              Flask REST API  (waitress, :8443)                   │
│  scans · findings · triage · reports · history · stats · SBOM    │
│  security.py: API key auth · rate limit · CORS · SSRF guards     │
├──────────────────────────────────────────────────────────────────┤
│              Scan Engine (src/core)                              │
│  rules → scanners → AST/dataflow/taint → validation → dedup      │
│  reachability · root cause · fix generation · LLM enrichment     │
├──────────────────────────────────────────────────────────────────┤
│              SQLite (WAL) — scans · findings · finding_state      │
└──────────────────────────────────────────────────────────────────┘
```

## Quick start

### Backend (API)

```bash
cd CodeWatch
python -m venv .venv && .venv\Scripts\activate     # Windows
python -m pip install -r requirements.txt
python run_api.py                                   # serves on :8443 (waitress)
```

Or install as a package:

```bash
pip install -e .
codewatch --help
```

### Frontend (web UI)

```bash
cd frontend
npm install
npm run dev                                        # http://localhost:3000
```

The frontend proxies `/api/*` to the backend (default `http://localhost:8443`, override with `API_BASE_URL`). In production run `npm run build && npm run start`.

> **Heads-up:** the web UI talks to the API. If the backend is protected by an API key, set `MYSCAN_API_KEY` for the frontend process too — the proxy injects it server-side.

## CLI usage

```bash
# Full scan
codewatch scan <target> [-o report.md] [-f markdown|json|sarif|html|csv]

# Enterprise analysis (AST, data flow, taint tracking)
codewatch scan <target> --enterprise

# Quick risk summary (critical/high only)
codewatch quick <target>

# Rules, languages, severity weights
codewatch info

# Compare against Semgrep / Bandit
codewatch benchmark <target> [--tools semgrep,bandit]
```

Common options for `scan`: `--no-security`, `--no-quality`, `--no-secrets`, `--no-deps`, `--include-tests`, `--include-docs`, `--threads N`, `--severity LEVEL`, `--secret-display full|masked|smart`, `--show-secrets`.

`<target>` can be a local path or a remote git URL (cloned shallowly; SSRF-guarded). Run `codewatch scan --help` for the full list.

## Web UI

| Route | Purpose |
|---|---|
| `/` | Security overview dashboard & KPI metrics |
| `/scan` | Guided scan wizard (Quick / Standard / Enterprise presets) |
| `/results` | Findings table with filters, sort, pagination, bulk triage, export |
| `/findings/[fingerprint]` | Single-finding deep dive |
| `/reports` | Per-scan findings browser + fix suggestions |
| `/settings` | Engine & integration settings |

## Docker

```bash
cd CodeWatch
cp .env.example .env            # set MYSCAN_API_KEY, provider keys
docker compose up --build -d
```

- **api** → `http://localhost:8443` (waitress, SQLite on the `codewatch_data` volume)
- **frontend** → `http://localhost:3000`

See [docs/docker.md](docs/docker.md) for details and [docs/deployment.md](docs/deployment.md) for production guidance.

## Environment variables

All configuration is environment-driven. Key variables (full list in [.env.example](.env.example) and [docs/security.md](docs/security.md)):

| Variable | Default | Purpose |
|---|---|---|
| `MYSCAN_API_KEY` | *(empty = auth off)* | API key required for all `/api/*` routes |
| `MYSCAN_HOST` / `MYSCAN_PORT` | `0.0.0.0` / `8443` | API bind address / port |
| `MYSCAN_RATE_LIMIT` | `300` | Requests per minute per client |
| `MYSCAN_RATE_LIMIT_BURST` | `60` | Burst cap per second |
| `MYSCAN_CORS_ORIGINS` | *(empty)* | Comma-separated allowed origins |
| `MYSCAN_ALLOWED_PATHS` | *(empty)* | Semicolon-separated local scan allowlist |
| `MYSCAN_TRUST_PROXY` | `0` | Trust `X-Forwarded-For` when behind a proxy |
| `MYSCAN_DB` | `src/codewatch.db` | SQLite database path |
| `MYSCAN_LLM_ENHANCE` | `1` | Enable/disable LLM enrichment |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_API_KEY` | — | LLM provider keys |
| `API_BASE_URL` | `http://localhost:8443` | Frontend → backend base URL (frontend proxy) |

## Project structure

```
CodeWatch/
├── run_api.py            # Production entry point (waitress)
├── pyproject.toml        # Package metadata, deps, pytest/ruff/mypy config
├── requirements.txt      # Pinned runtime requirements (Docker/CI)
├── Dockerfile            # Backend container
├── docker-compose.yml    # api + frontend services
├── .env.example          # Environment reference
├── src/
│   ├── api.py            # Flask REST API + SSE
│   ├── cli.py            # Click/Rich CLI
│   ├── store.py          # SQLite persistence
│   ├── security.py       # Auth, rate limiting, CORS, SSRF guards
│   ├── serialization.py  # Result/finding reconstruction
│   ├── progress.py       # ProgressTracker + SSE event queue
│   ├── core/             # Scan engine: rules, engine, pipeline, validation,
│   │                     #   dataflow, call graph, secret engine, risk scoring,
│   │                     #   dedup, dependency scanner, SBOM, policies, plugins
│   ├── scanners/         # security / quality / secrets scanners
│   ├── reporters/        # markdown · html · json · sarif · csv
│   ├── ai/               # LLM client, enhancer, explainer
│   └── codewatch.db         # Default SQLite database (see MYSCAN_DB)
├── frontend/             # Next.js 16 web UI
│   ├── src/app/          # Routes (dashboard, scan, results, reports, …)
│   ├── src/components/   # Page-level client components
│   ├── src/lib/          # api client, types, utils
│   └── src/proxy.ts      # API proxy (injects key server-side)
├── config/patterns.yaml  # Secret-detection patterns
├── tests/                # 574 tests
├── docs/                 # Full documentation suite
└── CHANGELOG.md
```

## Documentation

| Document | Covers |
|---|---|
| [docs/PRD.md](docs/PRD.md) | Product requirements & goals |
| [docs/TRD.md](docs/TRD.md) | Technical requirements |
| [docs/architecture.md](docs/architecture.md) | System architecture & scan pipeline |
| [docs/system-design.md](docs/system-design.md) | Detailed design of each subsystem |
| [docs/folder-structure.md](docs/folder-structure.md) | File-by-file layout |
| [docs/database-schema.md](docs/database-schema.md) | SQLite schema & ERD |
| [docs/api.md](docs/api.md) | REST API reference |
| [docs/deployment.md](docs/deployment.md) | Production deployment guide |
| [docs/docker.md](docs/docker.md) | Docker & Compose guide |
| [docs/ci-cd.md](docs/ci-cd.md) | CI/CD pipelines |
| [docs/security.md](docs/security.md) | Security model & hardening |
| [docs/authentication.md](docs/authentication.md) | API authentication reference |
| [docs/testing.md](docs/testing.md) | Testing strategy & test suite |
| [docs/user-guide.md](docs/user-guide.md) | End-user manual |
| [docs/admin-guide.md](docs/admin-guide.md) | Admin/ops manual |
| [docs/developer-guide.md](docs/developer-guide.md) | Developer onboarding |
| [docs/roadmap.md](docs/roadmap.md) | Roadmap |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common issues & fixes |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Development

```bash
# Backend
python -m pip install -e ".[dev]"      # or pip install -r requirements.txt
python -m pytest tests/ -q             # 574 tests
python -m ruff check src tests         # lint (line-length 120)

# Frontend
cd frontend
npm install
npm run lint
npm run build
```

Docs are kept in sync with the codebase by `scripts/check_docs_sync.py` (runs locally and in CI):

```bash
python scripts/check_docs_sync.py
```

## Testing

- **574 tests** across 23 test modules: scanner correctness (incl. the SQLi parameterization matrix), enterprise analysis modules, reporters, security layer, store persistence, API findings/triage, secret display modes, and full integration tests.
- Fixture target: `tests/fixtures/sample_app/app.py` (a deliberately vulnerable Flask app).
- See [docs/testing.md](docs/testing.md).

## CI/CD

The included GitHub Actions workflow (`main`/`master`, PRs) runs three jobs: backend tests on Python 3.11 and 3.12 plus CLI sanity, ruff lint + docs-sync, and a frontend lint + production build. mypy is not yet wired in (module-resolution issue) — see [docs/ci-cd.md](docs/ci-cd.md).

## Security

- All `/api/*` endpoints are protected by `MYSCAN_API_KEY` when configured (Bearer / Basic / `X-API-Key` / `?token=`).
- Constant-time key comparison, per-client rate limiting, CORS allowlist, SSRF guards for remote targets, and a local path allowlist.
- Secrets are masked by default in reports and UI (`smart` display mode).
- See [docs/security.md](docs/security.md) and [docs/authentication.md](docs/authentication.md).

## License

MIT — see [LICENSE](LICENSE) (or the `license` field in `pyproject.toml`).
