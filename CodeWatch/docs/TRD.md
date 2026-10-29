# Technical Requirements Document (TRD) — CodeWatch

> Version 3.0.0 · Status: Active · Applies to codebase at commit `c35443c`

## 1. Overview

This document specifies the technical requirements and constraints for CodeWatch. It is the authoritative reference for how the system is built and how its parts interoperate, complementing [architecture.md](architecture.md) and [system-design.md](system-design.md).

## 2. Technology stack

| Layer | Technology | Constraint |
|---|---|---|
| Language | Python | `>= 3.11` |
| Web framework | Flask | `>= 3.0` |
| WSGI server | waitress | `>= 3.0` (threads=16, channel_timeout=600) |
| Database | SQLite | WAL mode; file path via `MYSCAN_DB` (default `src/codewatch.db`) |
| Parsing | tree-sitter `>=0.21` + 9 language grammars | Python, JS, TS, Java, Go, PHP, C/C++, C#, Rust, Ruby |
| Graph analysis | networkx `>=3.2` | call graph, reachability |
| Serialization | orjson `>=3.9` | fast JSON |
| CLI | click `>=8.1`, rich `>=13.0` | |
| LLM | openai / anthropic / google-generativeai | optional (`[ai]` extra) |
| Web UI | Next.js **16.2.12**, React **19.2.4** | TypeScript, Tailwind v4, Recharts, framer-motion, lucide-react |
| Container | Docker (`python:3.13-slim` backend, `node:22-alpine` frontend) | docker-compose runs both |
| CI | GitHub Actions | Ubuntu, Python 3.11/3.12 matrix |

## 3. Runtime requirements

### 3.1 Backend entry points

- `python run_api.py` — production server. Reads `MYSCAN_HOST` (default `0.0.0.0`), `MYSCAN_PORT` (default `8443`), `MYSCAN_DEBUG`. Prefers waitress; falls back to Flask dev server.
- `codewatch` console script (from `src/cli.py`): subcommands `scan`, `quick`, `info`, `benchmark`.
- `src.api.create_app(config=None)` — programmatic Flask app factory (ensures settings file + `store.init_store()`).

### 3.2 Database

- SQLite at `MYSCAN_DB` or `src/codewatch.db`; `PRAGMA journal_mode=WAL`; parent directory auto-created.
- Tables: `scans`, `findings`, `finding_state` (see [database-schema.md](database-schema.md)).
- Additive schema migrations via `_migrate(conn)` using `PRAGMA table_info` checks (no migration framework).

### 3.3 Settings

Persisted to `src/myscan_settings.json` (auto-created). Defaults:

| Setting | Default |
|---|---|
| `threads` | 4 |
| `min_confidence` | 0.2 |
| `enterprise_mode` | false |
| `secret_display` | smart |
| `max_file_size_kb` | 1024 |
| `include_tests` / `include_docs` / `include_examples` | false |
| `max_history` | 50 |
| `report_format` | markdown |
| `notifications.scan_complete` / `critical_findings` / `scan_failed` | true |

## 4. Functional requirements (technical)

### TR-1 Scan lifecycle

1. `POST /api/v1/scan` validates target (SSRF/path guards), returns `202 {job_id, status: pending}`.
2. Background thread: status `running` → clone remote (shallow) → run engine → attach repo metadata → apply secret display → optional LLM enhancement → persist `scans` + `findings` → status `completed`/`failed`.
3. Progress is streamed over SSE (`GET /api/v1/scan/<id>/events`); frontend also polls as a fallback.
4. History retention: `store.prune_history(max_history)`; in-memory job cache capped at 200.

### TR-2 Scan engines

- **Standard mode:** `ScanEngine.scan` runs regex scanners (`SecurityScanner`, `QualityScanner`, `SecretsScanner`) per file, fingerprints (`sha256(rule_id:path:line:title)[:16]`), validates false positives, dedups, groups duplicates.
- **Enterprise mode:** `AnalysisPipeline` runs file indexing → AST → data flow → taint → context → risk → confidence → dedup, plus call-graph vulnerable paths and validation. Findings are enriched with fixes, AI explanations, secret analysis.
- Rules executed count is always recorded; 57 rules total (47 SEC + 10 QLT).

### TR-3 Rule model

`Rule{id, title, description, severity, confidence, category, cwe, cwe_name, owasp, languages, fix_suggestion, references, impact, pattern, pattern_type, tags, cvss_config}` with `get_cvss()`. Rules are language-gated (empty `languages` = all languages).

### TR-4 Reporting

- Reporter registry `REPORTERS = {markdown, json, sarif, html, csv}`; each exposes `generate(result: ScanResult) -> str`.
- All reports include repository metadata (branch, commit, repo size), scan ID/timestamps, version, severity counts, and per-finding evidence/occurrences/references (up to 5 references in HTML/Markdown/SARIF).

### TR-5 Findings & triage

- `GET /api/v1/findings` supports: `category, severity, rule_id, cwe, owasp, language, file_ext, status(false_positive|real), include_suppressed, min_cvss, min_confidence, search, sort(severity|cvss|confidence|file|rule|line), order(asc|desc), limit(1-500), offset`.
- `POST /api/v1/findings/bulk` actions: `suppress, unsuppress, mark_false_positive, unmark_false_positive, assign, create_issue`.
- Triage state is stored in `finding_state` (composite PK `scan_id + fingerprint`) and merged into findings responses.

### TR-6 Security requirements

- API key auth when `MYSCAN_API_KEY` is set (all `/api/*`; `/health` always open).
- Constant-time comparison; rate limit (sliding window) + burst cap; CORS allowlist; SSRF guards on remote targets; local path allowlist.
- Secrets masked by default in API/UI/reports (`smart` mode).

## 5. Non-functional requirements

| # | Requirement | Verification |
|---|---|---|
| NFR-1 | `pytest` suite passes: **574 tests** | `python -m pytest tests -q` |
| NFR-2 | Lint: ruff, line-length 120 | `python -m ruff check src tests` |
| NFR-3 | Type hints: mypy strict-ish (`disallow_untyped_defs`) | `python -m mypy src` |
| NFR-4 | Frontend type-checks and builds | `npm run build` (includes `tsc`) |
| NFR-5 | Frontend lints clean for new code | `npm run lint` |
| NFR-6 | Docs in sync with code | `python scripts/check_docs_sync.py` |
| NFR-7 | Docker Compose brings up api + frontend | `docker compose up --build -d` |
| NFR-8 | Backend handles SSE with 30s heartbeat | integration tests |
| NFR-9 | Scan of large repos bounded by file filters + threads | `--threads`, `max_file_size_kb` |

## 6. API constraints

- Content type for reports: `json`→`application/json`, `markdown`→`text/markdown`, `html`→`text/html`, `sarif`→`application/sarif+json`, `csv`→`text/csv`.
- `POST /api/v1/scan` body: `{target (required, ≤4096 chars), enterprise, threads (1–32), min_confidence (0–1), secret_display (smart|masked|full)}`.
- Findings in scan-status responses are truncated to 200.
- See [api.md](api.md) for the full contract.

## 7. Data retention & cleanup

- `max_history` prunes old scans and findings.
- In-memory scan history capped at 200 jobs; stale entries evicted.
- Remote clone temp directories cleaned after each scan (robust `rmdir` fallback on Windows) and on process exit (`atexit`).

## 8. Compatibility

- Windows, macOS, Linux (Windows-tested; `cmd /c rmdir` fallback in clone cleanup).
- Python 3.11–3.13.
- Browsers: modern evergreen (Next.js 16 default targets).
