# Changelog

All notable changes to MyScan. The version lives in `src/__init__.py` (must match `pyproject.toml`).

## [Unreleased]

- Bump version metadata to 3.0.1 across code, packaging, UI, and tests.
- **CI wiring** — `.github/workflows/ci.yml` now runs backend tests (Python 3.11/3.12 matrix), ruff lint + docs-sync, and frontend lint + production build.
- **Lint cleanup** — ruff: all 400+ findings resolved (incl. real fixes: missing `time` import in `llm_client`, un-wired `type_resolver_result` in `validation_engine`, missing `Optional` import in `serialization`); frontend: ESLint clean (0 errors/warnings) and `next build` green across all pages.

## [3.0.1] — 2026-07-31

- **SEC001 false-positive fix** — credentials-like patterns no longer trip on benign configuration values.
- **Finding dedup + occurrences** — duplicate findings collapse into a single finding with multiple occurrence locations; totals count occurrences.
- **Enriched reports** — all five formats (markdown, JSON, SARIF, HTML, CSV) carry `version`, branch, commit, rule counts, total vs occurrences, and evidence; CSV output is a fixed 27-column shape.
- **Findings API** — dedicated endpoints for findings list, detail, and bulk triage (suppress / unsuppress / false-positive / assignee), persisted in `finding_state`.
- **Enterprise results UI** — findings table with filters, sort, pagination, bulk triage bar, and a detail view showing `owasp: {code, title}`, state, and evidence.
- **Full documentation suite** — PRD, TRD, architecture, system design, database schema, API reference, folder structure, deployment, Docker, CI/CD, security, authentication, testing, user/admin/developer guides, roadmap, troubleshooting, changelog, and `README.md` (also required by `pyproject.toml`'s `readme` field).
- **`scripts/check_docs_sync.py`** — keeps version, API routes, env vars, CLI commands, and doc links aligned between docs and code.

## [3.0.0] — security hardening

- Server-side hardening: CORS allowlist, per-client rate limiting (sliding window + burst), API-key auth on all `/api/*` routes, constant-time comparison.
- SSRF protection for remote targets (scheme allowlist + private-network blocklist at resolve time) and `MYSCAN_ALLOWED_PATHS` for local scans.
- Secret display modes (`full` / `masked` / `smart`) and stronger secret analysis (strength, crack-time, environment, business impact).
- SSE pipeline fixes (resume, cancel, 30s heartbeat) for the live scan view.
- Dependency scanning with range matching (`>=`, `<=`, `~=`) against advisory data.
- LLM enrichment (`MYSCAN_LLM_ENHANCE`) — AI explanations for findings via OpenAI/Anthropic with timeouts and concurrency caps.
- Repo hygiene: `.gitignore`, `f11e6ec` build-artifact cleanup.

## [3.0.0 Phase 2] — analysis depth

- Import resolver (call graph across files), type inference, and data-flow/taint tracking for supported languages.
- Secret Engine 2.0 (entropy + context + validation).
- Code validation, evidence capture, and auto-fix suggestions.
- 47 security rules + 10 quality rules catalogued in `config/patterns.yaml`.

## [3.0.0 Enterprise] — platform foundation

- Multi-language AST parsing via tree-sitter (Python, JavaScript, TypeScript, Java, Go, PHP, C/C++, C#, Rust, Ruby).
- Security scanner (CWE/OWASP/CVSS), quality scanner, secrets scanner, dependency analyzer.
- REST API + web UI (dashboard, scan, results, analytics), CLI, and five report exporters.

## Format

Entries follow [Keep a Changelog](https://keepachangelog.com/). Version numbers are semantic (vMAJOR.MINOR.PATCH). The `[Unreleased]` section describes work on the current branch not yet tagged.
