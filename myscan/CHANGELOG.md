# Changelog

All notable changes to MyScan. The version lives in `src/__init__.py` (must match `pyproject.toml`).

## [Unreleased]

- **Secret scan precision hardening** — findings now require multiple corroborating signals before they are reported, eliminating false positives such as `sk-`/`SK` prefixes in unrelated identifiers, prose-like generic API keys (`api_key = "the_application_environment_variable"`), weak passwords (`qwerty123`, `admin123`), uniform-charset values, SQLite URLs without credentials, benign high-entropy strings, and Amazon's documented example keys (`AKIAIOSFODNN7EXAMPLE`).
- **Validation-pipeline secret fixes** — PEM private-key blocks (`-----BEGIN ... PRIVATE KEY-----`) are exempt from the repeated-run weak-value heuristic (the `-----` dashes are structural, not a keyboard walk), so complete keys now survive validation; legacy `SEC017`/`SEC043`-`SEC046` credential rules route through the multi-signal secret gate (they were skipped because `SEC017`.startswith(`"SEC_"`) is false), so placeholders like `api_key = "your-api-key-here"` are rejected while real passwords, AWS keys, and private keys are still reported. Regression coverage added at engine level in `TestEngineLevelValidation`.
  - New `src/core/secret_signals.py` — pure, unit-testable heuristics (placeholder/demo/weak/common-word/prose/uniform-charset detection, variable-name secret hints, known-format prefixes, DB-URL credential checks) and `score_secret(rule_kind, value, variable_name)` which returns a `SecretSignalScore` with a `reject_reason` (drop the finding) or a corroborated `confidence`.
  - Scanner and validation pipeline both apply the signal gate; `ScanConfig.secret_confidence_threshold` (default 0.6) classifies weak-but-passing secrets as likely false positives.
  - Only strong, verified evidence is reported: unsigned JWTs (`alg=none`), bare PEM headers (a header alone is partial — the block must include a base64 body and END marker), and vendor-format values on clearly non-secret identifiers (`trace_id`, `build_id`, `schema_hash`, `session_id`) are rejected as fabricated/partial/unrelated.
  - Each credential yields exactly one finding: higher-confidence rule attributions win over generic duplicates, `SEC_HIGH_ENTROPY` no longer re-reports a value already caught by a format rule, OpenAI's `sk-` pattern no longer misattributes Anthropic `sk-ant-` keys, and AWS/Google value patterns no longer truncate keys at a fixed length.
  - Findings carry `validation_checks` (exported in JSON) so users can see which signals corroborated a secret.
  - Added precision guardrail tests (`TestSecretFalsePositiveRejection`) and genuine-secret preservation tests (`TestGenuineSecretPreservation`); benchmark stays at precision 1.000 / recall 1.000 with zero clean-corpus findings.
- **Detection quality program** — five phases to raise accuracy before adding new rules:
  - **Severity gating** (`src/core/severity_gate.py`) — HIGH/CRITICAL findings are demoted unless supported by strong evidence or a confidence floor (CRITICAL ≥ 0.85, HIGH ≥ 0.60, MEDIUM ≥ 0.35); gates only ever demote, never promote; demotion reasons are prepended to `confidence_reasoning`.
  - **Secret quality** — 11 new secret patterns (Telegram, GitHub fine-grained, GitLab, OpenAI, Anthropic, Hugging Face, PyPI, Stripe restricted, Azure account key, DB-URL credentials); weak-credential rejection (keyboard walks, repeated runs, self-referential values) now enforced in the validation pipeline (the authoritative confidence source); secrets report the bare value (`raw_secret`) plus the surrounding line (`code_snippet`) and the triggering regex (`matched_pattern`).
  - **Evidence surfacing** — findings carry `verification_level`, `matched_pattern`, and full validation evidence (positive/negative with reasons + strengths); the results table and finding detail page show a "Detection Evidence" panel, matched pattern, verification badge, and multi-line confidence reasoning.
  - **Likely false positives + user verification** — validation auto-flags findings with contradictory or single-weak evidence (`likely_false_positive` + reason); a `mark_real` triage action persists `verified` state; new `likely_fp` status filter; "Likely FP" badges and one-click Confirm real / Mark FP in both list and detail views.
  - **Precision/recall benchmark** — `tests/benchmark/` labeled vulnerable + clean corpora, `scripts/benchmark_precision_recall.py` (currently 1.000 / 1.000, zero clean findings), and `tests/test_benchmark.py` gate (precision ≥ 0.7, recall ≥ 0.8, clean corpus empty). Fixed a real recall gap: SEC002 now also catches `subprocess.run(shell=True)`.
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
