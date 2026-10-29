# System Design — CodeWatch

Detailed design of each subsystem. Complements [architecture.md](architecture.md); source of truth is the code (`src/`).

## 1. Scan engine (`src/core/engine.py`)

`ScanEngine(config: ScanConfig, enterprise_mode=False, validate_findings=True, progress_tracker=None)`

- **`scan(target)`** — standard mode. Collects files, runs scanners, dedups, validates, groups duplicates, returns `ScanResult`.
- **`_scan_enterprise(target)`** — enterprise mode via `AnalysisPipeline`. Maps enterprise finding kinds to `Finding` with severity/category/OWASP maps, attaches `_enterprise_metrics`, enriches with fixes/explainers/secret analysis.
- File collection: `_should_include_file` enforces `SKIP_FILES`, `SKIP_EXTENSIONS`, `SKIP_PATH_PATTERNS`, `max_file_size`.
- `ScanResult` (models.py) carries `summary`, `findings`, `rules_executed`, `repository/branch/commit/target`, `repo_size_bytes`, `scan_start/end/duration`, `_enterprise_metrics`, `_llm_stats`, and `group_duplicates()`.

### Rules (`src/core/rules.py`)

- `Rule` dataclass + `ALL_RULES` (57: 47 SEC + 10 QLT), `RULE_MAP`, language-filtered lists.
- Security rules span OWASP categories: Injection (A03), Crypto failures (A02), Misconfiguration (A05), Broken access control (A01), Deserialization (A08), Vulnerable components (A06), Auth failures (A07), Logging (A09), Insecure design (A04), SSRF (A10).
- `CVSS.calculate(**cvss_config)` per rule.

### Scanners (`src/scanners/`)

| Scanner | Detects | Notes |
|---|---|---|
| `security_scanner.py` | SEC001–SEC047 | Regex over `ALL_RULES`; SEC001 has mechanism-aware validation (f-string/concat/format/`%` interpolation vs parameterized calls) to eliminate false positives |
| `quality_scanner.py` | QLT001–QLT010 | line length, TODO/FIXME, bare except, globals, nesting, magic numbers, duplicate code, unused imports, commented-out code |
| `secrets_scanner.py` | Secret patterns + entropy | 21+ patterns; `config/patterns.yaml`; `SecretAnalyzer` classifies strength/risk/environment |

## 2. Enterprise analysis pipeline (`src/core/pipeline.py`)

Phase chain: **Source Code → AST → Data Flow → Taint → Context → Risk → Confidence → Dedup → Report**.

Per-file analysis stack:

| Module | Output |
|---|---|
| `indexer.py` | `RepositoryIndex` / `FileIndex` with `FileCategory` (production/test/doc/generated/vendor/config/infra/unknown) |
| `ast_analyzer.py` | `PythonASTResult` — functions, classes, imports, assignments, calls, tainted sources, dangerous sinks |
| `call_graph.py` | `FunctionNode`/`CallEdge` graph; entry-point detection; vulnerable paths; reachability (`reachable/dead_code/test_only/generated/deprecated`) |
| `dataflow.py` | `DataFlowResult` — taint paths, source→sink mappings, sanitization points |
| `semantic_analyzer.py` | Call semantics — `builtins.eval` (dangerous) vs `torch.nn.Module.eval` (safe) |
| `type_resolver.py` | Import alias, ownership, inheritance, builtin vs library vs project origin |
| `import_resolver.py` | Python/JS/TS/Go import resolution |
| `context_analyzer.py` | eval/password/injection context + sanitization level |
| `confidence.py` | `ConfidenceResult{score, level, adjusted_severity, should_report, reasoning, evidences}` |
| `risk_scorer.py` | `RiskAssessment{risk_level, cvss, owasp_category}` |

### Validation (`validation_engine.py`, ~1040 lines)

`ValidationPipeline(min_confidence=0.15)` phases: `_validate_ast`, `_validate_type`, `_validate_imports`, `_validate_reachability`, `_validate_context`, `_validate_secret`, `_validate_password_assignment`. State injected via `set_import_resolution` / `set_reachability`.

### Evidence & trust

- `evidence_engine.py` — pre-validation evidence collection (`Evidence`, `EvidenceStrength`).
- `trust_engine.py` — weighted scoring: REGEX .15, AST .25, DATAFLOW .20, TAINT .20, REACHABILITY .10, AI .05, CONTEXT .05, TYPE .05, SCOPE .03, DEPENDENCY .02; negative penalties (constant −0.70, placeholder −0.80, comment −0.90, vendor −1.00, dead code −0.90). Report threshold ≥ 0.15 (or taint/dataflow > 0.7).

## 3. Secret engine

- **Detection** (`secrets_scanner.py`): regex patterns + Shannon entropy (threshold 4.5 in `config/patterns.yaml`).
- **Analysis** (`secret_analyzer.py`): `SecretAnalyzer.analyze(finding)` → classification, strength label + estimated crack time, risk level + environment + business impact, recommendations.
- **Display** (`secret_display.py`): modes `full | masked | smart`.
  - `mask_secret(value, visible_prefix=4, visible_suffix=4)`.
  - `smart` = show full in reports only for non-production contexts; masks weak/default-credential/production secrets.
  - `is_weak_password`, `is_default_credential`, `is_production_secret` heuristics.
- Applied post-scan in `_run_scan_job` and in the CLI.

## 4. Reporting (`src/reporters/`)

Registry `REPORTERS = {markdown, json, sarif, html, csv}`, each `generate(result) -> str`.

- **Markdown**: header (repository/branch/commit/scan time/scanner/scan ID/files/lines/rules/repo size/duration/risk score/grade), risk summary (totals + occurrences), per-finding blocks with CWE/OWASP/CVSS/language/occurrences/evidence (≤5)/root cause/impact/code/fix/fixed code/exploit/confidence reasoning/references (≤5), false-positive badge.
- **HTML**: severity-colored, full-secret warning banner, per-finding cards with evidence, occurrences, root cause, references.
- **JSON**: full `ScanResult.to_dict()` (3.0.0 schema).
- **SARIF**: SARIF 2.1.0; tool/driver from `ALL_RULES` + `__version__`; per-result evidence, additionalLocations, state.
- **CSV**: 27-column flat export (incl. occurrences, false positive, suppressed, assignee, issue URL).

## 5. Persistence (`src/store.py`)

- WAL SQLite; tables `scans`, `findings`, `finding_state` (schema in [database-schema.md](database-schema.md)).
- `save_findings` = delete-then-insert (replace semantics per scan).
- `get_findings` — dynamic WHERE + `LEFT JOIN finding_state`, sort map (`severity` via CASE, `cvss`, `confidence`, `file`, `rule`, `line`).
- `set_finding_state` — whitelisted fields, `ON CONFLICT(scan_id, fingerprint) DO UPDATE` with `excluded.` column refs.
- `get_security_score` — `score = clamp(100 − critical·8 − high·3 − secrets·5 − max(0,total//10), 0, 100)`; grades: <10 F, <25 D, <45 C, <65 B, <90 A, else A+; 30-point trend.
- `prune_history(max_history)` — deletes oldest scans + findings.

## 6. API layer (`src/api.py`)

- `create_app()` factory; module-level `app`; `run_api(host, port, debug)` waitress-first.
- Rate limit clamps: threads 1–32, min_confidence 0–1, limit 1–500, offset ≥ 0, min_cvss 0–10.
- Findings metadata block (`_scan_metadata_dict`): scan_id, repository, branch, commit, target, times, duration, scanner version/tool, enterprise, files/lines, rules, repo size, languages, occurrences/findings totals, risk score, grade.
- Job lookup `_get_job`: live in-memory history first, then DB (`result_from_dict`).
- SSE with 30s heartbeat + synthesized terminal events for completed jobs.

## 7. Security layer (`src/security.py`)

See [security.md](security.md) and [authentication.md](authentication.md). Highlights:

- Token extraction: Bearer → Basic (password part) → `X-API-Key` → `?token=`; `hmac.compare_digest`.
- Rate limit: sliding 60s window + 1s burst; proxy-aware client identity; 10k-client cap with stale eviction; `Retry-After`.
- CORS: origin allowlist; preflight 204.
- SSRF: scheme allowlist (http/https/git/ssh), blocked private networks incl. IPv4-mapped IPv6 normalization.
- Local path guards: `MYSCAN_ALLOWED_PATHS` allowlist; always blocks `/etc`, `/usr`, `C:\Windows`.

## 8. Frontend design (`frontend/`)

- Next.js 16 App Router; `src/proxy.ts` rewrites `/api/*` and `/health` to `API_BASE_URL`, injecting `MYSCAN_API_KEY` as `?token=` server-side.
- Data layer `src/lib/api.ts`: typed wrappers for every endpoint + `subscribeToScanEvents` (SSE → handler map).
- Shared UI: `MetricCard` (animated KPI), `SeverityBadge`; Tailwind v4 theme in `globals.css` (dark navy/cyan `#00E5FF`).
- Pages (see [user-guide.md](user-guide.md)): dashboard, scan wizard (SSE live progress + polling fallback), results (filters/sort/pagination/bulk triage/export), finding detail, reports (+fix suggestions), search, security score, analytics, history, settings.

## 9. LLM layer (`src/ai/`)

- `llm_client.py`: provider auto-detect from env (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`/`GEMINI_API_KEY`); default models gpt-4o-mini / claude-3-5-haiku / gemini-2.0-flash; temperature 0.3.
- `enhancer.py`: parallel workers (concurrency 4, timeout 30s, max 20 findings), sha256 cache key, `_llm_stats`; `MYSCAN_LLM_ENHANCE=0` disables.
- `explainer.py`: `CATEGORY_EXPLANATIONS` templates for offline fallback.

## 10. Extended scanners

| Module | Function |
|---|---|
| `dependency_scanner.py` | CVE matching across manifests; version spec parsing (`==`, `~=`, ranges, `||`, wildcards); risk score = critical·25 + high·15 + medium·8 + low·3 + vuln_ratio·50 (cap 100) |
| `sbom.py` | CycloneDX 1.5 (`urn:uuid:md5` serials) and SPDX 2.3 (DEPENDS_ON) |
| `config_security.py` | Docker/K8s/Terraform/GitHub Actions/NGINX misconfiguration scanning |
| `policy_engine.py` | `SecurityPolicy` with `pci_dss` / `hipaa` / `soc2` classmethods; check/filter/baseline |
| `plugin_sdk.py` | `PluginManager` + ABCs: `ScannerPlugin`, `RulePlugin`, `ReporterPlugin`, `ExporterPlugin`, `AnalysisPhasePlugin` |
| `performance.py` | `ASTCache`, `IncrementalScanner` (sha256 state), `ParallelScanner` (ThreadPoolExecutor), `ScanProgress` |
| `file_risk.py` / `function_risk.py` | Risk profiles with attack-surface, complexity, importance, exposure |
| `benchmark.py` | Semgrep/Bandit subprocess comparison: overlap, precision, recall, F1, coverage |
