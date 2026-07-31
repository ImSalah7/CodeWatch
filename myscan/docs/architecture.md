# Architecture — MyScan

> Companion docs: [system-design.md](system-design.md) (subsystem design), [folder-structure.md](folder-structure.md) (layout), [api.md](api.md) (API).

## 1. System context

MyScan is a three-surface application: a **web UI**, a **CLI**, and a **REST API**, all backed by a shared **scan engine** and a **SQLite** store. The web UI talks to the API exclusively through a server-side proxy so API credentials never reach the browser.

```
                    ┌─────────────────────────────────────────────┐
   Browser          │  Next.js 16 web UI  (port 3000)              │
   ───────────────► │  · pages: dashboard, scan wizard, results,   │
                    │    findings detail, reports, analytics, ...  │
                    │  · proxy.ts rewrites /api/* and /health      │
                    │    to the backend, injecting MYSCAN_API_KEY  │
                    └───────────────────┬─────────────────────────┘
                                        │ HTTP / SSE
   Terminal                             ▼
   ───────────────►  CLI (myscan)  ┌─────────────────────────────────────────────┐
   CI pipeline                      │  Flask REST API + SSE  (port 8443)          │
                                    │  api.py · security.py · store.py · progress │
                                    │  auth · rate limit · CORS · SSRF guards     │
                                    └───────────────────┬─────────────────────────┘
                                                        │ in-process
                                    ┌───────────────────▼─────────────────────────┐
                                    │  Scan Engine (src/core)                      │
                                    │  ScanEngine / AnalysisPipeline               │
                                    │  scanners · AST · dataflow · taint · call    │
                                    │  graph · validation · dedup · enrichment     │
                                    └───────────────────┬─────────────────────────┘
                                                        │ persist
                                    ┌───────────────────▼─────────────────────────┐
                                    │  SQLite (WAL)  scans · findings · state      │
                                    └─────────────────────────────────────────────┘
```

## 2. Layer model

| Layer | Modules | Responsibility |
|---|---|---|
| **Presentation** | `src/api.py`, `src/cli.py` | HTTP/SSE surface, CLI surface, settings endpoint |
| **Security** | `src/security.py` | API key auth, rate limiting, CORS, SSRF/path guards |
| **Application** | `src/progress.py`, `src/serialization.py` | Job lifecycle, progress events, result reconstruction |
| **Persistence** | `src/store.py` | SQLite schema, CRUD, filtering, triage state, stats |
| **Engine** | `src/core/*` | Rules, scanners, analysis pipeline, validation, dedup, enrichment |
| **Scanners** | `src/scanners/*` | Regex-based security/quality/secrets scanning |
| **Reporting** | `src/reporters/*` | Markdown / HTML / JSON / SARIF / CSV |
| **AI** | `src/ai/*` | Optional LLM client, enhancer, explainer |

## 3. Scan pipeline

### 3.1 Standard (regex) mode — `ScanEngine.scan`

```
target
  → _collect_files(target)          # os.walk; prunes skip dirs, skip ext, size cap
  → per file:
      _detect_language(file)        # extension map + special cases (Dockerfile, Makefile…)
      SecurityScanner.scan_file()   # SEC001–SEC047
      QualityScanner.scan_file()    # QLT001–QLT010
      SecretsScanner.scan_file()    # secret patterns + entropy
  → fingerprint findings            # sha256(rule_id:path:line:title)[:16]
  → false-positive validation       # ValidationPipeline or SmartFilter
  → group_duplicates()              # occurrences + locations[]
  → record rules_executed           # 57 rules
```

### 3.2 Enterprise mode — `AnalysisPipeline`

```
index_repository(path, include_tests/docs/examples)
  → FileIndex (classification, language, scannability)
  → per file: CallGraph.analyze_file · analyze_python_ast · analyze_data_flow · analyze_semantics
  → build_symbol_table · build_import_table · analyze_reachability
  → call_graph.get_vulnerable_paths()        # ENTERPRISE-VULNERABLE_PATH findings
  → per-finding validation                   # ValidationPipeline (imports, reachability, context…)
  → enrichment: code snippet · code context · root cause · reachability match
  → deduplicate_findings                     # before/after counts
  → map to Finding (severity/category/OWASP), generate fixes, AI explanations,
    SecretAnalyzer for secrets
  → _enterprise_metrics                      # functions, dataflow paths, taint, dup stats
```

### 3.3 Rule & finding flow

1. **Match** — a rule pattern or AST sink matches code.
2. **Validate** — `ValidationPipeline` checks AST, types, imports, reachability, context, secrets; `SmartFilter` and `TrustEngine` apply positive/negative evidence.
3. **Score** — `calculate_confidence` + `assess_risk` (severity adjustment, CVSS vector).
4. **Enrich** — code snippet, context, root cause, fix, optional AI explanation.
5. **Dedup** — identical findings across the repo collapse into one primary with `occurrences`/`locations`.
6. **Report** — persisted and rendered through reporters / API.

## 4. API & job lifecycle

`POST /api/v1/scan` → `202 {job_id, status: pending}` → daemon thread `_run_scan_job`:

1. `status = running`; `ProgressTracker` created.
2. Remote target → `git clone --depth 1 --single-branch --no-tags` (300s timeout) into a temp dir.
3. `ScanEngine(config, enterprise_mode, progress_tracker)` runs the appropriate pipeline.
4. `_attach_repo_metadata` — branch, commit, remote; repo size (skipping `.git`, `node_modules`, `__pycache__`, `.next`).
5. Apply `secret_display` mode to findings.
6. Optional `enhance_findings` (LLM) — never fails the scan.
7. `store.save_scan` + `store.save_findings` (replace semantics).
8. Terminal event (`complete`/`error`) via SSE; cleanup clone dir; `prune_history`; in-memory cap.

SSE events (from `progress.py` + `api.py`): `init`, `file`, `progress`, `rule`, `finding`, `paused`, `resumed`, `cancelled`, `complete`, `error`, `heartbeat` (30s).

## 5. Data model overview

See [database-schema.md](database-schema.md) for the full ERD. Core entities:

- **`scans`** — one row per job (`job_id` PK; target, status, timestamps, counts, `result_json`, `summary_json`).
- **`findings`** — one row per finding (fingerprint, rule, severity, CWE/OWASP/CVSS, location, JSON columns for references/tags/locations/evidence, `occurrences`).
- **`finding_state`** — triage per `(scan_id, fingerprint)`: suppressed, is_false_positive, assignee, issue_url, notes.

JSON is stored as TEXT (serialized); findings queries `LEFT JOIN finding_state` and merge state into responses.

## 6. Key design decisions

| Decision | Rationale |
|---|---|
| SQLite (not a server DB) | Zero-ops, single-file, WAL for concurrency; adequate for self-hosted scan history |
| Flask + waitress | Minimal, dependable production WSGI with bounded threads |
| tree-sitter (not full parsers) | Fast incremental parsing across 10 languages; failure-tolerant (`parse_errors` captured) |
| Regex + AST dual path | Standard mode is fast & portable; enterprise mode adds depth on demand |
| Dedup by fingerprint | Stable identity for triage; occurrences reduce noise |
| LLM optional & isolated | Deterministic core results; AI adds value without risk |
| API key + proxy token injection | Simple single-tenant auth; browser never sees secrets |
| In-memory + DB job duality | Live SSE/monitoring for active scans; durable history for completed ones |

## 7. Failure handling

- Scan exceptions → `status=failed`, error text stored, SSE `error` event emitted; the job remains in history.
- Per-file parse errors are captured and don't abort the repository scan.
- LLM failures are logged and skipped.
- Clone cleanup uses a robust cross-platform rmdir fallback (`cmd /c rmdir` on Windows).
- `atexit.register(_cleanup_temp_clones)` cleans temp clone dirs on process exit.
