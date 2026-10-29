# Folder Structure — CodeWatch

Repository layout with one-line descriptions. Source of truth: the tree at `myscan/`.

```
myscan/
├── run_api.py                      # Production entry point (waitress); reads MYSCAN_HOST/PORT/DEBUG
├── pyproject.toml                  # Package metadata (v3.0.0), deps, pytest/ruff/mypy config, `myscan` script
├── requirements.txt                # Pinned runtime requirements (Docker/CI install)
├── Dockerfile                      # Backend image: python:3.13-slim, editable install, waitress
├── docker-compose.yml              # api (:8443) + frontend (:3000) services + myscan_data volume
├── .env.example                    # Reference for every environment variable
├── .dockerignore / .gitignore
├── README.md                       # Project overview & quick start
├── CHANGELOG.md                    # Release history
├── config/
│   └── patterns.yaml               # Secret-detection regex patterns + entropy threshold + scan settings
├── rules/                          # Reserved for externalized rule packs (currently empty; rules live in code)
├── src/
│   ├── __init__.py                 # __version__ = "3.0.0"
│   ├── api.py                      # Flask app: all REST + SSE endpoints, job lifecycle, settings
│   ├── cli.py                      # Click/Rich CLI: scan, quick, info, benchmark
│   ├── store.py                    # SQLite persistence: schema, CRUD, filters, triage, stats, security score
│   ├── security.py                 # API key auth, rate limiting, CORS, SSRF/path guards
│   ├── serialization.py            # result_from_dict / finding_from_dict (DB → models round-trip)
│   ├── progress.py                 # ProgressTracker + SSE event fan-out queue
│   ├── myscan_settings.json        # Persisted settings (auto-created)
│   ├── codewatch.db                   # Default SQLite database (path via MYSCAN_DB)
│   ├── ai/
│   │   ├── llm_client.py           # OpenAI/Anthropic/Gemini client factory
│   │   ├── enhancer.py             # Parallel finding enrichment (cached, non-fatal)
│   │   └── explainer.py            # FindingExplanation + offline CATEGORY_EXPLANATIONS
│   ├── scanners/
│   │   ├── security_scanner.py     # SEC001–SEC047 regex scanning (mechanism-aware SEC001)
│   │   ├── quality_scanner.py      # QLT001–QLT010
│   │   └── secrets_scanner.py      # Secret patterns + entropy
│   ├── reporters/
│   │   ├── __init__.py             # REPORTERS registry
│   │   ├── markdown_report.py
│   │   ├── html_report.py
│   │   ├── json_report.py
│   │   ├── sarif.py
│   │   └── csv_report.py
│   └── core/                       # Scan engine & analysis (see table below)
├── frontend/
│   ├── Dockerfile                  # node:22-alpine multi-stage (builder + runner)
│   ├── package.json                # Next 16.2.12, React 19.2.4, Tailwind v4, Recharts, framer-motion
│   ├── next.config.ts              # outputFileTracingRoot for Docker standalone
│   ├── postcss.config.mjs          # @tailwindcss/postcss (Tailwind v4)
│   ├── tsconfig.json               # strict, @/* → ./src/*
│   ├── eslint.config.mjs           # next/core-web-vitals + typescript
│   └── src/
│       ├── app/                    # Routes: /, /scan, /results, /findings/[fingerprint], /reports, /settings
│       ├── components/             # Client components (results, findings, reports, scan, dashboard, ui, layout)
│       ├── lib/
│       │   ├── api.ts              # Typed API client + SSE subscription + download helper
│       │   ├── types.ts            # Finding, FindingsMetadata, ScanJob, Stats, etc.
│       │   └── utils.ts            # cn, formatNumber, timeAgo, gradeColor, severity colors
│       ├── proxy.ts                # Next.js proxy: /api/* → backend, injects MYSCAN_API_KEY
│       └── app/globals.css         # Tailwind v4 theme (dark navy/cyan) + component classes
├── scripts/
│   └── check_docs_sync.py          # Docs↔code consistency checker (CI + local)
├── tests/                          # 574 tests (see docs/testing.md)
│   └── fixtures/sample_app/app.py  # Deliberately vulnerable Flask app used by integration tests
└── codewatch_reports/                 # Report output (gitignored)
```

### `src/core/` inventory

| Module | Purpose |
|---|---|
| `config.py` | `ScanConfig` dataclass, skip sets |
| `models.py` | Enums (`Severity`, `OWASPTop10`, `CVSS`, `Language`, `Category`), `Finding`, `ScanResult`, `group_duplicates` |
| `rules.py` | Rule registry: 47 SEC + 10 QLT + CVSS config |
| `engine.py` | `ScanEngine` orchestrator (standard + enterprise) |
| `pipeline.py` | `AnalysisPipeline` enterprise orchestration |
| `ast_analyzer.py` | Python AST extraction (sources/sinks) |
| `call_graph.py` | Function call graph, entry points, vulnerable paths, reachability |
| `semantic_analyzer.py` | Call ownership/safety semantics |
| `dataflow.py` | Taint/data-flow analysis |
| `context_analyzer.py` | Eval/password/injection context |
| `confidence.py` | Evidence-based confidence scoring |
| `risk_scorer.py` | Risk assessment + CVSS vector building |
| `deduplicator.py` | `deduplicate_findings` grouping |
| `validation_engine.py` | `ValidationPipeline` (largest module, ~1040 lines) |
| `indexer.py` | Repository/file classification |
| `import_resolver.py` | Cross-file import resolution |
| `reachability.py` | Function reachability analysis |
| `symbol_table.py` | Repo-wide symbol table |
| `type_resolver.py` | Call-type resolution |
| `root_cause.py` | Root-cause + attack-scenario enrichment |
| `fix_generator.py` | Secure fix suggestions |
| `code_context.py` | ±5-line code context |
| `secret_analyzer.py` | Secret classification/risk/strength |
| `secret_display.py` | FULL/MASKED/SMART display modes |
| `smart_filter.py` | False-positive suppression |
| `evidence_engine.py` | Evidence collection |
| `trust_engine.py` | Weighted evidence trust scoring |
| `dependency_scanner.py` | CVE matching across manifests |
| `sbom.py` | CycloneDX / SPDX generation |
| `config_security.py` | IaC/config misconfiguration scanning |
| `policy_engine.py` | PCI-DSS/HIPAA/SOC2 policy presets |
| `plugin_sdk.py` | Plugin manager + plugin ABCs |
| `performance.py` | AST cache, incremental/parallel scanning |
| `file_risk.py` / `function_risk.py` | Risk profile scoring |
| `benchmark.py` | Semgrep/Bandit benchmark comparison |

### Dormant directories

`src/domain/`, `src/application/`, `src/presentation/`, `src/infrastructure/`, `src/analyzers/` are **empty scaffolding** from earlier design phases and are not used by the shipped code.
