# Testing — MyScan

## 1. Overview

MyScan's test suite covers the scanner core, security analyzers, API, and CLI. Test count: **405** as of the current revision.

| Layer | Location | Framework |
|---|---|---|
| Backend (unit + integration) | `myscan/tests/` | `pytest` |
| Frontend (lint + build) | `myscan/frontend/` | ESLint (Next config) + `next build` |
| Docs sync | `myscan/scripts/check_docs_sync.py` | standalone script |

## 2. Running the backend tests

```bash
cd myscan
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m pytest tests/ -q
#  405 passed in 4.12s   (example)

# Focused runs
python -m pytest tests/ -q -k scanner      # scanner core
python -m pytest tests/ -q -k security     # secret & security analyzers
python -m pytest tests/ -q -k api          # REST API
python -m pytest tests/ -q -k cli          # CLI
python -m pytest tests/test_exporters.py   # single file

# Coverage (optional)
pip install pytest-cov
python -m pytest tests/ -q --cov=src --cov-report=term-missing
```

The suite needs no external services; tests use `tmp_path` fixtures and a temporary in-memory/file database.

## 3. Lint & static analysis

Backend:

```bash
python -m ruff check src tests     # if ruff is installed (used in CI)
python -m mypy src                 # if mypy is installed
```

Frontend:

```bash
cd frontend
npm ci
npm run lint          # ESLint via next lint
npm run build         # type check + production build (also catches TS errors)
```

Known state: `results/page.tsx`, `ResultsClient.tsx`, `FindingDetailClient.tsx` lint clean; a small set of pre-existing lint warnings remain in legacy pages (settings/analytics/dashboard/scan/reports) and are tracked separately.

## 4. Documentation sync test

```bash
python scripts/check_docs_sync.py
```

Validates version consistency (`pyproject.toml` vs `src/__init__.py`), API route coverage in `docs/api.md`, env-var coverage in `.env.example`, and CLI subcommands in `docs/user-guide.md`. Exits non-zero on drift. See [ci-cd.md](ci-cd.md).

## 5. Test pyramid and philosophy

- **Scanner engine** — parse correctness across the 10 supported languages; detection of the 57 rules (47 security + 10 quality); severity/score computation; dedup and occurrence counting.
- **Secret analysis** — false-positive calibration, masking modes (`full`/`masked`/`smart`), strength/crack-time estimation.
- **API** — auth (401 vs 200), rate limiting (429), SSRF guard, path allowlist, scan lifecycle (start/cancel), SSE event shape, history pagination, triage/persistence.
- **Exporters** — all five report formats with complete metadata.
- **CLI** — argument parsing, subcommand wiring, version output.

## 6. Adding a test

- Put unit tests in `tests/` mirroring the `src/` layout.
- Use `pytest` fixtures from `tests/conftest.py` (app client, temp DB).
- Prefer fast, hermetic tests; avoid network calls (mock them).
- The docs-sync script should keep passing after changing routes/settings — update the docs in the same change.
