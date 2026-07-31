# CI/CD — MyScan

## 1. Current pipeline

The repo ships a GitHub Actions workflow at `.github/workflows/ci.yml` (name: `CI`).

Triggers:

- `push` on `main` and `master`
- `pull_request` (any branch)

Job `test` — matrix over Python **3.11** and **3.12** on `ubuntu-latest`:

1. `actions/checkout@v4`
2. `actions/setup-python@v5` with `cache: pip`
3. `pip install --upgrade pip` + `pip install -r requirements.txt`
4. `python -m pytest tests/ -q`
5. Sanity: `python -m src.cli --version`

## 2. Documentation sync check

`scripts/check_docs_sync.py` runs in CI and locally to keep documentation aligned with the codebase. It verifies:

- `README.md` exists (also required by `pyproject.toml`'s `readme` field).
- Version consistency between `pyproject.toml` and `src/__init__.py`.
- Every endpoint documented in `docs/api.md` (lines matching `` `METHOD /path` ``) exists in `src/api.py`.
- Every environment variable documented in `docs/security.md`, `docs/deployment.md`, and `docs/admin-guide.md` appears in `.env.example`.
- CLI subcommands documented in `docs/user-guide.md` exist in `src/cli.py`.
- Relative `.md` links in `docs/` and `README.md` resolve to real files.

Run locally:

```bash
python scripts/check_docs_sync.py
```

Exit code `0` = in sync; non-zero lists mismatches.

## 3. Recommended additions

The following are **not yet wired** but are the intended production pipeline:

```yaml
# .github/workflows/ci.yml (extended shape)
name: CI

on:
  push:
    branches: [main, master]
    tags: ["v*"]
  pull_request:

jobs:
  backend-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
      - run: pip install --upgrade pip
      - run: pip install -r requirements.txt
      - run: python -m pytest tests/ -q
      - run: python -m src.cli --version

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12", cache: pip }
      - run: pip install ruff mypy
      - run: ruff check src tests
      - run: mypy src

  frontend:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: frontend
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22, cache: npm }
      - run: npm ci
      - run: npm run lint
      - run: npm run build

  docs-sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: python scripts/check_docs_sync.py
```

### Docker build + publish

```yaml
  docker:
    runs-on: ubuntu-latest
    needs: [backend-tests, frontend, lint]
    if: startsWith(github.ref, 'refs/tags/v')
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: myscan
          push: true
          tags: ghcr.io/${{ github.repository }}/api:latest,ghcr.io/${{ github.repository }}/api:${{ github.ref_name }}
```

## 4. Local equivalent

```bash
# Backend
python -m pytest tests/ -q
python -m ruff check src tests
python -m mypy src
python scripts/check_docs_sync.py

# Frontend
cd frontend
npm ci && npm run lint && npm run build
```

## 5. Branching & releases

- Current default branch: `master`. The CI workflow already triggers on both `main` and `master`.
- Tag releases as `v3.0.x` and keep [CHANGELOG.md](../CHANGELOG.md) up to date (each entry should reference the codebase's `__version__`).
- No git remote is configured in the repository yet; add one (`git remote add origin <url>`) before pushing.
