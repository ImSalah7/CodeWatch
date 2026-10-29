# CI/CD — CodeWatch

## 1. Current pipeline

The repo ships a GitHub Actions workflow at `.github/workflows/ci.yml` (name: `CI`).

Triggers:

- `push` on `main` and `master`
- `pull_request` (any branch)

Three jobs, all on `ubuntu-latest`:

| Job | Steps |
|---|---|
| `test` | Matrix **3.11 / 3.12** · `pip install -r requirements.txt` · `python -m pytest tests/ -q` · `python -m src.cli --version` |
| `lint` | Python 3.12 · `pip install ruff` · `ruff check src tests scripts` · `python scripts/check_docs_sync.py` |
| `frontend` | Node 22 · `npm ci` · `npm run lint` · `npm run build` |

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

## 3. Ruff configuration

Configured in `pyproject.toml` (`[tool.ruff.lint]`): `select = [E4, E7, E9, F, B, C4, PERF, PIE, SIM, UP]` with a short `ignore` list for deliberate patterns:

- `BLE001`, `S110`, `S112` — the scanner intentionally swallows per-file exceptions so one bad module doesn't abort a scan.
- `RUF012`, `C408`, `E741`, `E402`, `B027`, `SIM105` — tolerated legacy style.

Ruff runs on `src`, `tests`, and `scripts`. `ruff format` is **not** enforced (the codebase predates it).

## 4. Type checking (deferred)

`[tool.mypy]` config exists (`python_version = "3.11"`, `disallow_untyped_defs`), but **mypy is not yet wired into CI**. mypy 2.x aborts on this repository with:

```
src/__init__.py: error: Source file found twice under different module names: "src" and "src.__init__"
```

This is a module-resolution collision between the `src` package layout (`src/__init__.py` at the package root) and mypy's import-graph mapping; it occurs regardless of `--explicit-package-bases`, `--namespace-packages`, `MYPYPATH`, or passing explicit file lists. Type checking is tracked in [roadmap.md](roadmap.md).

## 5. Docker build + publish (planned)

Image publish on version tags is the intended release path:

```yaml
  docker:
    runs-on: ubuntu-latest
    needs: [test, lint, frontend]
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
          context: CodeWatch
          push: true
          tags: ghcr.io/${{ github.repository }}/api:latest,ghcr.io/${{ github.repository }}/api:${{ github.ref_name }}
```

Requires the repository's CI to have `Actions: read` / `Packages: write` permissions configured.

## 6. Local equivalent

```bash
# Backend
python -m pytest tests/ -q
python -m ruff check src tests scripts
python scripts/check_docs_sync.py

# Frontend
cd frontend
npm ci && npm run lint && npm run build
```

## 7. Branching & releases

- Current default branch: `master`. The CI workflow already triggers on both `main` and `master`.
- Tag releases as `v3.0.x` and keep [CHANGELOG.md](../CHANGELOG.md) up to date (each entry should reference the codebase's `__version__`).
- No git remote is configured in the repository yet; add one (`git remote add origin <url>`) before pushing.
