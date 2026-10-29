# User Guide — CodeWatch

## 1. Quick start

```bash
cd CodeWatch
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Scan a local repository
python -m src.cli scan /path/to/project --local

# Run the API + web UI
python run_api.py                # http://localhost:8443
cd frontend && npm ci && npm run dev   # http://localhost:3000
```

## 2. The web UI

1. Start the API (`python run_api.py`) and the frontend (`cd frontend && npm run dev`).
2. Open **http://localhost:3000**.
3. **Dashboard** — security score, grade, finding counts, recent scans.
4. **New Scan** — enter a local path or a remote git URL, pick options, start.
5. **Results** — findings with severity filter, sort, pagination, and the new **bulk triage** bar (suppress / unsuppress / mark false-positive / assign owner; persisted via `finding_state`).
6. **Finding Detail** — severity, CWE/OWASP/CVSS, code evidence, location, root cause, exploit, fix, AI explanation (if LLM configured), and state controls.
7. **Reports** — download any of the five formats for a scan.
8. **Analytics** — language and rule distribution.
9. **Settings** — default scan options.

> The API key is injected by the Next.js proxy server-side; you never paste it into the browser.

## 3. CLI

### `scan` — full scan

```bash
python -m src.cli scan TARGET [options]
```

Key options:

| Option | Effect |
|---|---|
| `-l, --local` | Treat TARGET as a local directory (default is remote/git) |
| `-o, --output FILE` | Write the report to a file |
| `-f, --format` | `markdown` (default), `json`, `sarif`, `html`, `csv` |
| `--no-deps` | Skip dependency scanning |
| `--no-quality` | Skip quality rules |
| `--no-secrets` | Skip secrets scanning |
| `--no-security` | Skip security rules |
| `--include-tests` / `--include-docs` | Include test/doc files (skipped by default) |
| `--severity LEVEL` | Minimum severity to report (`critical`/`high`/`medium`/`low`/`info`) |
| `--threads N` | Worker threads |
| `--enterprise` | Enterprise AST/data-flow/taint analysis |
| `--secret-display MODE` | `full` / `masked` / `smart` (default `smart`) |
| `--show-secrets` | Alias for `--secret-display=full` |

```bash
# Local directory, HTML report, high+ only
python -m src.cli scan ./my-app --local -f html -o report.html --severity high
```

### `quick` — high/critical only

```bash
python -m src.cli quick TARGET [--no-deps] [--severity LEVEL]
```

### `info` — scanner capabilities

```bash
python -m src.cli info
# Shows modules, rule counts, supported languages
```

### `benchmark` — compare with semgrep/bandit

```bash
python -m src.cli benchmark TARGET [--tools semgrep,bandit] [-o out.md] [--enterprise]
```

Requires the external tools installed and on `PATH`.

### `--version`

```bash
python -m src.cli --version
```

## 4. Scan targets

- **Local:** any readable directory. Respects `MYSCAN_ALLOWED_PATHS` when configured; `/etc`, `/usr`, `C:\Windows` are always refused.
- **Remote git:** `https://…`, `http://…`, `git@host:org/repo.git` (ssh). SSRF-protected (private-network addresses are refused — see [security.md](security.md)).

## 5. Reports

Generated reports land in `codewatch_reports/` when `-o` is omitted. All formats share one content model: findings (severity, CWE, OWASP, CVSS, location, evidence, fix), plus metadata (version, branch, commit, rule counts, total/occurrences).

| Format | Use |
|---|---|
| Markdown | Readable summary, code blocks |
| JSON | Machine-readable, CI ingestion |
| SARIF | GitHub/VS Code / SARIF viewers |
| HTML | Self-contained, printable |
| CSV | Spreadsheets — 27 columns |

## 6. Interpreting findings

- **Severity & score:** derived from rule CVSS base score and custom calibrations; the dashboard grade is computed from counts and severities (see [system-design.md](system-design.md) §Scoring).
- **`owasp`** on each finding: `{code, title}` (e.g. `{"code":"A03","title":"Injection"}`).
- **Occurrences:** a finding may have multiple occurrence locations; each is listed in the report and counted in the totals.
- **Triage:** from the results UI, findings can be suppressed, marked as false positives, or assigned — decisions persist in `finding_state` and survive rescan.

## 7. Environment variables (user-facing)

| Variable | Default | Meaning |
|---|---|---|
| `MYSCAN_API_KEY` | *(empty)* | Required by the API when set |
| `MYSCAN_LLM_ENHANCE` | `1` | Enable AI explanations (`0` to disable) |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `MYSCAN_AI_PROVIDER` | — | LLM provider credentials (optional) |

Full list: [security.md](security.md) §2.
