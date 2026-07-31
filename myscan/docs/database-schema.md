# Database Schema — MyScan (SQLite)

> Source: `src/store.py` · Engine: SQLite in WAL mode · Path: `MYSCAN_DB` (default `src/myscan.db`)

## 1. Overview

- Three tables: `scans`, `findings`, `finding_state`.
- JSON payloads are stored as **TEXT** (serialized) columns.
- No foreign-key constraints (enforced by application code); `findings.scan_id` and `finding_state.scan_id` reference `scans.job_id`.
- Schema migrations are **additive only**, via `_migrate(conn)` which inspects `PRAGMA table_info(findings)` and adds missing columns (`occurrences`, `locations_json`, `evidence_json`).
- `init_store()` creates the parent directory, enables `PRAGMA journal_mode=WAL`, creates tables, runs migrations.

## 2. Entity-Relationship Diagram

```
┌────────────────────┐        ┌──────────────────────────────┐
│      scans         │        │         findings             │
├────────────────────┤        ├──────────────────────────────┤
│ job_id TEXT  PK ◄──┼────────┼── scan_id TEXT  (→ scans)     │
│ target TEXT        │        │ id INTEGER PK AUTOINCREMENT  │
│ status TEXT        │        │ fingerprint TEXT (sha256:16) │
│ enterprise INT     │        │ rule_id TEXT                 │
│ started_at TEXT    │        │ title / description TEXT     │
│ completed_at TEXT  │        │ severity TEXT                │
│ error TEXT         │        │ confidence REAL              │
│ scan_duration REAL │        │ category TEXT                │
│ finding_count INT  │        │ language TEXT                │
│ secret_display TEXT│        │ file_path / line / end_line  │
│ is_remote INT      │        │ column_num / code_snippet    │
│ result_json TEXT   │        │ function_name / class_name   │
│ summary_json TEXT  │        │ cwe / cwe_name               │
└────────────────────┘        │ owasp_code / owasp_title     │
                              │ cvss_score / cvss_vector     │
        ┌─────────────────────────┐  fix_suggestion/fixed_code│
        │      finding_state      │  references_json  (TEXT)  │
        ├─────────────────────────┤  exploit_scenario/impact  │
        │ scan_id TEXT  PK      ◄─┼── (scan_id, fingerprint)  │
        │ fingerprint TEXT PK     │  why_vulnerable           │
        │ suppressed INT          │  is_false_positive INT    │
        │ is_false_positive INT   │  confidence_reasoning     │
        │ assignee TEXT           │  tags_json  (TEXT)        │
        │ issue_url TEXT          │  raw_secret TEXT          │
        │ notes TEXT              │  reachability/root_cause  │
        │ updated_at TEXT         │  occurrences INT          │
        └─────────────────────────┘  locations_json (TEXT)    │
                                    evidence_json  (TEXT)     │
                                    └─────────────────────────┘
```

## 3. Tables & columns

### 3.1 `scans`

| Column | Type | Notes |
|---|---|---|
| `job_id` | TEXT | PRIMARY KEY |
| `target` | TEXT NOT NULL | local path or git URL |
| `status` | TEXT NOT NULL | `pending` \| `running` \| `completed` \| `failed` |
| `enterprise` | INTEGER NOT NULL DEFAULT 0 | boolean |
| `started_at` | TEXT NOT NULL | ISO-8601 UTC |
| `completed_at` | TEXT | nullable |
| `error` | TEXT | nullable |
| `scan_duration` | REAL DEFAULT 0 | seconds |
| `finding_count` | INTEGER DEFAULT 0 | |
| `secret_display` | TEXT DEFAULT 'smart' | `full` \| `masked` \| `smart` |
| `is_remote` | INTEGER NOT NULL DEFAULT 0 | boolean |
| `result_json` | TEXT | `ScanResult.to_dict()` JSON |
| `summary_json` | TEXT | summary dict JSON |

### 3.2 `findings`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | |
| `scan_id` | TEXT NOT NULL | references `scans.job_id` |
| `fingerprint` | TEXT NOT NULL | `sha256(...)`[:16] |
| `rule_id` | TEXT | e.g. SEC001 |
| `title` | TEXT | |
| `description` | TEXT | |
| `severity` | TEXT | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `confidence` | REAL | 0–1 |
| `category` | TEXT | `security` \| `quality` \| `secret` \| `dependency` \| … |
| `language` | TEXT | |
| `file_path` | TEXT | |
| `line` | INTEGER | |
| `end_line` | INTEGER | |
| `column_num` | INTEGER | |
| `code_snippet` | TEXT | |
| `function_name` | TEXT | |
| `class_name` | TEXT | |
| `cwe` | TEXT | e.g. `CWE-89` |
| `cwe_name` | TEXT | |
| `owasp_code` | TEXT | e.g. `A03:2021` |
| `owasp_title` | TEXT | |
| `cvss_score` | REAL | nullable |
| `cvss_vector` | TEXT | |
| `fix_suggestion` | TEXT | |
| `fixed_code` | TEXT | |
| `references_json` | TEXT | JSON array of strings |
| `exploit_scenario` | TEXT | |
| `impact` | TEXT | |
| `why_vulnerable` | TEXT | |
| `is_false_positive` | INTEGER DEFAULT 0 | legacy column |
| `confidence_reasoning` | TEXT | |
| `tags_json` | TEXT | JSON array of strings |
| `raw_secret` | TEXT | secret value (display-mode aware) |
| `reachability` | TEXT | |
| `root_cause` | TEXT | |
| `occurrences` | INTEGER DEFAULT 1 | *added by `_migrate`* |
| `locations_json` | TEXT | JSON array `{file,line,end_line,column}` *added by `_migrate`* |
| `evidence_json` | TEXT | JSON array `{type,detail,matched?,line?}` *added by `_migrate`* |

### 3.3 `finding_state`

| Column | Type | Notes |
|---|---|---|
| `scan_id` | TEXT NOT NULL | composite PK |
| `fingerprint` | TEXT NOT NULL | composite PK |
| `suppressed` | INTEGER DEFAULT 0 | |
| `is_false_positive` | INTEGER DEFAULT 0 | |
| `assignee` | TEXT | |
| `issue_url` | TEXT | |
| `notes` | TEXT | |
| `updated_at` | TEXT | set on upsert |

## 4. Indexes

| Index | Table / columns |
|---|---|
| `idx_findings_scan` | `findings(scan_id)` |
| `idx_findings_fp` | `findings(fingerprint)` |
| `idx_findings_sev` | `findings(severity)` |
| `idx_findings_rule` | `findings(rule_id)` |
| `idx_findings_lang` | `findings(language)` |
| `idx_scans_started` | `scans(started_at)` |

## 5. JSON column semantics

- Written via `json.dumps`; read via `json.loads` (missing/empty → `[]`).
- On read, empty `locations_json` falls back to a synthesized single location from `file_path`/`line`/`end_line`/`column_num`.
- `finding_state` rows are `LEFT JOIN`ed into findings queries as aliases `state_suppressed`, `state_fp`, `state_assignee`, `state_issue_url`, `state_notes`.

## 6. Behavioral notes

- `save_scan(job_id, …)` upserts; preserves original `target`, `started_at`, `enterprise`, `secret_display`, `is_remote`.
- `save_findings(scan_id, findings)` **deletes then inserts** (replace semantics).
- `set_finding_state` whitelists fields; upsert uses `ON CONFLICT(scan_id, fingerprint) DO UPDATE SET … = excluded.…`.
- `prune_history(max_history)` removes oldest scans and their findings beyond the cap.
- `list_scans`, `count_scans`, `get_stats`, `get_security_score`, `global_search` back the dashboard/analytics/history/score endpoints.
