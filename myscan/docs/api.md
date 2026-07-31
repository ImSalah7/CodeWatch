# API Reference — MyScan

> Base URL: `http://<host>:8443` · Auth: `MYSCAN_API_KEY` when set (see [authentication.md](authentication.md)) · Content type: `application/json` unless noted.

## 1. Authentication

When `MYSCAN_API_KEY` is configured, **every** `/api/*` route requires the key. Provide it one of four ways (priority order):

1. `Authorization: Bearer <key>`
2. `Authorization: Basic base64(user:key)` (password part used as the key)
3. `X-API-Key: <key>`
4. `?token=<key>` query parameter (used by the frontend proxy)

Unauthorized → `401 {"error": "Unauthorized. Provide a valid API key."}` with `WWW-Authenticate: Bearer realm="myscan"`.

Rate limiting: `MYSCAN_RATE_LIMIT` (default 300/min) + `MYSCAN_RATE_LIMIT_BURST` (60/s) per client → `429` with `Retry-After`.

## 2. Health

### `GET /health` — no auth, not rate-limited

```json
{ "status": "healthy", "version": "3.0.0", "timestamp": "2026-07-31T00:00:00.000000+00:00", "auth": true }
```

## 3. Scans

### `POST /api/v1/scan` — start a scan

Body:

| Field | Type | Default | Notes |
|---|---|---|---|
| `target` | string | **required** | local path or git/http/https/ssh URL (≤4096 chars) |
| `enterprise` | bool | `false` | enterprise analysis pipeline |
| `threads` | int | 4 | clamped 1–32 |
| `min_confidence` | float | 0.15 | clamped 0–1 |
| `secret_display` | string | `smart` | `smart` \| `masked` \| `full` |

`202`:

```json
{ "job_id": "b286477d1641", "status": "pending", "target": "/path/or/url", "enterprise": false, "is_remote": false }
```

Errors: `400` (missing target / SSRF or path rejected / bad scheme), `404` (local path not found).

### `GET /api/v1/scan/<job_id>` — status & result

`200` — job metadata, plus `result` when completed (findings truncated to 200):

```json
{
  "job_id": "…", "status": "completed", "target": "…", "enterprise": false,
  "started_at": "…", "completed_at": "…", "finding_count": 143,
  "result": {
    "tool": "MyScan", "version": "3.0.0", "scan_id": "…",
    "repository": "…", "branch": "master", "commit": "…", "target": "…",
    "rules_executed": 57, "repo_size_bytes": 5911481, "enterprise_mode": false,
    "secret_display_mode": "smart", "llm_stats": {},
    "scan_start": "…", "scan_end": "…", "scan_duration": 2.0,
    "summary": { "total_findings": 143, "occurrences_total": 185, "security_findings": 60,
                 "quality_findings": 129, "secret_findings": 1, "risk_score": 100, "grade": "F",
                 "severity_counts": { "critical": 41, "high": 9, "medium": 11, "low": 51, "info": 78 },
                 "files_scanned": 60, "lines_scanned": 19072, "languages": { "python": 59 } },
    "findings": [ … ]
  }
}
```

`404` unknown job. Live scans also include `enterprise_metrics` and `llm_stats` when present.

### `GET /api/v1/scan/<job_id>/events` — SSE live progress

`Content-Type: text/event-stream` · `Cache-Control: no-cache` · `X-Accel-Buffering: no`.

Each message: `data: {"event": "<type>", "data": {...}, "timestamp": <unix>}\n\n`

| Event | data |
|---|---|
| `init` | progress snapshot (job_id, total_files, scanned_files, current_file, current_rule, phase, findings_count, severity_counts, elapsed, eta, paused, cancelled, percent) |
| `file` | `{file, scanned, total}` |
| `progress` | `{scanned, total, percent, elapsed, eta, phase}` |
| `rule` | `{rule}` |
| `finding` | `{finding, total, severity_counts}` |
| `paused` / `resumed` / `cancelled` | `{}` |
| `complete` | `{summary, elapsed}` — terminal, stream closes |
| `error` | `{error}` — terminal, stream closes |
| `heartbeat` | `{}` (every 30s of inactivity) |

For completed jobs a synthesized `complete` event is returned. `404` if job/progress unavailable.

### `POST /api/v1/scan/<job_id>/cancel`

### `POST /api/v1/scan/<job_id>/pause`

### `POST /api/v1/scan/<job_id>/resume`

All three return `200 {"status": "cancelling" | "paused" | "resumed"}` · `400 {"error": "Scan not running"}` when no live tracker.

## 4. Findings

### `GET /api/v1/findings` — list with filters

Query params (all optional):

| Param | Values |
|---|---|
| `job_id` | defaults to most recent completed scan |
| `category` / `severity` / `rule_id` / `cwe` / `owasp` / `language` | exact match (case-insensitive) |
| `file_ext` | substring match on file path |
| `status` | `false_positive` \| `real` |
| `include_suppressed` | `1`/`true`/`yes` (hidden by default) |
| `min_cvss` | 0–10 |
| `min_confidence` | 0–1 |
| `sort` | `severity` \| `cvss` \| `confidence` \| `file` \| `rule` \| `line` |
| `order` | `asc` \| `desc` (default `asc`) |
| `limit` | 1–500 (default 100) |
| `offset` | ≥ 0 |
| `search` | substring over title/rule_id/file_path/cwe/description |

`200`:

```json
{
  "job_id": "…", "total": 143, "offset": 0, "limit": 100,
  "findings": [ { "rule_id": "SEC002", "title": "…", "severity": "critical",
                  "confidence": 0.95, "category": "security", "language": "python",
                  "cwe": "CWE-78", "cwe_name": "…", "owasp": { "code": "A03:2021", "title": "Injection" },
                  "cvss": { "score": 9.8, "vector": "…", "severity": "critical" }, "cvss_score": 9.8,
                  "file": "app.py", "line": 65, "location": { "file_path": "app.py", "line": 65,
                  "code_snippet": "…", "function": "…" }, "fingerprint": "2a064aa60cd7a2c8",
                  "occurrences": 3, "locations": [ … ], "evidence": [ … ],
                  "references": [ … ], "tags": [ … ], "state": { "suppressed": true },
                  "root_cause": "…", "reachability": "…", "raw_secret": "…" } ],
  "metadata": {
    "scan_id": "…", "repository": "…", "branch": "master", "commit": "…", "target": "…",
    "scan_time": "…", "completed_at": "…", "scan_duration": 2.0, "scanner_version": "3.0.0",
    "scanner_tool": "MyScan", "enterprise": false, "files_scanned": 60, "lines_scanned": 19072,
    "rules_executed": 57, "repo_size_bytes": 5911481,
    "languages": { "python": 59 }, "occurrences_total": 185, "findings_total": 143,
    "risk_score": 100, "grade": "F"
  }
}
```

`404` no scan found · `400` scan not completed.

### `GET /api/v1/findings/<fingerprint>` — finding detail

Search live scans first, then the database (latest row across scans). `200` single finding enriched with `scan_id`, `scan_target`, `scan_date`, `state`. `404 {"error": "Finding not found"}`.

### `POST /api/v1/findings/bulk` — bulk triage

Body:

```json
{ "scan_id": "…", "action": "suppress", "fingerprints": ["…", "…"], "value": "optional" }
```

| Action | Effect | Requires `value` |
|---|---|---|
| `suppress` / `unsuppress` | toggle `suppressed` | no |
| `mark_false_positive` / `unmark_false_positive` | toggle `is_false_positive` | no |
| `assign` | set `assignee` | **yes** |
| `create_issue` | set `issue_url` | **yes** |

`200`:

```json
{ "updated": 2, "action": "suppress", "states": { "<fp>": { "suppressed": true } } }
```

`400` for missing fields, unknown action, or missing `value`.

### `GET /api/v1/search?q=<str>` — global search

`q` ≥ 2 chars. `200`:

```json
{ "results": [ { "type": "finding", "fingerprint": "…", "title": "…", "rule_id": "SEC001",
                 "severity": "critical", "file": "app.py", "line": 12, "category": "security",
                 "cwe": "CWE-89", "scan_id": "…" } ], "total": 5 }
```

## 5. Reports

### `GET /api/v1/report/<job_id>?format=<fmt>`

`fmt`: `json` (default) · `markdown` · `html` · `sarif` · `csv`.

| Format | Content-Type |
|---|---|
| `json` | `application/json` |
| `markdown` | `text/markdown; charset=utf-8` |
| `html` | `text/html; charset=utf-8` |
| `sarif` | `application/sarif+json; charset=utf-8` |
| `csv` | `text/csv; charset=utf-8` |

`404` unknown job · `400` scan not completed or bad format.

## 6. Analytics & history

### `GET /api/v1/history?limit=<n>`

`limit` 1–500 (default 20). `200`:

```json
{ "history": [ { "job_id": "…", "target": "…", "status": "completed", "enterprise": false,
                 "started_at": "…", "completed_at": "…", "finding_count": 143, "error": null } ],
  "total": 12 }
```

### `GET /api/v1/stats`

```json
{ "total_scans": 12, "completed_scans": 11, "failed_scans": 1, "total_findings": 1245,
  "severity_totals": { "critical": 20, "high": 45, "medium": 130, "low": 300, "info": 750 },
  "category_totals": { "security": 200, "quality": 900, "secret": 5 },
  "avg_findings_per_scan": 103.75 }
```

### `GET /api/v1/security-score`

```json
{ "score": 42, "grade": "C", "trend": [ { "date": "2026-07-30", "score": 55 } ],
  "components": { "critical_findings": 20, "high_findings": 45, "secrets": 5,
                  "total_findings": 1245, "scans_completed": 11 } }
```

Formula: `score = clamp(100 − critical·8 − high·3 − secrets·5 − total//10, 0, 100)`; grade `<10 F, <25 D, <45 C, <65 B, <90 A, else A+`.

## 7. Settings

### `GET /api/v1/settings`

```json
{ "settings": {
    "threads": 4, "min_confidence": 0.2, "enterprise_mode": false, "secret_display": "smart",
    "max_file_size_kb": 1024, "include_tests": false, "include_docs": false, "include_examples": false,
    "max_history": 50, "report_format": "markdown",
    "notifications": { "scan_complete": true, "critical_findings": true, "scan_failed": true } } }
```

### `PUT /api/v1/settings`

Body: `{"settings": {...}}` or a flat settings object. Shallow-merges over persisted settings (file: `src/myscan_settings.json`). `200` returns merged settings.

## 8. Fixes & supply chain

### `POST /api/v1/fix`

Body: `{"job_id": "…", "finding_ids": ["SEC001"]}` (`finding_ids` optional, empty = all).

`200`:

```json
{ "job_id": "…", "fixes": [ { "rule_id": "SEC001", "title": "…", "file": "app.py", "line": 12,
    "fingerprint": "…", "fixes": [ { "description": "…", "before": "…", "after": "…", "effort": "low" } ] } ] }
```

### `POST /api/v1/dependencies`

Body: `{"target": "<local path>"}` (local only).

`200`:

```json
{ "manifests": [ … ], "total_manifests": 3, "total_dependencies": 42,
  "vulnerabilities": { "critical": 0, "high": 1, "medium": 2, "low": 5, "total": 8 },
  "target": "…" }
```

### `POST /api/v1/sbom`

Body: `{"target": "<local path>", "format": "json"|"spdx"}` (`json` = CycloneDX 1.5, `spdx` = SPDX 2.3). `200` is the SBOM document.

## 9. Error format

All errors: `{"error": "<message>"}` with the appropriate HTTP status (`400`, `401`, `404`, `429`, `500`).

## 10. Rate limits & concurrency

- `MYSCAN_RATE_LIMIT` per-minute sliding window + `MYSCAN_RATE_LIMIT_BURST` per-second cap, keyed per client IP (or first `X-Forwarded-For` hop when `MYSCAN_TRUST_PROXY=1`).
- `OPTIONS` preflight requests are exempt (CORS).
- Scan threads are clamped to 1–32 per request; waitress serves with 16 threads.

