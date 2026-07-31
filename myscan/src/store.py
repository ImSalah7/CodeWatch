"""SQLite persistence layer for the MyScan REST API.

Replaces the in-memory scan registry with durable storage so history, findings,
stats, search, and reports survive process restarts. Scan execution still uses
the in-memory registry + progress trackers; completed/failed results are written
through to the database immediately.

The database path is configurable via the MYSCAN_DB environment variable and
defaults to ``src/myscan.db`` (next to the settings file).
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# Location & schema
# --------------------------------------------------------------------------

_DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "myscan.db")

_db_path: str = ""


def _env_db_path() -> str:
    env = os.environ.get("MYSCAN_DB", "").strip()
    if env:
        return env
    return _DEFAULT_DB


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    job_id          TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    status          TEXT NOT NULL,
    enterprise      INTEGER NOT NULL DEFAULT 0,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    error           TEXT,
    scan_duration   REAL DEFAULT 0,
    finding_count   INTEGER DEFAULT 0,
    secret_display  TEXT DEFAULT 'smart',
    is_remote       INTEGER NOT NULL DEFAULT 0,
    result_json     TEXT,
    summary_json    TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             TEXT NOT NULL,
    fingerprint         TEXT NOT NULL,
    rule_id             TEXT,
    title               TEXT,
    description         TEXT,
    severity            TEXT,
    confidence          REAL,
    category            TEXT,
    language            TEXT,
    file_path           TEXT,
    line                INTEGER,
    end_line            INTEGER,
    column_num          INTEGER,
    code_snippet        TEXT,
    function_name       TEXT,
    class_name          TEXT,
    cwe                 TEXT,
    cwe_name            TEXT,
    owasp_code          TEXT,
    owasp_title         TEXT,
    cvss_score          REAL,
    cvss_vector         TEXT,
    fix_suggestion      TEXT,
    fixed_code          TEXT,
    references_json     TEXT,
    exploit_scenario    TEXT,
    impact              TEXT,
    why_vulnerable      TEXT,
    is_false_positive   INTEGER DEFAULT 0,
    confidence_reasoning TEXT,
    tags_json           TEXT,
    raw_secret          TEXT,
    reachability        TEXT,
    root_cause          TEXT,
    occurrences         INTEGER DEFAULT 1,
    locations_json      TEXT,
    evidence_json       TEXT
);

CREATE TABLE IF NOT EXISTS finding_state (
    scan_id             TEXT NOT NULL,
    fingerprint         TEXT NOT NULL,
    suppressed          INTEGER DEFAULT 0,
    is_false_positive   INTEGER DEFAULT 0,
    assignee            TEXT,
    issue_url           TEXT,
    notes               TEXT,
    updated_at          TEXT,
    PRIMARY KEY (scan_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_lang ON findings(language);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);
"""


def init_store(db_path: Optional[str] = None) -> None:
    """Create the schema if needed and record the resolved database path."""
    global _db_path
    _db_path = db_path or _env_db_path()
    parent = Path(_db_path).parent
    if str(parent) and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(_db_path)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the initial schema was deployed."""
    existing = {
        row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()
    }
    additions = {
        "occurrences": "ALTER TABLE findings ADD COLUMN occurrences INTEGER DEFAULT 1",
        "locations_json": "ALTER TABLE findings ADD COLUMN locations_json TEXT",
        "evidence_json": "ALTER TABLE findings ADD COLUMN evidence_json TEXT",
    }
    for name, ddl in additions.items():
        if name not in existing:
            conn.execute(ddl)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# --------------------------------------------------------------------------
# Serialization helpers (keep JSON contracts stable)
# --------------------------------------------------------------------------

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def finding_row_to_dict(row) -> dict:
    """Convert a findings row to the same shape as Finding.to_dict()."""
    references = json.loads(row["references_json"]) if row["references_json"] else []
    tags = json.loads(row["tags_json"]) if row["tags_json"] else []
    locations = json.loads(row["locations_json"]) if row["locations_json"] else []
    evidence = json.loads(row["evidence_json"]) if row["evidence_json"] else []
    owasp = None
    if row["owasp_code"]:
        owasp = {"code": row["owasp_code"], "title": row["owasp_title"] or ""}
    cvss = None
    if row["cvss_score"] is not None:
        cvss = {
            "score": row["cvss_score"],
            "vector": row["cvss_vector"] or "",
            "severity": row["severity"] or "info",
        }
    file_path = row["file_path"] or ""
    locations = locations or [{
        "file": file_path,
        "line": row["line"] or 0,
        "end_line": row["end_line"] or row["line"] or 0,
        "column": row["column_num"] or 0,
    }]
    row_keys = set(row.keys())

    def _state_val(*names):
        for name in names:
            if name in row_keys:
                value = row[name]
                if value not in (None, 0, ""):
                    return value
        return None

    state_fp = _state_val("state_fp", "is_false_positive")
    suppressed = _state_val("state_suppressed", "suppressed")
    assignee = _state_val("state_assignee", "assignee")
    issue_url = _state_val("state_issue_url", "issue_url")
    notes = _state_val("state_notes", "notes")
    state: dict = {}
    if suppressed:
        state["suppressed"] = True
    if state_fp:
        state["is_false_positive"] = True
    if assignee:
        state["assignee"] = assignee
    if issue_url:
        state["issue_url"] = issue_url
    if notes:
        state["notes"] = notes
    return {
        "rule_id": row["rule_id"] or "",
        "title": row["title"] or "",
        "description": row["description"] or "",
        "severity": row["severity"] or "info",
        "confidence": round(row["confidence"] or 0.0, 2),
        "category": row["category"] or "security",
        "language": row["language"] or "unknown",
        "cwe": row["cwe"] or "",
        "cwe_name": row["cwe_name"] or "",
        "owasp": owasp,
        "cvss": cvss,
        "cvss_score": cvss["score"] if cvss else None,
        "file": file_path,
        "line": row["line"] or 0,
        "end_line": row["end_line"] or row["line"] or 0,
        "location": {
            "file_path": file_path,
            "line": row["line"] or 0,
            "end_line": row["end_line"] or row["line"] or 0,
            "column": row["column_num"] or 0,
            "code_snippet": row["code_snippet"] or "",
            "function": row["function_name"] or "",
            "class": row["class_name"] or "",
        },
        "function": row["function_name"] or "",
        "class": row["class_name"] or "",
        "code_snippet": row["code_snippet"] or "",
        "fix_suggestion": row["fix_suggestion"] or "",
        "fixed_code": row["fixed_code"] or "",
        "references": references,
        "exploit_scenario": row["exploit_scenario"] or "",
        "impact": row["impact"] or "",
        "why_vulnerable": row["why_vulnerable"] or "",
        "is_false_positive": bool(state_fp),
        "confidence_reasoning": row["confidence_reasoning"] or "",
        "tags": tags,
        "fingerprint": row["fingerprint"] or "",
        "raw_secret": row["raw_secret"] or "",
        "evidence": evidence,
        "occurrences": int(row["occurrences"] or 1),
        "locations": locations,
        "state": state,
        "reachability": row["reachability"] or "",
        "root_cause": row["root_cause"] or "",
    }


def _finding_to_row(scan_id: str, f: dict) -> tuple:
    """Flatten a Finding.to_dict() payload into a row tuple."""
    loc = f.get("location", {}) or {}
    owasp = f.get("owasp") or {}
    cvss = f.get("cvss") or {}
    return (
        scan_id,
        f.get("fingerprint", ""),
        f.get("rule_id", ""),
        f.get("title", ""),
        f.get("description", ""),
        f.get("severity", "info"),
        f.get("confidence", 0.0),
        f.get("category", "security"),
        f.get("language", "unknown"),
        loc.get("file_path", ""),
        loc.get("line", 0),
        loc.get("end_line", loc.get("line", 0)),
        loc.get("column", 0),
        loc.get("code_snippet", ""),
        loc.get("function", ""),
        loc.get("class", ""),
        f.get("cwe", ""),
        f.get("cwe_name", ""),
        owasp.get("code", ""),
        owasp.get("title", ""),
        cvss.get("score"),
        cvss.get("vector", ""),
        f.get("fix_suggestion", ""),
        f.get("fixed_code", ""),
        json.dumps(f.get("references", [])),
        f.get("exploit_scenario", ""),
        f.get("impact", ""),
        f.get("why_vulnerable", ""),
        1 if f.get("is_false_positive") else 0,
        f.get("confidence_reasoning", ""),
        json.dumps(f.get("tags", [])),
        f.get("raw_secret", ""),
        f.get("reachability", ""),
        f.get("root_cause", ""),
        f.get("occurrences", 1) or 1,
        json.dumps(f.get("locations", [])),
        json.dumps(f.get("evidence", [])),
    )


# --------------------------------------------------------------------------
# Scan + finding persistence
# --------------------------------------------------------------------------

def save_scan(
    job_id: str,
    target: str,
    status: str,
    enterprise: bool,
    started_at: str,
    completed_at: str,
    error: str,
    scan_duration: float,
    finding_count: int,
    secret_display: str,
    is_remote: bool,
    result_json: Optional[str] = None,
    summary_json: Optional[str] = None,
) -> None:
    with closing(_connect()) as conn:
        conn.execute(
            """
            INSERT INTO scans (job_id, target, status, enterprise, started_at,
                completed_at, error, scan_duration, finding_count, secret_display,
                is_remote, result_json, summary_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                status=excluded.status,
                completed_at=excluded.completed_at,
                error=excluded.error,
                scan_duration=excluded.scan_duration,
                finding_count=excluded.finding_count,
                result_json=excluded.result_json,
                summary_json=excluded.summary_json
            """,
            (job_id, target, status, 1 if enterprise else 0, started_at,
             completed_at, error, scan_duration, finding_count, secret_display,
             1 if is_remote else 0, result_json, summary_json),
        )
        conn.commit()


_FINDING_COLUMNS = (
    "scan_id", "fingerprint", "rule_id", "title", "description", "severity",
    "confidence", "category", "language", "file_path", "line", "end_line",
    "column_num", "code_snippet", "function_name", "class_name", "cwe",
    "cwe_name", "owasp_code", "owasp_title", "cvss_score", "cvss_vector",
    "fix_suggestion", "fixed_code", "references_json", "exploit_scenario",
    "impact", "why_vulnerable", "is_false_positive", "confidence_reasoning",
    "tags_json", "raw_secret", "reachability", "root_cause",
    "occurrences", "locations_json", "evidence_json",
)


def save_findings(scan_id: str, findings: list[dict]) -> None:
    rows = [_finding_to_row(scan_id, f) for f in findings]
    columns = ",".join(_FINDING_COLUMNS)
    with closing(_connect()) as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        if rows:
            placeholders = ",".join(["?"] * len(rows[0]))
            conn.executemany(
                f"INSERT INTO findings ({columns}) VALUES ({placeholders})",
                rows,
            )
        conn.commit()


def get_scan(job_id: str) -> Optional[dict]:
    """Return a scan record (with result parsed) or None."""
    with closing(_connect()) as conn:
        row = conn.execute("SELECT * FROM scans WHERE job_id = ?", (job_id,)).fetchone()
    if not row:
        return None
    record = _scan_row_to_dict(row)
    return record


def _scan_row_to_dict(row) -> dict:
    result = None
    if row["result_json"]:
        try:
            result = json.loads(row["result_json"])
        except (TypeError, ValueError):
            result = None
    return {
        "job_id": row["job_id"],
        "target": row["target"],
        "status": row["status"],
        "enterprise": bool(row["enterprise"]),
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "error": row["error"] or "",
        "scan_duration": row["scan_duration"] or 0.0,
        "finding_count": row["finding_count"] or 0,
        "secret_display": row["secret_display"] or "smart",
        "is_remote": bool(row["is_remote"]),
        "result": result,
    }


def list_scans(limit: int = 20) -> list[dict]:
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (int(limit),)
        ).fetchall()
    return [_scan_row_to_dict(r) for r in rows]


def count_scans() -> int:
    with closing(_connect()) as conn:
        row = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
    return int(row[0])


_SORT_COLUMNS: dict[str, str] = {
    "severity": "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
    "cvss": "cvss_score",
    "confidence": "confidence",
    "file": "file_path",
    "rule": "rule_id",
    "line": "line",
}


def get_findings(
    scan_id: Optional[str] = None,
    category: str = "",
    severity: str = "",
    rule_id: str = "",
    cwe: str = "",
    owasp: str = "",
    min_cvss: float = 0.0,
    language: str = "",
    file_ext: str = "",
    min_confidence: float = 0.0,
    search: str = "",
    include_suppressed: bool = False,
    status: str = "",
    sort: str = "",
    order: str = "asc",
    limit: int = 100,
    offset: int = 0,
) -> tuple[int, list[dict]]:
    where = []
    params: list = []
    if scan_id:
        where.append("f.scan_id = ?")
        params.append(scan_id)
    if category:
        where.append("LOWER(f.category) = ?")
        params.append(category.lower())
    if severity:
        where.append("LOWER(f.severity) = ?")
        params.append(severity.lower())
    if rule_id:
        where.append("LOWER(f.rule_id) = ?")
        params.append(rule_id.lower())
    if cwe:
        where.append("LOWER(f.cwe) = ?")
        params.append(cwe.lower())
    if owasp:
        where.append("LOWER(f.owasp_code) = ?")
        params.append(owasp.lower())
    if min_cvss > 0:
        where.append("f.cvss_score >= ?")
        params.append(min_cvss)
    if language:
        where.append("LOWER(f.language) = ?")
        params.append(language.lower())
    if file_ext:
        where.append("LOWER(f.file_path) LIKE ?")
        params.append(f"%{file_ext.lower()}%")
    if min_confidence > 0:
        where.append("f.confidence >= ?")
        params.append(min_confidence)
    if not include_suppressed:
        where.append("COALESCE(fs.suppressed, 0) = 0")
    if status == "false_positive":
        where.append("COALESCE(fs.is_false_positive, 0) = 1")
    elif status == "real":
        where.append("COALESCE(fs.is_false_positive, 0) = 0")
    if search:
        where.append(
            "(LOWER(f.title) LIKE ? OR LOWER(f.rule_id) LIKE ? OR LOWER(f.file_path) LIKE ? "
            "OR LOWER(f.cwe) LIKE ? OR LOWER(f.description) LIKE ?)"
        )
        like = f"%{search.lower()}%"
        params.extend([like, like, like, like, like])

    from_clause = (
        "FROM findings f LEFT JOIN finding_state fs "
        "ON fs.scan_id = f.scan_id AND fs.fingerprint = f.fingerprint"
    )
    where_sql = f" WHERE {' AND '.join(where)}" if where else ""
    order_sql = ""
    if sort in _SORT_COLUMNS:
        direction = "DESC" if order == "desc" else "ASC"
        order_sql = f" ORDER BY {_SORT_COLUMNS[sort]} {direction}, f.line ASC"
    else:
        order_sql = " ORDER BY f.id DESC"

    with closing(_connect()) as conn:
        total = conn.execute(
            f"SELECT COUNT(*) {from_clause}{where_sql}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"SELECT f.*, fs.suppressed AS state_suppressed, "
            f"fs.is_false_positive AS state_fp, fs.assignee AS state_assignee, "
            f"fs.issue_url AS state_issue_url, fs.notes AS state_notes "
            f"{from_clause}{where_sql}{order_sql} LIMIT ? OFFSET ?",
            params + [int(limit), int(offset)],
        ).fetchall()
    return int(total), [finding_row_to_dict(r) for r in rows]


def get_finding_by_fingerprint(fingerprint: str) -> Optional[dict]:
    """Search a finding across all scans; enrich with scan metadata."""
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT f.*, s.target AS scan_target, s.completed_at AS scan_date, "
            "fs.suppressed AS state_suppressed, fs.is_false_positive AS state_fp, "
            "fs.assignee AS state_assignee, fs.issue_url AS state_issue_url, "
            "fs.notes AS state_notes "
            "FROM findings f JOIN scans s ON s.job_id = f.scan_id "
            "LEFT JOIN finding_state fs ON fs.scan_id = f.scan_id "
            "AND fs.fingerprint = f.fingerprint "
            "WHERE f.fingerprint = ? ORDER BY f.id DESC LIMIT 1",
            (fingerprint,),
        ).fetchone()
    if not row:
        return None
    d = finding_row_to_dict(row)
    d["scan_id"] = row["scan_id"]
    d["scan_target"] = row["scan_target"] or ""
    d["scan_date"] = row["scan_date"] or ""
    return d


def global_search(q: str, limit: int = 50) -> list[dict]:
    """Global search across findings; returns finding-shaped results."""
    like = f"%{q.lower()}%"
    with closing(_connect()) as conn:
        rows = conn.execute(
            """
            SELECT * FROM findings
            WHERE LOWER(title) LIKE ? OR LOWER(rule_id) LIKE ? OR LOWER(file_path) LIKE ?
               OR LOWER(cwe) LIKE ? OR LOWER(description) LIKE ? OR LOWER(category) LIKE ?
               OR LOWER(language) LIKE ?
            ORDER BY id DESC LIMIT ?
            """,
            (like, like, like, like, like, like, like, int(limit)),
        ).fetchall()

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results = []
    for row in rows:
        d = finding_row_to_dict(row)
        results.append({
            "type": "finding",
            "fingerprint": d["fingerprint"],
            "title": d["title"],
            "rule_id": d["rule_id"],
            "severity": d["severity"],
            "file": d["file"],
            "line": d["line"],
            "category": d["category"],
            "cwe": d["cwe"],
            "scan_id": row["scan_id"],
        })
    results.sort(key=lambda r: sev_rank.get(r.get("severity"), 99))
    return results


# --------------------------------------------------------------------------
# Finding triage state (suppress / false positive / assignee / issue)
# --------------------------------------------------------------------------

def set_finding_state(scan_id: str, fingerprint: str, **fields) -> dict:
    """Create or update the triage state row for a finding.

    Supported fields: suppressed, is_false_positive, assignee, issue_url, notes.
    """
    allowed = {"suppressed", "is_false_positive", "assignee", "issue_url", "notes"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        with closing(_connect()) as conn:
            row = conn.execute(
                "SELECT suppressed, is_false_positive, assignee, issue_url, notes "
                "FROM finding_state WHERE scan_id = ? AND fingerprint = ?",
                (scan_id, fingerprint),
            ).fetchone()
        return _state_row_to_dict(row) if row else {}

    updates["updated_at"] = _utcnow()
    set_clause = ", ".join(f"{k} = excluded.{k}" for k in updates)
    with closing(_connect()) as conn:
        conn.execute(
            f"""
            INSERT INTO finding_state (scan_id, fingerprint, {", ".join(updates)})
            VALUES (?, ?, {", ".join(["?"] * len(updates))})
            ON CONFLICT(scan_id, fingerprint) DO UPDATE SET {set_clause}
            """,
            [scan_id, fingerprint] + list(updates.values()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT suppressed, is_false_positive, assignee, issue_url, notes "
            "FROM finding_state WHERE scan_id = ? AND fingerprint = ?",
            (scan_id, fingerprint),
        ).fetchone()
    return _state_row_to_dict(row)


def _state_row_to_dict(row) -> dict:
    state: dict = {}
    if row["suppressed"]:
        state["suppressed"] = True
    if row["is_false_positive"]:
        state["is_false_positive"] = True
    if row["assignee"]:
        state["assignee"] = row["assignee"]
    if row["issue_url"]:
        state["issue_url"] = row["issue_url"]
    if row["notes"]:
        state["notes"] = row["notes"]
    return state


def get_scan_states(scan_id: str) -> dict[str, dict]:
    """Return {fingerprint: state} for every triaged finding in a scan."""
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT fingerprint, suppressed, is_false_positive, assignee, "
            "issue_url, notes FROM finding_state WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
    return {r["fingerprint"]: _state_row_to_dict(r) for r in rows}


# --------------------------------------------------------------------------
# Aggregates (stats + security score)
# --------------------------------------------------------------------------

def get_stats() -> dict:
    with closing(_connect()) as conn:
        status_rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM scans GROUP BY status"
        ).fetchall()
        total_findings = conn.execute(
            "SELECT COALESCE(SUM(finding_count), 0) FROM scans"
        ).fetchone()[0]
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
        ).fetchall()
        cat_rows = conn.execute(
            "SELECT category, COUNT(*) AS n FROM findings GROUP BY category"
        ).fetchall()

    status_map = {r["status"]: int(r["n"]) for r in status_rows}
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in sev_rows:
        severity_totals[r["severity"]] = int(r["n"])
    category_totals = {r["category"]: int(r["n"]) for r in cat_rows}

    total_scans = sum(status_map.values())
    completed = status_map.get("completed", 0)
    return {
        "total_scans": total_scans,
        "completed_scans": completed,
        "failed_scans": status_map.get("failed", 0),
        "total_findings": int(total_findings),
        "severity_totals": severity_totals,
        "category_totals": category_totals,
        "avg_findings_per_scan": round(int(total_findings) / max(completed, 1), 1),
    }


def get_security_score() -> dict:
    with closing(_connect()) as conn:
        completed = conn.execute(
            "SELECT job_id, completed_at, finding_count FROM scans "
            "WHERE status = 'completed' ORDER BY started_at"
        ).fetchall()
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
        ).fetchall()
        secrets = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE category = 'secret'"
        ).fetchone()[0]

    if not completed:
        return {"score": 100, "grade": "A+", "trend": [], "components": {}}

    sev_map = {r["severity"]: int(r["n"]) for r in sev_rows}
    total = sum(sev_map.values())
    critical = sev_map.get("critical", 0)
    high = sev_map.get("high", 0)
    secrets_count = int(secrets)

    score = max(0, 100 - critical * 8 - high * 3 - secrets_count * 5 - max(0, total // 10))
    score = min(100, score)

    if score < 10:
        grade = "F"
    elif score < 25:
        grade = "D"
    elif score < 45:
        grade = "C"
    elif score < 65:
        grade = "B"
    elif score < 90:
        grade = "A"
    else:
        grade = "A+"

    trend = [
        {"date": r["completed_at"], "score": max(0, 100 - int(r["finding_count"]))}
        for r in completed
    ]
    return {
        "score": score,
        "grade": grade,
        "trend": trend[-30:],
        "components": {
            "critical_findings": critical,
            "high_findings": high,
            "secrets": secrets_count,
            "total_findings": total,
            "scans_completed": len(completed),
        },
    }


# --------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------

def prune_history(max_history: int) -> int:
    """Delete the oldest scans (and their findings) beyond max_history."""
    if max_history < 0:
        return 0
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT job_id FROM scans ORDER BY started_at DESC LIMIT -1 OFFSET ?",
            (int(max_history),),
        ).fetchall()
        removed = 0
        for row in rows:
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (row["job_id"],))
            conn.execute("DELETE FROM scans WHERE job_id = ?", (row["job_id"],))
            removed += 1
        conn.commit()
    return removed
