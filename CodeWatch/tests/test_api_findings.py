"""Tests for the findings API endpoints: filters, sort, bulk triage, metadata."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src import store


@pytest.fixture()
def client():
    from src.api import app
    store.init_store(tempfile.mktemp(suffix=".db"))
    app.config["TESTING"] = True
    yield app.test_client()
    store.init_store(":memory:")


def _seed_scan(scan_id="job1"):
    f1 = {
        "rule_id": "SEC001", "title": "SQL Injection", "description": "Injection",
        "severity": "critical", "confidence": 0.95, "category": "security",
        "language": "python", "cwe": "CWE-89", "cwe_name": "SQL Injection",
        "location": {"file_path": "app.py", "line": 7, "end_line": 7, "column": 1,
                     "code_snippet": "cur.execute(q)", "function": "get_user", "class": ""},
        "fingerprint": "fp1", "occurrences": 3,
        "evidence": [{"type": "regex_match", "detail": "matched", "line": 7}],
    }
    f2 = {
        "rule_id": "SEC002", "title": "Command Injection", "description": "Cmd",
        "severity": "high", "confidence": 0.8, "category": "security",
        "language": "python", "cwe": "CWE-78",
        "location": {"file_path": "cli.py", "line": 12, "end_line": 12, "column": 1,
                     "code_snippet": "os.system(cmd)", "function": "run", "class": ""},
        "fingerprint": "fp2", "occurrences": 1,
    }
    result_json = {
        "repository": "acme/app", "branch": "main", "commit": "abc123",
        "scan_id": scan_id, "rules_executed": 120, "repo_size_bytes": 4096,
        "scan_start": "2026-01-01T00:00:00+00:00",
        "scan_end": "2026-01-01T00:00:01+00:00",
        "scan_duration": 1.0,
        "summary": {"files_scanned": 5, "lines_scanned": 100, "languages": {"python": 5},
                    "risk_score": 40, "grade": "B", "total_findings": 2,
                    "occurrences_total": 4},
        "findings": [f1, f2],
    }
    store.save_scan(
        job_id=scan_id, target="/tmp/repo", status="completed", enterprise=True,
        started_at="2026-01-01T00:00:00+00:00", completed_at="2026-01-01T00:00:01+00:00",
        error="", scan_duration=1.0, finding_count=2, secret_display="smart",
        is_remote=False, result_json=json.dumps(result_json),
        summary_json=json.dumps(result_json["summary"]),
    )
    store.save_findings(scan_id, [f1, f2])


def test_findings_metadata_block(client):
    _seed_scan()
    r = client.get("/api/v1/findings?job_id=job1")
    assert r.status_code == 200, r.data
    body = r.json
    assert body["total"] == 2
    m = body["metadata"]
    assert m["scan_id"] == "job1"
    assert m["repository"] == "acme/app"
    assert m["branch"] == "main"
    assert m["commit"] == "abc123"
    assert m["findings_total"] == 2
    assert m["scanner_tool"] == "CodeWatch"


def test_findings_filters_and_sort(client):
    _seed_scan()
    r = client.get("/api/v1/findings?job_id=job1&severity=critical")
    assert r.status_code == 200
    assert r.json["total"] == 1 and r.json["findings"][0]["rule_id"] == "SEC001"

    r = client.get("/api/v1/findings?job_id=job1&cwe=CWE-78")
    assert r.json["total"] == 1 and r.json["findings"][0]["rule_id"] == "SEC002"

    r = client.get("/api/v1/findings?job_id=job1&search=sql")
    assert r.json["total"] == 1

    r = client.get("/api/v1/findings?job_id=job1&sort=severity&order=desc&limit=1")
    assert len(r.json["findings"]) == 1
    assert r.json["findings"][0]["severity"] == "high"

    r = client.get("/api/v1/findings?job_id=job1&sort=file&order=asc")
    files = [f["file"] for f in r.json["findings"]]
    assert files == sorted(files)


def test_findings_pagination(client):
    _seed_scan()
    r = client.get("/api/v1/findings?job_id=job1&limit=1&offset=1")
    assert r.status_code == 200
    assert r.json["total"] == 2
    assert len(r.json["findings"]) == 1


def test_bulk_actions_persist_state(client):
    _seed_scan()
    r = client.post("/api/v1/findings/bulk", json={
        "scan_id": "job1", "action": "suppress", "fingerprints": ["fp1"],
    })
    assert r.status_code == 200, r.data
    assert r.json["updated"] == 1

    r = client.post("/api/v1/findings/bulk", json={
        "scan_id": "job1", "action": "assign", "fingerprints": ["fp2"], "value": "alice",
    })
    assert r.status_code == 200, r.data
    assert r.json["states"]["fp2"]["assignee"] == "alice"

    # suppressed finding hidden by default
    r = client.get("/api/v1/findings?job_id=job1")
    assert r.json["total"] == 1
    assert r.json["findings"][0]["fingerprint"] == "fp2"

    # visible when include_suppressed=1
    r = client.get("/api/v1/findings?job_id=job1&include_suppressed=1")
    assert r.json["total"] == 2

    # single-finding GET includes state
    r = client.get("/api/v1/findings/fp2")
    assert r.status_code == 200
    assert r.json["state"]["assignee"] == "alice"

    # unsuppress restores visibility
    r = client.post("/api/v1/findings/bulk", json={
        "scan_id": "job1", "action": "unsuppress", "fingerprints": ["fp1"],
    })
    assert r.status_code == 200
    r = client.get("/api/v1/findings?job_id=job1")
    assert r.json["total"] == 2


def test_bulk_actions_validation(client):
    _seed_scan()
    assert client.post("/api/v1/findings/bulk", json={}).status_code == 400
    assert client.post("/api/v1/findings/bulk", json={"scan_id": "job1", "action": "suppress"}).status_code == 400
    assert client.post("/api/v1/findings/bulk", json={"scan_id": "job1", "action": "assign", "fingerprints": ["fp1"]}).status_code == 400
    assert client.post("/api/v1/findings/bulk", json={"scan_id": "job1", "action": "bogus", "fingerprints": ["fp1"]}).status_code == 400


def test_report_formats_have_metadata(client):
    _seed_scan()
    for fmt, needle in (
        ("json", '"repository"'),
        ("html", "acme/app"),
        ("markdown", "acme/app"),
        ("csv", "Occurrences"),
        ("sarif", "acme/app"),
    ):
        r = client.get(f"/api/v1/report/job1?format={fmt}")
        assert r.status_code == 200, (fmt, r.status_code)
        assert needle in r.data.decode("utf-8", errors="ignore"), fmt
