"""Unit tests for the SQLite persistence layer."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src import store
from src.serialization import finding_from_dict, result_from_dict


@pytest.fixture()
def db(tmp_path):
    store.init_store(str(tmp_path / "test.db"))
    yield
    store.init_store(":memory:")


def _sample_finding_dict():
    return {
        "rule_id": "SEC001",
        "title": "SQL injection detected",
        "description": "User input concatenated into query",
        "severity": "critical",
        "confidence": 0.95,
        "category": "security",
        "language": "python",
        "cwe": "CWE-89",
        "cwe_name": "SQL Injection",
        "owasp": {"code": "A03:2021", "title": "Injection"},
        "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L", "severity": "critical"},
        "location": {
            "file_path": "app.py", "line": 7, "end_line": 7, "column": 5,
            "code_snippet": "cur.execute(query)", "function": "get_user_data", "class": "",
        },
        "fix_suggestion": "Use parameterized queries",
        "fixed_code": "cur.execute('SELECT name FROM users WHERE id=?', (user_id,))",
        "references": ["https://example.com/fix"],
        "exploit_scenario": "Attacker submits OR 1=1",
        "impact": "Data breach",
        "why_vulnerable": "String concatenation",
        "is_false_positive": False,
        "confidence_reasoning": "Direct sink",
        "tags": ["sql"],
        "fingerprint": "abc123",
        "raw_secret": "",
        "reachability": "direct",
        "root_cause": "Unsanitized input",
    }


def test_scan_crud_roundtrip(db):
    store.save_scan(
        job_id="job1", target="/tmp/repo", status="completed", enterprise=False,
        started_at="2026-01-01T00:00:00+00:00", completed_at="2026-01-01T00:00:01+00:00",
        error="", scan_duration=1.5, finding_count=1, secret_display="smart",
        is_remote=False, result_json='{"summary": {"x": 1}}', summary_json='{"x": 1}',
    )
    rec = store.get_scan("job1")
    assert rec is not None
    assert rec["status"] == "completed"
    assert rec["result"] == {"summary": {"x": 1}}
    assert store.count_scans() == 1


def test_findings_save_and_shape(db):
    store.save_findings("job1", [_sample_finding_dict()])
    total, findings = store.get_findings(scan_id="job1")
    assert total == 1
    d = findings[0]
    assert d["rule_id"] == "SEC001"
    assert d["severity"] == "critical"
    assert d["category"] == "security"
    assert d["cwe"] == "CWE-89"
    assert d["owasp"] == {"code": "A03:2021", "title": "Injection"}
    assert d["cvss"]["score"] == 9.8
    assert d["location"]["file_path"] == "app.py"
    assert d["references"] == ["https://example.com/fix"]
    assert d["is_false_positive"] is False
    assert d["reachability"] == "direct"
    assert d["root_cause"] == "Unsanitized input"


def test_findings_filters(db):
    for i in range(5):
        f = _sample_finding_dict()
        f["severity"] = "high" if i % 2 else "critical"
        f["fingerprint"] = f"fp{i}"
        store.save_findings(f"job{i}", [f])

    total, _ = store.get_findings(severity="critical")
    assert total == 3
    total, _ = store.get_findings(severity="high")
    assert total == 2
    total, _ = store.get_findings(category="security")
    assert total == 5
    total, _ = store.get_findings(search="injection", limit=2)
    assert total == 5
    total, _ = store.get_findings(search="bogus")
    assert total == 0


def test_finding_by_fingerprint_enriched(db):
    store.save_scan(
        job_id="job1", target="/tmp/repo", status="completed", enterprise=False,
        started_at="2026-01-01T00:00:00+00:00", completed_at="2026-01-01T00:00:01+00:00",
        error="", scan_duration=1.0, finding_count=1, secret_display="smart",
        is_remote=False, result_json=None, summary_json=None,
    )
    store.save_findings("job1", [_sample_finding_dict()])
    d = store.get_finding_by_fingerprint("abc123")
    assert d is not None
    assert d["scan_id"] == "job1"
    assert d["scan_target"] == "/tmp/repo"
    assert d["scan_date"]


def test_finding_state_lifecycle(db):
    store.save_findings("job1", [_sample_finding_dict()])
    state = store.set_finding_state("job1", "abc123", suppressed=True)
    assert state.get("suppressed") is True
    assert store.get_scan_states("job1")["abc123"].get("suppressed") is True

    store.set_finding_state("job1", "abc123", suppressed=False, is_false_positive=True)
    state = store.get_scan_states("job1")["abc123"]
    assert state.get("suppressed") is None
    assert state.get("is_false_positive") is True

    store.set_finding_state("job1", "abc123", assignee="alice", issue_url="https://github.com/o/1", notes="triaged")
    state = store.get_scan_states("job1")["abc123"]
    assert state["assignee"] == "alice"
    assert state["issue_url"] == "https://github.com/o/1"
    assert state["notes"] == "triaged"


def test_findings_state_filters(db):
    f1 = _sample_finding_dict()
    f2 = _sample_finding_dict()
    f2["fingerprint"] = "fp2"
    f2["rule_id"] = "SEC002"
    store.save_findings("job1", [f1, f2])
    store.set_finding_state("job1", "abc123", suppressed=True)
    store.set_finding_state("job1", "fp2", is_false_positive=True)

    total, findings = store.get_findings(scan_id="job1", status="false_positive", include_suppressed=True)
    assert total == 1 and findings[0]["fingerprint"] == "fp2"

    total, findings = store.get_findings(scan_id="job1", status="real", include_suppressed=True)
    assert total == 1 and findings[0]["fingerprint"] == "abc123"

    total, findings = store.get_findings(scan_id="job1", include_suppressed=False)
    assert total == 1 and findings[0]["fingerprint"] == "fp2"

    total, findings = store.get_findings(scan_id="job1", include_suppressed=True)
    assert total == 2
    by_fp = {f["fingerprint"]: f for f in findings}
    assert by_fp["abc123"]["state"]["suppressed"] is True
    assert by_fp["fp2"]["state"]["is_false_positive"] is True


def test_findings_sort(db):
    findings = []
    for i in range(3):
        f = _sample_finding_dict()
        f["fingerprint"] = f"s{i}"
        f["severity"] = ["critical", "low", "high"][i]
        f["location"]["line"] = f["line"] = [7, 100, 30][i]
        findings.append(f)
    store.save_findings("job1", findings)
    _, findings = store.get_findings(scan_id="job1", sort="severity", order="asc")
    assert [f["severity"] for f in findings] == ["critical", "high", "low"]
    _, findings = store.get_findings(scan_id="job1", sort="severity", order="desc")
    assert [f["severity"] for f in findings] == ["low", "high", "critical"]
    _, findings = store.get_findings(scan_id="job1", sort="line", order="asc")
    assert [f["line"] for f in findings] == [7, 30, 100]


def test_global_search(db):
    for i in range(3):
        f = _sample_finding_dict()
        f["fingerprint"] = f"gfp{i}"
        f["rule_id"] = f"RULE{i}"
        store.save_findings(f"job{i}", [f])
    res = store.global_search("injection")
    assert len(res) == 3
    assert res[0]["type"] == "finding"
    res = store.global_search("RULE1")
    assert len(res) == 1
    assert res[0]["rule_id"] == "RULE1"


def test_prune_history(db):
    for i in range(10):
        store.save_scan(
            job_id=f"job{i}", target=f"/t{i}", status="completed", enterprise=False,
            started_at=f"2026-01-0{i+1:02d}T00:00:00+00:00", completed_at="",
            error="", scan_duration=0.0, finding_count=i, secret_display="smart",
            is_remote=False, result_json=None, summary_json=None,
        )
    removed = store.prune_history(3)
    assert removed == 7
    assert store.count_scans() == 3


def test_stats_and_score(db):
    for i in range(3):
        f = _sample_finding_dict()
        f["severity"] = "critical" if i == 0 else "low"
        store.save_findings(f"job{i}", [f])
        store.save_scan(
            job_id=f"job{i}", target=f"/t{i}", status="completed", enterprise=False,
            started_at=f"2026-01-0{i+1:02d}T00:00:00+00:00", completed_at="2026-01-01T00:00:01+00:00",
            error="", scan_duration=1.0, finding_count=1, secret_display="smart",
            is_remote=False, result_json=None, summary_json=None,
        )
    stats = store.get_stats()
    assert stats["total_scans"] == 3
    assert stats["completed_scans"] == 3
    assert stats["severity_totals"]["critical"] == 1
    score = store.get_security_score()
    assert score["score"] < 100
    assert len(score["trend"]) == 3


def test_serialization_roundtrip(db):
    from src.core.models import ScanResult
    d = _sample_finding_dict()
    payload = {
        "tool": "MyScan", "version": "3.0.0",
        "scan_start": "2026-01-01T00:00:00+00:00",
        "scan_end": "2026-01-01T00:00:05+00:00",
        "scan_duration": 5.0,
        "summary": {
            "total_findings": 1, "security_findings": 1, "quality_findings": 0,
            "secret_findings": 0, "risk_score": 24, "grade": "C",
            "severity_counts": {"critical": 1},
            "files_scanned": 2, "lines_scanned": 10,
            "languages": {"python": 1},
        },
        "findings": [d],
    }
    result = result_from_dict(payload)
    assert isinstance(result, ScanResult)
    assert result.files_scanned == 2
    assert result.lines_scanned == 10
    assert result.languages_detected == {"python": 1}
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "SEC001"
    assert f.severity.value == "critical"
    assert f.category.value == "security"
    assert f.language.value == "python"
    assert f.cvss.base_score == 9.8
    assert f.owasp.code == "A03:2021"
    # Round trip through to_dict must be stable
    again = f.to_dict()
    assert again["rule_id"] == "SEC001"
    assert again["severity"] == "critical"
    assert again["owasp"] == {"code": "A03:2021", "title": "Injection"}
