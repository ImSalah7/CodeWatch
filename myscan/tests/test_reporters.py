"""Tests for reporters."""

import pytest
from src.core.models import (
    ScanResult, Finding, Severity, FindingCategory, Language,
    CodeLocation, CVSS, OWASPTop10,
)
from src.reporters.sarif import SARIFReporter
from src.reporters.html_report import HTMLReporter
from src.reporters.csv_report import CSVReporter
from src.reporters.json_report import JSONReporter
from src.reporters.markdown_report import MarkdownReporter
import json


@pytest.fixture
def sample_result():
    result = ScanResult()
    result.files_scanned = 5
    result.lines_scanned = 500
    result.scan_duration = 2.5
    result.languages_detected = {"python": 3, "javascript": 2}
    result.findings = [
        Finding(
            rule_id="SEC001", title="SQL Injection",
            description="SQL injection vulnerability",
            severity=Severity.CRITICAL, confidence=0.9,
            category=FindingCategory.SECURITY, language=Language.PYTHON,
            location=CodeLocation(file_path="app.py", line=10, code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"'),
            cwe="CWE-89", cwe_name="SQL Injection",
            owasp=OWASPTop10.A03_INJECTION,
            fix_suggestion="Use parameterized queries",
            why_vulnerable="User input directly interpolated into SQL query",
            impact="Full database compromise",
        ),
        Finding(
            rule_id="QLT001", title="Long Line",
            description="Line exceeds 120 characters",
            severity=Severity.INFO, confidence=1.0,
            category=FindingCategory.QUALITY, language=Language.PYTHON,
            location=CodeLocation(file_path="app.py", line=5),
        ),
        Finding(
            rule_id="SEC_AWS_ACCESS_KEY", title="AWS Access Key",
            description="Found AWS access key",
            severity=Severity.CRITICAL, confidence=0.95,
            category=FindingCategory.SECRET, language=Language.PYTHON,
            location=CodeLocation(file_path="config.py", line=1),
        ),
    ]
    return result


class TestSARIFReporter:
    def test_generate(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate(sample_result)
        data = json.loads(sarif)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 3

    def test_has_rules(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate(sample_result)
        data = json.loads(sarif)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) > 0


class TestHTMLReporter:
    def test_generate(self, sample_result):
        reporter = HTMLReporter()
        html = reporter.generate(sample_result)
        assert "<!DOCTYPE html>" in html
        assert "SQL Injection" in html
        assert "Critical" in html or "critical" in html


class TestCSVReporter:
    def test_generate(self, sample_result):
        reporter = CSVReporter()
        csv = reporter.generate(sample_result)
        lines = csv.strip().split("\n")
        assert len(lines) == 4
        assert "Rule ID" in lines[0]
        assert "SEC001" in lines[1]


class TestJSONReporter:
    def test_generate(self, sample_result):
        reporter = JSONReporter()
        json_str = reporter.generate(sample_result)
        data = json.loads(json_str)
        assert data["tool"]["name"] == "MyScan"
        assert data["summary"]["totalFindings"] == 3


class TestMarkdownReporter:
    def test_generate(self, sample_result):
        reporter = MarkdownReporter()
        md = reporter.generate(sample_result)
        assert "MyScan" in md
        assert "SQL Injection" in md
