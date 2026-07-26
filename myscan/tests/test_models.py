"""Tests for core models."""

import pytest
from src.core.models import (
    Severity, FindingCategory, OWASPTop10, Language, CVSS,
    CodeLocation, Finding, ScanResult, EXTENSION_MAP,
)


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL.numeric > Severity.HIGH.numeric > Severity.MEDIUM.numeric > Severity.LOW.numeric > Severity.INFO.numeric

    def test_weight(self):
        assert Severity.CRITICAL.weight == 25
        assert Severity.HIGH.weight == 15
        assert Severity.INFO.weight == 1

    def test_numeric(self):
        assert Severity.CRITICAL.numeric == 5
        assert Severity.INFO.numeric == 1


class TestOWASP:
    def test_codes(self):
        assert OWASPTop10.A01_BROKEN_ACCESS_CONTROL.code == "A01:2021"
        assert OWASPTop10.A03_INJECTION.code == "A03:2021"
        assert OWASPTop10.A10_SSRF.code == "A10:2021"


class TestCVSS:
    def test_critical_score(self):
        cvss = CVSS()
        score = cvss.calculate()
        assert 0.0 <= score <= 10.0

    def test_severity_mapping(self):
        cvss = CVSS()
        score = cvss.calculate(attack_vector="N", attack_complexity="L", privileges="N",
                      user_interaction="N", scope="C", confidentiality="H",
                      integrity="H", availability="H")
        assert score > 0
        assert cvss.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)


class TestLanguage:
    def test_extension_map(self):
        assert EXTENSION_MAP[".py"] == Language.PYTHON
        assert EXTENSION_MAP[".js"] == Language.JAVASCRIPT
        assert EXTENSION_MAP[".java"] == Language.JAVA
        assert EXTENSION_MAP[".go"] == Language.GO


class TestCodeLocation:
    def test_defaults(self):
        loc = CodeLocation(file_path="test.py", line=10)
        assert loc.end_line == 10


class TestFinding:
    def test_creation(self):
        f = Finding(
            rule_id="TEST001",
            title="Test Finding",
            description="A test finding",
            severity=Severity.HIGH,
            confidence=0.8,
            category=FindingCategory.SECURITY,
            language=Language.PYTHON,
            location=CodeLocation(file_path="test.py", line=10),
            cwe="CWE-89",
        )
        assert f.rule_id == "TEST001"
        assert f.fingerprint
        assert f.to_dict()["severity"] == "high"

    def test_deduplication(self):
        f1 = Finding(
            rule_id="TEST001", title="Test", description="Test",
            severity=Severity.HIGH, confidence=0.8,
            category=FindingCategory.SECURITY, language=Language.PYTHON,
            location=CodeLocation(file_path="test.py", line=10),
        )
        f2 = Finding(
            rule_id="TEST001", title="Test", description="Test",
            severity=Severity.HIGH, confidence=0.8,
            category=FindingCategory.SECURITY, language=Language.PYTHON,
            location=CodeLocation(file_path="test.py", line=10),
        )
        assert f1.fingerprint == f2.fingerprint


class TestScanResult:
    def test_empty(self):
        r = ScanResult()
        assert r.risk_score == 0
        assert r.grade == "A+"
        assert r.security_findings == []

    def test_grade_calculation(self):
        r = ScanResult()
        r.findings = [
            Finding(
                rule_id="T", title="T", description="T",
                severity=Severity.CRITICAL, confidence=1.0,
                category=FindingCategory.SECURITY, language=Language.PYTHON,
                location=CodeLocation(file_path="x.py", line=1),
            )
        ]
        assert r.risk_score > 0
        assert r.grade in ("A", "B", "C", "D", "F")

    def test_deduplicate(self):
        r = ScanResult()
        f = Finding(
            rule_id="T", title="T", description="T",
            severity=Severity.HIGH, confidence=0.8,
            category=FindingCategory.SECURITY, language=Language.PYTHON,
            location=CodeLocation(file_path="x.py", line=1),
        )
        r.findings = [f, f]
        r.deduplicate()
        assert len(r.findings) == 1
