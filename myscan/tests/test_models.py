"""Tests for core models."""

from src.core.models import (
    CVSS,
    EXTENSION_MAP,
    CodeLocation,
    Finding,
    FindingCategory,
    Language,
    OWASPTop10,
    ScanResult,
    Severity,
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

    def test_group_duplicates(self):
        def make(line):
            return Finding(
                rule_id="SEC001", title="SQL Injection", description="d",
                severity=Severity.CRITICAL, confidence=0.9,
                category=FindingCategory.SECURITY, language=Language.PYTHON,
                location=CodeLocation(file_path="app.py", line=line,
                                      code_snippet="cursor.execute(query)"),
            )
        r = ScanResult()
        a, b, c = make(10), make(20), make(30)
        c.severity = Severity.HIGH
        r.findings = [a, b, c]
        r.group_duplicates()
        assert len(r.findings) == 1
        g = r.findings[0]
        assert g.occurrences == 3
        assert len(g.locations) == 3
        # Primary is max(confidence, severity.numeric, line): (0.9, 5, 20) beats (0.9, 4, 30)
        assert g.location.line == 20
        assert r.occurrences_total == 3

    def test_group_duplicates_distinct_rules_stay_separate(self):
        def make(rule, line):
            return Finding(
                rule_id=rule, title="T", description="d",
                severity=Severity.HIGH, confidence=0.8,
                category=FindingCategory.SECURITY, language=Language.PYTHON,
                location=CodeLocation(file_path="app.py", line=line,
                                      code_snippet="sink(x)"),
            )
        r = ScanResult()
        r.findings = [make("SEC001", 1), make("SEC002", 2)]
        r.group_duplicates()
        assert len(r.findings) == 2
        assert r.occurrences_total == 2

    def test_finding_to_dict_roundtrip_new_fields(self):
        f = Finding(
            rule_id="SEC001", title="T", description="d",
            severity=Severity.HIGH, confidence=0.8,
            category=FindingCategory.SECURITY, language=Language.PYTHON,
            location=CodeLocation(file_path="app.py", line=5),
            evidence=[{"type": "regex_match", "detail": "matched"}],
            occurrences=3,
            locations=[{"file": "app.py", "line": 5}, {"file": "app.py", "line": 9}],
            state={"suppressed": True},
        )
        d = f.to_dict()
        assert d["occurrences"] == 3
        assert d["evidence"] == [{"type": "regex_match", "detail": "matched"}]
        assert d["state"] == {"suppressed": True}
        assert len(d["locations"]) == 2
