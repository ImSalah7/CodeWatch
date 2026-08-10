"""Tests for the severity gating engine.

HIGH/CRITICAL findings must be backed by strong evidence and sufficient
confidence. The gate only ever demotes - it never promotes.
"""

from src.core.models import (
    CodeLocation,
    Finding,
    FindingCategory,
    Language,
    ScanResult,
    Severity,
)
from src.core.severity_gate import apply_severity_gate, gate_severity


def _finding(
    severity=Severity.HIGH,
    confidence=0.9,
    evidence=None,
    verification_level="unverified",
    reasoning="",
):
    return Finding(
        rule_id="SEC001",
        title="Test Finding",
        description="test",
        severity=severity,
        confidence=confidence,
        category=FindingCategory.SECURITY,
        language=Language.PYTHON,
        location=CodeLocation(file_path="app.py", line=1, code_snippet="x = 1"),
        confidence_reasoning=reasoning,
        verification_level=verification_level,
        evidence=evidence or [],
    )


STRONG_SECRET_EVIDENCE = [{
    "evidences": [{
        "type": "secret_classified",
        "strength": "strong",
        "reason": "Secret classified as AWS Access Key",
    }],
}]

REGEX_ONLY_EVIDENCE = [{
    "evidences": [{
        "type": "regex_match",
        "strength": "strong",
        "reason": "Regex pattern matched",
    }],
}]

MODERATE_TAINT_EVIDENCE = [{
    "evidences": [{
        "type": "taint_path",
        "strength": "moderate",
        "reason": "Partial taint path",
    }],
}]


class TestGateSeverity:
    def test_high_with_strong_evidence_stays_high(self):
        f = _finding(severity=Severity.HIGH, confidence=0.9, evidence=STRONG_SECRET_EVIDENCE)
        sev, note = gate_severity(f)
        assert sev == Severity.HIGH
        assert note == ""

    def test_critical_with_strong_evidence_stays_critical(self):
        f = _finding(severity=Severity.CRITICAL, confidence=0.95, evidence=STRONG_SECRET_EVIDENCE)
        sev, note = gate_severity(f)
        assert sev == Severity.CRITICAL
        assert note == ""

    def test_high_without_strong_evidence_is_demoted(self):
        f = _finding(severity=Severity.HIGH, confidence=0.9, evidence=REGEX_ONLY_EVIDENCE)
        sev, note = gate_severity(f)
        assert sev == Severity.MEDIUM
        assert "no strong evidence" in note

    def test_critical_without_strong_evidence_is_demoted(self):
        f = _finding(severity=Severity.CRITICAL, confidence=0.95, evidence=REGEX_ONLY_EVIDENCE)
        sev, _ = gate_severity(f)
        assert sev == Severity.MEDIUM

    def test_strong_verification_level_counts_as_strong_evidence(self):
        f = _finding(severity=Severity.HIGH, confidence=0.8, verification_level="certain")
        sev, note = gate_severity(f)
        assert sev == Severity.HIGH
        assert note == ""

    def test_high_confidence_floor_demotion(self):
        f = _finding(severity=Severity.HIGH, confidence=0.5, evidence=STRONG_SECRET_EVIDENCE)
        sev, note = gate_severity(f)
        assert sev == Severity.MEDIUM
        assert "confidence" in note

    def test_critical_confidence_floor_demotion_to_high(self):
        f = _finding(severity=Severity.CRITICAL, confidence=0.7, evidence=STRONG_SECRET_EVIDENCE)
        sev, _ = gate_severity(f)
        assert sev == Severity.HIGH

    def test_low_confidence_demotes_to_info(self):
        f = _finding(severity=Severity.LOW, confidence=0.1, evidence=STRONG_SECRET_EVIDENCE)
        sev, _ = gate_severity(f)
        assert sev == Severity.INFO

    def test_medium_stays_medium_when_floor_met(self):
        f = _finding(severity=Severity.MEDIUM, confidence=0.5)
        sev, note = gate_severity(f)
        assert sev == Severity.MEDIUM
        assert note == ""

    def test_never_promotes(self):
        f = _finding(severity=Severity.MEDIUM, confidence=0.95, evidence=STRONG_SECRET_EVIDENCE)
        sev, _ = gate_severity(f)
        assert sev == Severity.MEDIUM

    def test_info_never_demoted(self):
        f = _finding(severity=Severity.INFO, confidence=0.0)
        sev, _ = gate_severity(f)
        assert sev == Severity.INFO

    def test_trusted_moderate_evidence_with_high_confidence_counts(self):
        f = _finding(severity=Severity.HIGH, confidence=0.8, evidence=MODERATE_TAINT_EVIDENCE)
        sev, note = gate_severity(f)
        assert sev == Severity.HIGH
        assert note == ""

    def test_flat_evidence_entries_are_parsed(self):
        f = _finding(
            severity=Severity.CRITICAL,
            confidence=0.9,
            evidence=[{"type": "literal_assignment", "strength": "strong", "reason": "literal"}],
        )
        sev, _ = gate_severity(f)
        assert sev == Severity.CRITICAL


class TestApplySeverityGate:
    def test_mutates_severity_and_records_reasoning(self):
        f = _finding(severity=Severity.HIGH, confidence=0.9, evidence=REGEX_ONLY_EVIDENCE)
        changed = apply_severity_gate(f)
        assert changed is True
        assert f.severity == Severity.MEDIUM
        assert "no strong evidence" in f.confidence_reasoning

    def test_unchanged_when_strong(self):
        f = _finding(severity=Severity.HIGH, confidence=0.9, evidence=STRONG_SECRET_EVIDENCE)
        changed = apply_severity_gate(f)
        assert changed is False
        assert f.severity == Severity.HIGH

    def test_reasoning_is_prepended_not_clobbered(self):
        f = _finding(
            severity=Severity.HIGH,
            confidence=0.9,
            evidence=REGEX_ONLY_EVIDENCE,
            reasoning="existing explanation",
        )
        apply_severity_gate(f)
        assert "Confidence capped at 0.60" in f.confidence_reasoning
        assert "Severity HIGH demoted" in f.confidence_reasoning
        assert "existing explanation" in f.confidence_reasoning


class TestConfidenceCap:
    def test_regex_only_confidence_capped(self):
        f = _finding(severity=Severity.MEDIUM, confidence=0.85, evidence=REGEX_ONLY_EVIDENCE)
        changed = apply_severity_gate(f)
        assert changed is True
        assert f.confidence <= 0.60

    def test_strong_evidence_confidence_not_capped(self):
        f = _finding(severity=Severity.HIGH, confidence=0.9, evidence=STRONG_SECRET_EVIDENCE)
        apply_severity_gate(f)
        assert f.confidence == 0.9
        assert f.severity == Severity.HIGH

    def test_already_capped_not_flagged_changed(self):
        f = _finding(severity=Severity.MEDIUM, confidence=0.5, evidence=REGEX_ONLY_EVIDENCE)
        changed = apply_severity_gate(f)
        assert changed is False
        assert f.confidence == 0.5


class TestScanResultGating:
    def test_applies_to_all_findings(self):
        result = ScanResult()
        result.findings = [
            _finding(severity=Severity.HIGH, confidence=0.9, evidence=REGEX_ONLY_EVIDENCE),
            _finding(severity=Severity.CRITICAL, confidence=0.95, evidence=STRONG_SECRET_EVIDENCE),
            _finding(severity=Severity.MEDIUM, confidence=0.5),
        ]
        result.apply_severity_gates()
        severities = {f.severity for f in result.findings}
        assert severities == {Severity.MEDIUM, Severity.CRITICAL}

    def test_severity_counts_reflect_gated_values(self):
        result = ScanResult()
        result.findings = [
            _finding(severity=Severity.HIGH, confidence=0.9, evidence=REGEX_ONLY_EVIDENCE),
            _finding(severity=Severity.HIGH, confidence=0.9, evidence=STRONG_SECRET_EVIDENCE),
        ]
        result.apply_severity_gates()
        counts = result.severity_counts
        assert counts["high"] == 1
        assert counts["medium"] == 1
