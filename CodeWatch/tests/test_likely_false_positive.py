"""Tests for the "likely false positive" auto-flag and its persistence."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src import store
from src.core.evidence_engine import Evidence, EvidenceStrength, ValidationResult
from src.core.validation_engine import ValidationPipeline


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
        "location": {
            "file_path": "app.py", "line": 7, "end_line": 7, "column": 5,
            "code_snippet": "cur.execute(query)", "function": "get_user_data", "class": "",
        },
        "fix_suggestion": "Use parameterized queries",
        "references": [],
        "why_vulnerable": "String concatenation",
        "is_false_positive": False,
        "confidence_reasoning": "Direct sink",
        "tags": ["sql"],
        "fingerprint": "abc123",
        "raw_secret": "",
        "reachability": "direct",
        "root_cause": "Unsanitized input",
    }


def _result(negative_reasons=(), confidence=0.9, verification_level="verified") -> ValidationResult:
    negative_evidences = [
        Evidence(
            evidence_type=None,
            signal="fake",
            strength=EvidenceStrength.NEGATIVE,
            weight=1.0,
            confidence_contribution=-0.3,
            reason=reason,
        )
        for reason in negative_reasons
    ]
    return ValidationResult(
        passed=True,
        negative_evidences=negative_evidences,
        confidence=confidence,
        should_report=True,
        verification_level=verification_level,
    )


class TestLikelyFalsePositiveFlag:
    def test_negative_evidence_flags(self):
        engine = ValidationPipeline()
        result = _result(negative_reasons=["Data flows from a safe source"], confidence=0.6)
        flagged, reason = engine._likely_false_positive(result)
        assert flagged is True
        assert "safe source" in reason

    def test_weak_unverified_evidence_flags(self):
        engine = ValidationPipeline()
        result = _result(confidence=0.3, verification_level="unverified")
        flagged, reason = engine._likely_false_positive(result)
        assert flagged is True
        assert "regex match" in reason

    def test_strong_evidence_not_flagged(self):
        engine = ValidationPipeline()
        result = _result(confidence=0.9, verification_level="partially_verified")
        flagged, _ = engine._likely_false_positive(result)
        assert flagged is False

    def test_negative_evidence_but_high_verification_still_flagged(self):
        engine = ValidationPipeline()
        result = _result(negative_reasons=["Weak context"], confidence=0.95, verification_level="verified")
        flagged, _ = engine._likely_false_positive(result)
        assert flagged is True


class TestPersistence:
    def test_new_fields_roundtrip(self, db):
        f = _sample_finding_dict()
        f["verification_level"] = "partially_verified"
        f["matched_pattern"] = r"sk-proj-\w+"
        f["likely_false_positive"] = True
        f["likely_false_positive_reason"] = "Contradictory evidence found during validation"
        store.save_findings("job1", [f])
        total, findings = store.get_findings(scan_id="job1")
        assert total == 1
        d = findings[0]
        assert d["verification_level"] == "partially_verified"
        assert d["matched_pattern"] == r"sk-proj-\w+"
        assert d["likely_false_positive"] is True
        assert d["likely_false_positive_reason"] == "Contradictory evidence found during validation"

    def test_verified_state_roundtrip(self, db):
        store.save_findings("job1", [_sample_finding_dict()])
        store.set_finding_state("job1", "abc123", verified=True, is_false_positive=False)
        _, findings = store.get_findings(scan_id="job1")
        assert findings[0]["state"].get("verified") is True

    def test_likely_fp_status_filter(self, db):
        f = _sample_finding_dict()
        f["likely_false_positive"] = True
        f["fingerprint"] = "fpA"
        store.save_findings("job1", [f])
        g = _sample_finding_dict()
        g["likely_false_positive"] = False
        g["fingerprint"] = "fpB"
        store.save_findings("job2", [g])
        total, _ = store.get_findings(status="likely_fp")
        assert total == 1
