"""Tests for the LLM finding enhancer."""

import pytest

from src.ai import enhancer
from src.ai.llm_client import LLMResponse
from src.core.models import (
    Finding, Severity, FindingCategory, Language, CodeLocation,
)
from src.ai.explainer import explain_finding


def _make_finding(rule_id="SEC001", snippet='cursor.execute("SELECT * FROM users")', severity="HIGH"):
    return Finding(
        rule_id=rule_id,
        title="SQL injection",
        description="User input reaches a raw query",
        severity=Severity(severity.lower()),
        confidence=0.9,
        category=FindingCategory.SECURITY,
        language=Language.PYTHON,
        location=CodeLocation(file_path="app.py", line=10, code_snippet=snippet),
        why_vulnerable="Static explanation",
    )


class _FakeClient:
    available = True
    provider_name = "fake"
    model_name = "fake-model"

    def __init__(self, content=None, calls=None):
        self.content = content or (
            '{"why_vulnerable": "User input flows into SQL", '
            '"impact": "Data breach", '
            '"exploit_scenario": "Craft payload", '
            '"fix_suggestion": "Use parameterized queries"}'
        )
        self._calls = calls if calls is not None else []

    def chat(self, prompt, system_prompt=None):
        self._calls.append(prompt)
        return LLMResponse(content=self.content, provider="fake", model="fake-model")


@pytest.fixture(autouse=True)
def _reset_enhancer(monkeypatch):
    monkeypatch.setattr(enhancer, "_enabled_flag", None)
    monkeypatch.setattr(enhancer, "_cache", {})
    yield


class TestParseResponse:
    def test_plain_json(self):
        fields = enhancer._parse_response(
            '{"why_vulnerable": "A", "impact": "B", "exploit_scenario": "C", "fix_suggestion": "D"}'
        )
        assert fields["why_vulnerable"] == "A"
        assert fields["impact"] == "B"
        assert fields["exploit_scenario"] == "C"
        assert fields["fix_suggestion"] == "D"

    def test_fenced_json(self):
        text = "```json\n{\"why_vulnerable\": \"A\"}\n```"
        fields = enhancer._parse_response(text)
        assert fields["why_vulnerable"] == "A"

    def test_garbage_falls_back_to_why_vulnerable(self):
        fields = enhancer._parse_response("just some prose")
        assert fields["why_vulnerable"].startswith("just some prose")
        assert "impact" not in fields

    def test_empty(self):
        assert enhancer._parse_response("") == {}
        assert enhancer._parse_response("   ") == {}


class TestEnhanceFindings:
    def test_disabled_by_env(self, monkeypatch):
        monkeypatch.setenv("MYSCAN_LLM_ENHANCE", "0")
        stats = enhancer.enhance_findings([_make_finding()])
        assert stats["enabled"] is False
        assert stats["enhanced"] == 0

    def test_no_provider_returns_error(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        stats = enhancer.enhance_findings([_make_finding()])
        assert stats["enabled"] is True
        assert stats["attempted"] == 0
        assert "no LLM provider" in stats["error"]

    def test_fields_applied_and_cached(self, monkeypatch):
        monkeypatch.setattr(enhancer, "LLMClient", _FakeClient)
        finding = _make_finding()
        stats = enhancer.enhance_findings([finding])
        assert stats["enhanced"] == 1
        assert stats["attempted"] == 1
        assert "User input flows into SQL" in finding.why_vulnerable
        assert finding.impact == "Data breach"
        assert "parameterized" in finding.fix_suggestion
        assert len(enhancer._cache) == 1

    def test_cache_reuses_prior_answer(self, monkeypatch):
        fake = _FakeClient()
        monkeypatch.setattr(enhancer, "LLMClient", lambda: fake)
        first = _make_finding()
        second = _make_finding()
        enhancer.enhance_findings([first])
        stats = enhancer.enhance_findings([second])
        assert stats["cached"] >= 1
        assert len(fake._calls) == 1

    def test_severity_priority_limits_count(self, monkeypatch):
        fake = _FakeClient()
        monkeypatch.setattr(enhancer, "LLMClient", lambda: fake)
        findings = [
            _make_finding(rule_id=f"SEC{i:03d}", snippet=f"code {i}", severity="INFO")
            for i in range(10)
        ]
        stats = enhancer.enhance_findings(findings, max_findings=3)
        assert stats["selected"] == 3
        assert len(fake._calls) == 3

    def test_max_findings_env(self, monkeypatch):
        monkeypatch.setenv("MYSCAN_LLM_MAX_FINDINGS", "2")
        fake = _FakeClient()
        monkeypatch.setattr(enhancer, "LLMClient", lambda: fake)
        findings = [_make_finding(rule_id=f"SEC{i:03d}", snippet=f"code {i}") for i in range(6)]
        stats = enhancer.enhance_findings(findings)
        assert stats["selected"] == 2
        assert stats["enhanced"] == 2

    def test_no_findings(self):
        stats = enhancer.enhance_findings([])
        assert stats["enhanced"] == 0
