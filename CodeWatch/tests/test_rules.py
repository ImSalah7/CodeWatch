"""Tests for rules system."""

from src.core.models import FindingCategory, OWASPTop10, Severity
from src.core.rules import ALL_RULES, RULE_MAP


class TestRules:
    def test_rules_loaded(self):
        assert len(ALL_RULES) > 0
        assert len(ALL_RULES) >= 40

    def test_rule_ids_unique(self):
        ids = [r.id for r in ALL_RULES]
        assert len(ids) == len(set(ids))

    def test_rule_map(self):
        for rule in ALL_RULES:
            assert rule.id in RULE_MAP

    def test_security_rules_have_cwe(self):
        security_rules = [r for r in ALL_RULES if r.category == FindingCategory.SECURITY]
        for rule in security_rules:
            if rule.cwe:
                assert rule.cwe.startswith("CWE-")

    def test_critical_rules_have_cvss(self):
        critical_rules = [r for r in ALL_RULES if r.severity == Severity.CRITICAL and r.cvss_config]
        for rule in critical_rules:
            cvss = rule.get_cvss()
            assert cvss.base_score > 0

    def test_injection_rules(self):
        injection_rules = [r for r in ALL_RULES if r.owasp == OWASPTop10.A03_INJECTION]
        assert len(injection_rules) >= 5

    def test_access_control_rules(self):
        access_rules = [r for r in ALL_RULES if r.owasp == OWASPTop10.A01_BROKEN_ACCESS_CONTROL]
        assert len(access_rules) >= 3

    def test_crypto_rules(self):
        crypto_rules = [r for r in ALL_RULES if r.owasp == OWASPTop10.A02_CRYPTOGRAPHIC_FAILURES]
        assert len(crypto_rules) >= 3

    def test_quality_rules(self):
        quality_rules = [r for r in ALL_RULES if r.category == FindingCategory.QUALITY]
        assert len(quality_rules) >= 8

    def test_rules_have_fix_suggestions(self):
        security_rules = [r for r in ALL_RULES if r.category == FindingCategory.SECURITY]
        for rule in security_rules:
            assert rule.fix_suggestion, f"Rule {rule.id} missing fix suggestion"
