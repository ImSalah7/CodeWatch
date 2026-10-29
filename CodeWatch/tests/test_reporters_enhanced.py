"""Tests for enterprise reporters, fix generator, and AI explainer."""

import json

from src import __version__
from src.ai.explainer import (
    CATEGORY_EXPLANATIONS,
    FindingExplanation,
    explain_finding,
    explain_taint_flow,
    get_severity_explanation,
)
from src.core.fix_generator import (
    generate_fix,
    generate_secure_alternative,
)
from src.core.models import (
    CVSS,
    CodeLocation,
    Finding,
    FindingCategory,
    Language,
    ScanResult,
    Severity,
)


def _make_finding(severity="HIGH", category="SECURITY", title="Test Finding",
                  rule_id="SEC001", cwe="CWE-89", confidence=0.8):
    return Finding(
        rule_id=rule_id,
        title=title,
        description="Test description",
        severity=Severity(severity.lower()),
        confidence=confidence,
        category=FindingCategory(category.lower()) if category.lower() in [e.value for e in FindingCategory] else FindingCategory.SECURITY,
        language=Language.PYTHON,
        location=CodeLocation(file_path="app.py", line=10, code_snippet="cursor.execute(\"SELECT * FROM users\")"),
        cwe=cwe,
        fix_suggestion="Use parameterized queries",
    )


class TestFixGenerator:
    def test_generate_fix_sql_injection(self):
        fixes = generate_fix("sql_injection", 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)')
        assert len(fixes) > 0
        assert fixes[0].confidence > 0.8
        assert "parameterized" in fixes[0].description.lower() or "Parameterized" in fixes[0].description

    def test_generate_fix_command_injection(self):
        fixes = generate_fix("command_injection", 'os.system("ping " + user_input)')
        assert len(fixes) > 0
        assert any("subprocess" in f.description.lower() for f in fixes)

    def test_generate_fix_eval(self):
        fixes = generate_fix("code_injection", 'result = eval(user_input)')
        assert len(fixes) > 0
        assert any("literal_eval" in f.description.lower() or "json" in f.description.lower() for f in fixes)

    def test_generate_fix_xss(self):
        fixes = generate_fix("xss", 'element.innerHTML = userInput')
        assert len(fixes) > 0

    def test_generate_fix_hardcoded_secret(self):
        fixes = generate_fix("hardcoded_secret", 'password = "SuperSecret123!"')
        assert len(fixes) > 0
        assert any("environ" in f.description.lower() for f in fixes)

    def test_generate_fix_unknown_category(self):
        fixes = generate_fix("unknown_category")
        assert len(fixes) == 1
        assert fixes[0].confidence == 0.5

    def test_secure_alternative_sql(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        result = generate_secure_alternative("sql_injection", code)
        assert result is not None
        assert len(result) > 0

    def test_secure_alternative_command(self):
        code = 'os.system("ping " + user_input)'
        result = generate_secure_alternative("command_injection", code)
        assert result is not None

    def test_fix_has_references(self):
        fixes = generate_fix("sql_injection")
        assert len(fixes) > 0
        assert len(fixes[0].references) > 0
        assert any("owasp" in r.lower() or "cwe" in r.lower() for r in fixes[0].references)

    def test_fix_has_effort(self):
        fixes = generate_fix("sql_injection")
        assert fixes[0].effort in ("low", "medium", "high")


class TestAIExplainer:
    def test_explain_sql_injection(self):
        exp = explain_finding(
            category="sql_injection",
            file_path="app.py",
            line=10,
            severity="HIGH",
            confidence=0.9,
            code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        )
        assert isinstance(exp, FindingExplanation)
        assert len(exp.summary) > 0
        assert len(exp.detailed_explanation) > 0
        assert len(exp.exploit_scenario) > 0
        assert len(exp.impact) > 0
        assert len(exp.remediation_steps) > 0
        assert exp.confidence == 0.9

    def test_explain_command_injection(self):
        exp = explain_finding(category="command_injection")
        assert "command" in exp.summary.lower() or "os" in exp.summary.lower()

    def test_explain_eval(self):
        exp = explain_finding(category="code_injection")
        assert "eval" in exp.summary.lower() or "exec" in exp.summary.lower()

    def test_explain_hardcoded_secret(self):
        exp = explain_finding(category="hardcoded_secret")
        assert "secret" in exp.summary.lower() or "credential" in exp.summary.lower()

    def test_explain_unknown_category(self):
        exp = explain_finding(category="unknown_vuln")
        assert len(exp.summary) > 0

    def test_explain_with_severity_context(self):
        exp_crit = explain_finding(category="sql_injection", severity="CRITICAL")
        exp_info = explain_finding(category="sql_injection", severity="INFO")
        assert "critical" in exp_crit.detailed_explanation.lower()
        assert len(exp_info.detailed_explanation) > 0
        assert exp_info.confidence == 0.5

    def test_taint_flow_explanation(self):
        explanation = explain_taint_flow(
            source_name="request.form.get('id')",
            source_type="user_input",
            sink_name="cursor.execute",
            sink_type="sql_query",
            variable_chain=["user_id", "query"],
            is_sanitized=False,
        )
        assert "request.form" in explanation
        assert "cursor.execute" in explanation
        assert "No sanitization" in explanation

    def test_taint_flow_with_sanitization(self):
        explanation = explain_taint_flow(
            source_name="request.form.get('id')",
            source_type="user_input",
            sink_name="cursor.execute",
            sink_type="sql_query",
            variable_chain=["user_id"],
            is_sanitized=True,
            sanitizer="parameterized query",
        )
        assert "parameterized query" in explanation

    def test_severity_explanation_critical(self):
        exp = get_severity_explanation("CRITICAL", 0.9)
        assert "critical" in exp.lower()
        assert "high confidence" in exp.lower()

    def test_severity_explanation_low(self):
        exp = get_severity_explanation("LOW", 0.3)
        assert "low" in exp.lower()
        assert "false positive" in exp.lower() or "low confidence" in exp.lower()

    def test_all_categories_have_explanations(self):
        for cat in ["sql_injection", "command_injection", "code_injection",
                     "hardcoded_secret", "xss", "path_traversal", "deserialization"]:
            assert cat in CATEGORY_EXPLANATIONS, f"Missing explanation for {cat}"


class TestEnhancedReporters:
    def _make_result(self):
        result = ScanResult()
        f1 = _make_finding(severity="HIGH", title="SQL Injection")
        f2 = _make_finding(severity="MEDIUM", title="Weak Password", rule_id="SEC002",
                           category="SECURITY", cwe="CWE-521")
        f3 = _make_finding(severity="LOW", title="Debug Mode", rule_id="SEC003",
                           category="SECURITY", cwe="CWE-489", confidence=0.5)
        result.findings = [f1, f2, f3]
        result.files_scanned = 10
        result.lines_scanned = 500
        result.scan_duration = 2.5
        return result

    def test_html_reporter(self):
        from src.reporters.html_report import HTMLReporter
        result = self._make_result()
        html = HTMLReporter().generate(result)
        assert "CodeWatch" in html
        assert "SQL Injection" in html
        assert "score-card" in html
        assert "owasp" in html.lower() or "finding-card" in html

    def test_html_reporter_has_cvss(self):
        from src.reporters.html_report import HTMLReporter
        result = self._make_result()
        result.findings[0].cvss = CVSS()
        result.findings[0].cvss.base_score = 8.5
        result.findings[0].cvss.vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        html = HTMLReporter().generate(result)
        assert "8.5" in html

    def test_sarif_reporter(self):
        from src.reporters.sarif import SARIFReporter
        result = self._make_result()
        sarif_str = SARIFReporter().generate(result)
        sarif = json.loads(sarif_str)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 3
        assert sarif["runs"][0]["tool"]["driver"]["version"] == __version__

    def test_sarif_reporter_has_cvss(self):
        from src.reporters.sarif import SARIFReporter
        result = self._make_result()
        result.findings[0].cvss = CVSS()
        result.findings[0].cvss.base_score = 9.0
        result.findings[0].cvss.vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        sarif_str = SARIFReporter().generate(result)
        sarif = json.loads(sarif_str)
        results = sarif["runs"][0]["results"]
        cvss_result = [r for r in results if r["properties"].get("cvssScore")]
        assert len(cvss_result) > 0
        assert cvss_result[0]["properties"]["cvssScore"] == 9.0

    def test_sarif_reporter_has_fix_suggestion(self):
        from src.reporters.sarif import SARIFReporter
        result = self._make_result()
        result.findings[0].fix_suggestion = "Use parameterized queries"
        sarif_str = SARIFReporter().generate(result)
        sarif = json.loads(sarif_str)
        results = sarif["runs"][0]["results"]
        assert any(r["properties"].get("fixSuggestion") for r in results)

    def test_markdown_reporter(self):
        from src.reporters.markdown_report import MarkdownReporter
        result = self._make_result()
        md = MarkdownReporter().generate(result)
        assert "CodeWatch" in md
        assert "SQL Injection" in md
        assert "Risk Summary" in md
        assert "Security Findings" in md

    def test_markdown_reporter_has_cvss(self):
        from src.reporters.markdown_report import MarkdownReporter
        result = self._make_result()
        result.findings[0].cvss = CVSS()
        result.findings[0].cvss.base_score = 8.5
        result.findings[0].cvss.vector = "CVSS:3.1/AV:N/AC:L"
        md = MarkdownReporter().generate(result)
        assert "8.5" in md

    def test_markdown_reporter_has_code_snippet(self):
        from src.reporters.markdown_report import MarkdownReporter
        result = self._make_result()
        md = MarkdownReporter().generate(result)
        assert "cursor.execute" in md

    def test_json_reporter(self):
        from src.reporters.json_report import JSONReporter
        result = self._make_result()
        json_str = JSONReporter().generate(result)
        data = json.loads(json_str)
        assert data["schemaVersion"] == "3.0.0"
        assert data["tool"]["version"] == __version__
        assert len(data["findings"]) == 3
        assert "scan" in data
        assert "summary" in data

    def test_json_reporter_has_cvss(self):
        from src.reporters.json_report import JSONReporter
        result = self._make_result()
        result.findings[0].cvss = CVSS()
        result.findings[0].cvss.base_score = 8.5
        json_str = JSONReporter().generate(result)
        data = json.loads(json_str)
        cvss_finding = [f for f in data["findings"] if f.get("cvss")]
        assert len(cvss_finding) > 0
        assert cvss_finding[0]["cvss"]["score"] == 8.5

    def test_json_reporter_has_location(self):
        from src.reporters.json_report import JSONReporter
        result = self._make_result()
        json_str = JSONReporter().generate(result)
        data = json.loads(json_str)
        for f in data["findings"]:
            assert "location" in f
            assert "file" in f["location"]
            assert "line" in f["location"]
