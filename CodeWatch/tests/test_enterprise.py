"""Tests for enterprise analysis modules."""

import os
import tempfile

from src.core.ast_analyzer import analyze_python_ast
from src.core.confidence import ConfidenceLevel, calculate_confidence, confidence_to_display
from src.core.dataflow import DataFlowResult, analyze_data_flow
from src.core.deduplicator import deduplicate_findings
from src.core.indexer import FileCategory, _classify_file
from src.core.pipeline import AnalysisPipeline
from src.core.risk_scorer import RiskLevel, assess_risk, calculate_cvss


class TestASTAnalyzer:
    def test_analyze_function(self):
        code = """
def process_user_input(data):
    result = eval(data)
    return result
"""
        result = analyze_python_ast(code, "test.py")
        assert len(result.functions) >= 1
        func_names = [f.name for f in result.functions]
        assert "process_user_input" in func_names

    def test_analyze_imports(self):
        code = """
import os
from pathlib import Path
import subprocess
"""
        result = analyze_python_ast(code, "test.py")
        assert len(result.imports) >= 2
        module_names = [i.module for i in result.imports]
        assert "os" in module_names
        assert "subprocess" in module_names

    def test_function_calls_detected(self):
        code = """
def handler(request):
    user_input = request.form.get("name")
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
"""
        result = analyze_python_ast(code, "test.py")
        assert len(result.functions) >= 1
        func = result.functions[0]
        assert len(func.calls) >= 2

    def test_eval_calls_detected(self):
        code = """
def handler(request):
    user_input = request.form.get("data")
    result = eval(user_input)
    return result
"""
        result = analyze_python_ast(code, "test.py")
        func = result.functions[0]
        eval_calls = [c for c in func.calls if c.name == "eval"]
        assert len(eval_calls) >= 1

    def test_assignments_detected(self):
        code = """
def handler(request):
    x = request.form.get("data")
    y = x.strip()
    return y
"""
        result = analyze_python_ast(code, "test.py")
        func = result.functions[0]
        assert len(func.assignments) >= 2


class TestDataFlow:
    def test_data_flow_result_structure(self):
        code = """
def handler(request):
    user_input = request.form.get("name")
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
"""
        ast_result = analyze_python_ast(code, "test.py")
        result = analyze_data_flow(ast_result, code)
        assert isinstance(result, DataFlowResult)
        assert hasattr(result, "taint_paths")
        assert hasattr(result, "total_sources")
        assert hasattr(result, "total_sinks")

    def test_clean_code_no_paths(self):
        code = """
def safe_function():
    x = "hello"
    print(x)
"""
        ast_result = analyze_python_ast(code, "test.py")
        result = analyze_data_flow(ast_result, code)
        assert len(result.taint_paths) == 0


class TestConfidence:
    def test_high_confidence(self):
        result = calculate_confidence(
            has_ast_match=True,
            has_taint_path=True,
            is_user_controlled=True,
            is_constant=False,
            is_sanitized=False,
            reachability="direct",
            file_context="production",
        )
        assert result.score >= 0.7
        assert result.level in (ConfidenceLevel.HIGH, ConfidenceLevel.CERTAIN)

    def test_medium_confidence(self):
        result = calculate_confidence(
            has_ast_match=True,
            has_taint_path=False,
            is_user_controlled=False,
            is_constant=True,
            is_sanitized=False,
            reachability="direct",
            file_context="production",
        )
        assert 0.2 <= result.score <= 0.8

    def test_vendor_code_rejected(self):
        result = calculate_confidence(is_in_vendor=True)
        assert result.should_report is False
        assert result.score == 0.01

    def test_confidence_display(self):
        assert confidence_to_display(0.95) == "Very High"
        assert confidence_to_display(0.75) == "High"
        assert confidence_to_display(0.5) == "Medium"
        assert confidence_to_display(0.3) == "Low"
        assert confidence_to_display(0.1) == "Very Low"

    def test_test_file_reduces_confidence(self):
        result = calculate_confidence(
            has_ast_match=True,
            has_taint_path=False,
            is_user_controlled=True,
            is_in_test=True,
        )
        result_without_test = calculate_confidence(
            has_ast_match=True,
            has_taint_path=False,
            is_user_controlled=True,
            is_in_test=False,
        )
        assert result.score < result_without_test.score

    def test_generated_code_reduces_confidence(self):
        result_with_gen = calculate_confidence(
            has_ast_match=True,
            is_in_generated=True,
        )
        result_without_gen = calculate_confidence(
            has_ast_match=True,
            is_in_generated=False,
        )
        assert result_with_gen.score < result_without_gen.score

    def test_in_comment_reduces_confidence(self):
        result_with_comment = calculate_confidence(
            has_ast_match=True,
            is_in_comment=True,
        )
        result_without_comment = calculate_confidence(
            has_ast_match=True,
            is_in_comment=False,
        )
        assert result_with_comment.score < result_without_comment.score


class TestRiskScorer:
    def test_cvss_critical(self):
        score = calculate_cvss(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="C", confidentiality="H", integrity="H", availability="H"
        )
        assert score.overall_score >= 9.0
        assert score.severity == RiskLevel.CRITICAL

    def test_cvss_high(self):
        score = calculate_cvss(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U", confidentiality="H", integrity="H", availability="H"
        )
        assert score.overall_score >= 9.0
        assert score.severity == RiskLevel.CRITICAL

    def test_cvss_medium_range(self):
        score = calculate_cvss(
            attack_vector="A", attack_complexity="H",
            privileges_required="L", user_interaction="R",
            scope="U", confidentiality="L", integrity="N", availability="N"
        )
        assert score.overall_score < 7.0
        assert score.severity in (RiskLevel.LOW, RiskLevel.MEDIUM)

    def test_cvss_low(self):
        score = calculate_cvss(
            attack_vector="P", attack_complexity="H",
            privileges_required="H", user_interaction="R",
            scope="U", confidentiality="N", integrity="N", availability="N"
        )
        assert score.overall_score < 3.0
        assert score.severity in (RiskLevel.LOW, RiskLevel.INFO)

    def test_cvss_vector_string(self):
        score = calculate_cvss()
        assert score.vector_string.startswith("CVSS:3.1/AV:")

    def test_assess_risk_high(self):
        result = assess_risk(
            category="sql_injection",
            confidence=0.9,
            is_production=True,
            has_taint_path=True,
            user_controlled=True,
        )
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert result.confidence_score == 0.9

    def test_assess_risk_low_for_test(self):
        result = assess_risk(
            category="sql_injection",
            confidence=0.5,
            is_production=False,
            has_taint_path=False,
            user_controlled=False,
        )
        assert result.risk_level in (RiskLevel.LOW, RiskLevel.INFO)

    def test_risk_reasoning(self):
        result = assess_risk(category="sql_injection", confidence=0.9)
        assert len(result.reasoning) > 0


class TestDeduplicator:
    def test_dedup_same_finding(self):
        class MockFinding:
            def __init__(self, rule_id, message, file_path, line, sev):
                self.finding_id = f"{rule_id}:{file_path}:{line}"
                self.rule_id = rule_id
                self.message = message
                self.file_path = file_path
                self.line_number = line
                self.column = 0
                self.severity = sev
                self.category = "test"
                self.code_snippet = ""
                self.confidence = 0.5
                self.cvss_score = 5.0
                self.fix_suggestion = ""
                self.value = ""
                self.references = []

        findings = [
            MockFinding("SEC001", "SQL Injection in query()", "app.py", 10, "HIGH"),
            MockFinding("SEC001", "SQL Injection in query()", "app.py", 10, "HIGH"),
            MockFinding("SEC001", "SQL Injection in query()", "app.py", 10, "HIGH"),
        ]

        deduped = deduplicate_findings(findings)
        assert len(deduped) == 1
        assert deduped[0].duplicate_count == 3

    def test_dedup_different_findings(self):
        class MockFinding:
            def __init__(self, rule_id, message, file_path, line):
                self.finding_id = f"{rule_id}:{file_path}:{line}"
                self.rule_id = rule_id
                self.message = message
                self.file_path = file_path
                self.line_number = line
                self.column = 0
                self.severity = "HIGH"
                self.category = "test"
                self.code_snippet = ""
                self.confidence = 0.5
                self.cvss_score = 5.0
                self.fix_suggestion = ""
                self.value = ""
                self.references = []

        findings = [
            MockFinding("SEC001", "SQL Injection", "app.py", 10),
            MockFinding("SEC002", "XSS Vulnerability", "app.py", 20),
        ]

        deduped = deduplicate_findings(findings)
        assert len(deduped) == 2

    def test_empty_findings(self):
        deduped = deduplicate_findings([])
        assert len(deduped) == 0


class TestIndexer:
    def test_file_category_production(self):
        from pathlib import Path
        assert _classify_file(
            Path("/project/src/app.py"),
            "src/app.py", "app.py", ".py", "python"
        ) == FileCategory.PRODUCTION

    def test_file_category_test(self):
        from pathlib import Path
        assert _classify_file(
            Path("/project/tests/test_app.py"),
            "tests/test_app.py", "test_app.py", ".py", "python"
        ) == FileCategory.TEST

    def test_file_category_doc(self):
        from pathlib import Path
        assert _classify_file(
            Path("/project/README.md"),
            "README.md", "readme.md", ".md", "markdown"
        ) == FileCategory.DOCUMENTATION

    def test_file_category_config(self):
        from pathlib import Path
        assert _classify_file(
            Path("/project/docker-compose.yml"),
            "docker-compose.yml", "docker-compose.yml", ".yml", "yaml"
        ) == FileCategory.CONFIGURATION

    def test_file_category_environment(self):
        from pathlib import Path
        assert _classify_file(
            Path("/project/.env"),
            ".env", ".env", ".env", "dotenv"
        ) == FileCategory.ENVIRONMENT


class TestPipeline:
    def test_analyze_file_clean(self):
        pipeline = AnalysisPipeline(min_confidence=0.1)
        code = "def hello():\n    print('world')\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            temp_path = f.name
        try:
            result = pipeline.analyze_file(temp_path)
            assert result is not None
            assert result.file_path == temp_path
            assert result.rule_id == "CLEAN"
        finally:
            try:
                os.unlink(temp_path)
            except PermissionError:
                pass

    def test_analyze_file_with_issues(self):
        pipeline = AnalysisPipeline(min_confidence=0.1)
        code = "import os\n\ndef process_user_input(data):\n    result = eval(data)\n    return result\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            temp_path = f.name
        try:
            result = pipeline.analyze_file(temp_path)
            assert result is not None
            assert result.file_path == temp_path
        finally:
            try:
                os.unlink(temp_path)
            except PermissionError:
                pass
