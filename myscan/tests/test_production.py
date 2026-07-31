"""Tests for production redesign modules.

Covers: Trust Engine, Type Resolver, File Risk, Function Risk,
Policy Engine, Dependency Scanner, Config Security, SBOM,
Plugin SDK, Performance Engine.
"""

import json
import tempfile
from pathlib import Path

import pytest

from src.core.trust_engine import (
    TrustEngine, TrustScore, Evidence, EvidenceType,
    build_trust_from_pipeline, EVIDENCE_WEIGHTS, NEGATIVE_EVIDENCE_PENALTIES,
)
from src.core.type_resolver import (
    TypeResolver, FunctionOrigin, SafetyLevel, CallResolution,
    KNOWN_DANGEROUS_BUILTINS, STDLIB_MODULES,
)
from src.core.file_risk import FileRiskScorer, FileRiskProfile, RiskLevel
from src.core.function_risk import FunctionRiskScorer, FunctionRiskProfile, FunctionRiskLevel
from src.core.policy_engine import (
    PolicyEngine, SecurityPolicy, PolicyCheckResult, PolicyViolation,
)
from src.core.dependency_scanner import (
    DependencyScanner, DependencyScanResult, Dependency, PackageManager,
    VulnerabilitySeverity, KNOWN_VULNERABILITIES,
)
from src.core.config_security import (
    ConfigSecurityScanner, ConfigType, ConfigSeverity, CONFIG_RULES, ConfigFinding,
)
from src.core.sbom import SBOMGenerator, SBOMDocument, SBOMComponent
from src.core.plugin_sdk import (
    PluginManager, PluginBase, PluginMetadata, ScannerPlugin,
    RulePlugin, ReporterPlugin,
)
from src.core.performance import (
    ASTCache, IncrementalScanner, ParallelScanner, ScanProgress, ScanMetrics,
)


# ============================================================
# Trust Engine Tests
# ============================================================

class TestTrustEngine:
    def test_empty_evidence(self):
        engine = TrustEngine()
        score = engine.calculate()
        assert score.score == 0.1
        assert score.should_report is False
        assert score.level == "speculative"

    def test_single_positive_evidence(self):
        engine = TrustEngine()
        engine.add_evidence(EvidenceType.REGEX_MATCH, "pattern_matched", 0.9, "SQL injection pattern found")
        score = engine.calculate()
        assert score.score > 0.1
        assert len(score.evidences) == 1
        assert score.evidence_summary != "Unverified"

    def test_multiple_evidences(self):
        engine = TrustEngine()
        engine.add_evidence(EvidenceType.REGEX_MATCH, "pattern_matched", 0.85, "Regex matched")
        engine.add_evidence(EvidenceType.AST_VERIFIED, "ast_confirmed", 0.95, "AST verified")
        engine.add_evidence(EvidenceType.TAINT_VERIFIED, "taint_confirmed", 0.9, "Taint verified")
        engine.add_evidence(EvidenceType.DATAFLOW_VERIFIED, "df_confirmed", 0.85, "Data flow verified")
        score = engine.calculate()
        assert score.score > 0.7
        assert score.level in ("high", "certain")
        assert score.should_report is True

    def test_negative_evidence_reduces_score(self):
        engine = TrustEngine()
        engine.add_evidence(EvidenceType.AST_VERIFIED, "ast_confirmed", 0.9, "AST verified")
        engine.add_negative_evidence("constant_value", "Value is constant", -0.7)
        score_pos = TrustEngine()
        score_pos.add_evidence(EvidenceType.AST_VERIFIED, "ast_confirmed", 0.9, "AST verified")
        score_without = score_pos.calculate()
        score = engine.calculate()
        assert score.score < score_without.score

    def test_vendor_code_not_reported(self):
        score = build_trust_from_pipeline(is_in_vendor=True)
        assert score.should_report is False
        assert score.score == 0.0

    def test_build_trust_from_pipeline(self):
        score = build_trust_from_pipeline(
            has_regex_match=True,
            has_ast_verification=True,
            has_taint_verification=True,
            has_dataflow_verification=True,
            is_reachable=True,
        )
        assert score.score > 0.7
        assert score.should_report is True
        assert "regex match" in score.evidence_summary
        assert "ast verified" in score.evidence_summary

    def test_sanitized_reduces_confidence(self):
        with_san = build_trust_from_pipeline(
            has_regex_match=True, has_ast_verification=True,
            is_sanitized=True, has_taint_verification=True,
        )
        without_san = build_trust_from_pipeline(
            has_regex_match=True, has_ast_verification=True,
            is_sanitized=False, has_taint_verification=True,
        )
        assert with_san.score < without_san.score

    def test_verification_levels(self):
        engine = TrustEngine()
        engine.add_evidence(EvidenceType.REGEX_MATCH, "regex", 0.9, "regex matched")
        score = engine.calculate()
        assert score.verification_level == "single_evidence"

        engine2 = TrustEngine()
        engine2.add_evidence(EvidenceType.REGEX_MATCH, "regex", 0.9, "regex")
        engine2.add_evidence(EvidenceType.AST_VERIFIED, "ast", 0.9, "ast")
        score2 = engine2.calculate()
        assert score2.verification_level == "partially_verified"

        engine3 = TrustEngine()
        for ev_type in (EvidenceType.REGEX_MATCH, EvidenceType.AST_VERIFIED, EvidenceType.DATAFLOW_VERIFIED, EvidenceType.TAINT_VERIFIED):
            engine3.add_evidence(ev_type, "signal", 0.9, "reason")
        score3 = engine3.calculate()
        assert score3.verification_level == "fully_verified"

    def test_severity_adjustment(self):
        score_high = build_trust_from_pipeline(has_regex_match=True, has_ast_verification=True, has_taint_verification=True, has_dataflow_verification=True)
        assert score_high.severity_adjustment == "no_change"

        score_low = build_trust_from_pipeline()
        assert score_low.score < 0.2
        assert score_low.severity_adjustment == "reduce_to_low"

    def test_custom_weights(self):
        engine = TrustEngine(custom_weights={EvidenceType.AST_VERIFIED: 0.5})
        assert engine._weights[EvidenceType.AST_VERIFIED] == 0.5
        assert engine._weights[EvidenceType.REGEX_MATCH] == EVIDENCE_WEIGHTS[EvidenceType.REGEX_MATCH]

    def test_reset(self):
        engine = TrustEngine()
        engine.add_evidence(EvidenceType.REGEX_MATCH, "regex", 0.9, "test")
        assert len(engine._evidences) == 1
        engine.reset()
        assert len(engine._evidences) == 0


# ============================================================
# Type Resolver Tests
# ============================================================

class TestTypeResolver:
    def test_builtin_eval_is_dangerous(self):
        resolver = TypeResolver()
        tree = ast.parse("eval(user_input)")
        call = tree.body[0].value
        resolution = resolver.resolve_call(call)
        assert resolution.is_dangerous_builtin is True
        assert resolution.safety == SafetyLevel.DANGEROUS
        assert resolution.origin == FunctionOrigin.BUILTIN

    def test_import_alias_tracking(self):
        resolver = TypeResolver()
        resolver.analyze_file("import pandas as pd\npd.eval('1+1')")
        tree = ast.parse("import pandas as pd\npd.eval('1+1')")
        call = tree.body[1].value
        resolution = resolver.resolve_call(call)
        assert resolution.full_name == "pandas.eval"
        assert resolution.safety == SafetyLevel.SAFE

    def test_module_import_tracking(self):
        resolver = TypeResolver()
        resolver.analyze_file("import os\nos.system(cmd)")
        tree = ast.parse("import os\nos.system(cmd)")
        call = tree.body[1].value
        resolution = resolver.resolve_call(call)
        assert "os.system" in resolution.full_name

    def test_safe_alternatives(self):
        resolver = TypeResolver()
        alts = resolver.get_safe_alternatives("eval")
        assert "ast.literal_eval" in alts
        assert "json.loads" in alts

    def test_dangerous_builtins_defined(self):
        assert "eval" in KNOWN_DANGEROUS_BUILTINS
        assert "exec" in KNOWN_DANGEROUS_BUILTINS
        assert "compile" in KNOWN_DANGEROUS_BUILTINS
        assert "__import__" in KNOWN_DANGEROUS_BUILTINS

    def test_stdlib_modules_populated(self):
        assert "os" in STDLIB_MODULES
        assert "json" in STDLIB_MODULES
        assert "subprocess" in STDLIB_MODULES

    def test_from_import_tracking(self):
        resolver = TypeResolver()
        resolver.analyze_file("from os import system\nsystem(cmd)")
        assert "system" in resolver._imports

    def test_class_definition_tracking(self):
        resolver = TypeResolver()
        resolver.analyze_file("class MyClass:\n    def my_method(self): pass")
        assert "MyClass" in resolver._class_methods
        assert "my_method" in resolver._class_methods["MyClass"]


import ast


# ============================================================
# File Risk Scorer Tests
# ============================================================

class TestFileRiskScorer:
    def test_clean_file_low_risk(self):
        scorer = FileRiskScorer()
        profile = scorer.score_file("utils.py", [], content="def add(a, b):\n    return a + b")
        assert profile.risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW)
        assert profile.total_findings == 0

    def test_file_with_critical_findings(self):
        scorer = FileRiskScorer()
        from src.core.models import Finding, Severity, FindingCategory, Language, CodeLocation
        findings = [
            Finding(rule_id="SEC001", title="SQL Injection", description="SQLi",
                    severity=Severity.CRITICAL, confidence=0.9,
                    category=FindingCategory.SECURITY, language=Language.PYTHON,
                    location=CodeLocation(file_path="app.py", line=10)),
        ]
        profile = scorer.score_file("auth/handler.py", findings, content="import os\nos.system(cmd)\ninput()")
        assert profile.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        assert profile.critical_count == 1
        assert profile.has_injection is True

    def test_attack_surface_calculation(self):
        scorer = FileRiskScorer()
        profile = scorer.score_file("api.py", [], content="import socket\nrequest.get()\ninput()")
        assert profile.attack_surface_score > 0
        assert profile.has_network is True
        assert profile.has_user_input is True

    def test_business_importance(self):
        scorer = FileRiskScorer()
        assert scorer._assess_business_importance("src/auth/login.py") == "critical"
        assert scorer._assess_business_importance("src/utils/helpers.py") == "medium"
        assert scorer._assess_business_importance("tests/test_example.py") == "low"

    def test_exposure_level(self):
        scorer = FileRiskScorer()
        assert scorer._assess_exposure("api/views.py") == "external"
        assert scorer._assess_exposure("service/user_service.py") == "internal"

    def test_to_dict(self):
        scorer = FileRiskScorer()
        profile = scorer.score_file("app.py", [])
        d = profile.to_dict()
        assert "filePath" in d
        assert "riskScore" in d
        assert "riskLevel" in d

    def test_complexity_estimation(self):
        scorer = FileRiskScorer()
        complex_code = "def f():\n" + "    if True:\n" * 10 + "        pass\n"
        profile = scorer.score_file("complex.py", [], content=complex_code)
        assert profile.cyclomatic_complexity > 10


# ============================================================
# Function Risk Scorer Tests
# ============================================================

class TestFunctionRiskScorer:
    def test_simple_function_low_risk(self):
        scorer = FunctionRiskScorer()
        tree = ast.parse("def add(a, b):\n    return a + b")
        func = tree.body[0]
        profile = scorer.score_function(func, "utils.py", "def add(a, b):\n    return a + b")
        assert profile.risk_level in (FunctionRiskLevel.MINIMAL, FunctionRiskLevel.LOW)
        assert profile.function_name == "add"

    def test_complex_function_higher_risk(self):
        scorer = FunctionRiskScorer()
        code = """def process(cmd, data, user_input):
    import os
    import subprocess
    user_data = input("Enter data: ")
    if cmd == 'run':
        os.system(user_data)
        subprocess.call(data)
        return True
    elif cmd == 'query':
        db.execute(data)
    return False"""
        tree = ast.parse(code)
        func = tree.body[0]
        profile = scorer.score_function(func, "handler.py", code)
        assert profile.function_name == "process"
        assert profile.cyclomatic_complexity >= 3
        assert profile.external_inputs >= 1
        assert profile.subprocess_call is True

    def test_function_risk_detection(self):
        scorer = FunctionRiskScorer()
        code = """def auth_check(username, password):
    import hashlib
    token = request.headers.get('Authorization')
    db.execute("SELECT * FROM users WHERE...")
    return True"""
        tree = ast.parse(code)
        func = tree.body[0]
        profile = scorer.score_function(func, "auth.py", code)
        assert profile.auth_code is True
        assert profile.crypto_usage is True
        assert profile.db_access is True

    def test_cyclomatic_complexity(self):
        scorer = FunctionRiskScorer()
        code = """def decision(a, b, c):
    if a:
        if b:
            for i in range(10):
                if c:
                    pass
    elif not a:
        while True:
            break"""
        tree = ast.parse(code)
        func = tree.body[0]
        profile = scorer.score_function(func, "logic.py", code)
        assert profile.cyclomatic_complexity >= 5

    def test_score_file_functions(self):
        scorer = FunctionRiskScorer()
        code = "def a():\n    pass\ndef b():\n    pass"
        profiles = scorer.score_file_functions("f.py", code)
        assert len(profiles) == 2
        assert profiles[0].function_name == "a"
        assert profiles[1].function_name == "b"

    def test_ai_summary(self):
        scorer = FunctionRiskScorer()
        code = """def dangerous(cmd):
    import os
    os.system(cmd)"""
        tree = ast.parse(code)
        func = tree.body[0]
        profile = scorer.score_function(func, "cmd.py", code)
        assert len(profile.ai_summary) > 0

    def test_syntax_error_returns_empty(self):
        scorer = FunctionRiskScorer()
        profiles = scorer.score_file_functions("bad.py", "def (invalid")
        assert profiles == []


# ============================================================
# Policy Engine Tests
# ============================================================

class TestPolicyEngine:
    def test_default_policy(self):
        policy = SecurityPolicy()
        engine = PolicyEngine(policy)
        assert engine.policy.name == "default"
        assert engine.policy.min_severity == "info"

    def test_pci_dss_policy(self):
        policy = SecurityPolicy.pci_dss()
        assert policy.name == "PCI-DSS"
        assert policy.max_critical == 0
        assert policy.fail_on_regression is True

    def test_hipaa_policy(self):
        policy = SecurityPolicy.hipaa()
        assert policy.name == "HIPAA"
        assert policy.max_critical == 0
        assert policy.max_high == 0

    def test_check_findings_pass(self):
        policy = SecurityPolicy(max_critical=5, max_high=10)
        engine = PolicyEngine(policy)
        from src.core.models import Finding, Severity, FindingCategory, Language, CodeLocation
        findings = [
            Finding(rule_id="SEC001", title="Low", description="Low issue",
                    severity=Severity.LOW, confidence=0.5,
                    category=FindingCategory.QUALITY, language=Language.PYTHON,
                    location=CodeLocation(file_path="app.py", line=1)),
        ]
        result = engine.check_findings(findings)
        assert result.passed is True

    def test_check_findings_fail(self):
        policy = SecurityPolicy(max_critical=0)
        engine = PolicyEngine(policy)
        from src.core.models import Finding, Severity, FindingCategory, Language, CodeLocation
        findings = [
            Finding(rule_id="SEC001", title="Critical", description="Critical issue",
                    severity=Severity.CRITICAL, confidence=0.9,
                    category=FindingCategory.SECURITY, language=Language.PYTHON,
                    location=CodeLocation(file_path="app.py", line=1)),
        ]
        result = engine.check_findings(findings)
        assert result.passed is False
        assert len(result.violations) > 0

    def test_filter_by_severity(self):
        policy = SecurityPolicy(min_severity="high")
        engine = PolicyEngine(policy)
        from src.core.models import Finding, Severity, FindingCategory, Language, CodeLocation
        findings = [
            Finding(rule_id="SEC001", title="High", description="High",
                    severity=Severity.HIGH, confidence=0.8,
                    category=FindingCategory.SECURITY, language=Language.PYTHON,
                    location=CodeLocation(file_path="app.py", line=1)),
            Finding(rule_id="SEC002", title="Low", description="Low",
                    severity=Severity.LOW, confidence=0.5,
                    category=FindingCategory.QUALITY, language=Language.PYTHON,
                    location=CodeLocation(file_path="app.py", line=2)),
        ]
        filtered = engine.filter_findings(findings)
        assert len(filtered) == 1
        assert filtered[0].rule_id == "SEC001"

    def test_ignore_rules(self):
        policy = SecurityPolicy(ignored_rules=["SEC001"])
        engine = PolicyEngine(policy)
        from src.core.models import Finding, Severity, FindingCategory, Language, CodeLocation
        findings = [
            Finding(rule_id="SEC001", title="Ignored", description="Ignored",
                    severity=Severity.HIGH, confidence=0.8,
                    category=FindingCategory.SECURITY, language=Language.PYTHON,
                    location=CodeLocation(file_path="app.py", line=1)),
        ]
        result = engine.check_findings(findings)
        assert result.passed is True

    def test_policy_serialization(self):
        policy = SecurityPolicy(name="test", min_severity="high", max_critical=0)
        d = policy.to_dict()
        assert d["name"] == "test"
        assert d["minSeverity"] == "high"
        restored = SecurityPolicy.from_dict(d)
        assert restored.name == "test"
        assert restored.min_severity == "high"

    def test_policy_save_load_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            policy = SecurityPolicy(name="test", min_severity="medium")
            policy.save(path)
            loaded = SecurityPolicy.from_file(path)
            assert loaded.name == "test"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_baseline_comparison(self):
        engine = PolicyEngine(SecurityPolicy(fail_on_regression=True))
        from src.core.models import Finding, Severity, FindingCategory, Language, CodeLocation
        baseline = [
            Finding(rule_id="SEC001", title="Old", description="Old",
                    severity=Severity.HIGH, confidence=0.8,
                    category=FindingCategory.SECURITY, language=Language.PYTHON,
                    location=CodeLocation(file_path="app.py", line=10)),
        ]
        current = [
            Finding(rule_id="SEC001", title="Old", description="Old",
                    severity=Severity.HIGH, confidence=0.8,
                    category=FindingCategory.SECURITY, language=Language.PYTHON,
                    location=CodeLocation(file_path="app.py", line=10)),
            Finding(rule_id="SEC002", title="New", description="New",
                    severity=Severity.CRITICAL, confidence=0.9,
                    category=FindingCategory.SECURITY, language=Language.PYTHON,
                    location=CodeLocation(file_path="app.py", line=20)),
        ]
        result = engine.check_baseline(current, baseline)
        assert result.passed is False

    def test_to_dict(self):
        result = PolicyCheckResult(passed=True, summary="All good")
        d = result.to_dict()
        assert d["passed"] is True
        assert d["summary"] == "All good"


# ============================================================
# Dependency Scanner Tests
# ============================================================

class TestDependencyScanner:
    def test_scan_requirements_txt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("requests==2.28.0\nflask==1.0\npyyaml==5.3\n")
            scanner = DependencyScanner()
            result = scanner.scan_file(str(req_file))
            assert result is not None
            assert result.total_dependencies == 3
            assert result.package_manager == PackageManager.PIP

    def test_known_vulnerabilities_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("pyyaml==5.3\nrequests==2.19.0\n")
            scanner = DependencyScanner()
            result = scanner.scan_file(str(req_file))
            assert result is not None
            assert len(result.vulnerabilities) > 0
            pyyaml_vulns = [v for v in result.vulnerabilities if v.dependency_name == "pyyaml"]
            assert len(pyyaml_vulns) > 0

    def test_package_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_file = Path(tmpdir) / "package.json"
            pkg_file.write_text(json.dumps({"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "^29.0"}}))
            scanner = DependencyScanner()
            result = scanner.scan_file(str(pkg_file))
            assert result is not None
            assert result.total_dependencies == 2
            assert result.dev_dependencies == 1

    def test_risk_score_calculation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("pyyaml==5.3\n")
            scanner = DependencyScanner()
            result = scanner.scan_file(str(req_file))
            assert result.risk_score > 0

    def test_known_vulns_registry(self):
        assert "requests" in KNOWN_VULNERABILITIES
        assert "flask" in KNOWN_VULNERABILITIES
        assert "pyyaml" in KNOWN_VULNERABILITIES

    def test_to_dict(self):
        result = DependencyScanResult(file_path="req.txt", package_manager=PackageManager.PIP)
        d = result.to_dict()
        assert "filePath" in d
        assert "vulnerabilities" in d

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("# no dependencies\n")
            scanner = DependencyScanner()
            result = scanner.scan_file(str(req_file))
            assert result is not None
            assert result.total_dependencies == 0

    def test_fixed_or_safe_versions_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text(
                "requests==2.20.0\nrequests==2.28.0\nflask==1.0\npyyaml==5.4\n"
                "urllib3==1.26.6\n"
            )
            scanner = DependencyScanner()
            result = scanner.scan_file(str(req_file))
            assert result is not None
            assert result.vulnerabilities == []
            assert result.critical_vulns == result.high_vulns == 0

    def test_exact_vulnerable_versions_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("requests==2.19.0\n")
            scanner = DependencyScanner()
            result = scanner.scan_file(str(req_file))
            assert result is not None
            vulns = [v for v in result.vulnerabilities if v.dependency_name == "requests"]
            assert len(vulns) == 1
            assert vulns[0].vulnerability_id == "CVE-2018-18074"
            assert vulns[0].fixed_version == "2.20.0"

    def test_upper_bound_excludes_fixed_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("pyyaml==5.3\npyyaml==5.4\npyyaml==5.5\n")
            scanner = DependencyScanner()
            result = scanner.scan_file(str(req_file))
            assert result is not None
            pyyaml_vulns = [v for v in result.vulnerabilities if v.dependency_name == "pyyaml"]
            assert len(pyyaml_vulns) == 1
            assert pyyaml_vulns[0].dependency_version == "5.3"

    def test_lower_bound_ranges_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("requests>=2.20.0\nrequests==2.20.0,<3.0\n")
            scanner = DependencyScanner()
            result = scanner.scan_file(str(req_file))
            assert result is not None
            assert all(v.dependency_name != "requests" for v in result.vulnerabilities)

    def test_wide_ranges_still_flagged_conservatively(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("requests~=2.19\nrequests<2.20.0\n")
            scanner = DependencyScanner()
            result = scanner.scan_file(str(req_file))
            assert result is not None
            req_vulns = [v for v in result.vulnerabilities if v.dependency_name == "requests"]
            assert len(req_vulns) >= 1

    def test_version_comparison_semantics(self):
        from src.core.dependency_scanner import _cmp_versions
        assert _cmp_versions("1.0", "1.0.0") == 0
        assert _cmp_versions("2.19.0", "2.20.0") < 0
        assert _cmp_versions("2023.7.21", "2023.7.22") < 0
        assert _cmp_versions("2.20.1", "2.20.0") > 0
        assert _cmp_versions("1.0.0rc1", "1.0.0") < 0
        assert _cmp_versions("1.0.1", "1.0.0") > 0


# ============================================================
# Config Security Scanner Tests
# ============================================================

class TestConfigSecurityScanner:
    def test_dockerfile_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile = Path(tmpdir) / "Dockerfile"
            dockerfile.write_text("FROM ubuntu:latest\nUSER root\nRUN apt-get update\n")
            scanner = ConfigSecurityScanner()
            findings = scanner.scan_file(str(dockerfile))
            assert len(findings) > 0
            assert any(f.rule_id == "docker_latest_tag" for f in findings)
            assert any(f.rule_id == "docker_root_user" for f in findings)

    def test_kubernetes_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            k8s_file = Path(tmpdir) / "deployment.yml"
            k8s_file.write_text("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n      - name: app\n        securityContext:\n          privileged: true\n")
            scanner = ConfigSecurityScanner()
            findings = scanner.scan_file(str(k8s_file), ConfigType.KUBERNETES)
            severities = [f.severity for f in findings]
            assert ConfigSeverity.CRITICAL in severities or ConfigSeverity.HIGH in severities

    def test_terraform_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text('resource "aws_s3_bucket" "data" {\n  acl = "public-read"\n}\nresource "aws_db_instance" "main" {\n  publicly_accessible = true\n}\n')
            scanner = ConfigSecurityScanner()
            findings = scanner.scan_file(str(tf_file), ConfigType.TERRAFORM)
            assert len(findings) >= 2
            assert any(f.rule_id == "terraform_public_acl" for f in findings)

    def test_github_actions_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gh_file = Path(tmpdir) / "ci.yml"
            gh_file.write_text("name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps:\n      - run: ${{ github.event.head_commit.message }}\n")
            scanner = ConfigSecurityScanner()
            findings = scanner.scan_file(str(gh_file), ConfigType.GITHUB_ACTIONS)
            assert len(findings) > 0

    def test_nginx_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ng_file = Path(tmpdir) / "nginx.conf"
            ng_file.write_text("server {\n    server_tokens on;\n    autoindex on;\n}\n")
            scanner = ConfigSecurityScanner()
            findings = scanner.scan_file(str(ng_file), ConfigType.NGINX)
            assert len(findings) >= 2

    def test_rules_defined(self):
        assert len(CONFIG_RULES) > 10
        assert "docker_privileged" in CONFIG_RULES
        assert "k8s_privileged" in CONFIG_RULES

    def test_to_dict(self):
        finding = ConfigFinding(
            file_path="Dockerfile", config_type=ConfigType.DOCKER,
            line=1, severity=ConfigSeverity.CRITICAL,
            rule_id="test", title="Test", description="Test",
        )
        d = finding.to_dict()
        assert d["severity"] == "critical"


# ============================================================
# SBOM Tests
# ============================================================

class TestSBOMGenerator:
    def test_generate_cyclonedx(self):
        gen = SBOMGenerator()
        deps = [
            Dependency(name="requests", version="2.28.0", package_manager=PackageManager.PIP),
            Dependency(name="flask", version="2.3.0", package_manager=PackageManager.PIP),
        ]
        doc = gen.generate_from_dependencies(deps, "my-project")
        assert doc.name == "my-project"
        assert len(doc.components) == 2
        output = doc.to_cyclonedx_json()
        parsed = json.loads(output)
        assert parsed["bomFormat"] == "CycloneDX"
        assert len(parsed["components"]) == 2

    def test_generate_spdx(self):
        gen = SBOMGenerator()
        deps = [
            Dependency(name="express", version="4.18.0", package_manager=PackageManager.NPM),
        ]
        doc = gen.generate_from_dependencies(deps, "web-app")
        output = doc.to_spdx_json()
        parsed = json.loads(output)
        assert parsed["spdxVersion"] == "SPDX-2.3"
        assert len(parsed["packages"]) == 2

    def test_purl_generation(self):
        gen = SBOMGenerator()
        dep = Dependency(name="requests", version="2.28.0", package_manager=PackageManager.PIP)
        doc = gen.generate_from_dependencies([dep])
        assert doc.components[0].purl == "pkg:pypi/requests@2.28.0"

    def test_from_scan_results(self):
        gen = SBOMGenerator()
        result = DependencyScanResult(file_path="req.txt", package_manager=PackageManager.PIP)
        result.dependencies = [
            Dependency(name="numpy", version="1.24.0", package_manager=PackageManager.PIP),
        ]
        doc = gen.generate_from_results([result], "data-project")
        assert len(doc.components) == 1
        assert doc.components[0].name == "numpy"


# ============================================================
# Plugin SDK Tests
# ============================================================

class TestPluginSDK:
    def test_register_scanner_plugin(self):
        class TestScanner(ScannerPlugin):
            @property
            def metadata(self):
                return PluginMetadata(name="test-scanner", version="1.0.0", plugin_type="scanner")
            def scan_file(self, file_path, content, language):
                return []

        manager = PluginManager()
        scanner = TestScanner()
        manager.register(scanner)
        assert len(manager.scanners) == 1

    def test_register_rule_plugin(self):
        class TestRules(RulePlugin):
            @property
            def metadata(self):
                return PluginMetadata(name="test-rules", version="1.0.0", plugin_type="rules")
            def get_rules(self):
                return [{"id": "CUSTOM001", "title": "Custom Rule"}]

        manager = PluginManager()
        rules = TestRules()
        manager.register(rules)
        all_rules = manager.get_all_scanner_rules()
        assert len(all_rules) == 1
        assert all_rules[0]["id"] == "CUSTOM001"

    def test_register_reporter_plugin(self):
        class TestReporter(ReporterPlugin):
            @property
            def metadata(self):
                return PluginMetadata(name="test-reporter", version="1.0.0", plugin_type="reporter")
            def generate(self, result):
                return "report"
            @property
            def format_name(self):
                return "test"

        manager = PluginManager()
        reporter = TestReporter()
        manager.register(reporter)
        assert len(manager.reporters) == 1

    def test_initialize_shutdown(self):
        class TestPlugin(PluginBase):
            def __init__(self):
                self.initialized = False
                self.shut_down = False
            @property
            def metadata(self):
                return PluginMetadata(name="test", version="1.0.0", plugin_type="test")
            def initialize(self, config):
                self.initialized = True
            def shutdown(self):
                self.shut_down = True

        manager = PluginManager()
        plugin = TestPlugin()
        manager.register(plugin)
        manager.initialize_all({"key": "value"})
        assert plugin.initialized is True
        manager.shutdown_all()
        assert plugin.shut_down is True

    def test_list_plugins(self):
        class TestPlugin(PluginBase):
            @property
            def metadata(self):
                return PluginMetadata(name="my-plugin", version="2.0.0", author="Test", description="A test plugin", plugin_type="test")

        manager = PluginManager()
        manager.register(TestPlugin())
        plugins = manager.list_plugins()
        assert len(plugins) == 1
        assert plugins[0]["name"] == "my-plugin"

    def test_load_from_nonexistent_directory(self):
        manager = PluginManager()
        loaded = manager.load_from_directory("/nonexistent/path")
        assert loaded == 0


# ============================================================
# Performance Engine Tests
# ============================================================

class TestASTCache:
    def test_cache_miss(self):
        cache = ASTCache()
        result = cache.get("app.py", "x = 1")
        assert result is None
        assert cache.misses == 1

    def test_cache_hit(self):
        cache = ASTCache()
        cache.put("app.py", "x = 1", {"ast": "data"})
        result = cache.get("app.py", "x = 1")
        assert result == {"ast": "data"}
        assert cache.hits == 1

    def test_cache_invalidation(self):
        cache = ASTCache()
        cache.put("app.py", "x = 1", {"ast": "data"})
        cache.invalidate("app.py")
        result = cache.get("app.py", "x = 1")
        assert result is None

    def test_hit_rate(self):
        cache = ASTCache()
        cache.put("a.py", "1", {"a": 1})
        cache.get("a.py", "1")
        cache.get("b.py", "2")
        assert cache.hit_rate == 0.5

    def test_max_size(self):
        cache = ASTCache(max_size=2)
        cache.put("a.py", "1", {"a": 1})
        cache.put("b.py", "2", {"b": 2})
        cache.put("c.py", "3", {"c": 3})
        assert len(cache._cache) == 2

    def test_clear(self):
        cache = ASTCache()
        cache.put("a.py", "1", {"a": 1})
        cache.clear()
        assert cache.hits == 0
        assert cache.misses == 0


class TestIncrementalScanner:
    def test_changed_file(self):
        scanner = IncrementalScanner()
        assert scanner.has_changed("app.py", "content1") is True
        scanner.update("app.py", "content1")
        assert scanner.has_changed("app.py", "content1") is False
        assert scanner.has_changed("app.py", "content2") is True

    def test_get_changed_files(self):
        scanner = IncrementalScanner()
        scanner.update("a.py", "same")
        scanner.update("b.py", "same")
        changed = scanner.get_changed_files(
            ["a.py", "b.py", "c.py"],
            {"a.py": "same", "b.py": "changed", "c.py": "new"},
        )
        assert "b.py" in changed
        assert "c.py" in changed
        assert "a.py" not in changed

    def test_save_load_state(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            scanner1 = IncrementalScanner(state_file=path)
            scanner1.update("app.py", "content")
            scanner1.save_state()

            scanner2 = IncrementalScanner(state_file=path)
            assert scanner2.has_changed("app.py", "content") is False
        finally:
            Path(path).unlink(missing_ok=True)


class TestParallelScanner:
    def test_sequential_scan(self):
        scanner = ParallelScanner(max_workers=1)
        files = [("a.py", "content_a"), ("b.py", "content_b")]
        results = scanner.scan_files(files, lambda fp, c: [{"file": fp}])
        assert len(results) == 2

    def test_parallel_scan(self):
        scanner = ParallelScanner(max_workers=2)
        files = [("a.py", "a"), ("b.py", "b"), ("c.py", "c")]
        results = scanner.scan_files(files, lambda fp, c: [{"file": fp}])
        assert len(results) == 3

    def test_error_handling(self):
        scanner = ParallelScanner(max_workers=2)
        files = [("a.py", "a")]
        def bad_scan(fp, c):
            raise ValueError("error")
        results = scanner.scan_files(files, bad_scan)
        assert len(results) == 1
        assert results[0][1] == []


class TestScanProgress:
    def test_progress_tracking(self):
        progress = ScanProgress(total=100)
        assert progress.percentage == 0.0
        progress.update(50)
        assert progress.percentage == 50.0
        assert progress.completed == 50

    def test_callback(self):
        progress = ScanProgress(total=10)
        called = []
        progress.on_update(lambda p: called.append(p.completed))
        progress.update(5)
        assert called == [5]

    def test_estimated_remaining(self):
        progress = ScanProgress(total=100)
        progress._start_time = progress._start_time - 10
        progress._completed = 50
        remaining = progress.estimated_remaining
        assert remaining > 0


class TestScanMetrics:
    def test_to_dict(self):
        metrics = ScanMetrics(files_total=100, files_scanned=95, scan_duration=5.5)
        d = metrics.to_dict()
        assert d["filesTotal"] == 100
        assert d["scanDuration"] == 5.5


class TestValidationPipelineIntegration:
    def test_validation_rejects_non_literal_password(self):
        from src.core.validation_engine import ValidationPipeline
        vp = ValidationPipeline(min_confidence=0.15)
        finding = {
            "rule_id": "SEC_PASSWORD_ASSIGNMENT",
            "title": "Hardcoded Password",
            "message": "password = input()",
            "severity": "CRITICAL",
            "category": "SECRET",
            "file_path": "app.py",
            "line": 1,
            "column": 0,
            "code_snippet": 'password = input("Enter password:")',
            "confidence": 0.85,
            "tags": ["secret", "password"],
        }
        result = vp.validate_finding(finding)
        assert result is None

    def test_validation_accepts_literal_password(self):
        from src.core.validation_engine import ValidationPipeline
        vp = ValidationPipeline(min_confidence=0.15)
        finding = {
            "rule_id": "SEC_PASSWORD_ASSIGNMENT",
            "title": "Hardcoded Password",
            "message": "password = s3cur3P@ss!",
            "severity": "CRITICAL",
            "category": "SECRET",
            "file_path": "config.py",
            "line": 1,
            "column": 0,
            "code_snippet": 'password = "s3cur3P@ss!"',
            "confidence": 0.85,
            "tags": ["secret", "password"],
        }
        result = vp.validate_finding(finding, file_content='password = "s3cur3P@ss!"')
        assert result is not None
        assert result["validated"] is True

    def test_validation_rejects_os_getenv_password(self):
        from src.core.validation_engine import ValidationPipeline
        vp = ValidationPipeline(min_confidence=0.15)
        finding = {
            "rule_id": "SEC_PASSWORD_ASSIGNMENT",
            "title": "Hardcoded Password",
            "message": "password = os.getenv('DB_PASS')",
            "severity": "CRITICAL",
            "category": "SECRET",
            "file_path": "config.py",
            "line": 1,
            "column": 0,
            "code_snippet": 'password = os.getenv("DB_PASS")',
            "confidence": 0.85,
            "tags": ["secret", "password"],
        }
        result = vp.validate_finding(finding)
        assert result is None

    def test_validation_rejects_variable_reference(self):
        from src.core.validation_engine import ValidationPipeline
        vp = ValidationPipeline(min_confidence=0.15)
        finding = {
            "rule_id": "SEC_PASSWORD_ASSIGNMENT",
            "title": "Hardcoded Password",
            "message": "password = settings.DB_PASSWORD",
            "severity": "CRITICAL",
            "category": "SECRET",
            "file_path": "config.py",
            "line": 1,
            "column": 0,
            "code_snippet": 'password = settings.DB_PASSWORD',
            "confidence": 0.85,
            "tags": ["secret", "password"],
        }
        result = vp.validate_finding(finding)
        assert result is None

    def test_validation_rejects_placeholder(self):
        from src.core.validation_engine import ValidationPipeline
        vp = ValidationPipeline(min_confidence=0.15)
        finding = {
            "rule_id": "SEC_PASSWORD_ASSIGNMENT",
            "title": "Hardcoded Password",
            "message": "password = changeme",
            "severity": "CRITICAL",
            "category": "SECRET",
            "file_path": "config.py",
            "line": 1,
            "column": 0,
            "code_snippet": 'password = "changeme"',
            "confidence": 0.85,
            "tags": ["secret", "password"],
            "raw_secret": "changeme",
        }
        result = vp.validate_finding(finding)
        assert result is None

    def test_validation_accepts_eval_in_production(self):
        from src.core.validation_engine import ValidationPipeline
        vp = ValidationPipeline(min_confidence=0.15)
        finding = {
            "rule_id": "SECURITY_EVAL_USAGE",
            "title": "eval() usage",
            "message": "eval(user_input)",
            "severity": "HIGH",
            "category": "SECURITY",
            "file_path": "src/app.py",
            "line": 10,
            "column": 0,
            "code_snippet": "eval(user_data)",
            "confidence": 0.7,
            "tags": ["security", "eval"],
        }
        result = vp.validate_finding(finding, file_content="eval(user_data)")
        assert result is not None

    def test_validation_rejects_comment_line(self):
        from src.core.validation_engine import ValidationPipeline
        vp = ValidationPipeline(min_confidence=0.15)
        finding = {
            "rule_id": "SEC_EVAL",
            "title": "eval usage",
            "message": "eval() in comment",
            "severity": "HIGH",
            "category": "SECURITY",
            "file_path": "src/app.py",
            "line": 1,
            "column": 0,
            "code_snippet": "# TODO: use eval() here",
            "confidence": 0.5,
            "tags": [],
        }
        result = vp.validate_finding(finding, file_content="# TODO: use eval() here")
        assert result is None

    def test_validation_batch(self):
        from src.core.validation_engine import ValidationPipeline
        vp = ValidationPipeline(min_confidence=0.15)
        findings = [
            {
                "rule_id": "SEC_PASSWORD_ASSIGNMENT",
                "title": "Hardcoded Password",
                "message": "password = input()",
                "severity": "CRITICAL",
                "category": "SECRET",
                "file_path": "app.py",
                "line": 1,
                "column": 0,
                "code_snippet": 'password = input("Enter:")',
                "confidence": 0.85,
                "tags": [],
            },
            {
                "rule_id": "SEC_AWS_ACCESS_KEY",
                "title": "AWS Access Key",
                "message": "Found AWS key",
                "severity": "CRITICAL",
                "category": "SECRET",
                "file_path": "app.py",
                "line": 5,
                "column": 0,
                "code_snippet": "AKIAIOSFODNN7EXAMPLE",
                "confidence": 0.95,
                "tags": ["secret", "aws"],
            },
        ]
        validated = vp.validate_all(findings)
        assert len(validated) == 1
        assert validated[0]["rule_id"] == "SEC_AWS_ACCESS_KEY"


class TestCallGraphIntegration:
    def test_call_graph_analyzes_file(self):
        from src.core.call_graph import CallGraph
        cg = CallGraph()
        source = '''
def main():
    user_input = input("Enter: ")
    process(user_input)

def process(data):
    dangerous(data)

def dangerous(data):
    eval(data)
'''
        cg.analyze_file("test.py", source)
        stats = cg.to_dict()["stats"]
        assert stats["total_functions"] >= 2

    def test_call_graph_finds_vulnerable_paths(self):
        from src.core.call_graph import CallGraph
        cg = CallGraph()
        source = '''
def main():
    data = input("Enter: ")
    process(data)

def process(data):
    run_eval(data)

def run_eval(data):
    eval(data)
'''
        cg.analyze_file("app.py", source)
        vuln_paths = cg.get_vulnerable_paths()
        assert len(vuln_paths) >= 1

    def test_call_graph_dead_code(self):
        from src.core.call_graph import CallGraph
        cg = CallGraph()
        source = '''
def main():
    print("hello")

def never_called():
    eval("secret")
'''
        cg.analyze_file("app.py", source)
        reachability = cg.get_reachability("never_called")
        assert reachability in ("dead_code", "test_only", "unreachable")

    def test_call_graph_repository(self):
        from src.core.call_graph import CallGraph
        import tempfile
        import os
        cg = CallGraph()
        with tempfile.TemporaryDirectory() as tmpdir:
            app_file = os.path.join(tmpdir, "app.py")
            with open(app_file, "w") as f:
                f.write('def main():\n    eval(input())\n')
            cg.analyze_repository(tmpdir)
            stats = cg.to_dict()["stats"]
            assert stats["total_functions"] >= 1


class TestPipelineValidationIntegration:
    def test_pipeline_with_validation(self):
        from src.core.pipeline import AnalysisPipeline
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            app_file = os.path.join(tmpdir, "app.py")
            with open(app_file, "w") as f:
                f.write('''
def main():
    data = input("Enter: ")
    eval(data)

def safe():
    print("safe code")
''')
            pipeline = AnalysisPipeline(
                include_tests=False,
                include_docs=False,
                validate_findings=True,
            )
            result = pipeline.analyze_repository(tmpdir)
            assert result.call_graph_stats.get("total_functions", 0) >= 1
            assert isinstance(result.vulnerable_paths, list)

    def test_pipeline_without_validation(self):
        from src.core.pipeline import AnalysisPipeline
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            app_file = os.path.join(tmpdir, "app.py")
            with open(app_file, "w") as f:
                f.write('x = 1\n')
            pipeline = AnalysisPipeline(validate_findings=False)
            result = pipeline.analyze_repository(tmpdir)
            assert result.rejected_by_validation == 0


class TestSecretAnalyzerIntegration:
    def test_analyzer_enriches_secret(self):
        from src.core.models import Finding, Severity, FindingCategory, Language, CodeLocation
        from src.core.secret_analyzer import SecretAnalyzer
        finding = Finding(
            rule_id="SEC_PASSWORD_ASSIGNMENT",
            title="Hardcoded Password",
            description="Found hardcoded password",
            severity=Severity.CRITICAL,
            confidence=0.85,
            category=FindingCategory.SECRET,
            language=Language.PYTHON,
            location=CodeLocation(file_path="config.py", line=1, code_snippet='password = "admin123"'),
            tags=["secret", "password"],
            raw_secret="admin123",
        )
        analyzer = SecretAnalyzer()
        result = analyzer.analyze(finding)
        assert result.secret_type.name
        assert result.risk.risk_level
        assert result.classification
        assert isinstance(result.recommendations, list)

    def test_analyzer_classifies_aws_key(self):
        from src.core.models import Finding, Severity, FindingCategory, Language, CodeLocation
        from src.core.secret_analyzer import SecretAnalyzer
        finding = Finding(
            rule_id="SEC_AWS_ACCESS_KEY",
            title="AWS Access Key",
            description="Found AWS key",
            severity=Severity.CRITICAL,
            confidence=0.95,
            category=FindingCategory.SECRET,
            language=Language.PYTHON,
            location=CodeLocation(file_path="app.py", line=1, code_snippet="AKIAIOSFODNN7EXAMPLE"),
            tags=["secret", "aws"],
            raw_secret="AKIAIOSFODNN7EXAMPLE",
        )
        analyzer = SecretAnalyzer()
        result = analyzer.analyze(finding)
        assert "AWS" in result.secret_type.provider or "AWS" in result.secret_type.name


class TestBenchmark:
    def test_run_myscan_local(self):
        from src.core.benchmark import _run_myscan
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            app_file = os.path.join(tmpdir, "app.py")
            with open(app_file, "w") as f:
                f.write('eval(input("Enter: "))\n')
            result = _run_myscan(tmpdir)
            assert result.tool_name == "myscan"
            assert result.finding_count >= 0
            assert result.scan_duration >= 0

    def test_normalize_file_path(self):
        from src.core.benchmark import _normalize_file_path
        assert _normalize_file_path("C:\\Users\\test\\app.py") == "C:/Users/test/app.py"
        assert _normalize_file_path("./src/app.py") == "src/app.py"
        assert _normalize_file_path("src/app.py") == "src/app.py"
        assert _normalize_file_path("../src/app.py") == "src/app.py"

    def test_normalize_finding_key(self):
        from src.core.benchmark import _normalize_finding_key
        f = {"file": "app.py", "line": 10, "rule_id": "SEC_001"}
        key = _normalize_finding_key(f)
        assert "app.py:10:SEC_001" == key

    def test_compute_overlap(self):
        from src.core.benchmark import _compute_overlap, ToolResult
        a = ToolResult(tool_name="a", findings=[
            {"rule_id": "R1", "file": "app.py", "line": 10},
            {"rule_id": "R2", "file": "app.py", "line": 20},
        ])
        b = ToolResult(tool_name="b", findings=[
            {"rule_id": "R1", "file": "app.py", "line": 10},
            {"rule_id": "R3", "file": "app.py", "line": 30},
        ])
        overlap = _compute_overlap(a, b)
        assert len(overlap) == 1

    def test_compute_unique(self):
        from src.core.benchmark import _compute_unique, ToolResult
        a = ToolResult(tool_name="a", findings=[
            {"rule_id": "R1", "file": "app.py", "line": 10},
            {"rule_id": "R2", "file": "app.py", "line": 20},
        ])
        b = ToolResult(tool_name="b", findings=[
            {"rule_id": "R1", "file": "app.py", "line": 10},
        ])
        unique = _compute_unique(a, b)
        assert len(unique) == 1
        assert unique[0]["rule_id"] == "R2"

    def test_run_myscan_benchmark_integration(self):
        from src.core.benchmark import run_benchmark
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            app_file = os.path.join(tmpdir, "app.py")
            with open(app_file, "w") as f:
                f.write('eval(input("Enter: "))\n')
            result = run_benchmark(tmpdir, tools=[])
            assert result.myscan_result is not None
            assert result.duration >= 0
            d = result.to_dict()
            assert "myscan" in d
            assert d["target"] == tmpdir
