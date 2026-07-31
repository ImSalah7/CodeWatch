"""Tests for scan engine and config."""

import tempfile
from pathlib import Path

from src.core.config import ScanConfig
from src.core.engine import ScanEngine
from src.core.models import CodeLocation, Finding, FindingCategory, Language, Severity
from src.core.smart_filter import SmartFilter


class TestScanConfig:
    def test_defaults(self):
        config = ScanConfig()
        assert not config.local
        assert not config.use_ai
        assert config.severity_threshold == "info"

    def test_skip_dirs(self):
        config = ScanConfig()
        dirs = config.skip_dirs
        assert ".git" in dirs
        assert "node_modules" in dirs
        assert "__pycache__" in dirs

    def test_include_tests(self):
        config = ScanConfig(include_tests=True)
        dirs = config.skip_dirs
        assert "tests" not in dirs


class TestSmartFilter:
    def setup_method(self):
        self.filter = SmartFilter(ScanConfig())

    def test_readme_filtered(self):
        finding = Finding(
            rule_id="SEC001", title="SQL Injection",
            description="SQL injection",
            severity=Severity.HIGH, confidence=0.8,
            category=FindingCategory.SECURITY,
            language=Language.PYTHON,
            location=CodeLocation(file_path="docs/README.md", line=10),
        )
        assert self.filter.is_false_positive(finding)

    def test_localhost_reduced(self):
        finding = Finding(
            rule_id="SEC001", title="Test",
            description="Test",
            severity=Severity.HIGH, confidence=0.8,
            category=FindingCategory.SECURITY,
            language=Language.PYTHON,
            location=CodeLocation(file_path="app.py", line=10, code_snippet="connect('localhost:5432')"),
        )
        self.filter.is_false_positive(finding)
        assert finding.confidence < 0.8 or finding.is_false_positive


class TestScanEngine:
    def test_local_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "app.py"
            test_file.write_text('cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")')
            config = ScanConfig(include_tests=True, include_docs=True)
            engine = ScanEngine(config)
            result = engine.scan(tmpdir)
            assert result.files_scanned >= 1
            assert len(result.findings) >= 1

    def test_scan_excludes_skip_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "src").mkdir()
            (Path(tmpdir) / "src" / "app.py").write_text("x = 1")
            (Path(tmpdir) / ".git").mkdir()
            (Path(tmpdir) / ".git" / "config").write_text("git config")
            (Path(tmpdir) / "node_modules").mkdir()
            (Path(tmpdir) / "node_modules" / "pkg.js").write_text("var x = 1")
            config = ScanConfig()
            engine = ScanEngine(config)
            result = engine.scan(tmpdir)
            assert result.files_scanned == 1

    def test_scan_with_multiple_languages(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.py").write_text("os.system(cmd)")
            (Path(tmpdir) / "app.js").write_text('element.innerHTML = userInput')
            (Path(tmpdir) / "app.java").write_text('Runtime.getRuntime().exec(cmd)')
            config = ScanConfig(include_tests=True)
            engine = ScanEngine(config)
            result = engine.scan(tmpdir)
            assert result.files_scanned >= 2
            assert len(result.findings) >= 2

    def test_clean_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "utils.py").write_text('''def add(a, b):
    return a + b

def multiply(a, b):
    return a * b''')
            config = ScanConfig()
            engine = ScanEngine(config)
            result = engine.scan(tmpdir)
            security = [f for f in result.findings if f.category == FindingCategory.SECURITY]
            assert len(security) == 0


class TestEnterpriseEngine:
    def test_enterprise_init(self):
        config = ScanConfig()
        engine = ScanEngine(config, enterprise_mode=True)
        assert engine.enterprise_mode is True

    def test_enterprise_scan_vulnerable_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "vuln.py").write_text(
                'import os\n'
                'def get_user_input():\n'
                '    return input("cmd: ")\n'
                'def run_cmd(cmd):\n'
                '    os.system(cmd)\n'
                'if __name__ == "__main__":\n'
                '    user_cmd = get_user_input()\n'
                '    run_cmd(user_cmd)\n'
            )
            config = ScanConfig(include_tests=True, include_docs=True)
            engine = ScanEngine(config, enterprise_mode=True)
            result = engine.scan(tmpdir)
            assert result.files_scanned >= 1
            assert getattr(result, '_enterprise_mode', False) is True
            assert hasattr(result, '_enterprise_metrics')

    def test_enterprise_scan_clean_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "clean.py").write_text(
                'def add(a, b):\n'
                '    return a + b\n'
            )
            config = ScanConfig()
            engine = ScanEngine(config, enterprise_mode=True)
            result = engine.scan(tmpdir)
            assert getattr(result, '_enterprise_mode', False) is True
            assert result.files_scanned >= 1

    def test_enterprise_finding_has_enriched_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "injection.py").write_text(
                'import os\n'
                'def execute(cmd):\n'
                '    os.system(cmd)\n'
                'execute(input("cmd: "))\n'
            )
            config = ScanConfig(include_tests=True, include_docs=True)
            engine = ScanEngine(config, enterprise_mode=True)
            result = engine.scan(tmpdir)
            for f in result.findings:
                assert hasattr(f, 'why_vulnerable')
                assert hasattr(f, 'impact')
                assert hasattr(f, 'exploit_scenario')
                assert hasattr(f, 'confidence_reasoning')

    def test_enterprise_metrics_populated(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.py").write_text(
                'import os\n'
                'os.system(input())\n'
            )
            config = ScanConfig()
            engine = ScanEngine(config, enterprise_mode=True)
            result = engine.scan(tmpdir)
            metrics = getattr(result, '_enterprise_metrics', {})
            assert "functionsAnalyzed" in metrics
            assert "dataFlowPaths" in metrics
            assert "taintSources" in metrics
            assert "taintSinks" in metrics

    def test_legacy_mode_no_enterprise_attrs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.py").write_text('x = 1')
            config = ScanConfig()
            engine = ScanEngine(config, enterprise_mode=False)
            result = engine.scan(tmpdir)
            assert getattr(result, '_enterprise_mode', False) is False
