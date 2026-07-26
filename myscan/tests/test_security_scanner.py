"""Tests for security scanner."""

import pytest
from src.core.models import Language, FindingCategory
from src.scanners.security_scanner import SecurityScanner


class TestSecurityScanner:
    def setup_method(self):
        self.scanner = SecurityScanner()

    def test_sql_injection(self):
        code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        sql_findings = [f for f in findings if "SQL Injection" in f.title]
        assert len(sql_findings) >= 1
        assert sql_findings[0].cwe == "CWE-89"

    def test_command_injection(self):
        code = 'os.system("echo " + user_input)'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        cmd_findings = [f for f in findings if "Command" in f.title]
        assert len(cmd_findings) >= 1

    def test_eval_usage(self):
        code = 'result = eval(user_input)'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        eval_findings = [f for f in findings if "eval()" in f.title]
        assert len(eval_findings) >= 1

    def test_pickle_deserialization(self):
        code = 'data = pickle.loads(untrusted_data)'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        pickle_findings = [f for f in findings if "pickle" in f.title.lower() or "deserialization" in f.title.lower()]
        assert len(pickle_findings) >= 1

    def test_yaml_unsafe(self):
        code = 'data = yaml.load(raw_data)'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        yaml_findings = [f for f in findings if "YAML" in f.title]
        assert len(yaml_findings) >= 1

    def test_debug_mode(self):
        code = 'DEBUG = True'
        findings = self.scanner.scan_file(code, "settings.py", Language.PYTHON)
        debug_findings = [f for f in findings if "Debug" in f.title]
        assert len(debug_findings) >= 1

    def test_cors_wildcard(self):
        code = 'CORS_ORIGINS = ["*"]'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        cors_findings = [f for f in findings if "CORS" in f.title]
        assert len(cors_findings) >= 1

    def test_ssl_verify_disabled(self):
        code = 'response = requests.get(url, verify=False)'
        findings = self.scanner.scan_file(code, "client.py", Language.PYTHON)
        ssl_findings = [f for f in findings if "SSL" in f.title or "Certificate" in f.title]
        assert len(ssl_findings) >= 1

    def test_innerhtml(self):
        code = 'element.innerHTML = userInput'
        findings = self.scanner.scan_file(code, "app.js", Language.JAVASCRIPT)
        xss_findings = [f for f in findings if "innerHTML" in f.title]
        assert len(xss_findings) >= 1

    def test_path_traversal(self):
        code = 'with open(request.args["file"]) as f:'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        path_findings = [f for f in findings if "Path" in f.title]
        assert len(path_findings) >= 1

    def test_clean_code_no_findings(self):
        code = '''
import os
def safe_function():
    result = os.path.join(base, user_input)
    return result
'''
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        assert len(findings) == 0

    def test_skips_comments(self):
        code = '# query = f"SELECT * FROM users WHERE id = {user_id}"'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        sql_findings = [f for f in findings if "SQL Injection" in f.title]
        assert len(sql_findings) == 0
