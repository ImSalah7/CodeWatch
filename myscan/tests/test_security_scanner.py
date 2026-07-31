"""Tests for security scanner."""

import pytest

from src.core.models import Language
from src.scanners.security_scanner import SecurityScanner


class TestSecurityScanner:
    def setup_method(self):
        self.scanner = SecurityScanner()

    def test_sql_injection(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        sql_findings = [f for f in findings if "SQL Injection" in f.title]
        assert len(sql_findings) >= 1
        assert sql_findings[0].cwe == "CWE-89"
        assert sql_findings[0].occurrences == 1
        assert sql_findings[0].evidence

    def test_sql_injection_parameterized_dict_is_safe(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", {"id": user_id})'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        sql_findings = [f for f in findings if "SQL Injection" in f.title]
        assert len(sql_findings) == 0

    def test_sql_injection_parameterized_tuple_is_safe(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        sql_findings = [f for f in findings if "SQL Injection" in f.title]
        assert len(sql_findings) == 0

    def test_sql_injection_parameterized_identifier_is_safe(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", params)'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        sql_findings = [f for f in findings if "SQL Injection" in f.title]
        assert len(sql_findings) == 0

    def test_sql_injection_concat_is_dangerous(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        sql_findings = [f for f in findings if "SQL Injection" in f.title]
        assert len(sql_findings) >= 1

    @pytest.mark.parametrize("code,expected", [
        # Parameterized calls are safe (no regex match, no finding)
        ('cursor.execute("SELECT * FROM users WHERE id = %s", {"id": user_id})', 0),
        ('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))', 0),
        ('cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])', 0),
        ('cursor.execute("SELECT * FROM users WHERE id = %s", params)', 0),
        ('cursor.execute("SELECT * FROM users WHERE id = %s", self.params)', 0),
        ('cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))', 0),
        ('cursor.execute("SELECT * FROM users WHERE id = ?")', 0),
        # Interpolated queries remain dangerous (embedded quotes included)
        ('cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")', 1),
        ("cursor.execute(f\"SELECT name FROM users WHERE id = '{user_id}'\")", 1),
        ('cursor.execute("SELECT name FROM users WHERE id = \'" + user_id + "\'")', 1),
        ('cursor.execute("SELECT * FROM users WHERE id = " + user_id)', 1),
        ("cursor.execute('SELECT name FROM users WHERE id = \"' + user_id + '\"')", 1),
        ('cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))', 1),
        ('cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)', 1),
        ('cursor.executemany("INSERT INTO t VALUES (" + rows + ")", data)', 1),
    ])
    def test_sql_injection_parameterized_vs_interpolated(self, code, expected):
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        sql_findings = [f for f in findings if "SQL Injection" in f.title]
        assert len(sql_findings) == expected

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
        code = '# cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = self.scanner.scan_file(code, "app.py", Language.PYTHON)
        sql_findings = [f for f in findings if "SQL Injection" in f.title]
        assert len(sql_findings) == 0
