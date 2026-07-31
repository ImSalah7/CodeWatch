"""Tests for secrets scanner."""

from src.core.models import FindingCategory, Language
from src.scanners.secrets_scanner import SecretsScanner


class TestSecretsScanner:
    def setup_method(self):
        self.scanner = SecretsScanner()

    def test_aws_key(self):
        code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        aws_findings = [f for f in findings if "AWS" in f.title]
        assert len(aws_findings) >= 1
        assert aws_findings[0].category == FindingCategory.SECRET

    def test_github_token(self):
        code = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        gh_findings = [f for f in findings if "GitHub" in f.title]
        assert len(gh_findings) >= 1

    def test_private_key(self):
        code = '-----BEGIN RSA PRIVATE KEY-----'
        findings = self.scanner.scan_file(code, "key.pem", Language.UNKNOWN)
        key_findings = [f for f in findings if "Private Key" in f.title]
        assert len(key_findings) >= 1

    def test_slack_token(self):
        code = 'SLACK_TOKEN = "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrSt"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        slack_findings = [f for f in findings if "Slack" in f.title]
        assert len(slack_findings) >= 1

    def test_password_in_code(self):
        code = 'password = "SuperSecret123!"'
        findings = self.scanner.scan_file(code, "auth.py", Language.PYTHON)
        pw_findings = [f for f in findings if "Password" in f.title]
        assert len(pw_findings) >= 1

    def test_google_api_key(self):
        code = 'GOOGLE_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        google_findings = [f for f in findings if "Google" in f.title]
        assert len(google_findings) >= 1

    def test_no_false_positive_on_example(self):
        code = 'API_KEY = "example_api_key_for_testing_purposes"'
        findings = self.scanner.scan_file(code, "example.py", Language.PYTHON)
        for f in findings:
            assert f.confidence < 0.5 or "example" not in code.lower()

    def test_jwt_token(self):
        code = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
        findings = self.scanner.scan_file(code, "auth.py", Language.PYTHON)
        jwt_findings = [f for f in findings if "JWT" in f.title]
        assert len(jwt_findings) >= 1

    def test_high_entropy_detection(self):
        code = 'SECRET = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3x"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        entropy_findings = [f for f in findings if "Entropy" in f.title or "entropy" in f.title.lower()]
        assert len(entropy_findings) >= 1
