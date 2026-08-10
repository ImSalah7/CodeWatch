"""Tests for secrets scanner."""

import tempfile
from pathlib import Path

from src.core.config import ScanConfig
from src.core.engine import ScanEngine
from src.core.models import FindingCategory, Language
from src.scanners.secrets_scanner import SecretsScanner


def _engine_findings(files: dict[str, str]) -> list:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for name, content in files.items():
            (root / name).write_text(content)
        cfg = ScanConfig(include_tests=True, include_docs=True, include_examples=True)
        return ScanEngine(cfg).scan(str(root)).findings


class TestSecretsScanner:
    def setup_method(self):
        self.scanner = SecretsScanner()

    def test_aws_key(self):
        code = 'AWS_KEY = "AKIA2X7KQ4N5B8VZ6C2D"'
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
        code = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA9f8e7d6c5b4a3z2y1x0w8F7s6G5h4J3k\n"
            "-----END RSA PRIVATE KEY-----"
        )
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

    def test_openai_key(self):
        code = 'OPENAI_KEY = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_AbCdEfGhI"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        assert len([f for f in findings if "OpenAI" in f.title]) >= 1

    def test_anthropic_key(self):
        code = 'ANTHROPIC_KEY = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEF"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        assert len([f for f in findings if "Anthropic" in f.title]) >= 1

    def test_gitlab_token(self):
        code = 'GITLAB_TOKEN = "glpat-AbCdEfGhIjKlMnOpQrStUvWxYz"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        assert len([f for f in findings if "GitLab" in f.title]) >= 1

    def test_github_fine_grained(self):
        code = 'TOKEN = "github_pat_11AABCDEFGabcdefghijklmnopqrstuvwxyz"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        assert len([f for f in findings if "Fine-Grained" in f.title]) >= 1

    def test_huggingface_token(self):
        code = 'HF_TOKEN = "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        assert len([f for f in findings if "Hugging Face" in f.title]) >= 1

    def test_azure_account_key(self):
        code = 'AccountKey="M0xY1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f3g4h5i6=="'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        assert len([f for f in findings if "Azure" in f.title]) >= 1

    def test_db_credentials_in_url(self):
        code = 'DATABASE_URL = "postgres://admin:Sup3rSecret!@db.internal:5432/app"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        assert len([f for f in findings if "Credentials in URL" in f.title]) >= 1

    def test_keyboard_walk_is_not_reported(self):
        code = 'API_KEY = "qwertyuiopasdfghjklzxcvbnm1234567890"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        for f in findings:
            assert f.confidence < 0.5

    def test_repeated_char_value_is_weak(self):
        code = 'password = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
        findings = self.scanner.scan_file(code, "auth.py", Language.PYTHON)
        for f in findings:
            assert f.confidence < 0.5

    def test_self_referential_value_is_weak(self):
        code = 'api_key = "api_key"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        for f in findings:
            assert f.confidence < 0.5

    def test_url_not_flagged_as_high_entropy(self):
        code = 'URL = "https://cdn.example.com/assets/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789.js"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        entropy_findings = [f for f in findings if "Entropy" in f.title]
        assert len(entropy_findings) == 0


class TestSecretFalsePositiveRejection:
    """Precision guardrails: values that look like secrets but are not real
    credentials must produce zero findings."""

    def setup_method(self):
        self.scanner = SecretsScanner()

    def assert_no_findings(self, content: str):
        findings = self.scanner.scan_file(content, "config.py", Language.PYTHON)
        assert findings == [], f"expected no findings, got {[f.rule_id for f in findings]}"

    def test_openai_prefix_in_unrelated_identifier(self):
        self.assert_no_findings('def _sk_live_metric(): return 1')

    def test_twilio_prefix_without_secret_variable(self):
        self.assert_no_findings(
            'build_id = "SK7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e"'
        )

    def test_prose_generic_api_key(self):
        self.assert_no_findings('api_key = "the_application_environment_variable"')

    def test_weak_passwords(self):
        self.assert_no_findings('password = "qwerty123"')
        self.assert_no_findings('password = "hello123"')
        self.assert_no_findings('password = "admin123"')
        self.assert_no_findings('password = "password"')

    def test_uniform_charset_value(self):
        self.assert_no_findings('password = "abcdefghijklmnopqrstuvwxyz"')

    def test_sqlite_url_without_credentials(self):
        self.assert_no_findings('DATABASE_URL = "sqlite:///app.db"')

    def test_benign_high_entropy_value(self):
        self.assert_no_findings(
            'schema_hash = "9f8e7d6c5b4a3z2y1x0w8F7s6G5h4J3k2L1m0N9p8Q"'
        )

    def test_aws_example_keys_rejected(self):
        self.assert_no_findings('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"')
        self.assert_no_findings(
            'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        )

    def test_unsigned_jwt_rejected(self):
        self.assert_no_findings(
            'jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.aaa"'
        )

    def test_bare_pem_header_rejected(self):
        self.assert_no_findings("-----BEGIN RSA PRIVATE KEY-----")

    def test_known_format_on_non_secret_identifier_rejected(self):
        self.assert_no_findings(
            'trace_id = "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"'
        )
        self.assert_no_findings(
            'build_id = "AIzaSyA-abcdefghijklmnopqrstuvwxyz01234567"'
        )


class TestGenuineSecretPreservation:
    """Real credential formats must still be detected despite the FP guardrails."""

    def setup_method(self):
        self.scanner = SecretsScanner()

    def test_sendgrid_key(self):
        code = (
            'SENDGRID_API_KEY = '
            '"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"'
        )
        findings = [f for f in self.scanner.scan_file(code, "config.py", Language.PYTHON)
                    if "SendGrid" in f.title]
        assert len(findings) >= 1

    def test_pem_private_key_block(self):
        code = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA9f8e7d6c5b4a3z2y1x0w8F7s6G5h4J3k\n"
            "-----END RSA PRIVATE KEY-----"
        )
        findings = [f for f in self.scanner.scan_file(code, "key.pem", Language.UNKNOWN)
                    if "Private Key" in f.title]
        assert len(findings) >= 1

    def test_jwt(self):
        code = (
            'JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
            'eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
            '9f8e7d6c5b4a3z2y1x0w8F7s6G5h4J3k"'
        )
        findings = [f for f in self.scanner.scan_file(code, "config.py", Language.PYTHON)
                    if "JWT" in f.title or "Token" in f.title]
        assert len(findings) >= 1

    def test_anthropic_key_not_misattributed_to_openai(self):
        code = 'ANTHROPIC_KEY = "sk-ant-9f8e7d6c5b4a3z2y1x0w8F7s6G5h4J3kQ2wE4r5t6y7u8i"'
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        assert [f for f in findings if f.rule_id == "SEC_OPENAI_KEY"] == []
        assert len([f for f in findings if f.rule_id == "SEC_ANTHROPIC_KEY"]) >= 1

    def test_single_finding_per_credential(self):
        code = (
            'SENDGRID_API_KEY = '
            '"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"'
        )
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC_SENDGRID_KEY"

    def test_aws_secret_key_value_not_truncated(self):
        code = (
            'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMIK7MDENGbPxRfiCYzK9xQ2V3mN8pL0"'
        )
        findings = self.scanner.scan_file(code, "config.py", Language.PYTHON)
        aws = [f for f in findings if f.rule_id == "SEC_AWS_SECRET_KEY"]
        assert len(aws) >= 1
        assert aws[0].raw_secret == "wJalrXUtnFEMIK7MDENGbPxRfiCYzK9xQ2V3mN8pL0"
        assert len(aws[0].raw_secret) == 42


class TestEngineLevelValidation:
    """End-to-end checks that real secrets survive the validation pipeline and
    placeholders are rejected, including via the legacy SEC01x rules."""

    def test_pem_private_key_survives_pipeline(self):
        findings = _engine_findings({
            "key.pem": (
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIEowIBAAKCAQEA9f8e7d6c5b4a3z2y1x0w8F7s6G5h4J3k\n"
                "-----END RSA PRIVATE KEY-----\n"
            ),
        })
        assert any(f.rule_id == "SEC_PRIVATE_KEY_HEADER" for f in findings)

    def test_bare_pem_header_rejected_at_engine_level(self):
        findings = _engine_findings({"key.pem": "-----BEGIN RSA PRIVATE KEY-----\n"})
        assert not [f for f in findings if f.rule_id == "SEC_PRIVATE_KEY_HEADER"]

    def test_placeholder_api_key_rejected_at_engine_level(self):
        findings = _engine_findings({
            "placeholder.py": 'api_key = "your-api-key-here"\npassword = "changeme"\n',
        })
        assert not [f for f in findings if f.rule_id in ("SEC017", "SEC_PASSWORD_ASSIGNMENT")]

    def test_real_password_preserved_at_engine_level(self):
        findings = _engine_findings({"auth.py": 'password = "P@ssw0rd!XyZz99"\n'})
        assert any(f.rule_id == "SEC_PASSWORD_ASSIGNMENT" for f in findings)

    def test_real_aws_key_found_at_engine_level(self):
        findings = _engine_findings({"creds.py": 'AWS_ACCESS_KEY_ID = "AKIA2EPBN2U4Z3FQRXDF"\n'})
        assert any(f.rule_id == "SEC_AWS_ACCESS_KEY" for f in findings)

    def test_documented_example_aws_key_rejected(self):
        findings = _engine_findings({"creds.py": 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'})
        assert not [f for f in findings if f.rule_id in ("SEC_AWS_ACCESS_KEY", "SEC043")]
