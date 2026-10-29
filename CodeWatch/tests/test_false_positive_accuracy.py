"""End-to-end regression tests for the false-positive corpus.

Every case here previously produced a bogus finding through the full engine
pipeline (scanner -> validation -> severity gate -> risk). Once fixed, the
canonical dataset is: placeholders, weak values, header/auth names, static
string literals and plain text are never reported, while real secrets,
dynamic XSS sinks and real vulnerabilities still are.
"""

import tempfile
from pathlib import Path

from src.core.config import ScanConfig
from src.core.engine import ScanEngine
from src.core.models import FindingCategory, Severity


def _engine(files: dict[str, str], **kwargs) -> list:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        cfg = ScanConfig(include_tests=True, include_docs=True, include_examples=True, **kwargs)
        return ScanEngine(cfg).scan(str(root)).findings


def _rules(findings, *rule_ids):
    return [f for f in findings if f.rule_id in rule_ids]


class TestPlaceholderCredentialsNotReported:
    def test_dictionary_words_in_text_are_not_aws_access_keys(self):
        findings = _engine({
            "animals.txt": (
                "asianconstablebutterfly\n"
                "akianimalclassification\n"
                "asiaswallowtailbutterfly\n"
                "prefixAKIA2EPBN2U4Z3FQRXDFsuffix\n"
            ),
            "words.py": (
                "asianconstablebutterfly\n"
                "akianimalclassification\n"
                "asiaswallowtailbutterfly\n"
                "prefixAKIA2EPBN2U4Z3FQRXDFsuffix\n"
            ),
        })

        assert not _rules(findings, "SEC_AWS_ACCESS_KEY", "SEC043")

    def test_myscan_test_api_key_placeholder_rejected_without_hiding_real_keys(self):
        fake = _engine({
            "app.js": 'const SERVICE_API_KEY = "mscan_test_7Hq2K9vP4xL8nR3sW6cD1fG5jA0";\n',
        })
        assert not _rules(fake, "SEC_GENERIC_API_KEY")

        real = _engine({
            "app.js": 'const SERVICE_API_KEY = "mS9vQ2xK7pL4nR8dW3cF1hJ6";\n',
        })
        assert any(f.rule_id == "SEC_GENERIC_API_KEY" for f in real)

        embedded_marker = _engine({
            "app.js": (
                'const SERVICE_API_KEY = "prefixmscan_test_7Hq2K9vP4xL8nR3sW6cD1fG5jA0";\n'
            ),
        })
        assert any(f.rule_id == "SEC_GENERIC_API_KEY" for f in embedded_marker)

    def test_dot_length_never_a_secret(self):
        findings = _engine({"a.py": 'password = "length"\napi_key = "size"\n'})
        assert not _rules(findings, "SEC_PASSWORD_ASSIGNMENT", "SEC017", "SEC_GENERIC_API_KEY")

    def test_existing_variable_name_placeholder(self):
        # Multi-line file: the credential line sits in the middle of unrelated
        # code. The old pipeline stored a multi-line context as the snippet and
        # never saw the actual value.
        findings = _engine({
            "b.js": (
                "const config = require('./config');\n"
                "let apiKey = \"existing\";\n"
                "const password = \"existing\";\n"
                "var secret = \"authorization\";\n"
                "export default config;\n"
            ),
        })
        assert not _rules(findings, "SEC017", "SEC_GENERIC_API_KEY", "SEC_PASSWORD_ASSIGNMENT")

    def test_authorization_header_name_not_a_secret(self):
        findings = _engine({"a.py": 'token = "authorization"\n'})
        assert not _rules(findings, "SEC017", "SEC_PASSWORD_ASSIGNMENT", "SEC_GENERIC_API_KEY")

    def test_weak_password_with_digits_rejected(self):
        findings = _engine({"a.py": 'password = "Existing123"\n'})
        assert not _rules(findings, "SEC_PASSWORD_ASSIGNMENT", "SEC017")

    def test_demo_camel_case_api_key_rejected(self):
        findings = _engine({"a.py": 'API_KEY = "S0meL0ngSecretT0kenValueHere"\n'})
        assert not _rules(findings, "SEC_GENERIC_API_KEY", "SEC017", "SEC_PASSWORD_ASSIGNMENT")

    def test_your_key_placeholder_rejected(self):
        findings = _engine({"a.py": 'api_key = "your-api-key-here"\npassword = "changeme"\n'})
        assert not _rules(findings, "SEC017", "SEC_PASSWORD_ASSIGNMENT", "SEC_GENERIC_API_KEY")

    def test_space_separated_placeholder_phrases_rejected(self):
        findings = _engine({"a.py": (
            'token = "your token here"\n'
            'secret = "put your secret here"\n'
            'password = "enter password here"\n'
            'api_key = "type your key"\n'
        )})
        assert not _rules(findings, "SEC017", "SEC_PASSWORD_ASSIGNMENT", "SEC_GENERIC_API_KEY")

    def test_demo_allcaps_placeholders_rejected(self):
        findings = _engine({"a.py": 'API_KEY = "YOUR_API_KEY"\nPASSWORD = "YOUR_PASSWORD"\n'})
        assert not _rules(findings, "SEC017", "SEC_PASSWORD_ASSIGNMENT", "SEC_GENERIC_API_KEY")

    def test_js_declarations_placeholder_rejected(self):
        findings = _engine({"app.js": (
            "const API_KEY = 'sk_live_1234'; // short sample\n"
            "const password = 'password';\n"
            "const secret = 'abcdefgh'; // uniform lowercase\n"
        )})
        assert not _rules(findings, "SEC017", "SEC_PASSWORD_ASSIGNMENT", "SEC_GENERIC_API_KEY")

    def test_inline_comment_value_survives(self):
        findings = _engine({"a.py": 'password = "P@ssw#ord!2024"  # production db\n'})
        assert any(f.rule_id == "SEC_PASSWORD_ASSIGNMENT" for f in findings)
        pw = [f for f in findings if f.rule_id == "SEC_PASSWORD_ASSIGNMENT"]
        assert pw and pw[0].raw_secret == "P@ssw#ord!2024"


class TestRealSecretsStillReported:
    def test_aws_access_key_ids_are_case_sensitive_exact_tokens(self):
        findings = _engine({
            "creds.py": (
                'AWS_ACCESS_KEY_ID = "AKIA2EPBN2U4Z3FQRXDF"\n'
                'AWS_SESSION_ACCESS_KEY_ID = "ASIA2EPBN2U4Z3FQRXDF"\n'
            ),
        })

        aws_findings = _rules(findings, "SEC_AWS_ACCESS_KEY")
        assert len(aws_findings) == 2
        assert not _rules(findings, "SEC043")
        assert {f.raw_secret for f in aws_findings} == {
            "AKIA2EPBN2U4Z3FQRXDF",
            "ASIA2EPBN2U4Z3FQRXDF",
        }
        assert all(f.severity == Severity.HIGH for f in aws_findings)
        assert all(0.6 <= f.confidence <= 0.95 for f in aws_findings)

    def test_stripe_test_key_still_detected(self):
        findings = _engine({
            "config.py": 'STRIPE_API_KEY = "sk_test_51H8kLmN4pQrT7vWxY2zA5bC9dEfGhJk"\n',
        })
        assert any(f.rule_id == "SEC_STRIPE_KEY_TEST" for f in findings)

    def test_strong_password_survives(self):
        findings = _engine({"auth.py": 'password = "P@ssw0rd!XyZz99"\n'})
        assert any(f.rule_id == "SEC_PASSWORD_ASSIGNMENT" for f in findings)

    def test_vendor_api_key_survives(self):
        findings = _engine({"config.py": 'OPENAI_API_KEY = "sk-9f8e7d6c5b4a3z2y1x0w8F7s6G5h4J3k"\n'})
        assert any(f.rule_id == "SEC_OPENAI_KEY" for f in findings)

    def test_real_aws_key_survives(self):
        findings = _engine({"creds.py": 'AWS_ACCESS_KEY_ID = "AKIA2EPBN2U4Z3FQRXDF"\n'})
        assert any(f.rule_id == "SEC_AWS_ACCESS_KEY" for f in findings)

    def test_real_db_url_survives(self):
        findings = _engine({"creds.py": 'DB_URL = "postgresql://appuser:S3cr3t!Pa55w0rd@prod-db.internal:5432/app"\n'})
        assert any(f.rule_id == "SEC_CLOUD_DB_URL_CREDS" for f in findings)


class TestAdditionalSecretRegressions:
    def test_real_credentials_in_test_fixtures_are_still_reported(self):
        findings = _engine({
            "tests/fixtures/config.py": (
                'API_TOKEN = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"\n'
                'DB_URL = "postgresql://deploy_user:Q7z!Lp3#vM8$N2xK@db.internal/app"\n'
                'password = "P@ssw0rd!XyZz99"\n'
            ),
        })
        reported = {f.rule_id for f in findings}
        assert "SEC_GENERIC_API_KEY" in reported
        assert "SEC_CLOUD_DB_URL_CREDS" in reported
        assert "SEC_PASSWORD_ASSIGNMENT" in reported

    def test_placeholders_dictionary_words_and_identifiers_are_rejected(self):
        findings = _engine({
            "credentials.py": (
                'API_TOKEN = "your-token-here"\n'
                'CLIENT_SECRET = "placeholder"\n'
                'api_key = "asianconstablebutterfly"\n'
                'request_id = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"\n'
            ),
        })
        assert not _rules(
            findings,
            "SEC_GENERIC_API_KEY",
            "SEC_PASSWORD_ASSIGNMENT",
            "SEC_CLOUD_DB_URL_CREDS",
        )

    def test_generated_urllib3_ca_fixture_is_not_suppressed_elsewhere(self):
        content = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA9f8e7d6c5b4a3z2y1x0w8F7s6G5h4J3k\n"
            "-----END PRIVATE KEY-----\n"
        )
        for key_name in ("cacert.key", "server.key"):
            findings = _engine({
                f"dummyserver/certs/{key_name}": content
            })
            assert not _rules(findings, "SEC_PRIVATE_KEY_HEADER")

        unrelated_path = _engine({"other/certs/cacert.key": content})
        assert any(
            f.rule_id == "SEC_PRIVATE_KEY_HEADER" for f in unrelated_path
        )

        real_key = _engine({"config/private.key": content})
        assert any(f.rule_id == "SEC_PRIVATE_KEY_HEADER" for f in real_key)


class TestXssStaticVsDynamic:
    def test_static_innerhtml_not_reported(self):
        findings = _engine({"app.js": 'element.innerHTML = "<h1>Hello</h1>";\n'})
        assert not _rules(findings, "SEC004")

    def test_dynamic_innerhtml_reported(self):
        findings = _engine({"app.js": 'element.innerHTML = userInput;\n'})
        assert any(f.rule_id == "SEC004" for f in findings)

    def test_interpolated_innerhtml_reported(self):
        findings = _engine({"app.js": 'element.innerHTML = name + "</div>";\n'})
        assert any(f.rule_id == "SEC004" for f in findings)

    def test_static_react_html_not_reported(self):
        findings = _engine({"App.jsx": 'return <div dangerouslySetInnerHTML={{__html: "<b>hi</b>"}} />;\n'})
        assert not _rules(findings, "SEC005")

    def test_dynamic_react_html_reported(self):
        findings = _engine({"App.jsx": 'return <div dangerouslySetInnerHTML={{__html: html}} />;\n'})
        assert any(f.rule_id == "SEC005" for f in findings)


class TestVulnerabilitiesStillDetected:
    def test_sql_injection_survives(self):
        findings = _engine({"app.py": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'})
        assert any(f.rule_id == "SEC001" for f in findings)

    def test_command_injection_survives(self):
        findings = _engine({"app.py": 'os.system("echo " + user_input)\n'})
        assert any(f.rule_id == "SEC002" for f in findings)

    def test_parameterized_sql_safe(self):
        findings = _engine({"app.py": 'cursor.execute("SELECT * FROM users WHERE id = %s", params)\n'})
        assert not _rules(findings, "SEC001")


class TestRiskScoreConsistency:
    def _result(self, files):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, content in files.items():
                (root / name).write_text(content)
            cfg = ScanConfig(include_tests=True, include_docs=True, include_examples=True)
            return ScanEngine(cfg).scan(str(root))

    def test_clean_code_zero_risk(self):
        r = self._result({
            "app.py": (
                "import os\n"
                "def safe(uid):\n"
                "    db_password = os.environ.get('DB_PASSWORD')\n"
                "    return os.path.join(base, uid)\n"
            ),
        })
        assert r.risk_score == 0
        assert r.grade == "A+"
        assert r.findings == []

    def test_quality_and_info_excluded_from_risk(self):
        from src.core.models import CodeLocation, Finding, Language

        r = self._result({})
        r.findings = [
            Finding(
                rule_id="Q001", title="Magic number", description="d",
                severity=Severity.MEDIUM, confidence=0.9,
                category=FindingCategory.QUALITY, language=Language.PYTHON,
                location=CodeLocation(file_path="x.py", line=1),
            ),
            Finding(
                rule_id="SEC017", title="Hardcoded", description="d",
                severity=Severity.HIGH, confidence=0.9,
                category=FindingCategory.SECURITY, language=Language.PYTHON,
                location=CodeLocation(file_path="x.py", line=2),
                is_false_positive=True,
            ),
            Finding(
                rule_id="SEC017", title="Hardcoded", description="d",
                severity=Severity.HIGH, confidence=0.9,
                category=FindingCategory.SECURITY, language=Language.PYTHON,
                location=CodeLocation(file_path="x.py", line=3),
                likely_false_positive=True,
            ),
        ]
        assert r.risk_score == 0

    def test_validated_security_finding_drives_risk(self):
        from src.core.models import CodeLocation, Finding, Language

        r = self._result({})
        r.findings = [
            Finding(
                rule_id="SEC001", title="SQL Injection", description="d",
                severity=Severity.CRITICAL, confidence=0.9,
                category=FindingCategory.SECURITY, language=Language.PYTHON,
                location=CodeLocation(file_path="x.py", line=1),
            ),
        ]
        assert r.risk_score > 0
