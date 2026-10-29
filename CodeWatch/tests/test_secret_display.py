"""Tests for Secret Display Mode - FULL, MASKED, SMART."""

from __future__ import annotations

import json

from src.core.models import (
    CodeLocation,
    Finding,
    FindingCategory,
    Language,
    ScanResult,
    SecretDisplayMode,
    Severity,
)
from src.core.secret_display import (
    SecretDisplayConfig,
    apply_secret_display_mode,
    get_secret_display_value,
    get_secret_display_warning,
    is_default_credential,
    is_weak_password,
    mask_secret,
)
from src.scanners.secrets_scanner import SecretsScanner


def _make_secret_finding(raw: str, rule_id: str = "SEC_PASSWORD_ASSIGNMENT",
                         tags: list[str] | None = None,
                         snippet: str = "") -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Hardcoded Password",
        description="Found hardcoded password.",
        severity=Severity.CRITICAL,
        confidence=0.85,
        category=FindingCategory.SECRET,
        language=Language.PYTHON,
        location=CodeLocation(
            file_path="app.py",
            line=10,
            code_snippet=snippet or raw,
        ),
        cwe="CWE-798",
        tags=tags or ["secret", "password_assignment"],
        raw_secret=raw,
    )


class TestMaskSecret:
    def test_long_secret(self):
        result = mask_secret("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        assert result.startswith("ghp_")
        assert result.endswith("xxxx")
        assert "**********" in result

    def test_short_secret(self):
        result = mask_secret("admin")
        assert len(result) >= 1
        assert result != "admin"

    def test_empty(self):
        assert mask_secret("") == "***"

    def test_very_long_secret(self):
        secret = "A" * 100
        result = mask_secret(secret)
        assert result.startswith("AAAA")
        assert result.endswith("AAAA")
        assert "****" in result

    def test_custom_mask_char(self):
        result = mask_secret("supersecret123", mask_char="#")
        assert "#" in result
        assert result.startswith("sup")
        assert result.endswith("123")

    def test_custom_visible_chars(self):
        result = mask_secret("verylongsecretvalue", visible_prefix=2, visible_suffix=2)
        assert result.startswith("ve")
        assert result.endswith("ue")


class TestWeakPasswordDetection:
    def test_admin(self):
        assert is_weak_password("admin") is True

    def test_password(self):
        assert is_weak_password("password") is True

    def test_123456(self):
        assert is_weak_password("123456") is True

    def test_admin123(self):
        assert is_weak_password("admin123") is True

    def test_qwerty(self):
        assert is_weak_password("qwerty") is True

    def test_production_secret_not_weak(self):
        assert is_weak_password("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") is False

    def test_case_insensitive(self):
        assert is_weak_password("ADMIN") is True
        assert is_weak_password("Password") is True

    def test_with_quotes(self):
        assert is_weak_password("'admin'") is True
        assert is_weak_password('"password"') is True

    def test_example_context(self):
        assert is_weak_password("anything", "example_password = 'test'") is True

    def test_unknown_not_weak(self):
        assert is_weak_password("xK9#mP2$vL") is False


class TestDefaultCredentialDetection:
    def test_admin_admin(self):
        assert is_default_credential("admin:admin") is True

    def test_root_root(self):
        assert is_default_credential("root:root") is True

    def test_admin_password(self):
        assert is_default_credential("admin:password") is True

    def test_just_admin(self):
        assert is_default_credential("admin") is True

    def test_just_root(self):
        assert is_default_credential("root") is True

    def test_line_context_password_admin(self):
        assert is_default_credential("admin123", "password = admin123") is True

    def test_unknown_not_default(self):
        assert is_default_credential("xK9#mP2$vL") is False


class TestFullMode:
    def test_full_mode_shows_raw_value(self):
        finding = _make_secret_finding("ghp_abc123def456ghi789jkl012mno345pqr")
        value = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert value == "ghp_abc123def456ghi789jkl012mno345pqr"

    def test_full_mode_shows_password(self):
        finding = _make_secret_finding("SuperSecretPass123!")
        value = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert value == "SuperSecretPass123!"

    def test_full_mode_no_masking(self):
        finding = _make_secret_finding("AKIAIOSFODNN7EXAMPLE")
        value = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert value == "AKIAIOSFODNN7EXAMPLE"

    def test_full_warning(self):
        warning = get_secret_display_warning(SecretDisplayMode.FULL)
        assert warning is not None
        assert "sensitive credentials" in warning


class TestMaskedMode:
    def test_masked_mode_masks_token(self):
        finding = _make_secret_finding("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        value = get_secret_display_value(finding, SecretDisplayMode.MASKED)
        assert "**********" in value
        assert value != "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

    def test_masked_mode_masks_password(self):
        finding = _make_secret_finding("SuperSecretPass123!")
        value = get_secret_display_value(finding, SecretDisplayMode.MASKED)
        assert "**********" in value
        assert value != "SuperSecretPass123!"

    def test_masked_mode_masks_weak_password(self):
        finding = _make_secret_finding("admin")
        value = get_secret_display_value(finding, SecretDisplayMode.MASKED)
        assert value != "admin"

    def test_masked_no_warning(self):
        warning = get_secret_display_warning(SecretDisplayMode.MASKED)
        assert warning is None


class TestSmartMode:
    def test_smart_shows_weak_passwords(self):
        finding = _make_secret_finding(
            "admin",
            tags=["secret", "password_assignment"],
        )
        value = get_secret_display_value(finding, SecretDisplayMode.SMART)
        assert value == "admin"

    def test_smart_shows_password_123456(self):
        finding = _make_secret_finding(
            "123456",
            tags=["secret", "password_assignment"],
        )
        value = get_secret_display_value(finding, SecretDisplayMode.SMART)
        assert value == "123456"

    def test_smart_shows_default_credential(self):
        finding = _make_secret_finding(
            "root",
            tags=["secret", "password_assignment"],
        )
        value = get_secret_display_value(finding, SecretDisplayMode.SMART)
        assert value == "root"

    def test_smart_masks_github_token(self):
        finding = _make_secret_finding(
            "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            rule_id="SEC_GITHUB_TOKEN",
            tags=["secret", "github_token"],
        )
        value = get_secret_display_value(finding, SecretDisplayMode.SMART)
        assert "**********" in value
        assert value != "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

    def test_smart_masks_aws_key(self):
        finding = _make_secret_finding(
            "AKIAIOSFODNN7ZYZX",
            rule_id="SEC_AWS_ACCESS_KEY",
            tags=["secret", "aws_access_key"],
            snippet='AWS_ACCESS_KEY = "AKIAIOSFODNN7ZYZX"',
        )
        value = get_secret_display_value(finding, SecretDisplayMode.SMART)
        assert "****" in value
        assert value != "AKIAIOSFODNN7ZYZX"

    def test_smart_masks_test_credential_despite_context_markers(self):
        raw = "sk_test_51H8kLmN4pQrT7vWxY2zA5bC9dEfGhJk"
        finding = _make_secret_finding(
            raw,
            rule_id="SEC_STRIPE_KEY_TEST",
            tags=["secret", "stripe_key_test"],
            snippet=f'STRIPE_API_KEY = "{raw}"  // synthetic test credential',
        )

        value = get_secret_display_value(finding, SecretDisplayMode.SMART)

        assert value != raw
        assert "sk_test_51H8kLmN4pQrT7vWxY2zA5bC9dEfGhJk" not in value

    def test_smart_masks_high_entropy(self):
        finding = _make_secret_finding(
            "xK9mP2vL8nQ4wR7jB3hY6tF5gD1sA0cE",
            rule_id="SEC_HIGH_ENTROPY",
            tags=["secret", "entropy"],
        )
        value = get_secret_display_value(finding, SecretDisplayMode.SMART)
        assert "****" in value

    def test_smart_masks_unknown_production_secret(self):
        finding = _make_secret_finding(
            "some_long_random_token_value_12345",
            rule_id="SEC_GENERIC_API_KEY",
            tags=["secret", "generic_api_key"],
        )
        value = get_secret_display_value(finding, SecretDisplayMode.SMART)
        assert "****" in value

    def test_smart_no_warning(self):
        warning = get_secret_display_warning(SecretDisplayMode.SMART)
        assert warning is None


class TestApplySecretDisplayMode:
    def test_apply_full_mode(self):
        findings = [
            _make_secret_finding("admin", tags=["secret", "password_assignment"]),
            _make_secret_finding("ghp_token123abc", rule_id="SEC_GITHUB_TOKEN",
                                 tags=["secret", "github_token"]),
        ]
        result = apply_secret_display_mode(findings, SecretDisplayMode.FULL)
        assert result[0].location.code_snippet == "admin"
        assert result[1].location.code_snippet == "ghp_token123abc"

    def test_apply_masked_mode(self):
        findings = [
            _make_secret_finding("admin", tags=["secret", "password_assignment"]),
            _make_secret_finding("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                                 rule_id="SEC_GITHUB_TOKEN",
                                 tags=["secret", "github_token"]),
        ]
        result = apply_secret_display_mode(findings, SecretDisplayMode.MASKED)
        assert result[0].location.code_snippet != "admin"
        assert "****" in result[1].location.code_snippet

    def test_apply_smart_mode(self):
        findings = [
            _make_secret_finding("admin", tags=["secret", "password_assignment"]),
            _make_secret_finding("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                                 rule_id="SEC_GITHUB_TOKEN",
                                 tags=["secret", "github_token"]),
        ]
        result = apply_secret_display_mode(findings, SecretDisplayMode.SMART)
        assert result[0].location.code_snippet == "admin"
        assert "****" in result[1].location.code_snippet

    def test_non_secret_findings_unchanged(self):
        finding = Finding(
            rule_id="SEC001",
            title="SQL Injection",
            description="Found SQL injection.",
            severity=Severity.HIGH,
            confidence=0.9,
            category=FindingCategory.SECURITY,
            language=Language.PYTHON,
            location=CodeLocation(file_path="app.py", line=1, code_snippet="cursor.execute(query)"),
        )
        original_snippet = finding.location.code_snippet
        result = apply_secret_display_mode([finding], SecretDisplayMode.MASKED)
        assert result[0].location.code_snippet == original_snippet

    def test_empty_findings(self):
        result = apply_secret_display_mode([], SecretDisplayMode.FULL)
        assert result == []

    def test_findings_without_raw_secret(self):
        finding = Finding(
            rule_id="SEC_HIGH_ENTROPY",
            title="High-Entropy String",
            description="May be a secret.",
            severity=Severity.MEDIUM,
            confidence=0.6,
            category=FindingCategory.SECRET,
            language=Language.PYTHON,
            location=CodeLocation(file_path="app.py", line=5, code_snippet="some_thing"),
            tags=["secret", "entropy"],
        )
        result = apply_secret_display_mode([finding], SecretDisplayMode.MASKED)
        assert result[0].location.code_snippet == "some_thing"


class TestSecretDisplayConfig:
    def test_default_config(self):
        config = SecretDisplayConfig()
        assert config.mode == SecretDisplayMode.SMART
        assert config.is_smart is True
        assert config.is_full is False
        assert config.is_masked is False

    def test_from_string_full(self):
        config = SecretDisplayConfig.from_string("full")
        assert config.mode == SecretDisplayMode.FULL

    def test_from_string_masked(self):
        config = SecretDisplayConfig.from_string("masked")
        assert config.mode == SecretDisplayMode.MASKED

    def test_from_string_smart(self):
        config = SecretDisplayConfig.from_string("smart")
        assert config.mode == SecretDisplayMode.SMART

    def test_from_string_invalid(self):
        config = SecretDisplayConfig.from_string("invalid")
        assert config.mode == SecretDisplayMode.SMART

    def test_to_dict(self):
        config = SecretDisplayConfig(SecretDisplayMode.SMART)
        d = config.to_dict()
        assert d["mode"] == "smart"
        assert d["warning"] is None

    def test_to_dict_full_warning(self):
        config = SecretDisplayConfig(SecretDisplayMode.FULL)
        d = config.to_dict()
        assert d["mode"] == "full"
        assert d["warning"] is not None


class TestSecretsScannerIntegration:
    def test_scanner_stores_raw_secret(self):
        scanner = SecretsScanner(mask_secrets=False)
        content = 'password = "P@ssw0rd2024!"'
        findings = scanner.scan_file(content, "test.py", Language.PYTHON)
        assert len(findings) > 0
        assert findings[0].raw_secret != ""
        assert findings[0].raw_secret == "P@ssw0rd2024!"
        assert "password" in findings[0].location.code_snippet

    def test_scanner_masks_by_default(self):
        scanner = SecretsScanner(mask_secrets=True)
        content = 'password = "SuperSecretPass123!"'
        findings = scanner.scan_file(content, "test.py", Language.PYTHON)
        assert len(findings) > 0
        assert findings[0].raw_secret != ""
        assert findings[0].location.code_snippet == 'password = "SuperSecretPass123!"'
        apply_secret_display_mode([findings[0]], SecretDisplayMode.MASKED)
        assert "SuperSecretPass123!" not in findings[0].location.code_snippet
        assert "password" in findings[0].location.code_snippet

    def test_scanner_raw_matches_content(self):
        scanner = SecretsScanner(mask_secrets=False)
        content = 'API_KEY = "ghp_abc123def456ghi789jkl012mno345pqr"'
        findings = scanner.scan_file(content, "test.py", Language.PYTHON)
        assert len(findings) > 0
        assert "ghp_" in findings[0].raw_secret


class TestJSONReporterIntegration:
    def test_json_includes_raw_secret(self):
        finding = _make_secret_finding("admin", tags=["secret", "password_assignment"])
        finding.fingerprint = "test123"
        result = ScanResult()
        result.findings = [finding]
        result._secret_display_mode = "full"

        from src.reporters.json_report import JSONReporter
        reporter = JSONReporter()
        report = json.loads(reporter.generate(result))

        assert report["secretDisplayMode"] == "full"
        secret_finding = report["findings"][0]
        assert secret_finding["rawSecret"] == "admin"

    def test_json_omits_raw_secret_unless_full_display_is_enabled(self):
        from src.reporters.json_report import JSONReporter

        for mode in ("smart", "masked"):
            finding = _make_secret_finding(
                "synthetic_dummy_credential_7Hq2K9vP4xL8",
                tags=["secret", "generic_api_key"],
            )
            result = ScanResult()
            result.findings = [finding]
            result._secret_display_mode = mode

            report = json.loads(JSONReporter().generate(result))

            assert report["secretDisplayMode"] == mode
            assert "rawSecret" not in report["findings"][0]

    def test_json_includes_display_mode(self):
        result = ScanResult()
        result._secret_display_mode = "smart"

        from src.reporters.json_report import JSONReporter
        reporter = JSONReporter()
        report = json.loads(reporter.generate(result))

        assert report["secretDisplayMode"] == "smart"

    def test_json_no_raw_secret_for_security_finding(self):
        finding = Finding(
            rule_id="SEC001",
            title="SQL Injection",
            description="Found SQL injection.",
            severity=Severity.HIGH,
            confidence=0.9,
            category=FindingCategory.SECURITY,
            language=Language.PYTHON,
            location=CodeLocation(file_path="app.py", line=1, code_snippet="cursor.execute(query)"),
            fingerprint="test456",
        )
        result = ScanResult()
        result.findings = [finding]

        from src.reporters.json_report import JSONReporter
        reporter = JSONReporter()
        report = json.loads(reporter.generate(result))

        assert "rawSecret" not in report["findings"][0]


class TestHTMLReporterIntegration:
    def test_html_full_mode_shows_warning(self):
        result = ScanResult()
        result._secret_display_mode = "full"
        result.findings = []

        from src.reporters.html_report import HTMLReporter
        reporter = HTMLReporter()
        html = reporter.generate(result)

        assert "Full Secret Display Enabled" in html
        assert "sensitive credentials" in html

    def test_html_masked_no_warning(self):
        result = ScanResult()
        result._secret_display_mode = "masked"
        result.findings = []

        from src.reporters.html_report import HTMLReporter
        reporter = HTMLReporter()
        html = reporter.generate(result)

        assert "Full Secret Display Enabled" not in html

    def test_html_smart_no_warning(self):
        result = ScanResult()
        result._secret_display_mode = "smart"
        result.findings = []

        from src.reporters.html_report import HTMLReporter
        reporter = HTMLReporter()
        html = reporter.generate(result)

        assert "Full Secret Display Enabled" not in html


class TestFullSecretDisplay:
    """Test that FULL mode shows complete assignment lines for password secrets
    and raw values for other secret types. Never shows ****** in FULL mode."""

    def test_password_admin123_shows_full_line(self):
        finding = _make_secret_finding(
            raw="admin123",
            rule_id="SEC_PASSWORD_ASSIGNMENT",
            snippet='password = "admin123"',
        )
        val = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert val == 'password = "admin123"'
        assert "****" not in val

    def test_db_password_shows_full_line(self):
        finding = _make_secret_finding(
            raw="Root@123",
            rule_id="SEC_PASSWORD_ASSIGNMENT",
            snippet='DB_PASSWORD = "Root@123"',
        )
        val = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert val == 'DB_PASSWORD = "Root@123"'
        assert "****" not in val

    def test_api_key_shows_raw_value(self):
        finding = _make_secret_finding(
            raw="sk-xxxxxxxxxxxxxxxxxxxxxxxx",
            rule_id="SEC_GENERIC_API_KEY",
            snippet='API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxx"',
        )
        val = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert val == "sk-xxxxxxxxxxxxxxxxxxxxxxxx"
        assert "****" not in val

    def test_jwt_secret_shows_raw_value(self):
        finding = _make_secret_finding(
            raw="my-super-secret",
            rule_id="SEC_JWT_SECRET",
            snippet='JWT_SECRET = "my-super-secret"',
        )
        val = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert val == "my-super-secret"
        assert "****" not in val

    def test_aws_secret_key_shows_raw_value(self):
        finding = _make_secret_finding(
            raw="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            rule_id="SEC_AWS_SECRET_KEY",
            snippet='AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        )
        val = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert val == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert "****" not in val

    def test_private_key_header_shows_raw_value(self):
        finding = _make_secret_finding(
            raw="-----BEGIN RSA PRIVATE KEY-----",
            rule_id="SEC_PRIVATE_KEY_HEADER",
            snippet="-----BEGIN RSA PRIVATE KEY-----",
        )
        val = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert val == "-----BEGIN RSA PRIVATE KEY-----"
        assert "****" not in val

    def test_github_token_shows_raw_value(self):
        finding = _make_secret_finding(
            raw="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            rule_id="SEC_GITHUB_TOKEN",
            snippet='GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"',
        )
        val = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert val == "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        assert "****" not in val

    def test_stripe_key_shows_raw_value(self):
        finding = _make_secret_finding(
            raw="sk_live_51H7aJkLmNoPqRsTuVwXyZ0123456789abcdef",
            rule_id="SEC_STRIPE_KEY_LIVE",
            snippet='STRIPE_KEY = "sk_live_51H7aJkLmNoPqRsTuVwXyZ0123456789abcdef"',
        )
        val = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert val == "sk_live_51H7aJkLmNoPqRsTuVwXyZ0123456789abcdef"
        assert "****" not in val

    def test_high_entropy_shows_raw_value(self):
        finding = _make_secret_finding(
            raw="aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z",
            rule_id="SEC_HIGH_ENTROPY",
            snippet="High-Entropy String",
            tags=["secret", "entropy"],
        )
        val = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert val == "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z"
        assert "****" not in val

    def test_masked_mode_always_masks(self):
        finding = _make_secret_finding(
            raw="admin123",
            rule_id="SEC_PASSWORD_ASSIGNMENT",
            snippet='password = "admin123"',
        )
        val = get_secret_display_value(finding, SecretDisplayMode.MASKED)
        assert "****" in val or val == "***"
        assert "admin123" not in val

    def test_variable_reference_not_shown_in_full_mode(self):
        """Variable references like input() must NEVER show full value."""
        finding = Finding(
            rule_id="SEC_PASSWORD_ASSIGNMENT",
            title="Hardcoded Password",
            description="Found hardcoded password.",
            severity=Severity.CRITICAL,
            confidence=0.85,
            category=FindingCategory.SECRET,
            language=Language.PYTHON,
            location=CodeLocation(
                file_path="app.py",
                line=10,
                code_snippet='password = input("Enter password:")',
            ),
            tags=["secret", "password_assignment"],
            raw_secret="input",
        )
        val = get_secret_display_value(finding, SecretDisplayMode.FULL)
        assert "input" in val
        assert "****" not in val

    def test_scanner_preserves_raw_secret_for_password(self):
        scanner = SecretsScanner(mask_secrets=True)
        content = 'password = "P@ssw0rd2024!"'
        findings = scanner.scan_file(content, "test.py", Language.PYTHON)
        assert len(findings) > 0
        f = findings[0]
        assert f.raw_secret == "P@ssw0rd2024!"
        assert "password" in f.location.code_snippet

        display_val = get_secret_display_value(f, SecretDisplayMode.FULL)
        assert display_val == 'password = "P@ssw0rd2024!"'

    def test_scanner_preserves_raw_secret_for_long_password(self):
        scanner = SecretsScanner(mask_secrets=True)
        content = 'DB_PASSWORD = "Root@123456!"'
        findings = scanner.scan_file(content, "test.py", Language.PYTHON)
        assert len(findings) > 0
        f = findings[0]
        assert f.raw_secret == "Root@123456!"
        assert "DB_PASSWORD" in f.location.code_snippet

        display_val = get_secret_display_value(f, SecretDisplayMode.FULL)
        assert display_val == 'DB_PASSWORD = "Root@123456!"'

    def test_scanner_preserves_raw_secret_for_db_password(self):
        scanner = SecretsScanner(mask_secrets=True)
        content = 'DB_PASSWORD = "Root@123!"'
        findings = scanner.scan_file(content, "test.py", Language.PYTHON)
        assert len(findings) > 0
        f = findings[0]
        assert f.raw_secret == "Root@123!"

        display_val = get_secret_display_value(f, SecretDisplayMode.FULL)
        assert display_val == 'DB_PASSWORD = "Root@123!"'

    def test_scanner_preserves_raw_secret_for_aws_key(self):
        scanner = SecretsScanner(mask_secrets=True)
        content = 'AWS_SECRET = "wJalrXUtnFEMIK7MDENG/bPxRfiCYzK9xQ2"'
        findings = scanner.scan_file(content, "test.py", Language.PYTHON)
        assert len(findings) > 0
        f = findings[0]
        assert "wJalrXUtnFEMI" in f.raw_secret

        display_val = get_secret_display_value(f, SecretDisplayMode.FULL)
        assert "wJalrXUtnFEMI" in display_val
        assert "****" not in display_val

    def test_apply_full_mode_sets_full_snippet(self):
        finding = _make_secret_finding(
            raw="admin123",
            rule_id="SEC_PASSWORD_ASSIGNMENT",
            snippet='password = "admin123"',
        )
        apply_secret_display_mode([finding], SecretDisplayMode.FULL)
        assert finding.location.code_snippet == 'password = "admin123"'

    def test_masked_mode_masks_value_in_line(self):
        finding = _make_secret_finding(
            raw="admin123",
            rule_id="SEC_PASSWORD_ASSIGNMENT",
            snippet='password = "admin123"',
        )
        apply_secret_display_mode([finding], SecretDisplayMode.MASKED)
        assert "admin123" not in finding.location.code_snippet
        assert "password" in finding.location.code_snippet

    def test_apply_full_mode_for_db_password(self):
        finding = _make_secret_finding(
            raw="Root@123",
            rule_id="SEC_PASSWORD_ASSIGNMENT",
            snippet='DB_PASSWORD = "Root@123"',
        )
        apply_secret_display_mode([finding], SecretDisplayMode.FULL)
        assert finding.location.code_snippet == 'DB_PASSWORD = "Root@123"'

    def test_apply_full_mode_for_api_key(self):
        finding = _make_secret_finding(
            raw="sk-1234567890abcdef1234567890abcdef",
            rule_id="SEC_GENERIC_API_KEY",
            snippet='API_KEY = "sk-1234567890abcdef1234567890abcdef"',
        )
        apply_secret_display_mode([finding], SecretDisplayMode.FULL)
        assert finding.location.code_snippet == "sk-1234567890abcdef1234567890abcdef"

    def test_apply_full_mode_for_private_key(self):
        finding = _make_secret_finding(
            raw="-----BEGIN RSA PRIVATE KEY-----",
            rule_id="SEC_PRIVATE_KEY_HEADER",
            snippet="-----BEGIN RSA PRIVATE KEY-----",
        )
        apply_secret_display_mode([finding], SecretDisplayMode.FULL)
        assert finding.location.code_snippet == "-----BEGIN RSA PRIVATE KEY-----"

    def test_masked_mode_applies_masking(self):
        finding = _make_secret_finding(
            raw="admin123",
            rule_id="SEC_PASSWORD_ASSIGNMENT",
            snippet='password = "admin123"',
        )
        apply_secret_display_mode([finding], SecretDisplayMode.MASKED)
        assert "****" in finding.location.code_snippet
        assert "admin123" not in finding.location.code_snippet
