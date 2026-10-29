"""Secret display mode configuration and masking logic.

Controls how detected secrets are displayed in reports:
- FULL: Show complete detected values without masking
- MASKED: Mask all secrets (e.g., admin********)
- SMART: Show weak passwords and default credentials in full, mask production secrets
"""

from __future__ import annotations

import re

from .models import Finding, FindingCategory, SecretDisplayMode

WEAK_PASSWORDS: set[str] = {
    "admin", "password", "123456", "admin123", "qwerty", "letmein",
    "welcome", "monkey", "dragon", "master", "abc123", "password1",
    "passw0rd", "root", "toor", "changeme", "default", "secret",
    "test", "guest", "info", "mysql", "oracle", "postgres",
    "pass", "12345678", "123456789", "12345", "1234", "123",
    "1234567890", "1234567", "12345678910", "12345678901",
    "qwerty123", "iloveyou", "sunshine", "princess", "football",
    "shadow", "trustno1", "batman", "access", "hello", "charlie",
    "donald", "login", "login123", "pass123", "p@ssword", "p@ssw0rd",
}

DEFAULT_CREDENTIALS: set[str] = {
    "admin:admin", "admin:password", "admin:123456", "admin:admin123",
    "root:root", "root:toor", "root:password", "root:123456",
    "user:user", "user:password", "test:test", "test:test123",
    "guest:guest", "demo:demo", "demo:password",
}

PRODUCTION_SECRET_PATTERNS: set[str] = {
    "aws_access_key", "aws_secret_key", "github_token", "github_oauth",
    "github_app_token", "slack_token", "slack_webhook", "google_api_key",
    "stripe_key_live", "heroku_api_key", "private_key_header",
    "generic_api_key", "database_url", "jwt_token", "npm_token",
    "sendgrid_key", "twilio_key", "telegram_token", "high_entropy",
}

DEFAULT_CREDENTIAL_PATTERNS: set[str] = {
    "password_assignment",
}

WEAK_PASSWORD_PATTERNS: set[str] = {
    "password_assignment",
}


def mask_secret(value: str, visible_prefix: int = 4, visible_suffix: int = 4,
                mask_char: str = "*") -> str:
    """Mask a secret value, showing only prefix and suffix.

    Args:
        value: The raw secret value to mask.
        visible_prefix: Number of characters to show at start.
        visible_suffix: Number of characters to show at end.
        mask_char: Character to use for masking.

    Returns:
        Masked string, e.g., "ghp_xxxx************xxxx".
    """
    if not value:
        return "***"
    length = len(value)
    if length <= visible_prefix + visible_suffix:
        min_visible = max(1, length // 3)
        return value[:min_visible] + mask_char * (length - min_visible * 2) + value[-min_visible:]
    return value[:visible_prefix] + mask_char * (length - visible_prefix - visible_suffix) + value[-visible_suffix:]


def is_weak_password(secret: str, line: str = "") -> bool:
    """Check if a secret is a weak/common password.

    In SMART mode, weak passwords are shown in full.
    """
    cleaned = secret.strip().strip("'\"").lower()
    if cleaned in WEAK_PASSWORDS:
        return True
    if line:
        lower = line.lower()
        if any(x in lower for x in ["example", "sample", "test", "mock", "dummy", "placeholder"]):
            return True
    return False


def is_default_credential(secret: str, line: str = "") -> bool:
    """Check if a secret is a default credential.

    In SMART mode, default credentials are shown in full.
    """
    cleaned = secret.strip().strip("'\"").lower()
    if cleaned in DEFAULT_CREDENTIALS:
        return True
    for cred in DEFAULT_CREDENTIALS:
        if ":" in cred:
            username, password = cred.split(":", 1)
            if cleaned in (username, password):
                return True
    if line:
        lower = line.lower()
        if "password" in lower and ("admin" in cleaned or "root" in cleaned or "default" in cleaned or "test" in cleaned):
            return True
    return False


def is_production_secret(rule_id: str, tags: list[str]) -> bool:
    """Check if a finding is a production secret that should be masked."""
    tag_set = set(tags)
    if tag_set & PRODUCTION_SECRET_PATTERNS:
        return True
    return "entropy" in tag_set


def get_secret_display_value(finding: Finding, mode: SecretDisplayMode = SecretDisplayMode.SMART) -> str:
    """Get the appropriate display value for a secret finding based on display mode.

    In FULL mode, password assignments show the complete line (variable = actual_value).
    Other secret types show just the raw value (title provides context).
    """
    if finding.category != FindingCategory.SECRET:
        return finding.location.code_snippet

    raw = finding.raw_secret or finding.location.code_snippet
    if not raw:
        return finding.location.code_snippet

    if mode == SecretDisplayMode.FULL:
        is_password_type = (
            finding.rule_id in ("SEC_PASSWORD_ASSIGNMENT", "SEC_passwd", "SEC_pwd")
            or any(t in ("password", "passwd", "pwd") for t in finding.tags)
            or "password" in finding.rule_id.lower()
            or "passwd" in finding.rule_id.lower()
        )
        if is_password_type:
            snippet = finding.location.code_snippet or ""
            var_match = re.match(r'(?i)\s*(\w+)\s*[=:]', snippet)
            if var_match:
                var_name = var_match.group(1)
                if snippet.strip().endswith(")"):
                    return snippet
                return f'{var_name} = "{raw}"'
        return raw

    if mode == SecretDisplayMode.MASKED:
        is_password_type = (
            finding.rule_id in ("SEC_PASSWORD_ASSIGNMENT", "SEC_passwd", "SEC_pwd")
            or any(t in ("password", "passwd", "pwd") for t in finding.tags)
            or "password" in finding.rule_id.lower()
            or "passwd" in finding.rule_id.lower()
        )
        if is_password_type:
            snippet = finding.location.code_snippet or ""
            var_match = re.match(r'(?i)\s*(\w+)\s*[=:]', snippet)
            if var_match:
                var_name = var_match.group(1)
                if snippet.strip().endswith(")"):
                    return snippet
                return f'{var_name} = {mask_secret(raw)}'
        return mask_secret(raw)

    if mode == SecretDisplayMode.SMART:
        if is_weak_password(raw):
            return raw

        if is_default_credential(raw):
            return raw

        if is_production_secret(finding.rule_id, finding.tags):
            return mask_secret(raw)

        return mask_secret(raw)

    return mask_secret(raw)


def apply_secret_display_mode(findings: list[Finding],
                              mode: SecretDisplayMode = SecretDisplayMode.SMART) -> list[Finding]:
    """Apply secret display mode to a list of findings, modifying code_snippet in place.

    Args:
        findings: List of Finding objects.
        mode: The display mode to apply.

    Returns:
        The same list with code_snippet updated for SECRET findings.
    """
    for finding in findings:
        if finding.category == FindingCategory.SECRET and finding.raw_secret:
            finding.location.code_snippet = get_secret_display_value(finding, mode)
    return findings


def get_secret_display_warning(mode: SecretDisplayMode) -> str | None:
    """Get a warning message if full secret display is enabled."""
    if mode == SecretDisplayMode.FULL:
        return (
            "Full secret display is enabled. "
            "Reports may expose sensitive credentials. "
            "Use only when developer explicitly enables FULL mode."
        )
    return None


class SecretDisplayConfig:
    """Configuration for secret display behavior."""

    def __init__(self, mode: SecretDisplayMode = SecretDisplayMode.SMART):
        self.mode = mode

    @classmethod
    def from_string(cls, value: str) -> SecretDisplayConfig:
        """Create config from string value."""
        try:
            mode = SecretDisplayMode(value.lower())
        except ValueError:
            mode = SecretDisplayMode.SMART
        return cls(mode=mode)

    @property
    def is_full(self) -> bool:
        return self.mode == SecretDisplayMode.FULL

    @property
    def is_masked(self) -> bool:
        return self.mode == SecretDisplayMode.MASKED

    @property
    def is_smart(self) -> bool:
        return self.mode == SecretDisplayMode.SMART

    def to_dict(self) -> dict:
        return {
            "mode": self.mode.value,
            "warning": get_secret_display_warning(self.mode),
        }
