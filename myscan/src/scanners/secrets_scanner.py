"""Secrets detection scanner with literal-assignment validation and precise classification."""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from ..core.models import CodeLocation, Finding, FindingCategory, Language, Severity
from ..core.secret_signals import score_secret, secret_rule_kind
from ..core.validation_engine import is_weak_credential_value
from ..scanners import BaseScanner

_DB_SCHEMES = r"(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|sqlserver|mssql|oracle|cassandra|clickhouse|sqlite)"

SECRET_PATTERNS: list[tuple[str, str, str, Severity, float, str, str]] = [
    ("aws_access_key", r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}", "AWS Access Key ID", Severity.CRITICAL, 0.95, "CWE-798", "Use IAM roles or environment variables."),
    ("aws_secret_key", r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40,}", "AWS Secret Access Key", Severity.CRITICAL, 0.95, "CWE-798", "Use IAM roles or environment variables."),
    ("github_token", r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", Severity.CRITICAL, 0.95, "CWE-798", "Use GitHub Actions secrets."),
    ("github_oauth", r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", Severity.CRITICAL, 0.95, "CWE-798", "Use GitHub Actions secrets."),
    ("github_app_token", r"(?:ghu|ghs)_[A-Za-z0-9]{36}", "GitHub App Token", Severity.CRITICAL, 0.9, "CWE-798", "Use GitHub App installation tokens."),
    ("slack_token", r"xox[bpoa]-[0-9]{10,13}-[a-zA-Z0-9-]+", "Slack Token", Severity.CRITICAL, 0.95, "CWE-798", "Use Slack app tokens with minimal scopes."),
    ("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "Slack Webhook URL", Severity.HIGH, 0.9, "CWE-798", "Store webhook URLs in environment variables."),
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35,}", "Google API Key", Severity.HIGH, 0.9, "CWE-798", "Restrict API keys by IP and API."),
    ("stripe_key_live", r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", Severity.CRITICAL, 0.95, "CWE-798", "Use Stripe environment variables."),
    ("stripe_key_test", r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Secret Key", Severity.MEDIUM, 0.7, "CWE-798", "Store test keys in environment variables."),
    ("heroku_api_key", r"(?i)heroku[_\s]*(?:api[_\s]*key)\s*[=:]\s*['\"]?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "Heroku API Key", Severity.CRITICAL, 0.9, "CWE-798", "Use Heroku config vars."),
    ("private_key_header", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key", Severity.CRITICAL, 0.95, "CWE-321", "Never commit private keys. Use a secrets manager."),
    ("generic_api_key", r"(?i)(?:api[_-]?key|apikey|api_secret|api[_-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,}", "Potential API Key", Severity.HIGH, 0.7, "CWE-798", "Move to environment variables."),
    ("password_assignment", r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?[^'\"\s]{8,}", "Hardcoded Password", Severity.CRITICAL, 0.85, "CWE-798", "Use a secrets manager."),
    ("database_url", rf"(?i)(?:db[_-]?url|database[_-]?url|mysql[_-]?url|postgres(?:ql)?[_-]?url|mongo(?:db)?[_-]?url|sqlserver[_-]?url|oracle[_-]?url)\s*[=:]\s*['\"]?{_DB_SCHEMES}://", "Database Connection String", Severity.HIGH, 0.8, "CWE-798", "Use environment variables for connection strings."),
    ("jwt_token", r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+", "JWT Token", Severity.HIGH, 0.8, "CWE-798", "Rotate tokens regularly. Never commit tokens."),
    ("npm_token", r"npm_[A-Za-z0-9]{36}", "NPM Access Token", Severity.CRITICAL, 0.9, "CWE-798", "Use .npmrc with environment variables."),
    ("sendgrid_key", r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "SendGrid API Key", Severity.CRITICAL, 0.95, "CWE-798", "Use environment variables."),
    ("twilio_key", r"SK[a-f0-9]{32}", "Twilio API Key", Severity.HIGH, 0.9, "CWE-798", "Use environment variables."),
    ("telegram_token", r"\d{8,10}:[A-Za-z0-9_-]{35}", "Telegram Bot Token", Severity.HIGH, 0.85, "CWE-798", "Use environment variables."),
    ("github_fine_grained", r"github_pat_[A-Za-z0-9_]{22,}", "GitHub Fine-Grained Token", Severity.CRITICAL, 0.95, "CWE-798", "Use GitHub Actions secrets or short-lived tokens."),
    ("gitlab_token", r"glpat-[A-Za-z0-9_\-]{20,}", "GitLab Personal Access Token", Severity.CRITICAL, 0.9, "CWE-798", "Use GitLab CI/CD variables."),
    ("openai_key", r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}", "OpenAI API Key", Severity.HIGH, 0.85, "CWE-798", "Use a secrets manager and rotate keys."),
    ("anthropic_key", r"sk-ant-[A-Za-z0-9_\-]{30,}", "Anthropic API Key", Severity.HIGH, 0.9, "CWE-798", "Use environment variables for API keys."),
    ("huggingface_token", r"hf_[A-Za-z0-9]{34}", "Hugging Face Token", Severity.HIGH, 0.9, "CWE-798", "Use environment variables."),
    ("pypi_token", r"pypi-[A-Za-z0-9_\-]{30,}", "PyPI Token", Severity.HIGH, 0.85, "CWE-798", "Use trusted publishing or environment variables."),
    ("stripe_restricted_key", r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key", Severity.CRITICAL, 0.95, "CWE-798", "Use Stripe environment variables."),
    ("azure_account_key", r"(?i)accountkey\s*[=:]\s*['\"]?[A-Za-z0-9+/=]{40,}", "Azure Storage Account Key", Severity.HIGH, 0.85, "CWE-798", "Use managed identities and short-lived SAS tokens."),
    ("github_url_creds", r"https?://[^/\s:@]+:[^@\s/]+@(?:github\.com|gist\.github\.com|raw\.githubusercontent\.com)", "GitHub Remote URL with Credentials", Severity.CRITICAL, 0.9, "CWE-798", "Never embed credentials in git clone URLs."),
    ("google_oauth_client_secret", r"GOCSPX-[A-Za-z0-9_-]{28}", "Google OAuth Client Secret", Severity.HIGH, 0.9, "CWE-798", "Use Google Cloud Secret Manager and environment variables."),
    ("digitalocean_token", r"dop_v1_[a-f0-9]{64}", "DigitalOcean Personal Access Token", Severity.HIGH, 0.9, "CWE-798", "Use environment variables."),
    ("cloud_db_url_creds", rf"{_DB_SCHEMES}://[^\s:'\"]+:[^\s@'\"]+@", "Database Credentials in URL", Severity.HIGH, 0.85, "CWE-798", "Never embed credentials in connection URLs."),
]

NOT_LITERAL_PATTERNS = [
    re.compile(r'(?i)\binput\s*\('),
    re.compile(r'(?i)\bos\.getenv\s*\('),
    re.compile(r'(?i)\bos\.environ\b'),
    re.compile(r'(?i)\benv\.get\s*\('),
    re.compile(r'(?i)\bst\.text_input\s*\('),
    re.compile(r'(?i)\bst\.number_input\s*\('),
    re.compile(r'(?i)\brequest\.form\s*\['),
    re.compile(r'(?i)\brequest\.args\s*\['),
    re.compile(r'(?i)\brequest\.json\b'),
    re.compile(r'(?i)\bsys\.argv\b'),
    re.compile(r'(?i)\bconfig\.\w+'),
    re.compile(r'(?i)\bsettings\.\w+'),
    re.compile(r'(?i)\bself\.\w+'),
    re.compile(r'(?i)\bkwargs\s*\['),
    re.compile(r'(?i)\bargs\s*\['),
    re.compile(r'(?i)\.get\s*\('),
    re.compile(r'(?i)\bgetattr\s*\('),
    re.compile(r'(?i)\bcollections\.\w+'),
    re.compile(r'(?i)\bdict\s*\('),
    re.compile(r'(?i)\bload_dotenv\s*\('),
    re.compile(r'(?i)\bdotenv\s*\('),
    re.compile(r'(?i)\bdecouple\s*\('),
    re.compile(r'(?i)\bclick\.prompt\s*\('),
    re.compile(r'(?i)\bclick\.option\s*\('),
    re.compile(r'(?i)\bargparse\b'),
    re.compile(r'(?i)\benviron\.get\s*\('),
]

PLACEHOLDER_PATTERNS = [
    re.compile(r'(?i)^(?:your[_-]?)?(?:password|secret|key|token|api[_-]?key)[_-]?(?:here|goes|placeholder|example|xxxx|xxxxx|changeme|default|todo|fixme)$'),
    re.compile(r'(?i)^(?:xxx+|changeme|password|secret|placeholder|example|sample|test|dummy|mock|fake|123456|admin|root)$'),
    re.compile(r'(?i)^(?:replace[_-]?(?:with|this|your)|insert[_-]?(?:your|this)|enter[_-]?(?:your|this))'),
    re.compile(r'(?i)^<.*>$'),
    re.compile(r'^\*{8,}$'),
    re.compile(r'^-{8,}$'),
    re.compile(r'^(?:TODO|FIXME|HACK|XXX|CHANGEME)'),
]

COMMENT_LINE_PATTERNS = [
    re.compile(r'^\s*(?:#|//|/\*|\*|;|--)\s*'),
    re.compile(r'^\s*(?:>>>|In\s*\[\d+\]:)'),
]

LDAP_FLAGS = {"ldap", "ldaps", "simple", "none", "external", "digest-md5", "gssapi"}

CONFIG_DEFAULT_PATTERNS = [
    re.compile(r'(?i)^(?:default|example|sample|demo|test|dev|local)[-_]?'),
    re.compile(r'(?i)[-_]?(?:default|example|sample|demo|test|dev|local)$'),
]


def _is_literal_value(value: str) -> bool:
    """Check if a value is a literal credential (string in quotes, numeric, etc)."""
    stripped = value.strip()
    if not stripped:
        return False
    if (stripped.startswith('"') and stripped.endswith('"')) or \
       (stripped.startswith("'") and stripped.endswith("'")):
        inner = stripped[1:-1]
        return len(inner) >= 1
    if stripped.startswith(('b"', "b'")):
        return True
    return bool(re.match(r'^-?\d+(\.\d+)?$', stripped))


def _is_non_literal_rhs(rhs: str) -> bool:
    """Check if the RHS of an assignment is a non-literal (function call, variable ref, etc)."""
    stripped = rhs.strip()
    if not stripped:
        return True
    if _is_literal_value(stripped):
        return False
    for pattern in NOT_LITERAL_PATTERNS:
        if pattern.search(stripped):
            return True
    return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_.]*$', stripped))


def _extract_variable_name(line: str) -> str:
    """Extract the variable / dict-key name from an assignment snippet.

    Handles `NAME = ...`, `obj.name = ...`, `"name": ...`, `NAME=...`.
    """
    match = re.match(r'\s*[\w.\'"\[\]]+\s*[=:]', line)
    if not match:
        return ""
    name = match.group(0).strip().rstrip("=:").strip()
    name = name.strip("'\"[]")
    return name.rsplit(".", 1)[-1].rsplit("[", 1)[-1].strip()


def _classify_password_secret(variable_name: str, value: str) -> str:
    """Sub-classify password-type secrets based on variable name and value context."""
    lower_name = variable_name.lower()
    value.lower().strip("'\"")
    if any(x in lower_name for x in ["db", "database", "mysql", "postgres", "redis", "mongo"]):
        return "Database Password"
    if any(x in lower_name for x in ["api_key", "apikey", "api_secret"]):
        return "API Key"
    if any(x in lower_name for x in ["jwt", "token", "secret_key", "signing"]):
        return "JWT Secret"
    if any(x in lower_name for x in ["aws", "amazon", "s3", "iam"]):
        return "AWS Secret"
    if any(x in lower_name for x in ["azure", "ms_", "microsoft"]):
        return "Azure Secret"
    if any(x in lower_name for x in ["google", "gcp", "firebase"]):
        return "Google Secret"
    if any(x in lower_name for x in ["github", "gh_"]):
        return "GitHub Token"
    if any(x in lower_name for x in ["gitlab", "gl_"]):
        return "GitLab Token"
    if any(x in lower_name for x in ["stripe", "sk_"]):
        return "Stripe Key"
    if any(x in lower_name for x in ["twilio", "tw_"]):
        return "Twilio Key"
    if any(x in lower_name for x in ["slack"]):
        return "Slack Token"
    if any(x in lower_name for x in ["discord"]):
        return "Discord Token"
    if "webhook" in lower_name:
        return "Webhook Secret"
    if any(x in lower_name for x in ["openai", "oa_"]):
        return "OpenAI Key"
    if any(x in lower_name for x in ["anthropic", "ant_"]):
        return "Anthropic Key"
    if "firebase" in lower_name:
        return "Firebase Key"
    if "bearer" in lower_name:
        return "Bearer Token"
    if "oauth" in lower_name:
        return "OAuth Secret"
    if any(x in lower_name for x in ["ssh", "rsa", "private"]):
        return "SSH Key"
    return "Hardcoded Password"


SECRET_CLASSIFICATIONS: dict[str, tuple[str, str, str]] = {
    "aws_access_key": ("AWS Access Key", "cloud_credential", "AWS"),
    "aws_secret_key": ("AWS Secret Access Key", "cloud_credential", "AWS"),
    "github_token": ("GitHub Personal Access Token", "api_token", "GitHub"),
    "github_oauth": ("GitHub OAuth Token", "api_token", "GitHub"),
    "github_app_token": ("GitHub App Token", "api_token", "GitHub"),
    "slack_token": ("Slack Token", "api_token", "Slack"),
    "slack_webhook": ("Slack Webhook URL", "webhook", "Slack"),
    "google_api_key": ("Google API Key", "api_key", "Google"),
    "stripe_key_live": ("Stripe Live Secret Key", "payment_key", "Stripe"),
    "stripe_key_test": ("Stripe Test Secret Key", "payment_key", "Stripe"),
    "heroku_api_key": ("Heroku API Key", "cloud_credential", "Heroku"),
    "private_key_header": ("Private Key", "cryptographic_key", "Generic"),
    "generic_api_key": ("API Key", "api_key", "Generic"),
    "database_url": ("Database Connection String", "connection_string", "Database"),
    "jwt_token": ("JWT Token", "authentication_token", "Generic"),
    "npm_token": ("NPM Access Token", "api_token", "NPM"),
    "sendgrid_key": ("SendGrid API Key", "api_key", "SendGrid"),
    "twilio_key": ("Twilio API Key", "api_key", "Twilio"),
    "telegram_token": ("Telegram Bot Token", "api_token", "Telegram"),
    "github_fine_grained": ("GitHub Fine-Grained Token", "api_token", "GitHub"),
    "gitlab_token": ("GitLab Personal Access Token", "api_token", "GitLab"),
    "openai_key": ("OpenAI API Key", "api_key", "OpenAI"),
    "anthropic_key": ("Anthropic API Key", "api_key", "Anthropic"),
    "huggingface_token": ("Hugging Face Token", "api_token", "Hugging Face"),
    "pypi_token": ("PyPI Token", "api_token", "PyPI"),
    "stripe_restricted_key": ("Stripe Restricted Key", "payment_key", "Stripe"),
    "azure_account_key": ("Azure Storage Account Key", "cloud_credential", "Azure"),
    "github_url_creds": ("GitHub Remote URL with Credentials", "connection_string", "GitHub"),
    "google_oauth_client_secret": ("Google OAuth Client Secret", "api_key", "Google"),
    "digitalocean_token": ("DigitalOcean Personal Access Token", "cloud_credential", "DigitalOcean"),
    "cloud_db_url_creds": ("Database Credentials in URL", "connection_string", "Database"),
    "high_entropy": ("High-Entropy String", "potential_secret", "Generic"),
}


class SecretsScanner(BaseScanner):
    name = "secrets"
    description = "Secrets and credential detection scanner"

    def __init__(self, mask_secrets: bool = True):
        self.mask_secrets = mask_secrets

    def scan_file(self, content: str, file_path: str, language: Language) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        ctx = self._file_context(file_path)

        for secret_type, pattern, _title, severity, confidence, cwe, fix in SECRET_PATTERNS:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith(("#", "//", "*")) and secret_type != "private_key_header":
                    continue
                match = regex.search(line)
                if not match:
                    continue
                raw = match.group()
                if secret_type == "private_key_header" and not self._has_complete_pem_block(lines, i - 1):
                    continue
                if secret_type == "password_assignment":
                    if not self._validate_password_line(line, raw):
                        continue
                    raw = self._extract_password_value(line)
                    snippet = line.strip()
                else:
                    raw = self._extract_matched_value(raw)
                    snippet = line.strip()
                classification = self._classify_finding(secret_type, line)

                # Multi-signal gate: only report secrets with corroborating
                # signals (assignment context, variable-name hint, entropy,
                # mixed charset, or an unambiguous secret format).
                variable_name = _extract_variable_name(line)
                rule_kind = secret_rule_kind(secret_type)
                # Example/fixture context: generic & entropy-only candidates are
                # almost always scaffolding, not live credentials.
                if ctx == "low" and rule_kind in ("generic_key", "password", "high_entropy"):
                    continue
                validation_checks: list[str] = []
                if rule_kind:
                    signal_score = score_secret(rule_kind, raw, variable_name, is_literal=True)
                    if not signal_score.reported:
                        continue
                    adjusted_confidence = signal_score.confidence
                    validation_checks = list(signal_score.checks)
                else:
                    adjusted_confidence = self._adjust_confidence(confidence, line)
                if ctx == "high":
                    adjusted_confidence = min(adjusted_confidence + 0.05, 0.95)

                findings.append(Finding(
                    rule_id=f"SEC_{secret_type.upper()}",
                    title=classification,
                    description=f"Found {classification.lower()} in source code.",
                    severity=severity,
                    confidence=adjusted_confidence,
                    category=FindingCategory.SECRET,
                    language=language,
                    location=CodeLocation(
                        file_path=file_path,
                        line=i,
                        code_snippet=snippet,
                    ),
                    cwe=cwe,
                    fix_suggestion=fix,
                    tags=["secret", secret_type],
                    raw_secret=raw,
                    matched_pattern=pattern,
                    validation_checks=validation_checks,
                ))

        # A single credential must produce exactly one finding per (line, value):
        # keep the highest-confidence rule attribution and drop weaker
        # duplicates (e.g. a generic "Potential API Key" next to a specific
        # vendor finding) so the critical section only shows one real finding.
        seen: dict[tuple[int, str], Finding] = {}
        for finding in findings:
            key = (finding.location.line, finding.raw_secret)
            prev = seen.get(key)
            if prev is None or finding.confidence > prev.confidence:
                seen[key] = finding
        findings = list(seen.values())

        findings.extend(
            self._check_high_entropy_strings(
                lines,
                file_path,
                language,
                reported_raws={f.raw_secret for f in findings},
                ctx=ctx,
            )
        )
        return findings

    def _file_context(self, file_path: str) -> str:
        """Categorize a file path by how likely it is to hold live credentials.

        Returns "high" (config/.env/secret files), "low" (examples, fixtures,
        tests, docs), or "neutral". Config files give a small confidence boost
        because secrets there are real; example/fixture paths suppress generic
        and entropy-only candidates which are usually scaffolding.
        """
        lower = file_path.lower()
        if any(x in lower for x in (
            "/test", "/tests", "/spec", "/fixtures", "/fixture", "/testdata",
            "/examples", "/example", "/demos", "/demo", "/docs", "/doc/",
            "/.github/", "/.circleci/", "/.travis/", "/samples", "/sample",
            "/playground", "/sandbox", "testdata/", "test-data/",
        )):
            return "low"
        name = Path(file_path).name.lower()
        if (
            name == ".env"
            or name.startswith(".env.")
            or ".env" in name
            or name in (
                "config.py", "settings.py", "configuration.py", "config.js",
                "settings.json", "config.json", "application.json",
                "wp-config.php", "database.yml", "database.yaml",
                "application.yml", "application.yaml", "application.properties",
                "secrets.yml", "secrets.yaml", "credentials.json",
                "docker-compose.yml", "docker-compose.yaml", ".npmrc",
                ".netrc", ".pypirc", "terraform.tfvars",
            )
            or lower.endswith((".ini", ".cfg", ".conf", ".properties", ".tfvars"))
        ):
            return "high"
        return "neutral"

    def _has_complete_pem_block(self, lines: list[str], begin_idx: int) -> bool:
        """A PEM private key header only counts when the block is complete:
        a BEGIN header, at least one base64 body line, and an END marker.
        A bare `-----BEGIN ... PRIVATE KEY-----` line is partial, not a key."""
        end_re = re.compile(r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
        body_re = re.compile(r"^[A-Za-z0-9+/=]{16,}$")
        window = lines[begin_idx:begin_idx + 200]
        has_body = False
        for line in window[1:]:
            if end_re.search(line):
                return has_body
            if body_re.match(line.strip()):
                has_body = True
        return False

    def _validate_password_line(self, line: str, match_value: str) -> bool:
        """Validate that a password assignment is a literal credential, not a variable/function."""
        eq_pos = line.lower().find("password")
        if eq_pos < 0:
            eq_pos = line.lower().find("passwd")
        if eq_pos < 0:
            eq_pos = line.lower().find("pwd")
        if eq_pos < 0:
            return True
        after_eq = line[eq_pos:]
        eq_match = re.search(r'[=:]\s*', after_eq)
        if not eq_match:
            return True
        rhs = after_eq[eq_match.end():]
        return not _is_non_literal_rhs(rhs)

    def _classify_finding(self, secret_type: str, line: str) -> str:
        """Classify the secret into a precise type."""
        if secret_type == "password_assignment":
            var_match = re.match(r'(?i)\s*(\w+)\s*[=:]', line)
            variable_name = var_match.group(1) if var_match else ""
            value_match = re.search(r'[=:]\s*[\'"]?([^\s\'"]+)', line)
            value = value_match.group(1) if value_match else ""
            return _classify_password_secret(variable_name, value)
        classification = SECRET_CLASSIFICATIONS.get(secret_type)
        if classification:
            return classification[0]
        return "Hardcoded Secret"

    def _adjust_confidence(self, base: float, line: str) -> float:
        lower = line.lower()
        stripped = line.strip()

        for pattern in PLACEHOLDER_PATTERNS:
            val_match = re.search(r'[=:]\s*[\'"]?([^\'"\s]+)', stripped)
            if val_match and pattern.match(val_match.group(1)):
                return base * 0.15

        for pattern in CONFIG_DEFAULT_PATTERNS:
            var_match = re.match(r'(?i)\s*(\w+)\s*[=:]', stripped)
            if var_match and pattern.match(var_match.group(1)):
                return base * 0.2

        val_match = re.search(r'[=:]\s*[\'"]([^\'"]+)[\'"]', stripped)
        if val_match:
            val = val_match.group(1)
            var_match = re.match(r'(?i)\s*(\w+)\s*[=:]', stripped)
            if var_match and var_match.group(1).lower() == val.lower():
                return base * 0.05
            if is_weak_credential_value(val):
                return base * 0.05
            if val.lower() in LDAP_FLAGS:
                return base * 0.1
            if val.lower() in ("true", "false", "1", "0", "yes", "no", "none", "null", "empty", "undefined"):
                return base * 0.1
            if len(val) <= 2:
                return base * 0.1

        if any(x in lower for x in ["example", "sample", "test", "mock", "dummy", "placeholder", "xxx"]):
            return base * 0.3
        if "TODO" in line or "FIXME" in line or "HACK" in line:
            return base * 0.5

        return base

    def _extract_matched_value(self, raw: str) -> str:
        """Extract just the credential value when the regex match includes
        a leading `key = ...` prefix (e.g. generic_api_key patterns)."""
        m = re.search(r'[=:]\s*[\'"]?([^\'"\s]+)', raw)
        return m.group(1) if m else raw

    def _extract_password_value(self, line: str) -> str:
        """Extract the actual password value from the assignment line."""
        eq_match = re.search(r'[=:]\s*', line)
        if not eq_match:
            return line.strip()
        rhs = line[eq_match.end():].strip()
        if (rhs.startswith('"') and rhs.endswith('"')) or (rhs.startswith("'") and rhs.endswith("'")):
            return rhs[1:-1]
        if rhs.startswith("(") and rhs.endswith(")"):
            inner = rhs[1:-1].strip()
            if (inner.startswith('"') and inner.endswith('"')) or (inner.startswith("'") and inner.endswith("'")):
                return inner[1:-1]
        return rhs.split()[0] if rhs.split() else rhs

    def _mask_secret(self, secret: str) -> str:
        if len(secret) > 8:
            return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
        return "***"

    def _check_high_entropy_strings(
        self,
        lines: list[str],
        file_path: str,
        lang: Language,
        reported_raws: set[str] | None = None,
        ctx: str = "neutral",
    ) -> list[Finding]:
        reported_raws = reported_raws or set()
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//")):
                continue
            for pattern in COMMENT_LINE_PATTERNS:
                if pattern.match(stripped):
                    break
            else:
                matches = re.findall(r'["\']([A-Za-z0-9+/=\-_]{32,80})["\']', line)
                for match in matches:
                    if "://" in match or "\\" in match:
                        continue
                    if re.search(r"@[a-z0-9.-]+\.[a-z]{2,}", match, re.IGNORECASE):
                        continue
                    if ctx == "low":
                        continue
                    if match in reported_raws:
                        continue
                    if is_weak_credential_value(match):
                        continue
                    entropy = self._entropy(match)
                    if (
                        entropy > 4.5
                        and not match.isupper()
                        and not match.islower()
                        and not match.isdigit()
                        and any(c in match for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                        and any(c in match for c in "0123456789")
                        and match != match[::-1]
                    ):
                        # Multi-signal gate: high entropy alone is not enough.
                        # The value must be assigned to a secret-hinting name or
                        # match a known secret format.
                        variable_name = _extract_variable_name(line)
                        signal_score = score_secret(
                            "high_entropy", match, variable_name, is_literal=True
                        )
                        if not signal_score.reported:
                            continue
                        findings.append(Finding(
                            rule_id="SEC_HIGH_ENTROPY",
                            title="High-Entropy String",
                            description=f"String has entropy {entropy:.1f}/8.0, may be a secret.",
                            severity=Severity.MEDIUM,
                            confidence=signal_score.confidence,
                            category=FindingCategory.SECRET,
                            language=lang,
                            location=CodeLocation(file_path=file_path, line=i, code_snippet=line.strip()),
                            cwe="CWE-798",
                            fix_suggestion="Verify if this is a secret. If so, move to environment variables.",
                            tags=["secret", "entropy"],
                            raw_secret=match,
                            matched_pattern=r"['\"][A-Za-z0-9+/=\-_]{32,80}['\"] (entropy > 4.5)",
                            validation_checks=list(signal_score.checks),
                        ))
                        break
        return findings

    def _entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
