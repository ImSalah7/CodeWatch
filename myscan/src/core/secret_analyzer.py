"""Secret Analyzer for CodeWatch.

Analyzes detected secrets to determine their type, strength, risk,
and context. Provides actionable recommendations for remediation.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .models import Finding, Severity

COMMON_PASSWORDS: set[str] = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
    "dragon", "login", "princess", "football", "shadow", "sunshine", "trustno1",
    "iloveyou", "batman", "access", "hello", "charlie", "password1", "letmein",
    "welcome", "admin", "passw0rd", "p@ssw0rd", "123456789", "1234567890",
    "iloveu", "password123", "1q2w3e4r", "qwerty123", "pass", "secret",
    "123123", "666666", "7777777", "654321", "111111", "000000", "121212",
    "test", "guest", "master123", "admin123", "root", "changeme", "default",
    "pass123", "pass1234", "changeme123", "welcome123", "temp", "temporary",
    "test123", "test1234", "example", "demo", "sample", "foobar", "foofoo",
    "barbar", "password!", "p@ssword", "p@ss1", "p@ssw0rd!", "abc",
    "abcdef", "abcdefg", "abcdefgh", "abcdefghi", "abcdefghij", "abcdefg123",
    "asdf", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm", "1qaz2wsx",
    "qwertyuiop", "1q2w3e", "1q2w3e4r5t", "a1b2c3", "a1b2c3d4",
    "samsung", "jennifer", "hunter2", "buster", "thomas", "robert",
    "soccer", "hockey", "ranger", "daniel", "andrew", "joshua", "matthew",
    "ashley", "jessica", "michael", "baseball", "mustang", "michelle",
}

TEST_ENV_KEYWORDS: set[str] = {
    "test", "tests", "testing", "spec", "specs", "mock", "mocks",
    "fixture", "fixtures", "stub", "stubs", "fake", "fakes",
    "sample", "samples", "example", "examples", "demo", "demos",
    "dummy", "temp", "tmp", "sandbox", "playground",
}

DEV_ENV_KEYWORDS: set[str] = {
    "dev", "develop", "development", "local", "localhost",
    "debug", "debugging", "wip", "work_in_progress", "experimental",
    "staging", "stage", "stg", "qa", "uat",
    "preproduction", "pre-production", "pre_prod",
}

PROD_ENV_KEYWORDS: set[str] = {
    "prod", "production", "live", "release", "deploy", "deployment",
    "main", "master", "stable", "rc", "release_candidate",
}

USAGE_KEYWORDS: dict[str, list[str]] = {
    "authentication": [
        "auth", "token", "jwt", "bearer", "session", "login", "credential",
        "api_key", "apikey", "access_token", "id_token",
    ],
    "authorization": [
        "oauth", "scope", "permission", "role", "grant", "refresh",
        "authorization",
    ],
    "data_access": [
        "database", "db", "connection", "url", "dsn", "host",
        "connection_string", "conn", "endpoint",
    ],
    "payment": [
        "stripe", "payment", "billing", "charge", "invoice",
        "checkout", "merchant",
    ],
}


@dataclass
class SecretType:
    """Classifies the type of a detected secret."""
    name: str
    category: str
    provider: str
    severity: Severity


@dataclass
class SecretStrength:
    """Quantifies the strength of a detected secret value."""
    entropy: float
    length: int
    has_uppercase: bool
    has_lowercase: bool
    has_digits: bool
    has_special: bool
    character_diversity: int
    dictionary_match: bool
    strength_label: str
    estimated_crack_time: str


@dataclass
class SecretRisk:
    """Assesses the risk associated with a detected secret."""
    risk_level: str
    leak_probability: str
    environment: str
    business_impact: str
    usage_context: str


@dataclass
class SecretAnalysisResult:
    """Complete analysis result for a detected secret."""
    secret_type: SecretType
    strength: SecretStrength
    risk: SecretRisk
    classification: str
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert analysis result to dictionary representation."""
        return {
            "secret_type": {
                "name": self.secret_type.name,
                "category": self.secret_type.category,
                "provider": self.secret_type.provider,
                "severity": self.secret_type.severity.value,
            },
            "strength": {
                "entropy": round(self.strength.entropy, 4),
                "length": self.strength.length,
                "has_uppercase": self.strength.has_uppercase,
                "has_lowercase": self.strength.has_lowercase,
                "has_digits": self.strength.has_digits,
                "has_special": self.strength.has_special,
                "character_diversity": self.strength.character_diversity,
                "dictionary_match": self.strength.dictionary_match,
                "strength_label": self.strength.strength_label,
                "estimated_crack_time": self.strength.estimated_crack_time,
            },
            "risk": {
                "risk_level": self.risk.risk_level,
                "leak_probability": self.risk.leak_probability,
                "environment": self.risk.environment,
                "business_impact": self.risk.business_impact,
                "usage_context": self.risk.usage_context,
            },
            "classification": self.classification,
            "recommendations": self.recommendations,
        }


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
    "password_assignment": ("Hardcoded Password", "password", "Generic"),
    "database_url": ("Database Connection String", "connection_string", "Database"),
    "jwt_token": ("JWT Token", "authentication_token", "Generic"),
    "npm_token": ("NPM Access Token", "api_token", "NPM"),
    "sendgrid_key": ("SendGrid API Key", "api_key", "SendGrid"),
    "twilio_key": ("Twilio API Key", "api_key", "Twilio"),
    "telegram_token": ("Telegram Bot Token", "api_token", "Telegram"),
    "high_entropy": ("High-Entropy String", "potential_secret", "Generic"),
}

RULE_ID_TO_CLASSIFICATION: dict[str, str] = {
    "secret-aws-access-key": "aws_access_key",
    "secret-aws-secret-key": "aws_secret_key",
    "secret-github-token": "github_token",
    "secret-github-oauth": "github_oauth",
    "secret-github-app-token": "github_app_token",
    "secret-slack-token": "slack_token",
    "secret-slack-webhook": "slack_webhook",
    "secret-google-api-key": "google_api_key",
    "secret-stripe-key-live": "stripe_key_live",
    "secret-stripe-key-test": "stripe_key_test",
    "secret-heroku-api-key": "heroku_api_key",
    "secret-private-key": "private_key_header",
    "secret-generic-api-key": "generic_api_key",
    "secret-password": "password_assignment",
    "secret-database-url": "database_url",
    "secret-jwt": "jwt_token",
    "secret-npm-token": "npm_token",
    "secret-sendgrid-key": "sendgrid_key",
    "secret-twilio-key": "twilio_key",
    "secret-telegram-token": "telegram_token",
    "secret-high-entropy": "high_entropy",
}

TAG_TO_CLASSIFICATION: dict[str, str] = {
    "aws": "aws_access_key",
    "github": "github_token",
    "slack": "slack_token",
    "google": "google_api_key",
    "stripe": "stripe_key_live",
    "heroku": "heroku_api_key",
    "jwt": "jwt_token",
    "npm": "npm_token",
    "sendgrid": "sendgrid_key",
    "twilio": "twilio_key",
    "telegram": "telegram_token",
    "private_key": "private_key_header",
    "password": "password_assignment",
    "database": "database_url",
    "api_key": "generic_api_key",
    "connection_string": "database_url",
}

CONTENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("github_app_token", re.compile(r"\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[bporas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}\b")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("stripe_key_live", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,99}\b")),
    ("stripe_key_test", re.compile(r"\bsk_test_[0-9a-zA-Z]{24,99}\b")),
    ("heroku_api_key", re.compile(r"(?i)heroku[_\-]?api[_\-]?key\s*[:=]\s*['\"]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")),
    ("private_key_header", re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----")),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}\b")),
    ("twilio_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("telegram_token", re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("database_url", re.compile(r"(?i)(?:postgres|mysql|mongodb|redis|amqp|mssql)://[^\s'\"]+", re.IGNORECASE)),
]


class SecretAnalyzer:
    """Analyzes detected secrets for type, strength, risk, and context."""

    def analyze(self, finding: Finding) -> SecretAnalysisResult:
        """Perform complete analysis of a detected secret."""
        secret_type = self._classify_secret(finding)
        value = finding.raw_secret if finding.raw_secret else finding.title
        strength = self._analyze_strength(value)
        risk = self._assess_risk(finding, strength, secret_type)
        classification = self._build_classification_label(secret_type)
        recommendations = self._generate_recommendations(secret_type, strength, risk)
        return SecretAnalysisResult(
            secret_type=secret_type,
            strength=strength,
            risk=risk,
            classification=classification,
            recommendations=recommendations,
        )

    def _classify_secret(self, finding: Finding) -> SecretType:
        """Determine the precise type of the secret based on rules, tags, and content."""
        classification_key: str | None = None

        if finding.rule_id in RULE_ID_TO_CLASSIFICATION:
            classification_key = RULE_ID_TO_CLASSIFICATION[finding.rule_id]

        if classification_key is None:
            for tag in finding.tags:
                tag_lower = tag.lower().replace("-", "_").replace(" ", "_")
                if tag_lower in TAG_TO_CLASSIFICATION:
                    classification_key = TAG_TO_CLASSIFICATION[tag_lower]
                    break

        if classification_key is None:
            content = finding.raw_secret or finding.title
            for pattern_key, pattern in CONTENT_PATTERNS:
                if pattern.search(content):
                    classification_key = pattern_key
                    break

        if classification_key is None:
            title_lower = finding.title.lower()
            if "password" in title_lower or "passwd" in title_lower:
                classification_key = "password_assignment"
            elif "api key" in title_lower or "apikey" in title_lower or "token" in title_lower or "secret" in title_lower or "key" in title_lower:
                classification_key = "generic_api_key"
            elif "database" in title_lower or "connection" in title_lower:
                classification_key = "database_url"
            elif "entropy" in title_lower or "string" in title_lower:
                classification_key = "high_entropy"
            else:
                classification_key = "high_entropy"

        if classification_key not in SECRET_CLASSIFICATIONS:
            classification_key = "high_entropy"

        name, category, provider = SECRET_CLASSIFICATIONS[classification_key]
        return SecretType(
            name=name,
            category=category,
            provider=provider,
            severity=finding.severity,
        )

    def _analyze_strength(self, value: str) -> SecretStrength:
        """Analyze the cryptographic and structural strength of a secret value."""
        if not value:
            return SecretStrength(
                entropy=0.0,
                length=0,
                has_uppercase=False,
                has_lowercase=False,
                has_digits=False,
                has_special=False,
                character_diversity=0,
                dictionary_match=True,
                strength_label="very_weak",
                estimated_crack_time="instant",
            )

        entropy = self._calculate_entropy(value)
        length = len(value)
        has_uppercase = any(c.isupper() for c in value)
        has_lowercase = any(c.islower() for c in value)
        has_digits = any(c.isdigit() for c in value)
        has_special = any(not c.isalnum() for c in value)
        character_diversity = len(set(value))
        dictionary_match = self._check_dictionary(value)

        strength_label = self._determine_strength_label(entropy, length)
        estimated_crack_time = self._estimate_crack_time(entropy, length)

        if dictionary_match and strength_label not in ("very_weak", "weak"):
            strength_label = "weak"
            estimated_crack_time = "minutes"

        return SecretStrength(
            entropy=entropy,
            length=length,
            has_uppercase=has_uppercase,
            has_lowercase=has_lowercase,
            has_digits=has_digits,
            has_special=has_special,
            character_diversity=character_diversity,
            dictionary_match=dictionary_match,
            strength_label=strength_label,
            estimated_crack_time=estimated_crack_time,
        )

    def _assess_risk(
        self,
        finding: Finding,
        strength: SecretStrength,
        secret_type: SecretType,
    ) -> SecretRisk:
        """Assess the risk level and impact of a detected secret."""
        environment = self._determine_environment(finding)
        usage_context = self._determine_usage_context(finding)

        risk_level = "medium"
        leak_probability = "possible"
        business_impact = "Potential unauthorized access if credential is exploited."

        category = secret_type.category

        if category == "cloud_credential":
            risk_level = "critical"
            leak_probability = "very_likely"
            business_impact = (
                "Cloud credentials can provide direct access to production infrastructure, "
                "data stores, and services. Full account compromise is possible."
            )
        elif category == "api_token":
            risk_level = "critical"
            leak_probability = "very_likely"
            business_impact = (
                "API tokens can grant programmatic access to services, enabling data exfiltration, "
                "privilege escalation, or unauthorized operations."
            )
        elif category == "payment_key":
            risk_level = "critical"
            leak_probability = "very_likely"
            business_impact = (
                "Payment keys can be used to initiate unauthorized transactions, "
                "access customer payment data, or cause financial loss."
            )
        elif category == "authentication_token":
            risk_level = "high"
            leak_probability = "likely"
            business_impact = (
                "Authentication tokens can allow impersonation of users or services, "
                "bypassing access controls."
            )
        elif category == "password":
            if strength.strength_label in ("very_weak", "weak"):
                risk_level = "high"
                leak_probability = "likely"
                business_impact = (
                    "Weak hardcoded passwords are easily guessable and provide "
                    "trivial unauthorized access."
                )
            elif strength.strength_label == "fair":
                risk_level = "medium"
                leak_probability = "possible"
                business_impact = (
                    "Moderate-strength hardcoded password may resist brute force "
                    "but exposes credentials in source code."
                )
            else:
                risk_level = "medium"
                leak_probability = "unlikely"
                business_impact = (
                    "Strong password found in source code. While resistant to brute force, "
                    "the credential is still exposed to anyone with repository access."
                )
        elif category == "connection_string":
            risk_level = "high"
            leak_probability = "likely"
            business_impact = (
                "Database connection strings can provide direct access to data stores, "
                "enabling data theft, modification, or destruction."
            )
        elif category == "cryptographic_key":
            risk_level = "high"
            leak_probability = "likely"
            business_impact = (
                "Exposed private keys can be used for authentication bypass, "
                "data decryption, or code signing."
            )
        elif category == "webhook":
            risk_level = "medium"
            leak_probability = "possible"
            business_impact = (
                "Webhook URLs can be used to send unauthorized messages or "
                "trigger unintended integrations."
            )
        elif category == "potential_secret":
            risk_level = "medium"
            leak_probability = "possible"
            business_impact = (
                "High-entropy string detected. This may be a secret or may be "
                "a benign value like a hash or identifier."
            )
        elif category == "api_key":
            risk_level = "high"
            leak_probability = "likely"
            business_impact = (
                "API keys can provide unauthorized access to services and data."
            )

        if environment in ("development", "testing"):
            if risk_level == "critical":
                risk_level = "high"
            elif risk_level == "high":
                risk_level = "medium"
            business_impact += (
                f" Found in {environment} environment which reduces but does not eliminate risk."
            )

        return SecretRisk(
            risk_level=risk_level,
            leak_probability=leak_probability,
            environment=environment,
            business_impact=business_impact,
            usage_context=usage_context,
        )

    def _generate_recommendations(
        self,
        secret_type: SecretType,
        strength: SecretStrength,
        risk: SecretRisk,
    ) -> list[str]:
        """Generate actionable recommendations based on the analysis."""
        recommendations: list[str] = []

        always_recommend = "Rotate the exposed credential immediately to prevent unauthorized access."
        recommendations.append(always_recommend)

        category = secret_type.category
        provider = secret_type.provider

        if provider == "AWS":
            recommendations.append(
                "Use IAM roles or environment variables instead of hardcoded AWS credentials."
            )
            recommendations.append(
                "Implement AWS Secrets Manager or SSM Parameter Store for credential management."
            )
            recommendations.append(
                "Enable AWS CloudTrail to monitor for unauthorized API calls using this credential."
            )
        elif provider == "GitHub":
            recommendations.append(
                "Use GitHub Actions secrets or Dependabot secrets for CI/CD credentials."
            )
            recommendations.append(
                "Configure repository-level secret scanning push protection to prevent future leaks."
            )
            recommendations.append(
                "Review GitHub audit log for unauthorized access using this token."
            )
        elif provider == "Slack":
            recommendations.append(
                "Regenerate the Slack token via the Slack API dashboard."
            )
            recommendations.append(
                "Store Slack tokens in environment variables or a secrets manager."
            )
            recommendations.append(
                "Review Slack app permissions and revoke unnecessary scopes."
            )
        elif provider == "Google":
            recommendations.append(
                "Regenerate the Google API key in the Google Cloud Console."
            )
            recommendations.append(
                "Restrict the API key to specific APIs and IP ranges."
            )
            recommendations.append(
                "Use service account credentials with minimal permissions instead."
            )
        elif provider == "Stripe":
            recommendations.append(
                "Immediately rotate the Stripe API key via the Stripe Dashboard."
            )
            recommendations.append(
                "Use Stripe test keys (sk_test_*) for development and staging environments."
            )
            recommendations.append(
                "Implement Stripe webhook signing to verify event authenticity."
            )
        elif provider == "Heroku":
            recommendations.append(
                "Rotate the Heroku API key via the Heroku Dashboard."
            )
            recommendations.append(
                "Use Heroku Config Vars for environment-specific configuration."
            )
        elif provider == "NPM":
            recommendations.append(
                "Revoke the NPM token via npmjs.com profile settings."
            )
            recommendations.append(
                "Use environment variables for NPM authentication in CI/CD pipelines."
            )
        elif provider == "SendGrid":
            recommendations.append(
                "Revoke the SendGrid API key and generate a new one."
            )
            recommendations.append(
                "Use environment variables for SendGrid API keys."
            )
        elif provider == "Twilio":
            recommendations.append(
                "Revoke the Twilio API key in the Twilio Console."
            )
            recommendations.append(
                "Store Twilio credentials in environment variables."
            )
        elif provider == "Telegram":
            recommendations.append(
                "Revoke the Telegram bot token via BotFather."
            )
            recommendations.append(
                "Store bot tokens in environment variables or a secrets manager."
            )

        if category == "password":
            recommendations.append(
                "Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) "
                "for all passwords and credentials."
            )
            recommendations.append(
                "Never hardcode passwords in source code, configuration files, or scripts."
            )
            if strength.strength_label in ("very_weak", "weak"):
                recommendations.append(
                    "The password strength is weak. Enforce password complexity requirements "
                    "and consider using randomly generated passwords."
                )
        elif category == "connection_string":
            recommendations.append(
                "Store database connection strings in environment variables, "
                "never in source code or configuration files."
            )
            recommendations.append(
                "Use connection pooling and least-privilege database accounts "
                "to limit exposure."
            )
            recommendations.append(
                "Enable TLS/SSL for all database connections and restrict network access."
            )
        elif category == "cryptographic_key":
            recommendations.append(
                "Immediately revoke and replace the exposed private key."
            )
            recommendations.append(
                "Use a Hardware Security Module (HSM) or cloud KMS for key management."
            )
            recommendations.append(
                "Implement key rotation policies and audit key usage."
            )
        elif category == "webhook":
            recommendations.append(
                "Regenerate the webhook URL and update all consumers."
            )
            recommendations.append(
                "Implement webhook signature verification to prevent replay attacks."
            )
        elif category == "authentication_token":
            recommendations.append(
                "Implement token expiration and automatic renewal mechanisms."
            )
            recommendations.append(
                "Use short-lived tokens with minimal required scopes."
            )

        if strength.dictionary_match:
            recommendations.append(
                "The value matches a common password. Use cryptographically random values "
                "for all secrets and credentials."
            )

        if risk.environment == "unknown":
            recommendations.append(
                "Determine the environment this credential belongs to and ensure "
                "environment-specific secrets are properly segregated."
            )

        recommendations.append(
            "Add pre-commit hooks or CI/CD secret scanning to prevent future secret exposure."
        )

        return recommendations

    def _check_dictionary(self, value: str) -> bool:
        """Check if the value matches a common password or dictionary word."""
        normalized = value.lower().strip()
        if normalized in COMMON_PASSWORDS:
            return True
        if normalized.rstrip("0123456789") in COMMON_PASSWORDS and len(normalized) <= 20:
            return True
        base = re.sub(r"[^a-zA-Z]", "", normalized)
        return bool(base in COMMON_PASSWORDS and len(base) <= 16)

    def _estimate_crack_time(self, entropy: float, length: int) -> str:
        """Estimate the time required to crack the secret."""
        if entropy < 2.0:
            return "instant"
        elif entropy < 3.0:
            return "minutes"
        elif entropy < 4.0:
            return "hours"
        elif entropy < 5.0:
            return "years"
        else:
            return "centuries"

    def _determine_strength_label(self, entropy: float, length: int) -> str:
        """Determine the strength label based on entropy and length."""
        if entropy < 2.0:
            label = "very_weak"
        elif entropy < 3.0:
            label = "weak"
        elif entropy < 4.0:
            label = "fair"
        elif entropy < 5.0:
            label = "strong"
        else:
            label = "very_strong"

        if length < 8:
            downgrade_map = {
                "very_strong": "strong",
                "strong": "fair",
                "fair": "weak",
                "weak": "very_weak",
                "very_weak": "very_weak",
            }
            label = downgrade_map[label]
        elif length > 16:
            boost_map = {
                "very_weak": "weak",
                "weak": "fair",
                "fair": "strong",
                "strong": "very_strong",
                "very_strong": "very_strong",
            }
            label = boost_map[label]

        return label

    def _calculate_entropy(self, value: str) -> float:
        """Calculate Shannon entropy of a string value."""
        if not value:
            return 0.0

        length = len(value)
        freq = Counter(value)
        entropy = 0.0

        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _determine_environment(self, finding: Finding) -> str:
        """Determine the environment based on file path and context clues."""
        file_path = finding.location.file_path.lower()
        code_snippet = finding.location.code_snippet.lower() if finding.location.code_snippet else ""
        combined = file_path + " " + code_snippet

        for keyword in PROD_ENV_KEYWORDS:
            if keyword in combined:
                return "production"

        for keyword in TEST_ENV_KEYWORDS:
            if keyword in combined:
                return "testing"

        for keyword in DEV_ENV_KEYWORDS:
            if keyword in combined:
                return "development"

        path_parts = file_path.replace("\\", "/").split("/")
        if any(
            part.startswith(".") and part not in (".", "..") for part in path_parts if part
        ) and any(kw in combined for kw in ("test", "spec", "mock", "example")):
            return "testing"

        return "unknown"

    def _determine_usage_context(self, finding: Finding) -> str:
        """Determine the usage context based on variable names and code context."""
        name_candidates = [
            finding.title.lower(),
            finding.location.function.lower() if finding.location.function else "",
            finding.location.class_name.lower() if finding.location.class_name else "",
            finding.location.code_snippet.lower() if finding.location.code_snippet else "",
        ]
        combined = " ".join(candidate for candidate in name_candidates if candidate)

        variable_pattern = re.compile(
            r"(?:variable|var|name|key|identifier|param)\s*[:=]\s*['\"]?(\w+)['\"]?",
            re.IGNORECASE,
        )
        match = variable_pattern.search(finding.location.code_snippet or "")
        if match:
            combined += " " + match.group(1).lower()

        for context_label, keywords in USAGE_KEYWORDS.items():
            for keyword in keywords:
                if keyword in combined:
                    return context_label

        raw = finding.raw_secret.lower() if finding.raw_secret else ""
        if "bearer" in combined or "bearer" in raw:
            return "authentication"
        if "password" in combined or "passwd" in combined:
            return "authentication"
        if "token" in combined:
            return "authentication"
        if "key" in combined:
            return "authorization"
        if re.search(r"(?:postgres|mysql|mongodb|redis)://", combined):
            return "data_access"

        return "unknown"

    def _build_classification_label(self, secret_type: SecretType) -> str:
        """Build a precise classification label for the secret."""
        parts = [secret_type.name]
        if secret_type.provider != "Generic":
            parts.append(f"Provider: {secret_type.provider}")
        parts.append(f"Category: {secret_type.category}")
        parts.append(f"Severity: {secret_type.severity.value}")
        return " | ".join(parts)
