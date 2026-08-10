"""Multi-signal secret detection heuristics.

A value should only be reported as a secret when several independent signals
corroborate that it is a real credential. This module centralizes the lexical
signals used by the secrets scanner and the validation pipeline:

  * literal-keyword / placeholder / demo-marker rejection
  * weak-value rejection (keyboard walks, repeated runs, sequential strings)
  * prose and dictionary-word rejection
  * uniform character-set rejection
  * entropy and length checks
  * variable-name secret hints
  * known secret format prefixes
  * DB URL credential checks

Everything here is a pure function of the candidate value and (optionally) the
variable name it is assigned to, so the heuristics stay testable in isolation.
"""

from __future__ import annotations

import base64
import json
import re
from collections import Counter
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Literal keywords / syntax that must never be reported as a secret.
# ---------------------------------------------------------------------------

LITERAL_KEYWORDS: frozenset[str] = frozenset(
    {
        "", ".", "..", "null", "nil", "none", "nan", "infinity",
        "true", "false", "yes", "no", "on", "off", "undefined", "void",
        "empty", "default", "n/a", "na", "unknown", "self", "cls",
        "length", "size", "count", "existing", "settings", "config",
        "password", "secret", "key", "token", "value",
        # Auth scheme / header names used as placeholder values.
        "bearer", "basic", "digest", "authorization", "authentication",
        "session", "cookie", "csrf", "grant_type", "client_id",
    }
)

# ---------------------------------------------------------------------------
# Placeholders / weak credential values that are not real secrets.
# ---------------------------------------------------------------------------

PLACEHOLDER_KEYWORDS: frozenset[str] = frozenset(
    {
        "changeme", "change_me", "changeit", "replace_me", "replace_this",
        "replace_it", "set_me", "your_key_here", "your_password", "your_secret",
        "your_token", "your_api_key", "your-here", "here", "placeholder",
        "placeholder_key", "dummy", "fake", "xxx", "xxxx", "xxxxx", "todo",
        "fixme", "hack", "example", "sample", "demo", "test", "testing",
        "password123", "admin123", "root123", "test123", "secret123",
        "abc123", "123456", "1234567", "12345678", "123456789", "1234567890",
        "000000", "00000000", "aaaaaa", "bbbbbb", "11111111", "qwerty",
        "qwerty123", "letmein", "welcome", "monkey", "dragon", "master",
        "shadow", "sunshine", "princess", "iloveyou", "trustno1", "admin",
        "root", "toor", "guest", "user", "pass", "password", "p@ssw0rd",
        "passw0rd", "nothing", "hello", "hello123", "password1",
    }
)

# Values that are only a placeholder when quoted literally, e.g. "******".
_PLACEHOLDER_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^[*_\-]{6,}$"),
    re.compile(r"^X{6,}$", re.IGNORECASE),
    re.compile(r"^<.*>$"),
    re.compile(r"^\{.*secret.*\}$", re.IGNORECASE),
    re.compile(r"^(?:TODO|FIXME|HACK|XXX|CHANGEME)"),
    re.compile(r"^\$\{?secrets?\.[\w.]+\}?$", re.IGNORECASE),
    re.compile(r"^#\{\w+\}$"),
    re.compile(r"^env\(['\"]?\w+['\"]?\)$", re.IGNORECASE),
    re.compile(r"^os\.environ(?:\.get)?\(['\"]?\w+['\"]?\)$", re.IGNORECASE),
)

# Substrings that mark a value as a demo/example rather than a live credential.
_DEMO_MARKERS: tuple[str, ...] = (
    "example", "exampl", "sample", "placeholder", "your_", "your-", "your-here",
    "replace_me", "replace-me", "changeme", "change-me", "dummy", "mock",
    "fake", "demo", "test_key", "test-key", "faketoken", "fake_",
)

# Stronger marker set applied to format-validated secrets (e.g. AKIA...EXAMPLE).
# These almost never appear in a live credential, so a match is a hard reject.
_STRONG_PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "example", "exampl", "sample", "placeholder", "your_", "your-", "your-here",
    "changeme", "change-me", "replace_me", "replace-me", "dummy", "faketoken",
)

# ---------------------------------------------------------------------------
# Common words used for prose detection (e.g. `prod_eu_west_1_primary_region`).
# ---------------------------------------------------------------------------

COMMON_WORD_TOKENS: frozenset[str] = frozenset(
    {
        "the", "a", "an", "and", "or", "but", "for", "with", "in", "on",
        "at", "of", "to", "from", "by", "is", "are", "be", "this", "that",
        "these", "those", "my", "your", "our", "their", "his", "her",
        "application", "app", "environment", "env", "variable", "var",
        "value", "val", "setting", "settings", "config", "configuration",
        "database", "db", "migration", "migrations", "rollback", "region",
        "regions", "primary", "secondary", "staging", "production", "prod",
        "development", "dev", "service", "services", "cluster", "instance",
        "instances", "node", "nodes", "worker", "workers", "server",
        "servers", "client", "clients", "default", "sample", "example",
        "demo", "local", "global", "public", "private", "secret", "key",
        "token", "api", "password", "user", "users", "admin", "master",
        "main", "auth", "authentication", "credential", "credentials",
        "account", "access", "control", "security", "secure", "shared",
        "engine", "framework", "library", "package", "module", "function",
        "method", "class", "object", "string", "integer", "float", "boolean",
        "data", "metadata", "information", "message", "messages", "request",
        "requests", "response", "responses", "header", "headers", "body",
        "query", "param", "params", "parameter", "parameters", "arg",
        "args", "kwargs", "option", "options", "flag", "flags", "mode",
        "type", "kind", "name", "names", "id", "version", "release", "build",
        "commit", "branch", "hash", "digest", "checksum", "uuid", "guid",
        "nonce", "salt", "seed", "cache", "memo", "memory", "storage",
        "store", "queue", "topic", "channel", "stream", "bucket", "zone", "domain", "host", "port", "url", "uri", "endpoint", "path",
        "route", "schema", "table", "column", "row", "index", "file",
        "files", "folder", "directory", "root", "tmp", "temp", "log",
        "logs", "debug", "trace", "span", "session", "cookie", "connection",
        "connectionstring", "conn", "databases", "hostname",
        "backend", "frontend", "web", "rest", "grpc", "http", "https",
        "versions", "number", "numbers", "list", "lists", "map",
        "maps", "set", "sets", "array", "arrays", "dict", "dictionary",
        "tertiary", "first", "second", "third",
        "east", "west", "north", "south", "central", "europe", "america",
        "asia", "pacific", "africa", "middle", "virginia", "oregon",
        "frankfurt", "london", "singapore", "tokyo", "sydney", "sao",
        "paulo", "mumbai", "delhi", "new", "york", "san", "francisco",
    }
)

# Common weak secret words, matched with an optional short digit suffix,
# e.g. `hello123`, `qwerty2024`, `welcome1`.
_COMMON_WORD_PLUS_DIGITS = re.compile(r"^([a-z@$!]+?)\d{1,6}$", re.IGNORECASE)


def is_placeholder_value(value: str) -> bool:
    """Check whether a value is a literal placeholder rather than a real secret."""
    v = value.strip()
    if not v:
        return True
    if v.lower() in PLACEHOLDER_KEYWORDS:
        return True
    for pattern in _PLACEHOLDER_VALUE_PATTERNS:
        if pattern.match(v):
            return True
    return v.lower() in LITERAL_KEYWORDS


def has_demo_marker(value: str) -> bool:
    """Check whether a value contains a demo/example marker."""
    lower = value.lower()
    return any(marker in lower for marker in _DEMO_MARKERS)


def has_placeholder_marker(value: str) -> bool:
    """Check whether a value contains a strong placeholder marker
    (applied only to format-validated secrets)."""
    lower = value.lower()
    return any(marker in lower for marker in _STRONG_PLACEHOLDER_MARKERS)


def is_common_word_value(value: str) -> bool:
    """Check whether a value is a common dictionary word or word + digit run."""
    v = value.strip().lower()
    if not v:
        return False
    if v in PLACEHOLDER_KEYWORDS or v in LITERAL_KEYWORDS:
        return True
    m = _COMMON_WORD_PLUS_DIGITS.match(v)
    if not m:
        return False
    return m.group(1) in PLACEHOLDER_KEYWORDS or m.group(1) in LITERAL_KEYWORDS


# ---------------------------------------------------------------------------
# Weak credential values (keyboard walks, repeated runs, sequential strings).
# ---------------------------------------------------------------------------

_KEYBOARD_ROWS: tuple[frozenset[str], ...] = (
    frozenset("qwertyuiop"),
    frozenset("asdfghjkl"),
    frozenset("zxcvbnm"),
)

_SEQUENTIAL_STARTS: tuple[str, ...] = (
    "0123456789", "1234567890", "qwertyuiop", "asdfghjkl",
    "zxcvbnm", "abcdefghijklmnop", "0987654321",
)


def is_weak_credential_value(value: str) -> bool:
    """Detect values that look like keyboard walks, repeated runs, or
    sequential strings rather than real credentials."""
    v = value.strip().lower()
    if not v:
        return True
    if re.search(r"(.)\1{3,}", v):
        return True
    if any(v.startswith(s) for s in _SEQUENTIAL_STARTS):
        return True
    return any(all(c in row for c in v) for row in _KEYBOARD_ROWS)


STRONG_PASSWORD_PATTERNS = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{12,}$"
)

# ---------------------------------------------------------------------------
# Character-set and entropy helpers.
# ---------------------------------------------------------------------------


def charset_classes(value: str) -> set[str]:
    classes: set[str] = set()
    for ch in value:
        if ch.islower():
            classes.add("lower")
        elif ch.isupper():
            classes.add("upper")
        elif ch.isdigit():
            classes.add("digit")
        elif not ch.isspace():
            classes.add("symbol")
    return classes


def has_mixed_alpha(value: str) -> bool:
    """True when the value contains both lowercase and uppercase letters."""
    return any(c.islower() for c in value) and any(c.isupper() for c in value)


def entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    length = len(value)
    return -sum((count / length) * __import__("math").log2(count / length) for count in freq.values())


# ---------------------------------------------------------------------------
# Token / prose detection.
# ---------------------------------------------------------------------------

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def split_tokens(value: str) -> list[str]:
    """Split a value into word-like tokens (snake, kebab, camel, dot cases)."""
    if not value:
        return []
    rough = re.split(r"[-_. /]", value)
    tokens: list[str] = []
    for part in rough:
        tokens.extend(_CAMEL_BOUNDARY.split(part))
    return [t for t in tokens if t]


def _is_wordy_token(token: str) -> bool:
    if not token:
        return False
    if token.isalpha() and len(token) >= 2:
        return token.lower() in COMMON_WORD_TOKENS or len(token) >= 4
    return bool(token.isdigit() and len(token) <= 6)


def looks_like_prose(value: str) -> bool:
    """Check whether a value reads like a multi-word identifier or prose of
    common words (e.g. `the_application_environment_variable`) rather than a
    credential. Real secrets virtually never consist of 3+ lowercase word/digit
    tokens separated only by `-`/`_`."""
    if not re.fullmatch(r"[a-z0-9\-_]+", value):
        return False
    tokens = split_tokens(value)
    if len(tokens) < 3:
        return False
    return all(re.fullmatch(r"[a-z]{2,}|\d{1,4}", t) for t in tokens)


def _is_camel_word_token(token: str) -> bool:
    if not token:
        return False
    if not any(c.isalpha() for c in token):
        return len(token) <= 2
    if len(token) < 3:
        return False
    if any(c in token for c in "!@#$%^&*()_+-=[]{}|;:,.<>?/`~\\"):
        return False
    return sum(1 for c in token if c.isdigit()) <= 2


def looks_like_camel_prose(value: str) -> bool:
    """Detect demo values that read as a concatenation of recognizable words
    (e.g. `SomeLongSecretTokenValueHere`, `ApiKeyForProductionEnv`).

    Real credentials are effectively never 4+ clean word tokens glued together;
    random strings split into short, single-character fragments instead.
    """
    if len(value) < 12 or not re.fullmatch(r"[A-Za-z0-9]+", value):
        return False
    tokens = split_tokens(value)
    return len(tokens) >= 4 and all(_is_camel_word_token(t) for t in tokens)


def has_uniform_charset(value: str) -> bool:
    """True when the value uses a single character class over its body
    (all lowercase alpha, all uppercase alpha, or digits only)."""
    classes = charset_classes(value)
    if len(classes) != 1:
        return False
    (cls,) = classes
    if cls in ("lower", "upper") and len(value) >= 8:
        return True
    if cls == "digit" and len(value) >= 8:
        return True
    return cls == "symbol"


# ---------------------------------------------------------------------------
# Variable-name secret hints.
# ---------------------------------------------------------------------------

_VARNAME_TOKEN_HINTS: frozenset[str] = frozenset(
    {
        "token", "tokens", "secret", "secrets", "key", "keys", "apikey",
        "pass", "passwd", "pwd", "password", "passphrase", "credential",
        "credentials", "auth", "authz", "authorization", "bearer",
        "privatekey", "signing", "webhook", "signature", "access_key",
        "client_secret", "client_key", "consumer_key", "consumer_secret",
        "oauth", "accesskey", "secretkey", "secret_key",
    }
)

_PROVIDER_HINTS: tuple[str, ...] = (
    "aws", "amazon", "s3", "iam", "azure", "gcp", "google", "firebase",
    "github", "gh_", "gitlab", "gl_", "stripe", "twilio", "slack",
    "sendgrid", "heroku", "openai", "anthropic", "huggingface", "telegram",
    "npm", "pypi", "discord", "digitalocean", "cloudflare", "docker",
    "dockerhub", "jfrog", "vault", "okta", "auth0", "mongodb", "mysql",
    "postgres", "postgresql", "redis", "redis_url", "cassandra", "neo4j",
    "elastic", "algolia", "paypal", "shopify", "mailgun", "twilio",
)


def has_secret_varname_hint(variable_name: str) -> bool:
    """Check whether a variable name hints that its value is a secret."""
    if not variable_name:
        return False
    lower = variable_name.lower()
    tokens = split_tokens(lower)

    if any(t in _VARNAME_TOKEN_HINTS for t in tokens):
        return True

    for provider in _PROVIDER_HINTS:
        if provider in lower:
            # Provider name alone is not enough; it must pair with a secret
            # noun, e.g. OPENAI_API_KEY, GITHUB_TOKEN, AWS_SECRET.
            return any(t in _VARNAME_TOKEN_HINTS for t in tokens) or bool(
                re.search(r"(api|key|token|secret|password|auth|credential)", lower)
            )

    return lower.startswith(("sk_", "ghp_", "gho_", "ghs_", "ghu_", "glpat_", "hf_", "npm_", "sk-ant-"))


# Variable names that denote a non-credential artifact: identifiers, hashes,
# runtime/request context, builds, or transport endpoints. A secret-format
# value assigned to one of these (e.g. `trace_id`, `build_id`, `schema_hash`)
# is unrelated to a real credential and must not be reported.
_NON_SECRET_VARNAME_TOKENS: frozenset[str] = frozenset(
    {
        "id", "ids", "uid", "uuid", "guid", "serial", "number", "numbers",
        "index", "idx", "name", "names", "slug", "ref", "reference",
        "hash", "hashes", "sha", "sha1", "sha256", "sha512", "md5", "digest",
        "checksum", "salt", "nonce", "iv", "seed",
        "build", "version", "versions", "release", "tag", "tags", "commit",
        "branch", "revision", "build_id", "trace_id",
        "path", "route", "endpoint", "host", "hostname", "port", "url", "uri",
        "domain", "zone", "region", "bucket", "queue", "topic", "channel",
        "stream", "schema", "table", "column", "row", "cache", "memo", "memory", "storage", "store", "log", "logs", "trace",
        "span", "request", "response", "session", "connection", "header",
        "headers", "query", "params", "args", "body", "payload", "message",
        "messages", "value", "val", "setting", "settings", "option",
        "options", "flag", "flags", "mode", "type", "kind", "status", "state",
        "data", "metadata", "info", "file", "files", "filename", "folder",
        "directory", "timestamp", "time",
    }
)


def has_non_secret_varname_hint(variable_name: str) -> bool:
    """True when a variable name consists entirely of non-secret artifact
    nouns (e.g. `trace_id`, `build_id`, `sha256_checksum`, `session_id`),
    meaning an assigned secret-format value is unrelated context."""
    if not variable_name:
        return False
    tokens = split_tokens(variable_name.lower())
    return bool(tokens) and all(t in _NON_SECRET_VARNAME_TOKENS for t in tokens)


def jwt_algorithm(value: str) -> str | None:
    """Decode the `alg` claim from a JWT header segment, or None on failure."""
    header = value.split(".", 1)[0] if value else ""
    if not header:
        return None
    try:
        padded = header + "=" * (-len(header) % 4)
        data = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(data.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None
    alg = parsed.get("alg")
    return str(alg) if isinstance(alg, str) else None


# ---------------------------------------------------------------------------
# Known secret format prefixes.
# ---------------------------------------------------------------------------

_KNOWN_PREFIXES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^AKIA[0-9A-Z]{16}$"), "AWS Access Key ID"),
    (re.compile(r"^ASIA[0-9A-Z]{16}$"), "AWS Temporary Access Key ID"),
    (re.compile(r"^ghp_[A-Za-z0-9]{36}$"), "GitHub Personal Access Token"),
    (re.compile(r"^gho_[A-Za-z0-9]{36}$"), "GitHub OAuth Token"),
    (re.compile(r"^ghu_[A-Za-z0-9]{36}$"), "GitHub App Token (user)"),
    (re.compile(r"^ghs_[A-Za-z0-9]{36}$"), "GitHub App Token (server)"),
    (re.compile(r"^github_pat_[A-Za-z0-9_]{22,}$"), "GitHub Fine-Grained Token"),
    (re.compile(r"^glpat-[A-Za-z0-9_\-]{20,}$"), "GitLab Personal Access Token"),
    (re.compile(r"^AIza[0-9A-Za-z\-_]{35}$"), "Google API Key"),
    (re.compile(r"^sk_live_[0-9a-zA-Z]{24,}$"), "Stripe Live Secret Key"),
    (re.compile(r"^rk_live_[0-9a-zA-Z]{24,}$"), "Stripe Restricted Key"),
    (re.compile(r"^sk_test_[0-9a-zA-Z]{24,}$"), "Stripe Test Secret Key"),
    (re.compile(r"^sk-ant-[A-Za-z0-9_\-]{30,}$"), "Anthropic API Key"),
    (re.compile(r"^hf_[A-Za-z0-9]{34}$"), "Hugging Face Token"),
    (re.compile(r"^npm_[A-Za-z0-9]{36}$"), "NPM Access Token"),
    (re.compile(r"^pypi-[A-Za-z0-9_\-]{30,}$"), "PyPI Token"),
    (re.compile(r"^SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}$"), "SendGrid API Key"),
    (re.compile(r"^xox[bpoa]-[0-9]{10,13}-[a-zA-Z0-9-]+$"), "Slack Token"),
    (re.compile(r"^\d{8,10}:[A-Za-z0-9_-]{35}$"), "Telegram Bot Token"),
    (re.compile(r"^GOCSPX-[A-Za-z0-9_-]{28}$"), "Google OAuth Client Secret"),
    (re.compile(r"^dop_v1_[a-f0-9]{64}$"), "DigitalOcean Personal Access Token"),
    (re.compile(r"^-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key"),
)


def known_format_label(value: str) -> str | None:
    """Return the label of a known secret format prefix, if the value matches."""
    for pattern, label in _KNOWN_PREFIXES:
        if pattern.match(value.strip()):
            return label
    return None


# ---------------------------------------------------------------------------
# DB URL credential checks.
# ---------------------------------------------------------------------------

_PLACEHOLDER_DB_USERS: frozenset[str] = frozenset(
    {"user", "username", "pass", "password", "your", "your_user", "youruser",
     "example", "exampl", "test", "root", "db", "database", "app", "admin", "administrator"}
)

_PLACEHOLDER_DB_PASSES: frozenset[str] = frozenset(
    {"pass", "password", "secret", "your_password", "yourpassword", "change_me",
     "changeme", "test", "test123", "password1", "1234", "123456", "xxxx", "xxxxx"}
)


def db_url_credential_check(url: str) -> tuple[bool, str | None]:
    """Validate that a DB URL actually embeds credentials.

    Returns (ok, reject_reason).
    """
    userinfo = url.split("//", 1)
    if len(userinfo) < 2 or "@" not in userinfo[1]:
        return False, "connection string has no embedded credentials"
    creds, _host = userinfo[1].split("@", 1)
    if ":" in creds:
        user, secret = creds.split(":", 1)
    else:
        user, secret = creds, ""
    user_l = (user or "").strip().lower()
    secret_l = (secret or "").strip().lower()
    if not user_l:
        return False, "connection string has no username"
    if user_l in _PLACEHOLDER_DB_USERS and secret_l in _PLACEHOLDER_DB_PASSES:
        return False, "connection string credentials look like placeholders"
    if secret_l and secret_l == user_l:
        return False, "connection string username and password are identical"
    if has_demo_marker(url) or "example" in url.lower():
        return False, "connection string is an example"
    return True, None


# ---------------------------------------------------------------------------
# Multi-signal scoring.
# ---------------------------------------------------------------------------


@dataclass
class SecretSignalScore:
    reject_reason: str | None = None
    signals: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def reported(self) -> bool:
        return self.reject_reason is None


_STRONG_FORMAT_HINTS: tuple[str, ...] = (
    "aws_access", "aws_secret", "github_token", "github_oauth", "github_app",
    "github_url", "slack_token", "slack_webhook", "google_api", "google_oauth",
    "stripe", "heroku", "digitalocean",
    "npm_token", "sendgrid", "telegram", "fine_grained", "gitlab",
    "anthropic", "huggingface", "pypi", "azure_account", "azure_key",
    "deploy_key", "bearer", "basic_auth", "hard_coded_secret", "jwt_secret",
)


def secret_rule_kind(identifier: str) -> str | None:
    """Map a scanner secret type or rule id to a multi-signal rule kind."""
    key = (identifier or "").lower().replace("-", "_")
    if "jwt" in key:
        return "jwt"
    if "openai" in key or "twilio" in key:
        return "ambiguous_format"
    if "generic_api_key" in key:
        return "generic_key"
    if "password" in key or "passwd" in key:
        return "password"
    if "database_url" in key or "db_url" in key or "cloud_db" in key:
        return "db_url"
    if "high_entropy" in key:
        return "high_entropy"
    if "private_key" in key or "private_key_header" in key:
        return "private_key"
    if any(hint in key for hint in _STRONG_FORMAT_HINTS):
        return "strong_format"
    return None


def _signal(checks: list[str], name: str, description: str) -> None:
    checks.append(name)
    return None


def score_secret(
    rule_kind: str,
    value: str,
    variable_name: str = "",
    *,
    is_literal: bool = True,
) -> SecretSignalScore:
    """Score a secret candidate across independent detection signals.

    ``rule_kind`` selects which signals are mandatory:
      * ``strong_format``    - trusted provider prefix (AKIA, ghp_, AIza, ...)
      * ``jwt`` / ``private_key`` - structurally unambiguous formats
      * ``ambiguous_format`` - generic prefixes such as OpenAI/Twilio keys
      * ``generic_key``      - generic API key assignments
      * ``password``         - hardcoded password assignments
      * ``db_url``           - database connection strings/URLs
      * ``high_entropy``     - high-entropy string candidates
    """
    v = value.strip()
    if not v:
        return SecretSignalScore(reject_reason="empty value")

    score = SecretSignalScore()
    checks: list[str] = []
    signals: list[str] = []

    if not is_literal:
        return SecretSignalScore(reject_reason="value is not a literal")

    # --- Rejections that apply to every secret type. ---------------------
    if is_placeholder_value(v):
        return SecretSignalScore(reject_reason="value is a known placeholder")
    # Structural formats (PEM headers contain `-----`, JWTs are base64url) can
    # legitimately contain repeated runs, so skip the weak-value check there.
    if rule_kind not in ("private_key", "jwt") and is_weak_credential_value(v):
        return SecretSignalScore(
            reject_reason="value is a keyboard walk, repeated run, or sequential string"
        )

    # Format-validated secrets (AKIA..., ghp_...) are structurally unambiguous,
    # so only strong placeholder markers reject them. Everything else must not
    # use a single character class (e.g. all-lowercase prose, digits only).
    if rule_kind in ("strong_format", "jwt", "private_key"):
        if has_placeholder_marker(v):
            return SecretSignalScore(reject_reason="value contains a demo/example marker")
    else:
        if has_demo_marker(v):
            return SecretSignalScore(reject_reason="value contains a demo/example marker")
        if has_uniform_charset(v):
            return SecretSignalScore(
                reject_reason="value uses a single character class (not a real credential)"
            )
        if looks_like_prose(v):
            return SecretSignalScore(
                reject_reason="value reads like a prose/identifier of common words, not a credential"
            )
        if looks_like_camel_prose(v):
            return SecretSignalScore(
                reject_reason="value is a concatenation of words, not a real credential"
            )

    if rule_kind in ("generic_key", "password", "high_entropy") and is_common_word_value(v):
        return SecretSignalScore(reject_reason="value is a common word, not a credential")

    # A vendor-format value assigned to a clearly non-secret identifier
    # (e.g. `trace_id = "SG...."`, `build_id = "AIza..."`) is unrelated context.
    if rule_kind in ("strong_format", "ambiguous_format") and has_non_secret_varname_hint(variable_name):
        return SecretSignalScore(
            reject_reason="value is assigned to a non-secret identifier (unrelated)"
        )

    # --- Signal gathering. ------------------------------------------------
    ent = entropy(v)
    has_varname = bool(variable_name) and has_secret_varname_hint(variable_name)
    mixed_alpha = has_mixed_alpha(v)
    long_enough = len(v) >= 16
    high_entropy_signal = ent >= 3.2

    if rule_kind in ("strong_format", "jwt", "private_key"):
        if rule_kind == "private_key":
            _signal(checks, "format", "Matched a private key/certificate header")
            score.confidence = 0.92
        elif rule_kind == "jwt":
            if (jwt_algorithm(v) or "").lower() == "none":
                return SecretSignalScore(
                    reject_reason="unsigned JWT (alg=none) is not a real credential"
                )
            _signal(checks, "format", "Matched a three-segment JWT structure")
            score.confidence = 0.85
        else:
            label = known_format_label(v)
            _signal(checks, "format", f"Matched a known secret format{f' ({label})' if label else ''}")
            score.confidence = 0.80
        if has_varname:
            _signal(checks, "varname", f"Variable name hints a secret ({variable_name})")
            score.confidence += 0.10
        if mixed_alpha:
            _signal(checks, "charset", "Value mixes upper and lower case")
            score.confidence += 0.05
        if long_enough:
            _signal(checks, "length", "Value is long enough to be a real credential")
            score.confidence += 0.05
        score.confidence = min(score.confidence, 0.95)

    elif rule_kind == "ambiguous_format":
        # Twilio API keys are `SK` + 32 hex chars, so the uppercase prefix makes
        # mixed-case a trivially-true signal; they must be corroborated by the
        # variable name. OpenAI-style `sk-...` keys mix case by design, so a
        # mixed-case value or a secret-hinting name both count as signals.
        if re.fullmatch(r"SK[0-9a-f]{32}", v):
            if not has_varname:
                return SecretSignalScore(
                    reject_reason="SK+hex value requires a secret-hinting variable name (Twilio)"
                )
        elif not has_varname and not mixed_alpha:
            return SecretSignalScore(
                reject_reason="ambiguous prefix requires a secret-hinting variable name or mixed-case value"
            )
        _signal(checks, "format", "Matched a vendor-prefixed secret format")
        score.confidence = 0.72
        if has_varname:
            _signal(checks, "varname", f"Variable name hints a secret ({variable_name})")
            score.confidence += 0.08
        if mixed_alpha:
            _signal(checks, "charset", "Value mixes upper and lower case")
            score.confidence += 0.08
        if high_entropy_signal:
            _signal(checks, "entropy", f"High entropy ({ent:.2f})")
            score.confidence += 0.05
        score.confidence = min(score.confidence, 0.90)

    elif rule_kind == "generic_key":
        if not has_varname:
            return SecretSignalScore(
                reject_reason="generic API key requires a secret-hinting variable name"
            )
        if not high_entropy_signal and not mixed_alpha:
            return SecretSignalScore(
                reject_reason="generic API key value lacks entropy and mixed character set"
            )
        _signal(checks, "varname", f"Variable name hints a secret ({variable_name})")
        score.confidence = 0.55
        if mixed_alpha:
            _signal(checks, "charset", "Value mixes character classes")
            score.confidence += 0.10
        if high_entropy_signal:
            _signal(checks, "entropy", f"High entropy ({ent:.2f})")
            score.confidence += 0.15
        if long_enough:
            _signal(checks, "length", "Value is long enough to be a real credential")
            score.confidence += 0.05
        score.confidence = min(score.confidence, 0.90)

    elif rule_kind == "password":
        if not has_varname:
            return SecretSignalScore(
                reject_reason="password assignment requires a secret-hinting variable name"
            )
        if not mixed_alpha and not (long_enough and high_entropy_signal):
            return SecretSignalScore(
                reject_reason="password value lacks mixed case or sufficient entropy"
            )
        _signal(checks, "varname", f"Variable name hints a secret ({variable_name})")
        score.confidence = 0.60
        if mixed_alpha:
            _signal(checks, "charset", "Password mixes upper and lower case")
            score.confidence += 0.10
        if high_entropy_signal:
            _signal(checks, "entropy", f"High entropy ({ent:.2f})")
            score.confidence += 0.10
        if long_enough:
            _signal(checks, "length", "Password is long enough to be plausible")
            score.confidence += 0.05
        score.confidence = min(score.confidence, 0.90)

    elif rule_kind == "db_url":
        ok, reason = db_url_credential_check(v)
        if not ok:
            return SecretSignalScore(reject_reason=reason or "invalid connection string")
        _signal(checks, "format", "URL embeds user credentials")
        score.confidence = 0.78
        if has_varname:
            _signal(checks, "varname", f"Variable name hints a secret ({variable_name})")
            score.confidence += 0.10
        if high_entropy_signal:
            _signal(checks, "entropy", f"High entropy ({ent:.2f})")
            score.confidence += 0.05
        score.confidence = min(score.confidence, 0.90)

    elif rule_kind == "high_entropy":
        if not has_varname and not known_format_label(v):
            return SecretSignalScore(
                reject_reason="high-entropy string lacks a secret-hinting variable name or known format"
            )
        _signal(checks, "entropy", f"High entropy ({ent:.2f})")
        score.confidence = 0.55
        if has_varname:
            _signal(checks, "varname", f"Variable name hints a secret ({variable_name})")
            score.confidence += 0.15
        if long_enough:
            _signal(checks, "length", "Value is long enough to be a real credential")
            score.confidence += 0.05
        score.confidence = min(score.confidence, 0.80)

    else:  # unknown rule kind - stay conservative
        score.confidence = min(0.50 + 0.10 * int(has_varname), 0.70)

    score.checks = checks
    score.signals = signals
    return score
