"""User accounts, API keys, and session tokens for the MyScan API.

Design:
    - Passwords are hashed with scrypt (stdlib only, no new dependencies).
    - API keys are generated once, shown to the caller, and stored as a SHA-256
      hash so a leaked database does not expose usable keys.
    - Session tokens are HMAC-SHA256 signed payloads (stateless; no server-side
      session table). They carry the username, role, and an expiry timestamp.
    - ``MYSCAN_API_KEY`` (the legacy shared key) still acts as a master key that
      grants the ``admin`` role, so existing deployments keep working.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

ROLES = ("admin", "operator", "viewer")

ROLE_LEVEL = {"viewer": 1, "operator": 2, "admin": 3}

# scrypt parameters (memory ~16 MiB per hash)
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1

SESSION_TTL_SECONDS = int(os.environ.get("MYSCAN_SESSION_TTL", "86400"))


# --------------------------------------------------------------------------
# Password hashing (scrypt)
# --------------------------------------------------------------------------

def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text)


def hash_password(password: str) -> str:
    """Hash a password with scrypt. Format: scrypt$n$r$p$salt$hash."""
    salt = os.urandom(16)
    dk = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time password verification against a stored scrypt hash."""
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = _b64d(salt_b64)
        expected = _b64d(hash_b64)
        dk = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------
# API keys (raw key shown once; only a hash is stored)
# --------------------------------------------------------------------------

def generate_api_key() -> str:
    """Generate a fresh API key. The raw value is returned exactly once."""
    return "ms_" + secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    """Hash an API key for storage/lookup."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Session tokens (stateless, HMAC-signed)
# --------------------------------------------------------------------------

def _session_secret() -> bytes:
    """HMAC secret for session tokens.

    Prefer ``MYSCAN_SESSION_SECRET``. If unset, derive a stable secret from
    ``MYSCAN_API_KEY`` so single-key deployments authenticate seamlessly; a
    purely local dev server falls back to a fixed (non-secret) key.
    """
    env = os.environ.get("MYSCAN_SESSION_SECRET", "").strip()
    if env:
        return env.encode("utf-8")
    master = os.environ.get("MYSCAN_API_KEY", "").strip()
    if master:
        return hashlib.sha256(f"myscan-session:{master}".encode()).digest()
    return b"myscan-dev-session-secret"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def issue_session_token(username: str, role: str, ttl: int = SESSION_TTL_SECONDS) -> str:
    """Return a signed session token valid for ``ttl`` seconds."""
    payload = {"sub": username, "role": role, "exp": int(time.time()) + int(ttl)}
    body = _b64url(json.dumps(payload).encode("utf-8"))
    sig = hmac.new(_session_secret(), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url(sig)}"


def verify_session_token(token: str) -> dict | None:
    """Validate a session token; returns {username, role} or None."""
    try:
        body, sig_b64 = token.rsplit(".", 1)
        sig = _b64url_decode(sig_b64)
        expected = hmac.new(_session_secret(), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64url_decode(body))
        if int(payload.get("exp", 0)) < time.time():
            return None
        return {"username": str(payload["sub"]), "role": str(payload["role"])}
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def valid_role(role: str) -> bool:
    return role in ROLES


def role_at_least(role: str, minimum: str) -> bool:
    """True when ``role`` grants at least ``minimum`` (admin >= operator >= viewer)."""
    return ROLE_LEVEL.get(role, 0) >= ROLE_LEVEL.get(minimum, 99)
