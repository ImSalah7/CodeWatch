"""Production security layer for the MyScan REST API.

Provides:
    - API key authentication (Bearer token, Basic auth, X-API-Key header, or ?token=)
    - Per-client rate limiting (sliding window)
    - CORS allowlist with preflight handling
    - SSRF guard for remote scan targets (blocks private/loopback/link-local hosts)
    - Optional local-path allowlist for scan targets

All settings are read from environment variables so no secrets live in code.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import ipaddress
import os
import socket
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from urllib.parse import urlparse

from flask import jsonify, request

# --------------------------------------------------------------------------
# Configuration (all from environment, with safe defaults)
# --------------------------------------------------------------------------

API_KEY = os.environ.get("MYSCAN_API_KEY", "").strip()
RATE_LIMIT_PER_MINUTE = int(os.environ.get("MYSCAN_RATE_LIMIT", "300"))
RATE_LIMIT_BURST = int(os.environ.get("MYSCAN_RATE_LIMIT_BURST", "60"))
CORS_ORIGINS = [
    o.strip() for o in os.environ.get("MYSCAN_CORS_ORIGINS", "").split(",") if o.strip()
]
ALLOWED_PATHS = [
    p.strip() for p in os.environ.get("MYSCAN_ALLOWED_PATHS", "").split(";") if p.strip()
]
TRUST_PROXY = os.environ.get("MYSCAN_TRUST_PROXY", "").strip().lower() in ("1", "true", "yes")

# Blocked remote URL schemes (defense in depth for SSRF)
ALLOWED_URL_SCHEMES = ("http", "https", "git", "ssh")


def auth_enabled() -> bool:
    """True when an API key is configured and must be enforced."""
    return bool(API_KEY)


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

def _extract_token() -> str:
    """Extract an API token from the request in priority order."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    if auth.startswith("Basic "):
        try:
            raw = base64.b64decode(auth[6:]).decode("utf-8")
            _, _, password = raw.partition(":")
            return password.strip()
        except (binascii.Error, UnicodeDecodeError):
            return ""
    token = request.headers.get("X-API-Key", "")
    if token:
        return token.strip()
    token = request.args.get("token", "")
    if token:
        return token.strip()
    return ""


def _token_valid(token: str) -> bool:
    if not auth_enabled():
        return True
    if not token:
        return False
    return hmac.compare_digest(token, API_KEY)


def require_auth(view):
    """Decorator: reject requests without a valid API key (when auth is enabled)."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _token_valid(_extract_token()):
            return (
                jsonify({"error": "Unauthorized. Provide a valid API key."}),
                401,
                {"WWW-Authenticate": 'Bearer realm="myscan"'},
            )
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------

_limiter_lock = threading.Lock()
_hit_times: dict[str, deque] = defaultdict(deque)
_MAX_CLIENTS = 10000


def _client_key() -> str:
    """Identity of the calling client (proxy-aware when configured)."""
    if TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def check_rate_limit() -> tuple[bool, int]:
    """Return (allowed, retry_after_seconds). Applies sliding-window limits."""
    now = time.monotonic()
    key = _client_key()
    with _limiter_lock:
        if len(_hit_times) > _MAX_CLIENTS:
            # Evict stale entries to bound memory
            cutoff = now - 60.0
            for k in [k for k, v in _hit_times.items() if not v or v[-1] < cutoff]:
                _hit_times.pop(k, None)
        hits = _hit_times.setdefault(key, deque())
        while hits and now - hits[0] > 60.0:
            hits.popleft()
        burst = sum(1 for t in hits if now - t <= 1.0)
        if len(hits) >= RATE_LIMIT_PER_MINUTE or burst >= RATE_LIMIT_BURST:
            retry_after = int(60.0 - (now - hits[0])) + 1 if hits else 1
            return False, max(retry_after, 1)
        hits.append(now)
    return True, 0


# --------------------------------------------------------------------------
# CORS
# --------------------------------------------------------------------------

def apply_cors(response):
    """Set CORS headers on a response based on the configured allowlist."""
    origin = request.headers.get("Origin")
    if origin and (origin in CORS_ORIGINS or "*" in CORS_ORIGINS):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-API-Key"
        )
        response.headers["Access-Control-Allow-Methods"] = (
            "GET, POST, PUT, DELETE, OPTIONS"
        )
        response.headers["Access-Control-Max-Age"] = "3600"
    return response


# --------------------------------------------------------------------------
# SSRF / target guards
# --------------------------------------------------------------------------

_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::ffff:0:0/96"),
)


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    # Normalize IPv4-mapped IPv6 like ::ffff:192.168.0.1
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in net for net in _PRIVATE_NETS)


def _host_for_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"git://{url}")
    host = parsed.hostname or ""
    if not host and url.startswith("git@"):
        # scp-like syntax: git@github.com:org/repo.git
        host = url[4:].split(":", 1)[0]
    return host.strip()


def validate_remote_target(url: str) -> None:
    """Raise ValueError if a remote target is disallowed (SSRF protection)."""
    scheme = (url.split("://", 1)[0].split(":", 1)[0]).lower() if "://" in url else "ssh"
    if url.startswith("git@"):
        scheme = "ssh"
    if scheme not in ALLOWED_URL_SCHEMES:
        raise ValueError(f"Unsupported URL scheme: {scheme}. Use http, https, git, or git@.")
    host = _host_for_url(url)
    if not host:
        raise ValueError(f"Could not determine host from target: {url}")

    # Resolve the hostname; block private/loopback/link-local addresses.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve host: {host}") from e
    for info in infos:
        ip = info[4][0]
        if _is_blocked_ip(ip):
            raise ValueError(
                f"Target host {host} resolves to a private/loopback address ({ip}) and is blocked."
            )


def validate_local_target(path: str) -> None:
    """Raise ValueError if a local scan target is outside the configured allowlist."""
    import os as _os
    resolved = _os.path.abspath(_os.path.normpath(path))
    if ALLOWED_PATHS:
        for allowed in ALLOWED_PATHS:
            base = _os.path.abspath(_os.path.normpath(allowed))
            if resolved == base or resolved.startswith(base + _os.sep):
                return
        raise ValueError(
            "Target path is not in the allowed paths list (MYSCAN_ALLOWED_PATHS)."
        )
    # Always refuse obvious system/sensitive directories even without an allowlist.
    sensitive = (_os.sep + "etc", _os.sep + "usr", "C:" + _os.sep + "Windows")
    normalized = resolved.lower()
    for s in sensitive:
        if normalized.startswith(s.lower()):
            raise ValueError(f"Scanning sensitive system path is not allowed: {path}")
