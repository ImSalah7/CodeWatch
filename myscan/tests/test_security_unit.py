"""Unit tests for the security layer (auth primitives, SSRF, path guards)."""

import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from flask import Flask, Response

from src import security


@pytest.fixture(autouse=True)
def _isolate_globals(monkeypatch):
    monkeypatch.setattr(security, "API_KEY", "")
    monkeypatch.setattr(security, "ALLOWED_PATHS", [])
    monkeypatch.setattr(security, "CORS_ORIGINS", [])
    yield


@pytest.fixture()
def app():
    return Flask(__name__)


class TestTokenValidation:
    def test_no_key_configured_allows_all(self):
        assert security._token_valid("") is True
        assert security._token_valid("anything") is True

    def test_key_configured(self, monkeypatch):
        monkeypatch.setattr(security, "API_KEY", "sekret")
        assert security.auth_enabled() is True
        assert security._token_valid("sekret") is True
        assert security._token_valid("wrong") is False
        assert security._token_valid("") is False


class TestBlockedIPs:
    def test_loopback(self):
        assert security._is_blocked_ip("127.0.0.1") is True
        assert security._is_blocked_ip("::1") is True

    def test_private_ranges(self):
        assert security._is_blocked_ip("10.0.0.1") is True
        assert security._is_blocked_ip("172.16.0.1") is True
        assert security._is_blocked_ip("172.31.255.255") is True
        assert security._is_blocked_ip("192.168.1.1") is True

    def test_link_local_and_metadata(self):
        assert security._is_blocked_ip("169.254.169.254") is True

    def test_ipv4_mapped(self):
        assert security._is_blocked_ip("::ffff:192.168.0.1") is True
        assert security._is_blocked_ip("::ffff:10.0.0.1") is True

    def test_public_allowed(self):
        assert security._is_blocked_ip("8.8.8.8") is False
        assert security._is_blocked_ip("1.1.1.1") is False
        assert security._is_blocked_ip("2606:4700:4700::1111") is False


class TestRemoteTarget:
    def test_bad_schemes(self):
        with pytest.raises(ValueError):
            security.validate_remote_target("file:///etc/passwd")
        with pytest.raises(ValueError):
            security.validate_remote_target("ftp://example.com/x")
        with pytest.raises(ValueError):
            security.validate_remote_target("gopher://example.com:70/")

    def test_no_host(self):
        with pytest.raises(ValueError):
            security.validate_remote_target("https:///path")

    def test_private_ip_blocked(self, monkeypatch):
        monkeypatch.setattr(
            security.socket, "getaddrinfo",
            lambda h, p: [(2, 1, 6, "", ("127.0.0.1", 80))],
        )
        with pytest.raises(ValueError, match="private/loopback"):
            security.validate_remote_target("https://myscan.internal/repo")

    def test_public_ip_allowed(self, monkeypatch):
        monkeypatch.setattr(
            security.socket, "getaddrinfo",
            lambda h, p: [(2, 1, 6, "", ("93.184.216.34", 80))],
        )
        security.validate_remote_target("https://example.com/repo.git")

    def test_resolution_failure(self, monkeypatch):
        def _boom(h, p):
            raise socket.gaierror("Name or service not known")
        monkeypatch.setattr(security.socket, "getaddrinfo", _boom)
        with pytest.raises(ValueError, match="Could not resolve"):
            security.validate_remote_target("https://nope.invalid/repo")


class TestLocalTarget:
    def test_allowlist_enforced(self, monkeypatch, tmp_path):
        allowed = tmp_path / "projects"
        allowed.mkdir()
        monkeypatch.setattr(security, "ALLOWED_PATHS", [str(allowed)])
        inside = allowed / "app"
        inside.mkdir()
        security.validate_local_target(str(inside))
        with pytest.raises(ValueError, match="allowed paths"):
            security.validate_local_target(str(tmp_path / "other"))

    def test_sensitive_windows_path_blocked_without_allowlist(self, monkeypatch):
        if sys.platform == "win32":
            monkeypatch.setattr(security, "ALLOWED_PATHS", [])
            with pytest.raises(ValueError):
                security.validate_local_target("C:\\Windows\\System32")


class TestCors:
    def _run(self, app, origin, cors_origins, method="GET"):
        security.CORS_ORIGINS = cors_origins
        with app.test_request_context(headers={"Origin": origin}):
            resp = security.apply_cors(Response())
        return resp

    def test_apply_cors_allowlisted_origin(self, app):
        resp = self._run(app, "https://good.example.com", ["https://good.example.com"])
        assert resp.headers["Access-Control-Allow-Origin"] == "https://good.example.com"
        assert resp.headers["Vary"] == "Origin"

    def test_apply_cors_denied_origin(self, app):
        resp = self._run(app, "https://evil.example.com", ["https://good.example.com"])
        assert "Access-Control-Allow-Origin" not in resp.headers

    def test_apply_cors_wildcard(self, app):
        resp = self._run(app, "https://any.example.com", ["*"])
        assert resp.headers["Access-Control-Allow-Origin"] == "https://any.example.com"


class TestClientKey:
    def test_remote_addr_used(self, app, monkeypatch):
        monkeypatch.setattr(security, "TRUST_PROXY", False)
        with app.test_request_context(environ_base={"REMOTE_ADDR": "10.0.0.5"}):
            assert security._client_key() == "10.0.0.5"

    def test_forwarded_used_when_trusted(self, app, monkeypatch):
        monkeypatch.setattr(security, "TRUST_PROXY", True)
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "10.0.0.5"},
            headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.5"},
        ):
            assert security._client_key() == "203.0.113.7"

    def test_forwarded_ignored_when_untrusted(self, app, monkeypatch):
        monkeypatch.setattr(security, "TRUST_PROXY", False)
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "10.0.0.5"},
            headers={"X-Forwarded-For": "203.0.113.7"},
        ):
            assert security._client_key() == "10.0.0.5"
