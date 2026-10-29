"""Multi-user authentication tests.

Unit tests cover password hashing and session tokens. Scenario tests run the
API in fresh subprocesses (like tests/test_integration.py) so the module-level
environment reads in src/security.py are isolated.
"""

import os
import subprocess
import sys
from pathlib import Path


from src import users as userlib

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def _run_scenario(script: str, env: dict) -> subprocess.CompletedProcess:
    merged = dict(os.environ)
    merged["PYTHONPATH"] = str(ROOT)
    for key in ("MYSCAN_API_KEY", "MYSCAN_ALLOWED_PATHS", "MYSCAN_RATE_LIMIT",
                "MYSCAN_RATE_LIMIT_BURST", "MYSCAN_CORS_ORIGINS", "MYSCAN_DB",
                "MYSCAN_SESSION_SECRET"):
        merged.pop(key, None)
    merged.update(env)
    return subprocess.run(
        [PYTHON, "-c", script],
        cwd=str(ROOT),
        env=merged,
        capture_output=True,
        text=True,
        timeout=300,
    )


def _assert_ok(result: subprocess.CompletedProcess):
    assert result.returncode == 0, (
        f"Scenario failed:\n--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )


# --------------------------------------------------------------------------
# Unit tests (users module)
# --------------------------------------------------------------------------

def test_password_hash_roundtrip():
    h = userlib.hash_password("correct horse battery staple")
    assert h.startswith("scrypt$")
    assert userlib.verify_password("correct horse battery staple", h)
    assert not userlib.verify_password("wrong password", h)


def test_password_hash_unique_salts():
    h1 = userlib.hash_password("same-password")
    h2 = userlib.hash_password("same-password")
    assert h1 != h2
    assert userlib.verify_password("same-password", h1)
    assert userlib.verify_password("same-password", h2)


def test_verify_password_rejects_garbage():
    assert not userlib.verify_password("x", "not-a-valid-hash")
    assert not userlib.verify_password("x", "")
    assert not userlib.verify_password("x", "scrypt$bogus")
    assert not userlib.verify_password("", "scrypt$2$8$1$!!!!$!!!!")


def test_api_key_generation_and_hashing():
    raw = userlib.generate_api_key()
    assert raw.startswith("ms_")
    assert len(raw) > 32
    h = userlib.hash_api_key(raw)
    assert len(h) == 64
    assert h != raw
    assert userlib.hash_api_key(raw) == h  # deterministic


def test_session_token_roundtrip(monkeypatch):
    monkeypatch.setenv("MYSCAN_SESSION_SECRET", "test-secret")
    token = userlib.issue_session_token("alice", "admin")
    ctx = userlib.verify_session_token(token)
    assert ctx == {"username": "alice", "role": "admin"}


def test_session_token_tamper(monkeypatch):
    monkeypatch.setenv("MYSCAN_SESSION_SECRET", "test-secret")
    token = userlib.issue_session_token("alice", "admin")
    body, sig = token.rsplit(".", 1)
    # Flip a char in the body.
    altered_body = ("A" if body[0] != "A" else "B") + body[1:]
    assert userlib.verify_session_token(f"{altered_body}.{sig}") is None
    assert userlib.verify_session_token("not.a.token") is None


def test_session_token_expiry(monkeypatch):
    monkeypatch.setenv("MYSCAN_SESSION_SECRET", "test-secret")
    token = userlib.issue_session_token("alice", "admin", ttl=-10)
    assert userlib.verify_session_token(token) is None


def test_session_secret_derivation_is_stable(monkeypatch):
    monkeypatch.delenv("MYSCAN_SESSION_SECRET", raising=False)
    monkeypatch.setenv("MYSCAN_API_KEY", "master-key")
    t1 = userlib.issue_session_token("u", "viewer")
    t2 = userlib.issue_session_token("u", "viewer")
    assert userlib.verify_session_token(t1) is not None
    assert userlib.verify_session_token(t2) is not None


def test_role_at_least():
    assert userlib.role_at_least("admin", "operator")
    assert userlib.role_at_least("admin", "admin")
    assert userlib.role_at_least("operator", "viewer")
    assert not userlib.role_at_least("viewer", "operator")
    assert not userlib.role_at_least("operator", "admin")
    assert userlib.valid_role("admin") and userlib.valid_role("operator") and userlib.valid_role("viewer")
    assert not userlib.valid_role("root")


# --------------------------------------------------------------------------
# API scenario: open mode (no key, no users)
# --------------------------------------------------------------------------

OPEN_MODE_SCRIPT = r"""
import tempfile, os
from src.api import app
from src import store

db = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["MYSCAN_DB"] = db
store.init_store(db)

client = app.test_client()
# Open instance: no auth required, all roles granted.
assert client.get("/health").status_code == 200
r = client.post("/api/v1/auth/login", json={"username": "nobody", "password": "x"})
assert r.status_code == 401  # user does not exist
assert client.get("/api/v1/history").status_code == 200
assert client.get("/api/v1/settings").status_code == 200
assert client.put("/api/v1/settings", json={"settings": {"threads": 2}}).status_code == 200
assert client.get("/api/v1/users").status_code == 200  # dev: admin role
print("OPEN_MODE_OK")
"""


def test_open_mode():
    result = _run_scenario(OPEN_MODE_SCRIPT, {})
    _assert_ok(result)
    assert "OPEN_MODE_OK" in result.stdout


# --------------------------------------------------------------------------
# API scenario: master key + users + roles + sessions
# --------------------------------------------------------------------------

AUTH_SCENARIO = r"""
import json, os, tempfile
from src.api import app
from src import store
from src import users as userlib

db = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["MYSCAN_DB"] = db
store.init_store(db)

store.create_user("admin", userlib.hash_password("admin-pass-123"), "admin")
store.create_user("op", userlib.hash_password("op-pass-1234"), "operator")
store.create_user("view", userlib.hash_password("view-pass-123"), "viewer")
# An API key for the operator (as the CLI would create it).
op_raw = userlib.generate_api_key()
store.add_api_key("op", userlib.hash_api_key(op_raw), "ci")

client = app.test_client()

# ---- master key acts as admin ----
r = client.get("/api/v1/users", headers={"Authorization": "Bearer master-secret"})
assert r.status_code == 200, r.data
assert len(r.json["users"]) == 3

# ---- password login ----
r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin-pass-123"})
assert r.status_code == 200, r.data
token = r.json["token"]
me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
assert me.status_code == 200 and me.json["role"] == "admin"

# wrong password
r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
assert r.status_code == 401

# ---- role enforcement ----
# viewer can read but not start scans / manage users
view_token = client.post("/api/v1/auth/login",
                         json={"username": "view", "password": "view-pass-123"}).json["token"]
vh = {"Authorization": f"Bearer {view_token}"}
assert client.get("/api/v1/history", headers=vh).status_code == 200
assert client.post("/api/v1/scan", json={"target": os.getcwd()}, headers=vh).status_code == 403
assert client.get("/api/v1/users", headers=vh).status_code == 403
assert client.put("/api/v1/settings", json={"settings": {}}, headers=vh).status_code == 403

# operator can act but not manage users / settings
op_token = client.post("/api/v1/auth/login",
                       json={"username": "op", "password": "op-pass-1234"}).json["token"]
oh = {"Authorization": f"Bearer {op_token}"}
assert client.get("/api/v1/history", headers=oh).status_code == 200
assert client.get("/api/v1/users", headers=oh).status_code == 403
assert client.put("/api/v1/settings", json={"settings": {}}, headers=oh).status_code == 403

# operator API key (Bearer) resolves to operator role
assert client.get("/api/v1/history", headers={"Authorization": f"Bearer {op_raw}"}).status_code == 200
assert client.get("/api/v1/users", headers={"Authorization": f"Bearer {op_raw}"}).status_code == 403

# ---- admin user management ----
r = client.post("/api/v1/users", headers=vh, json={"username": "newbie", "password": "password-123", "role": "viewer"})
assert r.status_code == 403  # viewer forbidden
r = client.post("/api/v1/users", headers={"Authorization": f"Bearer {token}"},
                json={"username": "newbie", "password": "password-123", "role": "viewer"})
assert r.status_code == 201, r.data
r = client.post("/api/v1/users", headers={"Authorization": f"Bearer {token}"},
                json={"username": "newbie", "password": "password-123", "role": "viewer"})
assert r.status_code == 409  # duplicate

# issue + use a key via the API
r = client.post("/api/v1/users/newbie/keys", headers={"Authorization": f"Bearer {token}"},
                json={"label": "laptop"})
assert r.status_code == 201, r.data
issued = r.json["key"]
assert issued.startswith("ms_")
assert client.get("/api/v1/history", headers={"Authorization": f"Bearer {issued}"}).status_code == 200

# revoke it
kid = r.json["id"]
r = client.delete(f"/api/v1/users/newbie/keys/{kid}", headers={"Authorization": f"Bearer {token}"})
assert r.status_code == 200
assert client.get("/api/v1/history", headers={"Authorization": f"Bearer {issued}"}).status_code == 401

# disable a user -> their login and keys stop working
assert client.put("/api/v1/users/view", headers={"Authorization": f"Bearer {token}"},
                  json={"active": False}).status_code == 200
assert client.post("/api/v1/auth/login", json={"username": "view", "password": "view-pass-123"}).status_code == 401

# delete a user
assert client.delete("/api/v1/users/newbie", headers={"Authorization": f"Bearer {token}"}).status_code == 200
assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {issued}"}).status_code == 401

# ---- auth disabled behaviour without any credential ----
r = client.get("/api/v1/history")
assert r.status_code == 401
print("AUTH_SCENARIO_OK")
"""


def test_auth_scenario():
    result = _run_scenario(AUTH_SCENARIO, {"MYSCAN_API_KEY": "master-secret"})
    _assert_ok(result)
    assert "AUTH_SCENARIO_OK" in result.stdout


# --------------------------------------------------------------------------
# API scenario: login rate limiting
# --------------------------------------------------------------------------

LOGIN_RATE_LIMIT_SCRIPT = r"""
import os, tempfile
from src.api import app
from src import store
from src import users as userlib

db = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["MYSCAN_DB"] = db
store.init_store(db)
store.create_user("admin", userlib.hash_password("password-123"), "admin")

client = app.test_client()
codes = set()
for _ in range(15):
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
    codes.add(r.status_code)
assert 429 in codes, codes  # the login-specific limit kicked in
print("LOGIN_RATE_LIMIT_OK")
"""


def test_login_rate_limit():
    result = _run_scenario(LOGIN_RATE_LIMIT_SCRIPT, {"MYSCAN_LOGIN_RATE_LIMIT": "3"})
    _assert_ok(result)
    assert "LOGIN_RATE_LIMIT_OK" in result.stdout
