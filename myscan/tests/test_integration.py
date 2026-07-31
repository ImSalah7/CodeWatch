"""End-to-end integration tests.

Each scenario runs the API in a fresh subprocess with its own environment so
that auth, rate limiting, CORS, SSRF guards, and persistence can be verified in
true production-like isolation.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "sample_app"
PYTHON = sys.executable


def _run_scenario(script: str, env: dict) -> subprocess.CompletedProcess:
    merged = dict(os.environ)
    merged["PYTHONPATH"] = str(ROOT)
    merged.pop("MYSCAN_API_KEY", None)
    merged.pop("MYSCAN_ALLOWED_PATHS", None)
    merged.pop("MYSCAN_RATE_LIMIT", None)
    merged.pop("MYSCAN_RATE_LIMIT_BURST", None)
    merged.pop("MYSCAN_CORS_ORIGINS", None)
    merged.pop("MYSCAN_DB", None)
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


BASIC_SCAN_SCRIPT = r"""
import json, os, sys, time
from src.api import app

client = app.test_client()
r = client.get("/health")
assert r.status_code == 200, r.data
assert r.json["status"] == "healthy"

r = client.post("/api/v1/scan", json={"target": r"FIXTURES", "threads": 2})
assert r.status_code == 202, (r.status_code, r.data)
jid = r.json["job_id"]

for _ in range(240):
    s = client.get(f"/api/v1/scan/{jid}").json
    if s["status"] in ("completed", "failed"):
        break
    time.sleep(0.5)
assert s["status"] == "completed", (s["status"], s.get("error"))
assert s["finding_count"] > 0, s

fr = client.get(f"/api/v1/findings?job_id={jid}&limit=5")
assert fr.status_code == 200
assert fr.json["total"] == s["finding_count"]
fp = fr.json["findings"][0]["fingerprint"]
d = client.get(f"/api/v1/findings/{fp}")
assert d.status_code == 200, d.data
assert d.json["scan_id"] == jid

for fmt in ("json", "html", "markdown", "csv", "sarif"):
    rr = client.get(f"/api/v1/report/{jid}?format={fmt}")
    assert rr.status_code == 200, (fmt, rr.status_code, rr.data[:200])

fix = client.post("/api/v1/fix", json={"job_id": jid})
assert fix.status_code == 200, fix.data
assert len(fix.json["fixes"]) == s["finding_count"]

sr = client.get("/api/v1/search?q=sql")
assert sr.status_code == 200
assert sr.json["total"] >= 1

assert client.get("/api/v1/history").json["total"] >= 1
st = client.get("/api/v1/stats").json
assert st["completed_scans"] >= 1 and st["total_findings"] > 0
sc = client.get("/api/v1/security-score").json
assert "grade" in sc and "score" in sc

print("BASIC_SCAN_OK", jid, s["finding_count"])
"""


def test_basic_scan_and_reporting():
    db = tempfile.mktemp(suffix=".db")
    script = BASIC_SCAN_SCRIPT.replace("FIXTURES", str(FIXTURES).replace("\\", "\\\\"))
    env = {"MYSCAN_DB": db}
    _assert_ok(_run_scenario(script, env))


RESTART_SCRIPT = r"""
import sys
from src.api import app
client = app.test_client()
h = client.get("/api/v1/history")
assert h.status_code == 200, h.data
assert h.json["total"] >= 1, h.json
job = h.json["history"][0]
jid = job["job_id"]

fr = client.get(f"/api/v1/findings?job_id={jid}")
assert fr.status_code == 200 and fr.json["total"] > 0, (fr.status_code, fr.data[:200])

st = client.get("/api/v1/stats").json
assert st["completed_scans"] >= 1

sc = client.get("/api/v1/security-score").json
assert "grade" in sc

for fmt in ("html", "markdown", "csv", "sarif"):
    rr = client.get(f"/api/v1/report/{jid}?format={fmt}")
    assert rr.status_code == 200, (fmt, rr.status_code, rr.data[:200])

# live-tracking state is gone after restart; a fresh scan must still work
r = client.post("/api/v1/scan", json={"target": r"FIXTURES", "threads": 2})
assert r.status_code == 202, r.data
print("RESTART_OK", jid)
"""


def test_persistence_across_restart():
    db = tempfile.mktemp(suffix=".db")
    env = {"MYSCAN_DB": db}
    _assert_ok(_run_scenario(BASIC_SCAN_SCRIPT.replace("FIXTURES", str(FIXTURES).replace("\\", "\\\\")), env))
    script = RESTART_SCRIPT.replace("FIXTURES", str(FIXTURES).replace("\\", "\\\\"))
    _assert_ok(_run_scenario(script, env))


AUTH_SCRIPT = r"""
import base64, json, sys
from src.api import app
client = app.test_client()

def g(path, **kw):
    kw.setdefault("environ_base", {"REMOTE_ADDR": "10.0.0.1"})
    return client.get(path, **kw)

assert g("/health").status_code == 200

assert g("/api/v1/stats").status_code == 401
assert g("/api/v1/stats", headers={"Authorization": "Bearer wrong"}).status_code == 401
assert g("/api/v1/stats", headers={"X-API-Key": "nope"}).status_code == 401
assert g("/api/v1/stats?token=wrong").status_code == 401

r = g("/api/v1/stats", headers={"Authorization": "Bearer secret123"})
assert r.status_code == 200, r.data

basic = base64.b64encode(b"user:secret123").decode()
r = g("/api/v1/stats", headers={"Authorization": "Basic " + basic})
assert r.status_code == 200, r.data

r = g("/api/v1/stats", headers={"X-API-Key": "secret123"})
assert r.status_code == 200, r.data

r = g("/api/v1/stats?token=secret123")
assert r.status_code == 200, r.data

assert g("/api/v1/scan/nope/events").status_code == 401
r = g("/api/v1/scan/nope/events?token=secret123")
assert r.status_code == 404, r.data  # auth passed, job missing

# CORS (separate client identity so rate limiting does not interfere)
def c(path, **kw):
    kw.setdefault("environ_base", {"REMOTE_ADDR": "10.0.0.2"})
    return client.get(path, **kw)

r = c("/api/v1/stats", headers={"Authorization": "Bearer secret123", "Origin": "https://good.example.com"})
assert r.headers.get("Access-Control-Allow-Origin") == "https://good.example.com", r.headers
r = c("/api/v1/stats", headers={"Authorization": "Bearer secret123", "Origin": "https://evil.example.com"})
assert r.headers.get("Access-Control-Allow-Origin") is None, r.headers
r = client.options("/api/v1/stats", headers={"Origin": "https://good.example.com", "Access-Control-Request-Method": "GET"},
                   environ_base={"REMOTE_ADDR": "10.0.0.2"})
assert r.status_code in (200, 204), r.status_code
assert r.headers.get("Access-Control-Allow-Origin") == "https://good.example.com", r.headers

print("AUTH_OK")
"""

RATE_LIMIT_SCRIPT = r"""
from src.api import app
client = app.test_client()

seen_429 = False
for _ in range(8):
    rr = client.get("/api/v1/stats", headers={"Authorization": "Bearer secret123"},
                    environ_base={"REMOTE_ADDR": "10.99.99.99"})
    if rr.status_code == 429:
        assert rr.headers.get("Retry-After") is not None
        seen_429 = True
        break
assert seen_429, "expected a 429 from rate limiting"
print("RATE_LIMIT_OK")
"""


def test_auth_rate_limit_cors():
    db = tempfile.mktemp(suffix=".db")
    env = {
        "MYSCAN_API_KEY": "secret123",
        "MYSCAN_RATE_LIMIT": "30",
        "MYSCAN_RATE_LIMIT_BURST": "20",
        "MYSCAN_CORS_ORIGINS": "https://good.example.com",
        "MYSCAN_DB": db,
    }
    _assert_ok(_run_scenario(AUTH_SCRIPT, env))


def test_rate_limit():
    db = tempfile.mktemp(suffix=".db")
    env = {
        "MYSCAN_API_KEY": "secret123",
        "MYSCAN_RATE_LIMIT": "5",
        "MYSCAN_RATE_LIMIT_BURST": "20",
        "MYSCAN_DB": db,
    }
    _assert_ok(_run_scenario(RATE_LIMIT_SCRIPT, env))


SSRF_SCRIPT = r"""
import os, sys, tempfile
from pathlib import Path
from src.api import app
client = app.test_client()

def scan(target):
    return client.post("/api/v1/scan", json={"target": target})

# Remote SSRF targets must be blocked
for bad in ("https://127.0.0.1:8443/repo", "http://169.254.169.254/meta",
            "https://192.168.1.5/repo", "file:///etc/passwd", "ftp://example.com/x"):
    r = scan(bad)
    assert r.status_code == 400, (bad, r.status_code, r.data)

# Local path outside the allowlist must be blocked
assert scan(r"OUTSIDE").status_code == 400

# Local path inside the allowlist must work
r = scan(r"INSIDE")
assert r.status_code == 202, (r.status_code, r.data)

# Input validation
assert client.post("/api/v1/scan", json={}).status_code == 400
assert client.post("/api/v1/scan", json={"target": "x" * 5000}).status_code == 400
assert client.post("/api/v1/scan", json={"target": r"DOES_NOT_EXIST_123"}).status_code == 404
assert client.post("/api/v1/scan", json={"target": r"INSIDE", "secret_display": "bogus"}).status_code == 202
print("SSRF_OK")
"""


def test_ssrf_and_path_allowlist():
    db = tempfile.mktemp(suffix=".db")
    with tempfile.TemporaryDirectory() as projects:
        projects = Path(projects)
        allowed = projects / "allowed"
        allowed.mkdir()
        (allowed / "app.py").write_text("print('hi')")
        outside = projects / "outside"
        outside.mkdir()
        (outside / "app.py").write_text("print('hi')")
        env = {
            "MYSCAN_ALLOWED_PATHS": str(allowed),
            "MYSCAN_DB": db,
        }
        script = (
            SSRF_SCRIPT
            .replace("OUTSIDE", str(outside).replace("\\", "\\\\"))
            .replace("INSIDE", str(allowed).replace("\\", "\\\\"))
        )
        _assert_ok(_run_scenario(script, env))


def test_dependency_and_sbom_endpoints():
    db = tempfile.mktemp(suffix=".db")
    script = r"""
import sys
from src.api import app
client = app.test_client()
target = r"FIXTURES"

r = client.post("/api/v1/dependencies", json={"target": target})
assert r.status_code == 200, (r.status_code, r.data[:300])
assert r.json["total_manifests"] >= 0

r = client.post("/api/v1/sbom", json={"target": target})
assert r.status_code == 200, (r.status_code, r.data[:300])

r = client.post("/api/v1/sbom", json={"target": target, "format": "spdx"})
assert r.status_code == 200, (r.status_code, r.data[:300])

# invalid path rejected by allowlist/sensitivity rules via input validation
r = client.post("/api/v1/dependencies", json={"target": r"DOES_NOT_EXIST_123"})
assert r.status_code == 404, r.status_code
print("DEPS_OK")
""".replace("FIXTURES", str(FIXTURES).replace("\\", "\\\\"))
    _assert_ok(_run_scenario(script, {"MYSCAN_DB": tempfile.mktemp(suffix=".db")}))
