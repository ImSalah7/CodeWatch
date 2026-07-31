"""MyScan REST API.

Endpoints:
    POST   /api/v1/scan            - Scan a target path
    GET    /api/v1/scan/:id        - Get scan status/result
    GET    /api/v1/scan/:id/events - SSE scan progress stream
    POST   /api/v1/scan/:id/cancel - Cancel a running scan
    POST   /api/v1/scan/:id/pause  - Pause a running scan
    POST   /api/v1/scan/:id/resume - Resume a paused scan
    GET    /api/v1/findings        - Get findings (with filters)
    GET    /api/v1/findings/:fp    - Get a single finding by fingerprint
    GET    /api/v1/search          - Global search
    GET    /api/v1/report/:id      - Generate report
    POST   /api/v1/fix             - Generate fix suggestions
    GET    /api/v1/history         - Get scan history
    GET    /api/v1/stats           - Get aggregate statistics
    GET    /api/v1/security-score  - Overall security score
    GET    /health                 - Health check (unauthenticated)

Production security (see src/security.py):
    - Authentication via MYSCAN_API_KEY (Bearer / Basic / X-API-Key / ?token=)
    - Rate limiting via MYSCAN_RATE_LIMIT / MYSCAN_RATE_LIMIT_BURST
    - CORS allowlist via MYSCAN_CORS_ORIGINS
    - SSRF guard + local path allowlist via MYSCAN_ALLOWED_PATHS

Persistence (see src/store.py):
    - Scans and findings are stored in SQLite (MYSCAN_DB, default src/myscan.db)
    - History, findings, search, stats, and reports survive restarts
"""

from __future__ import annotations

import atexit
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, request, Response, stream_with_context

from . import security as sec
from . import store
from .__init__ import __version__
from .core.config import ScanConfig
from .core.engine import ScanEngine
from .core.models import ScanResult
from .progress import create_tracker, get_tracker, remove_tracker

app = Flask(__name__)

SETTINGS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "myscan_settings.json"
)

DEFAULT_SETTINGS = {
    "threads": 4,
    "min_confidence": 0.2,
    "enterprise_mode": False,
    "secret_display": "smart",
    "max_file_size_kb": 1024,
    "include_tests": False,
    "include_docs": False,
    "include_examples": False,
    "max_history": 50,
    "report_format": "markdown",
    "notifications": {
        "scan_complete": True,
        "critical_findings": True,
        "scan_failed": True,
    },
}

_settings_lock = threading.Lock()

_MAX_MEMORY_JOBS = 200
_MAX_TARGET_LEN = 4096
_MAX_THREADS = 32
_ALLOWED_SECRET_DISPLAY = ("smart", "masked", "full")


def _load_settings() -> dict:
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
        merged = dict(DEFAULT_SETTINGS)
        merged.update(saved)
        return merged
    except (OSError, ValueError):
        return dict(DEFAULT_SETTINGS)


def _save_settings(settings: dict) -> None:
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)


def _ensure_settings_file() -> None:
    if not os.path.exists(SETTINGS_FILE):
        _save_settings(dict(DEFAULT_SETTINGS))


@dataclass
class ScanJob:
    job_id: str
    target: str
    status: str = "pending"
    enterprise: bool = False
    started_at: str = ""
    completed_at: str = ""
    result: Optional[ScanResult] = None
    error: str = ""
    scan_duration: float = 0.0
    finding_count: int = 0
    secret_display: str = "smart"
    clone_dir: str = ""
    is_remote: bool = False


_URL_PATTERN = re.compile(
    r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*://|git@).*",
    re.IGNORECASE,
)


def _is_remote_url(target: str) -> bool:
    return bool(_URL_PATTERN.match(target.strip()))


# --------------------------------------------------------------------------
# Request guards
# --------------------------------------------------------------------------

def _cors_preflight():
    resp = jsonify({})
    return sec.apply_cors(resp), 204


@app.before_request
def _before_request():
    if request.method == "OPTIONS":
        return _cors_preflight()
    if request.path.startswith("/api/"):
        allowed, retry_after = sec.check_rate_limit()
        if not allowed:
            return (
                jsonify({"error": "Rate limit exceeded. Please retry later."}),
                429,
                {"Retry-After": str(retry_after)},
            )
    return None


@app.after_request
def _after_request(response):
    return sec.apply_cors(response)


def _clamp_int(value, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def _clamp_float(value, default: float, lo: float, hi: float) -> float:
    try:
        return max(lo, min(hi, float(value)))
    except (TypeError, ValueError):
        return default


def _clean_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("Missing required field: target")
    if len(target) > _MAX_TARGET_LEN:
        raise ValueError(f"Target is too long (max {_MAX_TARGET_LEN} characters)")
    return target


# --------------------------------------------------------------------------
# Remote clone helpers
# --------------------------------------------------------------------------

def _clone_repo(url: str, dest: str) -> str:
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", url, dest]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(
            f"git clone failed (exit {proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return dest


def _rmtree_robust(path: str) -> None:
    if not os.path.isdir(path):
        return
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
    if os.path.isdir(path):
        for _ in range(3):
            try:
                subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", path], capture_output=True, timeout=30)
            except Exception:
                pass
            if not os.path.isdir(path):
                return
            time.sleep(1)


def _cleanup_temp_clones() -> None:
    temp = tempfile.gettempdir()
    try:
        for entry in os.listdir(temp):
            if entry.startswith("myscan_") and os.path.isdir(os.path.join(temp, entry)):
                _rmtree_robust(os.path.join(temp, entry))
    except OSError:
        pass


atexit.register(_cleanup_temp_clones)


# --------------------------------------------------------------------------
# Scan job execution + persistence
# --------------------------------------------------------------------------

_scan_history: dict[str, ScanJob] = {}
_history_lock = threading.Lock()


def _run_scan_job(job: ScanJob, config: ScanConfig) -> None:
    tracker = create_tracker(job.job_id)
    try:
        job.status = "running"
        scan_target = job.target

        if job.is_remote:
            clone_dest = os.path.join(tempfile.gettempdir(), f"myscan_{job.job_id}")
            tracker.phase = "cloning"
            job.clone_dir = _clone_repo(job.target, clone_dest)
            scan_target = job.clone_dir

        engine = ScanEngine(config, enterprise_mode=job.enterprise, progress_tracker=tracker)
        result = engine.scan(scan_target)

        from .core.secret_display import SecretDisplayConfig, apply_secret_display_mode
        display_config = SecretDisplayConfig.from_string(job.secret_display)
        apply_secret_display_mode(result.findings, display_config.mode)
        result._secret_display_mode = display_config.mode.value

        from .ai.enhancer import enhance_findings
        try:
            llm_stats = enhance_findings(result.findings)
            if llm_stats.get("enhanced"):
                result._llm_stats = llm_stats
        except Exception:
            pass

        job.result = result
        job.status = "completed"
        job.completed_at = datetime.now(timezone.utc).isoformat()
        job.finding_count = len(result.findings)
        job.scan_duration = result.scan_duration

        result_dict = result.to_dict()
        store.save_scan(
            job_id=job.job_id, target=job.target, status=job.status,
            enterprise=job.enterprise, started_at=job.started_at,
            completed_at=job.completed_at, error="", scan_duration=result.scan_duration,
            finding_count=len(result.findings), secret_display=job.secret_display,
            is_remote=job.is_remote, result_json=json.dumps(result_dict),
            summary_json=json.dumps(result_dict.get("summary", {})),
        )
        store.save_findings(job.job_id, [f.to_dict() for f in result.findings])
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.completed_at = datetime.now(timezone.utc).isoformat()
        t = get_tracker(job.job_id)
        if t:
            t.on_error(str(exc))
        store.save_scan(
            job_id=job.job_id, target=job.target, status="failed",
            enterprise=job.enterprise, started_at=job.started_at,
            completed_at=job.completed_at, error=str(exc),
            scan_duration=0.0, finding_count=0, secret_display=job.secret_display,
            is_remote=job.is_remote, result_json=None, summary_json=None,
        )
    finally:
        if job.clone_dir and os.path.isdir(job.clone_dir):
            _rmtree_robust(job.clone_dir)
        try:
            store.prune_history(int(_load_settings().get("max_history", 50)))
        except Exception:
            pass
        _prune_memory()


def _prune_memory() -> None:
    """Bound in-memory job cache to completed/failed jobs from this process."""
    with _history_lock:
        if len(_scan_history) <= _MAX_MEMORY_JOBS:
            return
        terminal = [
            j for j in _scan_history.values()
            if j.status in ("completed", "failed")
        ]
        terminal.sort(key=lambda j: j.started_at, reverse=True)
        for job in terminal[_MAX_MEMORY_JOBS:]:
            _scan_history.pop(job.job_id, None)


def _get_job(job_id: str):
    """Return (job, source) where source is 'live' or 'db' (or (None, None))."""
    with _history_lock:
        job = _scan_history.get(job_id)
    if job is not None:
        return job, "live"
    rec = store.get_scan(job_id)
    if rec is not None:
        return rec, "db"
    return None, None


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy", "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "auth": sec.auth_enabled(),
    })


@app.route("/api/v1/scan", methods=["POST"])
@sec.require_auth
def start_scan():
    body = request.get_json(silent=True) or {}
    try:
        target = _clean_target(body.get("target", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    is_remote = _is_remote_url(target)

    if is_remote:
        try:
            sec.validate_remote_target(target)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        scan_target = target
    else:
        target_path = Path(target).resolve()
        if not target_path.exists():
            return jsonify({"error": f"Target not found: {target}"}), 404
        try:
            sec.validate_local_target(str(target_path))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        scan_target = str(target_path)

    enterprise = bool(body.get("enterprise", False))
    threads = _clamp_int(body.get("threads"), 4, 1, _MAX_THREADS)
    min_confidence = _clamp_float(body.get("min_confidence"), 0.15, 0.0, 1.0)
    secret_display = body.get("secret_display", "smart")
    if secret_display not in _ALLOWED_SECRET_DISPLAY:
        secret_display = "smart"

    config = ScanConfig()
    config.min_confidence = min_confidence
    config.max_workers = threads

    job_id = uuid.uuid4().hex[:12]
    job = ScanJob(
        job_id=job_id, target=scan_target, enterprise=enterprise,
        started_at=datetime.now(timezone.utc).isoformat(),
        secret_display=secret_display, is_remote=is_remote,
    )

    with _history_lock:
        _scan_history[job_id] = job

    thread = threading.Thread(target=_run_scan_job, args=(job, config), daemon=True)
    thread.start()

    return jsonify({
        "job_id": job_id, "status": "pending", "target": scan_target,
        "enterprise": enterprise, "is_remote": is_remote,
    }), 202


@app.route("/api/v1/scan/<job_id>", methods=["GET"])
@sec.require_auth
def get_scan_status(job_id: str):
    job, source = _get_job(job_id)
    if job is None:
        return jsonify({"error": f"Job {job_id} not found"}), 404

    response = dict(
        job_id=job["job_id"] if source == "db" else job.job_id,
        status=job["status"] if source == "db" else job.status,
        target=job["target"] if source == "db" else job.target,
        enterprise=job["enterprise"] if source == "db" else job.enterprise,
        started_at=job["started_at"] if source == "db" else job.started_at,
        completed_at=job.get("completed_at") if source == "db" else job.completed_at,
        error=job.get("error", "") if source == "db" else job.error,
        finding_count=job.get("finding_count", 0) if source == "db" else job.finding_count,
    )

    if source == "live" and job.status == "completed" and job.result:
        payload = job.result.to_dict()
        if hasattr(job.result, "_enterprise_metrics") and job.result._enterprise_metrics:
            payload["enterprise_metrics"] = job.result._enterprise_metrics
        if hasattr(job.result, "_llm_stats") and job.result._llm_stats:
            payload["llm_stats"] = job.result._llm_stats
        payload["findings"] = payload["findings"][:200]
        response["result"] = payload
    elif source == "db" and job.get("status") == "completed" and job.get("result"):
        payload = dict(job["result"])
        payload["findings"] = payload.get("findings", [])[:200]
        response["result"] = payload

    return jsonify(response)


@app.route("/api/v1/scan/<job_id>/events", methods=["GET"])
@sec.require_auth
def stream_scan_events(job_id: str):
    """SSE endpoint streaming real-time scan progress."""
    tracker = get_tracker(job_id)
    if not tracker:
        job, source = _get_job(job_id)
        if job is None:
            return jsonify({"error": f"Job {job_id} not found"}), 404
        status = job.status if source == "live" else job.get("status")
        if status == "completed":
            def gen_completed():
                yield f"data: {json.dumps({'event': 'complete', 'data': {'status': 'completed'}})}\n\n"
            return Response(gen_completed(), mimetype="text/event-stream")
        return jsonify({"error": "No progress data available"}), 404

    q = tracker.subscribe()

    def event_stream():
        try:
            # Yield an immediate snapshot so response headers flush right away
            # even if the scan finishes before the client connects.
            yield f"data: {json.dumps({'event': 'init', 'data': tracker.to_dict()})}\n\n"
            # If the scan already reached a terminal phase before this client
            # subscribed, its events were not queued for us: synthesize them.
            if tracker.phase in ("completed", "error"):
                event_name = "complete" if tracker.phase == "completed" else "error"
                payload = {"summary": {}, "status": tracker.phase}
                if tracker.phase == "error":
                    payload["error"] = "Scan finished with an error."
                yield f"data: {json.dumps({'event': event_name, 'data': payload})}\n\n"
                return
            while True:
                try:
                    event = q.get(timeout=30)
                    if event.event_type == "init":
                        # superseded by the snapshot yielded above
                        continue
                    payload = json.dumps({
                        "event": event.event_type,
                        "data": event.data,
                        "timestamp": event.timestamp,
                    })
                    yield f"data: {payload}\n\n"
                    if event.event_type in ("complete", "error"):
                        break
                except Exception:
                    yield f"data: {json.dumps({'event': 'heartbeat', 'data': {}})}\n\n"
        finally:
            tracker.unsubscribe(q)

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/v1/scan/<job_id>/cancel", methods=["POST"])
@sec.require_auth
def cancel_scan(job_id: str):
    tracker = get_tracker(job_id)
    if not tracker:
        return jsonify({"error": "Scan not running"}), 400
    tracker.cancelled = True
    tracker.emit("cancelled", {})
    return jsonify({"status": "cancelling"})


@app.route("/api/v1/scan/<job_id>/pause", methods=["POST"])
@sec.require_auth
def pause_scan(job_id: str):
    tracker = get_tracker(job_id)
    if not tracker:
        return jsonify({"error": "Scan not running"}), 400
    tracker.on_paused()
    return jsonify({"status": "paused"})


@app.route("/api/v1/scan/<job_id>/resume", methods=["POST"])
@sec.require_auth
def resume_scan(job_id: str):
    tracker = get_tracker(job_id)
    if not tracker:
        return jsonify({"error": "Scan not running"}), 400
    tracker.on_resumed()
    return jsonify({"status": "resumed"})


@app.route("/api/v1/findings", methods=["GET"])
@sec.require_auth
def get_findings():
    job_id = request.args.get("job_id", "").strip()
    if not job_id:
        with _history_lock:
            if _scan_history:
                latest = max(_scan_history.values(), key=lambda j: j.started_at)
                job_id = latest.job_id
        if not job_id:
            latest = store.list_scans(1)
            if latest:
                job_id = latest[0]["job_id"]

    if not job_id:
        return jsonify({"error": "No scan found. Provide job_id parameter."}), 404

    job, source = _get_job(job_id)
    if job is None:
        return jsonify({"error": "No scan found. Provide job_id parameter."}), 404

    status = job.status if source == "live" else job.get("status")
    if status != "completed":
        return jsonify({"error": f"Scan {job_id} not completed (status: {status})"}), 400

    category = request.args.get("category", "")
    severity = request.args.get("severity", "")
    min_confidence = _clamp_float(request.args.get("min_confidence", 0), 0.0, 0.0, 1.0)
    limit = _clamp_int(request.args.get("limit", 100), 100, 1, 500)
    offset = max(0, _clamp_int(request.args.get("offset", 0), 0, 0, 10_000_000))
    search = request.args.get("search", "").lower()

    if source == "live":
        findings = job.result.findings
        if category:
            findings = [f for f in findings if f.category.value == category.lower()]
        if severity:
            findings = [f for f in findings if f.severity.value == severity.lower()]
        if min_confidence > 0:
            findings = [f for f in findings if f.confidence >= min_confidence]
        if search:
            findings = [
                f for f in findings
                if search in f.title.lower()
                or search in f.rule_id.lower()
                or search in f.location.file_path.lower()
                or search in (f.cwe or "").lower()
            ]
        total = len(findings)
        findings = findings[offset:offset + limit]
        return jsonify({
            "job_id": job_id, "total": total, "offset": offset,
            "limit": limit,
            "findings": [f.to_dict() for f in findings],
        })

    total, findings = store.get_findings(
        scan_id=job_id, category=category, severity=severity,
        min_confidence=min_confidence, search=search, limit=limit, offset=offset,
    )
    return jsonify({
        "job_id": job_id, "total": total, "offset": offset,
        "limit": limit, "findings": findings,
    })


@app.route("/api/v1/findings/<fingerprint>", methods=["GET"])
@sec.require_auth
def get_finding(fingerprint: str):
    """Get a single finding by fingerprint across all completed scans."""
    with _history_lock:
        jobs = list(_scan_history.items())
    for job_id, job in jobs:
        if job.status == "completed" and job.result:
            for f in job.result.findings:
                if f.fingerprint == fingerprint:
                    d = f.to_dict()
                    d["scan_id"] = job_id
                    d["scan_target"] = job.target
                    d["scan_date"] = job.completed_at
                    return jsonify(d)
    d = store.get_finding_by_fingerprint(fingerprint)
    if d:
        return jsonify(d)
    return jsonify({"error": "Finding not found"}), 404


@app.route("/api/v1/search", methods=["GET"])
@sec.require_auth
def global_search():
    """Global search across findings, files, rules, CWE, CVE, OWASP."""
    q = request.args.get("q", "").strip().lower()
    if not q or len(q) < 2:
        return jsonify({"results": [], "total": 0})
    results = store.global_search(q, limit=50)
    return jsonify({"results": results, "total": len(results)})


@app.route("/api/v1/report/<job_id>", methods=["GET"])
@sec.require_auth
def get_report(job_id: str):
    job, source = _get_job(job_id)
    if job is None:
        return jsonify({"error": f"Job {job_id} not found"}), 404

    if source == "live" and job.status == "completed" and job.result:
        result = job.result
        result_dict = result.to_dict()
    elif source == "db" and job.get("status") == "completed" and job.get("result"):
        result_dict = job["result"]
    else:
        return jsonify({"error": "Scan not completed"}), 400

    fmt = request.args.get("format", "json").lower()

    if fmt == "json":
        return jsonify(result_dict)

    from .reporters import REPORTERS
    reporter_cls = REPORTERS.get(fmt)
    if not reporter_cls:
        return jsonify({"error": f"Unsupported format: {fmt}. Use json, html, markdown, csv, or sarif."}), 400

    from .serialization import result_from_dict
    result = result_from_dict(result_dict)
    reporter = reporter_cls()
    content = reporter.generate(result)

    content_types = {
        "markdown": "text/markdown; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "sarif": "application/sarif+json; charset=utf-8",
        "csv": "text/csv; charset=utf-8",
        "json": "application/json; charset=utf-8",
    }
    content_type = content_types.get(fmt, "text/plain; charset=utf-8")

    if fmt == "sarif":
        return jsonify(json.loads(content))
    return content, 200, {"Content-Type": content_type}


@app.route("/api/v1/fix", methods=["POST"])
@sec.require_auth
def generate_fixes():
    body = request.get_json(silent=True) or {}
    job_id = body.get("job_id", "")
    finding_ids = body.get("finding_ids", [])

    job, source = _get_job(job_id)
    if job is None:
        return jsonify({"error": f"Job {job_id} not found"}), 404

    status = job.status if source == "live" else job.get("status")
    if status != "completed":
        return jsonify({"error": "Scan not completed"}), 400

    if source == "live":
        findings = [f.to_dict() for f in job.result.findings]
    else:
        findings = job["result"].get("findings", [])

    from .core.fix_generator import generate_fix
    fixes = []
    for finding in findings:
        if finding_ids and finding.get("rule_id") not in finding_ids:
            continue
        fix = generate_fix(
            category=finding.get("category", "security"),
            code_snippet=finding.get("code_snippet", ""),
        )
        fixes.append({
            "rule_id": finding.get("rule_id", ""),
            "title": finding.get("title", ""),
            "file": finding.get("file", ""),
            "line": finding.get("line", 0),
            "fingerprint": finding.get("fingerprint", ""),
            "fixes": [
                {"description": f.description, "before": f.before_code,
                 "after": f.after_code, "effort": f.effort}
                for f in fix
            ],
        })
    return jsonify({"job_id": job_id, "fixes": fixes})


@app.route("/api/v1/history", methods=["GET"])
@sec.require_auth
def get_history():
    limit = _clamp_int(request.args.get("limit", 20), 20, 1, 500)
    records = store.list_scans(limit)
    history = []
    for rec in records:
        history.append({
            "job_id": rec["job_id"], "target": rec["target"], "status": rec["status"],
            "enterprise": rec["enterprise"], "started_at": rec["started_at"],
            "completed_at": rec["completed_at"], "finding_count": rec["finding_count"],
            "error": rec["error"],
        })
    return jsonify({"history": history, "total": store.count_scans()})


@app.route("/api/v1/stats", methods=["GET"])
@sec.require_auth
def get_stats():
    return jsonify(store.get_stats())


@app.route("/api/v1/security-score", methods=["GET"])
@sec.require_auth
def get_security_score():
    """Calculate overall security score."""
    return jsonify(store.get_security_score())


@app.route("/api/v1/settings", methods=["GET"])
@sec.require_auth
def get_settings():
    return jsonify({"settings": _load_settings()})


@app.route("/api/v1/settings", methods=["PUT"])
@sec.require_auth
def update_settings():
    body = request.get_json(silent=True) or {}
    settings = body.get("settings", body)
    current = _load_settings()
    current.update(settings)
    _save_settings(current)
    return jsonify({"settings": current})


@app.route("/api/v1/dependencies", methods=["POST"])
@sec.require_auth
def scan_dependencies():
    """Scan a repository for vulnerable dependencies."""
    body = request.get_json(silent=True) or {}
    try:
        target = _clean_target(body.get("target", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    target_path = Path(target).resolve()
    if not target_path.exists():
        return jsonify({"error": f"Target not found: {target}"}), 404
    try:
        sec.validate_local_target(str(target_path))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    from .core.dependency_scanner import DependencyScanner

    try:
        scanner = DependencyScanner()
        results = scanner.scan_repository(str(target_path))
        payload = {
            "manifests": [r.to_dict() for r in results],
            "total_manifests": len(results),
            "total_dependencies": sum(r.total_dependencies for r in results),
            "vulnerabilities": {
                "critical": sum(r.critical_vulns for r in results),
                "high": sum(r.high_vulns for r in results),
                "medium": sum(r.medium_vulns for r in results),
                "low": sum(r.low_vulns for r in results),
                "total": sum(len(r.vulnerabilities) for r in results),
            },
            "target": str(target_path),
        }
        return jsonify(payload)
    except Exception as exc:
        return jsonify({"error": f"Dependency scan failed: {exc}"}), 500


@app.route("/api/v1/sbom", methods=["POST"])
@sec.require_auth
def generate_sbom():
    """Generate a CycloneDX or SPDX SBOM for a target repository."""
    body = request.get_json(silent=True) or {}
    try:
        target = _clean_target(body.get("target", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    fmt = body.get("format", "json").lower()

    target_path = Path(target).resolve()
    if not target_path.exists():
        return jsonify({"error": f"Target not found: {target}"}), 404
    try:
        sec.validate_local_target(str(target_path))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    from .core.dependency_scanner import DependencyScanner
    from .core.sbom import SBOMGenerator

    try:
        scanner = DependencyScanner()
        results = scanner.scan_repository(str(target_path))
        generator = SBOMGenerator()
        project_name = target_path.name
        doc = generator.generate_from_results(results, project_name=project_name)

        if fmt == "spdx":
            return jsonify(json.loads(doc.to_spdx_json()))
        return jsonify(json.loads(doc.to_cyclonedx_json()))
    except Exception as exc:
        return jsonify({"error": f"SBOM generation failed: {exc}"}), 500


def create_app(config: Optional[dict] = None) -> Flask:
    if config:
        app.config.update(config)
    _ensure_settings_file()
    store.init_store()
    return app


store.init_store()
_ensure_settings_file()


def run_api(host: str = "0.0.0.0", port: int = 8443, debug: bool = False) -> None:
    try:
        from waitress import serve
        serve(app, host=host, port=port, threads=16, channel_timeout=600)
    except ImportError:
        app.run(host=host, port=port, debug=debug)
