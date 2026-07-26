"""MyScan REST API.

Endpoints:
    POST   /api/v1/scan       - Scan a target path
    GET    /api/v1/scan/:id   - Get scan status/result
    GET    /api/v1/findings   - Get findings from last/specified scan
    GET    /api/v1/report/:id - Generate report (JSON/HTML/Markdown/SARIF)
    POST   /api/v1/fix        - Generate fix suggestions for findings
    GET    /api/v1/history    - Get scan history
    GET    /api/v1/stats      - Get aggregate statistics
    GET    /health             - Health check
"""

from __future__ import annotations

import json
import time
import uuid
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, request, send_file

from .core.config import ScanConfig
from .core.engine import ScanEngine
from .core.models import ScanResult


app = Flask(__name__)


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


_scan_history: dict[str, ScanJob] = {}
_history_lock = threading.Lock()


def _run_scan_job(job: ScanJob, config: ScanConfig) -> None:
    """Execute a scan job in background thread."""
    try:
        job.status = "running"
        engine = ScanEngine(config, enterprise_mode=job.enterprise)
        result = engine.scan(job.target)

        from .core.secret_display import SecretDisplayConfig, apply_secret_display_mode
        display_config = SecretDisplayConfig.from_string(job.secret_display)
        apply_secret_display_mode(result.findings, display_config.mode)
        result._secret_display_mode = display_config.mode.value

        job.result = result
        job.status = "completed"
        job.completed_at = datetime.now(timezone.utc).isoformat()
        job.finding_count = len(result.findings)
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.completed_at = datetime.now(timezone.utc).isoformat()


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "version": "3.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/v1/scan", methods=["POST"])
def start_scan():
    """Start a new scan. Body: {target, enterprise?, threads?, min_confidence?}"""
    body = request.get_json(silent=True) or {}
    target = body.get("target", "").strip()
    if not target:
        return jsonify({"error": "Missing required field: target"}), 400

    target_path = Path(target).resolve()
    if not target_path.exists():
        return jsonify({"error": f"Target not found: {target}"}), 404

    enterprise = body.get("enterprise", False)
    threads = body.get("threads", 4)
    min_confidence = body.get("min_confidence", 0.15)
    secret_display = body.get("secret_display", "smart")

    config = ScanConfig()
    config.min_confidence = min_confidence
    config.max_workers = threads

    job_id = uuid.uuid4().hex[:12]
    job = ScanJob(
        job_id=job_id,
        target=str(target_path),
        enterprise=enterprise,
        started_at=datetime.now(timezone.utc).isoformat(),
        secret_display=secret_display,
    )

    with _history_lock:
        _scan_history[job_id] = job

    thread = threading.Thread(target=_run_scan_job, args=(job, config), daemon=True)
    thread.start()

    return jsonify({
        "job_id": job_id,
        "status": "pending",
        "target": str(target_path),
        "enterprise": enterprise,
    }), 202


@app.route("/api/v1/scan/<job_id>", methods=["GET"])
def get_scan_status(job_id: str):
    """Get scan job status and result."""
    job = _scan_history.get(job_id)
    if not job:
        return jsonify({"error": f"Job {job_id} not found"}), 404

    response = {
        "job_id": job.job_id,
        "status": job.status,
        "target": job.target,
        "enterprise": job.enterprise,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "error": job.error,
        "finding_count": job.finding_count,
    }

    if job.status == "completed" and job.result:
        result = job.result
        response["result"] = {
            "summary": {
                "total_findings": len(result.findings),
                "security_findings": len(result.security_findings),
                "quality_findings": len(result.quality_findings),
                "secret_findings": len(result.secret_findings),
                "risk_score": result.risk_score,
                "grade": result.grade,
                "severity_counts": result.severity_counts,
                "files_scanned": result.files_scanned,
                "lines_scanned": result.lines_scanned,
                "languages": result.languages_detected,
                "scan_duration": round(result.scan_duration, 2),
            },
            "findings": [f.to_dict() for f in result.findings[:200]],
        }
        if hasattr(result, "_enterprise_metrics") and result._enterprise_metrics:
            response["result"]["enterprise_metrics"] = result._enterprise_metrics

    return jsonify(response)


@app.route("/api/v1/findings", methods=["GET"])
def get_findings():
    """Get findings. Query params: job_id, category, severity, min_confidence, limit, offset."""
    job_id = request.args.get("job_id", "")
    if not job_id:
        with _history_lock:
            if _scan_history:
                latest = max(_scan_history.values(), key=lambda j: j.started_at)
                job_id = latest.job_id

    job = _scan_history.get(job_id)
    if not job:
        return jsonify({"error": "No scan found. Provide job_id parameter."}), 404

    if job.status != "completed" or not job.result:
        return jsonify({"error": f"Scan {job_id} not completed (status: {job.status})"}), 400

    category = request.args.get("category", "")
    severity = request.args.get("severity", "")
    min_confidence = float(request.args.get("min_confidence", 0))
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))

    findings = job.result.findings

    if category:
        findings = [f for f in findings if f.category.value == category.lower()]
    if severity:
        findings = [f for f in findings if f.severity.value == severity.lower()]
    if min_confidence > 0:
        findings = [f for f in findings if f.confidence >= min_confidence]

    total = len(findings)
    findings = findings[offset:offset + limit]

    return jsonify({
        "job_id": job_id,
        "total": total,
        "offset": offset,
        "limit": limit,
        "findings": [f.to_dict() for f in findings],
    })


@app.route("/api/v1/report/<job_id>", methods=["GET"])
def get_report(job_id: str):
    """Generate report. Query params: format (json|html|markdown|sarif)."""
    job = _scan_history.get(job_id)
    if not job:
        return jsonify({"error": f"Job {job_id} not found"}), 404
    if job.status != "completed" or not job.result:
        return jsonify({"error": "Scan not completed"}), 400

    fmt = request.args.get("format", "json").lower()
    result = job.result

    if fmt == "json":
        return jsonify(result.to_dict())

    from .reporters import REPORTERS

    reporter_cls = REPORTERS.get(fmt)
    if not reporter_cls:
        return jsonify({"error": f"Unsupported format: {fmt}. Use json, html, markdown, csv, or sarif."}), 400

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

    if fmt in ("json", "sarif"):
        return jsonify(json.loads(content))

    return content, 200, {"Content-Type": content_type}


@app.route("/api/v1/fix", methods=["POST"])
def generate_fixes():
    """Generate fix suggestions. Body: {job_id, finding_ids?}"""
    body = request.get_json(silent=True) or {}
    job_id = body.get("job_id", "")
    finding_ids = body.get("finding_ids", [])

    job = _scan_history.get(job_id)
    if not job:
        return jsonify({"error": f"Job {job_id} not found"}), 404
    if job.status != "completed" or not job.result:
        return jsonify({"error": "Scan not completed"}), 400

    from .core.fix_generator import generate_fix

    fixes = []
    for finding in job.result.findings:
        if finding_ids and finding.rule_id not in finding_ids:
            continue
        fix = generate_fix(
            category=finding.category.value,
            code_snippet=finding.location.code_snippet or "",
        )
        fixes.append({
            "rule_id": finding.rule_id,
            "title": finding.title,
            "file": finding.location.file_path,
            "line": finding.location.line,
            "fixes": [
                {
                    "description": f.description,
                    "before": f.before_code,
                    "after": f.after_code,
                    "effort": f.effort,
                }
                for f in fix
            ],
        })

    return jsonify({"job_id": job_id, "fixes": fixes})


@app.route("/api/v1/history", methods=["GET"])
def get_history():
    """Get scan history. Query params: limit."""
    limit = int(request.args.get("limit", 20))

    with _history_lock:
        jobs = sorted(_scan_history.values(), key=lambda j: j.started_at, reverse=True)

    history = []
    for job in jobs[:limit]:
        history.append({
            "job_id": job.job_id,
            "target": job.target,
            "status": job.status,
            "enterprise": job.enterprise,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "finding_count": job.finding_count,
            "error": job.error,
        })

    return jsonify({"history": history, "total": len(jobs)})


@app.route("/api/v1/stats", methods=["GET"])
def get_stats():
    """Get aggregate statistics across all scans."""
    with _history_lock:
        jobs = list(_scan_history.values())

    total_scans = len(jobs)
    completed = [j for j in jobs if j.status == "completed"]
    failed = [j for j in jobs if j.status == "failed"]
    total_findings = sum(j.finding_count for j in completed)

    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    category_totals: dict[str, int] = {}
    for job in completed:
        if job.result:
            for f in job.result.findings:
                sev = f.severity.value
                severity_totals[sev] = severity_totals.get(sev, 0) + 1
                cat = f.category.value
                category_totals[cat] = category_totals.get(cat, 0) + 1

    return jsonify({
        "total_scans": total_scans,
        "completed_scans": len(completed),
        "failed_scans": len(failed),
        "total_findings": total_findings,
        "severity_totals": severity_totals,
        "category_totals": category_totals,
        "avg_findings_per_scan": round(total_findings / max(len(completed), 1), 1),
    })


def create_app(config: Optional[dict] = None) -> Flask:
    """Create and configure the Flask app."""
    if config:
        app.config.update(config)
    return app


def run_api(host: str = "0.0.0.0", port: int = 8443, debug: bool = False) -> None:
    """Run the REST API server."""
    app.run(host=host, port=port, debug=debug)
