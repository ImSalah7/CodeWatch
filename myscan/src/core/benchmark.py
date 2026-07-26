"""Benchmark Mode for MyScan.

Compares MyScan results against other SAST tools (Semgrep, Bandit).
Works by running MyScan and optionally external tools, then comparing
finding overlap, false positive estimates, unique findings, and coverage.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ToolResult:
    tool_name: str
    findings: list[dict]
    scan_duration: float = 0.0
    error: str = ""
    file_count: int = 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool_name,
            "finding_count": self.finding_count,
            "scan_duration": round(self.scan_duration, 2),
            "file_count": self.file_count,
            "error": self.error,
        }


@dataclass
class BenchmarkComparison:
    myscan_result: Optional[ToolResult] = None
    external_results: dict[str, ToolResult] = field(default_factory=dict)
    overlap: dict[str, list[dict]] = field(default_factory=dict)
    unique_per_tool: dict[str, list[dict]] = field(default_factory=dict)
    metrics: dict[str, dict] = field(default_factory=dict)
    target: str = ""
    duration: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "duration": round(self.duration, 2),
            "myscan": self.myscan_result.to_dict() if self.myscan_result else None,
            "external_tools": {
                name: r.to_dict() for name, r in self.external_results.items()
            },
            "overlap": {
                tool: len(findings) for tool, findings in self.overlap.items()
            },
            "unique_findings": {
                tool: len(findings) for tool, findings in self.unique_per_tool.items()
            },
            "metrics": self.metrics,
        }


def _normalize_file_path(path: str) -> str:
    """Normalize file path for comparison across tools."""
    path = path.replace("\\", "/")
    for prefix in ("./", "../"):
        while path.startswith(prefix):
            path = path[len(prefix):]
    return path


def _normalize_finding_key(finding: dict) -> str:
    """Create a normalized key for deduplication/comparison."""
    file_path = _normalize_file_path(
        finding.get("file", "")
        or finding.get("file_path", "")
        or finding.get("path", "")
        or finding.get("filename", "")
    )
    line = finding.get("line", 0) or finding.get("line_number", 0) or finding.get("start_line", 0)
    rule = (
        finding.get("rule_id", "")
        or finding.get("check_id", "")
        or finding.get("rule", "")
        or finding.get("id", "")
    )
    return f"{file_path}:{line}:{rule}"


def _normalize_severity(sev: str) -> str:
    """Normalize severity across tools."""
    sev = sev.lower().strip()
    if sev in ("error", "c", "blocker", "critical"):
        return "critical"
    if sev in ("warning", "b", "high", "major"):
        return "high"
    if sev in ("note", "a", "medium", "minor", "moderate"):
        return "medium"
    if sev in ("info", "d", "low", " suggestion"):
        return "low"
    return "info"


def _run_semgrep(target: str) -> ToolResult:
    """Run semgrep and parse results."""
    start = time.time()
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        proc = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--output", tmp_path, target],
            capture_output=True,
            text=True,
            timeout=300,
        )

        with open(tmp_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        os.unlink(tmp_path)

        findings = []
        for r in data.get("results", []):
            findings.append({
                "rule_id": r.get("check_id", ""),
                "file": _normalize_file_path(r.get("path", "")),
                "line": r.get("start", {}).get("line", 0),
                "severity": _normalize_severity(r.get("extra", {}).get("severity", "WARNING")),
                "message": r.get("extra", {}).get("message", ""),
            })

        return ToolResult(
            tool_name="semgrep",
            findings=findings,
            scan_duration=time.time() - start,
            file_count=len({f["file"] for f in findings}),
        )
    except FileNotFoundError:
        return ToolResult(tool_name="semgrep", findings=[], error="semgrep not installed")
    except subprocess.TimeoutExpired:
        return ToolResult(tool_name="semgrep", findings=[], error="semgrep timed out")
    except Exception as e:
        return ToolResult(tool_name="semgrep", findings=[], error=str(e))


def _run_bandit(target: str) -> ToolResult:
    """Run bandit and parse results."""
    start = time.time()
    try:
        proc = subprocess.run(
            ["bandit", "-r", target, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=300,
        )

        data = json.loads(proc.stdout) if proc.stdout else {}

        findings = []
        for r in data.get("results", []):
            findings.append({
                "rule_id": r.get("test_id", ""),
                "file": _normalize_file_path(r.get("filename", "")),
                "line": r.get("line_number", 0),
                "severity": _normalize_severity(r.get("issue_severity", "MEDIUM")),
                "message": r.get("issue_text", ""),
            })

        return ToolResult(
            tool_name="bandit",
            findings=findings,
            scan_duration=time.time() - start,
            file_count=len({f["file"] for f in findings}),
        )
    except FileNotFoundError:
        return ToolResult(tool_name="bandit", findings=[], error="bandit not installed")
    except subprocess.TimeoutExpired:
        return ToolResult(tool_name="bandit", findings=[], error="bandit timed out")
    except Exception as e:
        return ToolResult(tool_name="bandit", findings=[], error=str(e))


def _run_myscan(target: str, enterprise: bool = False) -> ToolResult:
    """Run MyScan and parse results."""
    start = time.time()
    try:
        from .config import ScanConfig
        from .engine import ScanEngine

        config = ScanConfig()
        engine = ScanEngine(config, enterprise_mode=enterprise)
        result = engine.scan(target)

        findings = []
        for f in result.findings:
            findings.append({
                "rule_id": f.rule_id,
                "file": _normalize_file_path(f.location.file_path),
                "line": f.location.line,
                "severity": f.severity.value,
                "message": f.title,
                "confidence": f.confidence,
                "category": f.category.value,
            })

        return ToolResult(
            tool_name="myscan",
            findings=findings,
            scan_duration=time.time() - start,
            file_count=result.files_scanned,
        )
    except Exception as e:
        return ToolResult(tool_name="myscan", findings=[], error=str(e))


def _compute_overlap(result_a: ToolResult, result_b: ToolResult) -> list[dict]:
    """Find findings that appear in both tools (by file+line)."""
    keys_a = {_normalize_finding_key(f): f for f in result_a.findings}
    keys_b = {_normalize_finding_key(f): f for f in result_b.findings}
    common_keys = set(keys_a.keys()) & set(keys_b.keys())
    return [{"key": k, "myscan": keys_a.get(k, {}), "external": keys_b.get(k, {})} for k in common_keys]


def _compute_unique(result_a: ToolResult, result_b: ToolResult) -> list[dict]:
    """Find findings unique to result_a."""
    keys_a = {_normalize_finding_key(f): f for f in result_a.findings}
    keys_b = {_normalize_finding_key(f): f for f in result_b.findings}
    unique_keys = set(keys_a.keys()) - set(keys_b.keys())
    return [keys_a[k] for k in unique_keys]


def _compute_metrics(
    myscan: ToolResult,
    external: ToolResult,
    overlap: list[dict],
) -> dict:
    """Compute precision/recall/coverage metrics."""
    ms_count = myscan.finding_count
    ext_count = external.finding_count
    overlap_count = len(overlap)

    precision_est = overlap_count / max(ms_count, 1)
    recall_est = overlap_count / max(ext_count, 1)
    f1_est = (
        2 * precision_est * recall_est / max(precision_est + recall_est, 0.001)
    )

    ms_files = set()
    for f in myscan.findings:
        ms_files.add(_normalize_file_path(f.get("file", "")))
    ext_files = set()
    for f in external.findings:
        ext_files.add(_normalize_file_path(f.get("file", "")))

    file_overlap = len(ms_files & ext_files)
    file_coverage_est = file_overlap / max(len(ext_files), 1)

    return {
        "myscan_findings": ms_count,
        "external_findings": ext_count,
        "overlap": overlap_count,
        "unique_to_myscan": ms_count - overlap_count,
        "unique_to_external": ext_count - overlap_count,
        "estimated_precision": round(precision_est, 3),
        "estimated_recall": round(recall_est, 3),
        "estimated_f1": round(f1_est, 3),
        "file_coverage": round(file_coverage_est, 3),
        "myscan_files": len(ms_files),
        "external_files": len(ext_files),
        "shared_files": file_overlap,
        "myscan_scan_time": round(myscan.scan_duration, 2),
        "external_scan_time": round(external.scan_duration, 2),
    }


def run_benchmark(
    target: str,
    enterprise: bool = False,
    tools: Optional[list[str]] = None,
) -> BenchmarkComparison:
    """Run a full benchmark comparing MyScan against external tools.

    Args:
        target: Path or URL to scan
        enterprise: Whether to use MyScan enterprise mode
        tools: List of external tools to compare (default: ["semgrep", "bandit"])

    Returns:
        BenchmarkComparison with all results and metrics
    """
    start = time.time()
    if tools is None:
        tools = ["semgrep", "bandit"]

    myscan_result = _run_myscan(target, enterprise=enterprise)

    external_results: dict[str, ToolResult] = {}
    tool_runners = {
        "semgrep": _run_semgrep,
        "bandit": _run_bandit,
    }

    for tool in tools:
        if tool in tool_runners:
            external_results[tool] = tool_runners[tool](target)

    overlap: dict[str, list[dict]] = {}
    unique_per_tool: dict[str, list[dict]] = {}
    metrics: dict[str, dict] = {}

    for tool_name, ext_result in external_results.items():
        if ext_result.finding_count > 0 or myscan_result.finding_count > 0:
            overlap[tool_name] = _compute_overlap(myscan_result, ext_result)
            unique_per_tool[f"myscan_only_vs_{tool_name}"] = _compute_unique(myscan_result, ext_result)
            unique_per_tool[f"{tool_name}_only"] = _compute_unique(ext_result, myscan_result)
            metrics[tool_name] = _compute_metrics(myscan_result, ext_result, overlap[tool_name])

    return BenchmarkComparison(
        myscan_result=myscan_result,
        external_results=external_results,
        overlap=overlap,
        unique_per_tool=unique_per_tool,
        metrics=metrics,
        target=target,
        duration=time.time() - start,
    )
