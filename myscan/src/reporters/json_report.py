"""Enhanced JSON report generator with full enriched finding data."""

from __future__ import annotations

import json
from typing import Any

from ..__init__ import __version__
from ..core.models import ScanResult
from ..core.secret_display import (
    SecretDisplayConfig,
    SecretDisplayMode,
    get_secret_display_value,
    mask_secret,
)


class JSONReporter:
    name = "json"

    def generate(self, result: ScanResult) -> str:
        secret_display = getattr(result, '_secret_display_mode', 'smart')

        report: dict[str, Any] = {
            "schemaVersion": "3.0.0",
            "tool": {
                "name": "CodeWatch",
                "version": __version__,
                "enterpriseMode": getattr(result, '_enterprise_mode', False),
            },
            "scan": {
                "startTime": result.scan_start.isoformat() if result.scan_start else None,
                "endTime": result.scan_end.isoformat() if result.scan_end else None,
                "duration": round(result.scan_duration, 2),
                "filesScanned": result.files_scanned,
                "linesScanned": result.lines_scanned,
                "skippedFiles": result.skipped_files,
                "rulesExecuted": getattr(result, "rules_executed", 0),
                "repository": getattr(result, "repository", ""),
                "branch": getattr(result, "branch", ""),
                "commit": getattr(result, "commit", ""),
                "target": getattr(result, "target", ""),
                "repositorySizeBytes": getattr(result, "repo_size_bytes", 0),
            },
            "summary": {
                "riskScore": result.risk_score,
                "grade": result.grade,
                "severityCounts": result.severity_counts,
                "totalFindings": len(result.findings),
                "securityFindings": len(result.security_findings),
                "qualityFindings": len(result.quality_findings),
                "secretFindings": len(result.secret_findings),
                "dependencyFindings": len(result.dependency_findings),
            },
            "secretDisplayMode": secret_display,
            "languages": result.languages_detected,
            "findings": self._serialize_findings(result, secret_display),
        }

        if hasattr(result, '_enterprise_metrics'):
            metrics = result._enterprise_metrics
            report["enterprise"] = metrics

        return json.dumps(report, indent=2, default=str)

    def _serialize_findings(self, result: ScanResult, secret_display: str) -> list[dict]:
        findings = []
        display_mode = SecretDisplayConfig.from_string(secret_display).mode
        for f in result.findings:
            finding: dict[str, Any] = {
                "ruleId": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "confidence": round(f.confidence, 2),
                "category": f.category.value,
                "language": f.language.value,
                "fingerprint": f.fingerprint,
                "location": {
                    "file": f.location.file_path,
                    "line": f.location.line,
                    "endLine": f.location.end_line,
                    "column": f.location.column,
                    "function": f.location.function,
                    "class": f.location.class_name,
                },
            }

            if f.location.code_snippet:
                finding["codeSnippet"] = f.location.code_snippet
            finding["occurrences"] = f.occurrences
            if len(f.locations) > 1:
                finding["locations"] = f.locations
            if f.evidence:
                finding["evidence"] = f.evidence
            if f.state:
                finding["state"] = f.state
            if f.cwe:
                finding["cwe"] = {"id": f.cwe, "name": f.cwe_name}
            if f.owasp:
                finding["owasp"] = {"code": f.owasp.code, "title": f.owasp.title}
            if f.cvss and f.cvss.base_score > 0:
                finding["cvss"] = {
                    "score": f.cvss.base_score,
                    "vector": f.cvss.vector,
                    "severity": f.cvss.severity.value,
                }
            if f.fix_suggestion:
                finding["fixSuggestion"] = f.fix_suggestion
            if f.fixed_code:
                finding["fixedCode"] = f.fixed_code
            if f.why_vulnerable:
                finding["explanation"] = f.why_vulnerable
            if f.impact:
                finding["impact"] = f.impact
            if f.exploit_scenario:
                finding["exploitScenario"] = f.exploit_scenario
            if f.confidence_reasoning:
                finding["confidenceReasoning"] = f.confidence_reasoning
            if f.references:
                finding["references"] = f.references
            if f.tags:
                finding["tags"] = f.tags
            if f.is_false_positive:
                finding["isFalsePositive"] = True
            if f.raw_secret and secret_display == "full":
                finding["rawSecret"] = f.raw_secret

            if f.raw_secret:
                if display_mode == SecretDisplayMode.FULL:
                    display_value = f.raw_secret
                elif f.category.value == "secret":
                    display_value = get_secret_display_value(f, display_mode)
                else:
                    display_value = mask_secret(f.raw_secret)
                finding = _replace_secret_text(finding, f.raw_secret, display_value)

            findings.append(finding)
        return findings


def _replace_secret_text(value: Any, secret: str, replacement: str) -> Any:
    if isinstance(value, str):
        return value.replace(secret, replacement)
    if isinstance(value, list):
        return [_replace_secret_text(item, secret, replacement) for item in value]
    if isinstance(value, dict):
        return {
            key: _replace_secret_text(item, secret, replacement)
            for key, item in value.items()
        }
    return value
