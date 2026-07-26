"""Enhanced JSON report generator with full enriched finding data."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..core.models import FindingCategory, ScanResult, SecretDisplayMode


class JSONReporter:
    name = "json"

    def generate(self, result: ScanResult) -> str:
        secret_display = getattr(result, '_secret_display_mode', 'smart')

        report: dict[str, Any] = {
            "schemaVersion": "2.0.0",
            "tool": {
                "name": "MyScan",
                "version": "2.0.0",
                "enterpriseMode": getattr(result, '_enterprise_mode', False),
            },
            "scan": {
                "startTime": result.scan_start.isoformat() if result.scan_start else None,
                "endTime": result.scan_end.isoformat() if result.scan_end else None,
                "duration": round(result.scan_duration, 2),
                "filesScanned": result.files_scanned,
                "linesScanned": result.lines_scanned,
                "skippedFiles": result.skipped_files,
            },
            "summary": {
                "riskScore": result.risk_score,
                "grade": result.grade,
                "severityCounts": result.severity_counts,
                "totalFindings": len(result.findings),
                "securityFindings": len(result.security_findings),
                "qualityFindings": len(result.quality_findings),
                "secretFindings": len(result.secret_findings),
            },
            "secretDisplayMode": secret_display,
            "languages": result.languages_detected,
            "findings": self._serialize_findings(result),
        }

        if hasattr(result, '_enterprise_metrics'):
            metrics = result._enterprise_metrics
            report["enterprise"] = metrics

        return json.dumps(report, indent=2, default=str)

    def _serialize_findings(self, result: ScanResult) -> list[dict]:
        findings = []
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
            if f.raw_secret:
                finding["rawSecret"] = f.raw_secret

            findings.append(finding)
        return findings
