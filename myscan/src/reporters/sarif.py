"""Enhanced SARIF report generator with taint paths, confidence, CVSS vectors, and code locations."""

from __future__ import annotations

import json
from typing import Any

from ..__init__ import __version__
from ..core.models import ScanResult


class SARIFReporter:
    name = "sarif"

    def generate(self, result: ScanResult) -> str:
        sarif: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "MyScan",
                        "version": __version__,
                        "informationUri": "https://github.com/myscan/myscan",
                        "rules": self._extract_rules(result),
                        "properties": {
                            "scanMode": getattr(result, '_enterprise_mode', False) and "enterprise" or "standard",
                            "totalFindings": len(result.findings),
                            "filesScanned": result.files_scanned,
                            "linesScanned": result.lines_scanned,
                            "scanDuration": result.scan_duration,
                            "riskScore": result.risk_score,
                            "grade": result.grade,
                            "repository": getattr(result, 'repository', '') or '',
                            "branch": getattr(result, 'branch', '') or '',
                            "commit": getattr(result, 'commit', '') or '',
                            "target": getattr(result, 'target', '') or '',
                            "rulesExecuted": getattr(result, 'rules_executed', 0),
                            "occurrencesTotal": getattr(result, 'occurrences_total', len(result.findings)),
                        },
                    }
                },
                "results": self._extract_results(result),
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": result.scan_start.isoformat() if result.scan_start else "",
                    "endTimeUtc": result.scan_end.isoformat() if result.scan_end else "",
                    "process": {"processId": 0},
                    "properties": {
                        "scanDuration": result.scan_duration,
                        "filesScanned": result.files_scanned,
                        "linesScanned": result.lines_scanned,
                        "rulesExecuted": getattr(result, 'rules_executed', 0),
                        "repository": getattr(result, 'repository', '') or '',
                        "branch": getattr(result, 'branch', '') or '',
                        "commit": getattr(result, 'commit', '') or '',
                    },
                }],
            }],
        }
        return json.dumps(sarif, indent=2, default=str)

    def _extract_rules(self, result: ScanResult) -> list[dict]:
        rule_ids: dict[str, dict] = {}
        for f in result.findings:
            if f.rule_id not in rule_ids:
                rule: dict[str, Any] = {
                    "id": f.rule_id,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": self._severity_to_level(f.severity.value),
                    },
                    "properties": {},
                }
                if f.cwe:
                    cwe_num = f.cwe.replace("CWE-", "")
                    rule["properties"]["tags"] = [f.cwe, f"external/cwe/cwe-{cwe_num}"]
                    rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                if f.owasp:
                    rule["properties"]["owasp"] = f"{f.owasp.code}: {f.owasp.title}"
                if f.cvss and f.cvss.base_score > 0:
                    rule["properties"]["cvssScore"] = f.cvss.base_score
                    rule["properties"]["cvssVector"] = f.cvss.vector
                rule["properties"]["confidence"] = f.confidence
                rule["properties"]["category"] = f.category.value
                if f.fix_suggestion:
                    rule["properties"]["fixSuggestions"] = [f.fix_suggestion]
                rule_ids[f.rule_id] = rule
        return list(rule_ids.values())

    def _extract_results(self, result: ScanResult) -> list[dict]:
        results = []
        for f in result.findings:
            level = self._severity_to_level(f.severity.value)
            r: dict[str, Any] = {
                "ruleId": f.rule_id,
                "message": {"text": self._build_message(f)},
                "level": level,
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location.file_path, "uriBaseId": "%SRCROOT%"},
                        "region": {
                            "startLine": f.location.line,
                            "startColumn": f.location.column or 1,
                            "endLine": f.location.end_line,
                        },
                    }
                }],
                "fingerprints": {"primaryLocationLineHash": f.fingerprint},
                "properties": {
                    "severity": f.severity.value,
                    "confidence": round(f.confidence, 2),
                    "category": f.category.value,
                    "language": f.language.value,
                },
            }

            if f.cwe:
                r["properties"]["cwe"] = f.cwe
            if f.owasp:
                r["properties"]["owasp"] = f"{f.owasp.code}: {f.owasp.title}"
            if f.cvss and f.cvss.base_score > 0:
                r["properties"]["cvssScore"] = f.cvss.base_score
                r["properties"]["cvssVector"] = f.cvss.vector
                r["properties"]["cvssSeverity"] = f.cvss.severity.value
            if f.fix_suggestion:
                r["properties"]["fixSuggestion"] = f.fix_suggestion
            if f.why_vulnerable:
                r["properties"]["explanation"] = f.why_vulnerable
            if f.impact:
                r["properties"]["impact"] = f.impact
            if f.exploit_scenario:
                r["properties"]["exploitScenario"] = f.exploit_scenario
            if f.location.code_snippet:
                r["properties"]["codeSnippet"] = f.location.code_snippet[:1000]
            if f.confidence_reasoning:
                r["properties"]["confidenceReasoning"] = f.confidence_reasoning
            if f.references:
                r["properties"]["references"] = f.references[:5]
            if f.occurrences > 1:
                r["properties"]["occurrences"] = f.occurrences
            if f.locations and len(f.locations) > 1:
                r["properties"]["additionalLocations"] = [
                    {
                        "uri": loc.get("file_path", ""),
                        "line": loc.get("line"),
                        "endLine": loc.get("end_line"),
                    }
                    for loc in f.locations[1:]
                ]
            if f.evidence:
                r["properties"]["evidence"] = [
                    {
                        "type": e.get("type", ""),
                        "detail": e.get("detail", ""),
                        "matched": e.get("matched", ""),
                        "line": e.get("line"),
                    }
                    for e in f.evidence
                ]
            if getattr(f, "state", None):
                r["properties"]["state"] = {
                    k: v for k, v in f.state.items() if v is not None
                }

            results.append(r)
        return results

    def _build_message(self, f) -> str:
        parts = [f.description]
        if f.why_vulnerable:
            parts.append(f"Why: {f.why_vulnerable}")
        if f.fix_suggestion:
            parts.append(f"Fix: {f.fix_suggestion}")
        return " ".join(parts)

    def _severity_to_level(self, severity: str) -> str:
        return {
            "critical": "error", "high": "error",
            "medium": "warning", "low": "note", "info": "note",
        }.get(severity, "note")
