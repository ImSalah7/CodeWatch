"""CSV report generator."""

from __future__ import annotations

import csv
import io

from ..core.models import ScanResult


class CSVReporter:
    name = "csv"

    def generate(self, result: ScanResult) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Rule ID", "Title", "Severity", "Confidence", "Category",
            "Language", "CWE", "OWASP", "CVSS Score", "File", "Line",
            "Function", "Code Snippet", "Evidence", "Root Cause",
            "Why Vulnerable", "Impact", "Exploit Scenario",
            "Fix Suggestion", "Fixed Code", "References", "Tags",
            "Occurrences", "False Positive", "Suppressed", "Assignee", "Issue URL",
        ])
        for f in result.findings:
            evidence = "; ".join(
                e.get("detail", "") for e in f.evidence
            ) if f.evidence else ""
            writer.writerow([
                f.rule_id, f.title, f.severity.value, f.confidence,
                f.category.value, f.language.value, f.cwe,
                f"{f.owasp.code} - {f.owasp.title}" if f.owasp else "",
                f.cvss.base_score if f.cvss else "",
                f.location.file_path, f.location.line, f.location.function,
                (f.location.code_snippet or "")[:200],
                evidence,
                getattr(f, "root_cause", "") or "",
                f.why_vulnerable, f.impact, f.exploit_scenario,
                f.fix_suggestion, (f.fixed_code or "")[:200],
                "; ".join(f.references), "; ".join(f.tags),
                f.occurrences,
                "yes" if f.is_false_positive else "no",
                "yes" if f.state.get("suppressed") else "no",
                f.state.get("assignee", ""),
                f.state.get("issue_url", ""),
            ])
        return output.getvalue()
