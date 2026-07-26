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
            "Function", "Code Snippet", "Why Vulnerable", "Impact",
            "Fix Suggestion", "References", "Tags",
        ])
        for f in result.findings:
            writer.writerow([
                f.rule_id, f.title, f.severity.value, f.confidence,
                f.category.value, f.language.value, f.cwe,
                f"{f.owasp.code} - {f.owasp.title}" if f.owasp else "",
                f.cvss.base_score if f.cvss else "",
                f.location.file_path, f.location.line, f.location.function,
                (f.location.code_snippet or "")[:200],
                f.why_vulnerable, f.impact, f.fix_suggestion,
                "; ".join(f.references[:3]), "; ".join(f.tags),
            ])
        return output.getvalue()
