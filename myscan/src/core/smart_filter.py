"""Smart filtering to reduce false positives."""

from __future__ import annotations

import re
from ..core.config import ScanConfig
from ..core.models import Finding, Severity, FindingCategory


FALSE_POSITIVE_PATTERNS = [
    (r"(?i)(?:localhost|127\.0\.0\.1|0\.0\.0\.0)", Severity.INFO, "Hardcoded localhost is not a real vulnerability"),
    (r"(?i)(?:development|dev|test|staging|example)", Severity.INFO, "Development/example code"),
    (r"(?i)(?:placeholder|sample|dummy|mock|fake)", Severity.INFO, "Placeholder content"),
    (r"(?:TODO|FIXME|HACK|XXX|TEMP)\b", Severity.INFO, "TODO/comment marker, not code"),
]

QUALITY_IN_SECURITY = {
    "long_line", "commented_code", "console_log", "var_declaration",
    "deep_nesting", "magic_number", "todo_fixme_hack", "print_debug",
}


class SmartFilter:
    def __init__(self, config: ScanConfig):
        self.config = config

    def is_false_positive(self, finding: Finding) -> bool:
        if finding.location.file_path.upper().endswith((".MD", ".RST", ".TXT", ".JSON")):
            if finding.category == FindingCategory.SECURITY:
                return True
        code = finding.location.code_snippet or ""
        title_lower = finding.title.lower()
        file_lower = finding.location.file_path.lower()

        if "readme" in file_lower or "docs/" in file_lower or "example" in file_lower:
            if finding.category == FindingCategory.SECURITY:
                return True
        for pattern, sev, reason in FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, code):
                if finding.severity.numeric >= sev.numeric:
                    finding.confidence_reasoning = f"Reduced confidence: {reason}"
                    finding.confidence *= 0.3
                    if finding.confidence < 0.3:
                        finding.is_false_positive = True
                        return True
        if finding.severity == Severity.HIGH and finding.confidence < 0.5:
            finding.severity = Severity.MEDIUM
        if finding.severity == Severity.CRITICAL and finding.confidence < 0.5:
            finding.severity = Severity.HIGH
        if "test" in file_lower and finding.category == FindingCategory.SECURITY:
            finding.confidence *= 0.5
            finding.confidence_reasoning = "Found in test file, reduced confidence"
        return False

    def should_include_finding(self, finding: Finding) -> bool:
        threshold = Severity(self.config.severity_threshold) if self.config.severity_threshold else Severity.INFO
        return finding.severity.numeric >= threshold.numeric

    def filter_findings(self, findings: list[Finding]) -> list[Finding]:
        result = []
        for f in findings:
            self.is_false_positive(f)
            if not f.is_false_positive and self.should_include_finding(f):
                result.append(f)
        return result
