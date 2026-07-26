"""Security vulnerability scanner using rules engine."""

from __future__ import annotations

import re
from typing import Optional

from ..core.models import Finding, FindingCategory, Language, CodeLocation, Severity
from ..core.rules import ALL_RULES, Rule
from ..scanners import BaseScanner


class SecurityScanner(BaseScanner):
    name = "security"
    description = "Pattern-based security vulnerability scanner"

    def __init__(self):
        self.rules = [r for r in ALL_RULES if r.category == FindingCategory.SECURITY]

    def scan_file(self, content: str, file_path: str, language: Language) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for rule in self.rules:
            if rule.languages and language not in rule.languages:
                continue
            if not rule.pattern:
                continue
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue

            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue
                if stripped.startswith("*") or stripped.startswith("/*"):
                    continue
                match = pattern.search(line)
                if match:
                    snippet = self._get_context(lines, i - 1)
                    function_name = self._extract_function(lines, i - 1)
                    cvss = rule.get_cvss() if rule.cvss_config else None
                    finding = Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        description=rule.description,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        category=FindingCategory.SECURITY,
                        language=language,
                        location=CodeLocation(
                            file_path=file_path,
                            line=i,
                            function=function_name,
                            code_snippet=snippet,
                        ),
                        cwe=rule.cwe,
                        cwe_name=rule.cwe_name,
                        owasp=rule.owasp,
                        cvss=cvss,
                        fix_suggestion=rule.fix_suggestion,
                        references=rule.references,
                        impact=rule.impact,
                        why_vulnerable=self._explain(rule, snippet),
                        tags=rule.tags,
                    )
                    findings.append(finding)

        return findings

    def _get_context(self, lines: list[str], idx: int, context: int = 2) -> str:
        start = max(0, idx - context)
        end = min(len(lines), idx + context + 1)
        return "\n".join(lines[start:end])

    def _extract_function(self, lines: list[str], idx: int) -> str:
        for i in range(idx, max(0, idx - 30), -1):
            line = lines[i].strip()
            m = re.match(r'(?:def|function|func|fn|public|private|protected|static)\s+(\w+)', line)
            if m:
                return m.group(1)
        return ""

    def _explain(self, rule: Rule, snippet: str) -> str:
        short_snippet = snippet.split("\n")[-1].strip()[:100] if snippet else "matched pattern"
        return f"{rule.title}: The code `{short_snippet}` {rule.description.lower()}"
