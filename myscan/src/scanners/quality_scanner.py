"""Code quality scanner."""

from __future__ import annotations

import re
from ..core.models import Finding, FindingCategory, Language, CodeLocation, Severity
from ..core.rules import ALL_RULES
from ..scanners import BaseScanner


class QualityScanner(BaseScanner):
    name = "quality"
    description = "Code quality and maintainability scanner"

    def __init__(self):
        self.rules = [r for r in ALL_RULES if r.category == FindingCategory.QUALITY]

    def scan_file(self, content: str, file_path: str, language: Language) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        findings.extend(self._check_line_length(lines, file_path, language))
        findings.extend(self._check_nesting(lines, file_path, language))
        findings.extend(self._check_pattern_rules(lines, file_path, language))
        findings.extend(self._check_duplicate_patterns(lines, file_path, language))

        return findings

    def _check_line_length(self, lines: list[str], file_path: str, lang: Language) -> list[Finding]:
        findings = []
        rule = next((r for r in self.rules if r.id == "QLT001"), None)
        if not rule:
            return findings
        long_count = 0
        for i, line in enumerate(lines, 1):
            if len(line) > 120:
                long_count += 1
                if long_count <= 3:
                    findings.append(Finding(
                        rule_id="QLT001",
                        title=rule.title,
                        description=f"Line is {len(line)} characters long (max 120).",
                        severity=rule.severity,
                        confidence=1.0,
                        category=FindingCategory.QUALITY,
                        language=lang,
                        location=CodeLocation(file_path=file_path, line=i, code_snippet=line[:150]),
                        tags=rule.tags,
                    ))
        if long_count > 3:
            findings.append(Finding(
                rule_id="QLT001",
                title=f"{long_count} Long Lines Total",
                description=f"File has {long_count} lines exceeding 120 characters.",
                severity=Severity.INFO,
                confidence=1.0,
                category=FindingCategory.QUALITY,
                language=lang,
                location=CodeLocation(file_path=file_path, line=1),
                tags=rule.tags,
            ))
        return findings

    def _check_nesting(self, lines: list[str], file_path: str, lang: Language) -> list[Finding]:
        findings = []
        rule = next((r for r in self.rules if r.id == "QLT006"), None)
        if not rule:
            return findings
        max_depth = 0
        max_line = 0
        for i, line in enumerate(lines, 1):
            if not line.strip():
                continue
            depth = (len(line) - len(line.lstrip())) // 4
            if depth > max_depth:
                max_depth = depth
                max_line = i
        if max_depth > 4:
            findings.append(Finding(
                rule_id="QLT006",
                title=rule.title,
                description=f"Maximum nesting depth is {max_depth} levels at line {max_line}.",
                severity=rule.severity,
                confidence=0.9,
                category=FindingCategory.QUALITY,
                language=lang,
                location=CodeLocation(file_path=file_path, line=max_line),
                fix_suggestion=rule.fix_suggestion,
                tags=rule.tags,
            ))
        return findings

    def _check_pattern_rules(self, lines: list[str], file_path: str, lang: Language) -> list[Finding]:
        findings = []
        for rule in self.rules:
            if not rule.pattern:
                continue
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        description=rule.description,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        category=FindingCategory.QUALITY,
                        language=lang,
                        location=CodeLocation(
                            file_path=file_path,
                            line=i,
                            code_snippet=stripped[:120],
                        ),
                        fix_suggestion=rule.fix_suggestion,
                        impact=rule.impact,
                        tags=rule.tags,
                    ))
                    break
        return findings

    def _check_duplicate_patterns(self, lines: list[str], file_path: str, lang: Language) -> list[Finding]:
        findings = []
        blocks: dict[str, int] = {}
        min_lines = 3
        for i in range(0, len(lines) - min_lines + 1):
            block = "\n".join(l.strip() for l in lines[i:i + min_lines] if l.strip())
            if len(block) > 30:
                if block in blocks:
                    findings.append(Finding(
                        rule_id="QLT008",
                        title="Duplicate Code Block",
                        description=f"Same code block appears at line {blocks[block]} and line {i + 1}.",
                        severity=Severity.LOW,
                        confidence=0.7,
                        category=FindingCategory.QUALITY,
                        language=lang,
                        location=CodeLocation(file_path=file_path, line=i + 1, code_snippet=block[:120]),
                        fix_suggestion="Extract into a shared function.",
                        tags=["duplication"],
                    ))
                    break
                blocks[block] = i + 1
        return findings
