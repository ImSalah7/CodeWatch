"""Smart Deduplication Engine.

Reduces noise by grouping similar findings and reporting them once:
- Same secret found 15x → report once with 14 references
- Same pattern across similar lines → consolidate
- Groups by: rule_id + file_category + normalized_code + value_hash
- Keeps highest severity instance, references rest
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field


@dataclass
class FindingReference:
    """Reference to a duplicated finding location."""
    file_path: str
    line_number: int
    column: int = 0
    context: str = ""


@dataclass
class DeduplicatedFinding:
    """A deduplicated finding with references to all locations."""
    finding_id: str
    rule_id: str
    message: str
    severity: str
    category: str
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    references: list[FindingReference] = field(default_factory=list)
    duplicate_count: int = 1
    group_hash: str = ""
    confidence: float = 0.5
    cvss_score: float = 0.0
    fix_suggestion: str = ""
    references_urls: list[str] = field(default_factory=list)


def _normalize_code(code: str) -> str:
    """Normalize code for comparison by removing whitespace and variable names."""
    normalized = re.sub(r'\s+', ' ', code.strip())
    normalized = re.sub(r'["\'].*?["\']', 'VALUE', normalized)
    normalized = re.sub(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', 'IDENT', normalized)
    return normalized


def _normalize_secret_value(value: str) -> str:
    """Normalize a secret value for deduplication."""
    value = re.sub(r'[A-Za-z]', 'L', value)
    value = re.sub(r'\d', 'D', value)
    return value


def _generate_group_hash(
    rule_id: str,
    message: str,
    file_path: str,
    code_snippet: str = "",
    value: str = "",
) -> str:
    """Generate a hash for grouping similar findings."""
    parts = [rule_id]

    normalized_msg = re.sub(r'["\'].*?["\']', 'VALUE', message)
    normalized_msg = re.sub(r'["\'].*?["\']', 'VALUE', normalized_msg)
    parts.append(normalized_msg)

    if value:
        norm_val = _normalize_secret_value(value)
        parts.append(norm_val)
    elif code_snippet:
        norm_code = _normalize_code(code_snippet)
        parts.append(norm_code)

    combined = "|".join(parts)
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def deduplicate_findings(findings: list) -> list[DeduplicatedFinding]:
    """Deduplicate a list of findings, grouping similar ones together."""
    if not findings:
        return []

    groups: dict[str, list] = {}

    for finding in findings:
        rule_id = getattr(finding, 'rule_id', '')
        message = getattr(finding, 'message', '')
        file_path = getattr(finding, 'file_path', '')
        code_snippet = getattr(finding, 'code_snippet', '') if hasattr(finding, 'code_snippet') else ""
        value = getattr(finding, 'value', '') if hasattr(finding, 'value') else ""

        group_hash = _generate_group_hash(rule_id, message, file_path, code_snippet, value)

        if group_hash not in groups:
            groups[group_hash] = []
        groups[group_hash].append(finding)

    deduplicated = []
    for group_hash, group_findings in groups.items():
        primary = _select_primary_finding(group_findings)

        references = []
        for f in group_findings:
            if f is primary:
                continue
            references.append(FindingReference(
                file_path=getattr(f, 'file_path', ''),
                line_number=getattr(f, 'line_number', 0),
                column=getattr(f, 'column', 0) if hasattr(f, 'column') else 0,
                context=getattr(f, 'code_snippet', '') if hasattr(f, 'code_snippet') else "",
            ))

        dedup = DeduplicatedFinding(
            finding_id=getattr(primary, 'finding_id', ''),
            rule_id=getattr(primary, 'rule_id', ''),
            message=getattr(primary, 'message', ''),
            severity=getattr(primary, 'severity', ''),
            category=getattr(primary, 'category', '') if hasattr(primary, 'category') else '',
            file_path=getattr(primary, 'file_path', ''),
            line_number=getattr(primary, 'line_number', 0),
            column=getattr(primary, 'column', 0) if hasattr(primary, 'column') else 0,
            code_snippet=getattr(primary, 'code_snippet', '') if hasattr(primary, 'code_snippet') else "",
            references=references,
            duplicate_count=len(group_findings),
            group_hash=group_hash,
            confidence=getattr(primary, 'confidence', 0.5) if hasattr(primary, 'confidence') else 0.5,
            cvss_score=getattr(primary, 'cvss_score', 0.0) if hasattr(primary, 'cvss_score') else 0.0,
            fix_suggestion=getattr(primary, 'fix_suggestion', '') if hasattr(primary, 'fix_suggestion') else "",
            references_urls=getattr(primary, 'references', []) if hasattr(primary, 'references') else [],
        )
        deduplicated.append(dedup)

    return deduplicated


def _select_primary_finding(findings: list):
    """Select the primary (most important) finding from a group."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    best = findings[0]
    best_severity = severity_order.get(getattr(best, 'severity', 'INFO').upper(), 4)

    for f in findings[1:]:
        f_severity = severity_order.get(getattr(f, 'severity', 'INFO').upper(), 4)
        if f_severity < best_severity:
            best = f
            best_severity = f_severity

    return best


def format_dedup_summary(findings: list[DeduplicatedFinding]) -> str:
    """Format a human-readable summary of deduplicated findings."""
    total_dupes = sum(f.duplicate_count - 1 for f in findings)
    lines = [
        f"Found {len(findings)} unique findings",
        f"Consolidated {total_dupes} duplicate occurrences",
    ]
    by_severity = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    lines.extend(
        f"  {sev}: {by_severity[sev]}"
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        if sev in by_severity
    )
    return "\n".join(lines)
