"""Reconstruct core model objects from persisted JSON.

Used to regenerate reports for scans that were loaded back from the database
after a process restart, where only the serialized ``result.to_dict()`` payload
is available.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .core.models import (
    CVSS,
    CodeLocation,
    Finding,
    FindingCategory,
    Language,
    OWASPTop10,
    ScanResult,
    Severity,
)


def _severity(value) -> Severity:
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.INFO


def _category(value) -> FindingCategory:
    if isinstance(value, FindingCategory):
        return value
    try:
        return FindingCategory(str(value).lower())
    except ValueError:
        return FindingCategory.SECURITY


def _language(value) -> Language:
    if isinstance(value, Language):
        return value
    try:
        return Language(str(value).lower())
    except ValueError:
        return Language.UNKNOWN


def _owasp_from_code(code: Optional[str]) -> Optional[OWASPTop10]:
    if not code:
        return None
    for member in OWASPTop10:
        if member.code == code:
            return member
    return None


def finding_from_dict(d: dict) -> Finding:
    """Rebuild a Finding dataclass from a ``to_dict()`` payload."""
    loc = d.get("location", {}) or {}
    location = CodeLocation(
        file_path=loc.get("file_path", ""),
        line=loc.get("line", 0),
        end_line=loc.get("end_line", loc.get("line", 0)),
        column=loc.get("column", 0),
        function=loc.get("function", ""),
        class_name=loc.get("class", ""),
        code_snippet=loc.get("code_snippet", ""),
    )

    cvss = None
    cvss_data = d.get("cvss")
    if cvss_data and cvss_data.get("score") is not None:
        cvss = CVSS(
            vector=cvss_data.get("vector", ""),
            base_score=cvss_data.get("score", 0.0),
            severity=_severity(cvss_data.get("severity", d.get("severity", "info"))),
        )

    owasp = _owasp_from_code((d.get("owasp") or {}).get("code")) if d.get("owasp") else None

    finding = Finding(
        rule_id=d.get("rule_id", ""),
        title=d.get("title", ""),
        description=d.get("description", ""),
        severity=_severity(d.get("severity", "info")),
        confidence=d.get("confidence", 0.0),
        category=_category(d.get("category", "security")),
        language=_language(d.get("language", "unknown")),
        location=location,
        cwe=d.get("cwe", ""),
        cwe_name=d.get("cwe_name", ""),
        owasp=owasp,
        cvss=cvss,
        fix_suggestion=d.get("fix_suggestion", ""),
        fixed_code=d.get("fixed_code", ""),
        references=d.get("references", []),
        exploit_scenario=d.get("exploit_scenario", ""),
        impact=d.get("impact", ""),
        why_vulnerable=d.get("why_vulnerable", ""),
        is_false_positive=bool(d.get("is_false_positive", False)),
        confidence_reasoning=d.get("confidence_reasoning", ""),
        tags=d.get("tags", []),
        fingerprint=d.get("fingerprint", ""),
        raw_secret=d.get("raw_secret", ""),
    )
    finding.reachability = d.get("reachability", "")
    finding.root_cause = d.get("root_cause", "")
    return finding


def result_from_dict(d: dict) -> ScanResult:
    """Rebuild a ScanResult dataclass from a ``to_dict()`` payload."""
    summary = d.get("summary", {}) or {}
    findings = [finding_from_dict(f) for f in d.get("findings", [])]

    def _parse_iso(value) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return None

    result = ScanResult(
        findings=findings,
        files_scanned=summary.get("files_scanned", 0),
        lines_scanned=summary.get("lines_scanned", 0),
        scan_duration=d.get("scan_duration", 0.0),
        scan_start=_parse_iso(d.get("scan_start")) or datetime.now(timezone.utc),
        scan_end=_parse_iso(d.get("scan_end")),
        languages_detected=summary.get("languages", {}),
    )
    return result
