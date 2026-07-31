"""Core data models for the SAST platform."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from ..__init__ import __version__


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}[self.value]

    @property
    def numeric(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    def __lt__(self, other: Severity) -> bool:
        return self.numeric > other.numeric


class SecretDisplayMode(Enum):
    """Controls how detected secrets are displayed in reports."""
    FULL = "full"
    MASKED = "masked"
    SMART = "smart"


class FindingCategory(Enum):
    SECURITY = "security"
    QUALITY = "quality"
    SECRET = "secret"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"
    INFRASTRUCTURE = "infrastructure"
    COMPLIANCE = "compliance"
    LICENSE = "license"
    STYLE = "style"


class OWASPTop10(Enum):
    A01_BROKEN_ACCESS_CONTROL = ("A01:2021", "Broken Access Control")
    A02_CRYPTOGRAPHIC_FAILURES = ("A02:2021", "Cryptographic Failures")
    A03_INJECTION = ("A03:2021", "Injection")
    A04_INSECURE_DESIGN = ("A04:2021", "Insecure Design")
    A05_SECURITY_MISCONFIGURATION = ("A05:2021", "Security Misconfiguration")
    A06_VULNERABLE_COMPONENTS = ("A06:2021", "Vulnerable and Outdated Components")
    A07_AUTH_FAILURES = ("A07:2021", "Identification and Authentication Failures")
    A08_DATA_INTEGRITY_FAILURES = ("A08:2021", "Software and Data Integrity Failures")
    A09_LOGGING_FAILURES = ("A09:2021", "Security Logging and Monitoring Failures")
    A10_SSRF = ("A10:2021", "Server-Side Request Forgery")

    def __init__(self, code: str, title: str):
        self.code = code
        self.title = title


class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    PHP = "php"
    CSHARP = "csharp"
    RUST = "rust"
    C = "c"
    CPP = "cpp"
    HTML = "html"
    CSS = "css"
    DOCKER = "docker"
    TERRAFORM = "terraform"
    YAML = "yaml"
    SHELL = "shell"
    KOTLIN = "kotlin"
    SWIFT = "swift"
    RUBY = "ruby"
    UNKNOWN = "unknown"


EXTENSION_MAP: dict[str, Language] = {
    ".py": Language.PYTHON, ".js": Language.JAVASCRIPT, ".ts": Language.TYPESCRIPT,
    ".jsx": Language.JAVASCRIPT, ".tsx": Language.TYPESCRIPT,
    ".java": Language.JAVA, ".go": Language.GO, ".php": Language.PHP,
    ".cs": Language.CSHARP, ".rs": Language.RUST,
    ".c": Language.C, ".h": Language.C, ".cpp": Language.CPP, ".cc": Language.CPP,
    ".html": Language.HTML, ".htm": Language.HTML, ".css": Language.CSS,
    ".scss": Language.CSS, ".less": Language.CSS,
    ".tf": Language.TERRAFORM, ".hcl": Language.TERRAFORM,
    ".yml": Language.YAML, ".yaml": Language.YAML,
    ".sh": Language.SHELL, ".bash": Language.SHELL, ".ps1": Language.SHELL,
    ".kt": Language.KOTLIN, ".swift": Language.SWIFT, ".rb": Language.RUBY,
}


@dataclass
class CVSS:
    """Common Vulnerability Scoring System."""
    version: str = "3.1"
    vector: str = ""
    base_score: float = 0.0
    severity: Severity = Severity.INFO

    def calculate(self, attack_vector: str = "N", attack_complexity: str = "L",
                  privileges: str = "N", user_interaction: str = "N",
                  scope: str = "U", confidentiality: str = "N",
                  integrity: str = "N", availability: str = "N") -> float:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(attack_vector, 0.85)
        ac = {"L": 0.77, "H": 0.44}.get(attack_complexity, 0.77)
        pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}.get(privileges, 0.85)
        ui = {"N": 0.85, "R": 0.62}.get(user_interaction, 0.85)
        scope_mult = 1.08 if scope == "C" else 1.0
        c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(confidentiality, 0.0)
        i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(integrity, 0.0)
        a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(availability, 0.0)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        impact = scope_mult * iss if iss > 0 else 0.0
        exploitability = 8.22 * av * ac * pr_u * ui
        if impact <= 0:
            self.base_score = 0.0
        else:
            if scope == "C":
                self.base_score = min(1.08 * (impact + exploitability), 10.0)
            else:
                self.base_score = min(impact + exploitability, 10.0)
        self.vector = f"CVSS:{self.version}/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
        self.severity = self._score_to_severity()
        return self.base_score

    def _score_to_severity(self) -> Severity:
        if self.base_score >= 9.0:
            return Severity.CRITICAL
        elif self.base_score >= 7.0:
            return Severity.HIGH
        elif self.base_score >= 4.0:
            return Severity.MEDIUM
        elif self.base_score >= 0.1:
            return Severity.LOW
        return Severity.INFO


@dataclass
class CodeLocation:
    file_path: str
    line: int
    end_line: int = 0
    column: int = 0
    function: str = ""
    class_name: str = ""
    code_snippet: str = ""

    def __post_init__(self):
        if not self.end_line:
            self.end_line = self.line


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    category: FindingCategory
    language: Language
    location: CodeLocation
    cwe: str = ""
    cwe_name: str = ""
    owasp: Optional[OWASPTop10] = None
    cvss: Optional[CVSS] = None
    fix_suggestion: str = ""
    fixed_code: str = ""
    references: list[str] = field(default_factory=list)
    exploit_scenario: str = ""
    impact: str = ""
    why_vulnerable: str = ""
    is_false_positive: bool = False
    confidence_reasoning: str = ""
    tags: list[str] = field(default_factory=list)
    fingerprint: str = ""
    raw_secret: str = ""
    evidence: list[dict] = field(default_factory=list)
    occurrences: int = 1
    locations: list[dict] = field(default_factory=list)
    state: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.fingerprint:
            raw = f"{self.rule_id}:{self.location.file_path}:{self.location.line}:{self.title}"
            self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if not self.locations:
            self.locations = [{
                "file": self.location.file_path,
                "line": self.location.line,
                "end_line": self.location.end_line,
                "column": self.location.column,
            }]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 2),
            "category": self.category.value,
            "language": self.language.value,
            "cwe": self.cwe,
            "cwe_name": self.cwe_name,
            "owasp": {"code": self.owasp.code, "title": self.owasp.title} if self.owasp else None,
            "cvss": {"score": self.cvss.base_score, "vector": self.cvss.vector, "severity": self.cvss.severity.value} if self.cvss else None,
            "cvss_score": self.cvss.base_score if self.cvss else None,
            "file": self.location.file_path,
            "line": self.location.line,
            "end_line": self.location.end_line,
            "location": {
                "file_path": self.location.file_path,
                "line": self.location.line,
                "end_line": self.location.end_line,
                "column": self.location.column,
                "code_snippet": self.location.code_snippet,
                "function": self.location.function,
                "class": self.location.class_name,
            },
            "function": self.location.function,
            "class": self.location.class_name,
            "code_snippet": self.location.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "fixed_code": self.fixed_code,
            "references": self.references,
            "exploit_scenario": self.exploit_scenario,
            "impact": self.impact,
            "why_vulnerable": self.why_vulnerable,
            "is_false_positive": self.is_false_positive,
            "confidence_reasoning": self.confidence_reasoning,
            "tags": self.tags,
            "fingerprint": self.fingerprint,
            "raw_secret": self.raw_secret,
            "evidence": self.evidence,
            "occurrences": self.occurrences,
            "locations": self.locations,
            "state": self.state,
            "reachability": getattr(self, "reachability", ""),
            "root_cause": getattr(self, "root_cause", ""),
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    scan_duration: float = 0.0
    scan_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_end: Optional[datetime] = None
    languages_detected: dict[str, int] = field(default_factory=dict)
    skipped_files: int = 0
    skipped_reasons: dict[str, int] = field(default_factory=dict)

    @property
    def security_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.category == FindingCategory.SECURITY]

    @property
    def quality_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.category == FindingCategory.QUALITY]

    @property
    def secret_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.category == FindingCategory.SECRET]

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> int:
        score = sum(f.severity.weight * f.confidence for f in self.findings)
        return min(int(score), 100)

    @property
    def grade(self) -> str:
        s = self.risk_score
        if s == 0:
            return "A+"
        elif s < 5:
            return "A"
        elif s < 15:
            return "B"
        elif s < 30:
            return "C"
        elif s < 60:
            return "D"
        return "F"

    def deduplicate(self):
        seen: set[str] = set()
        unique: list[Finding] = []
        for f in self.findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique.append(f)
        self.findings = unique

    def group_duplicates(self):
        """Group identical issues (same rule, title, normalized code) into one
        finding with an occurrence count and the full list of locations."""
        import re as _re

        def _normalize(code: str) -> str:
            return _re.sub(r"\s+", " ", (code or "").strip())

        groups: dict[str, list[Finding]] = {}
        for f in self.findings:
            key = "|".join([f.rule_id, f.title, _normalize(f.location.code_snippet)])
            groups.setdefault(key, []).append(f)

        grouped: list[Finding] = []
        for members in groups.values():
            if len(members) == 1:
                grouped.append(members[0])
                continue
            primary = max(members, key=lambda f: (f.confidence, f.severity.numeric, f.location.line))
            locations: list[dict] = []
            seen_loc: set[tuple] = set()
            for f in members:
                loc = (f.location.file_path, f.location.line)
                if loc in seen_loc:
                    continue
                seen_loc.add(loc)
                locations.append({
                    "file": f.location.file_path,
                    "line": f.location.line,
                    "end_line": f.location.end_line,
                    "column": f.location.column,
                })
            primary.occurrences = sum(m.occurrences for m in members)
            primary.locations = locations
            grouped.append(primary)
        self.findings = grouped

    @property
    def occurrences_total(self) -> int:
        return sum(f.occurrences for f in self.findings)

    def remove_false_positives(self):
        self.findings = [f for f in self.findings if not f.is_false_positive]

    def filter_false_positives(self):
        """Apply smart filtering to reduce false positives."""
        from ..core.smart_filter import SmartFilter
        from ..core.config import ScanConfig
        sf = SmartFilter(ScanConfig())
        self.findings = sf.filter_findings(self.findings)

    def filter_false_positives_with_validation(self, validation_pipeline):
        """Apply smart filtering + validation pipeline to reduce false positives."""
        from ..core.smart_filter import SmartFilter
        from ..core.config import ScanConfig
        sf = SmartFilter(ScanConfig())
        self.findings = sf.filter_findings(self.findings)
        validated: list[Finding] = []
        rejected = 0
        for f in self.findings:
            finding_dict = {
                "rule_id": f.rule_id,
                "title": f.title,
                "message": f.description,
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "category": f.category.value if hasattr(f.category, 'value') else str(f.category),
                "file_path": f.location.file_path,
                "line": f.location.line,
                "column": f.location.column or 0,
                "code_snippet": f.location.code_snippet or "",
                "confidence": f.confidence,
                "tags": f.tags if hasattr(f, 'tags') else [],
                "raw_secret": f.raw_secret if hasattr(f, 'raw_secret') else "",
            }
            result = validation_pipeline.validate_finding(finding_dict)
            if result is not None:
                f.confidence = result.get("confidence", f.confidence)
                if hasattr(f, 'validation_level'):
                    f.validation_level = result.get("verification_level", "")
                validated.append(f)
            else:
                rejected += 1
        self.findings = validated

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "MyScan",
            "version": __version__,
            "scan_id": getattr(self, "scan_id", ""),
            "repository": getattr(self, "repository", ""),
            "branch": getattr(self, "branch", ""),
            "commit": getattr(self, "commit", ""),
            "target": getattr(self, "target", ""),
            "rules_executed": getattr(self, "rules_executed", 0),
            "repo_size_bytes": getattr(self, "repo_size_bytes", 0),
            "enterprise_mode": getattr(self, "_enterprise_mode", False),
            "secret_display_mode": getattr(self, "_secret_display_mode", "smart"),
            "llm_stats": getattr(self, "_llm_stats", {}),
            "scan_start": self.scan_start.isoformat(),
            "scan_end": self.scan_end.isoformat() if self.scan_end else None,
            "scan_duration": round(self.scan_duration, 2),
            "summary": {
                "total_findings": len(self.findings),
                "occurrences_total": self.occurrences_total,
                "security_findings": len(self.security_findings),
                "quality_findings": len(self.quality_findings),
                "secret_findings": len(self.secret_findings),
                "risk_score": self.risk_score,
                "grade": self.grade,
                "severity_counts": self.severity_counts,
                "files_scanned": self.files_scanned,
                "lines_scanned": self.lines_scanned,
                "languages": self.languages_detected,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
