"""File Risk Scorer - Per-file risk assessment.

Scores every file based on:
- Vulnerability count and severity
- Attack surface (external inputs)
- Code complexity
- Business importance
- Exposure level
- Authentication/authorization code
- Crypto usage
- Network code
- Secret handling
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class FileRiskProfile:
    """Complete risk profile for a single file."""
    file_path: str
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.MINIMAL
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_findings: int = 0
    has_secrets: bool = False
    has_injection: bool = False
    has_auth_code: bool = False
    has_crypto: bool = False
    has_network: bool = False
    has_db_access: bool = False
    has_file_access: bool = False
    has_user_input: bool = False
    cyclomatic_complexity: float = 0.0
    lines_of_code: int = 0
    external_inputs: int = 0
    attack_surface_score: float = 0.0
    business_importance: str = "unknown"
    exposure_level: str = "internal"
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "filePath": self.file_path,
            "riskScore": round(self.risk_score, 2),
            "riskLevel": self.risk_level.value,
            "criticalCount": self.critical_count,
            "highCount": self.high_count,
            "mediumCount": self.medium_count,
            "totalFindings": self.total_findings,
            "hasSecrets": self.has_secrets,
            "hasInjection": self.has_injection,
            "hasAuthCode": self.has_auth_code,
            "hasCrypto": self.has_crypto,
            "hasNetwork": self.has_network,
            "hasDbAccess": self.has_db_access,
            "hasFileAccess": self.has_file_access,
            "hasUserInput": self.has_user_input,
            "cyclomaticComplexity": round(self.cyclomatic_complexity, 1),
            "linesOfCode": self.lines_of_code,
            "externalInputs": self.external_inputs,
            "attackSurfaceScore": round(self.attack_surface_score, 2),
            "businessImportance": self.business_importance,
            "exposureLevel": self.exposure_level,
        }


SEVERITY_WEIGHTS = {
    "critical": 25.0,
    "high": 15.0,
    "medium": 8.0,
    "low": 3.0,
    "info": 1.0,
}

SENSITIVE_PATTERNS = {
    "auth": ["login", "auth", "session", "token", "password", "credential", "oauth", "jwt"],
    "crypto": ["encrypt", "decrypt", "hash", "cipher", "aes", "rsa", "hmac", "sha", "md5"],
    "network": ["socket", "http", "request", "response", "fetch", "connect", "listen", "bind"],
    "db": ["query", "execute", "cursor", "connection", "database", "sql", "select", "insert"],
    "file": ["open", "read", "write", "unlink", "remove", "rename", "path"],
    "user_input": ["input", "request", "args", "argv", "stdin", "form", "query", "param"],
}

BUSINESS_IMPORTANT_PATHS = {
    "critical": ["auth", "login", "payment", "admin", "api", "security", "crypto", "session"],
    "high": ["user", "account", "profile", "settings", "core", "service", "model"],
    "medium": ["utils", "helpers", "common", "shared", "lib"],
    "low": ["test", "spec", "example", "demo", "doc"],
}

EXPOSED_PATHS = {
    "external": ["api", "view", "controller", "handler", "route", "endpoint", "public", "static"],
    "internal": ["service", "model", "repository", "dao", "manager"],
    "protected": ["admin", "internal", "system", "infra"],
}


@dataclass
class FileRiskScorer:
    """Scores risk for individual files."""

    def score_file(
        self,
        file_path: str,
        findings: list,
        content: str = "",
    ) -> FileRiskProfile:
        profile = FileRiskProfile(file_path=file_path)

        for f in findings:
            sev = getattr(f, "severity", None)
            sev_val = sev.value if hasattr(sev, "value") else str(sev).lower()
            profile.total_findings += 1

            if sev_val == "critical":
                profile.critical_count += 1
            elif sev_val == "high":
                profile.high_count += 1
            elif sev_val == "medium":
                profile.medium_count += 1
            elif sev_val == "low":
                profile.low_count += 1
            else:
                profile.info_count += 1

            cat = getattr(f, "category", None)
            cat_val = cat.value if hasattr(cat, "value") else str(cat).lower()

            if "secret" in cat_val:
                profile.has_secrets = True
            if "security" in cat_val:
                profile.has_injection = True

        if content:
            content_lower = content.lower()
            lines = content.split("\n")
            profile.lines_of_code = len([l for l in lines if l.strip() and not l.strip().startswith("#")])

            for category, patterns in SENSITIVE_PATTERNS.items():
                count = sum(1 for p in patterns if p in content_lower)
                if count > 0:
                    if category == "auth":
                        profile.has_auth_code = True
                    elif category == "crypto":
                        profile.has_crypto = True
                    elif category == "network":
                        profile.has_network = True
                    elif category == "db":
                        profile.has_db_access = True
                    elif category == "file":
                        profile.has_file_access = True
                    elif category == "user_input":
                        profile.has_user_input = True

            profile.cyclomatic_complexity = self._estimate_complexity(content)
            profile.external_inputs = self._count_external_inputs(content)

        profile.attack_surface_score = self._calculate_attack_surface(profile)
        profile.business_importance = self._assess_business_importance(file_path)
        profile.exposure_level = self._assess_exposure(file_path)
        profile.risk_score = self._calculate_risk_score(profile)
        profile.risk_level = self._score_to_level(profile.risk_score)
        profile.reasoning = self._build_reasoning(profile)

        return profile

    def _estimate_complexity(self, content: str) -> float:
        complexity = 1.0
        in_function = False
        for line in content.split("\n"):
            stripped = line.strip()
            if stripped.startswith("def ") or stripped.startswith("async def "):
                in_function = True
            if in_function:
                if any(kw in stripped for kw in ["if ", "elif ", "for ", "while ", "try:", "except", "with "]):
                    complexity += 1.0
                if stripped.startswith("def ") and complexity > 1:
                    complexity += 0.5
        return complexity

    def _count_external_inputs(self, content: str) -> int:
        count = 0
        for line in content.split("\n"):
            stripped = line.strip()
            if any(p in stripped for p in ["input(", "request.", "sys.argv", "os.environ", "stdin"]):
                count += 1
        return count

    def _calculate_attack_surface(self, profile: FileRiskProfile) -> float:
        score = 0.0
        if profile.has_user_input:
            score += 0.3
        if profile.has_network:
            score += 0.25
        if profile.has_auth_code:
            score += 0.2
        if profile.has_db_access:
            score += 0.15
        if profile.has_file_access:
            score += 0.1
        return min(1.0, score)

    def _assess_business_importance(self, file_path: str) -> str:
        path_lower = file_path.lower()
        for level, keywords in BUSINESS_IMPORTANT_PATHS.items():
            if any(kw in path_lower for kw in keywords):
                return level
        return "medium"

    def _assess_exposure(self, file_path: str) -> str:
        path_lower = file_path.lower()
        for level, keywords in EXPOSED_PATHS.items():
            if any(kw in path_lower for kw in keywords):
                return level
        return "internal"

    def _calculate_risk_score(self, profile: FileRiskProfile) -> float:
        vuln_score = (
            profile.critical_count * 25.0 +
            profile.high_count * 15.0 +
            profile.medium_count * 8.0 +
            profile.low_count * 3.0 +
            profile.info_count * 1.0
        )
        normalized_vuln = min(1.0, vuln_score / 50.0)

        surface_score = profile.attack_surface_score
        complexity_score = min(1.0, profile.cyclomatic_complexity / 20.0)
        importance_map = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
        importance_score = importance_map.get(profile.business_importance, 0.5)
        exposure_map = {"external": 1.0, "internal": 0.5, "protected": 0.75}
        exposure_score = exposure_map.get(profile.exposure_level, 0.5)

        raw = (
            normalized_vuln * 0.40 +
            surface_score * 0.20 +
            complexity_score * 0.10 +
            importance_score * 0.15 +
            exposure_score * 0.15
        )
        return max(0.0, min(100.0, raw * 100.0))

    @staticmethod
    def _score_to_level(score: float) -> RiskLevel:
        if score >= 75:
            return RiskLevel.CRITICAL
        elif score >= 50:
            return RiskLevel.HIGH
        elif score >= 25:
            return RiskLevel.MEDIUM
        elif score >= 10:
            return RiskLevel.LOW
        return RiskLevel.MINIMAL

    def _build_reasoning(self, profile: FileRiskProfile) -> str:
        parts = []
        if profile.critical_count:
            parts.append(f"{profile.critical_count} critical findings")
        if profile.high_count:
            parts.append(f"{profile.high_count} high findings")
        if profile.has_secrets:
            parts.append("contains secrets")
        if profile.has_injection:
            parts.append("has injection vulnerabilities")
        if profile.has_auth_code:
            parts.append("handles authentication")
        if profile.has_network:
            parts.append("makes network calls")
        if profile.has_db_access:
            parts.append("accesses database")
        if profile.external_inputs > 0:
            parts.append(f"{profile.external_inputs} external input(s)")
        if profile.cyclomatic_complexity > 10:
            parts.append(f"high complexity ({profile.cyclomatic_complexity:.0f})")
        if not parts:
            parts.append("no significant risk indicators")
        return "; ".join(parts)
