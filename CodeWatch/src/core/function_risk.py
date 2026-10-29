"""Function Risk Scorer - Per-function risk assessment.

Scores every function based on:
- Cyclomatic complexity
- External inputs
- Database access
- Authentication/authorization
- Secret handling
- Crypto usage
- Network I/O
- File I/O
- Vulnerability count
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum


class FunctionRiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class FunctionRiskProfile:
    """Risk profile for a single function."""
    function_name: str
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    risk_score: float = 0.0
    risk_level: FunctionRiskLevel = FunctionRiskLevel.MINIMAL
    cyclomatic_complexity: int = 1
    lines_of_code: int = 0
    external_inputs: int = 0
    db_access: bool = False
    auth_code: bool = False
    authorization_code: bool = False
    secrets_handling: bool = False
    crypto_usage: bool = False
    network_access: bool = False
    file_access: bool = False
    subprocess_call: bool = False
    deserialization: bool = False
    finding_count: int = 0
    max_finding_severity: str = "info"
    ai_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "functionName": self.function_name,
            "filePath": self.file_path,
            "lineStart": self.line_start,
            "lineEnd": self.line_end,
            "riskScore": round(self.risk_score, 2),
            "riskLevel": self.risk_level.value,
            "cyclomaticComplexity": self.cyclomatic_complexity,
            "linesOfCode": self.lines_of_code,
            "externalInputs": self.external_inputs,
            "dbAccess": self.db_access,
            "authCode": self.auth_code,
            "cryptoUsage": self.crypto_usage,
            "networkAccess": self.network_access,
            "findingCount": self.finding_count,
            "aiSummary": self.ai_summary,
        }


RISK_KEYWORDS = {
    "db_access": ["execute", "query", "cursor", "connection", "database", "sql"],
    "auth": ["login", "authenticate", "session", "token", "password"],
    "authorization": ["authorize", "permission", "role", "access_control", "policy"],
    "secrets": ["secret", "key", "credential", "api_key", "token"],
    "crypto": ["encrypt", "decrypt", "hash", "sign", "verify", "cipher"],
    "network": ["socket", "http", "request", "fetch", "connect", "send", "recv"],
    "file_access": ["open", "read", "write", "unlink", "rename"],
    "subprocess": ["system", "popen", "subprocess", "exec", "spawn"],
    "deserialization": ["pickle", "loads", "unserialize", "deserialize", "yaml.load"],
}


class FunctionRiskScorer:
    """Scores risk for individual functions."""

    def score_function(
        self,
        function_node: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str = "",
        content: str = "",
        findings: list | None = None,
    ) -> FunctionRiskProfile:
        profile = FunctionRiskProfile(
            function_name=function_node.name,
            file_path=file_path,
            line_start=function_node.lineno,
            line_end=getattr(function_node, "end_lineno", function_node.lineno) or function_node.lineno,
        )

        body_lines = ast.get_source_segment(content, function_node) if content else ""
        if body_lines:
            lines = body_lines.split("\n")
            profile.lines_of_code = len([l for l in lines if l.strip()])
            profile.cyclomatic_complexity = self._calculate_complexity(function_node)
            self._detect_risk_patterns(body_lines, profile)

        if findings:
            for f in findings:
                loc = getattr(f, "location", None)
                if loc and hasattr(loc, "function") and loc.function == function_node.name:
                    profile.finding_count += 1
                    sev = getattr(f, "severity", None)
                    sev_val = sev.value if hasattr(sev, "value") else str(sev).lower()
                    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                    curr_order = sev_order.get(profile.max_finding_severity, 0)
                    if sev_order.get(sev_val, 0) > curr_order:
                        profile.max_finding_severity = sev_val

        profile.risk_score = self._calculate_score(profile)
        profile.risk_level = self._score_to_level(profile.risk_score)
        profile.ai_summary = self._generate_summary(profile)
        return profile

    def score_file_functions(
        self,
        file_path: str,
        content: str,
        findings: list | None = None,
    ) -> list[FunctionRiskProfile]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        profiles = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                profile = self.score_function(node, file_path, content, findings)
                profiles.append(profile)
        return profiles

    def _calculate_complexity(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler, ast.And, ast.Or, ast.Assert)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

    def _detect_risk_patterns(self, code: str, profile: FunctionRiskProfile) -> None:
        code_lower = code.lower()
        for category, keywords in RISK_KEYWORDS.items():
            if any(kw in code_lower for kw in keywords):
                if category == "db_access":
                    profile.db_access = True
                elif category == "auth":
                    profile.auth_code = True
                elif category == "authorization":
                    profile.authorization_code = True
                elif category == "secrets":
                    profile.secrets_handling = True
                elif category == "crypto":
                    profile.crypto_usage = True
                elif category == "network":
                    profile.network_access = True
                elif category == "file_access":
                    profile.file_access = True
                elif category == "subprocess":
                    profile.subprocess_call = True
                elif category == "deserialization":
                    profile.deserialization = True

        for line in code.split("\n"):
            stripped = line.strip()
            if any(p in stripped for p in ["input(", "request.", "sys.argv", "args.", "kwargs."]):
                profile.external_inputs += 1

    def _calculate_score(self, profile: FunctionRiskProfile) -> float:
        complexity_score = min(1.0, (profile.cyclomatic_complexity - 1) / 19.0)
        risk_factor_count = sum([
            profile.db_access, profile.auth_code, profile.authorization_code,
            profile.secrets_handling, profile.crypto_usage, profile.network_access,
            profile.file_access, profile.subprocess_call, profile.deserialization,
        ])
        risk_factor_score = min(1.0, risk_factor_count / 5.0)
        input_score = min(1.0, profile.external_inputs / 5.0)

        sev_weights = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1}
        finding_score = min(1.0, profile.finding_count * 0.2) * sev_weights.get(profile.max_finding_severity, 0.1)

        raw = (
            complexity_score * 0.20 +
            risk_factor_score * 0.30 +
            input_score * 0.15 +
            finding_score * 0.35
        )
        return max(0.0, min(100.0, raw * 100.0))

    @staticmethod
    def _score_to_level(score: float) -> FunctionRiskLevel:
        if score >= 75:
            return FunctionRiskLevel.CRITICAL
        elif score >= 50:
            return FunctionRiskLevel.HIGH
        elif score >= 25:
            return FunctionRiskLevel.MEDIUM
        elif score >= 10:
            return FunctionRiskLevel.LOW
        return FunctionRiskLevel.MINIMAL

    def _generate_summary(self, profile: FunctionRiskProfile) -> str:
        parts = []
        if profile.risk_level in (FunctionRiskLevel.CRITICAL, FunctionRiskLevel.HIGH):
            parts.append(f"HIGH RISK function '{profile.function_name}'")
        elif profile.risk_level == FunctionRiskLevel.MEDIUM:
            parts.append(f"Medium risk function '{profile.function_name}'")
        else:
            parts.append(f"Function '{profile.function_name}'")

        if profile.cyclomatic_complexity > 10:
            parts.append(f"with high complexity ({profile.cyclomatic_complexity})")
        if profile.external_inputs > 0:
            parts.append(f"processing {profile.external_inputs} external input(s)")

        risks = []
        if profile.db_access:
            risks.append("database access")
        if profile.auth_code:
            risks.append("authentication")
        if profile.crypto_usage:
            risks.append("cryptography")
        if profile.network_access:
            risks.append("network I/O")
        if profile.subprocess_call:
            risks.append("subprocess execution")
        if profile.deserialization:
            risks.append("deserialization")
        if risks:
            parts.append("involving " + ", ".join(risks))

        if profile.finding_count:
            parts.append(f"with {profile.finding_count} finding(s)")

        return " ".join(parts) + "."
