"""Security Policy Engine - Configurable security policies.

Allows users to configure:
- Minimum severity threshold
- Ignored rules
- Allowed secrets (false positive management)
- Ignored paths
- Compliance rules (OWASP, CWE, PCI-DSS, HIPAA)
- Baseline comparison
- Custom policies
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PolicyRule:
    """A single policy rule."""
    rule_id: str
    action: str = "report"
    severity_threshold: str = "info"
    message: str = ""


@dataclass
class SecurityPolicy:
    """Complete security policy configuration."""
    name: str = "default"
    version: str = "1.0.0"
    min_severity: str = "info"
    ignored_rules: list[str] = field(default_factory=list)
    ignored_paths: list[str] = field(default_factory=list)
    allowed_secrets: list[str] = field(default_factory=list)
    compliance_frameworks: list[str] = field(default_factory=list)
    max_critical: int = -1
    max_high: int = -1
    max_medium: int = -1
    fail_on_regression: bool = False
    baseline_file: str = ""
    custom_rules: list[PolicyRule] = field(default_factory=list)
    excluded_files: list[str] = field(default_factory=list)
    excluded_dirs: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "minSeverity": self.min_severity,
            "ignoredRules": self.ignored_rules,
            "ignoredPaths": self.ignored_paths,
            "allowedSecrets": self.allowed_secrets,
            "complianceFrameworks": self.compliance_frameworks,
            "maxCritical": self.max_critical,
            "maxHigh": self.max_high,
            "maxMedium": self.max_medium,
            "failOnRegression": self.fail_on_regression,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> SecurityPolicy:
        return cls(
            name=data.get("name", "default"),
            version=data.get("version", "1.0.0"),
            min_severity=data.get("minSeverity", "info"),
            ignored_rules=data.get("ignoredRules", []),
            ignored_paths=data.get("ignoredPaths", []),
            allowed_secrets=data.get("allowedSecrets", []),
            compliance_frameworks=data.get("complianceFrameworks", []),
            max_critical=data.get("maxCritical", -1),
            max_high=data.get("maxHigh", -1),
            max_medium=data.get("maxMedium", -1),
            fail_on_regression=data.get("failOnRegression", False),
            baseline_file=data.get("baselineFile", ""),
            excluded_files=data.get("excludedFiles", []),
            excluded_dirs=data.get("excludedDirs", []),
            tags=data.get("tags", {}),
        )

    @classmethod
    def from_file(cls, path: str) -> SecurityPolicy:
        with open(path, "r", encoding="utf-8") as f:
            if path.endswith(".json"):
                data = json.load(f)
            elif path.endswith(".yaml") or path.endswith(".yml"):
                import yaml
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
        return cls.from_dict(data)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            if path.endswith(".json"):
                json.dump(self.to_dict(), f, indent=2)
            elif path.endswith(".yaml") or path.endswith(".yml"):
                import yaml
                yaml.dump(self.to_dict(), f, default_flow_style=False)

    @classmethod
    def pci_dss(cls) -> SecurityPolicy:
        return cls(
            name="PCI-DSS",
            min_severity="medium",
            compliance_frameworks=["pci-dss"],
            max_critical=0,
            max_high=5,
            fail_on_regression=True,
        )

    @classmethod
    def hipaa(cls) -> SecurityPolicy:
        return cls(
            name="HIPAA",
            min_severity="medium",
            compliance_frameworks=["hipaa"],
            max_critical=0,
            max_high=0,
            fail_on_regression=True,
        )

    @classmethod
    def soc2(cls) -> SecurityPolicy:
        return cls(
            name="SOC2",
            min_severity="low",
            compliance_frameworks=["soc2"],
            max_critical=0,
            max_high=3,
        )


@dataclass
class PolicyViolation:
    """A violation of a security policy."""
    policy_name: str
    violation_type: str
    severity: str
    message: str
    finding_id: str = ""
    rule_id: str = ""


@dataclass
class PolicyCheckResult:
    """Result of a policy check."""
    passed: bool
    violations: list[PolicyViolation] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "violations": [
                {
                    "type": v.violation_type,
                    "severity": v.severity,
                    "message": v.message,
                    "ruleId": v.rule_id,
                }
                for v in self.violations
            ],
            "summary": self.summary,
        }


class PolicyEngine:
    """Evaluates findings against security policies."""

    def __init__(self, policy: Optional[SecurityPolicy] = None):
        self.policy = policy or SecurityPolicy()
        self._severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def check_findings(self, findings: list) -> PolicyCheckResult:
        result = PolicyCheckResult(passed=True)
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        min_sev = self._severity_order.get(self.policy.min_severity, 0)

        for f in findings:
            rule_id = getattr(f, "rule_id", "")
            if rule_id in self.policy.ignored_rules:
                continue

            sev = getattr(f, "severity", None)
            sev_val = sev.value if hasattr(sev, "value") else str(sev).lower()
            sev_order = self._severity_order.get(sev_val, 0)

            if sev_order < min_sev:
                continue

            file_path = ""
            loc = getattr(f, "location", None)
            if loc and hasattr(loc, "file_path"):
                file_path = loc.file_path
            elif hasattr(f, "file"):
                file_path = f.file

            if self._matches_ignored_path(file_path):
                continue

            sev_counts[sev_val] = sev_counts.get(sev_val, 0) + 1

            if rule_id in self.policy.allowed_secrets:
                continue

        if self.policy.max_critical >= 0 and sev_counts["critical"] > self.policy.max_critical:
            result.passed = False
            result.violations.append(PolicyViolation(
                policy_name=self.policy.name,
                violation_type="severity_threshold",
                severity="critical",
                message=f"Found {sev_counts['critical']} critical issues (max allowed: {self.policy.max_critical})",
            ))

        if self.policy.max_high >= 0 and sev_counts["high"] > self.policy.max_high:
            result.passed = False
            result.violations.append(PolicyViolation(
                policy_name=self.policy.name,
                violation_type="severity_threshold",
                severity="high",
                message=f"Found {sev_counts['high']} high issues (max allowed: {self.policy.max_high})",
            ))

        if self.policy.max_medium >= 0 and sev_counts["medium"] > self.policy.max_medium:
            result.passed = False
            result.violations.append(PolicyViolation(
                policy_name=self.policy.name,
                violation_type="severity_threshold",
                severity="medium",
                message=f"Found {sev_counts['medium']} medium issues (max allowed: {self.policy.max_medium})",
            ))

        total = sum(sev_counts.values())
        if result.passed:
            result.summary = f"Policy '{self.policy.name}' PASSED. {total} findings within thresholds."
        else:
            result.summary = f"Policy '{self.policy.name}' FAILED. {len(result.violations)} violation(s)."

        return result

    def filter_findings(self, findings: list) -> list:
        filtered = []
        min_sev = self._severity_order.get(self.policy.min_severity, 0)

        for f in findings:
            rule_id = getattr(f, "rule_id", "")
            if rule_id in self.policy.ignored_rules:
                continue

            sev = getattr(f, "severity", None)
            sev_val = sev.value if hasattr(sev, "value") else str(sev).lower()
            if self._severity_order.get(sev_val, 0) < min_sev:
                continue

            file_path = ""
            loc = getattr(f, "location", None)
            if loc and hasattr(loc, "file_path"):
                file_path = loc.file_path
            elif hasattr(f, "file"):
                file_path = f.file

            if self._matches_ignored_path(file_path):
                continue

            filtered.append(f)

        return filtered

    def _matches_ignored_path(self, file_path: str) -> bool:
        if not file_path:
            return False
        for pattern in self.policy.ignored_paths:
            if pattern in file_path:
                return True
        return False

    def check_baseline(self, current_findings: list, baseline_findings: list) -> PolicyCheckResult:
        result = PolicyCheckResult(passed=True)

        current_ids = set()
        for f in current_findings:
            rule_id = getattr(f, "rule_id", "")
            loc = getattr(f, "location", None)
            file_path = loc.file_path if loc and hasattr(loc, "file_path") else ""
            line = loc.line if loc and hasattr(loc, "line") else 0
            current_ids.add(f"{rule_id}:{file_path}:{line}")

        baseline_ids = set()
        for f in baseline_findings:
            rule_id = getattr(f, "rule_id", "")
            loc = getattr(f, "location", None)
            file_path = loc.file_path if loc and hasattr(loc, "file_path") else ""
            line = loc.line if loc and hasattr(loc, "line") else 0
            baseline_ids.add(f"{rule_id}:{file_path}:{line}")

        new_findings = current_ids - baseline_ids
        resolved_findings = baseline_ids - current_ids

        if self.policy.fail_on_regression and new_findings:
            result.passed = False
            result.violations.append(PolicyViolation(
                policy_name=self.policy.name,
                violation_type="regression",
                severity="high",
                message=f"{len(new_findings)} new finding(s) since baseline",
            ))

        result.summary = (
            f"Baseline comparison: {len(new_findings)} new, "
            f"{len(resolved_findings)} resolved, "
            f"{len(current_ids & baseline_ids)} unchanged."
        )
        return result
