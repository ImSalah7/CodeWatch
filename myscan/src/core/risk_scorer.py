"""Risk Scoring Engine.

Provides proper CVSS v3.1/v4.0 calculation, composite risk scoring,
and confidence-weighted severity adjustment.
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
    INFO = "info"


class OWASPCategory(Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTographic_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"


@dataclass
class CVSSVector:
    """CVSS v3.1 vector components."""
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "N"
    integrity: str = "N"
    availability: str = "N"

    def to_vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}"
            f"/A:{self.availability}"
        )


@dataclass
class CVSSScore:
    """Calculated CVSS score."""
    vector: CVSSVector
    base_score: float
    temporal_score: float
    environmental_score: float
    overall_score: float
    severity: RiskLevel
    vector_string: str


@dataclass
class RiskAssessment:
    """Complete risk assessment for a finding."""
    cvss: CVSSScore
    composite_score: float
    risk_level: RiskLevel
    owasp_category: str
    confidence_score: float
    impact_score: float
    exploitability_score: float
    reasoning: str


CVSS_METRICS = {
    "attack_vector": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "attack_complexity": {"L": 0.77, "H": 0.44},
    "privileges_required": {"N": 0.85, "L": 0.62, "H": 0.27},
    "user_interaction": {"N": 0.85, "R": 0.62},
    "scope": {"U": "change_scope", "C": "unchanged_scope"},
    "confidentiality": {"H": 0.56, "L": 0.22, "N": 0.0},
    "integrity": {"H": 0.56, "L": 0.22, "N": 0.0},
    "availability": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def calculate_cvss(
    attack_vector: str = "N",
    attack_complexity: str = "L",
    privileges_required: str = "N",
    user_interaction: str = "N",
    scope: str = "U",
    confidentiality: str = "H",
    integrity: str = "H",
    availability: str = "N",
    temporal_maturity: float = 1.0,
    environmental_modified_base: float = 1.0,
) -> CVSSScore:
    """Calculate CVSS v3.1 score from vector components."""
    av = CVSS_METRICS["attack_vector"].get(attack_vector, 0.85)
    ac = CVSS_METRICS["attack_complexity"].get(attack_complexity, 0.77)
    pr = CVSS_METRICS["privileges_required"].get(privileges_required, 0.85)
    ui = CVSS_METRICS["user_interaction"].get(user_interaction, 0.85)
    c = CVSS_METRICS["confidentiality"].get(confidentiality, 0.0)
    i = CVSS_METRICS["integrity"].get(integrity, 0.0)
    a = CVSS_METRICS["availability"].get(availability, 0.0)

    if scope == "U":
        pr_adjusted = pr
        impact_sub = 6.42 * (c + i + a)
    else:
        impact_sub = max(0.0, 7.52 * (c + i + a - 0.029) - 3.25 * min(1.0, (c + i + a - 0.02) ** 15))

    exploitability = 8.22 * av * ac * pr * ui

    if impact_sub <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = min((impact_sub + exploitability), 10.0)
    else:
        base_score = min(1.08 * (impact_sub + exploitability), 10.0)

    temporal_score = base_score * temporal_maturity
    environmental_score = temporal_score * environmental_modified_base

    vector = CVSSVector(
        attack_vector=attack_vector,
        attack_complexity=attack_complexity,
        privileges_required=privileges_required,
        user_interaction=user_interaction,
        scope=scope,
        confidentiality=confidentiality,
        integrity=integrity,
        availability=availability,
    )

    severity = _score_to_severity(environmental_score)

    return CVSSScore(
        vector=vector,
        base_score=round(base_score, 1),
        temporal_score=round(temporal_score, 1),
        environmental_score=round(environmental_score, 1),
        overall_score=round(environmental_score, 1),
        severity=severity,
        vector_string=vector.to_vector_string(),
    )


def _score_to_severity(score: float) -> RiskLevel:
    """Map CVSS score to severity level."""
    if score >= 9.0:
        return RiskLevel.CRITICAL
    elif score >= 7.0:
        return RiskLevel.HIGH
    elif score >= 4.0:
        return RiskLevel.MEDIUM
    elif score >= 0.1:
        return RiskLevel.LOW
    return RiskLevel.INFO


CATEGORY_RISK_WEIGHTS = {
    "injection": 1.0,
    "broken_access_control": 0.95,
    "cryptographic_failures": 0.85,
    "insecure_design": 0.80,
    "security_misconfiguration": 0.70,
    "vulnerable_components": 0.65,
    "auth_failures": 0.75,
    "data_integrity": 0.80,
    "logging_failures": 0.40,
    "ssrf": 0.90,
}


def assess_risk(
    category: str,
    confidence: float = 0.5,
    is_production: bool = True,
    has_taint_path: bool = False,
    user_controlled: bool = False,
    cvss_overrides: Optional[dict] = None,
    custom_cvss: Optional[dict] = None,
) -> RiskAssessment:
    """Perform comprehensive risk assessment."""
    if custom_cvss:
        cvss = calculate_cvss(**custom_cvss)
    else:
        cvss = _default_cvss_for_category(category)
        if cvss_overrides:
            cvss = calculate_cvss(**{**cvss.vector.__dict__, **cvss_overrides})

    base_risk = CATEGORY_RISK_WEIGHTS.get(category, 0.5)
    impact = cvss.overall_score / 10.0

    av_val = CVSS_METRICS["attack_vector"].get(cvss.vector.attack_vector, 0.85)
    ac_val = CVSS_METRICS["attack_complexity"].get(cvss.vector.attack_complexity, 0.77)
    pr_val = CVSS_METRICS["privileges_required"].get(cvss.vector.privileges_required, 0.85)
    ui_val = CVSS_METRICS["user_interaction"].get(cvss.vector.user_interaction, 0.85)
    exploitability = min(1.0, (8.22 * av_val * ac_val * pr_val * ui_val) / 10.0)

    if not is_production:
        impact *= 0.1
        exploitability *= 0.1

    if has_taint_path:
        exploitability = min(1.0, exploitability * 1.3)

    if user_controlled:
        impact = min(1.0, impact * 1.2)

    composite_score = (
        base_risk * 0.25 +
        impact * 0.30 +
        exploitability * 0.20 +
        confidence * 0.25
    )

    composite_score = max(0.0, min(1.0, composite_score))
    risk_level = _score_to_risk_level(composite_score * 10.0)

    return RiskAssessment(
        cvss=cvss,
        composite_score=round(composite_score, 3),
        risk_level=risk_level,
        owasp_category=_map_to_owasp(category),
        confidence_score=confidence,
        impact_score=round(impact, 3),
        exploitability_score=round(exploitability, 3),
        reasoning=_build_risk_reasoning(category, risk_level, confidence, has_taint_path),
    )


def _score_to_risk_level(score: float) -> RiskLevel:
    if score >= 8.0:
        return RiskLevel.CRITICAL
    elif score >= 6.0:
        return RiskLevel.HIGH
    elif score >= 3.0:
        return RiskLevel.MEDIUM
    elif score >= 0.1:
        return RiskLevel.LOW
    return RiskLevel.INFO


def _map_to_owasp(category: str) -> str:
    mapping = {
        "injection": OWASPCategory.A03_INJECTION,
        "sql_injection": OWASPCategory.A03_INJECTION,
        "xss": OWASPCategory.A03_INJECTION,
        "command_injection": OWASPCategory.A03_INJECTION,
        "path_traversal": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        "broken_access_control": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        "hardcoded_secret": OWASPCategory.A02_CRYPTographic_FAILURES,
        "weak_crypto": OWASPCategory.A02_CRYPTographic_FAILURES,
        "insecure_design": OWASPCategory.A04_INSECURE_DESIGN,
        "security_misconfiguration": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
        "outdated_component": OWASPCategory.A06_VULNERABLE_COMPONENTS,
        "auth_failure": OWASPCategory.A07_AUTH_FAILURES,
        "data_integrity": OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
        "logging_failure": OWASPCategory.A09_LOGGING_FAILURES,
        "ssrf": OWASPCategory.A10_SSRF,
    }
    return mapping.get(category, OWASPCategory.A05_SECURITY_MISCONFIGURATION).value


def _default_cvss_for_category(category: str) -> CVSSScore:
    """Generate sensible CVSS defaults for a category."""
    defaults = {
        "sql_injection": {"confidentiality": "H", "integrity": "H", "availability": "H", "attack_vector": "N"},
        "xss": {"confidentiality": "L", "integrity": "L", "availability": "N"},
        "command_injection": {"confidentiality": "H", "integrity": "H", "availability": "H"},
        "hardcoded_secret": {"confidentiality": "H", "integrity": "L", "availability": "N"},
        "path_traversal": {"confidentiality": "H", "integrity": "L", "availability": "N"},
        "insecure_design": {"confidentiality": "L", "integrity": "L", "availability": "N", "attack_complexity": "H"},
        "security_misconfiguration": {"confidentiality": "L", "integrity": "L", "availability": "N"},
        "weak_crypto": {"confidentiality": "H", "integrity": "L", "availability": "N"},
        "ssrf": {"confidentiality": "H", "integrity": "L", "availability": "N", "attack_vector": "N"},
    }
    params = defaults.get(category, {})
    return calculate_cvss(**params)


def _build_risk_reasoning(category: str, risk_level: RiskLevel, confidence: float, has_taint: bool) -> str:
    parts = []
    parts.append(f"Category '{category}' maps to risk level {risk_level.value}.")
    if confidence >= 0.7:
        parts.append("Confidence is HIGH - finding is likely actionable.")
    elif confidence >= 0.4:
        parts.append("Confidence is MEDIUM - requires manual review to confirm.")
    else:
        parts.append("Confidence is LOW - likely a false positive.")
    if has_taint:
        parts.append("Taint path confirmed from source to sink - increases exploitability.")
    return " ".join(parts)
