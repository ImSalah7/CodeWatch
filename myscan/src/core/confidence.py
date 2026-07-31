"""Confidence Scoring Engine.

Calculates confidence for each finding based on multiple signals:
- AST evidence (direct call vs indirect)
- Data flow evidence (taint path exists)
- Context evidence (user-controlled vs constant)
- Reachability evidence (direct vs conditional)
- File context (production vs test)
- Pattern strength (exact match vs approximate)

Confidence score: 0.0 (certain false positive) to 1.0 (certain true positive).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ConfidenceLevel(Enum):
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SPECULATIVE = "speculative"


@dataclass
class ConfidenceEvidence:
    """A single piece of evidence contributing to confidence."""
    signal: str
    weight: float
    value: float
    reason: str


@dataclass
class ConfidenceResult:
    """Result of confidence calculation."""
    score: float
    level: ConfidenceLevel
    evidences: list[ConfidenceEvidence] = field(default_factory=list)
    adjusted_severity: str = ""
    should_report: bool = True
    reasoning: str = ""


AST_EVIDENCE_WEIGHTS = {
    "direct_call_to_sink": 0.30,
    "taint_source_identified": 0.25,
    "no_sanitization": 0.20,
    "user_controlled_input": 0.15,
    "reachable_code_path": 0.10,
}

CONTEXT_EVIDENCE_WEIGHTS = {
    "production_code": 0.20,
    "not_in_test": 0.15,
    "not_in_example": 0.10,
    "not_in_generated": 0.05,
    "not_placeholder_value": 0.10,
    "real_credential_pattern": 0.15,
    "entropy_check": 0.05,
    "variable_name_suspicious": 0.05,
    "no_comment_context": 0.05,
    "line_not_commented": 0.05,
}

DATAFLOW_EVIDENCE_WEIGHTS = {
    "taint_path_exists": 0.35,
    "source_is_external": 0.25,
    "sink_is_dangerous": 0.20,
    "no_intermediate_sanitization": 0.15,
    "direct_reachability": 0.05,
}


def calculate_confidence(
    has_ast_match: bool = False,
    has_taint_path: bool = False,
    is_user_controlled: bool = False,
    is_constant: bool = False,
    is_sanitized: bool = False,
    reachability: str = "unknown",
    file_context: str = "internal",
    variable_name: str = "",
    value: str = "",
    is_placeholder: bool = False,
    is_in_comment: bool = False,
    is_in_test: bool = False,
    is_in_example: bool = False,
    is_in_generated: bool = False,
    is_in_vendor: bool = False,
    base_confidence: float = 0.5,
    pattern_matched: bool = False,
    has_entropy_evidence: bool = False,
    sink_function: str = "",
    source_type: str = "",
    intermediate_assignments: int = 0,
    total_sinks: int = 0,
    total_sources: int = 0,
) -> ConfidenceResult:
    """Calculate comprehensive confidence score for a finding."""
    result = ConfidenceResult(score=0.0, level=ConfidenceLevel.LOW)
    evidences: list[ConfidenceEvidence] = []

    if is_in_vendor:
        result.score = 0.01
        result.level = ConfidenceLevel.SPECULATIVE
        result.should_report = False
        result.reasoning = "Finding is in vendored code - not actionable."
        return result

    if is_in_generated:
        evidences.append(ConfidenceEvidence("generated_code", -0.3, 0.8, "Code appears to be auto-generated."))

    if is_in_test:
        evidences.append(ConfidenceEvidence("test_code", -0.3, 0.2, "Found in test file - reduced confidence."))

    if is_in_example:
        evidences.append(ConfidenceEvidence("example_code", -0.5, 0.1, "Found in example code - likely not real vulnerability."))

    if is_in_comment:
        evidences.append(ConfidenceEvidence("in_comment", -0.7, 0.8, "Found in comment - not executable code."))

    if is_placeholder:
        evidences.append(ConfidenceEvidence("placeholder_value", -0.8, 0.05, "Value is a placeholder/dummy."))

    if has_ast_match:
        evidences.append(ConfidenceEvidence(
            "ast_match", AST_EVIDENCE_WEIGHTS["direct_call_to_sink"],
            0.9, "AST analysis confirmed the vulnerable pattern."
        ))
    else:
        evidences.append(ConfidenceEvidence(
            "ast_match", -0.1, 0.5, "Pattern-based match without AST confirmation."
        ))

    if has_taint_path:
        evidences.append(ConfidenceEvidence(
            "taint_path", DATAFLOW_EVIDENCE_WEIGHTS["taint_path_exists"],
            0.95, "Taint analysis confirmed data flows from source to sink."
        ))
        if source_type:
            evidences.append(ConfidenceEvidence(
                "external_source", DATAFLOW_EVIDENCE_WEIGHTS["source_is_external"],
                0.9, f"Source is external input ({source_type})."
            ))
    else:
        evidences.append(ConfidenceEvidence(
            "no_taint_path", -0.15, 0.3, "No confirmed taint path from source to sink."
        ))

    if is_user_controlled:
        evidences.append(ConfidenceEvidence(
            "user_controlled", CONTEXT_EVIDENCE_WEIGHTS["variable_name_suspicious"],
            0.85, "Input is user-controlled."
        ))

    if is_constant:
        evidences.append(ConfidenceEvidence(
            "constant_value", -0.7, 0.05, "Value is a constant - not attacker-controllable."
        ))

    if is_sanitized:
        evidences.append(ConfidenceEvidence(
            "sanitized", DATAFLOW_EVIDENCE_WEIGHTS["no_intermediate_sanitization"],
            0.1, "Input is sanitized before reaching the sink."
        ))

    if reachability == "direct":
        evidences.append(ConfidenceEvidence(
            "direct_reachability", 0.05, 0.9, "Code path is directly reachable."
        ))
    elif reachability == "conditional":
        evidences.append(ConfidenceEvidence(
            "conditional_reachability", -0.1, 0.5, "Code path is conditionally reachable."
        ))
    elif reachability == "unreachable":
        evidences.append(ConfidenceEvidence(
            "unreachable", -0.8, 0.0, "Code path appears unreachable."
        ))

    if intermediate_assignments > 3:
        evidences.append(ConfidenceEvidence(
            "many_transformations", -0.1, 0.5,
            f"Data passes through {intermediate_assignments} transformations - "
            f"may be sanitized."
        ))

    if variable_name:
        name_lower = variable_name.lower()
        suspicious_names = ("user", "input", "request", "param", "arg", "data", "body", "query")
        if any(s in name_lower for s in suspicious_names):
            evidences.append(ConfidenceEvidence(
                "suspicious_name", 0.1, 0.7,
                f"Variable name '{variable_name}' suggests user-controlled input."
            ))

        safe_names = ("constant", "config", "default", "static", "fixed", "literal")
        if any(s in name_lower for s in safe_names):
            evidences.append(ConfidenceEvidence(
                "safe_name", -0.2, 0.2,
                f"Variable name '{variable_name}' suggests constant/controlled value."
            ))

    raw_score = base_confidence
    for ev in evidences:
        raw_score += ev.weight * ev.value

    result.score = max(0.0, min(1.0, raw_score))

    if result.score >= 0.9:
        result.level = ConfidenceLevel.CERTAIN
    elif result.score >= 0.7:
        result.level = ConfidenceLevel.HIGH
    elif result.score >= 0.4:
        result.level = ConfidenceLevel.MEDIUM
    elif result.score >= 0.2:
        result.level = ConfidenceLevel.LOW
    else:
        result.level = ConfidenceLevel.SPECULATIVE

    if result.score < 0.15 and not has_taint_path:
        result.should_report = False

    result.evidences = evidences
    result.adjusted_severity = _adjust_severity(result.score)
    result.reasoning = _build_reasoning(evidences, result.score)

    return result


def _adjust_severity(confidence: float) -> str:
    """Suggest severity adjustment based on confidence."""
    if confidence >= 0.9 or confidence >= 0.7:
        return "no_change"
    elif confidence >= 0.4:
        return "reduce_one_level"
    elif confidence >= 0.2:
        return "reduce_to_medium_max"
    else:
        return "reduce_to_low"


def _build_reasoning(evidences: list[ConfidenceEvidence], score: float) -> str:
    """Build human-readable reasoning for the confidence score."""
    positive = [e for e in evidences if e.weight > 0 and e.value > 0.5]
    negative = [e for e in evidences if e.weight < 0]

    parts = []
    if positive:
        parts.append("Supporting evidence: " + "; ".join(e.reason for e in positive[:3]))
    if negative:
        parts.append("Reducing factors: " + "; ".join(e.reason for e in negative[:3]))

    if not parts:
        parts.append("Insufficient evidence for high-confidence determination.")

    return " ".join(parts)


def confidence_to_display(score: float) -> str:
    """Convert confidence score to display string."""
    if score >= 0.9:
        return "Very High"
    elif score >= 0.7:
        return "High"
    elif score >= 0.4:
        return "Medium"
    elif score >= 0.2:
        return "Low"
    return "Very Low"
