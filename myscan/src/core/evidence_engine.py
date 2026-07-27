"""Evidence Engine - Accumulates and validates evidence for every finding.

Every finding MUST have evidence before it can be reported.
Evidence is collected at each pipeline stage and evaluated for validity.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EvidenceType(Enum):
    REGEX_MATCH = "regex_match"
    AST_VERIFIED = "ast_verified"
    LITERAL_ASSIGNMENT = "literal_assignment"
    TYPE_VERIFIED = "type_verified"
    REACHABLE = "reachable"
    TAINT_PATH = "taint_path"
    DATAFLOW_VERIFIED = "dataflow_verified"
    CONTEXT_AUTH = "context_auth"
    CONTEXT_USER_INPUT = "context_user_input"
    CONTEXT_SINK_DANGEROUS = "context_sink_dangerous"
    AI_VALIDATED = "ai_validated"
    DEPENDENCY_KNOWN_VULN = "dependency_known_vuln"
    SECRET_CLASSIFIED = "secret_classified"
    CALL_GRAPH_CONNECTED = "call_graph_connected"
    IMPORT_VERIFIED = "import_verified"
    CROSS_FILE_TAINT = "cross_file_taint"


class EvidenceStrength(Enum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NEGATIVE = "negative"


EVIDENCE_WEIGHTS: dict[EvidenceType, float] = {
    EvidenceType.REGEX_MATCH: 0.15,
    EvidenceType.AST_VERIFIED: 0.25,
    EvidenceType.LITERAL_ASSIGNMENT: 0.20,
    EvidenceType.TYPE_VERIFIED: 0.15,
    EvidenceType.REACHABLE: 0.10,
    EvidenceType.TAINT_PATH: 0.20,
    EvidenceType.DATAFLOW_VERIFIED: 0.15,
    EvidenceType.CONTEXT_AUTH: 0.10,
    EvidenceType.CONTEXT_USER_INPUT: 0.10,
    EvidenceType.CONTEXT_SINK_DANGEROUS: 0.10,
    EvidenceType.AI_VALIDATED: 0.05,
    EvidenceType.DEPENDENCY_KNOWN_VULN: 0.30,
    EvidenceType.SECRET_CLASSIFIED: 0.10,
    EvidenceType.CALL_GRAPH_CONNECTED: 0.10,
    EvidenceType.IMPORT_VERIFIED: 0.15,
    EvidenceType.CROSS_FILE_TAINT: 0.20,
}

NEGATIVE_EVIDENCE_PENALTIES: dict[str, float] = {
    "constant_value": -0.70,
    "placeholder": -0.80,
    "in_comment": -0.90,
    "in_example": -0.50,
    "in_test": -0.25,
    "in_generated": -0.30,
    "in_vendor": -1.00,
    "sanitized": -0.40,
    "unreachable": -0.80,
    "type_mismatch": -0.60,
    "wrong_eval_target": -0.70,
    "safe_library": -0.50,
    "dead_code": -0.90,
    "not_literal": -0.80,
    "variable_reference": -0.60,
    "function_call_result": -0.50,
    "input_function": -0.70,
}


@dataclass
class Evidence:
    evidence_type: EvidenceType
    signal: str
    strength: EvidenceStrength
    weight: float
    confidence_contribution: float
    reason: str
    source_location: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def net_contribution(self) -> float:
        if self.strength == EvidenceStrength.NEGATIVE:
            return abs(self.confidence_contribution) * -1
        return self.confidence_contribution * self.weight


@dataclass
class ValidationResult:
    passed: bool
    evidences: list[Evidence] = field(default_factory=list)
    negative_evidences: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0
    should_report: bool = True
    rejection_reasons: list[str] = field(default_factory=list)
    verification_level: str = "unverified"

    @property
    def evidence_count(self) -> int:
        return len(self.evidences)

    @property
    def has_strong_evidence(self) -> bool:
        return any(e.strength == EvidenceStrength.STRONG for e in self.evidences)

    @property
    def negative_count(self) -> int:
        return len(self.negative_evidences)

    @property
    def net_evidence_score(self) -> float:
        pos = sum(e.net_contribution for e in self.evidences if e.strength != EvidenceStrength.NEGATIVE)
        neg = sum(abs(e.net_contribution) for e in self.negative_evidences)
        return pos - neg

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "confidence": round(self.confidence, 3),
            "shouldReport": self.should_report,
            "verificationLevel": self.verification_level,
            "evidenceCount": self.evidence_count,
            "negativeCount": self.negative_count,
            "evidences": [
                {
                    "type": e.evidence_type.value,
                    "signal": e.signal,
                    "strength": e.strength.value,
                    "weight": round(e.weight, 3),
                    "contribution": round(e.confidence_contribution, 3),
                    "reason": e.reason,
                }
                for e in self.evidences
            ],
            "negativeEvidences": [
                {
                    "signal": e.signal,
                    "strength": e.strength.value,
                    "penalty": round(e.confidence_contribution, 3),
                    "reason": e.reason,
                }
                for e in self.negative_evidences
            ],
            "rejectionReasons": self.rejection_reasons,
        }


class EvidenceEngine:
    """Collects and validates evidence for findings."""

    MIN_CONFIDENCE_TO_REPORT = 0.15
    MIN_EVIDENCE_TO_REPORT = 1
    MIN_STRONG_EVIDENCE = 1

    def __init__(self, min_confidence: float = 0.15):
        self.min_confidence = min_confidence

    def create_evidence(
        self,
        evidence_type: EvidenceType,
        signal: str,
        strength: EvidenceStrength,
        reason: str,
        contribution: Optional[float] = None,
        source_location: str = "",
        metadata: Optional[dict] = None,
    ) -> Evidence:
        weight = EVIDENCE_WEIGHTS.get(evidence_type, 0.1)
        if contribution is None:
            if strength == EvidenceStrength.STRONG:
                contribution = 0.9
            elif strength == EvidenceStrength.MODERATE:
                contribution = 0.6
            elif strength == EvidenceStrength.WEAK:
                contribution = 0.3
            else:
                contribution = 0.0
        return Evidence(
            evidence_type=evidence_type,
            signal=signal,
            strength=strength,
            weight=weight,
            confidence_contribution=contribution,
            reason=reason,
            source_location=source_location,
            metadata=metadata or {},
        )

    def create_negative_evidence(
        self,
        signal: str,
        reason: str,
        penalty: Optional[float] = None,
        source_location: str = "",
    ) -> Evidence:
        if penalty is None:
            penalty = NEGATIVE_EVIDENCE_PENALTIES.get(signal, -0.3)
        return Evidence(
            evidence_type=EvidenceType.REGEX_MATCH,
            signal=signal,
            strength=EvidenceStrength.NEGATIVE,
            weight=1.0,
            confidence_contribution=max(-1.0, min(0.0, penalty)),
            reason=reason,
            source_location=source_location,
        )

    def evaluate(
        self,
        positive_evidences: list[Evidence],
        negative_evidences: list[Evidence],
        min_evidence: int = 1,
    ) -> ValidationResult:
        positive_sum = 0.0
        positive_weight_sum = 0.0

        for ev in positive_evidences:
            if ev.strength != EvidenceStrength.NEGATIVE and ev.confidence_contribution > 0:
                positive_sum += ev.net_contribution
                positive_weight_sum += ev.weight

        if positive_weight_sum > 0:
            normalized_positive = positive_sum / max(positive_weight_sum, 0.01)
        else:
            normalized_positive = 0.0

        negative_sum = sum(abs(e.confidence_contribution) for e in negative_evidences)

        raw_confidence = normalized_positive - negative_sum
        confidence = max(0.0, min(1.0, raw_confidence))

        rejection_reasons = []
        should_report = True

        if confidence < self.min_confidence:
            rejection_reasons.append(f"Confidence {confidence:.3f} below threshold {self.min_confidence}")

        if len(positive_evidences) < min_evidence:
            rejection_reasons.append(f"Only {len(positive_evidences)} positive evidence(s), need {min_evidence}")

        has_strong = any(e.strength == EvidenceStrength.STRONG for e in positive_evidences)
        if not has_strong and len(positive_evidences) < 2:
            rejection_reasons.append("No strong evidence and fewer than 2 moderate evidences")

        if negative_sum >= 0.8:
            rejection_reasons.append(f"Negative evidence too strong ({negative_sum:.3f})")

        verification_level = self._determine_verification_level(positive_evidences)

        passed = len(rejection_reasons) == 0
        if not passed:
            should_report = False

        return ValidationResult(
            passed=passed,
            evidences=positive_evidences,
            negative_evidences=negative_evidences,
            confidence=confidence,
            should_report=should_report,
            rejection_reasons=rejection_reasons,
            verification_level=verification_level,
        )

    def _determine_verification_level(self, evidences: list[Evidence]) -> str:
        types = set(e.evidence_type for e in evidences if e.strength != EvidenceStrength.NEGATIVE)
        strong_count = sum(1 for e in evidences if e.strength == EvidenceStrength.STRONG and e.evidence_type in types)
        if len(types) >= 5 and strong_count >= 3:
            return "fully_verified"
        if len(types) >= 4:
            return "highly_verified"
        if len(types) >= 3:
            return "partially_verified"
        if len(types) >= 1:
            return "single_evidence"
        return "unverified"

    def calculate_dynamic_confidence(
        self,
        pattern_match: float = 0.0,
        ast_verified: float = 0.0,
        type_resolution: float = 0.0,
        reachability: float = 0.0,
        dataflow: float = 0.0,
        taint_analysis: float = 0.0,
        ai_validation: float = 0.0,
        context_auth: float = 0.0,
        context_user_input: float = 0.0,
        dependency_known: float = 0.0,
        secret_classification: float = 0.0,
        call_graph: float = 0.0,
    ) -> tuple[float, list[Evidence]]:
        evidences = []
        weights = {
            "pattern_match": (0.20, EvidenceType.REGEX_MATCH),
            "ast_verified": (0.25, EvidenceType.AST_VERIFIED),
            "type_resolution": (0.20, EvidenceType.TYPE_VERIFIED),
            "reachability": (0.15, EvidenceType.REACHABLE),
            "dataflow": (0.10, EvidenceType.DATAFLOW_VERIFIED),
            "taint_analysis": (0.05, EvidenceType.TAINT_PATH),
            "ai_validation": (0.05, EvidenceType.AI_VALIDATED),
            "context_auth": (0.10, EvidenceType.CONTEXT_AUTH),
            "context_user_input": (0.10, EvidenceType.CONTEXT_USER_INPUT),
            "dependency_known": (0.30, EvidenceType.DEPENDENCY_KNOWN_VULN),
            "secret_classification": (0.10, EvidenceType.SECRET_CLASSIFIED),
            "call_graph": (0.10, EvidenceType.CALL_GRAPH_CONNECTED),
        }

        raw_score = 0.0
        total_weight = 0.0

        for name, value in [
            ("pattern_match", pattern_match),
            ("ast_verified", ast_verified),
            ("type_resolution", type_resolution),
            ("reachability", reachability),
            ("dataflow", dataflow),
            ("taint_analysis", taint_analysis),
            ("ai_validation", ai_validation),
            ("context_auth", context_auth),
            ("context_user_input", context_user_input),
            ("dependency_known", dependency_known),
            ("secret_classification", secret_classification),
            ("call_graph", call_graph),
        ]:
            if value > 0:
                weight, evidence_type = weights[name]
                if value >= 0.7:
                    strength = EvidenceStrength.STRONG
                elif value >= 0.4:
                    strength = EvidenceStrength.MODERATE
                else:
                    strength = EvidenceStrength.WEAK

                evidences.append(self.create_evidence(
                    evidence_type=evidence_type,
                    signal=name,
                    strength=strength,
                    reason=f"{name} contributed {value:.2f}",
                    contribution=value,
                ))
                raw_score += weight * value
                total_weight += weight

        if total_weight > 0:
            confidence = min(1.0, raw_score / total_weight * 1.5)
        else:
            confidence = 0.0

        return confidence, evidences
