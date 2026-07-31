"""Trust Engine - Evidence-based confidence scoring.

Every finding MUST contain evidence. No hardcoded confidence values.

Evidence categories:
  - REGEX_MATCH: Pattern matched in source code (weight: 20%)
  - AST_VERIFIED: AST analysis confirmed the vulnerable call (weight: 25%)
  - DATAFLOW_VERIFIED: Data flow tracks source to sink (weight: 20%)
  - TAINT_VERIFIED: Taint analysis confirms untrusted data reaches sink (weight: 20%)
  - REACHABILITY_VERIFIED: Code path is reachable (weight: 10%)
  - AI_VERIFIED: AI/LLM confirmed the finding (weight: 5%)

Final confidence = weighted sum of all evidence signals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EvidenceType(Enum):
    """Types of evidence that contribute to confidence."""
    REGEX_MATCH = "regex_match"
    AST_VERIFIED = "ast_verified"
    DATAFLOW_VERIFIED = "dataflow_verified"
    TAINT_VERIFIED = "taint_verified"
    REACHABILITY_VERIFIED = "reachability_verified"
    AI_VERIFIED = "ai_verified"
    CONTEXT_VERIFIED = "context_verified"
    TYPE_VERIFIED = "type_verified"
    SCOPE_VERIFIED = "scope_verified"
    DEPENDENCY_VERIFIED = "dependency_verified"
    NEGATIVE = "negative"


EVIDENCE_WEIGHTS = {
    EvidenceType.REGEX_MATCH: 0.15,
    EvidenceType.AST_VERIFIED: 0.25,
    EvidenceType.DATAFLOW_VERIFIED: 0.20,
    EvidenceType.TAINT_VERIFIED: 0.20,
    EvidenceType.REACHABILITY_VERIFIED: 0.10,
    EvidenceType.AI_VERIFIED: 0.05,
    EvidenceType.CONTEXT_VERIFIED: 0.05,
    EvidenceType.TYPE_VERIFIED: 0.05,
    EvidenceType.SCOPE_VERIFIED: 0.03,
    EvidenceType.DEPENDENCY_VERIFIED: 0.02,
}

NEGATIVE_EVIDENCE_PENALTIES = {
    "constant_value": -0.70,
    "placeholder_value": -0.80,
    "in_comment": -0.90,
    "in_example_code": -0.50,
    "in_test_file": -0.25,
    "in_generated_code": -0.30,
    "in_vendor_code": -1.00,
    "sanitized_input": -0.40,
    "unreachable_code": -0.80,
    "type_mismatch": -0.60,
    "wrong_eval_target": -0.70,
    "safe_library_call": -0.50,
    "aliased_import": -0.15,
    "conditional_only": -0.15,
    "dead_code": -0.90,
}


@dataclass
class Evidence:
    """A single piece of evidence for or against a finding."""
    evidence_type: EvidenceType
    signal: str
    weight: float
    confidence_contribution: float
    reason: str
    source_location: str = ""

    @property
    def net_contribution(self) -> float:
        return self.weight * self.confidence_contribution


@dataclass
class TrustScore:
    """Complete trust assessment for a finding."""
    score: float
    level: str
    evidences: list[Evidence] = field(default_factory=list)
    should_report: bool = True
    severity_adjustment: str = "no_change"
    reasoning: str = ""
    evidence_summary: str = ""

    @property
    def positive_evidences(self) -> list[Evidence]:
        return [e for e in self.evidences if e.evidence_type != EvidenceType.NEGATIVE and e.confidence_contribution > 0.5]

    @property
    def negative_evidences(self) -> list[Evidence]:
        return [e for e in self.evidences if e.evidence_type == EvidenceType.NEGATIVE]

    @property
    def verification_level(self) -> str:
        verified = set()
        for e in self.evidences:
            if e.evidence_type != EvidenceType.NEGATIVE and e.confidence_contribution > 0.5:
                verified.add(e.evidence_type.value)
        if not verified:
            return "unverified"
        if len(verified) >= 4:
            return "fully_verified"
        if len(verified) >= 2:
            return "partially_verified"
        return "single_evidence"


class TrustEngine:
    """Calculates trust scores for findings based on accumulated evidence.

    Usage:
        engine = TrustEngine()
        engine.add_evidence(EvidenceType.REGEX_MATCH, "pattern_matched", 0.9, "SQL injection pattern found")
        engine.add_evidence(EvidenceType.AST_VERIFIED, "call_confirmed", 0.95, "AST confirmed os.system() call")
        engine.add_evidence(EvidenceType.TAINT_VERIFIED, "user_input_to_sink", 0.9, "input() -> os.system()")
        score = engine.calculate()
    """

    def __init__(self, custom_weights: dict[EvidenceType, float] | None = None):
        self._evidences: list[Evidence] = []
        self._weights = dict(EVIDENCE_WEIGHTS)
        if custom_weights:
            self._weights.update(custom_weights)

    def add_evidence(
        self,
        evidence_type: EvidenceType,
        signal: str,
        confidence_contribution: float,
        reason: str,
        source_location: str = "",
    ) -> None:
        weight = self._weights.get(evidence_type, 0.05)
        self._evidences.append(Evidence(
            evidence_type=evidence_type,
            signal=signal,
            weight=weight,
            confidence_contribution=max(0.0, min(1.0, confidence_contribution)),
            reason=reason,
            source_location=source_location,
        ))

    def add_negative_evidence(
        self,
        signal: str,
        reason: str,
        penalty: float | None = None,
        source_location: str = "",
    ) -> None:
        if penalty is None:
            penalty = NEGATIVE_EVIDENCE_PENALTIES.get(signal, -0.3)
        self._evidences.append(Evidence(
            evidence_type=EvidenceType.NEGATIVE,
            signal=signal,
            weight=1.0,
            confidence_contribution=max(-1.0, min(0.0, penalty)),
            reason=reason,
            source_location=source_location,
        ))

    def calculate(self, base_score: float = 0.0) -> TrustScore:
        if not self._evidences:
            return TrustScore(
                score=0.1,
                level="speculative",
                should_report=False,
                severity_adjustment=self._adjust_severity(0.1),
                reasoning="No evidence collected. Finding cannot be trusted.",
                evidence_summary="No evidence",
            )

        positive_sum = 0.0
        negative_sum = 0.0
        positive_weight_sum = 0.0

        for ev in self._evidences:
            if ev.evidence_type == EvidenceType.NEGATIVE:
                negative_sum += abs(ev.confidence_contribution)
            elif ev.confidence_contribution > 0.5:
                positive_sum += ev.net_contribution
                positive_weight_sum += ev.weight

        normalized_positive = positive_sum / max(positive_weight_sum, 0.01) if positive_weight_sum > 0 else 0.0

        raw_score = base_score + normalized_positive - negative_sum
        score = max(0.0, min(1.0, raw_score))

        level = self._score_to_level(score)
        should_report = score >= 0.15 or any(
            e.evidence_type in (EvidenceType.TAINT_VERIFIED, EvidenceType.DATAFLOW_VERIFIED)
            and e.confidence_contribution > 0.7
            for e in self._evidences
        )

        severity_adj = self._adjust_severity(score)
        reasoning = self._build_reasoning()
        evidence_summary = self._build_evidence_summary()

        return TrustScore(
            score=round(score, 3),
            level=level,
            evidences=list(self._evidences),
            should_report=should_report,
            severity_adjustment=severity_adj,
            reasoning=reasoning,
            evidence_summary=evidence_summary,
        )

    @staticmethod
    def _score_to_level(score: float) -> str:
        if score >= 0.9:
            return "certain"
        elif score >= 0.7:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.2:
            return "low"
        return "speculative"

    @staticmethod
    def _adjust_severity(score: float) -> str:
        if score >= 0.7:
            return "no_change"
        elif score >= 0.4:
            return "reduce_one_level"
        elif score >= 0.2:
            return "reduce_to_medium_max"
        return "reduce_to_low"

    def _build_reasoning(self) -> str:
        pos = [e for e in self._evidences if e.evidence_type != EvidenceType.NEGATIVE and e.confidence_contribution > 0.5]
        neg = [e for e in self._evidences if e.evidence_type == EvidenceType.NEGATIVE]

        parts = []
        if pos:
            parts.append("Evidence FOR: " + "; ".join(f"{e.signal} ({e.reason})" for e in pos[:4]))
        if neg:
            parts.append("Evidence AGAINST: " + "; ".join(f"{e.signal} ({e.reason})" for e in neg[:3]))

        if not parts:
            parts.append("Insufficient evidence for reliable assessment.")
        return " ".join(parts)

    def _build_evidence_summary(self) -> str:
        verified = [
            e.evidence_type.value.replace("_", " ")
            for e in self._evidences
            if e.evidence_type != EvidenceType.NEGATIVE and e.confidence_contribution > 0.5
        ]
        if not verified:
            return "Unverified"
        return ", ".join(verified)

    def reset(self) -> None:
        self._evidences.clear()


def build_trust_from_pipeline(
    has_regex_match: bool = False,
    has_ast_verification: bool = False,
    has_dataflow_verification: bool = False,
    has_taint_verification: bool = False,
    is_reachable: bool = False,
    has_ai_verification: bool = False,
    is_sanitized: bool = False,
    is_constant: bool = False,
    is_placeholder: bool = False,
    is_in_comment: bool = False,
    is_in_test: bool = False,
    is_in_generated: bool = False,
    is_in_vendor: bool = False,
    is_type_mismatch: bool = False,
    is_wrong_eval_target: bool = False,
    is_safe_library: bool = False,
    base_score: float = 0.0,
) -> TrustScore:
    """Convenience function to build a TrustScore from pipeline signals."""
    engine = TrustEngine()

    if has_regex_match:
        engine.add_evidence(EvidenceType.REGEX_MATCH, "pattern_matched", 0.85, "Regex pattern matched in source code")
    if has_ast_verification:
        engine.add_evidence(EvidenceType.AST_VERIFIED, "ast_call_confirmed", 0.95, "AST analysis confirmed vulnerable function call")
    if has_dataflow_verification:
        engine.add_evidence(EvidenceType.DATAFLOW_VERIFIED, "dataflow_tracked", 0.9, "Data flow analysis tracks source to sink")
    if has_taint_verification:
        engine.add_evidence(EvidenceType.TAINT_VERIFIED, "taint_confirmed", 0.9, "Taint analysis confirms untrusted data reaches dangerous sink")
    if is_reachable:
        engine.add_evidence(EvidenceType.REACHABILITY_VERIFIED, "code_reachable", 0.85, "Code path is reachable from entry points")
    if has_ai_verification:
        engine.add_evidence(EvidenceType.AI_VERIFIED, "ai_confirmed", 0.8, "AI analysis confirms this is a real vulnerability")

    if is_sanitized:
        engine.add_negative_evidence("sanitized_input", "Input is sanitized before reaching the sink", -0.40)
    if is_constant:
        engine.add_negative_evidence("constant_value", "Value is a constant - not attacker-controllable", -0.70)
    if is_placeholder:
        engine.add_negative_evidence("placeholder_value", "Value is a placeholder or dummy", -0.80)
    if is_in_comment:
        engine.add_negative_evidence("in_comment", "Found in comment - not executable code", -0.90)
    if is_in_test:
        engine.add_negative_evidence("in_test_file", "Found in test file - reduced confidence", -0.25)
    if is_in_generated:
        engine.add_negative_evidence("in_generated_code", "Code appears to be auto-generated", -0.30)
    if is_in_vendor:
        engine.add_negative_evidence("in_vendor_code", "Finding is in vendored code", -1.00)
    if is_type_mismatch:
        engine.add_negative_evidence("type_mismatch", "Type analysis shows this is not the dangerous variant", -0.60)
    if is_wrong_eval_target:
        engine.add_negative_evidence("wrong_eval_target", "eval() is called on a safe object (e.g., pandas.eval, not builtins.eval)", -0.70)
    if is_safe_library:
        engine.add_negative_evidence("safe_library_call", "Call is to a safe library function, not the dangerous builtin", -0.50)

    return engine.calculate(base_score=base_score)
