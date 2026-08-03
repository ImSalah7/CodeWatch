"""Severity Gating Engine.

Findings may only be reported as HIGH or CRITICAL when they carry strong
evidence. Severity is never promoted - it is only ever demoted, based on
two independent guards:

  1. Confidence floor: each severity level requires a minimum confidence
     score (CRITICAL >= 0.85, HIGH >= 0.60, ...). A HIGH finding reported
     at 0.4 confidence is not credible.
  2. Evidence strength: HIGH/CRITICAL findings must be backed by at least
     one piece of strong evidence (AST verification, taint path, secret
     classification, type verification, ...). A bare regex match is not
     enough to justify a HIGH/CRITICAL label.

This keeps precision high: quality and trustworthiness over raw counts.
"""

from __future__ import annotations

from typing import Any

from .models import Severity


SEVERITY_CONFIDENCE_FLOORS: dict[str, float] = {
    "CRITICAL": 0.85,
    "HIGH": 0.60,
    "MEDIUM": 0.35,
    "LOW": 0.20,
    "INFO": 0.00,
}

_SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Evidence types that substantiate a HIGH/CRITICAL finding. A plain regex
# match (always present after the first validation stage) is intentionally
# excluded so a regex hit alone cannot claim HIGH/CRITICAL.
_TRUSTED_STRONG_TYPES: frozenset[str] = frozenset({
    "ast_verified",
    "literal_assignment",
    "type_verified",
    "reachable",
    "taint_path",
    "dataflow_verified",
    "dependency_known_vuln",
    "secret_classified",
    "call_graph_connected",
    "import_verified",
    "cross_file_taint",
    "context_sink_dangerous",
})

# Verification levels / confidence levels that imply strong evidence.
_STRONG_VERIFICATION_LEVELS: frozenset[str] = frozenset({
    "certain",
    "high",
    "verified",
    "fully_verified",
    "highly_verified",
})


def _evidence_summaries(finding: Any) -> list[dict]:
    evidence = getattr(finding, "evidence", None) or []
    if isinstance(evidence, dict):
        return [evidence]
    if isinstance(evidence, list):
        return [e for e in evidence if isinstance(e, dict)]
    return []


def _evidence_strength(finding: Any) -> tuple[bool, bool]:
    """Return (has_strong_trusted_evidence, has_any_trusted_evidence)."""
    has_strong = False
    has_trusted = False
    for summary in _evidence_summaries(finding):
        entries = summary.get("evidences", []) if isinstance(summary, dict) else []
        if summary.get("type") and isinstance(summary.get("strength"), str):
            entries = [summary]
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            etype = entry.get("type", "")
            strength = entry.get("strength", "")
            if etype in _TRUSTED_STRONG_TYPES:
                has_trusted = True
                if strength == "strong":
                    has_strong = True
    return has_strong, has_trusted


def _has_strong_evidence(finding: Any) -> bool:
    has_strong, has_trusted = _evidence_strength(finding)
    if has_strong:
        return True
    level = getattr(finding, "verification_level", "") or ""
    if level in _STRONG_VERIFICATION_LEVELS:
        return True
    confidence = getattr(finding, "confidence", 0.0) or 0.0
    return bool(confidence >= 0.7 and has_trusted)


def _highest_affordable(confidence: float) -> str:
    for name in _SEVERITY_ORDER:
        if confidence >= SEVERITY_CONFIDENCE_FLOORS[name]:
            return name
    return "INFO"


def gate_severity(finding: Any) -> tuple[Severity, str]:
    """Return (severity, note). Never promotes; note is empty when unchanged."""
    severity = finding.severity
    sev_name = (severity.value if hasattr(severity, "value") else str(severity)).upper()
    if sev_name not in SEVERITY_CONFIDENCE_FLOORS:
        return severity, ""

    confidence = getattr(finding, "confidence", 0.0) or 0.0
    floor = SEVERITY_CONFIDENCE_FLOORS[sev_name]
    target = sev_name
    note = ""

    if confidence < floor:
        target = _highest_affordable(confidence)
        note = (
            f"Severity {sev_name} demoted to {target}: confidence "
            f"{confidence:.2f} is below the {floor:.2f} required for {sev_name}."
        )

    if target in ("CRITICAL", "HIGH") and not _has_strong_evidence(finding):
        target = "MEDIUM"
        note = (
            f"Severity {sev_name} demoted to MEDIUM: no strong evidence "
            "(AST verification, taint path, or secret classification) confirms the finding."
        )

    if target == sev_name:
        return severity, ""
    return Severity[target], note


def apply_severity_gate(finding: Any) -> bool:
    """Demote finding.severity in place when evidence/confidence is weak.

    Returns True if the severity was changed.
    """
    new_severity, note = gate_severity(finding)
    if new_severity is finding.severity or new_severity == finding.severity:
        return False
    finding.severity = new_severity
    reasoning = getattr(finding, "confidence_reasoning", "") or ""
    if note and note not in reasoning:
        finding.confidence_reasoning = f"{note} | {reasoning}" if reasoning else note
    return True
