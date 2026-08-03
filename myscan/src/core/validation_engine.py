"""Validation Engine - Multi-stage validation pipeline for findings.

Every detection MUST pass through this engine before becoming a finding.
The pipeline is:

  Pattern Match -> AST Validation -> Type Resolution -> Context Analysis
  -> Data Flow -> Reachability -> Confidence Calculation -> Report

If validation fails at any stage, DO NOT report the finding.
"""

from __future__ import annotations

import math
import re

from .context_analyzer import (
    ContextType,
    analyze_file_context,
)
from .evidence_engine import (
    Evidence,
    EvidenceEngine,
    EvidenceStrength,
    EvidenceType,
    ValidationResult,
)
from .import_resolver import ImportResolutionResult
from .reachability import ReachabilityResult
from .type_resolver import TypeResolver

DANGEROUS_CALL_RULE_PREFIXES = {
    "eval", "exec", "compile", "__import__",
}

SECRET_RULE_IDS = {
    "SEC_AWS_ACCESS_KEY", "SEC_AWS_SECRET_KEY", "SEC_GITHUB_TOKEN",
    "SEC_PASSWORD_ASSIGNMENT", "SEC_DATABASE_URL", "SEC_GENERIC_API_KEY",
    "SEC_PRIVATE_KEY_HEADER", "SEC_NPM_TOKEN", "SEC_PYPI_TOKEN",
    "SEC_SLACK_TOKEN", "SEC_STRIPE_KEY", "SEC_TWILIO_KEY",
    "SEC_SENDGRID_KEY", "SEC_HEROKU_API_KEY", "SEC_GOOGLE_API_KEY",
    "SEC_AZURE_KEY", "SEC_DEPLOY_KEY", "SEC_JWT_SECRET",
    "SEC_HARD_CODED_SECRET", "SEC_BASIC_AUTH", "SEC_BEARER_TOKEN",
}

NOT_LITERAL_PREFIXES = (
    "input(", "os.getenv(", "os.environ", "st.text_input(",
    "request.form[", "request.args[", "request.headers[",
    "config.", "env(", "dotenv", "getenv",
    "secrets.token", "uuid.uuid", "hashlib.",
)

PLACEHOLDER_KEYWORDS = {
    "changeme", "password123", "admin123", "test123", "example",
    "your_key_here", "replace_me", "set_me", "placeholder", "dummy",
    "fake", "xxx", "todo", "fixme", "xxxx", "000000", "aaaaaa",
    "placeholder_key", "change_me", "replace_this",
}

from .secret_signals import (
    is_weak_credential_value,  # noqa: F401  (re-exported for backwards compatibility)
    score_secret,
    secret_rule_kind,
    STRONG_PASSWORD_PATTERNS,  # noqa: F401  (re-exported for backwards compatibility)
)


class ValidationPipeline:
    """Multi-stage validation pipeline for SAST findings."""

    def __init__(self, min_confidence: float = 0.15, secret_confidence_threshold: float = 0.6):
        self.min_confidence = min_confidence
        self.secret_confidence_threshold = secret_confidence_threshold
        self.evidence_engine = EvidenceEngine(min_confidence=min_confidence)
        self.type_resolver = TypeResolver()
        self._import_cache: ImportResolutionResult | None = None
        self._reachability_cache: ReachabilityResult | None = None

    def set_import_resolution(self, result: ImportResolutionResult) -> None:
        self._import_cache = result

    def set_reachability(self, result: ReachabilityResult) -> None:
        self._reachability_cache = result

    def validate_finding(
        self,
        finding: dict,
        file_content: str = "",
        ast_result: dict | None = None,
        type_resolver_result: dict | None = None,
    ) -> dict | None:
        """Run the full validation pipeline on a single finding.

        Returns the validated finding dict with evidence attached if it passes,
        or None if it should be rejected.
        """
        positive_evidences: list[Evidence] = []
        negative_evidences: list[Evidence] = []

        rule_id = finding.get("rule_id", "")
        finding.get("title", "")
        finding.get("severity", "info")
        finding.get("confidence", 0.0)
        category = finding.get("category", "")
        finding.get("language", "python")
        file_path = finding.get("file_path", "")
        line = finding.get("line", 0)
        finding.get("code_snippet", "")
        finding.get("tags", [])
        finding.get("raw_secret", "")

        file_path.lower()

        # Stage 1: Pattern Validation
        # A regex matched, so we always have at least weak evidence.
        positive_evidences.append(
            self.evidence_engine.create_evidence(
                evidence_type=EvidenceType.REGEX_MATCH,
                signal="regex_matched",
                strength=EvidenceStrength.STRONG,
                reason=f"Regex pattern matched for rule {rule_id}",
                contribution=0.85,
                source_location=f"{file_path}:{line}",
            )
        )

        # Stage 2: AST Validation
        ast_rejection = self._validate_ast(
            finding, ast_result, file_content, positive_evidences, negative_evidences
        )
        if ast_rejection is not None:
            return None

        # Stage 3: Type Resolution
        type_rejection = self._validate_type(
            finding, ast_result, type_resolver_result, positive_evidences, negative_evidences
        )
        if type_rejection is not None:
            return None

        # Stage 4: Context Analysis
        self._validate_context(
            finding, file_content, positive_evidences, negative_evidences
        )

        # Stage 6: Secret-Specific Validation
        if category == "SECRET" or rule_id.startswith("SEC_"):
            secret_rejection = self._validate_secret(
                finding, file_content, positive_evidences, negative_evidences
            )
            if secret_rejection is not None:
                return None

        # Stage 7: Import Resolution Validation
        self._validate_imports(
            finding, file_content, positive_evidences, negative_evidences
        )

        # Stage 8: Reachability Validation
        self._validate_reachability(
            finding, positive_evidences, negative_evidences
        )

        # Stage 9: Evidence Collection is done above. Now evaluate.
        # Stage 10: Confidence Calculation
        result = self.evidence_engine.evaluate(
            positive_evidences=positive_evidences,
            negative_evidences=negative_evidences,
            min_evidence=1,
        )

        # Stage 11: Decision
        if not result.passed or not result.should_report:
            return None

        if result.confidence < self.min_confidence:
            return None

        validated = dict(finding)
        validated["confidence"] = round(result.confidence, 3)
        validated["verification_level"] = result.verification_level
        validated["evidence"] = result.to_dict()
        validated["validated"] = True
        likely_fp, likely_fp_reason = self._likely_false_positive(result)
        is_secret = category == "SECRET" or rule_id.startswith("SEC_")
        if is_secret and result.confidence < self.secret_confidence_threshold:
            likely_fp = True
            threshold_reason = (
                f"Confidence {result.confidence:.2f} is below the secret confidence "
                f"threshold ({self.secret_confidence_threshold:.2f})"
            )
            likely_fp_reason = "; ".join(filter(None, [likely_fp_reason, threshold_reason]))
        validated["likely_false_positive"] = likely_fp
        validated["likely_false_positive_reason"] = likely_fp_reason
        return validated

    def _likely_false_positive(self, result: ValidationResult) -> tuple[bool, str]:
        """Flag findings that validation still reported but that carry weak or
        contradictory evidence, so users can triage them first.

        Returns (is_likely_fp, reason). A finding is likely a false positive when
        validation recorded negative (contradictory) evidence, or when it was
        reported purely on a regex match without any corroborating evidence.
        """
        if result.negative_count > 0:
            reasons = [e.reason for e in result.negative_evidences if e.reason]
            reason = "; ".join(reasons) if reasons else "Contradictory evidence found during validation"
            return True, reason
        if result.verification_level in ("unverified", "single_evidence") and result.confidence < 0.5:
            return True, (
                "Reported on a single regex match without corroborating evidence "
                f"(confidence {result.confidence:.2f}, verification level '{result.verification_level}')"
            )
        return False, ""

    def _validate_ast(
        self,
        finding: dict,
        ast_result: dict | None,
        file_content: str,
        positive_evidences: list[Evidence],
        negative_evidences: list[Evidence],
    ) -> str | None:
        """Stage 2: AST Validation.

        Verify the vulnerable construct exists in the AST when available.
        Returns a rejection reason string if the finding should be rejected, else None.
        """
        rule_id = finding.get("rule_id", "")
        code_snippet = finding.get("code_snippet", "")
        line = finding.get("line", 0)

        is_call_finding = any(
            rule_id.lower().startswith(prefix)
            for prefix in DANGEROUS_CALL_RULE_PREFIXES
        )

        if not ast_result:
            return None

        ast_calls = ast_result.get("calls", [])
        ast_assignments = ast_result.get("assignments", [])

        if is_call_finding:
            call_name_lower = _extract_call_name_from_snippet(code_snippet)
            found_in_ast = False
            for call in ast_calls:
                ast_call_name = call.get("name", "") or call.get("full_name", "")
                if _names_match_fuzzy(call_name_lower, ast_call_name):
                    found_in_ast = True
                    break

            if not found_in_ast:
                ast_line = _find_call_at_line(ast_calls, line)
                if ast_line is not None:
                    found_in_ast = True

            if found_in_ast:
                positive_evidences.append(
                    self.evidence_engine.create_evidence(
                        evidence_type=EvidenceType.AST_VERIFIED,
                        signal="ast_call_confirmed",
                        strength=EvidenceStrength.STRONG,
                        reason=f"AST confirmed {call_name_lower} call exists in source",
                        contribution=0.95,
                        source_location=f"{finding.get('file_path', '')}:{line}",
                    )
                )
            else:
                negative_evidences.append(
                    self.evidence_engine.create_negative_evidence(
                        signal="ast_mismatch",
                        reason=(
                            f"AST did not find {call_name_lower} call at or near "
                            f"line {line}. Regex matched but AST cannot confirm."
                        ),
                        penalty=-0.50,
                        source_location=f"{finding.get('file_path', '')}:{line}",
                    )
                )

        if rule_id.startswith("SEC_") or finding.get("category") == "SECRET":
            found_assignment = False
            for assign in ast_assignments:
                target = assign.get("target", "")
                if _variable_matches_snippet(target, code_snippet):
                    found_assignment = True
                    break

            if found_assignment:
                positive_evidences.append(
                    self.evidence_engine.create_evidence(
                        evidence_type=EvidenceType.AST_VERIFIED,
                        signal="ast_assignment_confirmed",
                        strength=EvidenceStrength.STRONG,
                        reason="AST confirmed assignment exists",
                        contribution=0.90,
                        source_location=f"{finding.get('file_path', '')}:{line}",
                    )
                )

        return None

    def _validate_type(
        self,
        finding: dict,
        ast_result: dict | None,
        type_resolver_result: dict | None,
        positive_evidences: list[Evidence],
        negative_evidences: list[Evidence],
    ) -> str | None:
        """Stage 3: Type Resolution.

        For function call findings, determine if the call is actually dangerous.
        Returns rejection reason if the call is safe, else None.
        """
        rule_id = finding.get("rule_id", "")
        code_snippet = finding.get("code_snippet", "")

        is_call_finding = any(
            rule_id.lower().startswith(prefix)
            for prefix in DANGEROUS_CALL_RULE_PREFIXES
        )

        if not is_call_finding:
            return None

        call_name = _extract_call_name_from_snippet(code_snippet)
        if not call_name:
            return None

        bare_call = call_name.split(".")[-1] if "." in call_name else call_name
        owner = call_name.rsplit(".", 1)[0] if "." in call_name else ""

        safe_library_evals = {
            "torch", "torch.nn", "pandas", "numpy", "scipy",
            "sklearn", "xgboost", "lightgbm", "dask",
        }

        if owner:
            owner_parts = owner.split(".")
            for part in owner_parts:
                if part in safe_library_evals:
                    negative_evidences.append(
                        self.evidence_engine.create_negative_evidence(
                            signal="safe_library",
                            reason=(
                                f"{call_name} belongs to a safe library ({part}). "
                                f"Not the dangerous builtin."
                            ),
                            penalty=-0.70,
                        )
                    )
                    return "safe_library_call"

        if type_resolver_result:
            safety = type_resolver_result.get("safety", "unknown")
            if safety == "safe":
                negative_evidences.append(
                    self.evidence_engine.create_negative_evidence(
                        signal="safe_library",
                        reason=f"TypeResolver determined {call_name} is safe",
                        penalty=-0.70,
                    )
                )
                return "type_safe"
            elif safety == "dangerous":
                positive_evidences.append(
                    self.evidence_engine.create_evidence(
                        evidence_type=EvidenceType.TYPE_VERIFIED,
                        signal="type_dangerous",
                        strength=EvidenceStrength.STRONG,
                        reason=f"TypeResolver confirmed {call_name} is the dangerous builtin",
                        contribution=0.95,
                    )
                )
            elif safety == "conditionally_safe":
                positive_evidences.append(
                    self.evidence_engine.create_evidence(
                        evidence_type=EvidenceType.TYPE_VERIFIED,
                        signal="type_conditionally_safe",
                        strength=EvidenceStrength.MODERATE,
                        reason=f"TypeResolver: {call_name} is conditionally safe",
                        contribution=0.50,
                    )
                )
        else:
            if bare_call in KNOWN_DANGEROUS_CALLS:
                positive_evidences.append(
                    self.evidence_engine.create_evidence(
                        evidence_type=EvidenceType.TYPE_VERIFIED,
                        signal="type_likely_dangerous",
                        strength=EvidenceStrength.MODERATE,
                        reason=f"{call_name} appears to be the dangerous builtin (no type resolution available)",
                        contribution=0.65,
                    )
                )

        return None

    def _validate_imports(
        self,
        finding: dict,
        file_content: str,
        positive_evidences: list[Evidence],
        negative_evidences: list[Evidence],
    ) -> None:
        """Stage 7: Import Resolution Validation.

        Verify that the function/class being called is actually imported and available.
        """
        rule_id = finding.get("rule_id", "")
        code_snippet = finding.get("code_snippet", "")
        file_path = finding.get("file_path", "")

        is_call_finding = any(
            rule_id.lower().startswith(prefix)
            for prefix in DANGEROUS_CALL_RULE_PREFIXES
        )
        if not is_call_finding or not self._import_cache:
            return

        call_name = _extract_call_name_from_snippet(code_snippet)
        if not call_name:
            return

        root = call_name.split(".")[0] if "." in call_name else call_name
        for imp in self._import_cache.imports:
            if imp.source_file != file_path:
                continue
            for alias, real in imp.aliases.items():
                if alias == root or real == root.split(".")[-1]:
                    positive_evidences.append(
                        self.evidence_engine.create_evidence(
                            evidence_type=EvidenceType.AST_VERIFIED,
                            signal="import_confirmed",
                            strength=EvidenceStrength.MODERATE,
                            reason=f"Import confirmed: {root} is imported in {file_path}",
                            contribution=0.70,
                        )
                    )
                    return

        if root in ("eval", "exec", "compile", "__import__"):
            positive_evidences.append(
                self.evidence_engine.create_evidence(
                    evidence_type=EvidenceType.AST_VERIFIED,
                    signal="builtin_not_imported",
                    strength=EvidenceStrength.MODERATE,
                    reason=f"{root} is a builtin, no import needed",
                    contribution=0.60,
                )
            )
        elif "." in call_name:
            negative_evidences.append(
                self.evidence_engine.create_negative_evidence(
                    signal="import_not_found",
                    reason=f"Could not find import for {root} in {file_path}",
                    penalty=-0.30,
                )
            )

    def _validate_reachability(
        self,
        finding: dict,
        positive_evidences: list[Evidence],
        negative_evidences: list[Evidence],
    ) -> None:
        """Stage 8: Reachability Validation.

        Check if the vulnerable code is actually reachable from entry points.
        """
        if not self._reachability_cache:
            return

        file_path = finding.get("file_path", "")
        line = finding.get("line", 0)
        rule_id = finding.get("rule_id", "")

        is_call_finding = any(
            rule_id.lower().startswith(prefix)
            for prefix in DANGEROUS_CALL_RULE_PREFIXES
        )
        if not is_call_finding:
            return

        for freach in self._reachability_cache.functions.values():
            if freach.file_path == file_path and abs(freach.line - line) <= 3:
                if freach.status.value == "dead_code":
                    negative_evidences.append(
                        self.evidence_engine.create_negative_evidence(
                            signal="dead_code",
                            reason=f"Function {freach.name} is dead code (never called)",
                            penalty=-0.40,
                        )
                    )
                elif freach.status.value == "unused":
                    negative_evidences.append(
                        self.evidence_engine.create_negative_evidence(
                            signal="unused_function",
                            reason=f"Function {freach.name} is defined but never referenced",
                            penalty=-0.30,
                        )
                    )
                elif freach.status.value == "test_only":
                    negative_evidences.append(
                        self.evidence_engine.create_negative_evidence(
                            signal="test_only",
                            reason=f"Function {freach.name} is only called from tests",
                            penalty=-0.20,
                        )
                    )
                elif freach.status.value == "deprecated":
                    negative_evidences.append(
                        self.evidence_engine.create_negative_evidence(
                            signal="deprecated",
                            reason=f"Function {freach.name} is marked deprecated",
                            penalty=-0.15,
                        )
                    )
                elif freach.is_entry_point:
                    positive_evidences.append(
                        self.evidence_engine.create_evidence(
                            evidence_type=EvidenceType.CONTEXT_AUTH,
                            signal="entry_point",
                            strength=EvidenceStrength.STRONG,
                            reason=f"Function {freach.name} is an entry point",
                            contribution=0.80,
                        )
                    )
                elif freach.status.value == "reachable":
                    positive_evidences.append(
                        self.evidence_engine.create_evidence(
                            evidence_type=EvidenceType.CONTEXT_AUTH,
                            signal="reachable",
                            strength=EvidenceStrength.MODERATE,
                            reason=f"Function {freach.name} is reachable from entry points",
                            contribution=0.60,
                        )
                    )
                break

    def _validate_context(
        self,
        finding: dict,
        file_content: str,
        positive_evidences: list[Evidence],
        negative_evidences: list[Evidence],
    ) -> None:
        """Stage 4: Context Analysis.

        Check if the finding is in test code, examples, comments, generated code,
        or vendor code. Apply positive or negative evidence accordingly.
        """
        file_path = finding.get("file_path", "")
        line = finding.get("line", 0)
        finding.get("code_snippet", "")
        category = finding.get("category", "")

        context_type = analyze_file_context(file_path)

        if context_type == ContextType.VENDOR:
            negative_evidences.append(
                self.evidence_engine.create_negative_evidence(
                    signal="in_vendor",
                    reason=f"File {file_path} is vendor/third-party code",
                    penalty=-1.00,
                )
            )
        elif context_type == ContextType.EXAMPLE:
            negative_evidences.append(
                self.evidence_engine.create_negative_evidence(
                    signal="in_example",
                    reason=f"File {file_path} is example/sample code",
                    penalty=-0.50,
                )
            )
        elif context_type == ContextType.DOCUMENTATION:
            negative_evidences.append(
                self.evidence_engine.create_negative_evidence(
                    signal="in_comment",
                    reason=f"File {file_path} is documentation",
                    penalty=-0.90,
                )
            )
        elif context_type == ContextType.GENERATED:
            negative_evidences.append(
                self.evidence_engine.create_negative_evidence(
                    signal="in_generated",
                    reason=f"File {file_path} appears to be auto-generated",
                    penalty=-0.30,
                )
            )
        elif context_type == ContextType.TEST:
            negative_evidences.append(
                self.evidence_engine.create_negative_evidence(
                    signal="in_test",
                    reason=f"File {file_path} is a test file",
                    penalty=-0.25,
                )
            )
        elif context_type == ContextType.INTERNAL:
            positive_evidences.append(
                self.evidence_engine.create_evidence(
                    evidence_type=EvidenceType.CONTEXT_AUTH,
                    signal="production_code",
                    strength=EvidenceStrength.MODERATE,
                    reason=f"File {file_path} is production/internal code",
                    contribution=0.70,
                )
            )

        lines = file_content.splitlines()
        line_idx = line - 1
        if 0 <= line_idx < len(lines):
            line_text = lines[line_idx].strip()
            if line_text.startswith(("#", "//")):
                negative_evidences.append(
                    self.evidence_engine.create_negative_evidence(
                        signal="in_comment",
                        reason="Finding is on a comment line",
                        penalty=-0.90,
                    )
                )

        if file_content:
            lines_for_check = file_content.splitlines()
            check_start = max(0, line_idx - 3)
            check_end = min(len(lines_for_check), line_idx + 2)
            nearby_text = " ".join(
                lines_for_check[i].lower()
                for i in range(check_start, check_end)
            )

            if "autogenerated" in nearby_text or "auto-generated" in nearby_text:
                negative_evidences.append(
                    self.evidence_engine.create_negative_evidence(
                        signal="in_generated",
                        reason="Nearby code has auto-generated markers",
                        penalty=-0.30,
                    )
                )

        if category == "SECRET" or finding.get("rule_id", "").startswith("SEC_"):
            if context_type in (
                ContextType.CONFIGURATION, ContextType.INTERNAL,
                ContextType.TEST, ContextType.EXAMPLE,
            ):
                pass
            else:
                if context_type == ContextType.INTERNAL:
                    positive_evidences.append(
                        self.evidence_engine.create_evidence(
                            evidence_type=EvidenceType.SECRET_CLASSIFIED,
                            signal="secret_in_production",
                            strength=EvidenceStrength.MODERATE,
                            reason="Secret found in production code path",
                            contribution=0.70,
                        )
                    )

    def _validate_secret(
        self,
        finding: dict,
        file_content: str,
        positive_evidences: list[Evidence],
        negative_evidences: list[Evidence],
    ) -> str | None:
        """Stage 5: Secret-Specific Validation.

        For SECRET category findings, check if the value is a true literal,
        classify the secret type, and calculate entropy/strength.

        Returns rejection reason if the secret is not a literal, else None.
        """
        rule_id = finding.get("rule_id", "")
        code_snippet = finding.get("code_snippet", "")
        tags = finding.get("tags", [])
        raw_secret = finding.get("raw_secret", "")

        if rule_id == "SEC_PASSWORD_ASSIGNMENT" or "password" in rule_id.lower():
            password_rejection = self._validate_password_assignment(
                code_snippet, negative_evidences
            )
            if password_rejection is not None:
                return password_rejection

        value = _extract_rhs_value(code_snippet)
        if value and not raw_secret:
            raw_secret = value

        if raw_secret:
            stripped = raw_secret.strip("'\"").strip()
            if stripped.lower() in PLACEHOLDER_KEYWORDS:
                negative_evidences.append(
                    self.evidence_engine.create_negative_evidence(
                        signal="placeholder",
                        reason=f"Value '{stripped[:30]}' is a known placeholder",
                        penalty=-0.80,
                    )
                )
                return "placeholder_value"

            if len(stripped) < 4:
                negative_evidences.append(
                    self.evidence_engine.create_negative_evidence(
                        signal="variable_reference",
                        reason=f"Value '{stripped}' is too short to be a real secret",
                        penalty=-0.60,
                    )
                )
                return "value_too_short"

            var_match = re.match(r"\s*(\w+)\s*[=:]", code_snippet)
            if var_match and var_match.group(1).lower() == stripped.lower():
                negative_evidences.append(
                    self.evidence_engine.create_negative_evidence(
                        signal="self_referential",
                        reason=(
                            f"Value '{stripped}' equals the variable name - "
                            "placeholder, not a real credential"
                        ),
                        penalty=-0.80,
                    )
                )
                return "self_referential_value"

            if is_weak_credential_value(stripped):
                negative_evidences.append(
                    self.evidence_engine.create_negative_evidence(
                        signal="weak_value",
                        reason=(
                            f"Value '{stripped[:30]}' is a keyboard walk, repeated run, "
                            "or sequential string - not a real credential"
                        ),
                        penalty=-0.80,
                    )
                )
                return "weak_credential_value"

            # Multi-signal gate: require corroborating signals beyond the regex
            # match. Values that are prose, uniform charset, common words, or
            # credential-less DB URLs are rejected here even if the scanner was
            # lenient.
            variable_match = re.match(r"\s*(\w+)\s*[=:]", code_snippet)
            varname = variable_match.group(1) if variable_match else ""
            rule_kind = secret_rule_kind(rule_id)
            if rule_kind is None and ("://" in stripped or "://" in raw_secret):
                rule_kind = "db_url"
            if rule_kind:
                signal_score = score_secret(rule_kind, stripped, varname, is_literal=True)
                if not signal_score.reported:
                    negative_evidences.append(
                        self.evidence_engine.create_negative_evidence(
                            signal="multi_signal_reject",
                            reason=(
                                f"Value '{stripped[:30]}' rejected by multi-signal "
                                f"validation: {signal_score.reject_reason}"
                            ),
                            penalty=-0.80,
                        )
                    )
                    return f"multi_signal_reject:{signal_score.reject_reason}"

        secret_type = self._classify_secret(rule_id, code_snippet, tags)
        if secret_type:
            positive_evidences.append(
                self.evidence_engine.create_evidence(
                    evidence_type=EvidenceType.SECRET_CLASSIFIED,
                    signal="secret_classified",
                    strength=EvidenceStrength.STRONG,
                    reason=f"Secret classified as: {secret_type}",
                    contribution=0.85,
                    metadata={"secret_type": secret_type},
                )
            )

        if raw_secret:
            entropy = _calculate_entropy(raw_secret.strip("'\""))
            if entropy < 2.0:
                negative_evidences.append(
                    self.evidence_engine.create_negative_evidence(
                        signal="variable_reference",
                        reason=f"Secret has very low entropy ({entropy:.2f}), likely not a real credential",
                        penalty=-0.70,
                    )
                )
            elif entropy < 3.0:
                positive_evidences.append(
                    self.evidence_engine.create_evidence(
                        evidence_type=EvidenceType.SECRET_CLASSIFIED,
                        signal="low_entropy_secret",
                        strength=EvidenceStrength.WEAK,
                        reason=f"Secret has low-to-moderate entropy ({entropy:.2f})",
                        contribution=0.40,
                    )
                )
            else:
                positive_evidences.append(
                    self.evidence_engine.create_evidence(
                        evidence_type=EvidenceType.SECRET_CLASSIFIED,
                        signal="high_entropy_secret",
                        strength=EvidenceStrength.STRONG,
                        reason=f"Secret has high entropy ({entropy:.2f}), strong indicator of real credential",
                        contribution=0.90,
                    )
                )

        return None

    def _validate_password_assignment(
        self,
        code_snippet: str,
        negative_evidences: list[Evidence],
    ) -> str | None:
        """Check if a password-type finding is a literal assignment.

        Returns rejection reason if the value is not a literal, else None.
        """
        rhs = _extract_rhs_value(code_snippet)
        if not rhs:
            negative_evidences.append(
                self.evidence_engine.create_negative_evidence(
                    signal="not_literal",
                    reason="Could not extract right-hand side value from assignment",
                    penalty=-0.80,
                )
            )
            return "no_rhs_value"

        rhs_stripped = rhs.strip()
        rhs_lower = rhs_stripped.lower()

        for prefix in NOT_LITERAL_PREFIXES:
            if rhs_lower.startswith(prefix):
                negative_evidences.append(
                    self.evidence_engine.create_negative_evidence(
                        signal="not_literal",
                        reason=(
                            f"Password value '{rhs_stripped[:50]}' is a function call "
                            f"or dynamic source ({prefix}), not a hardcoded literal"
                        ),
                        penalty=-0.80,
                    )
                )
                return "function_call_not_literal"

        if rhs_stripped.startswith(("'", '"')) and rhs_stripped.endswith(("'", '"')):
            inner = rhs_stripped[1:-1]
            if inner and not any(ph in inner.lower() for ph in PLACEHOLDER_KEYWORDS):
                return None

        if rhs_stripped.startswith("(") and rhs_stripped.endswith(")"):
            inner = rhs_stripped[1:-1].strip()
            if inner.startswith(("'", '"')) and inner.endswith(("'", '"')):
                return None

        if _looks_like_variable_reference(rhs_stripped):
            negative_evidences.append(
                self.evidence_engine.create_negative_evidence(
                    signal="variable_reference",
                    reason=(
                        f"Password value '{rhs_stripped[:50]}' appears to be a variable "
                        f"reference, not a hardcoded literal"
                    ),
                    penalty=-0.60,
                )
            )
            return "variable_reference_not_literal"

        if (any(c.isdigit() for c in rhs_stripped) or any(
            c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for c in rhs_stripped
        )) and not rhs_stripped.startswith(("'", '"')):
            negative_evidences.append(
                self.evidence_engine.create_negative_evidence(
                    signal="not_literal",
                    reason=f"Value '{rhs_stripped[:50]}' has special chars but no quotes, unclear if literal",
                    penalty=-0.40,
                )
            )

        return None

    def _classify_secret(
        self,
        rule_id: str,
        code_snippet: str,
        tags: list[str],
    ) -> str | None:
        """Classify a secret into a precise type based on rule_id and content."""
        snippet_lower = code_snippet.lower()

        classification_map = {
            "SEC_AWS_ACCESS_KEY": "AWS Access Key",
            "SEC_AWS_SECRET_KEY": "AWS Secret Access Key",
            "SEC_GITHUB_TOKEN": "GitHub Token",
            "SEC_DATABASE_URL": "Database Connection String",
            "SEC_GENERIC_API_KEY": "API Key",
            "SEC_PRIVATE_KEY_HEADER": "Private Key",
            "SEC_NPM_TOKEN": "NPM Token",
            "SEC_PYPI_TOKEN": "PyPI Token",
            "SEC_SLACK_TOKEN": "Slack Token",
            "SEC_STRIPE_KEY": "Stripe Key",
            "SEC_TWILIO_KEY": "Twilio Key",
            "SEC_SENDGRID_KEY": "SendGrid Key",
            "SEC_HEROKU_API_KEY": "Heroku API Key",
            "SEC_GOOGLE_API_KEY": "Google API Key",
            "SEC_AZURE_KEY": "Azure Key",
            "SEC_DEPLOY_KEY": "Deploy Key",
            "SEC_BEARER_TOKEN": "Bearer Token",
            "SEC_BASIC_AUTH": "Basic Auth Credentials",
            "SEC_GITHUB_FINE_GRAINED": "GitHub Fine-Grained Token",
            "SEC_GITLAB_TOKEN": "GitLab Personal Access Token",
            "SEC_OPENAI_KEY": "OpenAI API Key",
            "SEC_ANTHROPIC_KEY": "Anthropic API Key",
            "SEC_HUGGINGFACE_TOKEN": "Hugging Face Token",
            "SEC_STRIPE_RESTRICTED_KEY": "Stripe Restricted Key",
            "SEC_AZURE_ACCOUNT_KEY": "Azure Storage Account Key",
            "SEC_CLOUD_DB_URL_CREDS": "Database Credentials in URL",
        }

        if rule_id in classification_map:
            if rule_id == "SEC_PASSWORD_ASSIGNMENT":
                return self._classify_password_secret(snippet_lower)
            return classification_map[rule_id]

        if "aws" in tags or "aws" in snippet_lower:
            if "access" in snippet_lower or "key" in snippet_lower:
                return "AWS Access Key"
            if "secret" in snippet_lower:
                return "AWS Secret Access Key"
        if "github" in tags or "github" in snippet_lower:
            return "GitHub Token"
        if "database" in tags or any(
            kw in snippet_lower
            for kw in ("db_password", "database_url", "postgres", "mysql", "mongo")
        ):
            return "Database Password"
        if "jwt" in tags or "jwt" in snippet_lower:
            return "JWT Secret"
        if "api_key" in tags or "apikey" in snippet_lower:
            return "API Key"
        if "private_key" in tags or "private" in snippet_lower:
            return "Private Key"
        if "token" in tags or "token" in snippet_lower:
            return "Token"
        if "password" in tags or "password" in snippet_lower:
            return "Hardcoded Password"

        return None

    def _classify_password_secret(self, snippet_lower: str) -> str:
        """Classify a password-type secret more precisely."""
        if any(
            kw in snippet_lower
            for kw in ("db_password", "database_password", "postgres", "mysql", "mongo")
        ):
            return "Database Password"
        if "api_key" in snippet_lower or "apikey" in snippet_lower:
            return "API Key"
        if "jwt" in snippet_lower or "secret_key" in snippet_lower:
            return "JWT Secret"
        if "ssh" in snippet_lower:
            return "SSH Password"
        if "redis" in snippet_lower:
            return "Redis Password"
        if "ftp" in snippet_lower:
            return "FTP Password"
        return "Hardcoded Password"

    def validate_all(
        self,
        findings: list[dict],
        file_contents: dict[str, str] | None = None,
        ast_results: dict[str, dict] | None = None,
        type_resolver_results: dict[str, dict] | None = None,
    ) -> list[dict]:
        """Validate a list of findings and return only those that pass the pipeline.

        Args:
            findings: List of finding dicts.
            file_contents: Optional mapping of file_path -> file content.
            ast_results: Optional mapping of file_path -> AST analysis result.
            type_resolver_results: Optional mapping of file_path -> TypeResolver result.

        Returns:
            List of validated findings with evidence attached.
        """
        if file_contents is None:
            file_contents = {}
        if ast_results is None:
            ast_results = {}
        if type_resolver_results is None:
            type_resolver_results = {}

        validated: list[dict] = []
        for finding in findings:
            fp = finding.get("file_path", "")
            result = self.validate_finding(
                finding,
                file_content=file_contents.get(fp, ""),
                ast_result=ast_results.get(fp),
                type_resolver_result=type_resolver_results.get(fp),
            )
            if result is not None:
                validated.append(result)

        return validated


KNOWN_DANGEROUS_CALLS = frozenset({
    "eval", "exec", "compile", "__import__",
})


def _extract_call_name_from_snippet(code_snippet: str) -> str:
    """Extract the function call name from a code snippet.

    Examples:
        'eval(user_input)' -> 'eval'
        'os.system(cmd)' -> 'os.system'
        'obj.eval(x)' -> 'obj.eval'
    """
    snippet = code_snippet.strip()
    if not snippet:
        return ""

    match = re.match(r"([a-zA-Z_][\w.]*)\s*\(", snippet)
    if match:
        return match.group(1)

    match = re.match(r"([a-zA-Z_][\w.]*)", snippet)
    if match:
        return match.group(1)

    return ""


def _names_match_fuzzy(snippet_name: str, ast_name: str) -> bool:
    """Check if two names refer to the same call, allowing for fuzzy matching."""
    if not snippet_name or not ast_name:
        return False

    snippet_bare = snippet_name.split(".")[-1]
    ast_bare = ast_name.split(".")[-1]

    if snippet_bare == ast_bare:
        if snippet_name == ast_name:
            return True
        if snippet_name.endswith(ast_name) or ast_name.endswith(snippet_name):
            return True
        if snippet_bare in KNOWN_DANGEROUS_CALLS:
            return True

    return snippet_name == ast_name


def _find_call_at_line(calls: list[dict], target_line: int) -> int | None:
    """Find a call at or near the target line number."""
    for call in calls:
        call_line = call.get("line", 0)
        if abs(call_line - target_line) <= 2:
            return call_line
    return None


def _variable_matches_snippet(variable: str, snippet: str) -> bool:
    """Check if a variable name from AST matches the code snippet."""
    if not variable or not snippet:
        return False
    return variable in snippet


def _extract_rhs_value(code_snippet: str) -> str | None:
    """Extract the right-hand side value from an assignment snippet.

    Examples:
        'password = "admin123"' -> '"admin123"'
        'DB_PASSWORD = "root"' -> '"root"'
        'key = input("Enter key:")' -> 'input("Enter key:")'
    """
    snippet = code_snippet.strip()
    if not snippet:
        return None

    match = re.match(r"[^=]+\s*=\s*(.+)", snippet)
    if match:
        return match.group(1).strip()

    return None


def _looks_like_variable_reference(value: str) -> bool:
    """Check if a value looks like a variable reference rather than a literal."""
    if not value:
        return False

    if value.startswith(("'", '"')):
        return False

    if value.startswith(("{", "(", "[", "b'", 'b"')):
        return False

    if re.match(r"^-?\d+(\.\d+)?$", value):
        return False

    if re.match(r"^[a-zA-Z_][\w.]*$", value):
        return value not in ("True", "False", "None", "self", "cls")

    return "(" in value


def _calculate_entropy(value: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not value:
        return 0.0

    freq: dict[str, int] = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1

    length = len(value)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy
