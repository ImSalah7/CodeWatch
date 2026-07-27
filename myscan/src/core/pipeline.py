"""Analysis Pipeline.

Orchestrates the enterprise-grade analysis:
Source Code → AST → Data Flow → Taint → Context → Risk → Confidence → Dedup → Report

Each phase enriches findings with more evidence, improving accuracy.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .ast_analyzer import (
    analyze_python_ast, PythonASTResult, CallInfo, SOURCES,
)
from .dataflow import analyze_data_flow, DataFlowResult, TaintPath
from .context_analyzer import (
    analyze_eval_context, analyze_password_context, analyze_injection_context,
    EvalContext, PasswordContext, InjectionContext,
)
from .confidence import calculate_confidence, ConfidenceResult, ConfidenceLevel
from .risk_scorer import assess_risk, RiskAssessment, RiskLevel
from .deduplicator import deduplicate_findings, DeduplicatedFinding
from .indexer import index_repository, RepositoryIndex, FileCategory, FileIndex
from .validation_engine import ValidationPipeline
from .call_graph import CallGraph
from .semantic_analyzer import analyze_semantics, SemanticSafety
from .symbol_table import build_symbol_table, SymbolTable
from .reachability import analyze_reachability, ReachabilityStatus
from .root_cause import generate_root_cause, enrich_finding_with_root_cause
from .code_context import ensure_code_snippet, get_code_context
from .import_resolver import build_import_table, ImportResolutionResult


@dataclass
class PipelinePhase:
    """A single analysis phase."""
    name: str
    duration: float = 0.0
    input_count: int = 0
    output_count: int = 0


@dataclass
class EnrichedFinding:
    """A finding enriched with all analysis results."""
    finding_id: str
    rule_id: str
    message: str
    severity: str
    original_severity: str
    category: str
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    confidence: float
    confidence_level: str
    risk_assessment: Optional[RiskAssessment] = None
    ast_result: Optional[PythonASTResult] = None
    dataflow_result: Optional[DataFlowResult] = None
    is_user_controlled: bool = False
    is_constant: bool = False
    is_sanitized: bool = False
    has_taint_path: bool = False
    owasp_category: str = ""
    cvss_vector: str = ""
    fix_suggestion: str = ""
    explanation: str = ""
    references: list[str] = field(default_factory=list)
    root_cause: str = ""
    attack_scenario: str = ""
    impact: str = ""
    exploitability: str = ""
    recommendation: str = ""
    secure_example: str = ""
    cwe: str = ""
    cwe_name: str = ""
    reachability: str = ""
    semantic_safety: str = ""
    code_context_before: list[str] = field(default_factory=list)
    code_context_after: list[str] = field(default_factory=list)
    evidence_summary: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    """Result of the complete analysis pipeline."""
    file_count: int
    functions_analyzed: int
    data_flow_paths: int
    taint_sources: int
    taint_sinks: int
    findings_before_dedup: int
    findings_after_dedup: int
    duplicates_removed: int
    findings: list[EnrichedFinding] = field(default_factory=list)
    deduplicated_findings: list[DeduplicatedFinding] = field(default_factory=list)
    validated_findings: list[EnrichedFinding] = field(default_factory=list)
    vulnerable_paths: list[dict] = field(default_factory=list)
    call_graph_stats: dict = field(default_factory=dict)
    rejected_by_validation: int = 0
    phases: list[PipelinePhase] = field(default_factory=list)
    total_duration: float = 0.0
    errors: list[str] = field(default_factory=list)


class AnalysisPipeline:
    """Orchestrates the complete enterprise analysis pipeline."""

    def __init__(
        self,
        include_tests: bool = False,
        include_docs: bool = False,
        include_examples: bool = False,
        min_confidence: float = 0.15,
        custom_rules: Optional[list] = None,
        validate_findings: bool = True,
    ):
        self.include_tests = include_tests
        self.include_docs = include_docs
        self.include_examples = include_examples
        self.min_confidence = min_confidence
        self.custom_rules = custom_rules or []
        self.validate_findings = validate_findings
        self.validation_pipeline = ValidationPipeline(min_confidence=min_confidence) if validate_findings else None

    def analyze_file(self, file_path: str) -> EnrichedFinding:
        """Analyze a single file through all phases."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
        except (OSError, PermissionError) as e:
            return EnrichedFinding(
                finding_id="",
                rule_id="ERROR",
                message=f"Cannot read file: {e}",
                severity="INFO",
                original_severity="INFO",
                category="error",
                file_path=file_path,
                line_number=0,
                column=0,
                code_snippet="",
                confidence=0.0,
                confidence_level="speculative",
            )

        ast_result = analyze_python_ast(source_code, file_path)
        dataflow_result = analyze_data_flow(ast_result, source_code)
        semantic_result = analyze_semantics(source_code, file_path, ast_result.imports)

        findings = self._analyze_with_results(
            source_code, file_path, ast_result, dataflow_result,
            semantic_result=semantic_result,
        )

        if findings:
            return findings[0]

        return EnrichedFinding(
            finding_id="",
            rule_id="CLEAN",
            message="No issues found",
            severity="INFO",
            original_severity="INFO",
            category="none",
            file_path=file_path,
            line_number=0,
            column=0,
            code_snippet="",
            confidence=0.0,
            confidence_level="info",
        )

    def analyze_repository(self, repo_path: str) -> PipelineResult:
        """Analyze an entire repository."""
        start_time = time.time()
        result = PipelineResult(file_count=0, functions_analyzed=0, data_flow_paths=0,
                                taint_sources=0, taint_sinks=0,
                                findings_before_dedup=0, findings_after_dedup=0,
                                duplicates_removed=0)

        repo_index = index_repository(
            repo_path,
            include_tests=self.include_tests,
            include_docs=self.include_docs,
            include_examples=self.include_examples,
        )

        scannable_files = [f for f in repo_index.files if f.is_scannable]
        result.file_count = len(scannable_files)

        all_enriched: list[EnrichedFinding] = []

        call_graph = CallGraph()

        file_contents: dict[str, str] = {}
        semantic_results: dict[str, object] = {}
        ast_results: dict[str, object] = {}

        for file_index in scannable_files:
            try:
                with open(file_index.path, "r", encoding="utf-8", errors="ignore") as f:
                    source_code = f.read()
            except (OSError, PermissionError) as e:
                result.errors.append(f"Cannot read {file_index.path}: {e}")
                continue

            file_contents[file_index.path] = source_code

            call_graph.analyze_file(file_index.path, source_code)

            ast_result = analyze_python_ast(source_code, file_index.path)
            dataflow_result = analyze_data_flow(ast_result, source_code)
            result.functions_analyzed += len(ast_result.functions)
            result.data_flow_paths += len(dataflow_result.taint_paths)
            result.taint_sources += dataflow_result.total_sources
            result.taint_sinks += dataflow_result.total_sinks

            semantic_result = analyze_semantics(source_code, file_index.path, ast_result.imports)
            semantic_results[file_index.path] = semantic_result
            ast_results[file_index.path] = ast_result

            enriched = self._analyze_with_results(
                source_code, file_index.path, ast_result, dataflow_result,
                file_index=file_index,
                semantic_result=semantic_result,
            )
            all_enriched.extend(enriched)

        symbol_table = build_symbol_table(repo_path, file_contents)

        import_resolution = build_import_table(file_contents, repo_path)

        reachability_result = analyze_reachability(
            file_contents,
            include_tests=self.include_tests,
        )

        vulnerable_paths = call_graph.get_vulnerable_paths()
        result.vulnerable_paths = vulnerable_paths
        result.call_graph_stats = call_graph.to_dict().get("stats", {})

        repo_path_resolved = Path(repo_path).resolve()

        for vp in vulnerable_paths:
            vp_file = vp["file"]
            try:
                vp_file = str(Path(vp_file).relative_to(repo_path_resolved))
            except ValueError:
                pass

            already_reported = any(
                ef.file_path == vp_file and ef.line_number == vp["line"]
                for ef in all_enriched
            )
            if not already_reported:
                path_desc = " -> ".join(vp.get("path", [])[:5])
                input_desc = "User input flows through call chain to dangerous sink" if vp["user_input_flows"] else "Reachable from entry point"
                vp_finding = EnrichedFinding(
                    finding_id=f"VULN_PATH:{vp_file}:{vp['line']}",
                    rule_id="ENTERPRISE-VULNERABLE_PATH",
                    message=(
                        f"Reachable dangerous sink in '{vp['function']}' ({input_desc}). "
                        f"Path: {path_desc}"
                    ),
                    severity="CRITICAL" if vp["risk"] == "critical" else "HIGH",
                    original_severity="CRITICAL" if vp["risk"] == "critical" else "HIGH",
                    category="call_graph_vulnerability",
                    file_path=vp_file,
                    line_number=vp["line"],
                    column=0,
                    code_snippet="",
                    confidence=0.85 if vp["user_input_flows"] else 0.65,
                    confidence_level="verified" if vp["user_input_flows"] else "likely",
                    is_user_controlled=vp["user_input_flows"],
                )
                all_enriched.append(vp_finding)

        result.findings_before_dedup = len(all_enriched)

        if self.validation_pipeline:
            self.validation_pipeline.set_import_resolution(import_resolution)
            self.validation_pipeline.set_reachability(reachability_result)
            validated: list[EnrichedFinding] = []
            for ef in all_enriched:
                finding_dict = {
                    "rule_id": ef.rule_id,
                    "title": ef.rule_id,
                    "message": ef.message,
                    "severity": ef.severity,
                    "category": ef.category,
                    "file_path": ef.file_path,
                    "line": ef.line_number,
                    "column": ef.column,
                    "code_snippet": ef.code_snippet,
                    "confidence": ef.confidence,
                    "tags": [],
                }
                file_content = file_contents.get(ef.file_path, "")
                validated_dict = self.validation_pipeline.validate_finding(
                    finding_dict,
                    file_content=file_content,
                )
                if validated_dict is not None:
                    ef.confidence = validated_dict.get("confidence", ef.confidence)
                    validated.append(ef)
                else:
                    result.rejected_by_validation += 1
            result.validated_findings = validated
            findings_for_dedup = validated
        else:
            result.validated_findings = all_enriched
            findings_for_dedup = all_enriched

        for ef in findings_for_dedup:
            self._enrich_with_new_engines(
                ef, file_contents, symbol_table, reachability_result
            )

        dedup_input = []
        for ef in findings_for_dedup:
            dedup_input.append(type("Finding", (), {
                "finding_id": ef.finding_id,
                "rule_id": ef.rule_id,
                "message": ef.message,
                "severity": ef.severity,
                "category": ef.category,
                "file_path": ef.file_path,
                "line_number": ef.line_number,
                "column": ef.column,
                "code_snippet": ef.code_snippet,
                "confidence": ef.confidence,
                "cvss_score": ef.risk_assessment.cvss.overall_score if ef.risk_assessment else 0.0,
                "fix_suggestion": ef.fix_suggestion,
                "value": "",
            })())

        deduped = deduplicate_findings(dedup_input)
        result.deduplicated_findings = deduped
        result.findings_after_dedup = len(deduped)
        result.duplicates_removed = result.findings_before_dedup - result.findings_after_dedup

        result.findings = all_enriched
        result.total_duration = time.time() - start_time
        return result

    def _enrich_with_new_engines(
        self,
        ef: EnrichedFinding,
        file_contents: dict[str, str],
        symbol_table: object,
        reachability_result: object,
    ) -> None:
        """Enrich a finding with root cause, code context, reachability, and semantic safety."""
        file_content = file_contents.get(ef.file_path, "")
        if not file_content:
            for fpath, fcontent in file_contents.items():
                if fpath.endswith(ef.file_path) or ef.file_path.endswith(fpath):
                    file_content = fcontent
                    break

        if file_content:
            ef.code_snippet = ensure_code_snippet(file_content, ef.line_number, ef.code_snippet)
            code_ctx = get_code_context(file_content, ef.line_number)
            if code_ctx.has_context:
                ef.code_context_before = code_ctx.before_lines
                ef.code_context_after = code_ctx.after_lines

        finding_dict = {
            "rule_id": ef.rule_id,
            "title": ef.rule_id,
            "description": ef.message,
            "code_snippet": ef.code_snippet,
            "file_path": ef.file_path,
            "line": ef.line_number,
            "severity": ef.severity,
            "confidence": ef.confidence,
            "category": ef.category,
            "cwe": ef.cwe,
            "owasp_category": ef.owasp_category,
            "explanation": ef.explanation,
        }
        enriched_dict = enrich_finding_with_root_cause(finding_dict, ef.category)
        ef.root_cause = enriched_dict.get("root_cause", "")
        ef.attack_scenario = enriched_dict.get("attack_scenario", "")
        ef.impact = enriched_dict.get("impact", "")
        ef.exploitability = enriched_dict.get("exploitability", "")
        ef.recommendation = enriched_dict.get("recommendation", "")
        ef.secure_example = enriched_dict.get("secure_example", "")
        ef.cwe = enriched_dict.get("cwe", ef.cwe)
        ef.cwe_name = enriched_dict.get("cwe_name", "")
        ef.owasp_category = enriched_dict.get("owasp_category", ef.owasp_category)
        if enriched_dict.get("fix_suggestion") and not ef.fix_suggestion:
            ef.fix_suggestion = enriched_dict["fix_suggestion"]

        if reachability_result and hasattr(reachability_result, "functions"):
            func_key = f"{ef.file_path}::{ef.rule_id.split('-')[-1].lower()}"
            for fkey, freach in reachability_result.functions.items():
                if freach.file_path == ef.file_path and abs(freach.line - ef.line_number) <= 3:
                    ef.reachability = freach.status.value
                    break

    def _analyze_with_results(
        self,
        source_code: str,
        file_path: str,
        ast_result: PythonASTResult,
        dataflow_result: DataFlowResult,
        file_index: Optional[FileIndex] = None,
        semantic_result: Optional[object] = None,
    ) -> list[EnrichedFinding]:
        """Analyze code with pre-computed AST and data flow results."""
        findings: list[EnrichedFinding] = []
        lines = source_code.split("\n")
        file_category = file_index.file_category if file_index else FileCategory.PRODUCTION

        safe_lines: set[int] = set()
        if semantic_result and hasattr(semantic_result, "safe_calls"):
            for sc in semantic_result.safe_calls:
                safe_lines.add(sc.line)

        for call in ast_result.dangerous_sinks:
            if call.line in safe_lines:
                continue
            enriched = self._create_enriched_finding_from_sink(
                call, lines, file_path, file_category,
                ast_result, dataflow_result,
            )
            if enriched and enriched.confidence >= self.min_confidence:
                findings.append(enriched)

        for call in ast_result.calls:
            if call.line in safe_lines:
                continue
            if call.name in ("eval", "exec") or call.full_name in ("os.system",):
                already_found = any(
                    ef.line_number == call.line for ef in findings
                )
                if not already_found:
                    enriched = self._create_enriched_finding_from_call(
                        call, lines, file_path, file_category,
                        ast_result, dataflow_result,
                    )
                    if enriched and enriched.confidence >= self.min_confidence:
                        findings.append(enriched)

        return findings

    def _create_enriched_finding_from_sink(
        self,
        call: CallInfo,
        lines: list[str],
        file_path: str,
        file_category: FileCategory,
        ast_result: PythonASTResult,
        dataflow_result: DataFlowResult,
    ) -> Optional[EnrichedFinding]:
        """Create an enriched finding from a dangerous sink call."""
        line_num = call.line
        if line_num < 1 or line_num > len(lines):
            return None

        line_content = lines[line_num - 1]
        category = self._classify_sink(call)
        severity = self._severity_for_sink(call)

        start_line = max(0, line_num - 6)
        end_line = min(len(lines), line_num + 5)
        code_snippet = "\n".join(lines[start_line:end_line])

        is_user_controlled = self._check_user_controlled_from_args(call.args)
        is_constant = not is_user_controlled and not any(
            src in " ".join(call.args) for src in SOURCES
        )

        has_taint_path = False
        for tp in dataflow_result.taint_paths:
            if tp.sink_line == line_num:
                has_taint_path = True
                break

        is_sanitized = any(
            san in " ".join(call.args) for san in ["escape", "sanitize", "quote", "parameterized"]
        )

        confidence_result = calculate_confidence(
            has_ast_match=True,
            has_taint_path=has_taint_path,
            is_user_controlled=is_user_controlled,
            is_constant=is_constant,
            is_sanitized=is_sanitized,
            reachability="direct" if not is_sanitized else "conditional",
            file_context="production" if file_category == FileCategory.PRODUCTION else "other",
            variable_name="",
            value="",
            is_placeholder=False,
            is_in_comment=line_content.strip().startswith("#"),
            is_in_test=(file_category == FileCategory.TEST),
            base_confidence=0.6 if has_taint_path else 0.4,
            pattern_matched=True,
            sink_function=call.full_name or call.name,
            source_type="user_input" if is_user_controlled else "unknown",
        )

        risk_assessment = assess_risk(
            category=category,
            confidence=confidence_result.score,
            is_production=(file_category == FileCategory.PRODUCTION),
            has_taint_path=has_taint_path,
            user_controlled=is_user_controlled,
        )

        adjusted_severity = self._adjust_severity(
            severity, confidence_result.adjusted_severity, risk_assessment.risk_level
        )

        if not confidence_result.should_report:
            return None

        return EnrichedFinding(
            finding_id=f"{call.full_name or call.name}:{file_path}:{line_num}",
            rule_id=f"ENTERPRISE-{(call.full_name or call.name).upper().replace('.', '_')}",
            message=self._generate_message(call, is_user_controlled, has_taint_path, category),
            severity=adjusted_severity,
            original_severity=severity,
            category=category,
            file_path=file_path,
            line_number=line_num,
            column=call.line,
            code_snippet=code_snippet,
            confidence=confidence_result.score,
            confidence_level=confidence_result.level.value,
            risk_assessment=risk_assessment,
            ast_result=ast_result,
            dataflow_result=dataflow_result,
            is_user_controlled=is_user_controlled,
            is_constant=is_constant,
            is_sanitized=is_sanitized,
            has_taint_path=has_taint_path,
            owasp_category=risk_assessment.owasp_category,
            cvss_vector=risk_assessment.cvss.vector_string,
            fix_suggestion=self._generate_fix_suggestion(call),
            explanation=confidence_result.reasoning,
        )

    def _create_enriched_finding_from_call(
        self,
        call: CallInfo,
        lines: list[str],
        file_path: str,
        file_category: FileCategory,
        ast_result: PythonASTResult,
        dataflow_result: DataFlowResult,
    ) -> Optional[EnrichedFinding]:
        """Create an enriched finding from a specific dangerous call."""
        line_num = call.line
        if line_num < 1 or line_num > len(lines):
            return None

        line_content = lines[line_num - 1]
        category = self._classify_call(call)
        severity = "HIGH" if call.name in ("eval", "exec") else "MEDIUM"

        start_line = max(0, line_num - 6)
        end_line = min(len(lines), line_num + 5)
        code_snippet = "\n".join(lines[start_line:end_line])

        is_user_controlled = self._check_user_controlled_from_args(call.args)

        confidence_result = calculate_confidence(
            has_ast_match=True,
            has_taint_path=False,
            is_user_controlled=is_user_controlled,
            is_constant=not is_user_controlled,
            is_sanitized=False,
            reachability="direct",
            file_context="production" if file_category == FileCategory.PRODUCTION else "other",
            base_confidence=0.5 if is_user_controlled else 0.3,
            pattern_matched=True,
            sink_function=call.name,
        )

        risk_assessment = assess_risk(
            category=category,
            confidence=confidence_result.score,
            is_production=(file_category == FileCategory.PRODUCTION),
            has_taint_path=False,
            user_controlled=is_user_controlled,
        )

        adjusted_severity = self._adjust_severity(
            severity, confidence_result.adjusted_severity, risk_assessment.risk_level
        )

        if not confidence_result.should_report:
            return None

        return EnrichedFinding(
            finding_id=f"{call.name}:{file_path}:{line_num}",
            rule_id=f"ENTERPRISE-{call.name.upper()}",
            message=self._generate_message(call, is_user_controlled, False, category),
            severity=adjusted_severity,
            original_severity=severity,
            category=category,
            file_path=file_path,
            line_number=line_num,
            column=call.line,
            code_snippet=code_snippet,
            confidence=confidence_result.score,
            confidence_level=confidence_result.level.value,
            risk_assessment=risk_assessment,
            ast_result=ast_result,
            dataflow_result=dataflow_result,
            is_user_controlled=is_user_controlled,
            is_constant=not is_user_controlled,
            is_sanitized=False,
            has_taint_path=False,
            owasp_category=risk_assessment.owasp_category,
            cvss_vector=risk_assessment.cvss.vector_string,
            fix_suggestion=self._generate_fix_suggestion(call),
            explanation=confidence_result.reasoning,
        )

    def _classify_sink(self, call: CallInfo) -> str:
        name = (call.full_name or call.name).lower()
        if "execute" in name or "cursor" in name:
            return "sql_injection"
        if "system" in name or "popen" in name or "subprocess" in name:
            return "command_injection"
        if "render" in name and "template" in name:
            return "template_injection"
        if "loads" in name or "unpickle" in name:
            return "deserialization"
        return "injection"

    def _classify_call(self, call: CallInfo) -> str:
        name = call.name.lower()
        if name in ("eval", "exec"):
            return "code_injection"
        return "injection"

    def _severity_for_sink(self, call: CallInfo) -> str:
        name = (call.full_name or call.name).lower()
        high = ["execute", "system", "popen", "eval", "exec", "loads"]
        if any(h in name for h in high):
            return "HIGH"
        return "MEDIUM"

    def _check_user_controlled_from_args(self, args: list[str]) -> bool:
        user_indicators = [
            "request.form", "request.args", "request.json",
            "input(", "sys.argv", "os.environ",
            "req.", "params.", "body[",
        ]
        args_str = " ".join(args)
        return any(ind in args_str for ind in user_indicators)

    def _adjust_severity(self, base: str, adjustment: str, risk_level: RiskLevel) -> str:
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            idx = severity_order.index(base)
        except ValueError:
            idx = 2

        if adjustment == "reduce_one_level":
            idx = max(0, idx - 1)
        elif adjustment == "reduce_to_medium_max":
            idx = min(idx, 2)
        elif adjustment == "reduce_to_low":
            idx = min(idx, 1)

        if risk_level == RiskLevel.CRITICAL:
            idx = max(idx, 3)
        elif risk_level == RiskLevel.HIGH:
            idx = max(idx, 2)

        return severity_order[min(idx, len(severity_order) - 1)]

    def _generate_message(self, call: CallInfo, is_user_controlled: bool,
                          has_taint_path: bool, category: str) -> str:
        sink = call.full_name or call.name
        parts = []
        if is_user_controlled:
            parts.append("User-controlled input")
        else:
            parts.append("Potentially unsafe pattern")
        parts.append(f"flows to {sink}() sink")
        if has_taint_path:
            parts.append("[Taint-confirmed]")
        return " ".join(parts) + f" ({category})"

    def _generate_fix_suggestion(self, call: CallInfo) -> str:
        suggestions = {
            "eval": "Use ast.literal_eval() for safe evaluation of literals, or json.loads() for JSON.",
            "exec": "Avoid exec(). Use specific function calls instead.",
            "os.system": "Use subprocess.run() with shell=False and explicit argument list.",
            "execute": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        }
        name = call.full_name or call.name
        return suggestions.get(name, "Review and apply security best practices.")
