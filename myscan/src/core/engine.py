"""Core analysis engine - orchestrates all scanners and analyzers.

Supports both legacy (regex-based) and enterprise (AST + DFG + Taint) analysis modes.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

from ..core.config import ScanConfig, SKIP_EXTENSIONS, SKIP_FILES, SKIP_PATH_PATTERNS
from ..core.models import (
    EXTENSION_MAP, Finding, FindingCategory, Language, ScanResult,
)
from ..core.rules import ALL_RULES, Rule
from .smart_filter import SmartFilter


class ScanEngine:
    """Main scan engine that orchestrates all scanning modules."""

    def __init__(self, config: ScanConfig, enterprise_mode: bool = False, validate_findings: bool = True, progress_tracker=None):
        self.config = config
        self.filter = SmartFilter(config)
        self.enterprise_mode = enterprise_mode
        self.validate_findings = validate_findings
        self.progress_tracker = progress_tracker
        self.scanners: list = []
        self._validation_pipeline = None
        if validate_findings:
            from .validation_engine import ValidationPipeline
            self._validation_pipeline = ValidationPipeline(min_confidence=config.min_confidence if hasattr(config, 'min_confidence') else 0.15)
        self._load_scanners()

    def _load_scanners(self):
        from ..scanners.security_scanner import SecurityScanner
        from ..scanners.quality_scanner import QualityScanner
        from ..scanners.secrets_scanner import SecretsScanner

        if not self.config.skip_security:
            self.scanners.append(SecurityScanner())
        if not self.config.skip_quality:
            self.scanners.append(QualityScanner())
        if not self.config.skip_secrets:
            self.scanners.append(SecretsScanner())

    def scan(self, target: str | Path) -> ScanResult:
        start = time.time()
        result = ScanResult(scan_start=__import__("datetime").datetime.now(__import__("datetime").timezone.utc))

        target_path = Path(target).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target not found: {target}")

        if self.enterprise_mode:
            return self._scan_enterprise(target_path, result, start)

        files = self._collect_files(target_path)
        result.files_scanned = len(files)

        tracker = self.progress_tracker
        if tracker:
            tracker.total_files = len(files)
            tracker.phase = "collecting"
            tracker.emit("init", {"total_files": len(files)})

        for file_path in files:
            if tracker:
                if tracker.cancelled:
                    raise RuntimeError("Scan cancelled by user")
                while tracker.paused:
                    time.sleep(0.5)
                    if tracker.cancelled:
                        raise RuntimeError("Scan cancelled by user")
                tracker.on_file_start(str(file_path))

            rel = file_path.relative_to(target_path)
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, PermissionError):
                result.skipped_files += 1
                result.skipped_reasons["read_error"] = result.skipped_reasons.get("read_error", 0) + 1
                if tracker:
                    tracker.on_file_done(str(file_path))
                continue

            lines = content.splitlines()
            result.lines_scanned += len(lines)

            language = self._detect_language(file_path)
            lang_name = language.value
            result.languages_detected[lang_name] = result.languages_detected.get(lang_name, 0) + 1

            for scanner in self.scanners:
                try:
                    findings = scanner.scan_file(content, str(rel), language)
                    new_findings = 0
                    for f in findings:
                        result.findings.extend([f])
                        new_findings += 1
                        if tracker and new_findings <= 5:
                            tracker.on_finding(f.to_dict())
                    if tracker and new_findings > 5:
                        tracker.findings_count += new_findings - 5
                except Exception:
                    result.skipped_files += 1
                    continue

            if tracker:
                tracker.on_file_done(str(file_path))

        result.deduplicate()
        if self._validation_pipeline:
            result.filter_false_positives_with_validation(self._validation_pipeline)
        else:
            result.filter_false_positives()
        result.scan_end = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        result.scan_duration = time.time() - start
        if tracker:
            tracker.on_complete(result.to_dict()["summary"])
        return result

    def _scan_enterprise(self, target_path: Path, result: ScanResult, start: float) -> ScanResult:
        """Run enterprise-grade analysis with AST, data flow, taint, and context analysis."""
        from .pipeline import AnalysisPipeline
        from .models import Severity, CVSS, CodeLocation, OWASPTop10
        from .fix_generator import generate_fix, generate_secure_alternative
        from ..ai.explainer import explain_finding, explain_taint_flow
        from .secret_analyzer import SecretAnalyzer

        result._enterprise_mode = True

        pipeline = AnalysisPipeline(
            include_tests=False,
            include_docs=False,
            include_examples=False,
            min_confidence=0.15,
        )

        repo_result = pipeline.analyze_repository(str(target_path))

        result.files_scanned = repo_result.file_count
        lines = 0
        for p in target_path.rglob("*"):
            if p.is_file() and p.suffix in (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php", ".cs", ".rs", ".c", ".h", ".cpp", ".rb", ".kt", ".swift", ".sh"):
                try:
                    lines += len(p.read_text(encoding="utf-8", errors="ignore").splitlines())
                except (OSError, PermissionError):
                    pass
        result.lines_scanned = lines

        result._enterprise_metrics = {
            "functionsAnalyzed": repo_result.functions_analyzed,
            "dataFlowPaths": repo_result.data_flow_paths,
            "taintSources": repo_result.taint_sources,
            "taintSinks": repo_result.taint_sinks,
            "findingsBeforeDedup": repo_result.findings_before_dedup,
            "findingsAfterDedup": repo_result.findings_after_dedup,
            "duplicatesRemoved": repo_result.duplicates_removed,
            "pipelineDuration": round(repo_result.total_duration, 2),
            "errors": repo_result.errors[:10],
        }

        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }

        category_map = {
            "sql_injection": FindingCategory.SECURITY,
            "xss": FindingCategory.SECURITY,
            "command_injection": FindingCategory.SECURITY,
            "path_traversal": FindingCategory.SECURITY,
            "hardcoded_secret": FindingCategory.SECRET,
            "insecure_design": FindingCategory.SECURITY,
            "code_injection": FindingCategory.SECURITY,
            "template_injection": FindingCategory.SECURITY,
            "deserialization": FindingCategory.SECURITY,
            "injection": FindingCategory.SECURITY,
            "call_graph_vulnerability": FindingCategory.SECURITY,
            "hardcoded_password": FindingCategory.SECRET,
        }

        owasp_map = {
            "sql_injection": OWASPTop10.A03_INJECTION,
            "xss": OWASPTop10.A03_INJECTION,
            "command_injection": OWASPTop10.A03_INJECTION,
            "path_traversal": OWASPTop10.A01_BROKEN_ACCESS_CONTROL,
            "hardcoded_secret": OWASPTop10.A02_CRYPTOGRAPHIC_FAILURES,
            "code_injection": OWASPTop10.A03_INJECTION,
            "deserialization": OWASPTop10.A08_DATA_INTEGRITY_FAILURES,
            "injection": OWASPTop10.A03_INJECTION,
        }

        secret_analyzer = SecretAnalyzer()

        enriched_by_id = {ef.finding_id: ef for ef in repo_result.findings}

        for deduped_finding in repo_result.deduplicated_findings:
            enriched = enriched_by_id.get(deduped_finding.finding_id)
            sev_str = deduped_finding.severity.upper()
            severity = severity_map.get(sev_str, Severity.INFO)

            cat_str = deduped_finding.category.lower()
            category = category_map.get(cat_str, FindingCategory.SECURITY)

            cvss = CVSS()
            cvss.base_score = deduped_finding.cvss_score

            location = CodeLocation(
                file_path=deduped_finding.file_path,
                line=deduped_finding.line_number,
                column=deduped_finding.column,
                code_snippet=deduped_finding.code_snippet,
            )

            owasp = owasp_map.get(cat_str)

            fix_suggestions = generate_fix(cat_str, deduped_finding.code_snippet)
            fix_text = fix_suggestions[0].description if fix_suggestions else deduped_finding.fix_suggestion
            fixed_code = ""
            if fix_suggestions:
                fixed_code = fix_suggestions[0].after_code

            explanation = explain_finding(
                category=cat_str,
                title=deduped_finding.rule_id,
                description=deduped_finding.message,
                file_path=deduped_finding.file_path,
                line=deduped_finding.line_number,
                severity=sev_str,
                confidence=deduped_finding.confidence,
                cvss_score=deduped_finding.cvss_score,
                code_snippet=deduped_finding.code_snippet,
                cwe="",
                owasp=owasp.value[0] if owasp else "",
            )

            finding = Finding(
                rule_id=deduped_finding.rule_id,
                title=explanation.summary,
                description=deduped_finding.message,
                severity=severity,
                confidence=deduped_finding.confidence,
                category=category,
                language=Language.UNKNOWN,
                location=location,
                cvss=cvss,
                fix_suggestion=enriched.fix_suggestion if enriched and enriched.fix_suggestion else fix_text,
                fixed_code=fixed_code,
                references=enriched.references if enriched and enriched.references else (deduped_finding.references_urls or explanation.learning_resources),
                why_vulnerable=enriched.root_cause if enriched and enriched.root_cause else explanation.detailed_explanation,
                impact=enriched.impact if enriched and enriched.impact else explanation.impact,
                exploit_scenario=enriched.attack_scenario if enriched and enriched.attack_scenario else explanation.exploit_scenario,
                confidence_reasoning=explanation.summary,
                owasp=owasp,
                cwe=enriched.cwe if enriched and enriched.cwe else "",
                cwe_name=enriched.cwe_name if enriched and enriched.cwe_name else "",
            )

            if enriched and enriched.fix_suggestion:
                finding.fix_suggestion = enriched.fix_suggestion
            if enriched and enriched.secure_example:
                finding.fixed_code = enriched.secure_example

            if category == FindingCategory.SECRET:
                try:
                    analysis = secret_analyzer.analyze(finding)
                    finding.fix_suggestion = analysis.recommendations[0] if analysis.recommendations else fix_text
                    finding.impact = (
                        f"Risk: {analysis.risk.risk_level} | "
                        f"Environment: {analysis.risk.environment} | "
                        f"Business impact: {analysis.risk.business_impact}"
                    )
                    finding.exploit_scenario = (
                        f"Classification: {analysis.classification} | "
                        f"Strength: {analysis.strength.strength_label} | "
                        f"Crack time: {analysis.strength.estimated_crack_time}"
                    )
                except Exception:
                    pass

            result.findings.append(finding)

        result.deduplicate()
        result.scan_end = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        result.scan_duration = time.time() - start
        return result

    def _collect_files(self, root: Path) -> list[Path]:
        files: list[Path] = []
        skip_dirs = self.config.skip_dirs
        for dirpath, dirnames, filenames in os.walk(str(root)):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for filename in filenames:
                fp = Path(dirpath) / filename
                if self._should_include_file(fp, root):
                    files.append(fp)
        return files

    def _should_include_file(self, file_path: Path, root: Path) -> bool:
        if file_path.name in SKIP_FILES:
            return False
        suffix = file_path.suffix.lower()
        if suffix in SKIP_EXTENSIONS:
            return False
        if file_path.name in SKIP_PATH_PATTERNS:
            return False
        name_lower = file_path.name.upper()
        for pat in SKIP_PATH_PATTERNS:
            if pat.upper() in name_lower:
                return False
        try:
            if file_path.stat().st_size > self.config.max_file_size:
                return False
        except OSError:
            return False
        rel = file_path.relative_to(root)
        parts = rel.parts
        skip_dirs = self.config.skip_dirs
        for part in parts:
            if part in skip_dirs:
                return False
        return True

    def _detect_language(self, file_path: Path) -> Language:
        name = file_path.name.lower()
        if name == "dockerfile":
            return Language.DOCKER
        if name == "makefile":
            return Language.SHELL
        if name == "gemfile":
            return Language.RUBY
        if name == "rakefile":
            return Language.RUBY
        return EXTENSION_MAP.get(file_path.suffix.lower(), Language.UNKNOWN)
