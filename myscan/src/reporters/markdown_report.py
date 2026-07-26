"""Enhanced Markdown report generator with code blocks, risk scores, and OWASP section."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape as html_escape

from ..core.models import ScanResult


class MarkdownReporter:
    name = "markdown"

    def generate(self, result: ScanResult) -> str:
        sc = result.severity_counts
        sec = result.security_findings
        qual = result.quality_findings
        secs = result.secret_findings
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines = [
            "# MyScan Enterprise Security Report\n",
            f"**Generated:** {now}  ",
            f"**Files scanned:** {result.files_scanned}  ",
            f"**Lines scanned:** {result.lines_scanned:,}  ",
            f"**Duration:** {result.scan_duration:.1f}s  ",
            f"**Risk Score:** {result.risk_score}/100  ",
            f"**Grade:** {result.grade}\n",
            "---\n",
            "## Risk Summary\n",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {sc['critical']} |",
            f"| 🟠 High | {sc['high']} |",
            f"| 🟡 Medium | {sc['medium']} |",
            f"| 🔵 Low | {sc['low']} |",
            f"| ⚪ Info | {sc['info']} |",
            f"| **Total** | **{sum(sc.values())}** |\n",
        ]

        if result.languages_detected:
            lines.extend(["## Languages\n", "| Language | Files |", "|----------|-------|"])
            for lang, count in sorted(result.languages_detected.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| {lang} | {count} |")
            lines.append("")

        owasp_section = self._build_owasp_section(sec)
        if owasp_section:
            lines.extend(owasp_section)

        if sec:
            lines.extend(["---\n", f"## Security Findings ({len(sec)})\n"])
            for i, f in enumerate(sorted(sec, key=lambda x: x.severity.numeric), 1):
                severity_badge = f"`{f.severity.value.upper()}`"
                lines.extend([
                    f"### {i}. {f.title} {severity_badge}\n",
                ])
                details = []
                if f.cwe:
                    details.append(f"- **CWE:** {f.cwe} ({f.cwe_name})")
                if f.owasp:
                    details.append(f"- **OWASP:** {f.owasp.code} - {f.owasp.title}")
                if f.cvss and f.cvss.base_score > 0:
                    details.append(f"- **CVSS:** {f.cvss.base_score:.1f} `{f.cvss.vector}`")
                details.extend([
                    f"- **File:** `{f.location.file_path}:{f.location.line}`",
                    f"- **Confidence:** {f.confidence:.0%}",
                    f"- **Language:** {f.language.value}",
                ])
                lines.extend(details)
                lines.append("")

                if f.description:
                    lines.extend([f"**Description:** {f.description}\n"])

                if f.why_vulnerable:
                    lines.extend([f"**Why Vulnerable:** {f.why_vulnerable}\n"])

                if f.impact:
                    lines.extend([f"**Impact:** {f.impact}\n"])

                if f.location.code_snippet:
                    snippet = f.location.code_snippet[:500]
                    lines.extend(["**Vulnerable Code:**\n", "```", snippet, "```\n"])

                if f.fix_suggestion:
                    lines.extend([f"**How to Fix:**\n", "```", f.fix_suggestion[:300], "```\n"])

                if f.fixed_code:
                    lines.extend(["**Suggested Fix Code:**\n", "```", f.fixed_code[:500], "```\n"])

                if f.exploit_scenario:
                    lines.extend([f"**Exploit Scenario:**\n", "> " + f.exploit_scenario.replace("\n", "\n> "), "\n"])

                if f.confidence_reasoning:
                    lines.extend([f"**Confidence Reasoning:** {f.confidence_reasoning}\n"])

                if f.references:
                    lines.append("**References:** " + " | ".join(f"[{j+1}]({r})" for j, r in enumerate(f.references[:3])))
                lines.append("")

        if qual:
            lines.extend(["---\n", f"## Quality Findings ({len(qual)})\n"])
            for i, f in enumerate(sorted(qual, key=lambda x: x.severity.numeric), 1):
                lines.extend([
                    f"### {i}. {f.title} (`{f.severity.value.upper()}`)",
                    f"- **File:** `{f.location.file_path}:{f.location.line}`",
                    f"- {f.description}\n",
                ])

        if secs:
            lines.extend(["---\n", f"## Secret Findings ({len(secs)})\n"])
            for i, f in enumerate(sorted(secs, key=lambda x: x.severity.numeric), 1):
                lines.extend([
                    f"### {i}. {f.title} (`{f.severity.value.upper()}`)",
                    f"- **File:** `{f.location.file_path}:{f.location.line}`",
                    f"- **Confidence:** {f.confidence:.0%}",
                    f"- {f.fix_suggestion}\n",
                ])

        lines.extend([
            "---\n",
            "*Report generated by MyScan v2.0.0 Enterprise - AI-Powered SAST Platform*",
        ])

        return "\n".join(lines)

    def _build_owasp_section(self, findings) -> list[str]:
        if not findings:
            return []
        owasp_counts: dict[str, dict] = {}
        for f in findings:
            if f.owasp:
                code = f.owasp.code
                if code not in owasp_counts:
                    owasp_counts[code] = {"code": code, "title": f.owasp.title, "count": 0}
                owasp_counts[code]["count"] += 1
        if not owasp_counts:
            return []
        lines = ["---\n", "## OWASP Top 10 Breakdown\n", "| Category | Count |", "|----------|-------|"]
        for item in sorted(owasp_counts.values(), key=lambda x: x["count"], reverse=True):
            lines.append(f"| **{item['code']}** - {item['title']} | {item['count']} |")
        lines.append("")
        return lines
