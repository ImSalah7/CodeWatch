"""Enhanced HTML report generator with code snippets, CVSS, OWASP breakdown, and AI explanations."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape as html_escape
from typing import Optional

from ..core.models import FindingCategory, ScanResult, SecretDisplayMode


class HTMLReporter:
    name = "html"

    def generate(self, result: ScanResult) -> str:
        sc = result.severity_counts
        sec = result.security_findings
        qual = result.quality_findings
        secs = result.secret_findings
        enterprise = getattr(result, '_enterprise_mode', False)
        secret_display = getattr(result, '_secret_display_mode', 'smart')

        secret_warning = ""
        if secret_display == "full":
            secret_warning = """<div style="background:rgba(220,38,38,0.15);border:1px solid rgba(220,38,38,0.4);border-radius:8px;padding:16px;margin-bottom:20px;color:#fca5a5;">
<strong style="color:#f87171;">WARNING: Full Secret Display Enabled</strong><br>
Reports may expose sensitive credentials. Use only when developer explicitly enables FULL mode.
</div>"""

        severity_colors = {
            "critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
            "low": "#2563eb", "info": "#6b7280",
        }
        severity_bgs = {
            "critical": "rgba(220,38,38,0.1)", "high": "rgba(234,88,12,0.1)",
            "medium": "rgba(202,138,4,0.1)", "low": "rgba(37,99,235,0.1)",
            "info": "rgba(107,114,128,0.1)",
        }

        owasp_breakdown = self._build_owasp_breakdown(sec)
        finding_cards = self._build_finding_cards(sec, severity_colors, severity_bgs)
        quality_rows = self._build_quality_rows(qual, severity_colors)
        secret_rows = self._build_secret_rows(secs, severity_colors)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MyScan Enterprise Security Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Fira Code', monospace; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
.header {{ background: linear-gradient(135deg, #1e293b, #0f172a); border: 1px solid #334155; border-radius: 12px; padding: 30px; margin-bottom: 20px; }}
.header h1 {{ font-size: 28px; margin-bottom: 5px; background: linear-gradient(90deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
.header .subtitle {{ color: #94a3b8; }}
.score-card {{ display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }}
.score-box {{ flex: 1; min-width: 120px; background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; text-align: center; }}
.score-box .number {{ font-size: 32px; font-weight: bold; }}
.score-box .label {{ color: #94a3b8; font-size: 13px; margin-top: 4px; }}
.grade {{ font-size: 64px; font-weight: bold; }}
.grade-a {{ color: #22c55e; }} .grade-b {{ color: #84cc16; }} .grade-c {{ color: #eab308; }}
.grade-d {{ color: #f97316; }} .grade-f {{ color: #ef4444; }}
.section {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
.section h2 {{ margin-bottom: 16px; font-size: 18px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
.section h3 {{ margin: 16px 0 8px 0; font-size: 15px; color: #94a3b8; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; font-size: 13px; }}
th {{ background: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
tr:hover {{ background: rgba(59, 130, 246, 0.05); }}
.bar-chart {{ margin-top: 10px; }}
.bar {{ display: flex; align-items: center; margin-bottom: 8px; }}
.bar-label {{ width: 100px; font-size: 13px; }}
.bar-track {{ flex: 1; height: 24px; background: #0f172a; border-radius: 4px; overflow: hidden; }}
.bar-fill {{ height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; font-size: 12px; font-weight: 600; }}
.footer {{ text-align: center; color: #64748b; font-size: 12px; padding: 20px; }}
.finding-card {{ background: #0f172a; border: 1px solid #334155; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
.finding-header {{ padding: 16px 20px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
.finding-header .severity-badge {{ padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; color: white; }}
.finding-header .title {{ font-weight: 600; font-size: 15px; flex: 1; }}
.finding-header .meta {{ color: #64748b; font-size: 12px; }}
.finding-body {{ padding: 0 20px 16px; }}
.finding-body .desc {{ color: #94a3b8; font-size: 13px; margin-bottom: 12px; }}
.finding-detail {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }}
.detail-box {{ background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 12px; }}
.detail-box .label {{ font-size: 11px; text-transform: uppercase; color: #64748b; margin-bottom: 4px; }}
.detail-box .value {{ font-size: 13px; }}
.code-block {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 12px; margin: 8px 0; overflow-x: auto; }}
.code-block pre {{ font-family: 'Fira Code', 'Cascadia Code', monospace; font-size: 12px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }}
.code-block .line-num {{ color: #475569; user-select: none; margin-right: 12px; display: inline-block; min-width: 24px; text-align: right; }}
.code-block .vuln-line {{ background: rgba(220, 38, 38, 0.15); border-left: 3px solid #dc2626; margin: 0 -12px; padding: 0 12px; display: block; }}
.fix-block {{ background: rgba(34, 197, 94, 0.05); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 6px; padding: 12px; margin: 8px 0; }}
.fix-block pre {{ font-family: 'Fira Code', monospace; font-size: 12px; color: #22c55e; }}
.cvss-bar {{ display: flex; align-items: center; gap: 8px; margin: 4px 0; }}
.cvss-score {{ font-size: 20px; font-weight: bold; }}
.cvss-vector {{ font-size: 11px; color: #64748b; font-family: monospace; }}
.owasp-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }}
.owasp-card {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 12px; }}
.owasp-card .code {{ font-size: 11px; color: #3b82f6; font-weight: 600; }}
.owasp-card .title {{ font-size: 13px; margin-top: 4px; }}
.owasp-card .count {{ font-size: 24px; font-weight: bold; margin-top: 8px; }}
.explanation {{ background: rgba(59, 130, 246, 0.05); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 6px; padding: 12px; margin: 8px 0; font-size: 13px; color: #93c5fd; }}
.taint-flow {{ font-family: monospace; font-size: 12px; padding: 8px 12px; background: #0f172a; border-radius: 4px; margin: 8px 0; color: #f59e0b; }}
.refs {{ margin-top: 8px; }}
.refs a {{ color: #3b82f6; text-decoration: none; margin-right: 12px; font-size: 12px; }}
.refs a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>MyScan Enterprise Security Report</h1>
<p class="subtitle">Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} | Files scanned: {result.files_scanned} | Duration: {result.scan_duration:.1f}s | Lines: {result.lines_scanned:,}</p>
</div>

{secret_warning}

<div class="score-card">
<div class="score-box">
<div class="number" style="color:{severity_colors['critical']}">{sc['critical']}</div>
<div class="label">Critical</div>
</div>
<div class="score-box">
<div class="number" style="color:{severity_colors['high']}">{sc['high']}</div>
<div class="label">High</div>
</div>
<div class="score-box">
<div class="number" style="color:{severity_colors['medium']}">{sc['medium']}</div>
<div class="label">Medium</div>
</div>
<div class="score-box">
<div class="number" style="color:{severity_colors['low']}">{sc['low']}</div>
<div class="label">Low</div>
</div>
<div class="score-box">
<div class="number" style="color:{severity_colors['info']}">{sc['info']}</div>
<div class="label">Info</div>
</div>
<div class="score-box">
<div class="number grade grade-{'a' if result.risk_score < 15 else 'b' if result.risk_score < 30 else 'c' if result.risk_score < 60 else 'd' if result.risk_score < 80 else 'f'}">{result.grade}</div>
<div class="label">Grade (Score: {result.risk_score}/100)</div>
</div>
</div>

<div class="section">
<h2>Risk Distribution</h2>
<div class="bar-chart">
{''.join(f'<div class="bar"><span class="bar-label">{sev.title()}</span><div class="bar-track"><div class="bar-fill" style="width:{max(count/max(sc.values(), default=1)*100, 2):.0f}%;background:{severity_colors.get(sev, "#6b7280")}">{count}</div></div></div>' for sev, count in sc.items() if count > 0)}
</div>
</div>

{owasp_breakdown}

<div class="section">
<h2>Security Findings ({len(sec)})</h2>
{finding_cards}
</div>

{'<div class="section"><h2>Quality Findings (' + str(len(qual)) + ')</h2><table><thead><tr><th>Severity</th><th>Title</th><th>Location</th><th>Description</th></tr></thead><tbody>' + quality_rows + '</tbody></table></div>' if qual else ''}

{'<div class="section"><h2>Secret Findings (' + str(len(secs)) + ')</h2><table><thead><tr><th>Severity</th><th>Title</th><th>Location</th><th>Fix</th></tr></thead><tbody>' + secret_rows + '</tbody></table></div>' if secs else ''}

<div class="footer">
<p>MyScan v2.0.0 Enterprise - AI-Powered SAST Platform</p>
</div>
</div>
</body>
</html>"""

    def _build_owasp_breakdown(self, findings) -> str:
        if not findings:
            return ""
        owasp_counts: dict[str, int] = {}
        for f in findings:
            if f.owasp:
                key = f"{f.owasp.code} - {f.owasp.title}"
                owasp_counts[key] = owasp_counts.get(key, 0) + 1
        if not owasp_counts:
            return ""
        cards = ""
        for owasp_info, count in sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True):
            code, _, title = owasp_info.partition(" - ")
            cards += f'<div class="owasp-card"><div class="code">{html_escape(code)}</div><div class="title">{html_escape(title)}</div><div class="count">{count}</div></div>'
        return f'<div class="section"><h2>OWASP Top 10 Breakdown</h2><div class="owasp-grid">{cards}</div></div>'

    def _build_finding_cards(self, findings, colors: dict, bgs: dict) -> str:
        cards = ""
        for i, f in enumerate(sorted(findings, key=lambda x: x.severity.numeric), 1):
            color = colors.get(f.severity.value, "#6b7280")
            bg = bgs.get(f.severity.value, "rgba(107,114,128,0.1)")

            refs_html = "".join(f'<a href="{html_escape(r)}" target="_blank">Ref {j+1}</a>' for j, r in enumerate(f.references[:3]))
            code_html = self._format_code_snippet(f.location.code_snippet, f.location.line) if f.location.code_snippet else ""
            fix_html = f'<div class="fix-block"><strong>Fix:</strong><pre>{html_escape(f.fix_suggestion)}</pre></div>' if f.fix_suggestion else ""
            fixed_code_html = ""
            if f.fixed_code:
                fixed_code_html = f'<div class="fix-block"><strong>Suggested Fix:</strong><pre>{html_escape(f.fixed_code)}</pre></div>'
            explanation_html = f'<div class="explanation"><strong>Why Vulnerable:</strong> {html_escape(f.why_vulnerable or f.description)}</div>' if (f.why_vulnerable or f.description) else ""
            impact_html = f'<div class="detail-box"><div class="label">Impact</div><div class="value">{html_escape(f.impact)}</div></div>' if f.impact else ""
            exploit_html = f'<div class="explanation" style="border-color:rgba(239,68,68,0.2);background:rgba(239,68,68,0.05);color:#fca5a5"><strong>Exploit Scenario:</strong><pre style="margin-top:8px;white-space:pre-wrap">{html_escape(f.exploit_scenario)}</pre></div>' if f.exploit_scenario else ""
            cvss_html = ""
            if f.cvss and f.cvss.base_score > 0:
                cvss_color = "#dc2626" if f.cvss.base_score >= 9 else "#ea580c" if f.cvss.base_score >= 7 else "#ca8a04" if f.cvss.base_score >= 4 else "#2563eb"
                cvss_html = f'<div class="cvss-bar"><span class="cvss-score" style="color:{cvss_color}">{f.cvss.base_score:.1f}</span><span class="cvss-vector">{html_escape(f.cvss.vector)}</span></div>'

            owasp_html = f'<span class="meta">| {f.owasp.code}</span>' if f.owasp else ""
            cwe_html = f'<span class="meta">| {html_escape(f.cwe)}</span>' if f.cwe else ""

            cards += f"""<div class="finding-card">
<div class="finding-header">
<span class="severity-badge" style="background:{color}">{f.severity.value.upper()}</span>
<span class="title">{html_escape(f.title)}</span>
<span class="meta">{html_escape(f.location.file_path)}:{f.location.line}</span>
{cwe_html}
{owasp_html}
<span class="meta">| Confidence: {f.confidence:.0%}</span>
</div>
<div class="finding-body">
<div class="desc">{html_escape(f.description[:200])}</div>
<div class="finding-detail">
<div class="detail-box"><div class="label">File</div><div class="value"><code>{html_escape(f.location.file_path)}:{f.location.line}</code></div></div>
<div class="detail-box"><div class="label">Category</div><div class="value">{html_escape(f.category.value)}</div></div>
<div class="detail-box"><div class="label">Language</div><div class="value">{html_escape(f.language.value)}</div></div>
<div class="detail-box"><div class="label">Confidence</div><div class="value">{f.confidence:.0%}</div></div>
</div>
{cvss_html}
{explanation_html}
{exploit_html}
{impact_html}
{code_html}
{fix_html}
{fixed_code_html}
{f'<div class="refs">{refs_html}</div>' if refs_html else ''}
</div>
</div>"""
        return cards

    def _format_code_snippet(self, snippet: str, vuln_line: int) -> str:
        if not snippet:
            return ""
        lines = snippet.split("\n")
        code_lines = ""
        base_line = max(1, vuln_line - len(lines) // 2)
        for j, line in enumerate(lines):
            ln = base_line + j
            is_vuln = ln == vuln_line
            escaped = html_escape(line)
            if is_vuln:
                code_lines += f'<span class="vuln-line"><span class="line-num">{ln}</span>{escaped}</span>'
            else:
                code_lines += f'<span class="line-num">{ln}</span>{escaped}\n'
        return f'<div class="code-block"><pre>{code_lines}</pre></div>'

    def _build_quality_rows(self, findings, colors: dict) -> str:
        rows = ""
        for f in findings:
            color = colors.get(f.severity.value, "#6b7280")
            rows += f"""<tr>
<td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;">{f.severity.value.upper()}</span></td>
<td><strong>{html_escape(f.title)}</strong></td>
<td><code style="font-size:12px;">{html_escape(f.location.file_path)}:{f.location.line}</code></td>
<td>{html_escape(f.description[:150])}</td>
</tr>"""
        return rows

    def _build_secret_rows(self, findings, colors: dict) -> str:
        rows = ""
        for f in findings:
            color = colors.get(f.severity.value, "#6b7280")
            rows += f"""<tr>
<td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;">{f.severity.value.upper()}</span></td>
<td><strong>{html_escape(f.title)}</strong></td>
<td><code style="font-size:12px;">{html_escape(f.location.file_path)}:{f.location.line}</code></td>
<td>{html_escape(f.fix_suggestion[:150])}</td>
</tr>"""
        return rows
