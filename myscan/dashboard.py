"""MyScan Enterprise Dashboard - Streamlit web interface with enterprise features."""

import json
import os
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent))

st.set_page_config(
    page_title="MyScan Enterprise - SAST Platform",
    page_icon="🔍",
    layout="wide",
)

st.title("MyScan Enterprise - SAST Platform")
st.caption("AI-Powered Static Application Security Testing")

SCRIPT_DIR = str(Path(__file__).parent)


def run_cli_scan(target: str, local: bool = False, use_ai: bool = False,
                 skip_deps: bool = False, enterprise: bool = False,
                 secret_display: str = "smart"):
    from src.cli import run_scan
    return run_scan(target, local=local, use_ai=use_ai, skip_deps=skip_deps,
                    enterprise=enterprise, secret_display=secret_display)


tab_scan, tab_report, tab_analytics = st.tabs(["Scan Repository", "View Report", "Analytics"])

with tab_scan:
    st.subheader("Scan a Repository")

    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input("GitHub URL or local path", placeholder="https://github.com/user/repo")
    with col2:
        local = st.checkbox("Local directory")

    col3, col4, col5 = st.columns(3)
    with col3:
        enterprise_mode = st.checkbox("Enterprise Mode", value=True,
                                       help="Enable AST, data flow, taint tracking, and context analysis")
    with col4:
        use_ai = st.checkbox("AI Analysis", value=False)
    with col5:
        skip_deps = st.checkbox("Skip Dependencies", value=False)

    st.markdown("**Secret Display**")
    secret_display_mode = st.radio(
        "Secret Display",
        ["smart", "masked", "full"],
        index=0,
        horizontal=True,
        help="Smart: show weak passwords, mask production secrets. Masked: always mask. Full: show all secrets (Developer Mode).",
        label_visibility="collapsed",
    )

    if secret_display_mode == "full":
        st.warning("Full secret display is enabled. Reports may expose sensitive credentials.")

    if st.button("Run Scan", type="primary", disabled=not target):
        with st.spinner("Scanning... this may take a while"):
            try:
                findings = run_cli_scan(target, local=local, use_ai=use_ai,
                                        skip_deps=skip_deps, enterprise=enterprise_mode,
                                        secret_display=secret_display_mode)
                st.session_state["findings"] = findings
                st.session_state["enterprise_mode"] = enterprise_mode
                st.session_state["secret_display_mode"] = secret_display_mode
                st.success(f"Found {len(findings)} issue(s)")
            except Exception as e:
                st.error(f"Scan failed: {e}")

    if "findings" in st.session_state:
        findings = st.session_state["findings"]
        is_enterprise = st.session_state.get("enterprise_mode", False)

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        st.subheader("Scan Results")
        c1, c2, c3, c4, c5, c6 = st.columns(6)
        c1.metric("Critical", sev_counts["critical"], delta=None,
                   delta_color="inverse")
        c2.metric("High", sev_counts["high"])
        c3.metric("Medium", sev_counts["medium"])
        c4.metric("Low", sev_counts["low"])
        c5.metric("Info", sev_counts["info"])
        c6.metric("Total", len(findings))

        if any(sev_counts.values()):
            st.subheader("Severity Distribution")
            chart_data = {k: v for k, v in sev_counts.items() if v > 0}
            if chart_data:
                st.bar_chart(chart_data)

        owasp_data = {}
        for f in findings:
            owasp = f.get("owasp")
            if owasp and isinstance(owasp, dict):
                code = owasp.get("code", "Unknown")
                owasp_data[code] = owasp_data.get(code, 0) + 1

        if owasp_data:
            st.subheader("OWASP Top 10 Breakdown")
            for code, count in sorted(owasp_data.items(), key=lambda x: x[1], reverse=True):
                cols = st.columns([3, 1])
                cols[0].write(f"**{code}**")
                cols[1].write(f"{count} findings")

        cvss_scores = []
        for f in findings:
            cvss = f.get("cvss")
            if cvss and isinstance(cvss, dict):
                score = cvss.get("score", 0)
                if score > 0:
                    cvss_scores.append({"rule": f.get("rule_id", ""), "score": score})

        if cvss_scores:
            st.subheader("CVSS Score Distribution")
            st.bar_chart({item["rule"]: item["score"] for item in cvss_scores[:20]})

        if findings:
            st.subheader("Findings")

            severity_filter = st.multiselect(
                "Filter by severity",
                ["critical", "high", "medium", "low", "info"],
                default=["critical", "high", "medium"],
            )

            category_filter = st.multiselect(
                "Filter by category",
                list(set(f.get("category", "unknown") for f in findings)),
                default=[],
            )

            filtered = [f for f in findings if f.get("severity") in severity_filter]
            if category_filter:
                filtered = [f for f in filtered if f.get("category") in category_filter]

            for f in filtered[:100]:
                severity = f.get("severity", "info")
                color_map = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
                icon = color_map.get(severity, "⚪")

                title = f.get("title", f.get("description", "Unknown Issue"))
                confidence = f.get("confidence", 0)
                conf_pct = f"{confidence:.0%}" if isinstance(confidence, (int, float)) else confidence

                st.markdown(f"**{icon} [{severity.upper()}]** {title} `Confidence: {conf_pct}`")

                cols = st.columns([2, 1, 1, 1])
                cols[0].caption(f"File: `{f.get('file', 'N/A')}`")
                cols[1].caption(f"Line: {f.get('line', 'N/A')}")
                cols[2].caption(f"Category: {f.get('category', 'N/A')}")
                cwe_val = f.get("cwe", "N/A")
                if isinstance(cwe_val, dict):
                    cwe_val = cwe_val.get("id", "N/A")
                cols[3].caption(f"CWE: {cwe_val}")

                cvss = f.get("cvss")
                if cvss and isinstance(cvss, dict):
                    score = cvss.get("score", 0)
                    vector = cvss.get("vector", "")
                    if score > 0:
                        st.caption(f"CVSS: {score:.1f} `{vector}`")

                if f.get("description"):
                    with st.expander("Description"):
                        st.write(f["description"])

                why_vuln = f.get("why_vulnerable") or f.get("explanation")
                if why_vuln:
                    with st.expander("Why Vulnerable"):
                        st.write(why_vuln)

                if f.get("impact"):
                    with st.expander("Impact"):
                        st.write(f["impact"])

                if f.get("exploit_scenario"):
                    with st.expander("Exploit Scenario"):
                        st.code(f["exploit_scenario"], language="text")

                code_snippet = f.get("code_snippet", "")
                if code_snippet:
                    with st.expander("Vulnerable Code"):
                        st.code(code_snippet, language="python")

                if f.get("fix_suggestion"):
                    st.info(f"**Fix:** {f['fix_suggestion']}")

                if f.get("fixed_code"):
                    with st.expander("Suggested Fix"):
                        st.code(f["fixed_code"], language="python")

                refs = f.get("references", [])
                if refs:
                    with st.expander("References"):
                        for r in refs:
                            st.markdown(f"- [{r}]({r})")

                st.divider()

            if len(filtered) > 100:
                st.info(f"Showing 100 of {len(filtered)} findings.")

with tab_report:
    st.subheader("View Existing Report")

    report_dir = Path("myscan_reports")
    if report_dir.exists():
        reports = sorted(report_dir.glob("*.json"), reverse=True)
        if reports:
            selected = st.selectbox("Select report", [r.name for r in reports[:20]])
            if selected:
                try:
                    with open(report_dir / selected, "r", encoding="utf-8") as f:
                        report_data = json.load(f)

                    if "summary" in report_data:
                        summary = report_data["summary"]
                        c1, c2, c3, c4, c5 = st.columns(5)
                        c1.metric("Risk Score", f"{summary.get('riskScore', summary.get('risk_score', 0))}/100")
                        c2.metric("Grade", summary.get("grade", "N/A"))
                        c3.metric("Total Findings", summary.get("totalFindings", summary.get("total_findings", 0)))
                        c4.metric("Files Scanned", summary.get("filesScanned", summary.get("files_scanned", 0)))
                        c5.metric("Duration", f"{report_data.get('scan', {}).get('duration', report_data.get('scan_duration', 0)):.1f}s")

                        sev = summary.get("severityCounts", summary.get("severity_counts", {}))
                        if sev:
                            st.subheader("Severity Breakdown")
                            st.bar_chart({k: v for k, v in sev.items() if v > 0})

                    findings_list = report_data.get("findings", [])
                    if findings_list:
                        st.subheader(f"Findings ({len(findings_list)})")

                        report_sev_filter = st.multiselect(
                            "Filter by severity",
                            ["critical", "high", "medium", "low", "info"],
                            default=["critical", "high", "medium"],
                            key="report_sev_filter",
                        )

                        report_filtered = [f for f in findings_list if f.get("severity") in report_sev_filter]

                        for f in report_filtered[:50]:
                            sev = f.get("severity", "info")
                            color_map = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
                            icon = color_map.get(sev, "⚪")
                            title = f.get("title", "Unknown")
                            rule_id = f.get("ruleId", f.get("rule_id", ""))
                            st.markdown(f"**{icon} [{sev.upper()}]** {title} `{rule_id}`")

                            loc = f.get("location", {})
                            file_path = loc.get("file", f.get("file", "N/A"))
                            line = loc.get("line", f.get("line", "N/A"))
                            st.caption(f"File: `{file_path}:{line}`")

                            if f.get("cwe"):
                                cwe = f["cwe"]
                                if isinstance(cwe, dict):
                                    st.caption(f"CWE: {cwe.get('id', '')} ({cwe.get('name', '')})")
                                else:
                                    st.caption(f"CWE: {cwe}")

                            if f.get("cvss") and isinstance(f["cvss"], dict):
                                st.caption(f"CVSS: {f['cvss'].get('score', 0):.1f}")

                            desc = f.get("description", "")
                            if desc:
                                with st.expander("Description"):
                                    st.write(desc)

                            code = f.get("codeSnippet", f.get("code_snippet", ""))
                            if code:
                                with st.expander("Code"):
                                    st.code(code, language="python")

                            fix = f.get("fixSuggestion", f.get("fix_suggestion", ""))
                            if fix:
                                st.info(f"**Fix:** {fix}")

                            st.divider()

                        if len(report_filtered) > 50:
                            st.info(f"Showing 50 of {len(report_filtered)} findings.")
                    else:
                        st.json(report_data)
                except Exception as e:
                    st.error(f"Failed to load report: {e}")
        else:
            st.info("No JSON reports found. Run a scan first.")
    else:
        st.info("No reports directory found. Run a scan first.")

    uploaded = st.file_uploader("Or upload a JSON report", type=["json"])
    if uploaded:
        try:
            report_data = json.load(uploaded)
            if "findings" in report_data:
                st.success(f"Loaded report with {len(report_data['findings'])} findings")
                st.json(report_data)
            else:
                st.json(report_data)
        except Exception as e:
            st.error(f"Failed to parse report: {e}")

with tab_analytics:
    st.subheader("Analytics Dashboard")

    if "findings" in st.session_state:
        findings = st.session_state["findings"]

        sev_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        risk_score = 0
        for f in findings:
            sev = f.get("severity", "info")
            conf = f.get("confidence", 0)
            risk_score += sev_weights.get(sev, 1) * conf
        risk_score = min(int(risk_score), 100)

        if risk_score == 0:
            grade = "A+"
        elif risk_score < 5:
            grade = "A"
        elif risk_score < 15:
            grade = "B"
        elif risk_score < 30:
            grade = "C"
        elif risk_score < 60:
            grade = "D"
        else:
            grade = "F"

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Findings", len(findings))
        c2.metric("Risk Score", f"{risk_score}/100")
        c3.metric("Grade", grade)
        c4.metric("Avg Confidence", f"{sum(f.get('confidence', 0) for f in findings) / max(len(findings), 1):.0%}")

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        if any(sev_counts.values()):
            st.subheader("Severity Distribution")
            st.bar_chart({k: v for k, v in sev_counts.items() if v > 0})

        cat_counts = {}
        for f in findings:
            cat = f.get("category", "unknown")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        if cat_counts:
            st.subheader("Findings by Category")
            st.bar_chart(cat_counts)

        lang_counts = {}
        for f in findings:
            lang = f.get("language", "unknown")
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
        if lang_counts:
            st.subheader("Findings by Language")
            st.bar_chart(lang_counts)

        conf_values = [f.get("confidence", 0) for f in findings if isinstance(f.get("confidence"), (int, float))]
        if conf_values:
            st.subheader("Confidence Distribution")
            st.bar_chart({"low": sum(1 for c in conf_values if c < 0.3),
                          "medium": sum(1 for c in conf_values if 0.3 <= c < 0.7),
                          "high": sum(1 for c in conf_values if c >= 0.7)})

        cwe_counts = {}
        for f in findings:
            cwe = f.get("cwe", "")
            if cwe:
                if isinstance(cwe, dict):
                    cwe = cwe.get("id", "")
                if cwe:
                    cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        if cwe_counts:
            st.subheader("Top CWEs")
            sorted_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            st.bar_chart(dict(sorted_cwes))

        cvss_scores = [f.get("cvss", {}).get("score", 0) for f in findings if isinstance(f.get("cvss"), dict) and f["cvss"].get("score", 0) > 0]
        if cvss_scores:
            st.subheader("CVSS Score Distribution")
            st.bar_chart({
                "Critical (9+)": sum(1 for s in cvss_scores if s >= 9),
                "High (7-8.9)": sum(1 for s in cvss_scores if 7 <= s < 9),
                "Medium (4-6.9)": sum(1 for s in cvss_scores if 4 <= s < 7),
                "Low (<4)": sum(1 for s in cvss_scores if s < 4),
            })
    else:
        st.info("Run a scan to see analytics.")

st.sidebar.title("MyScan Enterprise")
st.sidebar.markdown("""
**v2.0.0** - Enterprise SAST Platform

**Analysis Engine:**
- Python AST Analysis
- Data Flow / Taint Tracking
- Context-Aware Analysis
- Confidence Scoring (CVSS v3.1)
- Smart Deduplication
- Repository Indexing

**Scanners:**
- 47+ Security Rules
- 10 Quality Rules
- 20 Secret Patterns

**Usage:**
```bash
myscan scan https://github.com/user/repo
myscan scan . --local --enterprise
myscan quick https://github.com/user/repo
```
""")

st.sidebar.divider()
st.sidebar.markdown("**API Keys**")
if os.environ.get("OPENAI_API_KEY"):
    st.sidebar.success("OpenAI: configured")
else:
    st.sidebar.warning("OpenAI: not set")
if os.environ.get("ANTHROPIC_API_KEY"):
    st.sidebar.success("Anthropic: configured")
else:
    st.sidebar.warning("Anthropic: not set")
