# Product Requirements Document (PRD) — MyScan

> Version 3.0.0 · Status: Active · Owner: Engineering

## 1. Product summary

MyScan is an enterprise-grade, self-hosted **Static Application Security Testing (SAST)** platform. It analyzes source code repositories — local folders or remote git URLs — to detect security vulnerabilities, hardcoded secrets, code-quality issues, and vulnerable dependencies. It produces actionable findings with evidence, root-cause analysis, and remediation guidance, and exposes them through a REST API, a web UI, a CLI, and portable report artifacts.

MyScan is designed for development teams and security teams who want a fast, accurate, fully on-premise scanner with no per-seat licensing and full data control.

## 2. Problem statement

- Commercial SAST tools are expensive, often cloud-only, and slow to configure.
- Regex-only scanners produce high false-positive rates and no real analysis depth.
- Security findings without evidence, root cause, or fix suggestions are ignored by developers.
- Teams need a single tool that covers security, secrets, quality, and supply-chain visibility.

## 3. Goals / objectives

1. **Accurate detection** — combine regex rules with AST, data-flow, taint, call-graph, and reachability analysis to keep false positives low (verified by a rule-level validation pipeline).
2. **Fast scans** — parallel scanning, incremental cache, and a benchmark mode to measure precision/recall against Semgrep and Bandit.
3. **Actionable findings** — every finding carries description, CWE/OWASP/CVSS, evidence, code snippet, root cause, impact, exploit scenario, and secure-fix guidance.
4. **Secrets safety** — detect credentials with entropy analysis and enforce safe display modes (`full` / `masked` / `smart`).
5. **Deploy anywhere** — single-command Docker Compose (API + web UI), plus a pure CLI for CI pipelines.
6. **Enterprise readiness** — API key auth, rate limiting, SSRF/path guards, triage workflow (suppress / false-positive / assignee / issue), policy presets (PCI-DSS, HIPAA, SOC2), SBOM and dependency CVE scanning.

## 4. Target users

| Persona | Needs |
|---|---|
| **Developer** | Fast scan of a repo; clear, contextual findings with fix suggestions; low noise. |
| **Security engineer** | Cross-repo visibility, triage workflow, SARIF/HTML/Markdown exports, policy enforcement, benchmark accuracy. |
| **DevOps / SRE** | Containerized deployment, env-var configuration, CI integration via CLI/API, rate limiting and hardening. |
| **Compliance / audit** | SBOM (CycloneDX/SPDX), dependency CVE reports, OWASP/CWE mapping, evidence trail. |

## 5. Functional requirements

### 5.1 Scanning

- FR-1: Scan a local directory or a remote git repository (HTTP/HTTPS/SSH) as target.
- FR-2: Support Python, JavaScript, TypeScript, Java, Go, PHP, C/C++, C#, Rust, Ruby plus generic/config languages (Dockerfile, YAML, etc.).
- FR-3: Run in **standard** mode (regex scanners) or **enterprise** mode (AST + data flow + taint + call-graph reachability).
- FR-4: Exclude tests/docs/examples by default; include them via flags.
- FR-5: Apply severity thresholds, confidence minimums, and configurable parallelism.
- FR-6: Deduplicate identical findings across occurrences; report `occurrences` and per-location lists.

### 5.2 Detection rules

- FR-7: 47 security rules mapped to CWE and OWASP Top 10 (2021) with CVSS scoring.
- FR-8: 10 quality rules (code smells).
- FR-9: 21+ secret patterns with entropy analysis and weak-password/default-credential checks.
- FR-10: Dependency CVE matching across 9 lockfile/manifest formats.
- FR-11: Infrastructure-as-code config scanning (Docker, K8s, Terraform, GitHub Actions, NGINX).

### 5.3 Results & triage

- FR-12: Findings list with filters (severity, category, rule, CWE, language, file, search), sorting, pagination.
- FR-13: Bulk triage: suppress / unsuppress, mark false positive / real, assign, create issue — persisted per scan.
- FR-14: Single-finding detail view with evidence, all occurrences, remediation, references.
- FR-15: Report export: Markdown, HTML, JSON, SARIF 2.1.0, CSV.

### 5.4 Platform

- FR-16: REST API (see docs/api.md) with SSE live-progress stream.
- FR-17: Web UI (Next.js) covering scan, results, reports, analytics, history, search, settings.
- FR-18: CLI (`scan`, `quick`, `info`, `benchmark`).
- FR-19: Settings persistence (threads, confidence, secret display, retention) via API and file.
- FR-20: Security score dashboard (0–100, grade A+–F) with 30-point trend.

## 6. Non-functional requirements

| Category | Requirement |
|---|---|
| **Performance** | Parallel file scanning; incremental scan cache; benchmark mode reports timing. |
| **Security** | API-key auth, rate limiting, CORS allowlist, SSRF protection, local path allowlist, secrets masked by default. |
| **Reliability** | Scans run in background threads; failures are captured as `status=failed` with error text; LLM failures never fail a scan. |
| **Portability** | Pure Python backend (>=3.11) + Docker; SQLite persistence; no external services required. |
| **Observability** | `/health`, per-scan status, progress events, scan history, statistics endpoint. |
| **Retention** | `max_history` setting prunes old scans and their findings. |

## 7. Release scope

- **In scope:** everything in sections 5.1–5.5.
- **Out of scope for v3:** multi-user RBAC accounts (single shared API key), authenticated UI login, multi-tenant SaaS hosting, cloud artifact publishing, plugin marketplace.

## 8. Success metrics

- Test suite passes: **405 tests**.
- SQL injection rule verified against a 17-case parameterized-vs-interpolated matrix (no false positives on parameterized queries).
- A full self-scan of `src/` completes in seconds with deduplicated occurrences.
- Benchmark mode reports precision/recall/F1 vs Semgrep and Bandit.

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| False positives erode trust | Validation pipeline, confidence scoring, trust engine, dedup, manual triage states |
| SSRF via remote targets | Remote host resolution blocks private/loopback/link-local networks |
| Secret leakage in reports | `smart`/`masked` display modes; full-secret warning banner in HTML reports |
| Scan performance on large repos | File filters (size, extensions, dirs), parallel workers, incremental cache |
| LLM dependency | LLM enrichment is optional and never breaks scans; template fallbacks exist |
