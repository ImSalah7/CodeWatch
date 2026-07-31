# Roadmap — MyScan

Prioritized by impact. Items are community/enterprise driven; the order may change.

## Now (short term)

- [ ] **Type checking (mypy)** — blocked on mypy 2.x module-resolution collision with the `src/__init__.py` package layout (`Source file found twice: "src" and "src.__init__"`); see [ci-cd.md](ci-cd.md) §4.
- [ ] **Add the git remote and publish** — no remote is configured yet; tag and release `v3.0.1`.
- [x] **Frontend lint debt** — all pre-existing warnings/errors in settings/analytics/dashboard/scan/reports pages resolved; `npm run lint` clean and `npm run build` green.

## Near term

- [ ] **Multi-user auth** — replace the single shared API key with per-user accounts, roles (viewer/operator/admin), and scoped keys. Blocked on: password hashing + session design; see [authentication.md](authentication.md).
- [ ] **Scan scheduling** — cron-style recurring scans with alerting on new high/critical findings.
- [ ] **Triage workflows** — comments/timeline on findings, audit trail for `finding_state` transitions, re-verification ("fixed?") flows.
- [ ] **Native semgrep/bandit parity** — extend `benchmark` into a plugin runner so external tools feed the same findings model.
- [ ] **More languages** — tree-sitter grammars for Swift, Kotlin, Scala, and Dockerfile/TOML parsing.

## Later

- [ ] **Team dashboard** — per-repo/team aggregation, SLA views, trend charts across history.
- [ ] **Enterprise SSO** — SAML/OIDC federation in front of the UI.
- [ ] **Database option** — PostgreSQL backend for multi-instance HA deployments (SQLite today).
- [ ] **Cloud runners** — containerized, ephemeral scan workers; auto-scaling scan queues.
- [ ] **Policy as code** — define block/allow rules (e.g. "fail on any A01 critical") shipped as `myscan.policy.yaml`.
- [ ] **IDE + git-hook integration** — pre-commit hook, VS Code extension, GitHub Actions action.
- [ ] **i18n** for the web UI.

## Done

- [x] v3.0 Enterprise foundation (AST, 57 rules, API/UI/CLI/exporters)
- [x] v3.0.0 security hardening (auth, rate limit, SSRF, secret display modes, LLM)
- [x] v3.0.1 audit (SEC001 FP fix, dedup + occurrences, enriched reports, findings API + enterprise UI)
- [x] Production documentation suite + `scripts/check_docs_sync.py`
- [x] CI wiring: ruff lint, docs-sync, and frontend lint/build jobs (mypy deferred)
- [x] Version bump to 3.0.1

## Release cadence

- Patch (3.0.x): bug fixes, docs, minor hardening — on `master`.
- Minor (3.x): features — branch + merge request per item.
- Major (x.0): breaking changes — advisory + migration notes in [CHANGELOG.md](../CHANGELOG.md).
