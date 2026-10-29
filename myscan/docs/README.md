# CodeWatch Documentation

Enterprise AI-Powered SAST Platform.

## Start here

- [README](../README.md) — overview, badges, quick start
- [PRD](PRD.md) — product requirements
- [TRD](TRD.md) — technical requirements

## Architecture & design

- [Architecture](architecture.md) — components and data flow
- [System Design](system-design.md) — details, scoring, SSE protocol
- [Folder Structure](folder-structure.md) — repository layout
- [Database Schema](database-schema.md) — tables, columns, migrations (ERD)

## Reference

- [API Reference](api.md) — all routes, auth, errors, SSE
- [Security](security.md) — threat model, env vars, hardening
- [Authentication](authentication.md) — API-key model
- [CLI / User Guide](user-guide.md) — web UI + CLI workflows
- [Admin Guide](admin-guide.md) — production operations

## Operations

- [Deployment](deployment.md) — Docker Compose / bare metal / proxy / TLS
- [Docker](docker.md) — images, Compose reference, volumes
- [CI/CD](ci-cd.md) — GitHub Actions, docs sync, release flow
- [Troubleshooting](troubleshooting.md) — common problems

## Development

- [Developer Guide](developer-guide.md) — conventions, how-to's
- [Testing](testing.md) — running and adding tests

## Planning

- [Roadmap](roadmap.md) — upcoming work
- [Changelog](../CHANGELOG.md) — release history

## Keeping docs in sync

`scripts/check_docs_sync.py` verifies the documentation matches the codebase
(version, API routes, env vars, CLI commands). Run it in CI and before release:

```bash
python scripts/check_docs_sync.py
```

See [ci-cd.md](ci-cd.md) §2.
