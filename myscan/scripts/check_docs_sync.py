"""Documentation synchronization checker for MyScan.

Verifies that the documentation suite matches the codebase:

- README.md exists (required by pyproject.toml's ``readme`` field).
- Version matches between pyproject.toml and src/__init__.py.
- Every route documented in docs/api.md exists in src/api.py.
- Every environment variable documented in docs/security.md,
  docs/deployment.md, and docs/admin-guide.md exists in .env.example.
- Every CLI subcommand documented in docs/user-guide.md exists in src/cli.py.
- Relative .md links inside docs/ resolve to real files.

Exit code 0 = in sync; otherwise the mismatches are listed.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

VERSION_RE = re.compile(r"__version__\s*=\s*[\"']([^\"']+)[\"']")
PYPROJECT_VERSION_RE = re.compile(r"^version\s*=\s*[\"']([^\"']+)[\"']", re.MULTILINE)

# Lines in docs that look like `METHOD /path` (route documentation).
ROUTE_RE = re.compile(r"`\s*(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(/api/[A-Za-z0-9_/.<>=?&%-]+)\s*`")

ENV_VAR_RE = re.compile(r"\b(MYSCAN_[A-Z0-9_]+|API_BASE_URL)\b")

CLI_DOC_RE = re.compile(r"^###\s+`(scan|quick|info|benchmark|serve|list|delete|reports?|export|version|init)`", re.MULTILINE)

LINK_RE = re.compile(r"\]\(([^)]+\.md)\)")

# Docs that are allowed to define environment variables (checked against .env.example).
ENV_DOC_FILES = ("docs/security.md", "docs/deployment.md", "docs/admin-guide.md")

# CLI commands that are allowed to appear in docs but are not real subcommands
# (e.g. mentioned as examples). Real commands are discovered from cli.py.
CLI_ALIASES = {"version"}

ENV_ALIASES = {
    "API_BASE_URL",      # frontend-only, present in .env.example
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "MYSCAN_AI_PROVIDER",
}


def normalize_route(route: str) -> str:
    """Normalize a route for comparison (strip query, unify path params)."""
    route = route.split("?", 1)[0]
    route = re.sub(r"/<[^>]+>", "/<param>", route)
    route = route.rstrip("/")
    return route


def errors() -> list[str]:
    problems: list[str] = []

    readme = ROOT / "README.md"
    if not readme.is_file():
        problems.append("README.md missing (required by pyproject.toml readme field)")

    # 1. Version consistency.
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_src = (ROOT / "src" / "__init__.py").read_text(encoding="utf-8")
    m = PYPROJECT_VERSION_RE.search(pyproject)
    pyproject_version = m.group(1) if m else None
    m = VERSION_RE.search(version_src)
    src_version = m.group(1) if m else None
    if not pyproject_version or not src_version:
        problems.append("version not found in pyproject.toml or src/__init__.py")
    elif pyproject_version != src_version:
        problems.append(
            f"version drift: pyproject.toml={pyproject_version} src/__init__.py={src_version}"
        )

    # 2. API routes documented in docs/api.md must exist in src/api.py.
    api_doc = ROOT / "docs" / "api.md"
    api_src = (ROOT / "src" / "api.py").read_text(encoding="utf-8")
    if api_doc.is_file():
        doc_routes = {
            (method.upper(), normalize_route(route))
            for method, route in ROUTE_RE.findall(api_doc.read_text(encoding="utf-8"))
        }
        implemented = set()
        for m in re.finditer(
            r"@app\.route\(\s*[\"']([^\"']+)[\"']\s*,\s*methods=\[[\"'](GET|POST|PUT|DELETE|PATCH)[\"']", api_src
        ):
            implemented.add((m.group(2), normalize_route(m.group(1))))
        missing = doc_routes - implemented
        for method, route in sorted(missing):
            problems.append(f"docs/api.md documents {method} {route} but src/api.py has no such route")

    # 3. Environment variables in docs must exist in .env.example.
    env_example = ROOT / ".env.example"
    example_vars = set(ENV_VAR_RE.findall(env_example.read_text(encoding="utf-8"))) if env_example.is_file() else set()
    for rel in ENV_DOC_FILES:
        doc = ROOT / rel
        if not doc.is_file():
            continue
        for var in sorted(ENV_VAR_RE.findall(doc.read_text(encoding="utf-8"))):
            if var in ENV_ALIASES or var in example_vars:
                continue
            problems.append(f"{rel} documents {var} but it is absent from .env.example")

    # 4. CLI subcommands documented in docs/user-guide.md must exist in src/cli.py.
    cli_doc = ROOT / "docs" / "user-guide.md"
    cli_src = (ROOT / "src" / "cli.py").read_text(encoding="utf-8")
    if cli_doc.is_file():
        doc_cmds = set(CLI_DOC_RE.findall(cli_doc.read_text(encoding="utf-8"))) - CLI_ALIASES
        impl_cmds = set(re.findall(r"@(?:cli|app)\.command\(\)\s*\n\s*def\s+(\w+)", cli_src))
        # Click @cli.command() may be wrapped in a decorator line with arguments.
        impl_cmds.update(re.findall(r"def\s+(scan|quick|info|benchmark|serve)\s*\(", cli_src))
        missing = doc_cmds - impl_cmds
        problems.extend(
            f"docs/user-guide.md documents CLI subcommand '{cmd}' but it is not in src/cli.py"
            for cmd in sorted(missing)
        )

    # 5. Relative markdown links inside docs/ and README.md resolve.
    link_targets: list[Path] = []
    docs_dir = ROOT / "docs"
    if docs_dir.is_dir():
        link_targets = sorted(docs_dir.rglob("*.md"))
    if readme.is_file():
        link_targets.append(readme)
    for md in link_targets:
        for target in LINK_RE.findall(md.read_text(encoding="utf-8")):
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (md.parent / target).resolve()
            if not resolved.is_file():
                problems.append(f"{md.relative_to(ROOT)} links to missing file {target}")

    return problems


def main() -> int:
    problems = errors()
    if problems:
        print(f"Documentation out of sync ({len(problems)} issue(s)):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("Documentation in sync: version, routes, env vars, CLI, and links OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
