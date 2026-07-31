"""Scan configuration."""

from __future__ import annotations

from dataclasses import dataclass

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".eggs", "dist", "build",
    ".idea", ".vscode", "myscan_reports", "myscan.egg-info", ".cache",
    "vendor", "coverage", "htmlcov", ".nyc_output", "target",
    "__snapshots__", ".gradle", ".maven",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "Gemfile.lock",
    "Cargo.lock", "composer.lock", "go.sum",
}

SKIP_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin",
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".min.js", ".min.css", ".map",
    ".lock", ".sum", ".gradle.lockfile",
    ".mp4", ".mp3", ".wav", ".avi",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".db", ".sqlite", ".sqlite3",
}

SKIP_PATH_PATTERNS = {
    "README", "LICENSE", "CHANGELOG", "CONTRIBUTING", "AUTHORS",
    "HISTORY", "CHANGES", "NEWS", "examples/", "example/",
    "fixtures/", "__snapshots__/", "testdata/", "test-data/",
    "spec/", "__tests__/", ".github/", ".circleci/",
}

SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
    ".php", ".cs", ".rs", ".c", ".h", ".cpp", ".cc", ".hpp",
    ".rb", ".swift", ".kt", ".scala", ".sh", ".bash", ".ps1",
    ".sql", ".html", ".css", ".scss", ".less",
    ".tf", ".hcl", ".yml", ".yaml", ".toml", ".json", ".xml",
    ".dockerfile", ".proto", ".graphql", ".env", ".ini", ".cfg", ".conf",
}


@dataclass
class ScanConfig:
    target: str = ""
    local: bool = False
    use_ai: bool = False
    ai_provider: str | None = None
    ai_limit: int = 20
    skip_deps: bool = False
    skip_git: bool = False
    skip_quality: bool = False
    skip_secrets: bool = False
    skip_security: bool = False
    include_tests: bool = False
    include_examples: bool = False
    include_docs: bool = False
    max_file_size: int = 1_048_576
    max_line_length: int = 2000
    output_format: str = "markdown"
    output_path: str | None = None
    severity_threshold: str = "info"
    threads: int = 4
    max_workers: int = 4
    cache_enabled: bool = True
    min_confidence: float = 0.15

    @property
    def skip_dirs(self) -> set[str]:
        d = set(SKIP_DIRS)
        if not self.include_tests:
            d.update({"tests", "test", "__tests__", "spec", "test_", "_test"})
        if not self.include_examples:
            d.update({"examples", "example", "demo", "demos"})
        if not self.include_docs:
            d.update({"docs", "doc", "documentation"})
        return d
