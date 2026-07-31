"""Repository Indexer.

Classifies files into categories and determines what should be scanned:
- Production Code
- Tests
- Documentation
- Generated Code
- Vendor Libraries
- Configuration
- Secrets/Environment
- Infrastructure

Provides intelligent skip/include logic based on file classification.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class FileCategory(Enum):
    PRODUCTION = "production"
    TEST = "test"
    DOCUMENTATION = "documentation"
    GENERATED = "generated"
    VENDOR = "vendor"
    CONFIGURATION = "configuration"
    ENVIRONMENT = "environment"
    INFRASTRUCTURE = "infrastructure"
    LOCK_FILE = "lock_file"
    UNKNOWN = "unknown"


class CodeType(Enum):
    SOURCE = "source"
    SCRIPT = "script"
    CONFIG = "config"
    TEMPLATE = "template"
    MARKUP = "markup"
    STYLE = "style"
    DATA = "data"
    BINARY = "binary"
    INFRASTRUCTURE = "infrastructure"
    ENVIRONMENT = "environment"
    UNKNOWN = "unknown"


@dataclass
class FileIndex:
    """Indexed file information."""
    path: str
    relative_path: str
    language: str
    file_category: FileCategory
    code_type: CodeType
    size: int
    line_count: int = 0
    is_scannable: bool = True
    skip_reason: str = ""
    confidence: float = 1.0


@dataclass
class RepositoryIndex:
    """Complete repository index."""
    root_path: str
    files: list[FileIndex] = field(default_factory=list)
    production_files: list[FileIndex] = field(default_factory=list)
    test_files: list[FileIndex] = field(default_factory=list)
    doc_files: list[FileIndex] = field(default_factory=list)
    config_files: list[FileIndex] = field(default_factory=list)
    generated_files: list[FileIndex] = field(default_factory=list)
    vendor_files: list[FileIndex] = field(default_factory=list)
    env_files: list[FileIndex] = field(default_factory=list)
    infrastructure_files: list[FileIndex] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    total_files: int = 0
    scannable_files: int = 0
    skipped_files: int = 0


SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".eggs", "dist", "build",
    ".idea", ".vscode", "myscan_reports", "myscan.egg-info", ".cache",
    "vendor", "coverage", "htmlcov", ".nyc_output", "target",
    "__snapshots__", ".gradle", ".maven", ".next", "out",
    ".turbo", ".swc", ".parcel-cache", "bower_components",
    ".pub-cache", ".dart_tool", "Pods", ".bundle",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "Gemfile.lock",
    "Cargo.lock", "composer.lock", "go.sum",
    "e2e_report.json", "myscan.egg-info",
}

BINARY_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin",
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".db", ".sqlite", ".sqlite3",
    ".min.js", ".min.css", ".map",
}

SOURCE_EXTENSIONS = {
    ".py": ("python", CodeType.SOURCE),
    ".js": ("javascript", CodeType.SOURCE),
    ".ts": ("typescript", CodeType.SOURCE),
    ".jsx": ("javascript", CodeType.SOURCE),
    ".tsx": ("typescript", CodeType.SOURCE),
    ".java": ("java", CodeType.SOURCE),
    ".go": ("go", CodeType.SOURCE),
    ".php": ("php", CodeType.SOURCE),
    ".cs": ("csharp", CodeType.SOURCE),
    ".rs": ("rust", CodeType.SOURCE),
    ".c": ("c", CodeType.SOURCE),
    ".h": ("c", CodeType.SOURCE),
    ".cpp": ("cpp", CodeType.SOURCE),
    ".cc": ("cpp", CodeType.SOURCE),
    ".hpp": ("cpp", CodeType.SOURCE),
    ".rb": ("ruby", CodeType.SOURCE),
    ".swift": ("swift", CodeType.SOURCE),
    ".kt": ("kotlin", CodeType.SOURCE),
    ".scala": ("scala", CodeType.SOURCE),
    ".sh": ("shell", CodeType.SCRIPT),
    ".bash": ("shell", CodeType.SCRIPT),
    ".ps1": ("powershell", CodeType.SCRIPT),
    ".sql": ("sql", CodeType.SOURCE),
    ".html": ("html", CodeType.MARKUP),
    ".htm": ("html", CodeType.MARKUP),
    ".css": ("css", CodeType.STYLE),
    ".scss": ("scss", CodeType.STYLE),
    ".less": ("less", CodeType.STYLE),
    ".tf": ("terraform", CodeType.INFRASTRUCTURE),
    ".hcl": ("terraform", CodeType.INFRASTRUCTURE),
    ".yml": ("yaml", CodeType.CONFIG),
    ".yaml": ("yaml", CodeType.CONFIG),
    ".toml": ("toml", CodeType.CONFIG),
    ".json": ("json", CodeType.DATA),
    ".xml": ("xml", CodeType.DATA),
    ".md": ("markdown", CodeType.MARKUP),
    ".rst": ("rst", CodeType.MARKUP),
    ".proto": ("protobuf", CodeType.SOURCE),
    ".graphql": ("graphql", CodeType.SOURCE),
    ".dockerfile": ("dockerfile", CodeType.INFRASTRUCTURE),
    ".ini": ("ini", CodeType.CONFIG),
    ".cfg": ("ini", CodeType.CONFIG),
    ".conf": ("conf", CodeType.CONFIG),
    ".env": ("dotenv", CodeType.ENVIRONMENT),
}

CONFIG_FILENAMES = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "makefile", "cmakelists.txt", "rakefile", "gemfile",
    "procfile", "vagrantfile", "justfile", "taskfile",
    ".dockerignore", ".gitignore", ".eslintignore",
    "tsconfig.json", "webpack.config.js", "vite.config.js",
    "next.config.js", "nuxt.config.js", "babel.config.js",
    ".babelrc", ".eslintrc", ".prettierrc",
    "setup.py", "setup.cfg", "pyproject.toml", "tox.ini",
    "jest.config.js", "vitest.config.js", "karma.conf.js",
    "mocha.config.js", ".mocharc.yml",
}

TEST_INDICATORS = {
    "test_", "_test.py", "test.py", "tests.py",
    ".test.js", ".test.ts", ".spec.js", ".spec.ts",
    ".spec.tsx", ".test.tsx", ".test.jsx",
    "_test.go", "test_*.py", "*_test.go",
    "__tests__", "test/", "tests/", "spec/",
    "pytest.ini", "conftest.py", "setup.cfg",
}

DOC_INDICATORS = {
    "readme", "changelog", "contributing", "authors",
    "history", "changes", "news", "license",
    ".md", ".rst", ".txt",
    "docs/", "doc/", "documentation/",
}

TEST_DIRS = {"test", "tests", "__tests__", "spec", "test_", "_test", "__snapshots__"}


def index_repository(root_path: str, include_tests: bool = False,
                     include_docs: bool = False, include_examples: bool = False) -> RepositoryIndex:
    """Index an entire repository, classifying every file."""
    root = Path(root_path).resolve()
    index = RepositoryIndex(root_path=str(root))

    for dirpath, dirnames, filenames in os.walk(str(root)):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            fp = Path(dirpath) / filename
            file_index = _index_file(fp, root)
            index.files.append(file_index)
            index.total_files += 1

            lang = file_index.language
            if lang:
                index.languages[lang] = index.languages.get(lang, 0) + 1

            if not file_index.is_scannable:
                index.skipped_files += 1
                continue

            index.scannable_files += 1

            if file_index.file_category == FileCategory.PRODUCTION:
                index.production_files.append(file_index)
            elif file_index.file_category == FileCategory.TEST:
                index.test_files.append(file_index)
            elif file_index.file_category == FileCategory.DOCUMENTATION:
                index.doc_files.append(file_index)
            elif file_index.file_category == FileCategory.CONFIGURATION:
                index.config_files.append(file_index)
            elif file_index.file_category == FileCategory.GENERATED:
                index.generated_files.append(file_index)
            elif file_index.file_category == FileCategory.VENDOR:
                index.vendor_files.append(file_index)
            elif file_index.file_category == FileCategory.ENVIRONMENT:
                index.env_files.append(file_index)
            elif file_index.file_category == FileCategory.INFRASTRUCTURE:
                index.infrastructure_files.append(file_index)

    return index


def _index_file(file_path: Path, root: Path) -> FileIndex:
    """Index a single file."""
    try:
        relative_path = str(file_path.relative_to(root))
    except ValueError:
        relative_path = str(file_path)

    try:
        stat = file_path.stat()
        size = stat.st_size
    except OSError:
        size = 0

    suffix = file_path.suffix.lower()
    name = file_path.name.lower()

    if name in SKIP_FILES or suffix in BINARY_EXTENSIONS:
        return FileIndex(
            path=str(file_path),
            relative_path=relative_path,
            language="",
            file_category=FileCategory.UNKNOWN,
            code_type=CodeType.BINARY,
            size=size,
            is_scannable=False,
            skip_reason=f"Binary/lock file: {suffix or name}",
        )

    lang_info = SOURCE_EXTENSIONS.get(suffix)
    if lang_info:
        language, code_type = lang_info
    else:
        language = ""
        code_type = CodeType.UNKNOWN

    category = _classify_file(file_path, relative_path, name, suffix, language)

    line_count = 0
    if category not in (FileCategory.VENDOR, FileCategory.GENERATED, FileCategory.UNKNOWN):
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                line_count = sum(1 for _ in f)
        except (OSError, PermissionError):
            pass

    skip_reason = ""
    is_scannable = True
    if category == FileCategory.VENDOR:
        skip_reason = "Vendor/third-party code"
        is_scannable = False
    elif category == FileCategory.GENERATED:
        skip_reason = "Auto-generated code"
        is_scannable = False
    elif category == FileCategory.DOCUMENTATION:
        skip_reason = "Documentation file"
        is_scannable = False
    elif category == FileCategory.TEST and not include_tests_global():
        skip_reason = "Test file (use --include-tests)"
        is_scannable = False
    elif category == FileCategory.ENVIRONMENT:
        skip_reason = "Environment file - scan for secrets only"
    elif not language:
        skip_reason = f"Unsupported file type: {suffix}"
        is_scannable = False

    return FileIndex(
        path=str(file_path),
        relative_path=relative_path,
        language=language,
        file_category=category,
        code_type=code_type,
        size=size,
        line_count=line_count,
        is_scannable=is_scannable,
        skip_reason=skip_reason,
    )


def _classify_file(
    file_path: Path, relative_path: str, name: str, suffix: str, language: str
) -> FileCategory:
    """Classify a file into a category."""
    parts = Path(relative_path).parts

    if any(d in name for d in TEST_INDICATORS) or any(d in parts for d in TEST_DIRS):
        return FileCategory.TEST

    if any(ind in name for ind in DOC_INDICATORS) or "docs/" in relative_path.lower():
        return FileCategory.DOCUMENTATION

    if name in CONFIG_FILENAMES or suffix in (".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf"):
        return FileCategory.CONFIGURATION

    if name == ".env" or name.startswith(".env.") or suffix == ".env":
        return FileCategory.ENVIRONMENT

    if any(ind in name for ind in ("dockerfile", "makefile", "rakefile", "vagrantfile")):
        return FileCategory.INFRASTRUCTURE

    if suffix in (".tf", ".hcl") or "terraform" in relative_path.lower():
        return FileCategory.INFRASTRUCTURE

    if any(ind in relative_path.lower() for ind in ("vendor/", "third_party/", "node_modules/")):
        return FileCategory.VENDOR

    if any(ind in relative_path.lower() for ind in ("generated", "auto_gen", ".gen.", "autogenerated")):
        return FileCategory.GENERATED

    if any(ind in relative_path.lower() for ind in ("example", "demo", "sample")):
        return FileCategory.TEST

    if suffix in (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php",
                  ".cs", ".rs", ".c", ".cpp", ".cc", ".rb", ".swift", ".kt", ".scala"):
        return FileCategory.PRODUCTION

    return FileCategory.UNKNOWN


def include_tests_global() -> bool:
    """Whether to include test files (set by config)."""
    return False
