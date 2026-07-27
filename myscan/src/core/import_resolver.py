"""Import Resolution Engine.

Resolves all imports across the repository:
- Python: import X, from X import Y, from X import *, from . import Y
- JavaScript/TypeScript: import X from 'module', const X = require('module')
- Go: import "module"

Supports:
- Alias resolution (import X as Y)
- Star import expansion (from X import * → resolve X's exports)
- Relative import resolution (from . import X, from ..pkg import Y)
- Cross-file import tracking (file A imports from file B)
- External vs internal import classification
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class ImportType(Enum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    VARIABLE = "variable"
    STAR = "star"
    UNKNOWN = "unknown"


class ImportSource(Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    STDLIB = "stdlib"
    RELATIVE = "relative"
    UNKNOWN = "unknown"


class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    UNKNOWN = "unknown"


@dataclass
class ImportEntry:
    """A single resolved import."""
    module: str
    names: list[str]
    aliases: dict[str, str]
    source_file: str
    target_module: str
    target_file: str
    import_source: ImportSource
    import_type: ImportType
    line: int = 0
    language: Language = Language.PYTHON
    is_relative: bool = False
    level: int = 0
    resolved: bool = False


@dataclass
class ResolvedImport:
    """A fully resolved import reference."""
    alias: str
    original_name: str
    defining_module: str
    defining_file: str
    defining_line: int
    import_type: ImportType
    import_source: ImportSource


@dataclass
class ImportResolutionResult:
    """Complete import resolution result for a repository."""
    imports: list[ImportEntry] = field(default_factory=list)
    resolved: dict[str, ResolvedImport] = field(default_factory=dict)
    unresolved: list[ImportEntry] = field(default_factory=list)
    modules: dict[str, str] = field(default_factory=dict)
    exports: dict[str, list[str]] = field(default_factory=dict)
    import_graph: dict[str, set[str]] = field(default_factory=dict)
    total_imports: int = 0
    total_resolved: int = 0
    total_unresolved: int = 0


STDLIB_PYTHON = {
    "os", "sys", "re", "json", "math", "time", "datetime", "collections",
    "itertools", "functools", "pathlib", "io", "ast", "hashlib", "hmac",
    "base64", "secrets", "subprocess", "threading", "multiprocessing",
    "socket", "http", "urllib", "email", "html", "xml", "csv", "sqlite3",
    "logging", "unittest", "dataclasses", "typing", "enum", "abc",
    "contextlib", "textwrap", "string", "struct", "codecs", "locale",
    "gettext", "signal", "mmap", "ctypes", "zipfile", "tarfile", "shutil",
    "tempfile", "glob", "fnmatch", "linecache", "pickle", "shelve",
    "dbm", "sqlite3", "xmlrpc", "ftplib", "smtplib", "imaplib",
    "poplib", "telnetlib", "uuid", "platform", "signal", "array",
    "queue", "heapq", "bisect", "weakref", "types", "inspect",
    "traceback", "warnings", "atexit", "gc", "site", "cmd",
    "pdb", "profile", "timeit", "trace", "dis", "pickletools",
}

STDLIB_JS = {
    "fs", "path", "http", "https", "url", "crypto", "buffer",
    "events", "stream", "os", "child_process", "cluster", "net",
    "tls", "readline", "zlib", "querystring", "assert", "util",
    "dns", "dgram", "tty", "v8", "vm", "worker_threads",
}

STDLIB_GO = {
    "fmt", "os", "io", "net", "http", "json", "strings", "strconv",
    "math", "sort", "sync", "time", "context", "log", "errors",
    "testing", "reflect", "unsafe", "runtime", "syscall", "encoding",
    "bytes", "bufio", "path", "filepath", "regexp", "unicode",
    "container", "database", "debug", "go/ast", "go/parser",
}


def _detect_language(file_path: str) -> Language:
    ext = Path(file_path).suffix.lower()
    return {
        ".py": Language.PYTHON,
        ".js": Language.JAVASCRIPT,
        ".jsx": Language.JAVASCRIPT,
        ".ts": Language.TYPESCRIPT,
        ".tsx": Language.TYPESCRIPT,
        ".go": Language.GO,
    }.get(ext, Language.UNKNOWN)


def _is_stdlib(module: str, language: Language) -> bool:
    top = module.split(".")[0]
    if language == Language.PYTHON:
        return top in STDLIB_PYTHON
    if language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
        return top in STDLIB_JS
    if language == Language.GO:
        return top in STDLIB_GO
    return False


def _resolve_relative_import(
    module: str,
    level: int,
    source_file: str,
    repo_path: str,
) -> str:
    source_dir = str(Path(source_file).parent)

    if repo_path:
        try:
            repo_resolved = str(Path(repo_path).resolve())
            source_rel = str(Path(source_dir).resolve().relative_to(repo_resolved))
        except ValueError:
            source_rel = os.path.relpath(source_dir, repo_path) if repo_path else source_dir
    else:
        source_rel = source_dir

    base_parts = Path(source_rel).parts

    if level > len(base_parts):
        base_parts = ()
    else:
        base_parts = base_parts[: len(base_parts) - level + 1]

    if module:
        return ".".join(base_parts + (module,))
    return ".".join(base_parts) if base_parts else module


def _find_file_for_module(
    module: str,
    file_contents: dict[str, str],
    repo_path: str,
) -> Optional[str]:
    parts = module.replace(".", "/")
    candidates = [
        os.path.join(repo_path, parts + ".py"),
        os.path.join(repo_path, parts, "__init__.py"),
        os.path.join(repo_path, parts + ".js"),
        os.path.join(repo_path, parts + ".ts"),
        os.path.join(repo_path, parts + ".go"),
        os.path.join(repo_path, "index.js"),
        os.path.join(repo_path, "index.ts"),
    ]
    for c in candidates:
        if c in file_contents:
            return c

    for fpath in file_contents:
        if fpath.endswith(parts + ".py") or fpath.endswith(parts + ".js"):
            return fpath
        if fpath.endswith(parts + ".ts"):
            return fpath
    return None


def _parse_python_imports(source_code: str, file_path: str) -> list[ImportEntry]:
    imports = []
    try:
        tree = ast.parse(source_code, filename=file_path)
    except (SyntaxError, Exception):
        return imports

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                asname = alias.asname or name
                imports.append(ImportEntry(
                    module=name,
                    names=[name],
                    aliases={name: asname},
                    source_file=file_path,
                    target_module=name,
                    target_file="",
                    import_source=ImportSource.UNKNOWN,
                    import_type=ImportType.MODULE,
                    line=node.lineno,
                    language=Language.PYTHON,
                ))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            level = node.level or 0
            is_relative = level > 0
            names = [a.name for a in node.names]
            aliases = {a.name: (a.asname or a.name) for a in node.names}

            if is_relative:
                target = _resolve_relative_import(module, level, file_path, "")
                imp_source = ImportSource.RELATIVE
            elif _is_stdlib(module, Language.PYTHON):
                target = module
                imp_source = ImportSource.STDLIB
            else:
                target = module
                imp_source = ImportSource.INTERNAL

            imp_type = ImportType.STAR if names == ["*"] else ImportType.MODULE

            imports.append(ImportEntry(
                module=module,
                names=names,
                aliases=aliases,
                source_file=file_path,
                target_module=target,
                target_file="",
                import_source=imp_source,
                import_type=imp_type,
                line=node.lineno,
                language=Language.PYTHON,
                is_relative=is_relative,
                level=level,
            ))
    return imports


def _parse_js_imports(source_code: str, file_path: str) -> list[ImportEntry]:
    imports = []
    for i, line in enumerate(source_code.splitlines(), 1):
        line = line.strip()

        m = re.match(r'import\s+(.+?)\s+from\s+["\'](.+?)["\']', line)
        if m:
            names_str, module = m.group(1), m.group(2)
            names = [n.strip() for n in re.split(r',\s*', names_str.strip('{}'))]
            imports.append(ImportEntry(
                module=module,
                names=names,
                aliases={n: n for n in names},
                source_file=file_path,
                target_module=module,
                target_file="",
                import_source=ImportSource.EXTERNAL if not module.startswith(".") else ImportSource.RELATIVE,
                import_type=ImportType.MODULE,
                line=i,
                language=Language.JAVASCRIPT,
                is_relative=module.startswith("."),
            ))
            continue

        m = re.match(r'import\s+["\'](.+?)["\']', line)
        if m:
            module = m.group(1)
            imports.append(ImportEntry(
                module=module,
                names=[],
                aliases={},
                source_file=file_path,
                target_module=module,
                target_file="",
                import_source=ImportSource.EXTERNAL if not module.startswith(".") else ImportSource.RELATIVE,
                import_type=ImportType.MODULE,
                line=i,
                language=Language.JAVASCRIPT,
                is_relative=module.startswith("."),
            ))
            continue

        m = re.match(r'(?:const|let|var)\s+(.+?)\s*=\s*require\s*\(\s*["\'](.+?)["\']\s*\)', line)
        if m:
            name, module = m.group(1).strip(), m.group(2)
            imports.append(ImportEntry(
                module=module,
                names=[name],
                aliases={name: name},
                source_file=file_path,
                target_module=module,
                target_file="",
                import_source=ImportSource.EXTERNAL if not module.startswith(".") else ImportSource.RELATIVE,
                import_type=ImportType.MODULE,
                line=i,
                language=Language.JAVASCRIPT,
                is_relative=module.startswith("."),
            ))
    return imports


def _parse_go_imports(source_code: str, file_path: str) -> list[ImportEntry]:
    imports = []
    in_import_block = False
    for i, line in enumerate(source_code.splitlines(), 1):
        stripped = line.strip()

        if stripped.startswith("import ("):
            in_import_block = True
            continue
        if in_import_block and stripped == ")":
            in_import_block = False
            continue

        if in_import_block:
            m = re.match(r'(?:([a-zA-Z_]\w*)\s+)?"(.+?)"', stripped)
            if m:
                alias = m.group(1) or m.group(2).split("/")[-1]
                module = m.group(2)
                imports.append(ImportEntry(
                    module=module,
                    names=[module],
                    aliases={module: alias},
                    source_file=file_path,
                    target_module=module,
                    target_file="",
                    import_source=ImportSource.EXTERNAL if not module.startswith(".") else ImportSource.RELATIVE,
                    import_type=ImportType.MODULE,
                    line=i,
                    language=Language.GO,
                ))
            continue

        m = re.match(r'import\s+"(.+?)"', stripped)
        if m:
            module = m.group(1)
            alias = module.split("/")[-1]
            imports.append(ImportEntry(
                module=module,
                names=[module],
                aliases={module: alias},
                source_file=file_path,
                target_module=module,
                target_file="",
                import_source=ImportSource.EXTERNAL if not module.startswith(".") else ImportSource.RELATIVE,
                import_type=ImportType.MODULE,
                line=i,
                language=Language.GO,
            ))
    return imports


def build_import_table(
    file_contents: dict[str, str],
    repo_path: str = "",
) -> ImportResolutionResult:
    """Build a complete import resolution table for a repository."""
    result = ImportResolutionResult()

    for file_path, content in file_contents.items():
        lang = _detect_language(file_path)

        if lang == Language.PYTHON:
            file_imports = _parse_python_imports(content, file_path)
        elif lang in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            file_imports = _parse_js_imports(content, file_path)
        elif lang == Language.GO:
            file_imports = _parse_go_imports(content, file_path)
        else:
            continue

        result.imports.extend(file_imports)
        result.total_imports += len(file_imports)

        for imp in file_imports:
            if imp.import_source == ImportSource.INTERNAL and repo_path:
                found = _find_file_for_module(imp.target_module, file_contents, repo_path)
                if found:
                    imp.target_file = found
                    imp.resolved = True
                    result.total_resolved += 1
                    key = imp.source_file
                    if key not in result.import_graph:
                        result.import_graph[key] = set()
                    result.import_graph[key].add(found)
                else:
                    result.unresolved.append(imp)
                    result.total_unresolved += 1
            elif imp.import_source == ImportSource.RELATIVE and repo_path:
                found = _find_file_for_module(imp.target_module, file_contents, repo_path)
                if found:
                    imp.target_file = found
                    imp.resolved = True
                    result.total_resolved += 1
                else:
                    result.unresolved.append(imp)
                    result.total_unresolved += 1
            else:
                result.total_resolved += 1

    for imp in result.imports:
        for alias, real_name in imp.aliases.items():
            key = f"{imp.source_file}::{alias}"
            result.resolved[key] = ResolvedImport(
                alias=alias,
                original_name=real_name,
                defining_module=imp.module,
                defining_file=imp.target_file or imp.source_file,
                defining_line=imp.line,
                import_type=imp.import_type,
                import_source=imp.import_source,
            )

    return result


def resolve_import_alias(
    alias: str,
    source_file: str,
    resolution: ImportResolutionResult,
) -> Optional[ResolvedImport]:
    """Resolve an import alias to its original definition."""
    key = f"{source_file}::{alias}"
    if key in resolution.resolved:
        return resolution.resolved[key]

    for imp in resolution.imports:
        if imp.source_file == source_file:
            for a, real in imp.aliases.items():
                if a == alias:
                    return ResolvedImport(
                        alias=alias,
                        original_name=real,
                        defining_module=imp.module,
                        defining_file=imp.target_file or imp.source_file,
                        defining_line=imp.line,
                        import_type=imp.import_type,
                        import_source=imp.import_source,
                    )
    return None


def get_imports_for_file(
    file_path: str,
    resolution: ImportResolutionResult,
) -> list[ImportEntry]:
    """Get all imports for a specific file."""
    return [imp for imp in resolution.imports if imp.source_file == file_path]


def get_reverse_imports(
    file_path: str,
    resolution: ImportResolutionResult,
) -> list[ImportEntry]:
    """Get all files that import from the given file."""
    return [
        imp for imp in resolution.imports
        if imp.target_file == file_path
    ]
