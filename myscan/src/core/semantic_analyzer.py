"""Semantic Analysis Engine.

Replaces name-based detection with semantic understanding.

Instead of detecting `eval()` by name, understand:
- Which module does `eval` belong to?
- Is it `builtins.eval` (dangerous) or `torch.nn.Module.eval` (safe)?
- What is the actual receiver object?
- What does the function actually do?

This is the core of Phase 1 — never detect vulnerabilities using keywords alone.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum


class SemanticSafety(Enum):
    DANGEROUS = "dangerous"
    SAFE = "safe"
    CONDITIONALLY_SAFE = "conditionally_safe"
    UNKNOWN = "unknown"


@dataclass
class SemanticCallInfo:
    """Semantic information about a function call."""
    name: str
    full_name: str
    owner_module: str
    owner_class: str
    receiver_type: str
    safety: SemanticSafety
    reason: str
    line: int = 0
    column: int = 0
    args: list[str] = field(default_factory=list)
    source_code: str = ""


@dataclass
class SemanticAssignmentInfo:
    """Semantic information about a variable assignment."""
    target: str
    value_type: str
    source_module: str
    is_constant: bool = False
    is_from_import: bool = False
    is_from_env: bool = False
    is_from_user_input: bool = False
    literal_value: str = ""
    line: int = 0


@dataclass
class SemanticModuleInfo:
    """Semantic information about an import."""
    module: str
    alias: str
    names: list[str]
    resolved_path: str = ""
    is_standard_library: bool = False
    is_third_party: bool = False
    line: int = 0


@dataclass
class SemanticAnalysisResult:
    """Complete semantic analysis result."""
    calls: list[SemanticCallInfo] = field(default_factory=list)
    assignments: list[SemanticAssignmentInfo] = field(default_factory=list)
    imports: list[SemanticModuleInfo] = field(default_factory=list)
    dangerous_calls: list[SemanticCallInfo] = field(default_factory=list)
    safe_calls: list[SemanticCallInfo] = field(default_factory=list)
    unknown_calls: list[SemanticCallInfo] = field(default_factory=list)


# ============================================================
# Known safe libraries with .eval() or similar methods
# ============================================================

SAFE_EVAL_RECEIVERS = {
    "torch", "torch.nn", "torch.nn.Module",
    "pandas", "pandas.DataFrame", "pandas.Series",
    "numpy", "numpy.ndarray",
    "scipy", "sklearn", "xgboost", "lightgbm",
    "dask", "polars",
}

SAFE_EVAL_METHODS = {
    "torch.nn.Module.eval",
    "pandas.eval",
    "numpy.ndarray.__array_ufunc__",
}

DANGEROUS_EXECUTION_FUNCTIONS = {
    "builtins.eval", "builtins.exec", "builtins.compile",
    "eval", "exec",
}

DANGEROUS_SYSTEM_CALLS = {
    "os.system", "os.popen",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_call", "subprocess.check_output",
}

DANGEROUS_SQL_CALLS = {
    "sqlite3.Connection.execute",
    "sqlite3.Cursor.execute",
    "django.db.connection.cursor",
    "psycopg2.cursor.execute",
    "mysql.connector.cursor.execute",
    "SQLAlchemy.execute",
}

DANGEROUS_SHELL_PATTERNS = {
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "os.system", "os.popen", "popen",
}

SAFE_SHELL_PATTERNS = {
    "subprocess.run", "subprocess.call",
}

SANITIZATION_PATTERNS = {
    "shlex.quote", "shlex.join",
    "html.escape", "html.HTMLParser",
    "urllib.parse.quote", "urllib.parse.quote_plus",
    "cgi.escape",
    "bleach.clean",
    "markupsafe.escape",
}

PARAMETERIZED_QUERY_PATTERNS = {
    "cursor.execute", "cursor.executemany",
}

# Module that provides builtins
BUILTIN_MODULES = {"builtins", "__builtins__", "io"}


def analyze_semantics(
    source_code: str,
    file_path: str = "",
    imports: list | None = None,
) -> SemanticAnalysisResult:
    """Perform semantic analysis on Python source code.

    Understands actual function ownership, module, class, and safety.
    """
    result = SemanticAnalysisResult()

    try:
        tree = ast.parse(source_code, filename=file_path)
    except (SyntaxError, Exception):
        return result

    resolved_imports = _resolve_imports(tree, imports)
    result.imports = resolved_imports

    import_map = _build_import_map(resolved_imports)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_info = _analyze_call_semantics(node, import_map, source_code)
            result.calls.append(call_info)
            if call_info.safety == SemanticSafety.DANGEROUS:
                result.dangerous_calls.append(call_info)
            elif call_info.safety == SemanticSafety.SAFE:
                result.safe_calls.append(call_info)
            else:
                result.unknown_calls.append(call_info)

        elif isinstance(node, ast.Assign):
            assign_info = _analyze_assignment_semantics(node, import_map)
            result.assignments.append(assign_info)

    return result


def _resolve_imports(
    tree: ast.Module,
    existing_imports: list | None = None,
) -> list[SemanticModuleInfo]:
    """Resolve all imports in the AST."""
    imports: list[SemanticModuleInfo] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(
                SemanticModuleInfo(
                    module=alias.name,
                    alias=alias.asname or alias.name,
                    names=[alias.name],
                    is_standard_library=_is_stdlib(alias.name),
                    line=node.lineno,
                )
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = [alias.name for alias in node.names]
            imports.append(SemanticModuleInfo(
                module=module,
                alias=module,
                names=names,
                is_standard_library=_is_stdlib(module),
                line=node.lineno,
            ))

    return imports


def _build_import_map(imports: list[SemanticModuleInfo]) -> dict[str, str]:
    """Build a mapping from local name to module for import resolution."""
    import_map = {}
    for imp in imports:
        if imp.alias:
            import_map[imp.alias] = imp.module
        for name in imp.names:
            if name != "*":
                import_map[name] = f"{imp.module}.{name}" if imp.module else name
    return import_map


def _analyze_call_semantics(
    node: ast.Call,
    import_map: dict[str, str],
    source_code: str,
) -> SemanticCallInfo:
    """Analyze the semantics of a function call.

    Determines the actual module, class, receiver, and safety level.
    """
    name = ""
    full_name = ""
    owner_module = ""
    owner_class = ""
    receiver_type = ""
    args = []

    for arg in node.args:
        if isinstance(arg, ast.Name):
            args.append(arg.id)
        elif isinstance(arg, ast.Constant):
            args.append(repr(arg.value)[:50])
        elif isinstance(arg, ast.JoinedStr):
            args.append("f-string")
        else:
            args.append(ast.dump(arg)[:30])

    if isinstance(node.func, ast.Name):
        name = node.func.id
        resolved = import_map.get(name, "")
        if resolved:
            parts = resolved.rsplit(".", 1)
            owner_module = parts[0] if len(parts) > 1 else ""
            full_name = resolved
        else:
            full_name = name

    elif isinstance(node.func, ast.Attribute):
        name = node.func.attr
        if isinstance(node.func.value, ast.Name):
            obj_name = node.func.value.id
            resolved_obj = import_map.get(obj_name, obj_name)
            parts = resolved_obj.rsplit(".", 1)
            owner_module = parts[0] if len(parts) > 1 else ""
            owner_class = obj_name
            receiver_type = resolved_obj
            full_name = f"{resolved_obj}.{name}"
        elif isinstance(node.func.value, ast.Attribute):
            chain = _get_attribute_chain(node.func.value)
            resolved_chain = import_map.get(chain.split(".")[0], chain)
            full_name = f"{resolved_chain}.{name}"
            owner_module = resolved_chain.rsplit(".", 1)[0] if "." in resolved_chain else ""
            receiver_type = resolved_chain
        else:
            full_name = name

    safety = _determine_safety(name, full_name, owner_module, owner_class, receiver_type, args)

    return SemanticCallInfo(
        name=name,
        full_name=full_name,
        owner_module=owner_module,
        owner_class=owner_class,
        receiver_type=receiver_type,
        safety=safety,
        reason=_safety_reason(name, full_name, owner_module, receiver_type, safety),
        line=node.lineno,
        column=node.col_offset,
        args=args,
    )


def _get_attribute_chain(node: ast.Attribute) -> str:
    """Get the full attribute chain like 'a.b.c'."""
    parts = [node.attr]
    current = node.value
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    parts.reverse()
    return ".".join(parts)


def _determine_safety(
    name: str,
    full_name: str,
    owner_module: str,
    owner_class: str,
    receiver_type: str,
    args: list[str],
) -> SemanticSafety:
    """Determine the safety level of a function call.

    This is the core semantic analysis - understanding what a function
    ACTUALLY does based on its module, class, and receiver.
    """
    bare_name = name.lower() if name else ""
    full_lower = full_name.lower()
    owner_lower = owner_module.lower()
    receiver_lower = receiver_type.lower()

    if bare_name in ("eval", "exec", "compile"):
        for safe_prefix in SAFE_EVAL_RECEIVERS:
            if receiver_lower.startswith(safe_prefix.lower()):
                return SemanticSafety.SAFE
            if full_lower.startswith(safe_prefix.lower()):
                return SemanticSafety.SAFE

        if any(full_lower.startswith(dm) for dm in DANGEROUS_EXECUTION_FUNCTIONS):
            return SemanticSafety.DANGEROUS

        if owner_lower in ("builtins", "__builtins__", "") and not receiver_type:
            return SemanticSafety.DANGEROUS

        if receiver_type:
            return SemanticSafety.CONDITIONALLY_SAFE

        return SemanticSafety.DANGEROUS

    if bare_name in ("system", "popen") and owner_lower in ("os", "posix"):
        return SemanticSafety.DANGEROUS

    if bare_name in ("call", "run", "popen", "check_call", "check_output") and (
        owner_lower == "subprocess" or receiver_lower == "subprocess"
    ):
        args_str = " ".join(args).lower()
        if "shell=true" in args_str:
            return SemanticSafety.DANGEROUS
        if "shell=false" in args_str or not any("shell" in a.lower() for a in args):
            return SemanticSafety.CONDITIONALLY_SAFE
        return SemanticSafety.CONDITIONALLY_SAFE

    if bare_name == "execute" and "cursor" in receiver_lower:
        args_str = " ".join(args).lower()
        if "%" in args_str or "format" in args_str or "f'" in args_str or 'f"' in args_str:
            return SemanticSafety.DANGEROUS
        if "?" in args_str or "param" in args_str:
            return SemanticSafety.SAFE
        return SemanticSafety.CONDITIONALLY_SAFE

    if bare_name in ("loads", "load") and "pickle" in full_lower:
        return SemanticSafety.DANGEROUS

    if bare_name in ("loads", "load") and "yaml" in full_lower:
        args_str = " ".join(args).lower()
        if "loader=yaml.safe_loader" in args_str or "safe_load" in full_lower:
            return SemanticSafety.SAFE
        return SemanticSafety.DANGEROUS

    if bare_name in ("render",) and "template" in full_lower:
        args_str = " ".join(args).lower()
        if "string" in full_lower:
            return SemanticSafety.DANGEROUS
        return SemanticSafety.CONDITIONALLY_SAFE

    if bare_name == "open":
        return SemanticSafety.CONDITIONALLY_SAFE

    return SemanticSafety.UNKNOWN


def _safety_reason(
    name: str,
    full_name: str,
    owner_module: str,
    receiver_type: str,
    safety: SemanticSafety,
) -> str:
    """Generate a human-readable reason for the safety classification."""
    if safety == SemanticSafety.DANGEROUS:
        if name in ("eval", "exec"):
            if not receiver_type:
                return f"{full_name} is the dangerous builtin - can execute arbitrary code"
            return f"{full_name} is a dangerous execution function"
        if "system" in name or "popen" in name:
            return f"{full_name} can execute arbitrary shell commands"
        if "pickle" in full_name and "load" in name:
            return f"{full_name} can deserialize arbitrary objects - potential RCE"
        if "yaml" in full_name and name == "loads":
            return f"{full_name} without SafeLoader can execute arbitrary Python code"
        if "render" in name and "string" in full_name:
            return f"{full_name} can execute embedded code - potential SSTI"
        return f"{full_name} is classified as dangerous"

    if safety == SemanticSafety.SAFE:
        if receiver_type:
            return f"{full_name} belongs to safe library ({receiver_type})"
        return f"{full_name} is a safe variant"

    if safety == SemanticSafety.CONDITIONALLY_SAFE:
        return f"{full_name} is safe only with proper input validation and sanitization"

    return f"{full_name} safety cannot be determined without more context"


def _analyze_assignment_semantics(
    node: ast.Assign,
    import_map: dict[str, str],
) -> SemanticAssignmentInfo:
    """Analyze the semantics of a variable assignment."""
    target = ""
    if isinstance(node.targets[0], ast.Name):
        target = node.targets[0].id

    value_type = type(node.value).__name__
    source_module = ""
    is_constant = False
    is_from_import = False
    is_from_env = False
    is_from_user_input = False
    literal_value = ""

    if isinstance(node.value, ast.Constant):
        is_constant = True
        literal_value = repr(node.value.value)[:100]
        value_type = "constant"

    elif isinstance(node.value, ast.Name):
        resolved = import_map.get(node.value.id, "")
        if resolved:
            source_module = resolved
            is_from_import = True
        value_type = "variable"

    elif isinstance(node.value, ast.Call):
        if isinstance(node.value.func, ast.Name):
            call_name = node.value.func.id
            resolved_call = import_map.get(call_name, call_name)
            source_module = resolved_call.rsplit(".", 1)[0] if "." in resolved_call else ""
            if call_name in ("getenv", "environ") or "environ" in resolved_call.lower():
                is_from_env = True
                value_type = "environment_variable"
            elif call_name == "input" or "input" in resolved_call.lower():
                is_from_user_input = True
                value_type = "user_input"
        elif isinstance(node.value.func, ast.Attribute):
            attr_chain = _get_attribute_chain(node.value.func)
            resolved_chain = import_map.get(attr_chain.split(".")[0], attr_chain)
            if "environ" in resolved_chain.lower() or "getenv" in resolved_chain.lower():
                is_from_env = True
                value_type = "environment_variable"

    elif isinstance(node.value, ast.JoinedStr):
        value_type = "fstring"

    elif isinstance(node.value, (ast.List, ast.Dict, ast.Set, ast.Tuple)):
        value_type = f"collection_{type(node.value).__name__.lower()}"

    return SemanticAssignmentInfo(
        target=target,
        value_type=value_type,
        source_module=source_module,
        is_constant=is_constant,
        is_from_import=is_from_import,
        is_from_env=is_from_env,
        is_from_user_input=is_from_user_input,
        literal_value=literal_value,
        line=node.lineno,
    )


def _is_stdlib(module: str) -> bool:
    """Check if a module is part of the Python standard library."""
    if not module:
        return False
    top_level = module.split(".")[0]
    STDLIB_MODULES = {
        "os", "sys", "io", "re", "json", "math", "random", "datetime",
        "time", "logging", "collections", "itertools", "functools",
        "pathlib", "shutil", "subprocess", "threading", "multiprocessing",
        "socket", "http", "urllib", "email", "html", "xml", "csv",
        "sqlite3", "hashlib", "hmac", "secrets", "base64", "binascii",
        "struct", "codecs", "unicodedata", "string", "textwrap",
        "difflib", "enum", "dataclasses", "typing", "abc", "copy",
        "pprint", "ast", "inspect", "dis", "pickle", "shelve",
        "dbm", "ctypes", "mmap", "signal", "queue",
        "sched", "select", "selectors", "asyncio", "concurrent",
        "unittest", "test", "doctest", "pdb", "profile", "timeit",
        "traceback", "warnings", "contextlib", "decimal", "fractions",
        "numbers", "cmath", "array", "weakref", "types", "operator",
        "graphlib", "uuid", "getpass", "glob", "fnmatch", "tempfile",
        "gzip", "bz2", "lzma", "zipfile", "tarfile", "configparser",
        "argparse", "optparse", "getopt", "cmd", "shlex",
    }
    return top_level in STDLIB_MODULES
