"""Reachability Analysis Engine.

Determines if code is:
- Reachable (called from entry points)
- Dead code (never called)
- Unused (defined but never referenced)
- Test-only (only called from tests)
- Deprecated (has deprecated markers)

Critical findings in unreachable code should not be reported as CRITICAL.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum


class ReachabilityStatus(Enum):
    REACHABLE = "reachable"
    DEAD_CODE = "dead_code"
    UNUSED = "unused"
    TEST_ONLY = "test_only"
    DEPRECATED = "deprecated"
    CONDITIONALLY_REACHABLE = "conditional"
    UNKNOWN = "unknown"


@dataclass
class FunctionReachability:
    """Reachability info for a single function."""
    name: str
    file_path: str
    line: int
    status: ReachabilityStatus
    called_by: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    is_entry_point: bool = False
    depth: int = 0
    reason: str = ""


@dataclass
class ReachabilityResult:
    """Complete reachability analysis result."""
    functions: dict[str, FunctionReachability] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)
    total_reachable: int = 0
    total_dead: int = 0
    total_unused: int = 0
    total_test_only: int = 0


ENTRY_POINT_PATTERNS = {
    "main", "__main__", "app.run", "cli", "setup", "configure",
    "__init__", "__new__", "__init_subclass__",
}

ENTRY_POINT_DECORATORS = {
    "app.route", "app.before_request", "app.after_request",
    "click.command", "click.group",
    "celery.task", "celery.shared_task",
    "pytest.fixture", "unittest.TestCase",
}


def analyze_reachability(
    file_contents: dict[str, str],
    include_tests: bool = False,
) -> ReachabilityResult:
    """Analyze reachability across the entire repository."""
    result = ReachabilityResult()

    call_graph: dict[str, set[str]] = {}
    definitions: dict[str, tuple[str, int]] = {}

    for file_path, content in file_contents.items():
        try:
            tree = ast.parse(content, filename=file_path)
        except (SyntaxError, Exception):
            continue

        _analyze_file_reachability(
            tree, file_path, content, call_graph, definitions, result
        )

    _compute_reachability(call_graph, definitions, result, include_tests)

    return result


def _analyze_file_reachability(
    tree: ast.Module,
    file_path: str,
    content: str,
    call_graph: dict[str, set[str]],
    definitions: dict[str, tuple[str, int]],
    result: ReachabilityResult,
):
    """Analyze reachability for a single file."""
    current_class = ""

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef):
            current_class = node.name
            func_id = f"{file_path}::{node.name}"
            definitions[func_id] = (file_path, node.lineno)

            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_id = f"{file_path}::{current_class}.{child.name}"
                    definitions[method_id] = (file_path, child.lineno)

                    decorators = [_get_decorator_name(d) for d in child.decorator_list]
                    for dec in decorators:
                        if any(pat in dec for pat in ENTRY_POINT_DECORATORS):
                            result.entry_points.append(method_id)

            current_class = ""

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_id = f"{file_path}::{node.name}"
            definitions[func_id] = (file_path, node.lineno)

            decorators = [_get_decorator_name(d) for d in node.decorator_list]
            for dec in decorators:
                if any(pat in dec for pat in ENTRY_POINT_DECORATORS):
                    result.entry_points.append(func_id)

            if node.name == "main":
                result.entry_points.append(func_id)

            current_func_calls = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    called_name = _get_call_id(child, file_path)
                    if called_name:
                        current_func_calls.add(called_name)

            if func_id not in call_graph:
                call_graph[func_id] = set()
            call_graph[func_id].update(current_func_calls)

        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call_id = _get_call_id(node.value, file_path)
            if call_id:
                module_level = f"{file_path}::__module__"
                if module_level not in call_graph:
                    call_graph[module_level] = set()
                call_graph[module_level].add(call_id)


def _get_call_id(node: ast.Call, file_path: str) -> str:
    """Extract a call identifier from a Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        return node.func.attr
    return ""


def _get_decorator_name(node) -> str:
    """Get decorator name as string."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        return node.attr
    elif isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return "unknown"


def _compute_reachability(
    call_graph: dict[str, set[str]],
    definitions: dict[str, tuple[str, int]],
    result: ReachabilityResult,
    include_tests: bool,
):
    """Compute reachability from call graph and definitions."""
    called_set: set[str] = set()
    for callers in call_graph.values():
        called_set.update(callers)

    entry_set = set(result.entry_points)

    reachable = set()
    queue = list(entry_set)
    visited = set()

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        reachable.add(current)

        queue.extend(
            callee
            for callee in call_graph.get(current, set())
            if callee not in visited
        )

    for func_id, (file_path, line) in definitions.items():
        is_called = func_id in called_set
        is_reachable = func_id in reachable
        is_test = "test" in file_path.lower()

        if is_reachable or is_called:
            status = ReachabilityStatus.REACHABLE
        elif is_test and not include_tests:
            status = ReachabilityStatus.TEST_ONLY
        elif is_called and not is_reachable:
            status = ReachabilityStatus.CONDITIONALLY_REACHABLE
        elif not is_called and func_id not in entry_set:
            status = ReachabilityStatus.DEAD_CODE
        else:
            status = ReachabilityStatus.UNKNOWN

        func_name = func_id.split("::")[-1] if "::" in func_id else func_id
        fr = FunctionReachability(
            name=func_name,
            file_path=file_path,
            line=line,
            status=status,
            called_by=[c for c in call_graph if func_id in call_graph.get(c, set())],
            calls=list(call_graph.get(func_id, set())),
            is_entry_point=func_id in entry_set,
        )

        result.functions[func_id] = fr

        if status == ReachabilityStatus.REACHABLE:
            result.total_reachable += 1
        elif status == ReachabilityStatus.DEAD_CODE:
            result.total_dead += 1
        elif status == ReachabilityStatus.UNUSED:
            result.total_unused += 1
        elif status == ReachabilityStatus.TEST_ONLY:
            result.total_test_only += 1


def get_function_reachability(
    result: ReachabilityResult,
    function_name: str,
    file_path: str = "",
) -> FunctionReachability:
    """Get reachability for a specific function."""
    for func_id, fr in result.functions.items():
        if function_name in func_id and (not file_path or fr.file_path == file_path):
            return fr
    return FunctionReachability(
        name=function_name,
        file_path=file_path,
        line=0,
        status=ReachabilityStatus.UNKNOWN,
        reason="Function not found in reachability analysis",
    )
