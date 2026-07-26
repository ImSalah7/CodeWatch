"""AST-based code analysis for Python using the built-in ast module.

This replaces regex-based detection with proper syntax tree analysis.
Understands function calls, variable assignments, imports, scopes, and control flow.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ASTNode:
    """Simplified AST node representation."""
    node_type: str
    name: str = ""
    line: int = 0
    end_line: int = 0
    column: int = 0
    value: str = ""
    children: list["ASTNode"] = field(default_factory=list)
    parent: Optional["ASTNode"] = None
    scope: str = ""
    is_user_controlled: bool = False
    is_constant: bool = False
    is_imported: bool = False
    source_node: str = ""
    targets: list[str] = field(default_factory=list)
    args: list[str] = field(default_factory=list)
    keywords: dict[str, str] = field(default_factory=dict)


@dataclass
class FunctionDef:
    """Function definition with full context."""
    name: str
    line: int
    end_line: int
    args: list[str]
    body_lines: range = field(default_factory=lambda: range(0, 0))
    calls: list[ASTNode] = field(default_factory=list)
    assignments: list[ASTNode] = field(default_factory=list)
    returns: list[ASTNode] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    docstring: str = ""
    is_async: bool = False
    scope: str = ""


@dataclass
class ImportInfo:
    """Import statement information."""
    module: str
    names: list[str]
    alias: str = ""
    line: int = 0
    is_from_import: bool = False


@dataclass
class AssignmentInfo:
    """Variable assignment information."""
    target: str
    value: str
    value_type: str
    line: int = 0
    is_tainted: bool = False
    source: str = ""


@dataclass
class CallInfo:
    """Function call information."""
    name: str
    line: int
    args: list[str] = field(default_factory=list)
    keywords: dict[str, str] = field(default_factory=dict)
    is_method: bool = False
    object_name: str = ""
    full_name: str = ""


@dataclass
class PythonASTResult:
    """Complete AST analysis result for a Python file."""
    functions: list[FunctionDef] = field(default_factory=list)
    classes: list[FunctionDef] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    assignments: list[AssignmentInfo] = field(default_factory=list)
    calls: list[CallInfo] = field(default_factory=list)
    global_vars: list[AssignmentInfo] = field(default_factory=list)
    tainted_sources: list[str] = field(default_factory=list)
    dangerous_sinks: list[CallInfo] = field(default_factory=list)
    raw_nodes: list[ASTNode] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)


SOURCES = {
    "request", "request.args", "request.form", "request.json",
    "request.data", "request.values", "request.files", "request.cookies",
    "request.headers", "request.params", "request.query_string",
    "input", "sys.stdin", "os.environ",
    "getenv", "environ",
    "argv", "sys.argv",
    "flask.request", "django.request",
}

SINKS = {
    "execute", "executemany", "executescript",
    "os.system", "os.popen",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "eval", "exec", "compile",
    "open", "shutil.copy",
    "pickle.loads", "pickle.load",
    "yaml.load",
    "render_template_string", "Markup",
    "innerHTML", "dangerouslySetInnerHTML",
    "redirect", "send_file",
}


def analyze_python_ast(content: str, file_path: str = "") -> PythonASTResult:
    """Analyze Python source code using the built-in ast module."""
    result = PythonASTResult()

    try:
        tree = ast.parse(content, filename=file_path, type_comments=True)
    except SyntaxError as e:
        result.parse_errors.append(f"Syntax error at line {e.lineno}: {e.msg}")
        return result
    except Exception as e:
        result.parse_errors.append(f"Parse error: {str(e)}")
        return result

    _visit_module(tree, result, content)
    _identify_taint_sources(result, content)
    _identify_sinks(result)

    return result


def _visit_module(node: ast.Module, result: PythonASTResult, content: str):
    """Walk the AST and extract all relevant information."""
    lines = content.splitlines()

    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Import):
            _visit_import(child, result)
        elif isinstance(child, ast.ImportFrom):
            _visit_import_from(child, result)
        elif isinstance(child, ast.FunctionDef):
            result.functions.append(_visit_function(child, lines))
        elif isinstance(child, ast.AsyncFunctionDef):
            func = _visit_function(child, lines)
            func.is_async = True
            result.functions.append(func)
        elif isinstance(child, ast.ClassDef):
            cls = _visit_class(child, lines)
            result.classes.append(cls)
        elif isinstance(child, ast.Assign):
            _visit_assignment(child, result, lines)
        elif isinstance(child, ast.AnnAssign):
            _visit_ann_assignment(child, result, lines)
        elif isinstance(child, ast.Expr):
            if isinstance(child.value, ast.Call):
                result.calls.append(_visit_call(child.value, lines))


def _visit_import(node: ast.Import, result: PythonASTResult):
    """Extract import information."""
    for alias in node.names:
        result.imports.append(ImportInfo(
            module=alias.name,
            names=[alias.name],
            alias=alias.asname or "",
            line=node.lineno,
            is_from_import=False,
        ))


def _visit_import_from(node: ast.ImportFrom, result: PythonASTResult):
    """Extract from...import information."""
    module = node.module or ""
    for alias in node.names:
        result.imports.append(ImportInfo(
            module=module,
            names=[alias.name],
            alias=alias.asname or "",
            line=node.lineno,
            is_from_import=True,
        ))


def _visit_function(node, lines: list[str], scope: str = "") -> FunctionDef:
    """Extract function definition with full context."""
    func = FunctionDef(
        name=node.name,
        line=node.lineno,
        end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
        args=[arg.arg for arg in node.args.args],
        decorators=[_get_decorator_name(d) for d in node.decorator_list],
        is_async=isinstance(node, ast.AsyncFunctionDef),
        scope=scope,
    )

    if (node.body and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)):
        func.docstring = node.body[0].value.value

    func.body_lines = range(func.line, func.end_line + 1)

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func.calls.append(_visit_call(child, lines))
        elif isinstance(child, ast.Assign):
            _visit_assignment(child, None, lines)
            for target in child.targets:
                if isinstance(target, ast.Name):
                    func.assignments.append(AssignmentInfo(
                        target=target.id,
                        value=ast.dump(child.value)[:100],
                        value_type=type(child.value).__name__,
                        line=child.lineno,
                    ))
        elif isinstance(child, (ast.Return,)):
            func.returns.append(ASTNode(
                node_type="return", line=child.lineno,
            ))

    return func


def _visit_class(node: ast.ClassDef, lines: list[str]) -> FunctionDef:
    """Extract class definition."""
    cls = FunctionDef(
        name=node.name,
        line=node.lineno,
        end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
        args=[],
        decorators=[_get_decorator_name(d) for d in node.decorator_list],
    )

    for child in node.body:
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cls.calls.append(ASTNode(
                node_type="method",
                name=child.name,
                line=child.lineno,
            ))

    return cls


def _visit_assignment(node: ast.Assign, result: Optional[PythonASTResult], lines: list[str]):
    """Extract variable assignment."""
    for target in node.targets:
        if isinstance(target, ast.Name):
            value = ast.dump(node.value)[:100]
            assign = AssignmentInfo(
                target=target.id,
                value=value,
                value_type=type(node.value).__name__,
                line=node.lineno,
            )
            if result:
                result.assignments.append(assign)


def _visit_ann_assignment(node: ast.AnnAssign, result: Optional[PythonASTResult], lines: list[str]):
    """Extract annotated assignment (e.g., x: int = 5)."""
    if isinstance(node.target, ast.Name) and node.value:
        value = ast.dump(node.value)[:100]
        assign = AssignmentInfo(
            target=node.target.id,
            value=value,
            value_type=type(node.value).__name__,
            line=node.lineno,
        )
        if result:
            result.assignments.append(assign)


def _visit_call(node: ast.Call, lines: list[str]) -> CallInfo:
    """Extract function call information."""
    func_name = _get_call_name(node)
    obj_name = ""
    is_method = False

    if isinstance(node.func, ast.Attribute):
        is_method = True
        if isinstance(node.func.value, ast.Name):
            obj_name = node.func.value.id
        elif isinstance(node.func.value, ast.Attribute):
            obj_name = ast.dump(node.func.value)[:50]

    args = []
    for arg in node.args:
        if isinstance(arg, ast.Name):
            args.append(arg.id)
        elif isinstance(arg, ast.Constant):
            args.append(repr(arg.value)[:50])
        elif isinstance(arg, ast.JoinedStr):
            args.append(f"f-string")
        else:
            args.append(ast.dump(arg)[:30])

    keywords = {}
    for kw in node.keywords:
        if isinstance(kw.value, ast.Name):
            keywords[kw.arg or ""] = kw.value.id
        elif isinstance(kw.value, ast.Constant):
            keywords[kw.arg or ""] = repr(kw.value.value)[:50]
        elif isinstance(kw.value, ast.NameConstant):
            keywords[kw.arg or ""] = str(kw.value.value)
        elif isinstance(kw.value, ast.Attribute):
            keywords[kw.arg or ""] = ast.dump(kw.value)[:50]

    full_name = ""
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            full_name = f"{node.func.value.id}.{node.func.attr}"
        else:
            full_name = node.func.attr
    elif isinstance(node.func, ast.Name):
        full_name = node.func.id

    return CallInfo(
        name=func_name,
        line=node.lineno,
        args=args,
        keywords=keywords,
        is_method=is_method,
        object_name=obj_name,
        full_name=full_name,
    )


def _get_call_name(node: ast.Call) -> str:
    """Get the name of a function call."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr
    elif isinstance(node.func, ast.Subscript):
        return "subscript_call"
    return "unknown"


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


def _identify_taint_sources(result: PythonASTResult, content: str):
    """Identify variables that come from untrusted sources."""
    for call in result.calls:
        if call.full_name in SOURCES or call.name in SOURCES:
            result.tainted_sources.append(call.full_name or call.name)

    for assign in result.assignments:
        for source in SOURCES:
            if source in assign.value:
                assign.is_tainted = True
                assign.source = source


def _identify_sinks(result: PythonASTResult):
    """Identify dangerous function calls (sinks)."""
    for call in result.calls:
        if call.full_name in SINKS or call.name in SINKS:
            result.dangerous_sinks.append(call)
