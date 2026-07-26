"""Data Flow Analysis and Taint Tracking engine.

Tracks data from sources (user input) through transformations to sinks (dangerous functions).
Only reports vulnerabilities when tainted data actually reaches a dangerous sink.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from .ast_analyzer import (
    PythonASTResult, CallInfo, AssignmentInfo, SOURCES, SINKS
)


@dataclass
class TaintVariable:
    """A variable that may carry untrusted data."""
    name: str
    line: int
    source: str
    confidence: float = 1.0
    transformations: list[str] = field(default_factory=list)
    is_sanitized: bool = False
    sanitizer: str = ""


@dataclass
class TaintPath:
    """A path from a taint source to a sink."""
    source_name: str
    source_line: int
    source_type: str
    sink_name: str
    sink_line: int
    sink_type: str
    variable_chain: list[str] = field(default_factory=list)
    intermediate_assignments: list[int] = field(default_factory=list)
    is_sanitized: bool = False
    sanitizer: str = ""
    confidence: float = 0.0
    reachability: str = "direct"


@dataclass
class DataFlowResult:
    """Result of data flow analysis."""
    taint_paths: list[TaintPath] = field(default_factory=list)
    taint_variables: list[TaintVariable] = field(default_factory=list)
    source_to_sink_mappings: dict[str, list[str]] = field(default_factory=dict)
    sanitization_points: list[tuple[str, int]] = field(default_factory=list)
    total_sources: int = 0
    total_sinks: int = 0
    tainted_flows: int = 0
    sanitized_flows: int = 0


SANITIZERS = {
    "int", "float", "str", "bool",
    "html.escape", "escape",
    "shlex.quote", "quote",
    "re.escape",
    " bleach.clean", "clean",
    "markupsafe.escape",
    "urllib.parse.quote", "urlencode",
    "json.dumps", "json.loads",
    "ast.literal_eval",
    "parameterized", "format",
    "PreparedStatement", "cursor.execute",
    "os.path.join", "os.path.realpath",
    "Path", "pathlib.Path",
    "BaseHTTPRequestHandler", "validate",
    "sanitize", "clean", "filter",
}


def analyze_data_flow(ast_result: PythonASTResult, content: str) -> DataFlowResult:
    """Perform data flow analysis on a Python AST result."""
    result = DataFlowResult()
    lines = content.splitlines()

    taint_map: dict[str, TaintVariable] = {}

    result.total_sources = len(ast_result.tainted_sources)
    result.total_sinks = len(ast_result.dangerous_sinks)

    _propagate_taint(ast_result, taint_map, result, lines)

    _track_assignments(ast_result, taint_map, lines)

    _find_taint_flows(ast_result, taint_map, result, lines)

    result.taint_variables = list(taint_map.values())
    result.tainted_flows = len(result.taint_paths)

    for path in result.taint_paths:
        if path.is_sanitized:
            result.sanitized_flows += 1

    return result


def _propagate_taint(
    ast_result: PythonASTResult,
    taint_map: dict[str, TaintVariable],
    result: DataFlowResult,
    lines: list[str],
):
    """Propagate taint through assignments and function calls."""
    for call in ast_result.calls:
        if call.full_name in SOURCES or call.name in SOURCES:
            taint_var = TaintVariable(
                name=call.full_name or call.name,
                line=call.line,
                source=call.full_name or call.name,
            )
            taint_map[f"__source_{call.line}"] = taint_var

    for call in ast_result.calls:
        if call.full_name in SOURCES or call.name in SOURCES:
            for arg in call.args:
                if arg in taint_map or any(tv.name == arg for tv in taint_map.values()):
                    continue
                taint_var = TaintVariable(
                    name=arg,
                    line=call.line,
                    source=call.full_name or call.name,
                )
                taint_map[arg] = taint_var


def _track_assignments(
    ast_result: PythonASTResult,
    taint_map: dict[str, TaintVariable],
    lines: list[str],
):
    """Track taint through variable assignments."""
    for assign in ast_result.assignments:
        if assign.is_tainted:
            taint_var = TaintVariable(
                name=assign.target,
                line=assign.line,
                source=assign.source,
            )
            taint_map[assign.target] = taint_var
            continue

        for source_name in ast_result.tainted_sources:
            if source_name in assign.value:
                taint_var = TaintVariable(
                    name=assign.target,
                    line=assign.line,
                    source=source_name,
                )
                taint_map[assign.target] = taint_var
                break

        if assign.target in taint_map:
            src = taint_map[assign.target]
            for arg in assign.value.split():
                clean = arg.strip("(),'\"")
                if clean in taint_map:
                    taint_map[assign.target] = TaintVariable(
                        name=assign.target,
                        line=assign.line,
                        source=taint_map[clean].source,
                        transformations=src.transformations + [assign.value[:50]],
                    )
                    break


def _find_taint_flows(
    ast_result: PythonASTResult,
    taint_map: dict[str, TaintVariable],
    result: DataFlowResult,
    lines: list[str],
):
    """Find flows from taint sources to dangerous sinks."""
    for call in ast_result.dangerous_sinks:
        sink_args = set(call.args)

        for arg in call.args:
            clean_arg = arg.strip("(),'\"")
            if clean_arg in taint_map:
                tvar = taint_map[clean_arg]
                is_sanitized, sanitizer = _check_sanitization(clean_arg, call, lines)

                source_line = tvar.line
                source_type = tvar.source

                reachability = _determine_reachability(
                    source_line, call.line, lines
                )

                path = TaintPath(
                    source_name=tvar.name,
                    source_line=source_line,
                    source_type=source_type,
                    sink_name=call.full_name or call.name,
                    sink_line=call.line,
                    sink_type=call.full_name or call.name,
                    variable_chain=[tvar.name, call.full_name or call.name],
                    intermediate_assignments=tvar.transformations,
                    is_sanitized=is_sanitized,
                    sanitizer=sanitizer,
                    confidence=_calculate_flow_confidence(
                        tvar, call, is_sanitized, reachability
                    ),
                    reachability=reachability,
                )
                result.taint_paths.append(path)

        if not sink_args:
            if call.full_name in SOURCES or call.name in SOURCES:
                continue
            for tvar in taint_map.values():
                if tvar.source in (call.full_name or call.name):
                    continue

    _check_keyword_taint(ast_result, taint_map, result, lines)


def _check_keyword_taint(
    ast_result: PythonASTResult,
    taint_map: dict[str, TaintVariable],
    result: DataFlowResult,
    lines: list[str],
):
    """Check taint in keyword arguments (e.g., shell=True)."""
    for call in ast_result.dangerous_sinks:
        for kw_name, kw_value in call.keywords.items():
            if kw_name in ("shell", "cmd", "command", "query", "sql", "template"):
                clean_val = kw_value.strip("(),'\"")
                if clean_val in taint_map:
                    tvar = taint_map[clean_val]
                    is_sanitized, sanitizer = _check_sanitization(
                        clean_val, call, lines
                    )
                    path = TaintPath(
                        source_name=tvar.name,
                        source_line=tvar.line,
                        source_type=tvar.source,
                        sink_name=call.full_name or call.name,
                        sink_line=call.line,
                        sink_type=call.full_name or call.name,
                        variable_chain=[tvar.name, f"{call.full_name}.{kw_name}"],
                        is_sanitized=is_sanitized,
                        sanitizer=sanitizer,
                        confidence=_calculate_flow_confidence(
                            tvar, call, is_sanitized, "direct"
                        ),
                        reachability="direct",
                    )
                    result.taint_paths.append(path)


def _check_sanitization(
    sink_arg: str, call: CallInfo, lines: list[str]
) -> tuple[bool, str]:
    """Check if taint is sanitized before reaching the sink."""
    line_idx = call.line - 1
    start = max(0, line_idx - 10)

    for i in range(start, line_idx + 1):
        if i >= len(lines):
            break
        line = lines[i]
        for sanitizer in SANITIZERS:
            if sanitizer in line and sink_arg in line:
                return True, sanitizer

    for kw_value in call.keywords.values():
        clean = kw_value.strip("(),'\"")
        if clean in SANITIZERS:
            return True, clean

    return False, ""


def _determine_reachability(source_line: int, sink_line: int, lines: list[str]) -> str:
    """Determine if a taint path is actually reachable."""
    if sink_line <= source_line:
        return "unreachable"

    block_depths = {}
    current_depth = 0

    for i in range(source_line, min(sink_line, len(lines))):
        line = lines[i].lstrip()
        if line.startswith(("if ", "for ", "while ", "with ", "try:", "except", "elif ", "else:", "def ", "class ")):
            current_depth += 1
            block_depths[i] = current_depth

    in_different_branch = False
    for i in range(source_line, min(sink_line, len(lines))):
        line = lines[i].lstrip()
        if line.startswith(("if ", "elif ", "else:", "except")):
            in_different_branch = True

    if in_different_branch and current_depth > 2:
        return "conditional"

    if current_depth == 0:
        return "direct"

    return "likely"


def _calculate_flow_confidence(
    tvar: TaintVariable, call: CallInfo,
    is_sanitized: bool, reachability: str
) -> float:
    """Calculate confidence for a taint flow."""
    confidence = 0.9

    if is_sanitized:
        confidence *= 0.1

    if reachability == "unreachable":
        confidence = 0.0
    elif reachability == "conditional":
        confidence *= 0.6
    elif reachability == "likely":
        confidence *= 0.8

    if "test" in (tvar.source or "").lower():
        confidence *= 0.3

    if tvar.source in ("os.environ", "environ", "getenv"):
        confidence *= 0.7

    if call.name in ("eval", "exec"):
        confidence *= 1.0

    return min(max(confidence, 0.0), 1.0)
