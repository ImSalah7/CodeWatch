"""Context-aware analysis engine.

Determines the actual risk of findings based on context:
- Is eval() called with a constant or user input?
- Is a password variable actually a hardcoded secret or a variable name reference?
- Is the code in a test file, example, or production code?
- Is the finding reachable from external input?

This is what separates enterprise-grade SAST from regex-based scanners.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from .ast_analyzer import (
    PythonASTResult, CallInfo, AssignmentInfo, FunctionDef, SOURCES, SINKS
)


class ContextType(Enum):
    CONSTANT = "constant"
    USER_CONTROLLED = "user_controlled"
    INTERNAL = "internal"
    CONFIGURATION = "configuration"
    TEST = "test"
    EXAMPLE = "example"
    DOCUMENTATION = "documentation"
    GENERATED = "generated"
    VENDOR = "vendor"


class SanitizationLevel(Enum):
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"
    UNKNOWN = "unknown"


class Reachability(Enum):
    DIRECT = "direct"
    THROUGH_VARIABLE = "through_variable"
    CONDITIONAL = "conditional"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


@dataclass
class ContextAnalysis:
    """Detailed context analysis for a finding."""
    context_type: ContextType = ContextType.INTERNAL
    reachability: Reachability = Reachability.UNKNOWN
    sanitization: SanitizationLevel = SanitizationLevel.UNKNOWN
    confidence_multiplier: float = 1.0
    risk_adjustment: float = 0.0
    explanation: str = ""
    evidence: list[str] = field(default_factory=list)
    is_user_controlled: bool = False
    is_constant: bool = False
    is_imported_value: bool = False
    is_return_value: bool = False
    is_in_test: bool = False
    is_in_example: bool = False
    is_in_generated: bool = False
    is_in_vendor: bool = False
    source_of_input: str = ""
    sanitizer: str = ""
    line_context: str = ""
    function_context: str = ""
    class_context: str = ""
    file_context: str = ""


@dataclass
class EvalContext:
    """Specific context for eval/exec analysis."""
    argument: str
    is_constant: bool = False
    is_user_controlled: bool = False
    is_from_config: bool = False
    is_imported: bool = False
    constant_value: str = ""
    risk_level: str = "info"
    explanation: str = ""


@dataclass
class PasswordContext:
    """Specific context for password/secret analysis."""
    variable_name: str
    value: str
    is_hardcoded: bool = False
    is_from_env: bool = False
    is_from_vault: bool = False
    is_placeholder: bool = False
    is_in_config: bool = False
    is_in_example: bool = False
    is_in_test: bool = False
    is_in_comment: bool = False
    risk_level: str = "info"
    explanation: str = ""


@dataclass
class InjectionContext:
    """Specific context for injection analysis (SQL, command, etc.)."""
    sink_function: str
    arguments: list[str]
    is_parameterized: bool = False
    is_user_controlled: bool = False
    source_variable: str = ""
    source_type: str = ""
    has_validation: bool = False
    has_sanitization: bool = False
    sanitizer: str = ""
    risk_level: str = "info"
    explanation: str = ""


FALSE_POSITIVE_INDICATORS = {
    "example", "sample", "test", "mock", "fake", "placeholder",
    "demo", "tutorial", "documentation", "docs", "README",
    "tmp", "temp", "debug", "prototype", "scratch",
}

PLACEHOLDER_VALUES = {
    "xxx", "changeme", "password123", "admin123", "test123",
    "example", "your_key_here", "replace_me", "set_me",
    "todo", "fixme", "placeholder", "dummy", "fake",
    "akiaxxxxxxxxxxxx", "xxxxxxxxxxxxxxxx",
    "0000000000000000000000000000000000000000",
}

SAFE_VARIABLE_NAMES = {
    "password_hash", "hashed_password", "password_column",
    "password_field", "password_label", "password_name",
    "password_error", "password_placeholder", "password_strength",
    "password_regex", "password_pattern", "password_policy",
    "password_min_length", "password_max_length",
    "hashed_pwd", "encrypted_password", "stored_password",
    "db_password", "database_password",
    "password_verification", "verify_password", "check_password",
}


def analyze_eval_context(
    call: CallInfo,
    ast_result: PythonASTResult,
    content: str,
    lines: list[str],
) -> EvalContext:
    """Analyze the context of an eval()/exec() call to determine actual risk."""
    ctx = EvalContext(
        argument=call.args[0] if call.args else "",
    )

    if not call.args:
        ctx.risk_level = "info"
        ctx.explanation = "eval() called with no arguments - likely dead code."
        ctx.is_constant = True
        return ctx

    arg = call.args[0].strip("'\"")

    if arg in ("True", "False", "None", "true", "false", "null"):
        ctx.is_constant = True
        ctx.constant_value = arg
        ctx.risk_level = "info"
        ctx.explanation = f"eval() called with constant value {arg}. No user input involved."
        return ctx

    try:
        float(arg)
        ctx.is_constant = True
        ctx.constant_value = arg
        ctx.risk_level = "info"
        ctx.explanation = f"eval() called with numeric literal {arg}. No user input involved."
        return ctx
    except ValueError:
        pass

    if arg.startswith(("'", '"', "f'", 'f"')):
        if "{" not in arg:
            ctx.is_constant = True
            ctx.constant_value = arg
            ctx.risk_level = "info"
            ctx.explanation = f"eval() called with string literal {arg}. No interpolation detected."
            return ctx

    if call.keywords.get("globals") or call.keywords.get("locals"):
        ctx.risk_level = "medium"
        ctx.explanation = "eval() called with custom globals/locals - reduced but still present risk."
        ctx.confidence_multiplier = 0.7
        return ctx

    if any(source in arg for source in SOURCES):
        ctx.is_user_controlled = True
        ctx.source_of_input = next(s for s in SOURCES if s in arg)
        ctx.risk_level = "critical"
        ctx.explanation = (
            f"eval() called with user-controlled input from {ctx.source_of_input}. "
            f"An attacker can execute arbitrary Python code by crafting the input value."
        )
        return ctx

    for assign in ast_result.assignments:
        if assign.target == arg:
            if any(source in assign.value for source in SOURCES):
                ctx.is_user_controlled = True
                ctx.source_of_input = assign.source
                ctx.risk_level = "critical"
                ctx.explanation = (
                    f"eval() called with variable '{arg}' which is assigned from "
                    f"untrusted source {assign.source}. An attacker can execute arbitrary code."
                )
                return ctx

    for func in ast_result.functions:
        for ret in func.returns:
            if ret.name == arg:
                ctx.is_return_value = True
                ctx.risk_level = "medium"
                ctx.explanation = (
                    f"eval() called with return value of function. "
                    f"Risk depends on whether the function processes user input."
                )
                ctx.confidence_multiplier = 0.6
                return ctx

    ctx.is_imported = any(
        arg in imp.module or arg in imp.names
        for imp in ast_result.imports
    )
    if ctx.is_imported:
        ctx.risk_level = "low"
        ctx.explanation = "eval() called with imported module/class - likely framework usage."
        ctx.confidence_multiplier = 0.3
        return ctx

    ctx.risk_level = "medium"
    ctx.explanation = (
        f"eval() called with variable '{arg}'. Cannot statically determine if this "
        f"contains user input. Manual review recommended."
    )
    ctx.confidence_multiplier = 0.5
    return ctx


def analyze_password_context(
    variable_name: str,
    value: str,
    file_path: str,
    line: int,
    lines: list[str],
    ast_result: Optional[PythonASTResult] = None,
) -> PasswordContext:
    """Analyze the context of a potential hardcoded password."""
    ctx = PasswordContext(
        variable_name=variable_name,
        value=value,
    )

    file_lower = file_path.lower()
    name_lower = variable_name.lower()

    if any(ind in file_lower for ind in FALSE_POSITIVE_INDICATORS):
        ctx.is_in_example = True
        ctx.risk_level = "info"
        ctx.explanation = (
            f"Variable '{variable_name}' found in {file_path} which appears to be "
            f"example/test code. Likely not a real secret."
        )
        return ctx

    if any(name in name_lower for name in SAFE_VARIABLE_NAMES):
        ctx.risk_level = "info"
        ctx.explanation = (
            f"Variable '{variable_name}' appears to be a reference to a password "
            f"(e.g., hash, field name, label) rather than an actual password value."
        )
        return ctx

    if any(placeholder in value.lower() for placeholder in PLACEHOLDER_VALUES):
        ctx.is_placeholder = True
        ctx.risk_level = "info"
        ctx.explanation = (
            f"Value appears to be a placeholder/dummy value: '{value[:20]}...'. "
            f"Not a real credential."
        )
        return ctx

    if value.lower() in ("password", "secret", "key", "token", "auth"):
        ctx.is_placeholder = True
        ctx.risk_level = "info"
        ctx.explanation = f"Value '{value}' is a common placeholder word, not a real credential."
        return ctx

    if "env(" in value.lower() or "os.environ" in value or "getenv" in value:
        ctx.is_from_env = True
        ctx.risk_level = "info"
        ctx.explanation = f"Password loaded from environment variable - properly externalized."
        return ctx

    if "vault" in value.lower() or "secret" in value.lower() and "manager" in value.lower():
        ctx.is_from_vault = True
        ctx.risk_level = "info"
        ctx.explanation = "Password loaded from secrets manager - properly externalized."
        return ctx

    line_idx = line - 1
    if 0 <= line_idx < len(lines):
        line_content = lines[line_idx].strip()
        if line_content.startswith("#") or line_content.startswith("//"):
            ctx.is_in_comment = True
            ctx.risk_level = "info"
            ctx.explanation = "Password found in comment - not executable code."
            return ctx

    if line_idx > 0:
        prev_line = lines[line_idx - 1].strip().lower() if line_idx > 0 else ""
        if "example" in prev_line or "sample" in prev_line or "test" in prev_line:
            ctx.is_in_example = True
            ctx.risk_level = "info"
            ctx.explanation = "Password found near example/test annotation."
            return ctx

    if len(value) < 8:
        ctx.risk_level = "low"
        ctx.explanation = (
            f"Short value ({len(value)} chars) is unlikely to be a real production credential."
        )
        ctx.confidence_multiplier = 0.4
        return ctx

    if value in ("", "changeme", "password", "admin", "root", "test"):
        ctx.is_placeholder = True
        ctx.risk_level = "info"
        ctx.explanation = f"Value '{value}' is a default/placeholder credential."
        return ctx

    ctx.is_hardcoded = True
    ctx.risk_level = "critical"
    ctx.explanation = (
        f"Variable '{variable_name}' contains a hardcoded credential with {len(value)} characters. "
        f"If this repository is public or accessible to unauthorized users, "
        f"this credential can be extracted and used for unauthorized access. "
        f"Store this value in environment variables or a secrets manager."
    )
    return ctx


def analyze_injection_context(
    call: CallInfo,
    ast_result: PythonASTResult,
    content: str,
    lines: list[str],
) -> InjectionContext:
    """Analyze the context of a potential injection vulnerability."""
    ctx = InjectionContext(
        sink_function=call.full_name or call.name,
        arguments=call.args,
    )

    for arg in call.args:
        if any(source in arg for source in SOURCES):
            ctx.is_user_controlled = True
            ctx.source_variable = arg
            ctx.source_type = next(s for s in SOURCES if s in arg)
            break

    if not ctx.is_user_controlled:
        for arg in call.args:
            clean = arg.strip("(),'\"")
            for assign in ast_result.assignments:
                if assign.target == clean and assign.is_tainted:
                    ctx.is_user_controlled = True
                    ctx.source_variable = assign.target
                    ctx.source_type = assign.source
                    break

    for arg in call.args:
        if arg in ("format", "f", "f-string") or "f'" in arg or 'f"' in arg:
            ctx.is_parameterized = False
            break
        if "%" in arg and ("s" in arg or "d" in arg):
            ctx.is_parameterized = False
            break
        if "?" in arg or ":param" in arg or "bound" in arg.lower():
            ctx.is_parameterized = True
            break

    line_idx = call.line - 1
    for i in range(max(0, line_idx - 5), line_idx + 1):
        if i >= len(lines):
            break
        line = lines[i]
        for sanitizer in ("sanitize", "escape", "clean", "validate", "whitelist",
                          "allowed", "parameterized", "prepared"):
            if sanitizer in line.lower():
                ctx.has_sanitization = True
                ctx.sanitizer = sanitizer
                break
        if "parameterized" in line.lower() or "prepared" in line.lower() or "?" in line:
            ctx.is_parameterized = True

    if ctx.is_user_controlled:
        if ctx.is_parameterized:
            ctx.risk_level = "low"
            ctx.explanation = (
                f"{call.full_name or call.name} receives user input but uses parameterized queries. "
                f"Low risk of injection."
            )
        elif ctx.has_sanitization:
            ctx.risk_level = "medium"
            ctx.explanation = (
                f"{call.full_name or call.name} receives user input with sanitization via {ctx.sanitizer}. "
                f"Verify the sanitizer is sufficient for this context."
            )
        else:
            ctx.risk_level = "critical"
            ctx.explanation = (
                f"{call.full_name or call.name} receives unsanitized user input from "
                f"{ctx.source_type or 'external source'}. "
                f"An attacker can inject malicious input to manipulate the {call.full_name or call.name} operation."
            )
    else:
        if ctx.is_parameterized:
            ctx.risk_level = "info"
            ctx.explanation = (
                f"{call.full_name or call.name} uses parameterized queries with no detected user input. "
                f"No injection risk."
            )
        else:
            ctx.risk_level = "low"
            ctx.explanation = (
                f"{call.full_name or call.name} called without detected user-controlled input. "
                f"Low injection risk. Verify no indirect user influence exists."
            )

    return ctx


def analyze_file_context(file_path: str) -> ContextType:
    """Determine the context type of a file."""
    fp_lower = file_path.lower()

    if any(x in fp_lower for x in ("test_", "_test.py", "test.py", "tests/", "spec/", "spec.py")):
        return ContextType.TEST
    if any(x in fp_lower for x in ("example", "demo", "sample", "tutorial")):
        return ContextType.EXAMPLE
    if any(x in fp_lower for x in ("docs/", "doc/", "documentation", "readme", ".md")):
        return ContextType.DOCUMENTATION
    if any(x in fp_lower for x in ("generated", "auto_generated", ".gen.", "autogenerated")):
        return ContextType.GENERATED
    if any(x in fp_lower for x in ("vendor/", "third_party/", "node_modules/", ".cache/")):
        return ContextType.VENDOR
    if any(x in fp_lower for x in ("config", "settings", ".env", "conf.", "configuration")):
        return ContextType.CONFIGURATION
    return ContextType.INTERNAL


def get_context_confidence_multiplier(ctx: ContextAnalysis) -> float:
    """Calculate confidence multiplier from context analysis."""
    multiplier = 1.0

    if ctx.context_type == ContextType.TEST:
        multiplier *= 0.2
    elif ctx.context_type == ContextType.EXAMPLE:
        multiplier *= 0.1
    elif ctx.context_type == ContextType.DOCUMENTATION:
        multiplier *= 0.05
    elif ctx.context_type == ContextType.GENERATED:
        multiplier *= 0.3
    elif ctx.context_type == ContextType.VENDOR:
        multiplier *= 0.01
    elif ctx.context_type == ContextType.CONFIGURATION:
        multiplier *= 0.8

    if ctx.reachability == Reachability.UNREACHABLE:
        multiplier *= 0.0
    elif ctx.reachability == Reachability.CONDITIONAL:
        multiplier *= 0.5
    elif ctx.reachability == Reachability.THROUGH_VARIABLE:
        multiplier *= 0.7

    if ctx.sanitization == SanitizationLevel.FULL:
        multiplier *= 0.1
    elif ctx.sanitization == SanitizationLevel.PARTIAL:
        multiplier *= 0.5

    if ctx.is_constant:
        multiplier *= 0.05

    return multiplier
