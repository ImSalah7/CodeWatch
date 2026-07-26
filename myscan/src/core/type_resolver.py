"""Type Resolver - Advanced type resolution for false positive reduction.

Resolves what a function call actually targets by tracking:
- Import aliases (import X as Y)
- Module ownership (X.func() -> what is X?)
- Class method ownership (self.method() -> what class?)
- Inheritance chains
- Built-in vs library vs custom functions

Critical for distinguishing:
- builtins.eval()       -> DANGEROUS
- torch.nn.Module.eval() -> SAFE (training mode)
- pandas.eval()          -> SAFE (different semantics)
- custom_obj.eval()      -> UNKNOWN (needs investigation)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class FunctionOrigin(Enum):
    """Where a function call originates from."""
    BUILTIN = "builtin"
    STANDARD_LIB = "standard_lib"
    THIRD_PARTY = "third_party"
    PROJECT_DEFINED = "project_defined"
    UNKNOWN = "unknown"
    METHOD = "method"
    CLASS_METHOD = "class_method"
    STATIC_METHOD = "static_method"
    LAMBDA = "lambda"


class SafetyLevel(Enum):
    """How safe a function call is."""
    DANGEROUS = "dangerous"
    SAFE = "safe"
    CONDITIONALLY_SAFE = "conditionally_safe"
    UNKNOWN = "unknown"


@dataclass
class TypeBinding:
    """A resolved type binding for a name."""
    name: str
    resolved_type: str
    module: str
    origin: FunctionOrigin
    safety: SafetyLevel
    confidence: float
    reasoning: str


@dataclass
class CallResolution:
    """Resolution result for a function call."""
    call_name: str
    full_name: str
    binding: Optional[TypeBinding]
    origin: FunctionOrigin
    safety: SafetyLevel
    is_dangerous_builtin: bool
    reasoning: str
    alternatives: list[str] = field(default_factory=list)


KNOWN_DANGEROUS_BUILTINS = {
    "eval": {"safe_alternatives": ["ast.literal_eval", "json.loads", "int()", "float()"]},
    "exec": {"safe_alternatives": ["importlib.import_module", "subprocess.run"]},
    "compile": {"safe_alternatives": ["ast.parse"]},
    "__import__": {"safe_alternatives": ["importlib.import_module"]},
}

SAFE_OWNERS = {
    "eval": {
        "torch", "torch.nn", "torch.nn.Module", "pandas", "numpy",
        "scipy", "sklearn", "xgboost", "lightgbm", "dask",
    },
    "exec": set(),
    "compile": {"py_compile", "compile", "code"},
    "__import__": set(),
}

STDLIB_MODULES = {
    "os", "sys", "io", "math", "json", "csv", "re", "collections",
    "itertools", "functools", "operator", "pathlib", "shutil",
    "subprocess", "threading", "multiprocessing", "socket",
    "http", "urllib", "email", "html", "xml", "logging",
    "unittest", "test", "ast", "tokenize", "dis", "code",
    "codecs", "encodings", "locale", "datetime", "time",
    "hashlib", "hmac", "secrets", "base64", "struct",
    "ctypes", "importlib", "pkgutil", "platform", "signal",
    "tempfile", "glob", "fnmatch", "textwrap", "difflib",
    "string", "textwrap", "reprlib", "enum", "dataclasses",
    "typing", "contextlib", "abc", "copy", "pprint",
}


class TypeResolver:
    """Resolves types and function ownership across a codebase."""

    def __init__(self):
        self._imports: dict[str, str] = {}
        self._import_aliases: dict[str, str] = {}
        self._module_members: dict[str, set[str]] = {}
        self._class_methods: dict[str, set[str]] = {}
        self._variable_types: dict[str, str] = {}
        self._function_definitions: dict[str, ast.FunctionDef] = {}

    def analyze_file(self, content: str, file_path: str = "") -> None:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return
        self._visit_imports(tree)
        self._visit_class_definitions(tree)
        self._visit_function_definitions(tree)
        self._visit_assignments(tree)

    def resolve_call(self, call_node: ast.Call, file_path: str = "") -> CallResolution:
        call_name = self._get_call_name(call_node)
        full_name = self._resolve_full_name(call_name)

        binding = self._resolve_binding(call_name)
        origin = self._determine_origin(full_name, call_name)
        safety = self._determine_safety(full_name, call_name, origin)

        is_dangerous_builtin = (
            call_name in KNOWN_DANGEROUS_BUILTINS
            and origin in (FunctionOrigin.BUILTIN, FunctionOrigin.UNKNOWN)
            and safety != SafetyLevel.SAFE
        )

        alternatives = []
        if call_name in KNOWN_DANGEROUS_BUILTINS:
            alternatives = KNOWN_DANGEROUS_BUILTINS[call_name]["safe_alternatives"]

        reasoning = self._build_reasoning(call_name, full_name, origin, safety, binding)

        return CallResolution(
            call_name=call_name,
            full_name=full_name,
            binding=binding,
            origin=origin,
            safety=safety,
            is_dangerous_builtin=is_dangerous_builtin,
            reasoning=reasoning,
            alternatives=alternatives,
        )

    def is_dangerous_call(self, call_node: ast.Call) -> bool:
        resolution = self.resolve_call(call_node)
        return resolution.is_dangerous_builtin

    def get_safe_alternatives(self, call_name: str) -> list[str]:
        if call_name in KNOWN_DANGEROUS_BUILTINS:
            return KNOWN_DANGEROUS_BUILTINS[call_name]["safe_alternatives"]
        return []

    def _get_call_name(self, call_node: ast.Call) -> str:
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            parts = []
            node = call_node.func
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            parts.reverse()
            return ".".join(parts)
        return ""

    def _resolve_full_name(self, call_name: str) -> str:
        if "." in call_name:
            parts = call_name.split(".")
            root = parts[0]
            if root in self._import_aliases:
                resolved = self._import_aliases[root]
                return ".".join([resolved] + parts[1:])
            if root in self._imports:
                return ".".join([self._imports[root]] + parts[1:])
        if call_name in self._import_aliases:
            return self._import_aliases[call_name]
        if call_name in self._imports:
            return self._imports[call_name]
        return call_name

    def _resolve_binding(self, call_name: str) -> Optional[TypeBinding]:
        root = call_name.split(".")[0] if "." in call_name else call_name

        if root in self._import_aliases:
            module = self._import_aliases[root]
            return TypeBinding(
                name=root,
                resolved_type=module,
                module=module,
                origin=FunctionOrigin.THIRD_PARTY if module not in STDLIB_MODULES else FunctionOrigin.STANDARD_LIB,
                safety=SafetyLevel.UNKNOWN,
                confidence=0.8,
                reasoning=f"Import alias: {root} -> {module}",
            )

        if root in self._imports:
            module = self._imports[root]
            return TypeBinding(
                name=root,
                resolved_type=module,
                module=module,
                origin=FunctionOrigin.THIRD_PARTY if module not in STDLIB_MODULES else FunctionOrigin.STANDARD_LIB,
                safety=SafetyLevel.UNKNOWN,
                confidence=0.9,
                reasoning=f"Direct import: {root} from {module}",
            )

        if root in self._variable_types:
            type_name = self._variable_types[root]
            return TypeBinding(
                name=root,
                resolved_type=type_name,
                module="",
                origin=FunctionOrigin.PROJECT_DEFINED,
                safety=SafetyLevel.UNKNOWN,
                confidence=0.6,
                reasoning=f"Variable type inferred: {root} is {type_name}",
            )

        if call_name in KNOWN_DANGEROUS_BUILTINS:
            return TypeBinding(
                name=call_name,
                resolved_type="builtins",
                module="builtins",
                origin=FunctionOrigin.BUILTIN,
                safety=SafetyLevel.DANGEROUS,
                confidence=0.9,
                reasoning=f"Python builtin: {call_name}() is dangerous",
            )

        return None

    def _determine_origin(self, full_name: str, call_name: str) -> FunctionOrigin:
        parts = full_name.split(".")
        root = parts[0] if parts else call_name

        if root in STDLIB_MODULES:
            return FunctionOrigin.STANDARD_LIB
        if root in KNOWN_DANGEROUS_BUILTINS and len(parts) == 1:
            return FunctionOrigin.BUILTIN
        if root in self._imports or root in self._import_aliases:
            return FunctionOrigin.THIRD_PARTY
        if call_name in self._function_definitions:
            return FunctionOrigin.PROJECT_DEFINED
        return FunctionOrigin.UNKNOWN

    def _determine_safety(self, full_name: str, call_name: str, origin: FunctionOrigin) -> SafetyLevel:
        bare_name = call_name.split(".")[-1] if "." in call_name else call_name

        if bare_name in KNOWN_DANGEROUS_BUILTINS:
            if origin == FunctionOrigin.BUILTIN:
                return SafetyLevel.DANGEROUS
            root = call_name.split(".")[0] if "." in call_name else call_name
            safe_owners = SAFE_OWNERS.get(bare_name, set())
            for part in full_name.split("."):
                if part in safe_owners:
                    return SafetyLevel.SAFE
            if origin == FunctionOrigin.UNKNOWN:
                return SafetyLevel.UNKNOWN
            return SafetyLevel.CONDITIONALLY_SAFE

        return SafetyLevel.UNKNOWN

    def _build_reasoning(
        self, call_name: str, full_name: str,
        origin: FunctionOrigin, safety: SafetyLevel,
        binding: Optional[TypeBinding],
    ) -> str:
        parts = []
        if binding:
            parts.append(binding.reasoning)
        parts.append(f"Origin: {origin.value}")
        parts.append(f"Safety: {safety.value}")
        if full_name != call_name:
            parts.append(f"Resolved: {full_name}")
        return "; ".join(parts)

    def _visit_imports(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    self._imports[name] = alias.name
                    if alias.asname:
                        self._import_aliases[alias.asname] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    name = alias.asname or alias.name
                    full = f"{module}.{alias.name}" if module else alias.name
                    self._imports[name] = full
                    if alias.asname:
                        self._import_aliases[alias.asname] = full

    def _visit_class_definitions(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                methods = set()
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods.add(item.name)
                self._class_methods[node.name] = methods

    def _visit_function_definitions(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._function_definitions[node.name] = node

    def _visit_assignments(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        type_name = self._infer_type(node.value)
                        if type_name:
                            self._variable_types[target.id] = type_name

    def _infer_type(self, value: ast.expr) -> Optional[str]:
        if isinstance(value, ast.Call):
            if isinstance(value.func, ast.Name):
                return value.func.id
            elif isinstance(value.func, ast.Attribute):
                return value.func.attr
        if isinstance(value, ast.Name):
            return self._variable_types.get(value.id)
        if isinstance(value, ast.Attribute):
            if isinstance(value.value, ast.Name):
                base = self._variable_types.get(value.value.id, value.value.id)
                return f"{base}.{value.attr}"
        return None
