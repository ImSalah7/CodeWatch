"""Repository-wide Symbol Table.

Builds a complete symbol table for the entire repository:
- Variables (name, type, value, scope, file, line)
- Functions (name, args, return type, decorators, scope)
- Classes (name, base classes, methods, decorators)
- Imports (module, alias, names)
- Constants (name, value, type)
- Scopes (global, function, class, module)

Every finding references resolved symbols instead of plain text.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class SymbolType(Enum):
    VARIABLE = "variable"
    FUNCTION = "function"
    CLASS = "class"
    METHOD = "method"
    CONSTANT = "constant"
    IMPORT = "import"
    PARAMETER = "parameter"
    ATTRIBUTE = "attribute"
    MODULE = "module"
    UNKNOWN = "unknown"


class ScopeType(Enum):
    GLOBAL = "global"
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    LOCAL = "local"
    BUILTIN = "builtin"


@dataclass
class Symbol:
    """A single symbol in the table."""
    name: str
    symbol_type: SymbolType
    scope: ScopeType
    file_path: str
    line: int
    end_line: int = 0
    column: int = 0
    inferred_type: str = ""
    value: str = ""
    decorators: list[str] = field(default_factory=list)
    base_classes: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    return_type: str = ""
    is_async: bool = False
    is_imported: bool = False
    import_source: str = ""
    docstring: str = ""
    children: list[str] = field(default_factory=list)


@dataclass
class SymbolScope:
    """A scope containing symbols."""
    name: str
    scope_type: ScopeType
    file_path: str
    line: int
    end_line: int = 0
    parent: str = ""
    symbols: dict[str, Symbol] = field(default_factory=dict)


@dataclass
class SymbolTable:
    """Complete repository symbol table."""
    symbols: dict[str, list[Symbol]] = field(default_factory=dict)
    scopes: list[SymbolScope] = field(default_factory=list)
    files: dict[str, dict] = field(default_factory=dict)
    total_symbols: int = 0
    total_files: int = 0


def build_symbol_table(repo_path: str, file_contents: dict[str, str]) -> SymbolTable:
    """Build a complete symbol table for the repository."""
    table = SymbolTable()
    table.total_files = len(file_contents)

    for file_path, content in file_contents.items():
        _analyze_file(file_path, content, table)

    return table


def build_symbol_table_from_file(file_path: str, content: str) -> SymbolTable:
    """Build a symbol table for a single file."""
    table = SymbolTable()
    table.total_files = 1
    _analyze_file(file_path, content, table)
    return table


def _analyze_file(file_path: str, content: str, table: SymbolTable):
    """Analyze a single file and add symbols to the table."""
    try:
        tree = ast.parse(content, filename=file_path)
    except (SyntaxError, Exception):
        return

    file_info = {
        "path": file_path,
        "symbols": [],
        "imports": [],
        "functions": [],
        "classes": [],
        "assignments": [],
    }

    module_scope = SymbolScope(
        name=file_path,
        scope_type=ScopeType.MODULE,
        file_path=file_path,
        line=1,
    )

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            _visit_import(node, file_path, table, module_scope, file_info)
        elif isinstance(node, ast.ImportFrom):
            _visit_import_from(node, file_path, table, module_scope, file_info)
        elif isinstance(node, ast.FunctionDef):
            _visit_function(node, file_path, table, module_scope, file_info, ScopeType.FUNCTION)
        elif isinstance(node, ast.AsyncFunctionDef):
            _visit_function(node, file_path, table, module_scope, file_info, ScopeType.FUNCTION, is_async=True)
        elif isinstance(node, ast.ClassDef):
            _visit_class(node, file_path, table, module_scope, file_info)
        elif isinstance(node, ast.Assign):
            _visit_assignment(node, file_path, table, module_scope, file_info)
        elif isinstance(node, ast.AnnAssign):
            _visit_ann_assignment(node, file_path, table, module_scope, file_info)

    table.scopes.append(module_scope)
    table.files[file_path] = file_info
    table.total_symbols += len(file_info["symbols"])


def _visit_import(node: ast.Import, file_path: str, table: SymbolTable,
                   scope: SymbolScope, file_info: dict):
    for alias in node.names:
        name = alias.asname or alias.name
        sym = Symbol(
            name=name,
            symbol_type=SymbolType.IMPORT,
            scope=ScopeType.MODULE,
            file_path=file_path,
            line=node.lineno,
            inferred_type="module",
            value=alias.name,
            is_imported=True,
            import_source=alias.name,
        )
        _add_symbol(table, scope, sym)
        file_info["imports"].append(alias.name)


def _visit_import_from(node: ast.ImportFrom, file_path: str, table: SymbolTable,
                        scope: SymbolScope, file_info: dict):
    module = node.module or ""
    for alias in node.names:
        name = alias.asname or alias.name
        full_source = f"{module}.{name}" if module else name
        sym = Symbol(
            name=name,
            symbol_type=SymbolType.IMPORT,
            scope=ScopeType.MODULE,
            file_path=file_path,
            line=node.lineno,
            inferred_type="module" if name == "*" else "symbol",
            value=full_source,
            is_imported=True,
            import_source=full_source,
        )
        _add_symbol(table, scope, sym)
        file_info["imports"].append(full_source)


def _visit_function(node, file_path: str, table: SymbolTable,
                     scope: SymbolScope, file_info: dict,
                     scope_type: ScopeType, is_async: bool = False):
    decorators = [_get_decorator_name(d) for d in node.decorator_list]
    args = [arg.arg for arg in node.args.args]

    docstring = ""
    if (node.body and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)):
        docstring = node.body[0].value.value

    return_type = ""
    if node.returns:
        return_type = ast.dump(node.returns)[:50]

    sym = Symbol(
        name=node.name,
        symbol_type=SymbolType.FUNCTION,
        scope=scope_type,
        file_path=file_path,
        line=node.lineno,
        end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
        decorators=decorators,
        parameters=args,
        return_type=return_type,
        is_async=is_async,
        docstring=docstring,
    )
    _add_symbol(table, scope, sym)
    file_info["functions"].append(node.name)

    func_scope = SymbolScope(
        name=f"{scope.name}::{node.name}",
        scope_type=scope_type,
        file_path=file_path,
        line=node.lineno,
        end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
        parent=scope.name,
    )

    for arg in node.args.args:
        param_sym = Symbol(
            name=arg.arg,
            symbol_type=SymbolType.PARAMETER,
            scope=ScopeType.FUNCTION,
            file_path=file_path,
            line=node.lineno,
        )
        _add_symbol(table, func_scope, param_sym)

    table.scopes.append(func_scope)


def _visit_class(node: ast.ClassDef, file_path: str, table: SymbolTable,
                  scope: SymbolScope, file_info: dict):
    decorators = [_get_decorator_name(d) for d in node.decorator_list]
    base_classes = []
    for base in node.bases:
        if isinstance(base, ast.Name):
            base_classes.append(base.id)
        elif isinstance(base, ast.Attribute):
            base_classes.append(ast.dump(base)[:50])

    docstring = ""
    if (node.body and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)):
        docstring = node.body[0].value.value

    sym = Symbol(
        name=node.name,
        symbol_type=SymbolType.CLASS,
        scope=ScopeType.CLASS,
        file_path=file_path,
        line=node.lineno,
        end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
        decorators=decorators,
        base_classes=base_classes,
        docstring=docstring,
    )
    _add_symbol(table, scope, sym)
    file_info["classes"].append(node.name)

    class_scope = SymbolScope(
        name=f"{scope.name}::{node.name}",
        scope_type=ScopeType.CLASS,
        file_path=file_path,
        line=node.lineno,
        end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
        parent=scope.name,
    )

    for child in node.body:
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            is_async = isinstance(child, ast.AsyncFunctionDef)
            child_decorators = [_get_decorator_name(d) for d in child.decorator_list]
            child_args = [arg.arg for arg in child.args.args]
            method_sym = Symbol(
                name=child.name,
                symbol_type=SymbolType.METHOD,
                scope=ScopeType.METHOD,
                file_path=file_path,
                line=child.lineno,
                end_line=getattr(child, "end_lineno", child.lineno) or child.lineno,
                decorators=child_decorators,
                parameters=child_args,
                is_async=is_async,
            )
            _add_symbol(table, class_scope, method_sym)
            sym.children.append(child.name)

    table.scopes.append(class_scope)


def _visit_assignment(node: ast.Assign, file_path: str, table: SymbolTable,
                       scope: SymbolScope, file_info: dict):
    for target in node.targets:
        if isinstance(target, ast.Name):
            value_type = type(node.value).__name__
            literal_value = ""
            is_constant = False

            if isinstance(node.value, ast.Constant):
                literal_value = repr(node.value.value)[:100]
                is_constant = True

            sym_type = SymbolType.CONSTANT if is_constant else SymbolType.VARIABLE
            sym = Symbol(
                name=target.id,
                symbol_type=sym_type,
                scope=scope.scope_type,
                file_path=file_path,
                line=node.lineno,
                inferred_type=value_type,
                value=literal_value,
            )
            _add_symbol(table, scope, sym)
            file_info["assignments"].append(target.id)


def _visit_ann_assignment(node: ast.AnnAssign, file_path: str, table: SymbolTable,
                           scope: SymbolScope, file_info: dict):
    if isinstance(node.target, ast.Name) and node.value:
        value_type = type(node.value).__name__
        literal_value = ""
        is_constant = False

        if isinstance(node.value, ast.Constant):
            literal_value = repr(node.value.value)[:100]
            is_constant = True

        ann_type = ast.dump(node.annotation)[:30] if node.annotation else ""

        sym_type = SymbolType.CONSTANT if is_constant else SymbolType.VARIABLE
        sym = Symbol(
            name=node.target.id,
            symbol_type=sym_type,
            scope=scope.scope_type,
            file_path=file_path,
            line=node.lineno,
            inferred_type=ann_type or value_type,
            value=literal_value,
        )
        _add_symbol(table, scope, sym)
        file_info["assignments"].append(node.target.id)


def _add_symbol(table: SymbolTable, scope: SymbolScope, sym: Symbol):
    """Add a symbol to both the table and the scope."""
    if sym.name not in table.symbols:
        table.symbols[sym.name] = []
    table.symbols[sym.name].append(sym)
    scope.symbols[sym.name] = sym


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


def lookup_symbol(table: SymbolTable, name: str, file_path: str = "") -> list[Symbol]:
    """Look up a symbol by name, optionally filtered by file."""
    symbols = table.symbols.get(name, [])
    if file_path:
        symbols = [s for s in symbols if s.file_path == file_path]
    return symbols


def resolve_type(table: SymbolTable, name: str, file_path: str = "") -> str:
    """Resolve the type of a symbol."""
    symbols = lookup_symbol(table, name, file_path)
    if not symbols:
        return "unknown"
    sym = symbols[0]
    if sym.inferred_type:
        return sym.inferred_type
    if sym.symbol_type == SymbolType.CONSTANT:
        return "constant"
    if sym.symbol_type == SymbolType.FUNCTION:
        return "function"
    if sym.symbol_type == SymbolType.CLASS:
        return "class"
    return "unknown"
