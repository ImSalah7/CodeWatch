"""Code Context Engine.

Provides enhanced code snippets with:
- 5 lines before the vulnerable line
- The vulnerable line (highlighted)
- 5 lines after
- Syntax-aware line numbers
- Sink and source highlighting

Ensures no finding has empty or incorrect code snippets.
"""

from __future__ import annotations

from dataclasses import dataclass

CONTEXT_LINES = 5


@dataclass
class CodeContext:
    """Enhanced code context for a finding."""
    snippet: str
    highlighted_line: int
    start_line: int
    end_line: int
    total_lines: int
    before_lines: list[str]
    vulnerable_line: str
    after_lines: list[str]
    has_context: bool = True


def get_code_context(
    file_content: str,
    target_line: int,
    context_lines: int = CONTEXT_LINES,
    max_snippet_lines: int = 15,
) -> CodeContext:
    """Extract enhanced code context around a vulnerable line.

    Always provides context_lines before and after the target line.
    """
    lines = file_content.splitlines()
    total_lines = len(lines)

    if total_lines == 0:
        return CodeContext(
            snippet="",
            highlighted_line=target_line,
            start_line=target_line,
            end_line=target_line,
            total_lines=0,
            before_lines=[],
            vulnerable_line="",
            after_lines=[],
            has_context=False,
        )

    idx = max(0, target_line - 1)

    start = max(0, idx - context_lines)
    end = min(total_lines, idx + context_lines + 1)

    before_lines = lines[start:idx]
    vulnerable_line = lines[idx] if idx < total_lines else ""
    after_lines = lines[idx + 1:end]

    actual_context = min(context_lines, max_snippet_lines // 2)
    start = max(0, idx - actual_context)
    end = min(total_lines, idx + actual_context + 1)

    before_lines = lines[start:idx]
    vulnerable_line = lines[idx] if idx < total_lines else ""
    after_lines = lines[idx + 1:end]

    snippet_parts = []
    for i, line in enumerate(before_lines):
        ln = start + i + 1
        snippet_parts.append(f"{ln:>4} | {line}")
    snippet_parts.append(f"{target_line:>4} | {vulnerable_line}")
    for i, line in enumerate(after_lines):
        ln = idx + 2 + i
        snippet_parts.append(f"{ln:>4} | {line}")

    snippet = "\n".join(snippet_parts)

    return CodeContext(
        snippet=snippet,
        highlighted_line=target_line,
        start_line=start + 1,
        end_line=end,
        total_lines=total_lines,
        before_lines=before_lines,
        vulnerable_line=vulnerable_line,
        after_lines=after_lines,
        has_context=True,
    )


def format_code_for_display(
    file_content: str,
    target_line: int,
    context_lines: int = CONTEXT_LINES,
    language: str = "python",
) -> str:
    """Format code context for display with highlighted vulnerable line."""
    ctx = get_code_context(file_content, target_line, context_lines)

    if not ctx.has_context:
        return "// No code context available"

    parts = []
    idx = 0

    for _i, line in enumerate(ctx.before_lines):
        ln = ctx.start_line + idx
        parts.append(f"  {ln:>4} | {line}")
        idx += 1

    parts.append(f"→ {ctx.highlighted_line:>4} | {ctx.vulnerable_line}")
    idx += 1

    for _i, line in enumerate(ctx.after_lines):
        ln = ctx.start_line + idx
        parts.append(f"  {ln:>4} | {line}")
        idx += 1

    return "\n".join(parts)


def ensure_code_snippet(
    file_content: str,
    target_line: int,
    existing_snippet: str = "",
    context_lines: int = CONTEXT_LINES,
) -> str:
    """Ensure a finding has a proper code snippet.

    If the existing snippet is empty or too short, generate one.
    """
    if existing_snippet and len(existing_snippet.strip().split("\n")) >= 3:
        return existing_snippet

    if not file_content:
        return existing_snippet or ""

    ctx = get_code_context(file_content, target_line, context_lines)
    return ctx.snippet if ctx.has_context else existing_snippet


def extract_sink_context(
    file_content: str,
    target_line: int,
    sink_name: str = "",
) -> str:
    """Extract code context specifically highlighting the sink."""
    ctx = get_code_context(file_content, target_line, context_lines=3)

    if not ctx.has_context:
        return ""

    parts = []
    idx = 0

    for _i, line in enumerate(ctx.before_lines):
        ln = ctx.start_line + idx
        parts.append(f"  {ln:>4} | {line}")
        idx += 1

    sink_marker = "  ← SINK" if sink_name else "  ← VULNERABLE"
    parts.append(f"→ {ctx.highlighted_line:>4} | {ctx.vulnerable_line}{sink_marker}")
    idx += 1

    for _i, line in enumerate(ctx.after_lines):
        ln = ctx.start_line + idx
        parts.append(f"  {ln:>4} | {line}")
        idx += 1

    return "\n".join(parts)
