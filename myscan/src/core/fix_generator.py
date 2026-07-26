"""Secure Fix Generation Engine.

Generates code transformation suggestions for each vulnerability type:
- SQL Injection → parameterized queries
- Command Injection → subprocess with shell=False
- XSS → template escaping
- eval/exec → safe alternatives
- Hardcoded secrets → environment variables
- Path traversal → path validation
- Deserialization → safe alternatives
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FixSuggestion:
    """A specific fix suggestion with code example."""
    title: str
    description: str
    before_code: str
    after_code: str
    confidence: float
    references: list[str] = field(default_factory=list)
    effort: str = "low"
    breaking_change: bool = False


@dataclass
class CodeTransform:
    """A code transformation rule."""
    pattern: str
    replacement: str
    description: str
    confidence: float = 0.8


SQL_INJECTION_FIXES = [
    CodeTransform(
        pattern=r'execute\s*\(\s*f["\'](.+?)["\']',
        replacement=r'execute("SELECT * FROM table WHERE id = ?", (param,))',
        description="Use parameterized queries with ? placeholders instead of f-string interpolation",
        confidence=0.95,
    ),
    CodeTransform(
        pattern=r'execute\s*\(\s*["\'](.+?)["\']\.format\(',
        replacement=r'execute("SELECT * FROM table WHERE id = ?", (param,))',
        description="Use parameterized queries instead of .format() string interpolation",
        confidence=0.95,
    ),
    CodeTransform(
        pattern=r'execute\s*\(\s*["\'](.+?)["\']\s*\+\s*',
        replacement=r'execute("SELECT * FROM table WHERE id = ?", (param,))',
        description="Use parameterized queries instead of string concatenation",
        confidence=0.95,
    ),
    CodeTransform(
        pattern=r'execute\s*\(\s*["\'](.+?)["\']\s*%\s*',
        replacement=r'execute("SELECT * FROM table WHERE id = ?", (param,))',
        description="Use parameterized queries instead of % string formatting",
        confidence=0.95,
    ),
]

COMMAND_INJECTION_FIXES = [
    CodeTransform(
        pattern=r'os\.system\s*\(',
        replacement='subprocess.run(args, shell=False, check=True)',
        description="Use subprocess.run() with shell=False and explicit argument list",
        confidence=0.90,
    ),
    CodeTransform(
        pattern=r'subprocess\.(call|run)\s*\(.*shell\s*=\s*True',
        replacement='subprocess.run(args, shell=False, check=True)',
        description="Set shell=False and pass arguments as a list",
        confidence=0.90,
    ),
    CodeTransform(
        pattern=r'os\.popen\s*\(',
        replacement='subprocess.run(args, shell=False, capture_output=True, text=True)',
        description="Use subprocess.run() instead of os.popen()",
        confidence=0.85,
    ),
]

EVAL_EXEC_FIXES = [
    CodeTransform(
        pattern=r'\beval\s*\(',
        replacement='ast.literal_eval(expr)  # For literals only\n# or json.loads(expr)  # For JSON',
        description="Use ast.literal_eval() for safe evaluation of Python literals, or json.loads() for JSON data",
        confidence=0.90,
    ),
    CodeTransform(
        pattern=r'\bexec\s*\(',
        replacement='# Replace with specific function calls\n# exec() is almost never safe',
        description="Avoid exec() entirely. Refactor to use specific function calls or a safe interpreter",
        confidence=0.85,
    ),
]

XSS_FIXES = [
    CodeTransform(
        pattern=r'innerHTML\s*=',
        replacement='element.textContent = value  // or use DOMPurify.sanitize(value)',
        description="Use textContent instead of innerHTML, or sanitize with DOMPurify",
        confidence=0.90,
    ),
    CodeTransform(
        pattern=r'render_template_string\s*\(',
        replacement='render_template("template.html", data=value)',
        description="Use render_template() with a separate template file instead of render_template_string()",
        confidence=0.90,
    ),
]

HARDCODED_SECRET_FIXES = [
    CodeTransform(
        pattern=r'(password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']',
        replacement=r'\1 = os.environ.get("\1_UPPER")',
        description="Store secrets in environment variables and access via os.environ.get()",
        confidence=0.85,
    ),
    CodeTransform(
        pattern=r'(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*["\'][^"\']+["\']',
        replacement=r'# Use AWS credentials file or IAM roles\n# os.environ.get("AWS_ACCESS_KEY_ID")',
        description="Use AWS credentials file, environment variables, or IAM roles instead of hardcoded keys",
        confidence=0.90,
    ),
]

PATH_TRAVERSAL_FIXES = [
    CodeTransform(
        pattern=r'open\s*\(\s*(?:request\.|user_)',
        replacement='open(os.path.join(ALLOWED_DIR, os.path.basename(filename)))',
        description="Validate and sanitize file paths. Use os.path.basename() to prevent directory traversal",
        confidence=0.85,
    ),
]

DESERIALIZATION_FIXES = [
    CodeTransform(
        pattern=r'pickle\.loads?\s*\(',
        replacement='json.loads(data)  # Use JSON for safe deserialization',
        description="Use json.loads() instead of pickle for safe deserialization",
        confidence=0.90,
    ),
    CodeTransform(
        pattern=r'yaml\.load\s*\((?!.*Loader)',
        replacement='yaml.safe_load(data)',
        description="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        confidence=0.95,
    ),
]

ALL_FIXES = {
    "sql_injection": SQL_INJECTION_FIXES,
    "command_injection": COMMAND_INJECTION_FIXES,
    "code_injection": EVAL_EXEC_FIXES,
    "xss": XSS_FIXES,
    "hardcoded_secret": HARDCODED_SECRET_FIXES,
    "path_traversal": PATH_TRAVERSAL_FIXES,
    "deserialization": DESERIALIZATION_FIXES,
    "template_injection": XSS_FIXES,
    "injection": SQL_INJECTION_FIXES + COMMAND_INJECTION_FIXES,
}

CATEGORY_TO_TITLE = {
    "sql_injection": "SQL Injection Prevention",
    "command_injection": "Command Injection Prevention",
    "code_injection": "Code Injection Prevention",
    "xss": "Cross-Site Scripting Prevention",
    "hardcoded_secret": "Secret Management",
    "path_traversal": "Path Traversal Prevention",
    "deserialization": "Deserialization Safety",
    "template_injection": "Template Injection Prevention",
    "injection": "Injection Prevention",
    "insecure_design": "Security Design Review",
    "security_misconfiguration": "Configuration Hardening",
}


def generate_fix(category: str, code_snippet: str = "",
                 function_name: str = "", file_path: str = "") -> list[FixSuggestion]:
    """Generate fix suggestions for a finding."""
    fixes = ALL_FIXES.get(category, [])
    suggestions: list[FixSuggestion] = []

    for fix in fixes:
        before = code_snippet[:500] if code_snippet else _generate_before_example(category)
        after = fix.replacement

        if function_name:
            after = after.replace("param", f"{function_name}_param")

        suggestions.append(FixSuggestion(
            title=CATEGORY_TO_TITLE.get(category, "Security Fix"),
            description=fix.description,
            before_code=before,
            after_code=after,
            confidence=fix.confidence,
            references=_get_references(category),
            effort=_estimate_effort(category),
        ))

    if not suggestions:
        suggestions.append(FixSuggestion(
            title=CATEGORY_TO_TITLE.get(category, "Security Review"),
            description=f"Review the code for {category} vulnerabilities and apply security best practices.",
            before_code=code_snippet[:500] if code_snippet else "",
            after_code="# Apply security best practices for this vulnerability category",
            confidence=0.5,
            references=[],
            effort="medium",
        ))

    return suggestions


def generate_secure_alternative(category: str, original_code: str) -> str:
    """Generate a secure code alternative for the given code."""
    for fix in ALL_FIXES.get(category, []):
        match = re.search(fix.pattern, original_code)
        if match:
            return _apply_transform(original_code, match, fix)

    return _generate_fallback_fix(category, original_code)


def _apply_transform(code: str, match: re.Match, fix: CodeTransform) -> str:
    """Apply a code transformation."""
    lines = code.split("\n")
    for i, line in enumerate(lines):
        if re.search(fix.pattern, line):
            indent = len(line) - len(line.lstrip())
            spaces = " " * indent
            transformed = re.sub(fix.pattern, fix.replacement, line)
            lines[i] = f"{spaces}{transformed}"
    return "\n".join(lines)


def _generate_before_example(category: str) -> str:
    examples = {
        "sql_injection": 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        "command_injection": 'os.system("ping " + user_input)',
        "code_injection": 'result = eval(user_input)',
        "xss": 'element.innerHTML = userInput',
        "hardcoded_secret": 'password = "SuperSecret123!"',
        "path_traversal": 'open(request.args.get("file"))',
        "deserialization": 'data = pickle.loads(request.data)',
        "template_injection": 'render_template_string(user_input)',
    }
    return examples.get(category, "# Vulnerable code")


def _generate_fallback_fix(category: str, code: str) -> str:
    return f"# Apply security best practices for {category}\n# Review OWASP guidelines for this vulnerability type"


def _get_references(category: str) -> list[str]:
    refs = {
        "sql_injection": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
        "command_injection": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
        "code_injection": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Code_Injection_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
        "xss": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
        "hardcoded_secret": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
    }
    return refs.get(category, [])


def _estimate_effort(category: str) -> str:
    effort_map = {
        "sql_injection": "medium",
        "command_injection": "medium",
        "code_injection": "high",
        "xss": "low",
        "hardcoded_secret": "low",
        "path_traversal": "low",
        "deserialization": "low",
    }
    return effort_map.get(category, "medium")
