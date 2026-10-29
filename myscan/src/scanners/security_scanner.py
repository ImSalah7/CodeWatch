"""Security vulnerability scanner using rules engine."""

from __future__ import annotations

import re

from ..core.models import CodeLocation, Finding, FindingCategory, Language
from ..core.rules import ALL_RULES, Rule
from ..scanners import BaseScanner


# Rules whose regex cannot distinguish a real credential from a placeholder,
# header name, or variable reference. The matched line is handed to the
# validation pipeline as the code snippet so the multi-signal secret gates
# (placeholder / weak-value / prose / known-format) actually see the value.
CREDENTIAL_RULE_IDS: frozenset[str] = frozenset(
    {"SEC017", "SEC043", "SEC044", "SEC045", "SEC046"}
)

# innerHTML / dangerouslySetInnerHTML sinks assigned a pure static literal are
# not XSS: there is no user input flowing into the sink.
XSS_RULE_IDS: frozenset[str] = frozenset({"SEC004", "SEC005"})

_CREDENTIAL_ASSIGNMENT = re.compile(r"(?i)(\w+)\s*[=:]\s*[\"']([^\"']+)")


class SecurityScanner(BaseScanner):
    name = "security"
    description = "Pattern-based security vulnerability scanner"

    def __init__(self, suppress_secret_rules: bool = False):
        self.suppress_secret_rules = suppress_secret_rules
        self.rules = [r for r in ALL_RULES if r.category == FindingCategory.SECURITY]

    def scan_file(self, content: str, file_path: str, language: Language) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for rule in self.rules:
            if rule.languages and language not in rule.languages:
                continue
            if not rule.pattern:
                continue
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue

            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith(("#", "//")):
                    continue
                if stripped.startswith(("*", "/*")):
                    continue
                match = pattern.search(line)
                if match:
                    if not self._validate_match(rule, line):
                        continue
                    snippet = self._get_context(lines, i - 1)
                    function_name = self._extract_function(lines, i - 1)
                    cvss = rule.get_cvss() if rule.cvss_config else None
                    matched = match.group(0).strip()
                    mechanism = self._detect_mechanism(rule, matched)
                    finding = Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        description=rule.description,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        category=FindingCategory.SECURITY,
                        language=language,
                        location=CodeLocation(
                            file_path=file_path,
                            line=i,
                            column=match.start() + 1,
                            function=function_name,
                            # Store the matched line, not a multi-line window:
                            # the validation pipeline extracts the assigned
                            # value from the snippet, so context would hide the
                            # credential behind unrelated surrounding code.
                            code_snippet=line,
                        ),
                        cwe=rule.cwe,
                        cwe_name=rule.cwe_name,
                        owasp=rule.owasp,
                        cvss=cvss,
                        fix_suggestion=rule.fix_suggestion,
                        references=rule.references,
                        impact=rule.impact,
                        why_vulnerable=self._explain(rule, snippet, matched, file_path, i, mechanism),
                        confidence_reasoning=self._confidence_reasoning(rule, matched, i, mechanism),
                        matched_pattern=rule.pattern,
                        tags=rule.tags,
                        raw_secret=(
                            self._extract_credential(line)[1] or matched
                            if rule.id in CREDENTIAL_RULE_IDS
                            else ""
                        ),
                        evidence=[{
                            "type": "regex_match",
                            "detail": (
                                f"Rule {rule.id} matched at {file_path}:{i} "
                                f"({mechanism}). Matched text: {matched[:200]!r}"
                            ),
                            "matched": matched[:500],
                            "line": i,
                            "column": match.start() + 1,
                        }],
                    )
                    findings.append(finding)

        return findings

    def _validate_match(self, rule: Rule, line: str) -> bool:
        """Post-validation to reject false positives a regex cannot express.

        For SQL injection (SEC001), a parameterized execute() call such as
        ``execute("SELECT ... %s", params)`` is safe even though the query
        string contains a ``%s`` placeholder, so we drop those matches.

        Credential rules must not duplicate format-specific
        secrets (reported by the secrets scanner) or password assignments
        (reported as SEC_PASSWORD_ASSIGNMENT).

        XSS sinks (SEC004/SEC005) assigned a pure static string contain no
        user input and are not vulnerabilities.
        """
        if rule.id == "SEC001":
            return self._validate_sql_injection(line)
        if rule.id in CREDENTIAL_RULE_IDS:
            return self._validate_credential_match(line)
        if rule.id in XSS_RULE_IDS:
            return not self._is_static_html_rhs(line)
        return True

    def _validate_sql_injection(self, line: str) -> bool:
        # If the query string is interpolated (f-string, concatenation,
        # .format(), or %-formatting) it is dangerous regardless of whether an
        # extra bind-parameter argument is also present.
        interpolated = re.search(
            r'f["\']|["\']\s*\+|\.\s*format\s*\(|["\']\s*%\s*[a-zA-Z(]',
            line,
        )
        if interpolated:
            return True
        # Static literal query: parameterized call is safe when the second
        # argument is a literal dict/tuple/list or an identifier that receives
        # the bind parameters.
        param_call = re.search(
            r"(?:execute|executemany|executescript)\s*\([^)\n]*,\s*"
            r"(?:\{[^}]*\}|\([^)]*\)|\[[^\]]*\]|self\.\w+|[a-zA-Z_]\w*)\s*\)\s*$",
            line,
        )
        return not param_call

    def _extract_credential(self, line: str) -> tuple[str, str]:
        """Return (varname_lower, value) for a credential assignment line."""
        m = _CREDENTIAL_ASSIGNMENT.search(line)
        if not m:
            return "", ""
        return m.group(1).lower(), m.group(2)

    def _validate_credential_match(self, line: str) -> bool:
        if self.suppress_secret_rules:
            return False
        from ..core.secret_signals import known_format_label

        varname, value = self._extract_credential(line)
        if not value:
            return True
        if any(varname == k or varname.endswith(f"_{k}") for k in ("password", "passwd", "pwd")):
            return False
        return not known_format_label(value.strip())

    def _is_static_html_rhs(self, line: str) -> bool:
        """True when the sink is assigned a pure static string literal.

        A React ``{{__html: "..."}}`` or ``element.innerHTML = "..."`` with no
        interpolation carries no user input, so it is not a DOM-XSS sink.
        """
        eq = line.find("=")
        if eq < 0:
            return False
        rhs = line[eq + 1:].strip()
        if rhs.startswith("{{__html:"):
            end = rhs.find("}}")
            if end < 0:
                return False
            inner = rhs[len("{{__html:"):end].strip()
        elif rhs.startswith("{__html:"):
            end = rhs.find("}")
            if end < 0:
                return False
            inner = rhs[len("{__html:"):end].strip()
        else:
            inner = rhs.rstrip(";").strip()
        if not inner:
            return False
        if (inner.startswith('"') and inner.endswith('"')) or (
            inner.startswith("'") and inner.endswith("'")
        ):
            body = inner[1:-1]
            return "{" not in body and "}" not in body and "+" not in body and "$" not in body
        return False

    def _detect_mechanism(self, rule: Rule, matched: str) -> str:
        if rule.id == "SEC001":
            if matched.startswith(("execute", "executemany", "executescript")) and re.search(r"f[\"']", matched):
                return "f-string interpolation"
            if re.search(r"\.\s*format\s*\(", matched):
                return ".format() interpolation"
            if re.search(r"[\"']\s*%\s*[a-zA-Z(]", matched):
                return "% string formatting"
            if re.search(r"[\"']\s*\+", matched):
                return "string concatenation"
        return "string formatting"

    def _get_context(self, lines: list[str], idx: int, context: int = 2) -> str:
        start = max(0, idx - context)
        end = min(len(lines), idx + context + 1)
        return "\n".join(lines[start:end])

    def _extract_function(self, lines: list[str], idx: int) -> str:
        for i in range(idx, max(0, idx - 30), -1):
            line = lines[i].strip()
            m = re.match(r'(?:def|function|func|fn|public|private|protected|static)\s+(\w+)', line)
            if m:
                return m.group(1)
        return ""

    def _explain(self, rule: Rule, snippet: str, matched: str, file_path: str, line: int, mechanism: str) -> str:
        safe = f"`{matched[:160]}`"
        return (
            f"Rule {rule.id} ({rule.title}) matched at {file_path}:{line}.\n\n"
            f"The code `{safe}` builds a SQL query using {mechanism}. Because the "
            f"interpolated value is injected into the statement before the driver "
            f"binds any parameters, an attacker-controlled value can alter the "
            f"structure of the query (e.g. terminate the statement and append a "
            f"new one). This enables {rule.description.lower()}"
        )

    def _confidence_reasoning(self, rule: Rule, matched: str, line: int, mechanism: str) -> str:
        return (
            f"Detected via pattern matching on line {line} ({mechanism}); the matched "
            f"fragment was {matched[:120]!r}. Confidence reflects the rule default "
            f"({rule.confidence:.0%}) for regex-level detection."
        )
