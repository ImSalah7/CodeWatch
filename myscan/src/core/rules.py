"""Scanner rules with CWE, OWASP, and CVSS mappings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import CVSS, FindingCategory, Language, OWASPTop10, Severity


@dataclass
class Rule:
    id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    category: FindingCategory
    cwe: str = ""
    cwe_name: str = ""
    owasp: Optional[OWASPTop10] = None
    languages: list[Language] = field(default_factory=list)
    fix_suggestion: str = ""
    references: list[str] = field(default_factory=list)
    impact: str = ""
    pattern: str = ""
    pattern_type: str = "regex"
    tags: list[str] = field(default_factory=list)
    cvss_config: dict[str, str] = field(default_factory=dict)

    def get_cvss(self) -> CVSS:
        cvss = CVSS()
        if self.cvss_config:
            cvss.calculate(**self.cvss_config)
        return cvss


def _build_rules() -> list[Rule]:
    rules: list[Rule] = []

    def r(id, title, desc, sev, conf, cat, cwe="", cwe_name="", owasp=None,
          langs=None, fix="", refs=None, impact="", pattern="", tags=None, cvss=None):
        rules.append(Rule(
            id=id, title=title, description=desc, severity=sev, confidence=conf,
            category=cat, cwe=cwe, cwe_name=cwe_name, owasp=owasp,
            languages=langs or [], fix_suggestion=fix, references=refs or [],
            impact=impact, pattern=pattern, tags=tags or [], cvss_config=cvss or {},
        ))

    # ── INJECTION (A03) ──
    r("SEC001", "SQL Injection via String Formatting",
      "User input may be interpolated directly into a SQL query string, allowing SQL injection attacks.",
      Severity.CRITICAL, 0.9, FindingCategory.SECURITY,
      "CWE-89", "SQL Injection", OWASPTop10.A03_INJECTION,
      [Language.PYTHON, Language.JAVA, Language.PHP, Language.CSHARP],
      "Use parameterized queries or an ORM instead of string formatting.",
      ["https://cwe.mitre.org/data/definitions/89.html", "https://owasp.org/Top10/A03_2021-Injection/"],
      "An attacker could execute arbitrary SQL commands, read/modify/delete all data, or escalate privileges.",
      pattern=r'execute\s*\(\s*(f["\']|["\'].*\%|["\'].*\{)|f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{|["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*',
      cvss={"attack_vector": "N", "attack_complexity": "L", "privileges": "N", "user_interaction": "N", "scope": "C", "confidentiality": "H", "integrity": "H", "availability": "H"})

    r("SEC002", "OS Command Injection",
      "User input may be passed to OS command execution, allowing arbitrary command injection.",
      Severity.CRITICAL, 0.95, FindingCategory.SECURITY,
      "CWE-78", "OS Command Injection", OWASPTop10.A03_INJECTION,
      [Language.PYTHON, Language.PHP, Language.RUBY, Language.GO],
      "Avoid os.system(). Use subprocess.run() with shell=False and validated input lists.",
      ["https://cwe.mitre.org/data/definitions/78.html"],
      "Full system compromise. Attacker can execute any OS command with the application's privileges.",
      pattern=r'os\.system\s*\(|os\.popen\s*\(|subprocess\.call.*shell\s*=\s*True|subprocess\.Popen.*shell\s*=\s*True',
      cvss={"attack_vector": "N", "attack_complexity": "L", "privileges": "N", "user_interaction": "N", "scope": "C", "confidentiality": "H", "integrity": "H", "availability": "H"})

    r("SEC003", "Code Injection via eval()",
      "Use of eval() on potentially user-controlled input enables arbitrary code execution.",
      Severity.CRITICAL, 0.9, FindingCategory.SECURITY,
      "CWE-94", "Code Injection", OWASPTop10.A03_INJECTION,
      [Language.PYTHON, Language.JAVASCRIPT, Language.PHP],
      "Never use eval(). Use ast.literal_eval() for data parsing or explicit function dispatch.",
      ["https://cwe.mitre.org/data/definitions/94.html"],
      "Complete application takeover through arbitrary code execution.",
      pattern=r'(?<!\w)eval\s*\(|(?<!\w)exec\s*\(',
      cvss={"attack_vector": "N", "attack_complexity": "L", "privileges": "N", "user_interaction": "N", "scope": "C", "confidentiality": "H", "integrity": "H", "availability": "H"})

    r("SEC004", "XSS via innerHTML Assignment",
      "Assigning unsanitized input to innerHTML creates a DOM-based XSS vulnerability.",
      Severity.HIGH, 0.85, FindingCategory.SECURITY,
      "CWE-79", "Cross-site Scripting", OWASPTop10.A03_INJECTION,
      [Language.JAVASCRIPT, Language.TYPESCRIPT],
      "Use textContent instead of innerHTML, or sanitize with DOMPurify.",
      ["https://cwe.mitre.org/data/definitions/79.html"],
      "Session hijacking, credential theft, phishing, malware distribution.",
      pattern=r'\.innerHTML\s*=',
      cvss={"attack_vector": "N", "attack_complexity": "L", "privileges": "N", "user_interaction": "R", "scope": "U", "confidentiality": "L", "integrity": "L", "availability": "N"})

    r("SEC005", "XSS via dangerouslySetInnerHTML (React)",
      "dangerouslySetInnerHTML bypasses React's XSS protections when used with user data.",
      Severity.HIGH, 0.8, FindingCategory.SECURITY,
      "CWE-79", "Cross-site Scripting", OWASPTop10.A03_INJECTION,
      [Language.JAVASCRIPT, Language.TYPESCRIPT],
      "Use React's JSX rendering. If HTML is needed, sanitize with DOMPurify first.",
      ["https://cwe.mitre.org/data/definitions/79.html"],
      "Client-side attacks including session hijacking and data theft.",
      pattern=r'dangerouslySetInnerHTML')

    r("SEC006", "Unsafe Deserialization (pickle)",
      "Loading untrusted data with pickle can execute arbitrary code during deserialization.",
      Severity.CRITICAL, 0.9, FindingCategory.SECURITY,
      "CWE-502", "Deserialization of Untrusted Data", OWASPTop10.A08_DATA_INTEGRITY_FAILURES,
      [Language.PYTHON],
      "Use json or msgpack for serialization. If pickle is required, use RestrictedUnpickler.",
      ["https://cwe.mitre.org/data/definitions/502.html"],
      "Remote code execution. An attacker can craft a malicious pickle payload.",
      pattern=r'pickle\.loads?\s*\(|shelve\.open\s*\(')

    r("SEC007", "Unsafe YAML Deserialization",
      "yaml.load() without a SafeLoader allows arbitrary Python object instantiation.",
      Severity.HIGH, 0.85, FindingCategory.SECURITY,
      "CWE-502", "Deserialization of Untrusted Data", OWASPTop10.A08_DATA_INTEGRITY_FAILURES,
      [Language.PYTHON],
      "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
      ["https://cwe.mitre.org/data/definitions/502.html"],
      "Remote code execution through crafted YAML payloads.",
      pattern=r'yaml\.load\s*\((?!.*Loader)')

    r("SEC008", "Path Traversal",
      "User-controlled file paths without sanitization may allow reading arbitrary files.",
      Severity.HIGH, 0.75, FindingCategory.SECURITY,
      "CWE-22", "Path Traversal", OWASPTop10.A01_BROKEN_ACCESS_CONTROL,
      [Language.PYTHON, Language.JAVA, Language.GO, Language.PHP, Language.CSHARP],
      "Use os.path.realpath() and verify the path starts with the expected base directory.",
      ["https://cwe.mitre.org/data/definitions/22.html"],
      "Read arbitrary files including credentials, source code, and system files.",
      pattern=r'open\s*\([^)]*(?:request|input|args|params|argv)',
      cvss={"attack_vector": "N", "attack_complexity": "L", "privileges": "N", "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "N", "availability": "N"})

    r("SEC009", "Server-Side Request Forgery (SSRF)",
      "User-controlled URLs passed to HTTP clients may allow requests to internal services.",
      Severity.HIGH, 0.75, FindingCategory.SECURITY,
      "CWE-918", "Server-Side Request Forgery", OWASPTop10.A10_SSRF,
      [Language.PYTHON, Language.JAVA, Language.GO, Language.PHP, Language.CSHARP],
      "Validate and whitelist allowed URLs. Block internal/private IP ranges.",
      ["https://cwe.mitre.org/data/definitions/918.html"],
      "Access internal services, cloud metadata endpoints, and internal APIs.",
      pattern=r'requests\.(get|post|put|delete|head|patch)\s*\([^)]*(?:request|input|args|params|url_param)',
      cvss={"attack_vector": "N", "attack_complexity": "L", "privileges": "N", "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "N", "availability": "N"})

    r("SEC010", "XML External Entity (XXE)",
      "XML parsing without disabling external entities can lead to file disclosure and SSRF.",
      Severity.HIGH, 0.8, FindingCategory.SECURITY,
      "CWE-611", "XML External Entity", OWASPTop10.A05_SECURITY_MISCONFIGURATION,
      [Language.PYTHON, Language.JAVA, Language.PHP, Language.CSHARP],
      "Use defusedxml library. For Java, set FEATURE_SECURE_PROCESSING.",
      ["https://cwe.mitre.org/data/definitions/611.html"],
      "Read local files, perform SSRF, and cause denial of service.",
      pattern=r'xml\.etree\.ElementTree\.parse\s*\(|xml\.dom\.minidom\.parse\s*\(|xml\.sax\.parse\s*\(|lxml\.etree\.parse\s*\(')

    # ── CRYPTOGRAPHIC FAILURES (A02) ──
    r("SEC011", "Weak Cryptographic Hash (MD5/SHA1)",
      "MD5 and SHA1 are cryptographically broken and should not be used for security purposes.",
      Severity.MEDIUM, 0.8, FindingCategory.SECURITY,
      "CWE-328", "Use of Weak Hash", OWASPTop10.A02_CRYPTOGRAPHIC_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.GO, Language.PHP, Language.CSHARP],
      "Use SHA-256, SHA-3, or bcrypt/scrypt for password hashing.",
      ["https://cwe.mitre.org/data/definitions/328.html"],
      "Collision attacks could forge certificates, tokens, or file integrity checks.",
      pattern=r'(?:hashlib\.md5|hashlib\.sha1|MD5\.getInstance|MessageDigest\.getInstance\s*\(\s*["\']MD5|crypto\.createHash\s*\(\s*["\']md5|createHash\s*\(\s*["\']sha1)')

    r("SEC012", "SSL/TLS Certificate Verification Disabled",
      "Disabling certificate verification allows man-in-the-middle attacks.",
      Severity.HIGH, 0.9, FindingCategory.SECURITY,
      "CWE-295", "Improper Certificate Validation", OWASPTop10.A02_CRYPTOGRAPHIC_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.GO, Language.PHP],
      "Never disable SSL verification in production. Configure proper CA certificates.",
      ["https://cwe.mitre.org/data/definitions/295.html"],
      "Attackers can intercept, modify, and replay all HTTPS traffic.",
      pattern=r'verify\s*=\s*False|SSL_VERIFY\s*=\s*false|InsecureRequestWarning|CHECK_CERT_HOSTNAME\s*=\s*false',
      cvss={"attack_vector": "A", "attack_complexity": "L", "privileges": "N", "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "H", "availability": "N"})

    r("SEC013", "Use of ECB Mode Cipher",
      "ECB mode encrypts identical plaintext blocks to identical ciphertext, leaking patterns.",
      Severity.MEDIUM, 0.8, FindingCategory.SECURITY,
      "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", OWASPTop10.A02_CRYPTOGRAPHIC_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.PHP],
      "Use CBC, GCM, or other authenticated encryption modes.",
      ["https://cwe.mitre.org/data/definitions/327.html"],
      "Pattern analysis of encrypted data reveals plaintext structure.",
      pattern=r'AES\.new\s*\([^)]*MODE_ECB|DES\.new\s*\([^)]*MODE_ECB|DESede\.getInstance')

    # ── SECURITY MISCONFIGURATION (A05) ──
    r("SEC014", "Flask/Django Debug Mode Enabled",
      "Running with debug mode in production exposes sensitive stack traces and enables the debugger.",
      Severity.HIGH, 0.95, FindingCategory.SECURITY,
      "CWE-489", "Active Debug Code", OWASPTop10.A05_SECURITY_MISCONFIGURATION,
      [Language.PYTHON, Language.JAVA],
      "Set DEBUG=False in production. Use environment variables for configuration.",
      ["https://cwe.mitre.org/data/definitions/489.html"],
      "Information disclosure, remote code execution via debug console.",
      pattern=r'DEBUG\s*=\s*True|debug\s*=\s*True|FLASK_DEBUG\s*=\s*1',
      cvss={"attack_vector": "N", "attack_complexity": "L", "privileges": "N", "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "L", "availability": "N"})

    r("SEC015", "CORS Wildcard Origin",
      "CORS allow-all origins permits any website to make authenticated requests.",
      Severity.MEDIUM, 0.85, FindingCategory.SECURITY,
      "CWE-942", "Permissive Cross-domain Policy", OWASPTop10.A05_SECURITY_MISCONFIGURATION,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.GO],
      "Whitelist specific trusted origins instead of using *.",
      ["https://cwe.mitre.org/data/definitions/942.html"],
      "Cross-origin data theft and CSRF attacks against authenticated users.",
      pattern=r'Access-Control-Allow-Origin.*\*|CORS_ORIGINS.*\*|allow_origins\s*=\s*\[.*\*|cors\.origin\s*=\s*["\']\*')

    r("SEC016", "Missing Security Headers",
      "Response headers are missing critical security protections.",
      Severity.MEDIUM, 0.7, FindingCategory.SECURITY,
      "CWE-693", "Protection Mechanism Failure", OWASPTop10.A05_SECURITY_MISCONFIGURATION,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.GO],
      "Add X-Content-Type-Options, X-Frame-Options, CSP, HSTS headers.",
      ["https://cwe.mitre.org/data/definitions/693.html"],
      "Clickjacking, MIME sniffing attacks, content injection.",
      pattern=r'X-Frame-Options|Content-Security-Policy|X-Content-Type-Options|Strict-Transport-Security')

    # ── BROKEN ACCESS CONTROL (A01) ──
    r("SEC017", "Hardcoded Password/Secret",
      "Passwords or secrets embedded directly in source code can be extracted by anyone with access.",
      Severity.CRITICAL, 0.85, FindingCategory.SECURITY,
      "CWE-798", "Use of Hard-coded Credentials", OWASPTop10.A01_BROKEN_ACCESS_CONTROL,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.GO, Language.PHP, Language.CSHARP, Language.RUBY],
      "Store credentials in environment variables or a secrets manager.",
      ["https://cwe.mitre.org/data/definitions/798.html"],
      "Account takeover, data breach, lateral movement.",
      pattern=r'(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{8,}',
      tags=["credentials"])

    r("SEC018", "Open Redirect",
      "User-controlled redirect URLs may redirect victims to malicious sites for phishing.",
      Severity.MEDIUM, 0.7, FindingCategory.SECURITY,
      "CWE-601", "Open Redirect", OWASPTop10.A01_BROKEN_ACCESS_CONTROL,
      [Language.PYTHON, Language.JAVA, Language.PHP, Language.JAVASCRIPT],
      "Validate redirect targets against a whitelist of allowed domains.",
      ["https://cwe.mitre.org/data/definitions/601.html"],
      "Phishing, credential theft, malware distribution.",
      pattern=r'redirect\s*\(\s*(?:request|args|params|input)',
      cvss={"attack_vector": "N", "attack_complexity": "L", "privileges": "N", "user_interaction": "R", "scope": "U", "confidentiality": "L", "integrity": "N", "availability": "N"})

    r("SEC019", "Insecure Random Number Generator",
      "Using predictable random number generators for security-sensitive operations.",
      Severity.MEDIUM, 0.7, FindingCategory.SECURITY,
      "CWE-330", "Use of Insufficiently Random Values", OWASPTop10.A02_CRYPTOGRAPHIC_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.PHP],
      "Use secrets module (Python), SecureRandom (Java), crypto.randomBytes (JS).",
      ["https://cwe.mitre.org/data/definitions/330.html"],
      "Predictable tokens, session IDs, and cryptographic keys.",
      pattern=r'(?<!\w)random\.(?:random|randint|choice|randrange|sample)\s*\(',
      tags=["crypto"])

    # ── VULNERABLE COMPONENTS (A06) ──
    r("SEC020", "Regex Denial of Service (ReDoS)",
      "Catastrophic backtracking in regex patterns can cause denial of service.",
      Severity.MEDIUM, 0.6, FindingCategory.SECURITY,
      "CWE-1333", "Inefficient Regular Expression Complexity", OWASPTop10.A06_VULNERABLE_COMPONENTS,
      [Language.PYTHON, Language.JAVASCRIPT, Language.JAVA, Language.PHP, Language.GO],
      "Simplify regex patterns. Avoid nested quantifiers. Use re2 library.",
      ["https://cwe.mitre.org/data/definitions/1333.html"],
      "Denial of service through CPU exhaustion on crafted input.",
      pattern=r're\.compile\s*\([^)]*(?:\.\*){2,}|re\.compile\s*\([^)]*(?:\+\.*)|(?:\.\*)\+')

    r("SEC021", "LDAP Injection",
      "Unsanitized input in LDAP queries allows injection of arbitrary LDAP statements.",
      Severity.HIGH, 0.75, FindingCategory.SECURITY,
      "CWE-90", "LDAP Injection", OWASPTop10.A03_INJECTION,
      [Language.PYTHON, Language.JAVA, Language.PHP, Language.CSHARP],
      "Use parameterized LDAP queries and escape special characters.",
      ["https://cwe.mitre.org/data/definitions/90.html"],
      "Authentication bypass, data exposure, directory manipulation.",
      pattern=r'ldap\.search_s\s*\([^)]*(?:request|input|args)|ldap_search_ext_s\s*\(')

    r("SEC022", "NoSQL Injection",
      "Unsanitized input in NoSQL queries allows injection of operator expressions.",
      Severity.HIGH, 0.75, FindingCategory.SECURITY,
      "CWE-943", "Improper Neutralization of Special Elements in Data Query Logic", OWASPTop10.A03_INJECTION,
      [Language.PYTHON, Language.JAVASCRIPT],
      "Use parameterized queries. Validate and sanitize all input before query construction.",
      ["https://cwe.mitre.org/data/definitions/943.html"],
      "Authentication bypass, data exfiltration, data modification.",
      pattern=r'\.find\s*\(\s*\{[^}]*(?:request|input|args|\$where)|\.find_one\s*\(\s*\{')

    r("SEC023", "Mass Assignment",
      "Binding user input directly to model objects allows unauthorized field modification.",
      Severity.HIGH, 0.7, FindingCategory.SECURITY,
      "CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes", OWASPTop10.A01_BROKEN_ACCESS_CONTROL,
      [Language.PYTHON, Language.RUBY, Language.JAVASCRIPT],
      "Use explicit field allowlists. Never pass raw request data to model constructors.",
      ["https://cwe.mitre.org/data/definitions/915.html"],
      "Privilege escalation, unauthorized data modification.",
      pattern=r'create\s*\(\s*\*\*request\.|\.objects\.create\s*\(\s*\*\*request|Model\(\s*\*\*request\.',
      cvss={"attack_vector": "N", "attack_complexity": "L", "privileges": "N", "user_interaction": "N", "scope": "U", "confidentiality": "L", "integrity": "H", "availability": "N"})

    # ── LOGGING (A09) ──
    r("SEC024", "Log Injection",
      "Unsanitized user input in log messages can forge log entries or exploit log viewers.",
      Severity.MEDIUM, 0.6, FindingCategory.SECURITY,
      "CWE-117", "Improper Output Neutralization for Logs", OWASPTop10.A09_LOGGING_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.PHP],
      "Sanitize log input. Remove newlines and control characters before logging.",
      ["https://cwe.mitre.org/data/definitions/117.html"],
      "Log forgery, log injection attacks, disruption of log analysis.",
      pattern=r'logging\.(?:info|warning|error|debug)\s*\([^)]*(?:request|input|args)|logger\.(?:info|warning|error)\s*\([^)]*(?:request|input)')

    # ── INSECURE DESIGN (A04) ──
    r("SEC025", "Missing Rate Limiting",
      "No rate limiting on sensitive endpoints enables brute-force and enumeration attacks.",
      Severity.MEDIUM, 0.6, FindingCategory.SECURITY,
      "CWE-307", "Improper Restriction of Excessive Authentication Attempts", OWASPTop10.A04_INSECURE_DESIGN,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.GO],
      "Implement rate limiting with exponential backoff on authentication endpoints.",
      ["https://cwe.mitre.org/data/definitions/307.html"],
      "Credential stuffing, brute-force attacks, account enumeration.",
      tags=["authentication"])

    r("SEC026", "Missing Input Validation",
      "User input is processed without validation, enabling multiple attack vectors.",
      Severity.HIGH, 0.7, FindingCategory.SECURITY,
      "CWE-20", "Improper Input Validation", OWASPTop10.A03_INJECTION,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.GO, Language.PHP, Language.CSHARP],
      "Validate all input against a strict schema. Use allowlists over denylists.",
      ["https://cwe.mitre.org/data/definitions/20.html"],
      "Enables injection attacks, buffer overflows, and logic flaws.",
      tags=["validation"])

    r("SEC027", "Email Header Injection",
      "User input in email headers allows injection of additional headers or recipients.",
      Severity.HIGH, 0.7, FindingCategory.SECURITY,
      "CWE-644", "Improper Neutralization of HTTP Headers for Scripting Syntax", OWASPTop10.A03_INJECTION,
      [Language.PYTHON, Language.PHP, Language.RUBY],
      "Validate email addresses. Use proper email libraries that handle encoding.",
      ["https://cwe.mitre.org/data/definitions/644.html"],
      "Spam relay, phishing, information disclosure.",
      pattern=r'sendmail\s*\(|send_mail\s*\([^)]*(?:request|input)|\.from_header\s*=|email\.message')

    r("SEC028", "Weak Password Hashing",
      "Passwords are hashed with fast algorithms vulnerable to brute-force attacks.",
      Severity.HIGH, 0.8, FindingCategory.SECURITY,
      "CWE-916", "Use of Password Hash With Insufficient Computational Effort", OWASPTop10.A07_AUTH_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.PHP, Language.CSHARP],
      "Use bcrypt, scrypt, or argon2 with appropriate work factors.",
      ["https://cwe.mitre.org/data/definitions/916.html"],
      "Password cracking through rainbow tables or brute force.",
      pattern=r'hashlib\.(?:sha256|sha1|md5)\s*\(\s*(?:password|passwd|pwd)',
      tags=["authentication"])

    r("SEC029", "Disabled SSL Verification (HTTP Client)",
      "HTTP client requests with SSL verification disabled are vulnerable to MITM attacks.",
      Severity.HIGH, 0.85, FindingCategory.SECURITY,
      "CWE-295", "Improper Certificate Validation", OWASPTop10.A02_CRYPTOGRAPHIC_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.GO],
      "Enable SSL verification. Configure proper CA bundle for self-signed certificates.",
      ["https://cwe.mitre.org/data/definitions/295.html"],
      "Man-in-the-middle attacks, credential theft, data manipulation.",
      pattern=r'verify\s*=\s*False|VerifySSL\s*=\s*false|TLSClientConfig\s*\{[^}]*InsecureSkipVerify:\s*true')

    r("SEC030", "Prototype Pollution (JavaScript)",
      "Modifying Object.prototype enables property injection across all objects.",
      Severity.HIGH, 0.7, FindingCategory.SECURITY,
      "CWE-1321", "Improperly Controlled Modification of Object Prototype Attributes", OWASPTop10.A08_DATA_INTEGRITY_FAILURES,
      [Language.JAVASCRIPT, Language.TYPESCRIPT],
      "Use Object.create(null) for dictionaries. Validate and sanitize property names.",
      ["https://cwe.mitre.org/data/definitions/1321.html"],
      "Remote code execution, denial of service, property injection.",
      pattern=r'Object\.prototype|__proto__|constructor\s*\[|\.prototype\s*=')

    r("SEC031", "Zip Slip (Path Traversal via Archive)",
      "Extracting archive files without path validation allows writing to arbitrary locations.",
      Severity.HIGH, 0.8, FindingCategory.SECURITY,
      "CWE-22", "Path Traversal", OWASPTop10.A01_BROKEN_ACCESS_CONTROL,
      [Language.PYTHON, Language.JAVA, Language.GO, Language.CSHARP],
      "Validate that extracted paths remain within the target directory.",
      ["https://cwe.mitre.org/data/definitions/22.html"],
      "Arbitrary file write leading to code execution or denial of service.",
      pattern=r'ZipFile|zipfile\.extract|\.extractall|tarfile\.extract|ZipFile\.extractall')

    r("SEC032", "Insecure Temporary File",
      "Creating predictable temporary files enables symlink attacks and data leakage.",
      Severity.LOW, 0.5, FindingCategory.SECURITY,
      "CWE-377", "Insecure Temporary File", OWASPTop10.A05_SECURITY_MISCONFIGURATION,
      [Language.PYTHON, Language.JAVA, Language.PHP],
      "Use tempfile.mkstemp() or tempfile.TemporaryFile() for secure temporary files.",
      ["https://cwe.mitre.org/data/definitions/377.html"],
      "Information disclosure, privilege escalation via symlink attacks.",
      pattern=r'tempfile\.mktemp\s*\(|os\.tmpnam\s*\(|tmp/[^"\']*\.(?:tmp|temp)')

    r("SEC033", "Insufficient Session Expiration",
      "Session tokens without proper expiration allow indefinite account access.",
      Severity.MEDIUM, 0.6, FindingCategory.SECURITY,
      "CWE-613", "Insufficient Session Expiration", OWASPTop10.A07_AUTH_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.PHP, Language.JAVASCRIPT],
      "Set session timeout. Implement idle timeout and absolute expiration.",
      ["https://cwe.mitre.org/data/definitions/613.html"],
      "Session hijacking, unauthorized access after user logout.",
      tags=["session"])

    r("SEC034", "Clickjacking (Missing X-Frame-Options)",
      "Without X-Frame-Options or CSP frame-ancestors, pages can be framed by attackers.",
      Severity.MEDIUM, 0.65, FindingCategory.SECURITY,
      "CWE-1021", "Improper Restriction of Rendered UI Layers", OWASPTop10.A05_SECURITY_MISCONFIGURATION,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.GO],
      "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
      ["https://cwe.mitre.org/data/definitions/1021.html"],
      "Clickjacking attacks tricking users into clicking unintended UI elements.",
      tags=["headers"])

    r("SEC035", "Race Condition (TOCTOU)",
      "Time-of-check to time-of-use gaps allow state changes between validation and action.",
      Severity.HIGH, 0.6, FindingCategory.SECURITY,
      "CWE-367", "Time-of-check Time-of-use (TOCTOU) Race Condition", OWASPTop10.A04_INSECURE_DESIGN,
      [Language.PYTHON, Language.JAVA, Language.GO, Language.C, Language.CPP],
      "Use atomic operations, locks, or database transactions for critical sections.",
      ["https://cwe.mitre.org/data/definitions/367.html"],
      "Privilege escalation, data corruption, double-spending.",
      pattern=r'if\s+os\.path\.exists|\.exists\(\).*open\(',
      tags=["race_condition"])

    r("SEC036", "Buffer Overflow Pattern",
      "Unbounded memory operations may allow overwriting adjacent memory.",
      Severity.CRITICAL, 0.7, FindingCategory.SECURITY,
      "CWE-120", "Buffer Copy without Checking Size of Input", OWASPTop10.A04_INSECURE_DESIGN,
      [Language.C, Language.CPP],
      "Use bounded string functions (strncpy, strncat). Use modern safe abstractions.",
      ["https://cwe.mitre.org/data/definitions/120.html"],
      "Remote code execution, denial of service, privilege escalation.",
      pattern=r'gets\s*\(|sprintf\s*\(|strcpy\s*\(|strcat\s*\(|memcpy\s*\(')

    r("SEC037", "Unsafe File Upload",
      "File uploads without proper validation may allow malicious file execution.",
      Severity.HIGH, 0.75, FindingCategory.SECURITY,
      "CWE-434", "Unrestricted Upload of File with Dangerous Type", OWASPTop10.A04_INSECURE_DESIGN,
      [Language.PYTHON, Language.PHP, Language.JAVA, Language.JAVASCRIPT],
      "Validate file type by content, not extension. Store uploads outside webroot.",
      ["https://cwe.mitre.org/data/definitions/434.html"],
      "Remote code execution through webshell upload.",
      tags=["upload"])

    r("SEC038", "Authorization Bypass",
      "Missing or incorrect authorization checks allow unauthorized access to resources.",
      Severity.CRITICAL, 0.8, FindingCategory.SECURITY,
      "CWE-862", "Missing Authorization", OWASPTop10.A01_BROKEN_ACCESS_CONTROL,
      [Language.PYTHON, Language.JAVA, Language.PHP, Language.JAVASCRIPT, Language.GO],
      "Implement authorization checks on every endpoint. Use RBAC/ABAC.",
      ["https://cwe.mitre.org/data/definitions/862.html"],
      "Unauthorized access to any resource, privilege escalation.",
      tags=["authorization"])

    r("SEC039", "Broken JWT Validation",
      "JWT tokens without proper validation may allow authentication bypass.",
      Severity.HIGH, 0.8, FindingCategory.SECURITY,
      "CWE-347", "Improper Verification of Cryptographic Signature", OWASPTop10.A07_AUTH_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT],
      "Validate signature, algorithm, expiration, and issuer. Never use 'none' algorithm.",
      ["https://cwe.mitre.org/data/definitions/347.html"],
      "Authentication bypass, token forgery, impersonation.",
      pattern=r'jwt\.decode\s*\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[.*none|JwtHandler.*none',
      tags=["authentication", "jwt"])

    r("SEC040", "CSRF Vulnerability",
      "State-changing endpoints missing CSRF tokens allow cross-site request forgery.",
      Severity.MEDIUM, 0.7, FindingCategory.SECURITY,
      "CWE-352", "Cross-Site Request Forgery", OWASPTop10.A01_BROKEN_ACCESS_CONTROL,
      [Language.PYTHON, Language.PHP, Language.JAVASCRIPT],
      "Implement CSRF tokens. Use SameSite cookie attribute. Verify Origin header.",
      ["https://cwe.mitre.org/data/definitions/352.html"],
      "Unauthorized state changes, account takeover in some cases.",
      tags=["csrf"])

    r("SEC041", "Weak Cipher (DES/RC4)",
      "DES (56-bit) and RC4 are cryptographically broken ciphers.",
      Severity.HIGH, 0.85, FindingCategory.SECURITY,
      "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", OWASPTop10.A02_CRYPTOGRAPHIC_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.C, Language.CPP],
      "Use AES-256-GCM or ChaCha20-Poly1305.",
      ["https://cwe.mitre.org/data/definitions/327.html"],
      "Encrypted data can be decrypted through cryptanalysis.",
      pattern=r'DES\.new\s*\(|DES3\.new\s*\(|Cipher\.getInstance\s*\(\s*["\']DES|RC4|ARC4')

    r("SEC042", "Server-Side Includes (SSI) Injection",
      "Unvalidated input in SSI-enabled pages allows command execution.",
      Severity.HIGH, 0.7, FindingCategory.SECURITY,
      "CWE-97", "Improper Neutralization of Server-Side Includes", OWASPTop10.A03_INJECTION,
      [Language.PHP, Language.JAVA],
      "Disable SSI or validate/sanitize all user input before server-side processing.",
      ["https://cwe.mitre.org/data/definitions/97.html"],
      "Remote code execution on the web server.",
      tags=["injection"])

    r("SEC043", "Hardcoded AWS Access Key",
      "AWS access keys in source code can be used for unauthorized cloud access.",
      Severity.CRITICAL, 0.95, FindingCategory.SECURITY,
      "CWE-798", "Use of Hard-coded Credentials", OWASPTop10.A01_BROKEN_ACCESS_CONTROL,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.GO, Language.PHP, Language.CSHARP, Language.RUBY],
      "Use IAM roles, environment variables, or AWS Secrets Manager.",
      ["https://cwe.mitre.org/data/definitions/798.html"],
      "Full AWS account compromise, data theft, resource abuse.",
      pattern=r'AKIA[0-9A-Z]{16}',
      tags=["aws", "credentials"])

    r("SEC044", "Hardcoded Azure Key",
      "Azure storage keys or connection strings in source code enable unauthorized access.",
      Severity.CRITICAL, 0.9, FindingCategory.SECURITY,
      "CWE-798", "Use of Hard-coded Credentials", OWASPTop10.A01_BROKEN_ACCESS_CONTROL,
      [Language.PYTHON, Language.JAVA, Language.CSHARP],
      "Use Azure Managed Identity, Key Vault, or environment variables.",
      ["https://cwe.mitre.org/data/definitions/798.html"],
      "Unauthorized access to Azure storage, databases, and services.",
      pattern=r'DefaultEndpointsProtocol=https.*AccountKey=|AccountName=.*AccountKey=',
      tags=["azure", "credentials"])

    r("SEC045", "Hardcoded GitHub Token",
      "GitHub personal access tokens in code allow unauthorized repository access.",
      Severity.CRITICAL, 0.95, FindingCategory.SECURITY,
      "CWE-798", "Use of Hard-coded Credentials", OWASPTop10.A01_BROKEN_ACCESS_CONTROL,
      [],
      "Use GitHub Actions secrets, .env files, or credential helpers.",
      ["https://cwe.mitre.org/data/definitions/798.html"],
      "Repository compromise, code theft, supply chain attacks.",
      pattern=r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}',
      tags=["github", "credentials"])

    r("SEC046", "Hardcoded JWT Secret",
      "Hardcoded JWT signing secrets allow token forgery and authentication bypass.",
      Severity.CRITICAL, 0.9, FindingCategory.SECURITY,
      "CWE-798", "Use of Hard-coded Credentials", OWASPTop10.A07_AUTH_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT],
      "Store JWT secrets in environment variables or a secrets manager.",
      ["https://cwe.mitre.org/data/definitions/798.html"],
      "Full authentication bypass, impersonation of any user.",
      pattern=r'(?:jwt_secret|JWT_SECRET|SIGNING_KEY|token_secret)\s*=\s*["\'][^"\']{16,}',
      tags=["jwt", "credentials"])

    # ── SECURITY LOGGING (A09) ──
    r("SEC047", "Missing Security Logging",
      "Security-critical events (login, access control) are not being logged.",
      Severity.LOW, 0.5, FindingCategory.SECURITY,
      "CWE-778", "Insufficient Logging", OWASPTop10.A09_LOGGING_FAILURES,
      [Language.PYTHON, Language.JAVA, Language.PHP, Language.JAVASCRIPT],
      "Log all authentication events, access control failures, and input validation errors.",
      ["https://cwe.mitre.org/data/definitions/778.html"],
      "Delayed breach detection, inability to perform forensics.",
      tags=["logging"])

    # ── CODE QUALITY ──
    r("QLT001", "Long Line (>120 characters)",
      "Lines exceeding 120 characters reduce readability and maintainability.",
      Severity.INFO, 1.0, FindingCategory.QUALITY,
      "", "", None, [],
      "Break long lines using line continuation, intermediate variables, or refactoring.",
      impact="Reduced code readability and increased merge conflict likelihood.",
      tags=["style"])

    r("QLT002", "TODO/FIXME Comment",
      "Unresolved technical debt markers found in code.",
      Severity.INFO, 1.0, FindingCategory.QUALITY,
      "", "", None, [],
      "Address the TODO/FIXME or create a tracked issue.",
      impact="Technical debt accumulation.",
      pattern=r'#\s*(?:TODO|FIXME|HACK|XXX|TEMP)\b|//\s*(?:TODO|FIXME|HACK|XXX|TEMP)\b',
      tags=["debt"])

    r("QLT003", "Empty Exception Handler",
      "Silent exception handling hides errors and makes debugging difficult.",
      Severity.LOW, 0.8, FindingCategory.QUALITY,
      "CWE-390", "Detection of Error Condition Without Action", None,
      [Language.PYTHON, Language.JAVA, Language.JAVASCRIPT, Language.CSHARP],
      "Log the exception or re-raise it. Never silently swallow exceptions.",
      ["https://cwe.mitre.org/data/definitions/390.html"],
      "Silent failures, data corruption, security bypass.",
      pattern=r'except\s*(?:Exception|\w+Error)?\s*:\s*(?:pass|\.\.\.)|catch\s*\(\s*\w+\s*\)\s*\{\s*\}',
      tags=["error_handling"])

    r("QLT004", "Bare Except Clause",
      "Catching all exceptions including SystemExit and KeyboardInterrupt.",
      Severity.LOW, 0.7, FindingCategory.QUALITY,
      "CWE-396", "Catch Generic Exception", None,
      [Language.PYTHON],
      "Catch specific exceptions instead of using bare except.",
      ["https://cwe.mitre.org/data/definitions/396.html"],
      "Masked errors, difficulty debugging, security issues.",
      pattern=r'except\s*:')

    r("QLT005", "Global Variable Usage",
      "Global mutable state creates hidden dependencies and testing difficulties.",
      Severity.LOW, 0.6, FindingCategory.QUALITY,
      "CWE-710", "Improper Adherence to Coding Standards", None,
      [Language.PYTHON, Language.JAVASCRIPT],
      "Use dependency injection, class attributes, or function parameters.",
      impact="Reduced testability, hidden coupling, race conditions.",
      pattern=r'^global\s+\w+|^\s*var\s+\w+\s*(?:=\s*[^=]|\s*$)')

    r("QLT006", "Deep Nesting (>4 levels)",
      "Deeply nested code is hard to read, test, and maintain.",
      Severity.INFO, 0.9, FindingCategory.QUALITY,
      "", "", None, [],
      "Extract nested logic into helper functions. Use early returns.",
      impact="Reduced maintainability and increased cognitive complexity.",
      tags=["complexity"])

    r("QLT007", "Magic Number",
      "Unexplained numeric literals in code should be named constants.",
      Severity.INFO, 0.7, FindingCategory.QUALITY,
      "", "", None, [],
      "Extract magic numbers into named constants with descriptive names.",
      impact="Reduced code readability and maintainability.",
      tags=["readability"])

    r("QLT008", "Duplicate Code Block",
      "Repeated code blocks increase maintenance burden and bug risk.",
      Severity.LOW, 0.7, FindingCategory.QUALITY,
      "CWE-1164", "Unnecessary Code", None, [],
      "Extract duplicated code into shared functions or utilities.",
      ["https://cwe.mitre.org/data/definitions/1164.html"],
      "Inconsistent bug fixes, increased maintenance cost.",
      tags=["duplication"])

    r("QLT009", "Unused Import",
      "Imported modules that are never referenced increase load time and clutter.",
      Severity.INFO, 0.9, FindingCategory.QUALITY,
      "", "", None, [],
      "Remove unused imports.",
      impact="Code clutter, slightly increased load time.",
      tags=["cleanup"])

    r("QLT010", "Commented-Out Code",
      "Dead code left as comments should be removed and tracked in version control.",
      Severity.INFO, 0.8, FindingCategory.QUALITY,
      "", "", None, [],
      "Remove commented code. Use version control history if needed.",
      impact="Code clutter, confusion about active functionality.",
      tags=["cleanup"])

    return rules


ALL_RULES: list[Rule] = _build_rules()
RULE_MAP: dict[str, Rule] = {r.id: r for r in ALL_RULES}

PYTHON_RULES = [r for r in ALL_RULES if Language.PYTHON in r.languages or not r.languages]
JS_RULES = [r for r in ALL_RULES if Language.JAVASCRIPT in r.languages or not r.languages]
JAVA_RULES = [r for r in ALL_RULES if Language.JAVA in r.languages or not r.languages]
GO_RULES = [r for r in ALL_RULES if Language.GO in r.languages or not r.languages]
C_CPP_RULES = [r for r in ALL_RULES if r.languages and Language.C in r.languages]
PHP_RULES = [r for r in ALL_RULES if Language.PHP in r.languages or not r.languages]
