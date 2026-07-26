# MyScan Security Report

**Generated:** 2026-07-21 17:02:24 UTC
**Repository:** .
**Risk Score:** 100/100

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 10 |
| High     | 8 |
| Medium   | 0 |
| Low      | 0 |
| Info     | 0 |
| **Total** | **18** |

## Findings by File

| File | Issues |
|------|--------|
| `tests\test_secret_scanner.py` | 17 |
| `tests\test_report_generator.py` | 1 |

---

## Detailed Findings

### 1. AWS Access Key ID

- **Severity:** [red]CRITICAL[/red]
- **Confidence:** 95%
- **File:** `tests\test_report_generator.py`
- **Line:** 79
- **Type:** aws_access_key
- **Entropy:** 3.68

**Matched:**
```
AKIAIOSFODNN7EXAMPLE
```

### 2. AWS Access Key ID

- **Severity:** [red]CRITICAL[/red]
- **Confidence:** 95%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 43
- **Type:** aws_access_key
- **Entropy:** 3.68

**Matched:**
```
AKIAIOSFODNN7EXAMPLE
```

### 3. GitHub Personal Access Token

- **Severity:** [red]CRITICAL[/red]
- **Confidence:** 95%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 50
- **Type:** github_token
- **Entropy:** 5.22

**Matched:**
```
ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
```

### 4. Private Key

- **Severity:** [red]CRITICAL[/red]
- **Confidence:** 99%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 56
- **Type:** private_key
- **Entropy:** 3.38

**Matched:**
```
-----BEGIN RSA PRIVATE KEY-----
```

### 5. Slack Token

- **Severity:** [red]CRITICAL[/red]
- **Confidence:** 90%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 63
- **Type:** slack_token
- **Entropy:** 4.51

**Matched:**
```
xoxb-1234567890-1234567890123-AbCdEfGhIjKl
```

### 6. Google API Key

- **Severity:** [red]CRITICAL[/red]
- **Confidence:** 95%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 69
- **Type:** google_api_key
- **Entropy:** 5.18

**Matched:**
```
AIzaSyA1234567890abcdefghijklmnopqrstuv
```

### 7. Stripe API Key

- **Severity:** [red]CRITICAL[/red]
- **Confidence:** 95%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 75
- **Type:** stripe_key
- **Entropy:** 4.38

**Matched:**
```
sk_live_1234567890abcdef1234567890
```

### 8. AWS Access Key ID

- **Severity:** [red]CRITICAL[/red]
- **Confidence:** 95%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 93
- **Type:** aws_access_key
- **Entropy:** 3.68

**Matched:**
```
AKIAIOSFODNN7EXAMPLE
```

### 9. AWS Access Key ID

- **Severity:** [red]CRITICAL[/red]
- **Confidence:** 95%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 103
- **Type:** aws_access_key
- **Entropy:** 3.68

**Matched:**
```
AKIAIOSFODNN7EXAMPLE
```

### 10. AWS Access Key ID

- **Severity:** [red]CRITICAL[/red]
- **Confidence:** 95%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 125
- **Type:** aws_access_key
- **Entropy:** 3.68

**Matched:**
```
AKIAIOSFODNN7EXAMPLE
```

### 11. Generic API Key

- **Severity:** [orange3]HIGH[/orange3]
- **Confidence:** 70%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 69
- **Type:** generic_api_key
- **Entropy:** 5.42

**Matched:**
```
API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv...
```

### 12. Hardcoded Password

- **Severity:** [orange3]HIGH[/orange3]
- **Confidence:** 75%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 81
- **Type:** password_in_code
- **Entropy:** 4.11

**Matched:**
```
password = "SuperSecret123!"
```

### 13. Database Connection URL

- **Severity:** [orange3]HIGH[/orange3]
- **Confidence:** 85%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 87
- **Type:** database_url
- **Entropy:** 3.94

**Matched:**
```
postgresql://user:pass@localhost/db
```

### 14. Generic API Key

- **Severity:** [orange3]HIGH[/orange3]
- **Confidence:** 70%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 103
- **Type:** generic_api_key
- **Entropy:** 4.08

**Matched:**
```
API_KEY = "AKIAIOSFODNN7EXAMPLE"
```

### 15. High-entropy string in secret-like variable

- **Severity:** [orange3]HIGH[/orange3]
- **Confidence:** 57%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 50
- **Type:** high_entropy_secret
- **Entropy:** 5.22

**Matched:**
```
ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
```

### 16. High-entropy string in secret-like variable

- **Severity:** [orange3]HIGH[/orange3]
- **Confidence:** 50%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 63
- **Type:** high_entropy_secret
- **Entropy:** 4.51

**Matched:**
```
xoxb-1234567890-1234567890123-AbCdEfGhIjKl
```

### 17. High-entropy string in secret-like variable

- **Severity:** [orange3]HIGH[/orange3]
- **Confidence:** 57%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 69
- **Type:** high_entropy_secret
- **Entropy:** 5.18

**Matched:**
```
AIzaSyA1234567890abcdefghijklmnopqrstuv
```

### 18. High-entropy string in secret-like variable

- **Severity:** [orange3]HIGH[/orange3]
- **Confidence:** 51%
- **File:** `tests\test_secret_scanner.py`
- **Line:** 108
- **Type:** high_entropy_secret
- **Entropy:** 4.62

**Matched:**
```
a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6
```

---

## Recommendations

- [ ] **IMMEDIATE ACTION:** Fix critical findings before deployment
- [ ] Address high-severity issues in current sprint

---

*Report generated by MyScan v0.1.0*