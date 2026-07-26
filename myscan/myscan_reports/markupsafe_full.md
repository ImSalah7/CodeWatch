# MyScan Security Report

**Generated:** 2026-07-26 16:18:55 UTC
**Repository:** https://github.com/pallets/markupsafe
**Risk Score:** 100/100

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 0 |
| Medium   | 47 |
| Low      | 1 |
| Info     | 0 |
| **Total** | **48** |

## Findings by Scanner

| Scanner | Count |
|---------|-------|
| Suspicious Code Scanner | 48 |

## Findings by File

| File | Issues |
|------|--------|
| `tests\test_markupsafe.py` | 38 |
| `tests\test_escape.py` | 6 |
| `tests\test_ext_init.py` | 2 |
| `.readthedocs.yaml` | 1 |
| `tests\test_leak.py` | 1 |

---

## Detailed Findings

### 1. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_escape.py`
- **Line:** 34
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 2. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_escape.py`
- **Line:** 53
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 3. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_escape.py`
- **Line:** 54
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 4. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_escape.py`
- **Line:** 55
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 5. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_escape.py`
- **Line:** 67
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 6. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_escape.py`
- **Line:** 68
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 7. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_ext_init.py`
- **Line:** 27
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 8. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_ext_init.py`
- **Line:** 28
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 9. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_leak.py`
- **Line:** 28
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 10. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 16
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 11. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 33
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 12. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 37
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 13. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 39
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 14. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 50
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 15. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 52
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 16. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 58
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 17. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 64
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 18. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 70
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 19. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 74
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 20. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 78
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 21. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 79
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 22. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 93
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 23. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 97
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 24. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 103
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 25. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 104
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 26. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 109
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 27. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 112
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 28. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 115
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 29. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 120
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 30. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 125
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 31. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 140
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 32. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 141
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 33. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 166
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 34. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 174
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 35. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 178
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 36. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 179
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 37. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 180
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 38. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 185
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 39. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 186
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 40. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 187
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 41. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 191
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 42. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 195
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 43. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 196
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 44. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 202
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 45. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 206
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 46. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 207
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 47. assert statement - disabled when Python runs with -O flag

- **Severity:** MEDIUM
- **Confidence:** 60%
- **Scanner:** Suspicious Code Scanner
- **File:** `tests\test_markupsafe.py`
- **Line:** 208
- **Type:** assert_in_production
- **Category:** code_quality
- **Fix:** Use proper validation with raise ValueError() instead of assert

**Matched:**
```
assert 
```

### 48. Global variable usage - may indicate poor design

- **Severity:** LOW
- **Confidence:** 50%
- **Scanner:** Suspicious Code Scanner
- **File:** `.readthedocs.yaml`
- **Line:** 9
- **Type:** global_variable
- **Category:** code_quality
- **Fix:** Consider using class instances, dependency injection, or function parameters

**Matched:**
```
global uv
```

---

## Recommendations

- [ ] Plan medium-severity fixes for upcoming releases
- [ ] Consider addressing low-severity items during refactoring

---

*Report generated by MyScan v0.2.0*