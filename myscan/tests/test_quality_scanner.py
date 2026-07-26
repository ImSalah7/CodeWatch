"""Tests for quality scanner."""

import pytest
from src.core.models import Language, FindingCategory
from src.scanners.quality_scanner import QualityScanner


class TestQualityScanner:
    def setup_method(self):
        self.scanner = QualityScanner()

    def test_long_line(self):
        code = 'x = "a' + 'b' * 120 + '"'
        findings = self.scanner.scan_file(code, "test.py", Language.PYTHON)
        long_findings = [f for f in findings if f.rule_id == "QLT001"]
        assert len(long_findings) >= 1

    def test_empty_except(self):
        code = '''try:
    x = 1
except:
    pass'''
        findings = self.scanner.scan_file(code, "test.py", Language.PYTHON)
        except_findings = [f for f in findings if "Exception" in f.title or "bare" in f.title.lower()]
        assert len(except_findings) >= 1

    def test_todo_comment(self):
        code = '# TODO: implement this feature'
        findings = self.scanner.scan_file(code, "test.py", Language.PYTHON)
        todo_findings = [f for f in findings if "TODO" in f.title]
        assert len(todo_findings) >= 1

    def test_deep_nesting(self):
        code = '''def deeply_nested():
    for i in range(10):
        for j in range(10):
            for k in range(10):
                for l in range(10):
                    for m in range(10):
                        print(i)'''
        findings = self.scanner.scan_file(code, "test.py", Language.PYTHON)
        nest_findings = [f for f in findings if "Nesting" in f.title]
        assert len(nest_findings) >= 1

    def test_duplicate_code(self):
        block = '''    x = 1
    y = 2
    z = x + y
    result = z * 3
    return result'''
        code = block + "\n\n" + block
        findings = self.scanner.scan_file(code, "test.py", Language.PYTHON)
        dup_findings = [f for f in findings if "Duplicate" in f.title]
        assert len(dup_findings) >= 1

    def test_clean_code(self):
        code = '''def clean_function():
    result = calculate_sum([1, 2, 3])
    return result

def calculate_sum(numbers):
    return sum(numbers)'''
        findings = self.scanner.scan_file(code, "test.py", Language.PYTHON)
        assert len(findings) == 0
