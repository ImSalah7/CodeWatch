"""Unit tests for the validation-engine value/variable helpers."""

from src.core.validation_engine import (
    _clean_secret_value,
    _extract_assignment_varname,
)


class TestExtractAssignmentVarname:
    def test_plain_assignment(self):
        assert _extract_assignment_varname('password = "x"') == "password"
        assert _extract_assignment_varname('DB_PASSWORD = "x"') == "DB_PASSWORD"

    def test_js_declarations_skip_keyword(self):
        assert _extract_assignment_varname("const secret = 'x'") == "secret"
        assert _extract_assignment_varname("let apiKey = 'x'") == "apiKey"
        assert _extract_assignment_varname("var token = 'x'") == "token"

    def test_no_assignment(self):
        assert _extract_assignment_varname("") == ""
        assert _extract_assignment_varname("no assignment here") == ""


class TestCleanSecretValue:
    def test_strips_quotes_and_separators(self):
        assert _clean_secret_value('"secret";') == "secret"
        assert _clean_secret_value("('secret')") == "secret"

    def test_strips_inline_comment_after_literal(self):
        assert _clean_secret_value("'abc123'; // demo") == "abc123"
        assert _clean_secret_value('"abc123" # note') == "abc123"
        assert _clean_secret_value("'abc123' /* block */") == "abc123"

    def test_keeps_url_scheme(self):
        assert _clean_secret_value("//appuser:S3cr3t!Pa55w0rd@") == "//appuser:S3cr3t!Pa55w0rd@"
        assert _clean_secret_value('"postgresql://u:p@host/db"') == "postgresql://u:p@host/db"

    def test_keeps_hash_inside_quotes(self):
        assert _clean_secret_value('"P@ssw#ord!2024"') == "P@ssw#ord!2024"

    def test_keeps_unquoted_values_unchanged(self):
        assert _clean_secret_value("aB3x#Z9qW4rT7mN2vC5xE8fR1sT6uY0i") == "aB3x#Z9qW4rT7mN2vC5xE8fR1sT6uY0i"
