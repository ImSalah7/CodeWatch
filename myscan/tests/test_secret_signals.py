"""Unit tests for multi-signal secret heuristics."""

from src.core.secret_signals import (
    is_common_word_value,
    looks_like_camel_prose,
    score_secret,
)


class TestLooksLikeCamelProse:
    def test_demo_value_rejected(self):
        assert looks_like_camel_prose("S0meL0ngSecretT0kenValueHere")
        assert looks_like_camel_prose("SomeLongSecretTokenValueHere")
        assert looks_like_camel_prose("ApiKeyForProductionEnv")

    def test_random_secret_not_prose(self):
        assert not looks_like_camel_prose("aB3xZ9qW4rT7mN2vC5xE8fR1sT6uY0i")
        assert not looks_like_camel_prose("wJalrXUtnFEMIK7MDENGbPxRfiCYzK9xQ2V3mN8pL0")

    def test_short_or_symbolic_values_not_prose(self):
        assert not looks_like_camel_prose("SuperSecret2024!")
        assert not looks_like_camel_prose("secret")
        assert not looks_like_camel_prose("")


class TestCommonWordWithLiteralBase:
    def test_literal_keyword_plus_digits_rejected(self):
        assert is_common_word_value("Existing123")
        assert is_common_word_value("existing123")

    def test_real_values_kept(self):
        assert not is_common_word_value("SuperSecret2024!")
        assert not is_common_word_value("wJalrXUtnFEMIK7MDENG")


class TestScoreSecretCamelProseGate:
    def test_generic_key_demo_value_rejected(self):
        score = score_secret("generic_key", "S0meL0ngSecretT0kenValueHere", "API_KEY")
        assert not score.reported

    def test_password_demo_value_rejected(self):
        score = score_secret("password", "SomeLongSecretTokenValueHere", "password")
        assert not score.reported

    def test_strong_password_preserved(self):
        score = score_secret("password", "P@ssw0rd!XyZz99", "password")
        assert score.reported
