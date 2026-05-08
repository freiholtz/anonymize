"""Unit tests for the standalone mask_* helper functions."""

from anonymize import (
    KNOWN_FIRST_NAMES,
    mask_email,
    mask_full,
    mask_name_full,
    mask_name_word,
    mask_phone,
    mask_ssn,
    mask_token,
)


class TestMaskNameWord:
    def test_short_word_full_mask(self):
        assert mask_name_word("Li") == "***"

    def test_normal_word(self):
        assert mask_name_word("John") == "J***n"

    def test_long_word(self):
        assert mask_name_word("Bartholomew") == "B***w"

    def test_strips_whitespace(self):
        assert mask_name_word("  John  ") == "J***n"


class TestMaskNameFull:
    def test_long_surname_masked(self):
        assert mask_name_full("Jane Bartholomew") == "Jane B***w"

    def test_short_token_skipped(self):
        # Tokens <= 6 chars are skipped to avoid mangling Swedish/Norwegian
        # prose that English NER often absorbs into a person span.
        assert mask_name_full("Jag heter Bartholomew") == "Jag heter B***w"

    def test_allowlisted_long_token_skipped(self):
        # Tokens in KNOWN_FIRST_NAMES are skipped by the heuristic.
        assert "Caroline" in KNOWN_FIRST_NAMES
        assert mask_name_full("Caroline Bartholomew") == "Caroline B***w"

    def test_empty_string(self):
        assert mask_name_full("") == ""


class TestMaskEmail:
    def test_short_prefix(self):
        assert mask_email("a@b.com") == "a***@b.com"

    def test_long_prefix(self):
        assert mask_email("janedoe@example.com") == "jan***@example.com"

    def test_no_at_sign(self):
        assert mask_email("notanemail") == "***@***"


class TestMaskPhone:
    def test_keeps_last_four(self):
        assert mask_phone("555-123-4567") == "***-***-4567"

    def test_short_phone(self):
        assert mask_phone("123") == "****"

    def test_international_format(self):
        # 10 digits, last 4 = "4567"
        assert mask_phone("+1 555 123 4567") == "+* *** *** 4567"

    def test_preserves_separators(self):
        assert mask_phone("(555) 123-4567") == "(***) ***-4567"


class TestMaskSsn:
    def test_swedish_personnummer(self):
        # Keeps first 4 digits (birth year), masks rest.
        assert mask_ssn("850712-1234") == "8507**-****"

    def test_us_ssn(self):
        assert mask_ssn("123-45-6789") == "123-4*-****"


class TestMaskToken:
    def test_short_token(self):
        assert mask_token("sk-abc") == "sk*****"

    def test_long_token(self):
        assert mask_token("sk-abcdefghijklmnop") == "sk-ab*****lmnop"

    def test_strips_whitespace(self):
        assert mask_token("  sk-abcdefghijklmnop  ") == "sk-ab*****lmnop"


class TestMaskFull:
    def test_full_mask_preserves_length(self):
        assert mask_full("secret") == "******"

    def test_strips_whitespace(self):
        # Length is computed AFTER strip.
        assert mask_full("  secret  ") == "******"
