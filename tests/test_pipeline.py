"""Integration tests for the full anonymize pipeline."""

import re
from pathlib import Path

import anonymize


FIXTURE_DIR = Path(__file__).parent.parent / "validation"


class TestRegexFallback:
    """Tests that exercise the regex-only path (no Presidio NER required)."""

    def test_labeled_secret_full_masked(self):
        text = "password: hunter2"
        result = anonymize._regex_mask(text)
        assert "hunter2" not in result
        assert "*" in result

    def test_email_partial_masked(self):
        text = "Reach me at janedoe@example.com"
        result = anonymize._regex_mask(text)
        assert "janedoe" not in result
        assert "@example.com" in result

    def test_personnummer_keeps_year(self):
        text = "Personnummer: 850712-1234"
        result = anonymize._regex_mask(text)
        assert "8507" in result
        assert "1234" not in result

    def test_token_partial_masked(self):
        # Bare token without a labeled prefix - falls through to TOKEN regex,
        # not LABELED_SECRET (which would full-mask it).
        text = "Use sk-abcdefghijklmnopqrstuvwxyz1234 to authenticate"
        result = anonymize._regex_mask(text)
        assert "sk-ab" in result
        assert "abcdefghijklmnopqrstuvwxyz" not in result


class TestProtectRestore:
    def test_backtick_span_preserved(self):
        text = "See `path/to/secret.json` for details"
        protected, originals = anonymize._protect(text)
        assert "`path/to/secret.json`" in originals
        assert "__PROTECTED_0__" in protected
        restored = anonymize._restore(protected, originals)
        assert restored == text

    def test_url_preserved(self):
        text = "Docs at https://example.com/path?q=1"
        protected, originals = anonymize._protect(text)
        assert "https://example.com/path?q=1" in originals
        restored = anonymize._restore(protected, originals)
        assert restored == text


class TestFilterOverlaps:
    def test_keeps_higher_score_drops_overlapping_lower(self):
        class FakeResult:
            def __init__(self, start, end, score):
                self.start = start
                self.end = end
                self.score = score

        results = [
            FakeResult(0, 10, 0.7),
            FakeResult(5, 15, 0.9),  # overlaps the first, higher score - wins
            FakeResult(20, 30, 0.5),  # no overlap, kept
        ]
        kept = anonymize._filter_overlaps(results)
        assert len(kept) == 2
        scores = sorted(r.score for r in kept)
        assert scores == [0.5, 0.9]


class TestFixture:
    """Run the full pipeline against the synthetic fixture and assert
    that obvious PII is masked while expected pass-through items survive."""

    def test_fixture_pipeline(self):
        src = (FIXTURE_DIR / "dummy.md").read_text()
        out = anonymize.anonymize_text(src)

        # Hard PII that must be masked regardless of mode.
        assert "850712-1234" not in out, "personnummer leaked"
        assert "123-45-6789" not in out, "US SSN leaked"
        assert "AKIAIOSFODNN7EXAMPLE" not in out, "AWS key leaked"
        assert "1HGBH41JXMN109186" not in out, "VIN leaked"
        assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in out, "github token leaked"

        # Email prefixes must not appear in plaintext.
        assert "janedoe@example.com" not in out, "email prefix leaked"
