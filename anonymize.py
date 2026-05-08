"""
anonymize - PII and secrets masking tool.

Reads from stdin or macOS clipboard if no stdin is piped.
Outputs masked text to stdout.

Two modes (selected automatically):
  - Presidio mode: full NER + pattern recognition (requires presidio + spaCy)
  - Regex fallback: pattern-only, no bare-name detection (always available)

Configuration flags (top of file):
  MASK_IP_ADDRESSES  - when True (default), IP addresses are partial-masked.
                       Set to False to leave them unchanged.
"""

import re
import sys


# ── Configuration flags ──────────────────────────────────────────────────────
# Toggle which entity classes get masked. Edit in place; no CLI override.

MASK_IP_ADDRESSES = True

HELP_TEXT = """\
anonymize - PII and secrets masking tool

Masks personal information and secrets in text before sharing.
Reads from stdin or macOS clipboard (pbpaste) if no stdin is piped.
Outputs masked text to stdout.

Usage:
  echo "text" | anonymize           mask from stdin
  pbpaste | anonymize               mask clipboard via pipe
  anonymize                         reads clipboard automatically
  cat file.txt | anonymize > out.txt

Options:
  --help       Show this help text
  --show-pii   Passthrough mode - no masking (for debugging)

Masked fields:
  Names (bare)    J***n L***t  (first + last char per word)
  Names (labeled) first_name: J***n
  Emails          joh***@domain.com
  Phones          ****4567 (last 4 digits preserved)
  Personnummer    1980****-**** (birth year only)
  Tokens/keys     sk-ab*****nop (first/last 5 preserved)
  Secrets         ********** (full mask)
  Credit cards    **************** (full mask)

Exit codes: 0 = success, 1 = no input available

Setup (one-time, for bare name detection):
  python -m spacy download en_core_web_lg
"""


# ── Masking helper functions ──────────────────────────────────────────────────
# Standalone so they can be used both as Presidio operator lambdas and in the
# regex fallback path.


def mask_name_word(s: str) -> str:
    """J***n  (first char + *** + last char)."""
    s = s.strip()
    if len(s) <= 2:
        return "***"
    return s[0] + "***" + s[-1]


# Allowlist of short common-name tokens. Used by the multi-token name
# heuristic below to skip false positives in non-English prose where
# Presidio's English NER occasionally absorbs adjacent words into a
# PERSON span.
KNOWN_FIRST_NAMES = {
    "Caroline", "Sebastian", "Jonathan", "Christopher",
    "Charlotte", "Christina", "Elisabeth", "Alexander", "Frederik",
    "Henrietta", "Beatrice", "Veronica", "Stephanie",
}


def mask_name_full(value: str) -> str:
    """Best-effort masking of multi-token PERSON spans.

    Heuristic:
    - Single-token spans pass through unchanged. NER on bare single-word
      input is too noisy to mask reliably without a confirmed corpus.
    - Multi-token spans: long Title-case tokens (>6 chars and not in the
      common-name allowlist) get masked as surname-shaped. Shorter
      tokens, lowercase tokens, and non-alphabetic tokens are skipped
      to avoid mangling Swedish/Norwegian prose that English NER often
      lumps into a person span (e.g. "Jag heter ...", "och bor på ...").

    Known false-positive trade-offs:
    - Title-case English words >6 chars that aren't names (Yesterday,
      Wednesday) will be masked. Acceptable cost.
    - Title-case place names >6 chars (city names) will be masked when
      Presidio NER includes them in a person span.
    """
    parts = value.split()
    if not parts:
        return value
    if len(parts) == 1:
        return parts[0]
    out = []
    for w in parts:
        is_name_shaped = w.isalpha() and w[:1].isupper() and len(w) > 2
        is_likely_first_name = len(w) <= 6 or w in KNOWN_FIRST_NAMES
        if is_name_shaped and not is_likely_first_name:
            out.append(mask_name_word(w))
        else:
            out.append(w)
    return " ".join(out)


def mask_email(value: str) -> str:
    """joh***@domain.com  (first 3 chars of prefix + *** + @domain)."""
    value = value.strip()
    if "@" not in value:
        return "***@***"
    prefix, domain = value.split("@", 1)
    masked = (prefix[:3] + "***") if len(prefix) > 3 else (prefix[:1] + "***")
    return f"{masked}@{domain}"


def mask_phone(value: str) -> str:
    """All digits masked except the last 4; non-digit chars preserved in place."""
    digits = re.sub(r"\D", "", value)
    if len(digits) <= 4:
        return "****"
    keep_from = len(digits) - 4
    result, count = [], 0
    for ch in value:
        if ch.isdigit():
            result.append(ch if count >= keep_from else "*")
            count += 1
        else:
            result.append(ch)
    return "".join(result)


def mask_ssn(value: str) -> str:
    """1980****-****  (first 4 digits kept, rest masked, separators preserved)."""
    seen, result = 0, []
    for ch in value:
        if ch.isdigit():
            result.append(ch if seen < 4 else "*")
            seen += 1
        elif ch in "-/" and seen >= 4:
            result.append(ch)
        elif seen < 4:
            result.append(ch)
        else:
            result.append("*")
    return "".join(result)


def mask_token(value: str) -> str:
    """sk-ab*****nop  (first 5 + ***** + last 5)."""
    s = value.strip()
    if len(s) <= 10:
        return s[:2] + "*****"
    return s[:5] + "*****" + s[-5:]


def mask_full(value: str) -> str:
    """Full mask, same length as input."""
    return "*" * len(value.strip())


# ── Presidio custom recognizers ───────────────────────────────────────────────


def _build_custom_recognizers() -> list:
    """
    Returns a list of custom Presidio recognizers.
    Only call when presidio is already imported.
    """
    from presidio_analyzer import (
        Pattern,
        PatternRecognizer,
        EntityRecognizer,
        RecognizerResult,
    )

    def _capture_group_recognizer(
        entity: str,
        regex: re.Pattern,
        score: float = 0.95,
    ):
        """Build an EntityRecognizer that emits results from regex group(1).

        Presidio's PatternRecognizer matches on `match.group(0)` (whole match)
        with no group-aware variant. For "labeled field" recognizers
        (e.g. `password: <value>`) we need to mask only the value, not the
        prefix. This helper bakes the analyze() boilerplate so each labeled
        recognizer is one line at the call site.
        """

        class CaptureGroupRecognizer(EntityRecognizer):
            def __init__(self) -> None:
                super().__init__(
                    supported_entities=[entity],
                    name=f"{entity}Recognizer",
                    supported_language="en",
                )

            def load(self) -> None:
                pass

            def analyze(self, text, entities, nlp_artifacts=None):
                return [
                    RecognizerResult(
                        entity_type=entity,
                        start=m.start(1),
                        end=m.end(1),
                        score=score,
                    )
                    for m in regex.finditer(text)
                ]

        return CaptureGroupRecognizer()

    LABELED_NAME_REGEX = re.compile(
        r"(?:first_name|last_name|full_name)\s*['\"]?\s*[:=]\s*['\"]?"
        r"([A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ\-]+)['\"]?",
        re.IGNORECASE,
    )
    LABELED_SECRET_REGEX = re.compile(
        r"(?:password|passwd|secret|token|api_key|private_key|webhook_token)"
        r"\s*['\"]?\s*[:=]\s*['\"]?([^\s'\">,\n]{4,})['\"]?",
        re.IGNORECASE,
    )

    class SwedishPersonnummerRecognizer(PatternRecognizer):
        def __init__(self) -> None:
            super().__init__(
                supported_entity="SE_PERSONNUMMER",
                patterns=[Pattern("personnummer", r"\b\d{6,8}[-/]\d{4}\b", 0.95)],
                context=["personnummer", "pnr", "ssn", "person"],
            )

    class SwedishPhoneRecognizer(PatternRecognizer):
        def __init__(self) -> None:
            super().__init__(
                supported_entity="PHONE_NUMBER",
                patterns=[
                    Pattern("se_intl", r"\+46\s?\d[\d\s\-\.]{6,12}\d", 0.8),
                    Pattern(
                        "se_local",
                        r"(?<!\d)0\d{1,3}[\s\-]?\d{3,4}[\s\-]?\d{2,4}(?!\d)",
                        0.6,
                    ),
                ],
                context=["phone", "tel", "mobile", "mobil", "telefon", "telefonnummer"],
            )

    class TokenRecognizer(PatternRecognizer):
        """Detects bare API tokens/keys by prefix pattern or length."""

        def __init__(self) -> None:
            super().__init__(
                supported_entity="TOKEN",
                patterns=[
                    Pattern(
                        "prefixed_token",
                        r"\b(?:sk-|pk_|sk_|rk_|whsec_|tok_)[A-Za-z0-9_\-]{10,}\b",
                        0.9,
                    ),
                    Pattern("long_token", r"\b[A-Za-z0-9_\-]{25,}\b", 0.7),
                ],
            )

    class UsSsnRecognizer(PatternRecognizer):
        """US Social Security Number: NNN-NN-NNNN."""

        def __init__(self) -> None:
            super().__init__(
                supported_entity="US_SSN",
                patterns=[Pattern("us_ssn", r"\b\d{3}-\d{2}-\d{4}\b", 0.95)],
                context=["ssn", "social", "security"],
            )

    class AwsAccessKeyRecognizer(PatternRecognizer):
        """AWS access key id: AKIA / ASIA / etc + 16 alphanumeric uppercase."""

        def __init__(self) -> None:
            super().__init__(
                supported_entity="AWS_KEY",
                patterns=[
                    Pattern(
                        "aws_access_key",
                        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b",
                        0.95,
                    ),
                ],
                context=["aws", "access", "key"],
            )

    class VinRecognizer(PatternRecognizer):
        """Vehicle Identification Number: 17 chars, no I/O/Q. Word-boundary
        match; context-boosted by `vin` to reduce false positives."""

        def __init__(self) -> None:
            super().__init__(
                supported_entity="VIN",
                patterns=[
                    Pattern("vin_17", r"\b[A-HJ-NPR-Z0-9]{17}\b", 0.5),
                ],
                context=["vin", "chassis"],
            )

    class ParensPhoneRecognizer(PatternRecognizer):
        """Phone in `(NNN) NNN-NNNN` style. Common US/Swedish form Presidio's
        default English phone recognizer misses when wrapped in parens."""

        def __init__(self) -> None:
            super().__init__(
                supported_entity="PHONE_NUMBER",
                patterns=[
                    Pattern(
                        "parens_phone",
                        r"\(\s*\d{2,4}\s*\)\s*\d{3,4}[-.\s]?\d{2,4}",
                        0.7,
                    ),
                    Pattern(
                        "intl_dashed",
                        r"\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}",
                        0.7,
                    ),
                ],
                context=["phone", "tel", "mobile", "call"],
            )

    class StreetAddressRecognizer(PatternRecognizer):
        """Best-effort street address. Two patterns:

        - Swedish: <street-word> <number>, <5digit zip> <city>
          e.g. "Storgatan 12, 441 30 Storby"
        - US: <number> <words>, <city>, <STATE> <5digit zip>
          e.g. "1 Apple Park Way, Cupertino, CA 95014"

        Conservative: requires the full address shape, not bare street
        names. Reduces false positives at the cost of missing partial
        addresses (only-street-line, only-city-zip).
        """

        def __init__(self) -> None:
            super().__init__(
                supported_entity="STREET_ADDRESS",
                patterns=[
                    Pattern(
                        "se_address",
                        r"[A-ZÅÄÖ][a-zåäö]+(?:vägen|gatan|gränden|stigen|torget|backen|allén)\s+\d{1,4}\b(?:\s*,\s*\d{3}\s?\d{2}\s+[A-ZÅÄÖ][a-zåäö]+)?",
                        0.7,
                    ),
                    Pattern(
                        "us_address",
                        r"\b\d{1,5}\s+[A-Z][A-Za-z]*(?:\s+[A-Z][A-Za-z]*){0,5}\s*,\s*[A-Z][A-Za-z]+\s*,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?\b",
                        0.85,
                    ),
                ],
                context=["address", "street", "addr"],
            )

    return [
        SwedishPersonnummerRecognizer(),
        SwedishPhoneRecognizer(),
        _capture_group_recognizer("LABELED_NAME", LABELED_NAME_REGEX),
        _capture_group_recognizer("LABELED_SECRET", LABELED_SECRET_REGEX),
        TokenRecognizer(),
        UsSsnRecognizer(),
        AwsAccessKeyRecognizer(),
        VinRecognizer(),
        ParensPhoneRecognizer(),
        StreetAddressRecognizer(),
    ]


def _build_operators() -> dict:
    from presidio_anonymizer.entities import OperatorConfig

    operators = {
        "PERSON":          OperatorConfig("custom", {"lambda": mask_name_full}),
        "LABELED_NAME":    OperatorConfig("custom", {"lambda": mask_name_word}),
        "EMAIL_ADDRESS":   OperatorConfig("custom", {"lambda": mask_email}),
        "PHONE_NUMBER":    OperatorConfig("custom", {"lambda": mask_phone}),
        "SE_PERSONNUMMER": OperatorConfig("custom", {"lambda": mask_ssn}),
        "US_SSN":          OperatorConfig("custom", {"lambda": mask_ssn}),
        "LABELED_SECRET":  OperatorConfig("custom", {"lambda": mask_full}),
        "TOKEN":           OperatorConfig("custom", {"lambda": mask_token}),
        "AWS_KEY":         OperatorConfig("custom", {"lambda": mask_token}),
        "VIN":             OperatorConfig("custom", {"lambda": mask_token}),
        "CREDIT_CARD":     OperatorConfig("custom", {"lambda": mask_full}),
        "IBAN_CODE":       OperatorConfig("custom", {"lambda": mask_full}),
        "STREET_ADDRESS":  OperatorConfig("custom", {"lambda": mask_name_full}),
        # IP_ADDRESS is always requested from the analyzer so it wins conflict
        # resolution against the default PHONE_NUMBER recognizer for dotted-IP
        # shapes like 81.226.119.45. Whether it gets masked is controlled by
        # MASK_IP_ADDRESSES at the top of the file.
        "IP_ADDRESS":      (
            OperatorConfig("custom", {"lambda": mask_token})
            if MASK_IP_ADDRESSES
            else OperatorConfig("keep", {})
        ),
    }
    return operators


# ── Presidio pipeline singleton ───────────────────────────────────────────────

_pipeline = None   # (analyzer, anonymizer, operators) once initialized
_checked = False   # True once we've tried to build the pipeline


def _get_pipeline():
    """
    Lazily build and cache the Presidio pipeline.
    Returns (analyzer, anonymizer, operators) or None if Presidio unavailable.

    Operators are rebuilt on each call so runtime flag flips
    (e.g. MASK_IP_ADDRESSES) take effect without a full re-init.
    """
    global _pipeline, _checked
    if _checked and _pipeline is not None:
        analyzer, anonymizer, _ = _pipeline
        return (analyzer, anonymizer, _build_operators())
    if _checked:
        return _pipeline
    _checked = True

    try:
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_anonymizer import AnonymizerEngine

        # Try spaCy models in order of preference. Only models already installed.
        # Presidio calls sys.exit() if a model is missing (via spacy.cli.download),
        # so we check availability first to avoid killing the process.
        import spacy.util

        nlp_engine = None
        for model_name in ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"]:
            if not spacy.util.is_package(model_name):
                continue
            try:
                config = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": model_name}],
                }
                provider = NlpEngineProvider(nlp_configuration=config)
                nlp_engine = provider.create_engine()
                break
            except Exception:
                continue

        if nlp_engine is None:
            # No model available. AnalyzerEngine would try to auto-download one
            # (via spacy.cli.download -> sys.exit), so fall through to regex mode.
            print(
                "[anonymize] No spaCy model found - bare name detection disabled.\n"
                "[anonymize] To enable: uv run python -m spacy download en_core_web_lg",
                file=sys.stderr,
            )
            _pipeline = None
            return _pipeline

        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()
        for recognizer in _build_custom_recognizers():
            registry.add_recognizer(recognizer)

        analyzer = AnalyzerEngine(
            registry=registry,
            supported_languages=["en"],
            nlp_engine=nlp_engine,
        )
        anonymizer = AnonymizerEngine()
        operators = _build_operators()

        _pipeline = (analyzer, anonymizer, operators)

    except Exception as e:
        print(
            f"[anonymize] Presidio unavailable ({type(e).__name__}: {e}) - regex-only mode.",
            file=sys.stderr,
        )
        _pipeline = None

    return _pipeline


# ── Regex fallback ────────────────────────────────────────────────────────────
# Used when Presidio is not installed. Does not detect bare names in prose.

_RE_SSN    = re.compile(r"\b(\d{6,8}[-/]\d{4})\b")
_RE_TOKEN  = re.compile(r"\b((?:sk-|pk_|rk_|whsec_|tok_)[A-Za-z0-9_\-]{10,}|[A-Za-z0-9_\-]{25,})\b")
_RE_EMAIL  = re.compile(r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
_RE_PHONE  = re.compile(r"(?<!\d)(\+?(?:46|0)\s?[-.\s]?\d[\d\s\-\.]{6,14}\d)(?!\d)")
_RE_SECRET = re.compile(
    r"((?:password|passwd|secret|token|api_key|private_key|webhook_token)"
    r"\s*['\"]?\s*[:=]\s*['\"]?)([^\s'\">,\n]{4,})(['\"]?)",
    re.IGNORECASE,
)
_RE_NAME = re.compile(
    r"((?:first_name|last_name|full_name)\s*['\"]?\s*[:=]\s*['\"]?)"
    r"([A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ\-]{1,})(['\"]?)",
    re.IGNORECASE,
)


def _regex_mask(text: str) -> str:
    # Order matters: labeled secrets first (highest priority), then patterns
    text = _RE_SECRET.sub(lambda m: m.group(1) + mask_full(m.group(2)) + m.group(3), text)
    text = _RE_SSN.sub(lambda m: mask_ssn(m.group(1)), text)
    text = _RE_EMAIL.sub(lambda m: mask_email(m.group(1)), text)
    text = _RE_PHONE.sub(lambda m: mask_phone(m.group(1)), text)
    text = _RE_NAME.sub(lambda m: m.group(1) + mask_name_word(m.group(2)) + m.group(3), text)
    text = _RE_TOKEN.sub(
        lambda m: mask_token(m.group(1))
        if "***" not in m.group(1) and len(m.group(1)) >= 20
        else m.group(1),
        text,
    )
    return text


# ── Protect-then-restore for safe spans ───────────────────────────────────────
# Backtick spans and full URLs are extracted before masking and restored after.
# This prevents URL path slugs and session IDs in code spans from being mangled.

_PROTECT_PATTERNS = [
    re.compile(r'`[^`\n]+`'),                  # backtick spans
    re.compile(r'https?://[^\s\'"<>\)]+'),      # full URLs
]


def _protect(text: str) -> tuple[str, list[str]]:
    """Replace protected spans with placeholders. Returns (modified_text, originals)."""
    protected: list[str] = []

    def replacer(m: re.Match) -> str:
        protected.append(m.group(0))
        return f"__PROTECTED_{len(protected) - 1}__"

    for pattern in _PROTECT_PATTERNS:
        text = pattern.sub(replacer, text)
    return text, protected


def _restore(text: str, protected: list[str]) -> str:
    """Restore protected spans."""
    for i, original in enumerate(protected):
        text = text.replace(f"__PROTECTED_{i}__", original)
    return text


# ── Main pipeline ─────────────────────────────────────────────────────────────


def _filter_overlaps(results: list) -> list:
    """Drop lower-score results that overlap with higher-score ones.

    Presidio's anonymizer applies all results, including partial overlaps,
    which produces double-masked artifacts (e.g. PERSON span 0:45 and
    STREET_ADDRESS span 37:48 both fire on the Swedish prose line, leaving
    `H***nH***n 12`). Keep highest-score-first, drop anything that touches
    an already-kept span.
    """
    sorted_results = sorted(results, key=lambda r: (-r.score, r.start, -(r.end - r.start)))
    kept: list = []
    for r in sorted_results:
        if any(r.start < k.end and r.end > k.start for k in kept):
            continue
        kept.append(r)
    return kept


def anonymize_text(text: str) -> str:
    """Mask PII in text. Uses Presidio if available, regex fallback otherwise."""
    protected_text, originals = _protect(text)

    pipeline = _get_pipeline()
    if pipeline is None:
        return _restore(_regex_mask(protected_text), originals)

    analyzer, anonymizer, operators = pipeline
    entities = list(operators.keys())

    try:
        results = analyzer.analyze(text=protected_text, language="en", entities=entities)
        results = _filter_overlaps(results)
        result = anonymizer.anonymize(
            text=protected_text, analyzer_results=results, operators=operators
        )
        return _restore(result.text, originals)
    except Exception as e:
        print(f"[anonymize] Presidio error ({e}) - regex fallback.", file=sys.stderr)
        return _restore(_regex_mask(protected_text), originals)


# ── I/O ───────────────────────────────────────────────────────────────────────


def read_input() -> str | None:
    """Read from stdin if piped, otherwise try macOS clipboard."""
    if not sys.stdin.isatty():
        return sys.stdin.read()

    import subprocess

    try:
        result = subprocess.run(["pbpaste"], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            print("[anonymize] No stdin - reading from clipboard.", file=sys.stderr)
            return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return None


def main() -> None:
    args = sys.argv[1:]

    if "--help" in args:
        print(HELP_TEXT)
        return

    show_pii = "--show-pii" in args

    raw = read_input()
    if raw is None:
        print(HELP_TEXT)
        sys.exit(0)

    if show_pii:
        print(raw, end="")
        return

    print(anonymize_text(raw), end="")


if __name__ == "__main__":
    main()
