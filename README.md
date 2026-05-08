# anonymize

PII and secrets masking for text. Pipe in a ticket, paste, or log line; get
back the same text with personal information and credentials masked. Designed
for the moment before you share something with a chatbot, a coworker, or a
public issue tracker.

```bash
echo "Reach Jane Doe at jane.doe@example.com or 555-123-4567" | anonymize
# Reach Jane Doe at jan***@example.com or ***-***-4567
```

## Install

Requires Python 3.11+. The tool is `uv`-managed.

```bash
git clone https://github.com/freiholtz/anonymize
cd anonymize
uv sync

# Optional but recommended: download the spaCy model for bare-name detection
uv run python -m spacy download en_core_web_lg
```

Without the spaCy model the tool falls back to regex-only mode, which masks
labeled fields, emails, phones, tokens, and personnummer but does NOT detect
bare names in prose. The fallback is graceful, no errors.

## Usage

```bash
echo "text" | anonymize           # mask from stdin
pbpaste | anonymize               # mask clipboard via pipe (macOS)
anonymize                          # reads clipboard automatically (macOS)
cat file.txt | anonymize > out.txt
```

Flags:

| Flag | Effect |
|------|--------|
| `--help` | Print usage |
| `--show-pii` | Passthrough mode, no masking, for debugging |

## What gets masked

| Field | Mask style |
|-------|-----------|
| Names (bare PERSON spans) | `Jane B***w` (multi-token spans, longer Title-case tokens masked) |
| Names (labeled fields) | `first_name: J***n` |
| Emails | `joh***@domain.com` (first 3 chars of prefix kept) |
| Phones | `***-***-4567` (last 4 digits kept) |
| Swedish personnummer | `1980****-****` (birth year kept) |
| US SSN | `123-4*-****` |
| API tokens / keys | `sk-ab*****wxyz1` (first/last 5 kept) |
| AWS access key id | `AKIAI*****AMPLE` |
| Vehicle ID number (VIN) | `1HGBH*****09186` |
| Credit cards | `****************` (full mask) |
| IBAN | `***************************` (full mask) |
| Labeled secrets (`password:`, `token:`) | `**********` (full mask) |
| Street addresses | `S***n 12, 441 30 S***y` (readable partial mask) |
| IP addresses | masked by default - flag `MASK_IP_ADDRESSES` to disable |

## Configuration flags

Top of `anonymize.py`:

```python
MASK_IP_ADDRESSES = True
```

Edit in place. There is no CLI override on purpose. The file is the source of
truth for what your install masks.

## How it works

Two-mode pipeline:

1. **Presidio mode** (when `presidio-analyzer` and a spaCy model are
   available). Full named-entity recognition + custom pattern recognizers.
   Detects bare names in prose, addresses, multilingual text.
2. **Regex fallback** (always available). Pattern-only. Catches labeled
   fields, emails, phones, tokens, personnummer. Misses bare names.

URLs and backtick-quoted code spans are extracted before masking and restored
after, so paths and session IDs in code blocks survive intact.

When two recognizers overlap (e.g. PERSON and STREET_ADDRESS on the same
Swedish prose line), the higher-score result wins and the lower one is
dropped, preventing double-masked artifacts.

## Custom recognizers

`anonymize.py` ships with these custom Presidio recognizers in addition to
Presidio's defaults:

- `SE_PERSONNUMMER` (Swedish national id format)
- `SE_PHONE` (Swedish dialing patterns +46 / 0...)
- `LABELED_NAME` (`first_name:` / `last_name:` / `full_name:` fields)
- `LABELED_SECRET` (`password:` / `token:` / `api_key:` etc)
- `TOKEN` (prefixed API tokens + long opaque strings)
- `US_SSN` (NNN-NN-NNNN format)
- `AWS_KEY` (AKIA / ASIA prefix + 16 alphanumeric)
- `VIN` (17-char vehicle id, no I/O/Q)
- `PHONE_NUMBER` extension for `(NNN) NNN-NNNN` parens form
- `STREET_ADDRESS` (Swedish + US shapes)

Add your own by editing `_build_custom_recognizers()`.

## Tests

```bash
uv run pytest
```

Unit tests cover every `mask_*` helper. An integration test runs the full
pipeline against `validation/dummy.md` and asserts that hard PII is masked
while pass-through items survive.

## Caveats

- **English NER only.** Bare-name detection requires the English spaCy model.
  Names in pure non-English prose may not be detected as PERSON.
- **No detection is perfect.** This is a best-effort tool. Always review the
  output before sharing sensitive material.
- **Lowercase names slip through.** spaCy NER ignores `jane doe` (no
  capitalization). Don't rely on this tool to catch deliberately obfuscated
  data.
- **macOS clipboard read** (`pbpaste`) is macOS-specific. On Linux/Windows,
  pipe stdin instead.

## License

[MIT](LICENSE).
