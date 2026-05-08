# Anonymize Django Shell Snippets

A pattern for writing **PII-safe-by-default** Django shell snippets. Drop the
helper block at the top of any investigation script and every print goes
through a mask layer. The default is masked; full PII is an explicit,
conscious override.

This is the *preventive* counterpart to the [`anonymize`](README.md) text
scrubber: the scrubber cleans raw text after the fact, this pattern keeps
raw PII from ever leaving the database row.

## When to use

Reach for this whenever you write a Python block that will:

- Run in a production or staging Django shell (`manage.py shell`,
  `kubectl exec ... shell`, Heroku one-off dyno, etc.).
- Print account, user, customer, subscriber, contact, or order data.
- Land its output anywhere a human or AI agent will read it: terminal,
  chat paste, ticket comment, investigation file, Slack thread.

If output may contain names, emails, phones, government IDs, tokens,
secrets, or webhook payloads, this pattern is the first thing in the file.

## The principle

1. **Default OFF, override ON.** `SHOW_FULL_PII = False` at the top of every
   snippet. Flipping to `True` is a deliberate act, not the path of least
   resistance.
2. **Mask at the print boundary, not the query.** Pull the real row from
   the DB so business logic works correctly. Mask only when the value
   crosses into stdout, a log, a copy-paste buffer, or a chat window.
3. **One helper, one shape language.** The same `mask()` helper masks
   names, emails, phones, government IDs, and tokens with consistent
   shapes so a reader recognises the pattern at a glance.
4. **The override is loud.** Setting `SHOW_FULL_PII = True` should look
   like a yellow flag in code review. Never set it silently. Comment why
   the unmasked output is necessary and what regulatory framing applies
   in your context (GDPR, HIPAA, SOC2, internal policy).

## The masking helper block

Paste this verbatim into the Configuration section of any snippet:

```python
# ── PII Masking ───────────────────────────────────────────────
SHOW_FULL_PII = False  # Set True only if explicitly needed

def mask(value, mode="name"):
    if SHOW_FULL_PII or not value:
        return value
    s = str(value)
    if mode == "name":
        return s[0] + "***" + s[-1] if len(s) > 2 else "***"
    if mode == "email":
        p, _, d = s.partition("@")
        return (p[:3] + "***@" + d) if d else "***@***"
    if mode == "phone":
        return "*" * max(len(s) - 4, 0) + s[-4:]
    if mode == "token":
        return s[:5] + "*****" + s[-5:] if len(s) > 10 else s[:2] + "*****"
    if mode == "ssn":
        return s[:4] + "****-****"
    return "***"
```

| Mode | Input | Output |
|------|-------|--------|
| `name` | `Bartholomew` | `B***w` |
| `email` | `jane.doe@example.com` | `jan***@example.com` |
| `phone` | `+1 555 123 4567` | `***********4567` |
| `token` | `sk-abcdefghijklmnop` | `sk-ab*****lmnop` |
| `ssn` | `19801218-1234` | `1980****-****` |

The shapes match the `anonymize.py` text scrubber in this repo, so output
masked at the source and output scrubbed after the fact look identical.

## Usage in print statements

```python
# Default: masked.
print(f"Name:  {mask(user.first_name)} {mask(user.last_name)}")
print(f"Email: {mask(user.email, 'email')}")
print(f"Phone: {mask(user.phone, 'phone')}")
print(f"Token: {mask(subscription.api_token, 'token')}")

# Loops: still masked.
for order in Order.objects.filter(user_id=USER_ID):
    print(f"  #{order.id}  {mask(order.shipping_email, 'email')}  "
          f"{mask(order.shipping_phone, 'phone')}")
```

The query reads real data. Only the format-string render goes through `mask()`.

## Combined configuration block

When a snippet both reads and mutates, pair the PII guard with a `DRY_RUN`
guard so destructive writes also default to safe:

```python
# ── Configuration ────────────────────────────────────────────
DRY_RUN = True           # Set False to execute changes
SHOW_FULL_PII = False    # Set True only if explicitly needed
USER_ID = 12345
```

Both flags follow the same default-safe rule: `True` in the safe state,
flipped to `False` only as a conscious step.

## Sectioned snippets, not functions

Write snippets as **sequential top-level sections** the operator can
copy-paste section by section into the shell. Avoid wrapping in
functions or `if __name__ == '__main__'` blocks unless the same logic
runs in a loop. Sections make it easy to stop after the lookup phase
without executing the mutation phase.

```python
# ── Imports ──────────────────────────────────────────────────
from myapp.users.models import User

# ── Configuration ────────────────────────────────────────────
DRY_RUN = True
SHOW_FULL_PII = False
USER_ID = 12345

# ── PII Masking ───────────────────────────────────────────────
# (paste the mask() helper block here)

# ── Lookup ───────────────────────────────────────────────────
user = User.objects.get(id=USER_ID)
print(f"Name:  {mask(user.first_name)} {mask(user.last_name)}")
print(f"Email: {mask(user.email, 'email')}")

# ── Mutation (gated by DRY_RUN) ───────────────────────────────
if DRY_RUN:
    print("[DRY_RUN] Would update user.is_active = False")
else:
    user.is_active = False
    user.save(update_fields=["is_active"])
    print(f"[REAL] Updated {mask(user.email, 'email')}")
```

## Don't kill the shell

Never `sys.exit()`, `raise SystemExit(...)`, or `exit()` inside a
production shell. These end the shell session (or, depending on host
shape, the whole pod). Print a warning and continue with later sections
gracefully:

```python
# WRONG - kills the shell
if not test_user:
    raise SystemExit(1)

# CORRECT - warn and let later sections handle absence
if not test_user:
    print("[WARN] No matching user - skipping mutation section.")
else:
    # ... mutation code ...
```

## When to flip `SHOW_FULL_PII = True`

Rare. Examples:

- An operator (not an agent) is debugging an encoding bug where the masked
  output hides the actual character that's broken.
- A regulatory request (subject access request, lawful warrant) requires
  full unmasked output for a specific legitimate identity.
- A migration verification step where masked output would mask the
  difference being checked.

In every case:

1. The override is set in the file, with a one-line comment explaining
   the legitimate basis.
2. The unmasked output is treated as restricted data and not pasted into
   chat, ticket bodies, or AI agent contexts.
3. The override is reverted before the file is shared, committed, or
   archived.

## Why "by default" matters more than "always"

A snippet that *can* mask but doesn't by default leaks PII the first time
someone copies it without thinking. A snippet that masks by default leaks
nothing the first time and only leaks deliberately, with someone's name
attached to the override commit. Defaults are the privacy boundary.

This pattern pairs naturally with [`anonymize.py`](anonymize.py) for the
inverse case where raw text already exists and needs scrubbing before
sharing. Two tools, same shape language, full coverage of the
"don't paste PII into the chatbot" problem.
