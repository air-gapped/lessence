## Context

Pure removal — no new code, no migration. The feature was never widely adopted and the token counting was fundamentally wrong.

## Goals / Non-Goals

**Goals:**
- Cleanly remove all traces of `--max-tokens` functionality
- Ensure all tests pass after removal

**Non-Goals:**
- Replacing with a different output-limiting mechanism (future work if needed)
- Backward compatibility shim (clean break)

## Decisions

**1. Full removal, no deprecation warning**

The flag was misleading. A deprecation cycle would just extend the life of a broken feature.

**2. Remove token estimates from stats output**

The `print_stats()` method currently shows "~N tokens" estimates. These are meaningless (50 tokens/line guess). Remove them, keep line counts which are accurate.

## Risks / Trade-offs

- [Breaking change] Users relying on `--max-tokens` will get an unknown flag error. → Acceptable; the feature was dishonest.
