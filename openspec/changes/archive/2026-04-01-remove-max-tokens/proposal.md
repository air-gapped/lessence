## Why

The `--max-tokens` flag uses fake token counting (`words / 0.75`) that is dishonest — it doesn't reflect actual tokenizer behavior. The use case (capping output for LLM context windows) is better served by `head -n` or piping through standard Unix tools.

## What Changes

- **BREAKING**: Remove `--max-tokens` CLI flag, `parse_token_count()` function, `max_tokens` config field, and all token counting/limiting logic
- Remove `count_tokens()` methods from folder.rs
- Remove token estimation from stats output
- Update documentation (CLAUDE.md flags list)

## Capabilities

### New Capabilities
<!-- None — this is a removal -->

### Modified Capabilities
<!-- No spec-level changes — removing an undocumented/misleading feature -->

## Impact

- `src/main.rs`: Remove CLI arg, `parse_token_count()`, token limit checks in main loop
- `src/config.rs`: Remove `max_tokens` field
- `src/folder.rs`: Remove `count_tokens()`, token estimation in `print_stats()`
- `CLAUDE.md`: Remove `--max-tokens` from flags list
- Tests referencing `max_tokens` need updating
