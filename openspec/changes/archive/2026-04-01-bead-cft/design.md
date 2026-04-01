## Context

lessence processes logs through: normalize → group similar → fold duplicates → output. Currently, `finish()` flushes groups in buffer order (roughly chronological). Groups already track their line count via `PatternGroup::count()`. The data for frequency sorting exists — it just needs reordering before output.

The main challenge: in streaming mode, `process_line()` emits output incrementally as groups become "safe" to flush. For `--top N`, we need ALL groups before we can sort. This means `--top` must buffer everything and emit at the end, similar to how `--format markdown` already works.

## Goals / Non-Goals

**Goals:**
- Add `--top N` flag to CLI and Config
- Collect all groups, sort by count descending, output top N
- Show count prominently and a coverage footer

**Non-Goals:**
- Changing the default output mode (stays chronological)
- Adding a general `--sort` flag (unnecessary complexity for a pipe tool)
- Streaming top-N (would require approximate algorithms like Count-Min Sketch)

## Decisions

### 1. Buffer all output when --top is active

When `--top` is set, suppress incremental output from `process_line()`. After all input is consumed, call `finish()` to get remaining groups, then sort all groups by count and emit the top N.

This mirrors how `--format markdown` already works (sets `use_structured_output` and collects into `collected_outputs`). The implementation can reuse that pattern.

**Alternative**: Add a sorting pass inside `finish()` — rejected because `finish()` currently returns formatted strings, not structured data with counts. We'd need to parse counts back out of strings.

### 2. New method `finish_top_n(n: usize)` on PatternFolder

Returns `Vec<(usize, String)>` — (count, formatted_output) pairs sorted by count descending, truncated to N. This keeps the top-N logic in the folder where the group data lives.

### 3. Count format: `[Nx]` prefix

Prepend `[1247x]` to each group's output. Distinct from the existing `[+N similar]` suffix which shows how many lines were collapsed within a group.

### 4. Footer on stderr (not stdout)

The coverage footer (`showing top 5 of 142 patterns...`) goes to stderr so stdout remains clean for piping. Consistent with how stats already go to stderr in some modes.

## Risks / Trade-offs

- [Memory] `--top` buffers all output in memory. For very large logs this could be significant. → Acceptable because the compressed output is already much smaller than input, and `--max-lines` can cap input size.
- [Interaction with --format markdown] Both need buffered output. → Handle by checking both flags and using the appropriate output path.
