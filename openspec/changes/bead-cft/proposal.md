## Why

lessence outputs compressed logs in chronological order, which is great for reading logs as a timeline. But for triage — "what's the most common error?" — you want frequency-sorted output. Currently an agent has to read the full output and mentally sort by the `[+N similar]` counts. `--top N` makes the answer instant.

## What Changes

- Add `--top N` flag that shows only the N most frequent pattern groups, sorted by count descending
- Output format changes: count shown prominently, e.g. `[1247x] Connection refused from <IP>`
- Footer shows context: `(showing top 5 of 142 patterns, covering 98.2% of input lines)`
- All input is still processed (normalization, grouping, folding) — only the output is filtered and reordered

## Capabilities

### New Capabilities
- `top-n-mode`: Frequency-sorted output showing only the N most common pattern groups

### Modified Capabilities

## Impact

- `src/main.rs` — new CLI flag
- `src/config.rs` — new config field
- `src/folder.rs` — new method to return groups sorted by frequency, formatting changes for count display
- No changes to normalization or pattern detection
- No breaking changes — default behavior unchanged
