## Why

lessence currently prints human-readable stats to stderr (lines processed, compression ratio, etc.), but there's no machine-readable output for scripts, CI pipelines, or monitoring dashboards. A `--stats-json` flag would let automation consumers get structured statistics without parsing text.

## What Changes

- New `--stats-json` flag that emits a single JSON object to stderr after processing completes
- JSON fields: `input_lines`, `output_lines`, `compression_ratio`, `groups`, `elapsed_ms`, `pattern_hits`
- Orthogonal to `--no-stats`: `--no-stats --stats-json` gives clean stdout + JSON stderr
- When `--stats-json` is active, the human-readable stats footer is suppressed (replaced by JSON)

## Capabilities

### New Capabilities
- `stats-json`: Structured JSON statistics output on stderr via `--stats-json` flag

### Modified Capabilities
<!-- No existing spec-level requirements are changing -->

## Impact

- `src/main.rs`: New CLI flag, JSON emission after processing
- `src/config.rs`: New `stats_json: bool` field
- `src/folder.rs`: May need to expose timing/count data if not already available
- `serde_json` already in dependencies (no new deps)
