## ADDED Requirements

### Requirement: JSON statistics output via --stats-json flag
The system SHALL accept a `--stats-json` flag that emits a single JSON object containing processing statistics to stderr after all output is flushed to stdout.

#### Scenario: Basic JSON stats output
- **WHEN** user runs `lessence --stats-json < app.log`
- **THEN** compressed output appears on stdout AND a valid JSON object appears on stderr containing at minimum: `input_lines`, `output_lines`, `compression_ratio`, `collapsed_groups`, `lines_saved`, `patterns_detected`, `elapsed_ms`, and `pattern_hits`

#### Scenario: JSON stats with piped output
- **WHEN** user runs `lessence --stats-json < app.log > compressed.log 2> stats.json`
- **THEN** `stats.json` SHALL contain exactly one valid JSON object AND `compressed.log` SHALL contain compressed output with no JSON

### Requirement: --stats-json suppresses human-readable stats
When `--stats-json` is active, the human-readable markdown statistics footer SHALL NOT be printed. The JSON object replaces it entirely.

#### Scenario: No duplicate stats
- **WHEN** user runs `lessence --stats-json < app.log`
- **THEN** stderr SHALL contain only the JSON object, not the markdown stats footer

#### Scenario: --no-stats with --stats-json
- **WHEN** user runs `lessence --no-stats --stats-json < app.log`
- **THEN** stderr SHALL contain the JSON stats object (--stats-json overrides --no-stats for JSON output)

### Requirement: --stats-json without --stats-json produces no JSON
The system SHALL NOT emit JSON to stderr unless `--stats-json` is explicitly provided.

#### Scenario: Default behavior unchanged
- **WHEN** user runs `lessence < app.log` without `--stats-json`
- **THEN** stderr SHALL contain the human-readable stats footer (if --no-stats is not set) and no JSON

### Requirement: JSON schema stability
The JSON output SHALL include all pattern category fields even when their count is zero, to ensure predictable schema for consumers.

#### Scenario: Zero-count categories included
- **WHEN** input contains no kubernetes patterns
- **THEN** the `pattern_hits` object SHALL include `"kubernetes": 0` rather than omitting the field

### Requirement: Elapsed time measurement
The `elapsed_ms` field SHALL measure wall-clock time from the start of input processing to completion of output, in milliseconds.

#### Scenario: Elapsed time is positive
- **WHEN** any input is processed with `--stats-json`
- **THEN** `elapsed_ms` SHALL be a non-negative integer

### Requirement: Compression ratio calculation
The `compression_ratio` field SHALL be a float representing the percentage of lines saved (lines_saved / input_lines * 100).

#### Scenario: Compression ratio accuracy
- **WHEN** 100 lines are processed and 60 are saved
- **THEN** `compression_ratio` SHALL be `60.0`
