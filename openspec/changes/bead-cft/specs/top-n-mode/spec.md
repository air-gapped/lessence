## ADDED Requirements

### Requirement: Top-N flag shows most frequent patterns
The CLI SHALL accept a `--top N` flag that outputs only the N most frequent pattern groups, sorted by occurrence count descending.

#### Scenario: Top 5 from a large log
- **WHEN** user runs `lessence --top 5 < app.log` where the log produces 100+ pattern groups
- **THEN** output shows exactly 5 groups, sorted from most frequent to least frequent

#### Scenario: Top N larger than total groups
- **WHEN** user runs `lessence --top 20 < app.log` where the log produces only 8 pattern groups
- **THEN** output shows all 8 groups sorted by frequency (no error, just shows what's available)

#### Scenario: Default behavior unchanged
- **WHEN** user runs `lessence < app.log` without --top flag
- **THEN** output is chronological as before (no change to default behavior)

### Requirement: Count displayed prominently in top-N output
When `--top` is active, each group's output SHALL begin with a count indicator showing how many input lines matched that pattern.

#### Scenario: Count format
- **WHEN** a pattern group matched 1247 input lines
- **THEN** the output line starts with `[1247x]` followed by the representative log line

### Requirement: Top-N footer shows coverage context
When `--top` is active, a footer SHALL be displayed showing how many total groups exist and what percentage of input lines the shown groups cover.

#### Scenario: Footer content
- **WHEN** user runs `lessence --top 5 < app.log` and there are 142 total groups
- **THEN** footer shows something like `(showing top 5 of 142 patterns, covering 98.2% of input lines)`

### Requirement: Top-N works with file arguments
The `--top` flag SHALL work with both stdin and file arguments.

#### Scenario: Top-N with file argument
- **WHEN** user runs `lessence --top 3 app.log`
- **THEN** output shows top 3 patterns from app.log sorted by frequency
