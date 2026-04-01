## ADDED Requirements

### Requirement: Exit non-zero when pattern matches input
The system SHALL accept a `--fail-on-pattern <regex>` flag. When provided, the system SHALL exit with code 1 if any raw input line matches the regex, and exit with code 0 if no lines match.

#### Scenario: Pattern matches input
- **WHEN** user runs `echo "ERROR something failed" | lessence --fail-on-pattern "ERROR"`
- **THEN** compressed output SHALL appear on stdout AND the process SHALL exit with code 1

#### Scenario: Pattern does not match input
- **WHEN** user runs `echo "INFO all good" | lessence --fail-on-pattern "ERROR"`
- **THEN** compressed output SHALL appear on stdout AND the process SHALL exit with code 0

#### Scenario: Invalid regex
- **WHEN** user runs `lessence --fail-on-pattern "[invalid"`
- **THEN** the process SHALL exit with code 2 and print an error message to stderr

### Requirement: Output always produced regardless of match
The compressed output SHALL always be emitted to stdout, even when the pattern matches. The exit code is the only signal of the match.

#### Scenario: Output with match
- **WHEN** pattern matches and `--fail-on-pattern` is active
- **THEN** stdout SHALL contain the same compressed output as without the flag

### Requirement: Pattern matches raw input lines
The regex SHALL be tested against original input lines before normalization, not against normalized/tokenized text.

#### Scenario: Match on original text
- **WHEN** input contains `ERROR timeout after 30s on host 10.0.0.1`
- **AND** pattern is `timeout`
- **THEN** the pattern SHALL match (tested against raw line, not normalized)
