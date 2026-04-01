## ADDED Requirements

### Requirement: Shell completion generation via --completions flag
The system SHALL accept a `--completions <shell>` flag that prints a shell completion script to stdout and exits immediately without processing any input.

#### Scenario: Generate bash completions
- **WHEN** user runs `lessence --completions bash`
- **THEN** a valid bash completion script SHALL be printed to stdout and the process SHALL exit with code 0

#### Scenario: Generate zsh completions
- **WHEN** user runs `lessence --completions zsh`
- **THEN** a valid zsh completion script SHALL be printed to stdout

#### Scenario: Invalid shell name
- **WHEN** user runs `lessence --completions invalid`
- **THEN** clap SHALL reject the value with an error listing valid options

### Requirement: No input processing when generating completions
The `--completions` flag SHALL short-circuit before any log processing. It SHALL NOT read stdin or require input files.

#### Scenario: No stdin blocking
- **WHEN** user runs `lessence --completions bash` without piping input
- **THEN** the command SHALL complete immediately without waiting for stdin
