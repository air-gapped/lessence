## ADDED Requirements

### Requirement: Accept positional file arguments
The CLI SHALL accept zero or more file paths as positional arguments after all flags. When file arguments are provided, the tool SHALL read from those files instead of stdin.

#### Scenario: Single file argument
- **WHEN** user runs `lessence app.log`
- **THEN** the tool reads from `app.log` and produces compressed output identical to `lessence < app.log`

#### Scenario: Multiple file arguments
- **WHEN** user runs `lessence app.log server.log worker.log`
- **THEN** the tool concatenates all files into a single input stream and compresses them together as one log

#### Scenario: No arguments (stdin fallback)
- **WHEN** user runs `echo "log line" | lessence` with no file arguments
- **THEN** the tool reads from stdin (current behavior, unchanged)

### Requirement: Explicit stdin via dash
The CLI SHALL interpret `-` as a file argument meaning "read from stdin." This allows mixing stdin with file arguments.

#### Scenario: Dash as stdin
- **WHEN** user runs `lessence -` 
- **THEN** the tool reads from stdin, equivalent to `lessence` with no arguments

#### Scenario: Dash mixed with files
- **WHEN** user runs `cat extra.log | lessence app.log - server.log`
- **THEN** the tool reads `app.log`, then stdin, then `server.log`, concatenated in order

### Requirement: Graceful error handling on bad files
The CLI SHALL warn on stderr and skip files that cannot be opened, continuing to process remaining files. It SHALL NOT abort the entire run because of one unreadable file.

#### Scenario: Nonexistent file among valid files
- **WHEN** user runs `lessence app.log missing.log server.log`
- **THEN** stderr shows a warning about `missing.log`, and output contains compressed results from `app.log` and `server.log`

#### Scenario: All files invalid
- **WHEN** user runs `lessence missing1.log missing2.log`
- **THEN** stderr shows warnings for both files, and the tool exits with a non-zero exit code

### Requirement: Shell handles glob expansion
The CLI SHALL NOT implement its own glob expansion. File argument expansion (e.g., `*.log`) is handled by the shell before the process starts.

#### Scenario: Shell glob
- **WHEN** user runs `lessence /var/log/*.log` in a shell with matching files
- **THEN** the shell expands the glob to individual file paths, and the tool processes each one
