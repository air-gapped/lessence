## Why

No shell completions exist for lessence. Users must remember all flag names. Adding completion generation is standard CLI polish and takes minimal effort with clap_complete.

## What Changes

- Add `clap_complete` dependency
- Add `--completions <shell>` flag that prints a completion script and exits
- Supports bash, zsh, fish, elvish, powershell

## Capabilities

### New Capabilities
- `shell-completions`: Generate shell completion scripts via `--completions <shell>` flag

### Modified Capabilities
<!-- None -->

## Impact

- `Cargo.toml`: New dependency `clap_complete`
- `src/main.rs`: New flag and generation logic (~15 lines)
