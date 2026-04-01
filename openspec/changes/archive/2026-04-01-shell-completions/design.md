## Context

lessence uses clap derive for CLI parsing, no subcommands. clap_complete generates completion scripts at runtime from the clap Command definition.

## Goals / Non-Goals

**Goals:**
- `lessence --completions bash` prints bash completion script to stdout and exits
- Support all shells clap_complete provides (bash, zsh, fish, elvish, powershell)

**Non-Goals:**
- No build.rs generation (runtime is simpler)
- No auto-installation (user pipes to the right file)

## Decisions

**1. Use `clap_complete::Shell` enum as value type**

clap_complete provides a `Shell` enum that implements `ValueEnum`, so clap parses it directly. No manual validation needed.

**2. Handle before config construction**

The `--completions` flag should short-circuit before any config/processing logic — just print and exit. Check it right after `Cli::parse()`.

**3. Use `clap_complete::generate` with `Cli::command()`**

`Cli::command()` returns the clap `Command` definition including all flags, which is what the completion generator needs.

## Risks / Trade-offs

- [New dependency] `clap_complete` is from the clap ecosystem, well-maintained, small. Acceptable.
