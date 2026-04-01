## Why

lessence only accepts input via stdin (`lessence < app.log`). Every comparable CLI tool (grep, rg, cat, bat, jq) accepts file arguments. This creates friction on every invocation — both for humans who expect `lessence app.log` and for coding agents that naturally write file arguments first and have to retry with redirection.

## What Changes

- Add optional positional file arguments to the CLI
- When files are given, read and concatenate them as input (like cat/jq)
- When no files are given, read from stdin (current behavior, unchanged)
- Support `-` as explicit stdin in the file list
- Warn and skip files that can't be opened (don't abort on one bad file)

## Capabilities

### New Capabilities
- `file-input`: Accept file paths as positional arguments, concatenate into a single input stream, fall back to stdin when none given

### Modified Capabilities

## Impact

- `src/main.rs` — CLI struct gets a new positional arg, input reading logic changes from hardcoded stdin to a dispatcher
- No changes to the processing pipeline (normalize, fold, output) — it still receives lines from a `BufRead`
- No new dependencies needed
- No breaking changes — stdin-only usage continues to work identically
