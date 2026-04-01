## Why

lessence always exits 0, even when the logs contain errors. In CI pipelines, you want to gate on log content — fail the build if ERROR or FATAL lines appear. Currently this requires a separate `grep` step after lessence, which defeats the purpose of a single pipeline tool.

## What Changes

- New `--fail-on-pattern <regex>` flag that scans raw input lines against a regex
- Exit code 1 when the pattern matches any input line, 0 when clean
- Exit code 2 reserved for tool errors (trivy/hadolint convention)
- Compressed output is always emitted regardless — you get diagnosis AND gating in one step

## Capabilities

### New Capabilities
- `fail-on-pattern`: CI exit code gating via regex pattern matching on input lines

### Modified Capabilities
<!-- None -->

## Impact

- `src/main.rs`: New CLI flag, regex compilation, match scanning during ingestion, exit code logic
- `src/config.rs`: New `fail_pattern: Option<String>` field
- `regex` already a dependency
