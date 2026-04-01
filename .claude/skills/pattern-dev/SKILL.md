---
name: pattern-dev
description: Pattern detection internals — detection order, adding new patterns, normalization pipeline, timestamp architecture. Use when editing src/patterns/ or src/normalize.rs.
---

# Pattern Development

## Detection Order

Order matters — earlier patterns take priority in normalization:

1. **Timestamps** — 30+ formats via unified registry (`patterns/timestamp/`)
2. **Email** — RFC 5322 (`patterns/email.rs`)
3. **Paths** — before Network to preserve URLs (`patterns/path.rs`)
4. **JSON** — structure detection (`patterns/json.rs`)
5. **UUIDs** — standard format (`patterns/uuid.rs`)
6. **Network** — IPs, ports (`patterns/network.rs`)
7. **Hashes** — MD5, SHA1, SHA256 (`patterns/hash.rs`)
8. **Process IDs** — PIDs, thread IDs (`patterns/process.rs`)
9. **Kubernetes** — namespaces, pods, volumes (`patterns/kubernetes.rs`)
10. **Enhanced** — HTTP status, brackets, key=value (`patterns/http_status.rs`, `bracket_context.rs`, `key_value.rs`)
11. **Durations** — time and size values (`patterns/duration.rs`)
12. **Names** — variable names (`patterns/names.rs`)
13. **Quoted strings** — last to avoid consuming other tokens (`patterns/quoted.rs`)

## Normalization Pipeline

`normalize.rs` orchestrates pattern detection:

1. Each pattern detector has `detect_and_replace(line) -> (normalized, Vec<Token>)`
2. Detectors are called in order above
3. Each replaces matched content with tokens like `<IP>`, `<TIMESTAMP>`, `<UUID>`
4. The normalized line + tokens are returned as a `LogLine`
5. Similarity matching uses character overlap on normalized text

## Timestamp Architecture

The timestamp system uses a unified registry (`patterns/timestamp/registry.rs`):

- **30+ patterns** covering ISO 8601, RFC 3339, syslog, K8s, Apache, PostgreSQL, etc.
- **Longest-match-first** — overlap resolution by length, then priority
- **Unix timestamps** demoted to lowest priority to avoid false positives on plain numbers
- **LazyLock** for thread-safe static initialization

Key files:
- `patterns/timestamp/registry.rs` — pattern definitions and merging
- `patterns/timestamp/detector.rs` — detection engine
- `patterns/timestamp/formats.rs` — format enum and metadata

## Adding a New Pattern

1. Create `src/patterns/your_pattern.rs`
2. Implement `pub fn detect_and_replace(line: &str) -> (String, Vec<Token>)` (or similar)
3. Add the token variant to `Token` enum in `patterns/mod.rs`
4. Add `pub mod your_pattern;` to `patterns/mod.rs`
5. Wire it into `normalize.rs` at the correct position in the detection order
6. Add to `--disable-patterns` validation in `cli/mod.rs`
7. Add stats counter to `FoldingStats` in `folder.rs`
8. Write unit tests with realistic log samples
9. Test ReDoS resistance with malicious inputs

## Essence Mode

`essence/processor.rs` removes timestamps from normalized output, replacing them with `<TIMESTAMP>`. This enables pattern analysis independent of when events occurred. Uses the same unified timestamp registry as the main detector.
