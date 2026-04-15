---
name: pattern-dev
description: >-
  Pattern detection internals — detection order, adding new patterns,
  normalization pipeline, timestamp architecture. Use when editing
  src/patterns/ or src/normalize.rs, adding a pattern, fixing detection,
  changing normalization order.
---

# Pattern Development

## Detection Order

Order matters — earlier patterns consume text first, preventing later patterns
from matching the same content. Timestamps before Network preserves URLs.
Quoted strings last to avoid consuming tokens detected by earlier patterns.
Actual order in `normalize.rs`:

1. **Timestamps** — 30+ formats via unified registry (`patterns/timestamp/`)
2. **Email** — RFC 5322 (`patterns/email.rs`)
3. **Paths** — before Network to preserve URLs (`patterns/path.rs`)
4. **JSON** — structure detection (`patterns/json.rs`)
5. **UUIDs** — standard format (`patterns/uuid.rs`)
6. **Network** — IPs, ports, FQDNs (`patterns/network.rs`)
7. **Hashes** — MD5, SHA1, SHA256, SHA512 (`patterns/hash.rs`)
8. **Process IDs** — PIDs, thread IDs (`patterns/process.rs`)
9. **Kubernetes** — namespaces, pods, volumes (`patterns/kubernetes.rs`)
10. **HTTP Status** — status codes (`patterns/http_status.rs`)
11. **Bracket Context** — `[error]`-style tags (`patterns/bracket_context.rs`)
12. **Key-Value** — `key=value` pairs (`patterns/key_value.rs`)
13. **Log Module** — level + module patterns (`patterns/log_module.rs`)
14. **Structured Messages** — component + level (`patterns/structured.rs`)
15. **Durations** — time and size values (`patterns/duration.rs`)
16. **Names** — variable names (`patterns/names.rs`) — always enabled
17. **Quoted Strings** — last to avoid consuming other tokens (`patterns/quoted.rs`)

## Normalization Pipeline

`Normalizer` struct in `normalize.rs` orchestrates detection:

1. `Normalizer::normalize_line(original) -> Result<LogLine>` is the entry point
2. Each detector has `DetectorName::detect_and_replace(&normalized) -> (String, Vec<Token>)`
3. Detectors are called in the order above, each replacing matched content with tokens (`<IP>`, `<TIMESTAMP>`, `<UUID>`, etc.)
4. The normalized line + tokens are returned as a `LogLine`
5. A hash of the normalized text is computed for fast similarity comparison

Token variants are defined in `patterns/mod.rs` as the `Token` enum.

## Timestamp Architecture

The timestamp system uses a unified registry (`patterns/timestamp/registry.rs`):

- **30+ patterns** covering ISO 8601, RFC 3339, syslog, K8s, Apache, PostgreSQL, etc.
- **Longest-match-first** — overlap resolution by length, then priority
- **Unix timestamps** demoted to lowest priority to avoid false positives on plain numbers
- **LazyLock** for thread-safe static initialization

Key files:
- `patterns/timestamp/mod.rs` — public API re-exports + `TimestampDetector` legacy shim that `normalize.rs` calls into
- `patterns/timestamp/registry.rs` — pattern definitions and merging
- `patterns/timestamp/detector.rs` — `UnifiedTimestampDetector` (the actual engine behind the shim)
- `patterns/timestamp/formats.rs` — format enum and metadata
- `patterns/timestamp/priority.rs` — `PatternPriority` + `FormatFamily` (implements the overlap-resolution logic)

## Adding a New Pattern

1. Create `src/patterns/your_pattern.rs`
2. Implement `pub fn detect_and_replace(line: &str) -> (String, Vec<Token>)`
3. Add the token variant to `Token` enum in `patterns/mod.rs`
4. Add `pub mod your_pattern;` to `patterns/mod.rs`
5. Wire into `normalize.rs` at the correct position in detection order
6. Add to `--disable-patterns` handling in `main.rs` (the `disable_patterns` → `config.normalize_*` mapping)
7. Add stats counter to `FoldingStats` in `folder.rs`
8. Write unit tests with realistic log samples
9. Test ReDoS resistance with malicious inputs (see `testing` skill)

## Essence Mode

`--essence` is a flag on `Config` (`config.rs:24` `essence_mode: bool`), not a
separate module. The standalone `essence/` module was deleted as dead code.

Timestamps are already tokenized to `<TIMESTAMP>` by the normal `TimestampDetector`
in every mode — that's not essence-specific. What `--essence` actually does is
**suppress timestamp variations during variation-type aggregation**
(`normalize.rs:355-358`): when comparing the first and last line in a group,
timestamp token differences are ignored, so groups that differ only by timestamp
don't get flagged as "varying: timestamp" in the rollup.

Net effect: structural comparison between log periods works, because the same
template with a different time now counts as the same pattern.
