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
The order is declared in one place: the `DETECTOR_ORDER` table in
`normalize.rs` (one `DetectorEntry` per detector with `enabled` config gate,
`prefilter` cheap byte check, and the `run` hook). `normalize_line` just
walks the table:

1. **CPU quantities** — millicpu fields (`cpu: 250m`) before the JSON, key-value and minute-duration passes can take the value (`DurationDetector::cpu_quantities`, `patterns/duration.rs`)
2. **Timestamps** — one scored table of about 40 formats (`patterns/timestamp/detector.rs`)
3. **Email** — RFC 5322 (`patterns/email.rs`)
4. **Paths** — before Network to preserve URLs; also carries the `&Event{ObjectMeta:{…}` pass, which therefore runs before JSON's copy. An escaped flat struct (`\"{phase:Running}\"`) stays literal: its values are the event (`patterns/path.rs`)
5. **JSON** — the same Event pass (`patterns/json.rs`); shadowed by Paths, so `--disable-patterns json` does not reach it yet
6. **UUIDs** — standard format (`patterns/uuid.rs`)
7. **Network** — IPs, ports, FQDNs (`patterns/network.rs`)
8. **Hashes** — MD5, SHA1, SHA256, SHA512 (`patterns/hash.rs`)
9. **Process IDs** — PIDs, thread IDs (`patterns/process.rs`)
10. **Syslog host** — the positional host field between a normalized timestamp and a program tag (`replace_syslog_host`, `normalize.rs`); gated by the FQDN flag
11. **Kubernetes** — namespaces, pods, volumes (`patterns/kubernetes.rs`)
12. **HTTP Status** — status codes (`patterns/http_status.rs`)
13. **Bracket Context** — `[proxy]`-style context tags, a chain of them as one `<BRACKET_CONTEXT>` (`patterns/bracket_context.rs`). A level (`[error]`, `[NOTICE]`) is never a context: it stays literal and splits a chain. "Is this a level" is `briefing::word_to_level`, the crate's one level vocabulary — do not add a second list
14. **Key-Value** — `key=value` pairs; the key and separator stay and only the value folds (`timeout=<KEY_VALUE>`). `level` is not a foldable key (`patterns/key_value.rs`)
15. **Log Module** — level + module token for the statistics; Apache, nginx and systemd lines keep their text, the Java-logger form still folds to `[<LOG_WITH_MODULE>]` (`patterns/log_module.rs`)
16. **Structured Messages** — component + level token for stats only; the line text is preserved verbatim so distinct messages fold into distinct groups (`patterns/structured.rs`)
17. **Durations** — time and size values; a `<name>Duration=` field keeps its key (`podStartSLOduration=<DURATION_FIELD>`) (`patterns/duration.rs`)
18. **Names** — generated names; the component stays and only the generated tail folds (`nginx-<SUFFIX>`, `web-v2-<HASH>-hcwqj` → `web-v2-<SUFFIX>`) (`patterns/names.rs`) — gated by `--disable-patterns name` like the others
19. **Quoted Strings** — last to avoid consuming other tokens; its nested cascade honours the same `--disable-patterns` gates (`patterns/quoted.rs`)

## Normalization Pipeline

`Normalizer` struct in `normalize.rs` orchestrates detection:

1. `Normalizer::normalize_line(original) -> Result<LogLine>` is the entry point
2. Each detector has `DetectorName::detect_and_replace(&normalized) -> (String, Vec<Token>)`
3. `normalize_line` walks `DETECTOR_ORDER`, each entry replacing matched content with tokens (`<IP>`, `<TIMESTAMP>`, `<UUID>`, etc.)
4. A gate asks about the shape its detector folds, never about a word elsewhere on the line: a word such as `pod/`, `etcd`, `param=` or `update` must not switch a detector on or off for the whole line (the kubernetes deference and the bracket and SQL-word vetoes were removed for this, lessence-enl)
5. The normalized line + tokens are returned as a `LogLine`
6. A hash of the normalized text is computed for fast similarity comparison

Token variants are defined in `patterns/mod.rs` as the `Token` enum.

## Timestamp Architecture

The whole timestamp engine is one table, `PATTERNS` in `patterns/timestamp/detector.rs`:

- **About 40 formats**, each a name, a regex and a score: ISO 8601, RFC 2822/822, syslog, klog, Apache, asctime, PostgreSQL, epochs and more
- **Lowest score wins an overlap**, whatever the lengths; equal scores fall back to position, then table order. A format that a stronger one always matches on the same text can never be chosen, so it does not belong in the table
- **Unix epochs** score last, so a plain number never outranks a real date
- A `RegexSet` of the same table (`ASCII_CANDIDATES`) skips formats that cannot match a line before their regexes run
- Every format starts on a word boundary, and a weekday or month is spelled as the calendar name, not `\w{3}`

Key files:
- `patterns/timestamp/mod.rs` — public API re-exports and `DetectionResult` / `TimestampMatch`
- `patterns/timestamp/detector.rs` — the `PATTERNS` table and `UnifiedTimestampDetector`, the engine

## Adding a New Pattern

1. Create `src/patterns/your_pattern.rs`
2. Implement `pub fn detect_and_replace(line: &str) -> (String, Vec<Token>)`
3. Add the token variant to `Token` enum in `patterns/mod.rs`, plus its `KindFacts` row in `Token::facts()` and its arm in `Token::value_string()` — the taxonomy owns machine name, display label, stats bucket, sample-worthiness, and value stringification; the folder/renderer consumers are projections of it
4. Add `pub mod your_pattern;` to `patterns/mod.rs`
5. Add a `DetectorEntry` to `DETECTOR_ORDER` in `normalize.rs` at the correct position (set `enabled`, and a `prefilter` if a cheap byte check exists)
6. Add to `--disable-patterns` handling in `main.rs` (the `disable_patterns` → `config.normalize_*` mapping)
7. Add stats counter to `FoldingStats` in `folder/mod.rs`
8. Write unit tests with realistic log samples
9. Test ReDoS resistance with malicious inputs (see `testing` skill)

## Essence Mode

`--essence` is a flag on `Config` (`essence_mode: bool` in `src/config.rs`), not a
separate module. The standalone `essence/` module was deleted as dead code.

Timestamps are already tokenized to `<TIMESTAMP>` by the normal `TimestampDetector`
in every mode — that's not essence-specific. What `--essence` actually does is
**omit the time-range segment of the text rollup marker**
(`render_compact_marker` in `src/folder/mod.rs`): the `[+N similar | first → last | …]`
marker is printed without its `first → last` timestamps, so two runs of the same
log over different periods render identically.

Net effect: structural comparison between log periods works, because the same
template with a different time now counts as the same pattern.
