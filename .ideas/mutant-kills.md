# Mutation Testing Kill Plan

Results from `cargo mutants -f src/normalize.rs`: 50 caught, 38 missed (55% kill rate).
Deduplicated missed mutants grouped by function, with test strategy for each.

## 1. `similarity_score` — 16 missed mutants

The core similarity calculation has zero direct unit tests. All testing is
indirect via `are_similar()` which just checks a threshold.

### Missed mutations
- Line 233: `min_len / max_len` — replacing `/` with `*` or `%` not caught
- Line 234: `length_ratio < 0.7` — changing `<` to `==` or `<=` not caught
- Line 235: `length_ratio * 100.0` — changing `*` to `+` or `/` not caught
- Line 244: `i < s2_chars.len()` — changing `<` to `>` not caught
- Line 244: `c1 == s2_chars[i]` — changing `==` to `!=` not caught
- Line 245: `matches += 1` — changing `+=` to `-=` or `*=` not caught
- Line 249: `(matches / max_len) * 100.0` — changing `*` to `/` not caught

### Test strategy
Add direct tests for `similarity_score` with known inputs and exact expected scores:

```rust
#[test]
fn test_similarity_score_identical() {
    // "hello" vs "hello" → 100.0
}

#[test]
fn test_similarity_score_completely_different() {
    // "aaaa" vs "zzzz" → 0.0
}

#[test]
fn test_similarity_score_partial_match() {
    // "hello" vs "hella" → 80.0 (4/5 chars match)
}

#[test]
fn test_similarity_score_length_ratio_rejection() {
    // "ab" vs "abcdefghij" → rejected by 0.7 ratio check, returns ratio*100
}

#[test]
fn test_similarity_score_empty() {
    // "" vs "" → 100.0
    // "" vs "hello" → 0.0
}
```

These kill all 16 mutants because any math change produces a wrong score.

## 2. `summarize_variation_types` — 8 missed mutants

Returns which token types differ between first and last lines of a group
(e.g., "IP", "timestamp"). No direct tests exist.

### Missed mutations
- Line 310: replacing return with `vec![]`, `vec![String::new()]`, `vec!["xyzzy"]`
- Line 371: `self.config.essence_mode && token_type == "timestamp"` — `&&`→`||`, `==`→`!=`
- Line 379: `first_vals != last_vals` — `!=`→`==`

### Test strategy
Test with constructed token lists that have known variations:

```rust
#[test]
fn test_variation_types_different_ips() {
    // first: [IPv4("10.0.0.1")], last: [IPv4("10.0.0.2")]
    // → ["IP"]
}

#[test]
fn test_variation_types_same_tokens() {
    // first: [IPv4("10.0.0.1")], last: [IPv4("10.0.0.1")]
    // → [] (no variation)
}

#[test]
fn test_variation_types_essence_mode_skips_timestamps() {
    // essence_mode=true, first: [Timestamp("T1")], last: [Timestamp("T2")]
    // → [] (timestamps ignored in essence mode)
}

#[test]
fn test_variation_types_multiple_types() {
    // first: [IPv4("1"), Uuid("a")], last: [IPv4("2"), Uuid("b")]
    // → ["IP", "UUID"] (sorted)
}
```

## 3. `normalize_line` short-circuit — 2 missed mutants

### Missed mutations
- Line 86: `normalize_ips || normalize_ports || normalize_fqdns` — `||`→`&&`

### Test strategy
Test that disabling individual network sub-flags still allows others to work:

```rust
#[test]
fn test_normalize_ips_only() {
    // config: normalize_ips=true, normalize_ports=false, normalize_fqdns=false
    // input with IP → IP normalized, ports kept literal
}

#[test]
fn test_normalize_ports_only() {
    // config: normalize_ips=false, normalize_ports=true
    // input with port → port normalized, IPs kept literal
}
```

## Priority

1. **similarity_score** (16 mutants) — highest impact, core algorithm untested
2. **summarize_variation_types** (8 mutants) — affects user-visible output
3. **normalize_line short-circuit** (2 mutants) — edge case, lower priority

Estimated effort: ~1 hour for all three groups.
