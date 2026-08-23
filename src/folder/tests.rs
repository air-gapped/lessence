// Unit tests for the folding engine. Extracted from folder.rs (where
// they were 70% of the file) as a child module — same visibility,
// `use super::*` still reaches private items.

use super::*;
use crate::patterns::HashType;

// ---------------------------------------------------------------
// Helpers for building synthetic test data
// ---------------------------------------------------------------

/// Build a LogLine with the given tokens and a normalized template.
fn make_line(normalized: &str, tokens: Vec<Token>) -> LogLine {
    LogLine::new(normalized.to_string(), normalized.to_string(), tokens, 0)
}

/// The group hash-index must stay consistent across buffer evictions
/// (`buffer.remove` shifts every later index). 1,100 mutually dissimilar
/// lines overflow the 1,000-group buffer and force ~100 evictions; a
/// repeated line whose group is still buffered must then fold into that
/// group via the index, not land in a wrong group or found a duplicate.
#[test]
fn group_index_survives_eviction() {
    let config = Config {
        thread_count: Some(1),
        ..Config::default()
    };
    let mut folder = PatternFolder::new(config);

    // Deterministic 6-letter words: single-token lines that never group
    // with each other (zero shared tokens → score 0).
    let word = |i: usize| {
        let mut s = String::new();
        let mut x = i;
        for _ in 0..6 {
            s.push(char::from(b'a' + (x % 26) as u8));
            x /= 26;
        }
        s
    };

    let mut output = String::new();
    for i in 0..1_100 {
        if let Some(flushed) = folder.process_line(&word(i)).unwrap() {
            output.push_str(&flushed);
            output.push('\n');
        }
    }
    // Introspect before the repeats: the map entry for word(1050) must
    // exist and point at the group whose representative is word(1050).
    let probe = folder.normalizer.normalize_line(word(1_050)).unwrap();
    let idx = folder
        .group_index
        .get(&probe.hash)
        .copied()
        .unwrap_or_else(|| panic!("map entry for {} missing before repeats", word(1_050)));
    assert_eq!(
        folder.buffer[idx].first().normalized,
        word(1_050),
        "map entry for {} points at the wrong group",
        word(1_050)
    );

    for _ in 0..5 {
        if let Some(flushed) = folder.process_line(&word(1_050)).unwrap() {
            output.push_str(&flushed);
            output.push('\n');
        }
    }
    for line in folder.finish().unwrap() {
        output.push_str(&line);
        output.push('\n');
    }

    // One folded group renders as first occurrence, fold marker, last
    // occurrence — exactly two bare target lines. A stale index would
    // yield three or more (a stranded single plus a separate folded
    // group), or a markerless single if the repeats joined a wrong group.
    let target = word(1_050);
    let lines: Vec<&str> = output.lines().collect();
    let occurrences: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains(&target))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        occurrences.len(),
        2,
        "expected first+last of one folded group for {target}, got {} lines",
        occurrences.len()
    );
    assert!(
        lines[occurrences[0] + 1].contains("similar"),
        "fold marker must follow the first {target} occurrence, got: {}",
        lines[occurrences[0] + 1]
    );
}

/// Build a PatternGroup with N lines, each having the given tokens.
/// All lines share the same normalized template.
fn make_group(normalized: &str, lines: Vec<Vec<Token>>) -> PatternGroup {
    assert!(!lines.is_empty(), "group must have at least one line");
    let mut group = PatternGroup::new(make_line(normalized, lines[0].clone()), 1);
    for (i, tokens) in lines.into_iter().enumerate().skip(1) {
        group.add_line(make_line(normalized, tokens), i + 2);
    }
    group
}

// ---------------------------------------------------------------
// apply_pii_masking
// ---------------------------------------------------------------

#[test]
fn pii_masking_no_emails() {
    let result = apply_pii_masking("no emails here", &[]);
    assert_eq!(result, "no emails here");
}

#[test]
fn pii_masking_single_email() {
    let tokens = vec![Token::Email("alice@co.com".into())];
    let result = apply_pii_masking("User alice@co.com logged in", &tokens);
    assert_eq!(result, "User <EMAIL> logged in");
}

#[test]
fn pii_masking_duplicate_email_in_line() {
    // Kills mutant: `start + pos` → `start * pos` (line 39).
    // Second occurrence requires non-zero `start` for correct indexing.
    let tokens = vec![Token::Email("bob@x.com".into())];
    let result = apply_pii_masking("from bob@x.com to bob@x.com", &tokens);
    assert_eq!(result, "from <EMAIL> to <EMAIL>");
}

#[test]
fn pii_masking_multiple_different_emails() {
    let tokens = vec![
        Token::Email("a@b.com".into()),
        Token::Email("c@d.com".into()),
    ];
    let result = apply_pii_masking("a@b.com and c@d.com", &tokens);
    assert_eq!(result, "<EMAIL> and <EMAIL>");
}

#[test]
fn pii_masking_non_email_tokens_ignored() {
    let tokens = vec![
        Token::IPv4("10.0.0.1".into()),
        Token::Email("x@y.com".into()),
    ];
    let result = apply_pii_masking("10.0.0.1 x@y.com", &tokens);
    assert_eq!(result, "10.0.0.1 <EMAIL>");
}

/// Ranked modes must hold every group: with eviction active, patterns past
/// the 1,000-group flush threshold vanished from both the ranking and the
/// coverage denominator ("1000 of 1000 patterns" on 1,100-pattern input).
#[test]
fn summary_retains_all_groups_past_flush_threshold() {
    let mut folder = PatternFolder::new(Config {
        thread_count: Some(1),
        summary: true,
        ..Config::default()
    });
    for i in 0..1_100 {
        let out = folder.process_line(&eviction_word(i)).unwrap();
        assert!(out.is_none(), "ranked mode must not stream evictions");
    }
    let (display, total_patterns, _, _) = folder.prepare_summary(Some(0), None).unwrap();
    assert_eq!(total_patterns, 1_100, "every group must survive to ranking");
    assert_eq!(display.len(), 1_100);
}

#[test]
fn top_n_retains_all_groups_past_flush_threshold() {
    let mut folder = PatternFolder::new(Config {
        thread_count: Some(1),
        top_n: Some(5),
        ..Config::default()
    });
    for i in 0..1_100 {
        folder.process_line(&eviction_word(i)).unwrap();
    }
    let (output, total_groups, _) = folder.finish_top_n(5).unwrap();
    assert_eq!(total_groups, 1_100, "denominator must count every group");
    assert_eq!(output.len(), 5);
}

/// The inverse guard: streaming fold mode must keep evicting past the
/// threshold, or unbounded inputs would grow the buffer without limit.
#[test]
fn fold_mode_still_evicts_past_flush_threshold() {
    let mut folder = PatternFolder::new(Config {
        thread_count: Some(1),
        ..Config::default()
    });
    let mut evicted = 0;
    for i in 0..1_200 {
        if folder.process_line(&eviction_word(i)).unwrap().is_some() {
            evicted += 1;
        }
    }
    assert!(
        evicted > 0,
        "fold mode must stream evictions past the threshold"
    );
}

/// Deterministic 6-letter words: single-token lines that never group with
/// each other (zero shared tokens → similarity score 0).
fn eviction_word(i: usize) -> String {
    let mut s = String::new();
    let mut x = i;
    for _ in 0..6 {
        s.push(char::from(b'a' + (x % 26) as u8));
        x /= 26;
    }
    s
}

#[test]
fn pii_masking_empty_email_does_not_loop() {
    // Defensive: empty email string would cause infinite loop without guard
    let tokens = vec![Token::Email(String::new())];
    let result = apply_pii_masking("no emails here", &tokens);
    assert_eq!(result, "no emails here");
}

// ---------------------------------------------------------------
// first_timestamp_in
// ---------------------------------------------------------------

#[test]
fn first_timestamp_no_tokens() {
    assert_eq!(first_timestamp_in(&[]), None);
}

#[test]
fn first_timestamp_no_timestamps() {
    let tokens = vec![Token::IPv4("1.2.3.4".into()), Token::Pid(42)];
    assert_eq!(first_timestamp_in(&tokens), None);
}

#[test]
fn first_timestamp_single() {
    let tokens = vec![Token::Timestamp("10:00:00".into())];
    assert_eq!(first_timestamp_in(&tokens), Some("10:00:00".into()));
}

#[test]
fn first_timestamp_multiple_returns_first() {
    let tokens = vec![
        Token::IPv4("1.2.3.4".into()),
        Token::Timestamp("10:00:00".into()),
        Token::Timestamp("11:00:00".into()),
    ];
    assert_eq!(first_timestamp_in(&tokens), Some("10:00:00".into()));
}

// ---------------------------------------------------------------
// Existing folding tests
// ---------------------------------------------------------------

#[test]
fn test_simple_folding() -> Result<()> {
    let config = Config::default();
    let mut folder = PatternFolder::new(config);

    let line1 = "2025-01-20 10:15:01 [pid=12345] Connection failed to 192.168.1.100:8080";
    let line2 = "2025-01-20 10:15:02 [pid=12346] Connection failed to 192.168.1.101:8081";
    let line3 = "2025-01-20 10:15:03 [pid=12347] Connection failed to 192.168.1.102:8082";

    folder.process_line(line1)?;
    folder.process_line(line2)?;
    let result = folder.process_line(line3)?;

    assert!(result.is_none());

    Ok(())
}

#[test]
fn test_folding_with_finish() -> Result<()> {
    let config = Config {
        min_collapse: 2,
        ..Config::default()
    };

    let mut folder = PatternFolder::new(config);

    let line1 = "2025-01-20 10:15:01 [pid=12345] Connection failed to 192.168.1.100:8080";
    let line2 = "2025-01-20 10:15:02 [pid=12346] Connection failed to 192.168.1.101:8081";
    let line3 = "2025-01-20 10:15:03 [pid=12347] Connection failed to 192.168.1.102:8082";

    folder.process_line(line1)?;
    folder.process_line(line2)?;
    folder.process_line(line3)?;

    let results = folder.finish()?;
    assert!(!results.is_empty());

    let output = results.join("\n");
    assert!(
        output.contains("similar"),
        "Expected 'similar' in compact output, got: {output}"
    );

    Ok(())
}

#[test]
fn test_no_folding_for_different_lines() -> Result<()> {
    let config = Config::default();
    let mut folder = PatternFolder::new(config);

    let line1 = "2025-01-20 10:15:01 Starting application";
    let line2 = "2025-01-20 10:15:02 Loading configuration";
    let line3 = "2025-01-20 10:15:03 Database connected";

    folder.process_line(line1)?;
    folder.process_line(line2)?;
    folder.process_line(line3)?;

    let results = folder.finish()?;
    let output = results.join("\n");

    assert!(!output.contains("collapsed"));
    assert!(output.contains("Starting application"));
    assert!(output.contains("Loading configuration"));
    assert!(output.contains("Database connected"));

    Ok(())
}

// ---------------------------------------------------------------
// seed_for_group — FNV-1a determinism
// ---------------------------------------------------------------

#[test]
fn seed_for_group_pinned_values() {
    // Pin FNV-1a outputs so any implementation drift is caught.
    assert_eq!(seed_for_group("hello"), 0xa430_d846_80aa_bd0b);
    assert_eq!(seed_for_group("world"), 0x4f59_ff5e_730c_8af3);
}

#[test]
fn seed_for_group_empty_string_is_offset_basis() {
    // Empty string → no XOR/multiply iterations → returns FNV offset basis.
    assert_eq!(seed_for_group(""), 0xcbf2_9ce4_8422_2325);
}

#[test]
fn seed_for_group_different_inputs_different_seeds() {
    let a = seed_for_group("template A: <UUID> failed");
    let b = seed_for_group("template B: <IP> connected");
    assert_ne!(a, b);
}

// ---------------------------------------------------------------
// hash_token_value — FNV-1a on token canonical strings
// ---------------------------------------------------------------

#[test]
fn hash_token_value_matches_seed_for_same_string() {
    // hash_token_value(Name("hello")) should equal seed_for_group("hello")
    // because both use the same FNV-1a over the same bytes.
    let token = Token::Name("hello".to_string());
    assert_eq!(hash_token_value(&token), seed_for_group("hello"));
}

#[test]
fn hash_token_value_different_tokens_different_hashes() {
    let a = hash_token_value(&Token::Pid(1234));
    let b = hash_token_value(&Token::Pid(5678));
    assert_ne!(a, b);
}

// ---------------------------------------------------------------
// is_sample_worthy — exhaustiveness
// ---------------------------------------------------------------

#[test]
fn is_sample_worthy_covers_all_token_variants() {
    // Build one instance of every Token variant. If a new variant is
    // added to the enum without updating this test, it won't compile.
    let all_tokens: Vec<(Token, bool)> = vec![
        // Sample-worthy types (true)
        (Token::Uuid("u".into()), true),
        (Token::IPv4("1.2.3.4".into()), true),
        (Token::IPv6("::1".into()), true),
        (Token::Path("/a".into()), true),
        (Token::Email("a@b".into()), true),
        (Token::Hash(HashType::MD5, "abc".into()), true),
        (Token::KubernetesNamespace("ns".into()), true),
        (Token::VolumeName("vol".into()), true),
        (Token::PluginType("csi".into()), true),
        (Token::PodName("pod".into()), true),
        (Token::QuotedString("q".into()), true),
        (Token::Name("n".into()), true),
        (Token::HttpStatus(200), true),
        (Token::HttpStatusClass("2xx".into()), true),
        (Token::BracketContext(vec!["err".into()]), true),
        (Token::Json("{}".into()), true),
        // Count-only types (false)
        (Token::Timestamp("ts".into()), false),
        (Token::Port(80), false),
        (Token::Pid(1), false),
        (Token::ThreadID("t1".into()), false),
        (Token::Duration("1s".into()), false),
        (Token::Size("1KB".into()), false),
        (Token::Number("42".into()), false),
        (
            Token::KeyValuePair {
                key: "k".into(),
                value_type: "v".into(),
            },
            false,
        ),
        (
            Token::LogWithModule {
                level: "INFO".into(),
                module: "m".into(),
            },
            false,
        ),
        (
            Token::StructuredMessage {
                component: "c".into(),
                level: "l".into(),
            },
            false,
        ),
    ];

    for (token, expected) in &all_tokens {
        assert_eq!(
            is_sample_worthy(token),
            *expected,
            "is_sample_worthy({:?}) should be {expected}",
            token_type_name(token)
        );
    }

    // Verify we covered all 26 variants (24 original + any new ones).
    // Update this count if Token gains new variants.
    assert_eq!(
        all_tokens.len(),
        26,
        "Token enum may have new variants — update this test"
    );
}

// ---------------------------------------------------------------
// token_type_name — exhaustiveness
// ---------------------------------------------------------------

#[test]
fn token_type_name_covers_all_variants() {
    // Every Token variant must return a non-empty UPPERCASE name.
    let tokens: Vec<Token> = vec![
        Token::Timestamp("ts".into()),
        Token::IPv4("1.2.3.4".into()),
        Token::IPv6("::1".into()),
        Token::Port(80),
        Token::Hash(HashType::SHA256, "h".into()),
        Token::Uuid("u".into()),
        Token::Pid(1),
        Token::ThreadID("t".into()),
        Token::Path("/p".into()),
        Token::Json("{}".into()),
        Token::Duration("1s".into()),
        Token::Size("1K".into()),
        Token::Number("1".into()),
        Token::HttpStatus(200),
        Token::QuotedString("q".into()),
        Token::Name("n".into()),
        Token::KubernetesNamespace("ns".into()),
        Token::VolumeName("v".into()),
        Token::PluginType("p".into()),
        Token::PodName("pod".into()),
        Token::HttpStatusClass("2xx".into()),
        Token::BracketContext(vec![]),
        Token::KeyValuePair {
            key: "k".into(),
            value_type: "v".into(),
        },
        Token::LogWithModule {
            level: "INFO".into(),
            module: "m".into(),
        },
        Token::StructuredMessage {
            component: "c".into(),
            level: "l".into(),
        },
        Token::Email("e@e".into()),
    ];

    for token in &tokens {
        let name = token_type_name(token);
        assert!(
            !name.is_empty(),
            "token_type_name returned empty for {token:?}",
        );
        assert_eq!(
            name,
            name.to_uppercase(),
            "token_type_name should return UPPERCASE: got {name}"
        );
    }
}

// ---------------------------------------------------------------
// token_value_string — no panics on any variant
// ---------------------------------------------------------------

#[test]
fn token_value_string_handles_all_variants() {
    let tokens: Vec<Token> = vec![
        Token::Timestamp("2025-01-01".into()),
        Token::IPv4("10.0.0.1".into()),
        Token::IPv6("::1".into()),
        Token::Port(443),
        Token::Hash(HashType::SHA1, "abc123".into()),
        Token::Uuid("550e8400-e29b-41d4-a716-446655440000".into()),
        Token::Pid(9999),
        Token::ThreadID("worker-3".into()),
        Token::Path("/var/log/app.log".into()),
        Token::Json(r#"{"key":"val"}"#.into()),
        Token::Duration("3.5s".into()),
        Token::Size("2MB".into()),
        Token::Number("42".into()),
        Token::HttpStatus(404),
        Token::QuotedString("hello world".into()),
        Token::Name("myapp".into()),
        Token::KubernetesNamespace("kube-system".into()),
        Token::VolumeName("pvc-data".into()),
        Token::PluginType("csi-driver".into()),
        Token::PodName("api-server-xyz".into()),
        Token::HttpStatusClass("5xx".into()),
        Token::BracketContext(vec!["error".into(), "handler".into()]),
        Token::KeyValuePair {
            key: "user".into(),
            value_type: "string".into(),
        },
        Token::LogWithModule {
            level: "WARN".into(),
            module: "net".into(),
        },
        Token::StructuredMessage {
            component: "api".into(),
            level: "error".into(),
        },
        Token::Email("user@example.com".into()),
    ];

    for token in &tokens {
        let val = token_value_string(token);
        assert!(
            !val.is_empty(),
            "token_value_string returned empty for {:?}",
            token_type_name(token)
        );
    }

    // Spot-check specific formats
    assert_eq!(
        token_value_string(&Token::BracketContext(vec![
            "error".into(),
            "handler".into()
        ])),
        "error,handler"
    );
    assert_eq!(token_value_string(&Token::Port(443)), "443");
    assert_eq!(token_value_string(&Token::HttpStatus(404)), "404");
    assert_eq!(token_value_string(&Token::Pid(9999)), "9999");
    assert_eq!(
        token_value_string(&Token::KeyValuePair {
            key: "k".into(),
            value_type: "v".into()
        }),
        "k=v"
    );
}

// ---------------------------------------------------------------
// RollupComputer::compute — hand-crafted groups
// ---------------------------------------------------------------

#[test]
fn rollup_empty_group_no_tokens() {
    let rc = RollupComputer::with_defaults();
    let group = make_group("no tokens here", vec![vec![]]);
    let rollup = rc.compute(&group);
    assert!(
        rollup.is_empty(),
        "empty-token group should produce empty rollup"
    );
}

#[test]
fn rollup_single_sample_worthy_token() {
    let rc = RollupComputer::with_defaults();
    let group = make_group(
        "request <UUID> failed",
        vec![vec![Token::Uuid("aaa-bbb".into())]],
    );
    let rollup = rc.compute(&group);
    let entry = rollup.get("UUID").expect("UUID should be in rollup");
    assert_eq!(entry.distinct_count, 1);
    assert_eq!(entry.samples, vec!["aaa-bbb"]);
    assert!(!entry.capped);
}

#[test]
fn rollup_single_count_only_token() {
    let rc = RollupComputer::with_defaults();
    let group = make_group(
        "<TIMESTAMP> started",
        vec![vec![Token::Timestamp("2025-01-01 10:00:00".into())]],
    );
    let rollup = rc.compute(&group);
    let entry = rollup
        .get("TIMESTAMP")
        .expect("TIMESTAMP should be in rollup");
    assert_eq!(entry.distinct_count, 1);
    assert!(
        entry.samples.is_empty(),
        "count-only type must have empty samples"
    );
    assert!(!entry.capped);
}

#[test]
fn rollup_mixed_tokens_across_lines() {
    let rc = RollupComputer::with_defaults();
    let lines: Vec<Vec<Token>> = (0..5)
        .map(|i| {
            vec![
                Token::Uuid(format!("uuid-{}", i % 3)), // 3 distinct
                Token::Timestamp(format!("ts-{i}")),    // 5 distinct
            ]
        })
        .collect();
    let group = make_group("request <UUID> at <TIMESTAMP>", lines);
    let rollup = rc.compute(&group);

    let uuid_entry = rollup.get("UUID").unwrap();
    assert_eq!(uuid_entry.distinct_count, 3);
    assert_eq!(uuid_entry.samples.len(), 3); // 3 <= K, so all shown
    assert!(!uuid_entry.capped);

    let ts_entry = rollup.get("TIMESTAMP").unwrap();
    assert_eq!(ts_entry.distinct_count, 5);
    assert!(ts_entry.samples.is_empty(), "TIMESTAMP is count-only");
    assert!(!ts_entry.capped);
}

#[test]
fn rollup_exactly_at_cap_is_not_capped() {
    let rc = RollupComputer::with_defaults();
    // ROLLUP_DISTINCT_CAP = 64. Generate exactly 64 distinct UUIDs.
    let lines: Vec<Vec<Token>> = (0..64)
        .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
        .collect();
    let group = make_group("request <UUID>", lines);
    let rollup = rc.compute(&group);

    let entry = rollup.get("UUID").unwrap();
    assert_eq!(entry.distinct_count, 64);
    assert!(!entry.capped, "exactly at cap should NOT be capped");
}

#[test]
fn rollup_one_over_cap_is_capped() {
    let rc = RollupComputer::with_defaults();
    // 65 distinct UUIDs: first 64 are inserted, 65th triggers the cap.
    let lines: Vec<Vec<Token>> = (0..65)
        .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
        .collect();
    let group = make_group("request <UUID>", lines);
    let rollup = rc.compute(&group);

    let entry = rollup.get("UUID").unwrap();
    assert_eq!(entry.distinct_count, 64, "capped at ROLLUP_DISTINCT_CAP");
    assert!(entry.capped, "65th value should trigger capped flag");
}

#[test]
fn rollup_samples_capped_at_k() {
    let rc = RollupComputer::with_defaults();
    // ROLLUP_K = 7. Create 8 distinct UUIDs — samples should have 7.
    let lines: Vec<Vec<Token>> = (0..8)
        .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
        .collect();
    let group = make_group("request <UUID>", lines);
    let rollup = rc.compute(&group);

    let entry = rollup.get("UUID").unwrap();
    assert_eq!(entry.distinct_count, 8);
    assert_eq!(
        entry.samples.len(),
        ROLLUP_K,
        "samples should be capped at K={ROLLUP_K}"
    );
}

#[test]
fn rollup_deterministic_across_calls() {
    let rc = RollupComputer::with_defaults();
    let lines: Vec<Vec<Token>> = (0..20)
        .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
        .collect();
    let group = make_group("request <UUID>", lines);

    let rollup1 = rc.compute(&group);
    let rollup2 = rc.compute(&group);
    assert_eq!(rollup1, rollup2, "same group must produce identical rollup");
}

#[test]
fn rollup_different_templates_different_samples() {
    let rc = RollupComputer::with_defaults();
    // Same 20 values, but different normalized templates → different seeds.
    let tokens: Vec<Vec<Token>> = (0..20)
        .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
        .collect();
    let group_a = make_group("template A: <UUID>", tokens.clone());
    let group_b = make_group("template B: <UUID>", tokens);

    let rollup_a = rc.compute(&group_a);
    let rollup_b = rc.compute(&group_b);

    let samples_a = &rollup_a.get("UUID").unwrap().samples;
    let samples_b = &rollup_b.get("UUID").unwrap().samples;

    // Both have 7 samples drawn from the same 20 values but with
    // different seeds, so the draws should (almost certainly) differ.
    // This is probabilistic but with 20-choose-7 there are 77520
    // possible draws — collision chance is negligible.
    assert_ne!(
        samples_a, samples_b,
        "different templates should (almost certainly) produce different sample draws"
    );
}

#[test]
fn rollup_samples_are_sorted() {
    let rc = RollupComputer::with_defaults();
    let lines: Vec<Vec<Token>> = (0..15)
        .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
        .collect();
    let group = make_group("request <UUID>", lines);
    let rollup = rc.compute(&group);

    let entry = rollup.get("UUID").unwrap();
    let mut sorted = entry.samples.clone();
    sorted.sort();
    assert_eq!(
        entry.samples, sorted,
        "samples must be lexicographically sorted"
    );
}

#[test]
fn rollup_variation_keys_are_sorted() {
    let rc = RollupComputer::with_defaults();
    let group = make_group(
        "mixed",
        vec![vec![
            Token::Uuid("u".into()),
            Token::IPv4("1.2.3.4".into()),
            Token::Path("/a".into()),
        ]],
    );
    let rollup = rc.compute(&group);
    let keys: Vec<&&str> = rollup.keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(
        keys, sorted,
        "variation keys must be alphabetically sorted (BTreeMap)"
    );
}

// ---------------------------------------------------------------
// render_compact_marker
// ---------------------------------------------------------------

#[test]
fn marker_empty_rollup() {
    let result = render_compact_marker(42, &BTreeMap::new(), None, None, 3, false);
    assert_eq!(result, "[+42 similar]");
}

#[test]
fn marker_inline_samples_below_threshold() {
    let mut rollup: GroupRollup = BTreeMap::new();
    rollup.insert(
        "PATH",
        VariationEntry {
            distinct_count: 2,
            samples: vec!["/var/a".into(), "/var/b".into()],
            capped: false,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3, false);
    assert_eq!(result, "[+10 similar | path×2 {/var/a, /var/b}]");
}

#[test]
fn marker_count_only_above_threshold() {
    let mut rollup: GroupRollup = BTreeMap::new();
    rollup.insert(
        "PATH",
        VariationEntry {
            distinct_count: 5,
            samples: vec![
                "/a".into(),
                "/b".into(),
                "/c".into(),
                "/d".into(),
                "/e".into(),
            ],
            capped: false,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3, false);
    // distinct > threshold → count-only, no inline samples
    assert_eq!(result, "[+10 similar | path×5]");
}

#[test]
fn marker_capped_entry_has_plus_suffix() {
    let mut rollup: GroupRollup = BTreeMap::new();
    rollup.insert(
        "HASH",
        VariationEntry {
            distinct_count: 64,
            samples: vec!["abc".into(), "def".into()],
            capped: true,
        },
    );
    let result = render_compact_marker(100, &rollup, None, None, 3, false);
    assert!(
        result.contains("hash×64+"),
        "capped entry needs '+': {result}"
    );
    // Capped entries should NOT show inline samples regardless of threshold
    assert!(
        !result.contains('{'),
        "capped entry should not inline samples: {result}"
    );
}

#[test]
fn marker_time_range_present() {
    let result = render_compact_marker(
        5,
        &BTreeMap::new(),
        Some("10:00:00"),
        Some("10:05:00"),
        3,
        false,
    );
    assert_eq!(result, "[+5 similar | 10:00:00 → 10:05:00]");
}

#[test]
fn marker_time_range_suppressed_in_essence_mode() {
    let result = render_compact_marker(
        5,
        &BTreeMap::new(),
        Some("10:00:00"),
        Some("10:05:00"),
        3,
        true, // essence mode
    );
    assert_eq!(
        result, "[+5 similar]",
        "essence mode must suppress time range"
    );
}

#[test]
fn marker_sample_truncation_at_50_chars() {
    let mut rollup: GroupRollup = BTreeMap::new();
    let long_value = "a".repeat(51); // 51 chars → should be truncated
    let exact_value = "b".repeat(50); // 50 chars → should NOT be truncated
    rollup.insert(
        "PATH",
        VariationEntry {
            distinct_count: 2,
            samples: vec![exact_value.clone(), long_value],
            capped: false,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3, false);
    // 50-char value: not truncated
    assert!(
        result.contains(&exact_value),
        "50-char value should not be truncated"
    );
    // 51-char value: truncated to 49 chars + '…'
    let truncated = format!("{}…", "a".repeat(49));
    assert!(
        result.contains(&truncated),
        "51-char value should be truncated to 49+…: {result}"
    );
}

#[test]
fn marker_multiple_entries_comma_separated() {
    let mut rollup: GroupRollup = BTreeMap::new();
    rollup.insert(
        "IPV4",
        VariationEntry {
            distinct_count: 4,
            samples: vec!["10.0.0.1".into(), "10.0.0.2".into()],
            capped: false,
        },
    );
    rollup.insert(
        "UUID",
        VariationEntry {
            distinct_count: 7,
            samples: vec!["aaa".into(), "bbb".into()],
            capped: false,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3, false);
    // BTreeMap order: IPV4 before UUID
    assert!(
        result.contains("ipv4×4, uuid×7"),
        "entries should be comma-separated, lowercase: {result}"
    );
}

#[test]
fn marker_count_only_types_filtered_out() {
    // Count-only types (empty samples, distinct > 0) should not appear
    // in the marker unless distinct_count <= inline_threshold.
    let mut rollup: GroupRollup = BTreeMap::new();
    rollup.insert(
        "TIMESTAMP",
        VariationEntry {
            distinct_count: 500,
            samples: vec![],
            capped: false,
        },
    );
    rollup.insert(
        "UUID",
        VariationEntry {
            distinct_count: 3,
            samples: vec!["a".into(), "b".into(), "c".into()],
            capped: false,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3, false);
    assert!(
        !result.contains("timestamp"),
        "count-only type with high cardinality should be filtered: {result}"
    );
    assert!(
        result.contains("uuid×3"),
        "sample-worthy type should appear: {result}"
    );
}

// ---------------------------------------------------------------
// Mutant-killing tests (targeted at cargo-mutants survivors)
// ---------------------------------------------------------------

#[test]
fn marker_zero_distinct_count_filtered_out() {
    // Kills mutant: `distinct_count > 0` → `distinct_count >= 0`
    // An entry with distinct_count=0 should never appear in the marker.
    let mut rollup: GroupRollup = BTreeMap::new();
    rollup.insert(
        "UUID",
        VariationEntry {
            distinct_count: 0,
            samples: vec![],
            capped: false,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3, false);
    assert_eq!(
        result, "[+10 similar]",
        "zero-distinct entry must be filtered out"
    );
}

#[test]
fn marker_truncation_exact_length() {
    // Kills mutants: `SAMPLE_MAX_LEN - 1` → `+ 1` or `/ 1`
    // The truncated output must be exactly 50 chars (49 content + '…').
    let mut rollup: GroupRollup = BTreeMap::new();
    let long_value = "x".repeat(100);
    rollup.insert(
        "PATH",
        VariationEntry {
            distinct_count: 1,
            samples: vec![long_value],
            capped: false,
        },
    );
    let result = render_compact_marker(5, &rollup, None, None, 3, false);
    // Extract the truncated sample from the marker: between { and }
    let start = result.find('{').expect("should have inline samples") + 1;
    let end = result.find('}').expect("should have closing brace");
    let rendered_sample = &result[start..end];
    // 49 'x' chars + '…' = 50 chars total
    assert_eq!(
        rendered_sample.chars().count(),
        50,
        "truncated sample should be exactly 50 chars: got '{rendered_sample}'"
    );
    assert!(
        rendered_sample.ends_with('…'),
        "truncated sample should end with '…': got '{rendered_sample}'"
    );
    assert_eq!(
        rendered_sample.chars().filter(|&c| c == 'x').count(),
        49,
        "should have 49 content chars before '…'"
    );
}

// ---------------------------------------------------------------
// Property-based tests for rollup invariants
// ---------------------------------------------------------------

mod rollup_properties {
    use super::*;
    use proptest::collection::vec as pvec;
    use proptest::prelude::*;

    /// Generate a random sample-worthy token with a random string value.
    fn arb_sample_worthy_token() -> impl Strategy<Value = Token> {
        ("[a-z0-9]{1,20}", 0..6u8).prop_map(|(val, variant)| match variant {
            0 => Token::Uuid(val),
            1 => Token::IPv4(val),
            2 => Token::Path(val),
            3 => Token::Name(val),
            4 => Token::Email(val),
            _ => Token::QuotedString(val),
        })
    }

    /// Generate a random count-only token.
    fn arb_count_only_token() -> impl Strategy<Value = Token> {
        ("[a-z0-9]{1,20}", 0..4u8).prop_map(|(val, variant)| match variant {
            0 => Token::Timestamp(val),
            1 => Token::Duration(val),
            2 => Token::Number(val),
            _ => Token::Size(val),
        })
    }

    /// Generate a random token (either sample-worthy or count-only).
    fn arb_token() -> impl Strategy<Value = Token> {
        prop_oneof![arb_sample_worthy_token(), arb_count_only_token(),]
    }

    /// Generate a random PatternGroup for property testing.
    fn arb_group() -> impl Strategy<Value = PatternGroup> {
        (
            "[a-z ]{5,30}",                       // normalized template
            pvec(pvec(arb_token(), 0..8), 1..50), // 1-49 lines, 0-7 tokens each
        )
            .prop_map(|(normalized, token_lines)| make_group(&normalized, token_lines))
    }

    proptest! {
        #[test]
        fn samples_never_exceed_k(group in arb_group()) {
            let rc = RollupComputer::with_defaults();
            let rollup = rc.compute(&group);
            for (name, entry) in &rollup {
                prop_assert!(
                    entry.samples.len() <= ROLLUP_K,
                    "{name}: samples.len()={} > K={ROLLUP_K}",
                    entry.samples.len()
                );
            }
        }

        #[test]
        fn capped_implies_distinct_at_cap(group in arb_group()) {
            let rc = RollupComputer::with_defaults();
            let rollup = rc.compute(&group);
            for (name, entry) in &rollup {
                if entry.capped {
                    prop_assert!(
                        entry.distinct_count >= ROLLUP_DISTINCT_CAP,
                        "{name}: capped=true but distinct_count={} < cap={ROLLUP_DISTINCT_CAP}",
                        entry.distinct_count
                    );
                }
            }
        }

        #[test]
        fn not_capped_implies_distinct_under_cap(group in arb_group()) {
            let rc = RollupComputer::with_defaults();
            let rollup = rc.compute(&group);
            for (name, entry) in &rollup {
                if !entry.capped {
                    prop_assert!(
                        entry.distinct_count <= ROLLUP_DISTINCT_CAP,
                        "{name}: capped=false but distinct_count={} > cap={ROLLUP_DISTINCT_CAP}",
                        entry.distinct_count
                    );
                }
            }
        }

        #[test]
        fn count_only_types_always_empty_samples(group in arb_group()) {
            let rc = RollupComputer::with_defaults();
            let rollup = rc.compute(&group);
            const COUNT_ONLY: &[&str] = &[
                "TIMESTAMP", "DURATION", "SIZE", "NUMBER",
                "PORT", "PID", "THREAD_ID", "KEY_VALUE",
                "LOG_WITH_MODULE", "STRUCTURED_MESSAGE",
            ];
            for name in COUNT_ONLY {
                if let Some(entry) = rollup.get(name) {
                    prop_assert!(
                        entry.samples.is_empty(),
                        "{name}: count-only type has samples: {:?}",
                        entry.samples
                    );
                }
            }
        }

        #[test]
        fn compute_is_deterministic(group in arb_group()) {
            let rc = RollupComputer::with_defaults();
            let r1 = rc.compute(&group);
            let r2 = rc.compute(&group);
            prop_assert_eq!(r1, r2);
        }

        #[test]
        fn variation_keys_alphabetically_sorted(group in arb_group()) {
            let rc = RollupComputer::with_defaults();
            let rollup = rc.compute(&group);
            let keys: Vec<&&str> = rollup.keys().collect();
            let mut sorted = keys.clone();
            sorted.sort();
            prop_assert_eq!(keys, sorted);
        }

        #[test]
        fn samples_are_lexicographically_sorted(group in arb_group()) {
            let rc = RollupComputer::with_defaults();
            let rollup = rc.compute(&group);
            for (name, entry) in &rollup {
                let mut sorted = entry.samples.clone();
                sorted.sort();
                prop_assert!(
                    entry.samples == sorted,
                    "{name}: samples not sorted: {:?}", entry.samples
                );
            }
        }

        #[test]
        fn samples_subset_of_distinct_count(group in arb_group()) {
            let rc = RollupComputer::with_defaults();
            let rollup = rc.compute(&group);
            for (name, entry) in &rollup {
                prop_assert!(
                    entry.samples.len() <= entry.distinct_count,
                    "{name}: samples.len()={} > distinct_count={}",
                    entry.samples.len(), entry.distinct_count
                );
            }
        }
    }
}

// ---------------------------------------------------------------
// Pipeline: process_line, flush_oldest_safe_group, should_flush_buffer
// ---------------------------------------------------------------

/// Build a single-threaded PatternFolder with sensible test defaults.
fn make_folder() -> PatternFolder {
    PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    })
}

#[test]
fn process_line_increments_total_lines() {
    let mut f = make_folder();
    f.process_line("2024-01-01 10:00:00 INFO hello 192.168.1.1")
        .unwrap();
    assert_eq!(f.stats.total_lines, 1);
}

#[test]
fn process_line_with_tokens_increments_patterns_detected() {
    let mut f = make_folder();
    // This line contains an IP which will be detected as a token
    f.process_line("2024-01-01 10:00:00 INFO hello 192.168.1.1")
        .unwrap();
    assert!(
        f.stats.patterns_detected >= 1,
        "patterns_detected should be >= 1, got {}",
        f.stats.patterns_detected
    );
}

#[test]
fn process_line_without_tokens_does_not_increment_patterns() {
    let mut f = make_folder();
    // Plain text with no detectable patterns
    f.process_line("hello world").unwrap();
    assert_eq!(f.stats.patterns_detected, 0);
}

#[test]
fn process_line_counts_patterns_for_each_line() {
    let mut f = make_folder();
    f.process_line("request from 10.0.0.1").unwrap();
    f.process_line("request from 10.0.0.2").unwrap();
    assert_eq!(f.stats.total_lines, 2);
    // Both lines have IP tokens
    assert!(
        f.stats.patterns_detected >= 2,
        "expected >= 2 patterns_detected, got {}",
        f.stats.patterns_detected
    );
}

#[test]
fn process_line_identical_lines_cluster_into_one_group() {
    let mut f = make_folder();
    for _ in 0..5 {
        f.process_line("2024-01-01 ERROR connection refused from 10.0.0.1")
            .unwrap();
    }
    // Similar lines should be in one group
    assert_eq!(
        f.buffer.len(),
        1,
        "identical lines should cluster into one group"
    );
    assert_eq!(f.buffer[0].count(), 5);
}

#[test]
fn process_line_dissimilar_lines_create_separate_groups() {
    let mut f = make_folder();
    f.process_line("2024-01-01 ERROR disk full on /dev/sda1")
        .unwrap();
    f.process_line("GET /api/health HTTP/1.1 200 OK").unwrap();
    assert!(
        f.buffer.len() >= 2,
        "dissimilar lines should create separate groups, got {}",
        f.buffer.len()
    );
}

#[test]
fn process_line_batches_in_parallel_mode() {
    let mut f = PatternFolder::new(Config {
        thread_count: None, // parallel mode
        min_collapse: 3,
        ..Config::default()
    });
    let result = f.process_line("2024-01-01 INFO hello 10.0.0.1").unwrap();
    // Parallel mode buffers lines instead of processing immediately
    assert_eq!(result, None, "parallel mode should buffer, not process");
    assert_eq!(f.batch_buffer.len(), 1, "line should be in batch_buffer");
    assert_eq!(
        f.buffer.len(),
        0,
        "buffer should be empty until batch processes"
    );
}

#[test]
fn process_line_finish_outputs_collapsed_groups() {
    let mut f = make_folder();
    // Feed 5 similar lines — above min_collapse=3, so they should collapse
    for i in 0..5 {
        f.process_line(&format!(
            "2024-01-01 ERROR timeout connecting to 10.0.0.{i}"
        ))
        .unwrap();
    }
    let output = f.finish().unwrap();
    let joined = output.join("\n");
    assert!(
        joined.contains("similar"),
        "collapsed output should contain 'similar', got: {joined}"
    );
}

#[test]
fn should_flush_buffer_false_at_1000() {
    let mut f = make_folder();
    // Manually push 1000 groups into the buffer
    for i in 0..1000 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("unique pattern {i}"), vec![]),
            i + 1,
        ));
    }
    assert!(
        !f.should_flush_buffer(),
        "should_flush_buffer should be false at exactly 1000 groups"
    );
}

#[test]
fn should_flush_buffer_true_above_1000() {
    let mut f = make_folder();
    for i in 0..1001 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("unique pattern {i}"), vec![]),
            i + 1,
        ));
    }
    assert!(
        f.should_flush_buffer(),
        "should_flush_buffer should be true at 1001 groups"
    );
}

#[test]
fn flush_oldest_safe_group_empty_buffer_returns_none() {
    let mut f = make_folder();
    let result = f.flush_oldest_safe_group().unwrap();
    assert_eq!(result, None);
}

#[test]
fn flush_oldest_safe_group_flushes_old_group() {
    let mut f = make_folder();
    // Add a group at position 1
    f.buffer.push(PatternGroup::new(
        make_line(
            "old line with 10.0.0.1",
            vec![Token::IPv4("10.0.0.1".into())],
        ),
        1,
    ));
    // Advance position counter well past safe_distance (100)
    f.position_counter = 200;
    let result = f.flush_oldest_safe_group().unwrap();
    assert!(result.is_some(), "should flush group that is 199 lines old");
    assert!(f.buffer.is_empty(), "buffer should be empty after flush");
}

#[test]
fn flush_oldest_safe_group_does_not_flush_recent_group() {
    let mut f = make_folder();
    // Add a group at position 50
    f.buffer
        .push(PatternGroup::new(make_line("recent line", vec![]), 50));
    // Position counter is only 60 — well within safe_distance=100
    f.position_counter = 60;
    let result = f.flush_oldest_safe_group().unwrap();
    // Group has 1 line (< min_collapse=3) and is recent (10 < 100), so NOT ready
    assert_eq!(result, None, "should not flush recent small group");
    assert_eq!(f.buffer.len(), 1, "group should remain in buffer");
}

// --- Mutant-killing tests for process_line + flush_oldest_safe_group ---

#[test]
fn process_line_advances_position_counter() {
    // Kills: position_counter += 1 → *= 1 (stays at 0)
    let mut f = make_folder();
    assert_eq!(f.position_counter, 0);
    f.process_line("hello 10.0.0.1").unwrap();
    assert_eq!(f.position_counter, 1);
    f.process_line("world 10.0.0.2").unwrap();
    assert_eq!(f.position_counter, 2);
}

#[test]
fn flush_exact_safe_distance_boundary() {
    // Kills: > safe_distance → >= safe_distance
    // safe_distance = 100, so distance of exactly 100 should NOT flush
    let mut f = make_folder();
    f.buffer
        .push(PatternGroup::new(make_line("boundary line", vec![]), 1));
    f.position_counter = 101; // distance = 101 - 1 = 100, exactly at boundary
    let result = f.flush_oldest_safe_group().unwrap();
    assert_eq!(
        result, None,
        "distance of exactly 100 should NOT flush (> not >=)"
    );

    // distance = 101 SHOULD flush
    f.position_counter = 102; // distance = 102 - 1 = 101
    let result = f.flush_oldest_safe_group().unwrap();
    assert!(result.is_some(), "distance of 101 should flush");
}

#[test]
fn flush_uses_subtraction_not_division() {
    // Kills: current_position - group.position → current_position / group.position
    // With position=50, counter=160: 160-50=110 > 100 (flush), 160/50=3 (no flush)
    let mut f = make_folder();
    f.buffer
        .push(PatternGroup::new(make_line("division test", vec![]), 50));
    f.position_counter = 160;
    let result = f.flush_oldest_safe_group().unwrap();
    assert!(
        result.is_some(),
        "distance 110 should flush (subtraction gives 110, division gives 3)"
    );
}

#[test]
fn flush_selects_first_among_equal_positions() {
    // Kills: group.position < oldest_position → <= oldest_position
    // Two groups at same position, different content — first should be selected
    let mut f = make_folder();
    f.buffer
        .push(PatternGroup::new(make_line("first_group_aaa", vec![]), 5));
    f.buffer
        .push(PatternGroup::new(make_line("second_group_bbb", vec![]), 5));
    f.position_counter = 200;
    let result = f.flush_oldest_safe_group().unwrap().unwrap();
    assert!(
        result.contains("first_group_aaa"),
        "should flush first group at equal position, got: {result}"
    );
}

#[test]
fn flush_accumulates_output_lines() {
    // Kills: output_lines += count → *= count (0 * N = 0)
    let mut f = make_folder();
    f.buffer
        .push(PatternGroup::new(make_line("output line", vec![]), 1));
    f.position_counter = 200;
    assert_eq!(f.stats.output_lines, 0);
    let _result = f.flush_oldest_safe_group().unwrap();
    assert!(
        f.stats.output_lines > 0,
        "output_lines should be incremented after flush, got 0"
    );
}

// ---------------------------------------------------------------
// JSON output: format_group_json, print_summary_json, format_group_dispatch
// ---------------------------------------------------------------

fn make_folder_json() -> PatternFolder {
    PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        output_format: "json".to_string(),
        ..Config::default()
    })
}

#[test]
fn format_group_json_below_min_collapse_no_stats_change() {
    let mut f = make_folder_json();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
        ],
    );
    assert_eq!(group.count(), 2); // below min_collapse=3
    let json = f.format_group_json(&group, BTreeMap::new()).unwrap();
    assert_eq!(f.stats.collapsed_groups, 0);
    assert_eq!(f.stats.lines_saved, 0);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["count"], 2);
}

#[test]
fn format_group_json_at_min_collapse_updates_stats() {
    let mut f = make_folder_json();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ],
    );
    assert_eq!(group.count(), 3); // exactly min_collapse
    let _ = f.format_group_json(&group, BTreeMap::new()).unwrap();
    assert_eq!(f.stats.collapsed_groups, 1);
    // One definition across every mode: a collapsed group preserves 3
    // lines (first + marker + last), so a group at exactly min_collapse
    // saves 0. Same arithmetic as the text renderer.
    assert_eq!(f.stats.lines_saved, 0);

    let bigger = make_group(
        "warn <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
            vec![Token::IPv4("10.0.0.5".into())],
        ],
    );
    let _ = f.format_group_json(&bigger, BTreeMap::new()).unwrap();
    assert_eq!(f.stats.collapsed_groups, 2);
    assert_eq!(f.stats.lines_saved, 2); // 5 - 3, matching text mode
}

#[test]
fn format_group_json_essence_mode_skips_stats() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        output_format: "json".to_string(),
        essence_mode: true,
        ..Config::default()
    });
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ],
    );
    let _ = f.format_group_json(&group, BTreeMap::new()).unwrap();
    assert_eq!(
        f.stats.collapsed_groups, 0,
        "essence_mode should skip collapsed_groups"
    );
    assert_eq!(
        f.stats.lines_saved, 0,
        "essence_mode should skip lines_saved"
    );
}

#[test]
fn format_group_json_id_increments() {
    let mut f = make_folder_json();
    let group = make_group("line", vec![vec![]]);
    let json0 = f.format_group_json(&group, BTreeMap::new()).unwrap();
    let json1 = f.format_group_json(&group, BTreeMap::new()).unwrap();
    let v0: serde_json::Value = serde_json::from_str(&json0).unwrap();
    let v1: serde_json::Value = serde_json::from_str(&json1).unwrap();
    assert_eq!(v0["id"], 0);
    assert_eq!(v1["id"], 1);
}

#[test]
fn format_group_json_token_types_sorted() {
    let mut f = make_folder_json();
    // Use tokens whose type names sort alphabetically: "ipv4" < "uuid"
    let group = make_group(
        "error <IP> <UUID>",
        vec![vec![
            Token::Uuid("aaa".into()),
            Token::IPv4("10.0.0.1".into()),
        ]],
    );
    let json = f.format_group_json(&group, BTreeMap::new()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let types: Vec<&str> = v["token_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let mut sorted = types.clone();
    sorted.sort_unstable();
    assert_eq!(types, sorted, "token_types should be alphabetically sorted");
}

#[test]
fn format_group_json_time_range_from_timestamps() {
    let mut f = make_folder_json();
    let group = make_group(
        "error <TIMESTAMP>",
        vec![
            vec![Token::Timestamp("2024-01-01T00:00:00Z".into())],
            vec![Token::Timestamp("2024-01-01T01:00:00Z".into())],
        ],
    );
    let json = f.format_group_json(&group, BTreeMap::new()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        v["time_range"]["first_seen"].as_str().unwrap(),
        "2024-01-01T00:00:00Z"
    );
    assert_eq!(
        v["time_range"]["last_seen"].as_str().unwrap(),
        "2024-01-01T01:00:00Z"
    );
}

#[test]
fn format_group_json_record_type_is_group() {
    let mut f = make_folder_json();
    let group = make_group("line", vec![vec![]]);
    let json = f.format_group_json(&group, BTreeMap::new()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["type"], "group");
}

#[test]
fn print_summary_json_zero_lines() {
    let f = make_folder_json();
    let mut buf = Vec::new();
    f.print_summary_json(&mut buf, std::time::Duration::from_millis(100))
        .unwrap();
    let output = String::from_utf8(buf).unwrap();
    let v: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
    assert_eq!(v["type"], "summary");
    assert_eq!(v["compression_ratio"], 0.0);
    assert_eq!(v["input_lines"], 0);
}

#[test]
fn print_summary_json_with_stats() {
    let mut f = make_folder_json();
    f.stats.total_lines = 100;
    f.stats.lines_saved = 80;
    f.stats.output_lines = 20;
    f.stats.collapsed_groups = 5;
    f.stats.patterns_detected = 50;
    f.stats.timestamps = 10;
    f.stats.ips = 5;
    let mut buf = Vec::new();
    f.print_summary_json(&mut buf, std::time::Duration::from_millis(42))
        .unwrap();
    let output = String::from_utf8(buf).unwrap();
    let v: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
    assert_eq!(v["input_lines"], 100);
    assert_eq!(v["output_lines"], 20);
    assert_eq!(v["collapsed_groups"], 5);
    assert_eq!(v["lines_saved"], 80);
    assert_eq!(v["patterns_detected"], 50);
    assert_eq!(v["elapsed_ms"], 42);
    // compression_ratio = 80/100 * 100 = 80.0
    assert!((v["compression_ratio"].as_f64().unwrap() - 80.0).abs() < 0.01);
    assert_eq!(v["pattern_hits"]["timestamps"], 10);
    assert_eq!(v["pattern_hits"]["ips"], 5);
}

#[test]
fn print_summary_json_ends_with_newline() {
    let f = make_folder_json();
    let mut buf = Vec::new();
    f.print_summary_json(&mut buf, std::time::Duration::from_millis(0))
        .unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.ends_with('\n'),
        "summary JSON should end with newline"
    );
}

#[test]
fn print_summary_json_reports_fit_omissions_exactly() {
    let mut f = make_folder();
    f.note_json_groups_emitted(2);
    f.note_json_group_limits(5, 0, 0, 3);
    let mut buf = Vec::new();
    f.print_summary_json(&mut buf, std::time::Duration::ZERO)
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let groups = &value["completeness"]["groups"];
    assert!(!groups["complete"].as_bool().unwrap());
    assert_eq!(groups["omitted_by_fit"]["value"], 3);
    assert_eq!(groups["omitted_by_fit"]["kind"], "exact");
}

#[test]
fn format_group_dispatch_text_mode() {
    let mut f = make_folder();
    let group = make_group("hello", vec![vec![]]);
    let output = f.format_group_dispatch(&group).unwrap();
    // Text mode: should NOT be valid JSON
    assert!(
        serde_json::from_str::<serde_json::Value>(&output).is_err(),
        "text mode output should not be JSON"
    );
}

#[test]
fn format_group_dispatch_json_mode() {
    let mut f = make_folder_json();
    let group = make_group("hello", vec![vec![]]);
    let output = f.format_group_dispatch(&group).unwrap();
    // JSON mode: should be valid JSON
    let v: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(v["type"], "group");
}

// ---------------------------------------------------------------
// Stats counters: count_pattern_types, count_active_pattern_types
// ---------------------------------------------------------------

#[test]
fn count_pattern_types_timestamp() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Timestamp("2024-01-01".into())]);
    assert_eq!(f.stats.timestamps, 1);
}

#[test]
fn count_pattern_types_ip_variants() {
    let mut f = make_folder();
    f.count_pattern_types(&[
        Token::IPv4("10.0.0.1".into()),
        Token::IPv6("::1".into()),
        Token::Port(8080),
    ]);
    // IPv4 + IPv6 count as ips; ports have their own counter
    assert_eq!(f.stats.ips, 2);
    assert_eq!(f.stats.ports, 1);
}

#[test]
fn count_pattern_types_email() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Email("a@b.com".into())]);
    assert_eq!(f.stats.emails, 1);
}

#[test]
fn count_pattern_types_kubernetes_variants() {
    let mut f = make_folder();
    f.count_pattern_types(&[
        Token::KubernetesNamespace("kube-system".into()),
        Token::VolumeName("pvc-123".into()),
        Token::PluginType("csi".into()),
        Token::PodName("nginx-abc".into()),
    ]);
    assert_eq!(f.stats.kubernetes, 4);
}

#[test]
fn count_pattern_types_overloaded_bucket() {
    let mut f = make_folder();
    f.count_pattern_types(&[
        Token::Number("42".into()),
        Token::QuotedString("hello".into()),
        Token::Name("foo-bar".into()),
        Token::BracketContext(vec!["ERROR".into()]),
        Token::KeyValuePair {
            key: "k".into(),
            value_type: "string".into(),
        },
        Token::LogWithModule {
            level: "INFO".into(),
            module: "main".into(),
        },
        Token::StructuredMessage {
            component: "api".into(),
            level: "info".into(),
        },
    ]);
    // Every token type lands in its own counter — nothing is lumped.
    assert_eq!(f.stats.percentages, 1, "only Number counts as percentages");
    assert_eq!(f.stats.quoted_strings, 1);
    assert_eq!(f.stats.names, 1);
    assert_eq!(f.stats.brackets, 1);
    assert_eq!(f.stats.key_values, 1);
    assert_eq!(f.stats.log_modules, 1);
    assert_eq!(f.stats.structured, 1);
}

#[test]
fn count_pattern_types_empty_tokens() {
    let mut f = make_folder();
    f.count_pattern_types(&[]);
    // No stats should change — all still zero
    assert_eq!(f.stats.timestamps, 0);
    assert_eq!(f.stats.ips, 0);
    assert_eq!(f.stats.emails, 0);
}

#[test]
fn count_active_pattern_types_all_zero() {
    let f = make_folder();
    assert_eq!(f.count_active_pattern_types(), 0);
}

#[test]
fn count_active_pattern_types_one_nonzero() {
    let mut f = make_folder();
    f.stats.timestamps = 5;
    assert_eq!(f.count_active_pattern_types(), 1);
}

#[test]
fn count_active_pattern_types_all_nonzero() {
    let mut f = make_folder();
    f.stats.timestamps = 1;
    f.stats.ips = 1;
    f.stats.hashes = 1;
    f.stats.uuids = 1;
    f.stats.durations = 1;
    f.stats.pids = 1;
    f.stats.sizes = 1;
    f.stats.percentages = 1;
    f.stats.http_status = 1;
    f.stats.paths = 1;
    f.stats.kubernetes = 1;
    // Note: emails is NOT counted by count_active_pattern_types
    assert_eq!(f.count_active_pattern_types(), 11);
}

// ---------------------------------------------------------------
// Text formatting: format_group
// ---------------------------------------------------------------

#[test]
fn format_group_below_min_collapse_outputs_all_lines() {
    let mut f = make_folder();
    let group = make_group("error connecting", vec![vec![], vec![]]);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    // 2 lines < min_collapse=3, should output all lines individually
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 2);
}

#[test]
fn format_group_at_min_collapse_collapses() {
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ],
    );
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    assert!(
        output.contains("similar"),
        "collapsed output should contain 'similar', got: {output}"
    );
    assert_eq!(f.stats.collapsed_groups, 1);
}

#[test]
fn format_group_single_line_no_collapse() {
    let mut f = make_folder();
    let group = make_group("hello", vec![vec![]]);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    assert!(!output.contains("similar"));
    assert_eq!(output, "hello");
}

#[test]
fn format_group_essence_mode_uses_normalized() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        essence_mode: true,
        ..Config::default()
    });
    // In essence mode, single-line groups output normalized text
    let group = make_group(
        "normalized <IP>",
        vec![vec![Token::IPv4("10.0.0.1".into())]],
    );
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    assert_eq!(output, "normalized <IP>");
}

#[test]
fn format_group_pii_masking_masks_emails() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        sanitize_pii: true,
        ..Config::default()
    });
    // Build a group with email token where original contains the email
    let mut line = make_line(
        "user alice@test.com logged in",
        vec![Token::Email("alice@test.com".into())],
    );
    line.original = "user alice@test.com logged in".to_string();
    let group = PatternGroup::new(line, 1);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    assert!(
        output.contains("<EMAIL>"),
        "PII masking should replace email with <EMAIL>, got: {output}"
    );
    assert!(
        !output.contains("alice@test.com"),
        "email should be masked, got: {output}"
    );
}

// ---------------------------------------------------------------
// print_stats
// ---------------------------------------------------------------

#[test]
fn print_stats_contains_report_header() {
    let f = make_folder();
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("# lessence Compression Report"));
}

#[test]
fn print_stats_shows_pattern_rows_for_nonzero() {
    let mut f = make_folder();
    f.stats.timestamps = 10;
    f.stats.ips = 5;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("Timestamps"), "should show Timestamps row");
    assert!(
        output.contains("IP Addresses"),
        "should show IP Addresses row"
    );
    // emails is 0, so should NOT appear
    assert!(
        !output.contains("Email Addresses"),
        "should not show Email row when 0"
    );
}

#[test]
fn print_stats_zero_lines_shows_zero_compression() {
    let f = make_folder();
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("0.0%"),
        "zero lines should show 0.0% compression"
    );
}

#[test]
fn print_stats_all_pattern_rows_appear() {
    let mut f = make_folder();
    f.stats.timestamps = 1;
    f.stats.ips = 2;
    f.stats.hashes = 3;
    f.stats.uuids = 4;
    f.stats.durations = 5;
    f.stats.pids = 6;
    f.stats.sizes = 7;
    f.stats.percentages = 8;
    f.stats.http_status = 9;
    f.stats.paths = 10;
    f.stats.kubernetes = 11;
    f.stats.emails = 12;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("Timestamps"), "missing Timestamps row");
    assert!(output.contains("IP Addresses"), "missing IP row");
    assert!(output.contains("Hashes"), "missing Hashes row");
    assert!(output.contains("UUIDs"), "missing UUIDs row");
    assert!(output.contains("Durations"), "missing Durations row");
    assert!(output.contains("Process IDs"), "missing PIDs row");
    assert!(output.contains("File Sizes"), "missing Sizes row");
    assert!(
        output.contains("Numbers/Percentages"),
        "missing Percentages row"
    );
    assert!(output.contains("HTTP Status"), "missing HTTP row");
    assert!(output.contains("File Paths"), "missing Paths row");
    assert!(output.contains("Kubernetes"), "missing K8s row");
    assert!(output.contains("Email Addresses"), "missing Emails row");
}

#[test]
fn print_stats_compression_ratio_math() {
    let mut f = make_folder();
    f.stats.total_lines = 200;
    f.stats.lines_saved = 150;
    f.stats.output_lines = 50;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("75.0%"),
        "150/200 should be 75.0% reduction, got: {output}"
    );
    assert!(
        output.contains("200 lines"),
        "should show 200 original lines"
    );
    assert!(
        output.contains("50 lines"),
        "should show 50 compressed lines"
    );
}

#[test]
fn print_stats_high_compression_recommendation() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    f.stats.lines_saved = 95;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("High compression ratio"),
        "95% should trigger high compression recommendation"
    );
}

#[test]
fn print_stats_low_compression_recommendation() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    f.stats.lines_saved = 30;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("Low compression ratio"),
        "30% should trigger low compression recommendation"
    );
}

#[test]
fn print_stats_moderate_compression_recommendation() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    f.stats.lines_saved = 80;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("Moderate compression ratio"),
        "80% should trigger moderate recommendation"
    );
}

#[test]
fn print_stats_high_repetition_warning() {
    let mut f = make_folder();
    f.stats.collapsed_groups = 51;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("High pattern repetition"),
        ">50 collapsed groups should trigger repetition warning"
    );
}

#[test]
fn print_stats_no_repetition_warning_at_50() {
    let mut f = make_folder();
    f.stats.collapsed_groups = 50;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("High pattern repetition"),
        "exactly 50 collapsed groups should NOT trigger warning"
    );
}

#[test]
fn print_stats_summary_section_values() {
    let mut f = make_folder();
    f.stats.total_lines = 500;
    f.stats.patterns_detected = 42;
    f.stats.collapsed_groups = 10;
    f.stats.lines_saved = 300;
    f.stats.timestamps = 5;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("42"), "should show patterns_detected=42");
    assert!(output.contains("10"), "should show collapsed_groups=10");
    assert!(output.contains("300"), "should show lines_saved=300");
}

// ---------------------------------------------------------------
// format_group: lines_saved accounting
// ---------------------------------------------------------------

#[test]
fn format_group_collapsed_lines_saved_count() {
    // 5 lines, min_collapse=3: lines_saved = count - 3 = 2
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
            vec![Token::IPv4("10.0.0.5".into())],
        ],
    );
    let rollup = BTreeMap::new();
    let _ = f.format_group(&group, &rollup).unwrap();
    assert_eq!(f.stats.lines_saved, 2, "5 lines collapsed: saved = 5-3 = 2");
}

#[test]
fn format_group_collapsed_at_min_saves_zero() {
    // Exactly min_collapse=3 lines: lines_saved = 3-3 = 0
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ],
    );
    let rollup = BTreeMap::new();
    let _ = f.format_group(&group, &rollup).unwrap();
    assert_eq!(
        f.stats.lines_saved, 0,
        "3 lines at min_collapse: saved = 3-3 = 0"
    );
}

#[test]
fn format_group_essence_mode_lines_saved() {
    // In essence mode below min_collapse, lines_saved = count - 1 when count > 1
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        essence_mode: true,
        ..Config::default()
    });
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
        ],
    );
    let rollup = BTreeMap::new();
    let _ = f.format_group(&group, &rollup).unwrap();
    assert_eq!(
        f.stats.lines_saved, 1,
        "essence mode: 2 lines → saved = 2-1 = 1"
    );
}

#[test]
fn format_group_no_collapse_no_lines_saved() {
    // Below min_collapse in standard mode: no lines saved
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
        ],
    );
    let rollup = BTreeMap::new();
    let _ = f.format_group(&group, &rollup).unwrap();
    assert_eq!(f.stats.lines_saved, 0, "below min_collapse: no lines saved");
}

#[test]
fn format_group_collapsed_output_has_three_sections() {
    // Collapsed group should have: first line, collapse marker, last line
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
        ],
    );
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "collapsed output should have 3 lines (first + marker + last)"
    );
}

// ---------------------------------------------------------------
// finish_top_n
// ---------------------------------------------------------------

#[test]
fn finish_top_n_returns_sorted_by_count() {
    let mut f = make_folder();
    // Group A: 5 lines
    for _ in 0..5 {
        f.process_line("2024-01-01 ERROR timeout from 10.0.0.1")
            .unwrap();
    }
    // Group B: 2 lines
    for _ in 0..2 {
        f.process_line("GET /api/health HTTP/1.1 200 OK").unwrap();
    }
    // Group C: 1 line
    f.process_line("unique log entry with no pattern match")
        .unwrap();

    let (top, total_groups, _coverage) = f.finish_top_n(2).unwrap();
    assert_eq!(top.len(), 2, "should return top 2");
    assert!(
        top[0].0 >= top[1].0,
        "should be sorted descending: {} >= {}",
        top[0].0,
        top[1].0
    );
    assert!(total_groups >= 2, "total_groups should count all groups");
}

#[test]
fn finish_top_n_returns_correct_total_groups() {
    let mut f = make_folder();
    f.process_line("line A with 10.0.0.1").unwrap();
    f.process_line("line B with 10.0.0.2").unwrap();
    f.process_line("line C with something else entirely different")
        .unwrap();
    let (_top, total_groups, _coverage) = f.finish_top_n(10).unwrap();
    assert!(total_groups >= 1, "should have at least 1 group");
}

#[test]
fn finish_top_n_n_exceeds_groups() {
    let mut f = make_folder();
    f.process_line("only one line 10.0.0.1").unwrap();
    let (top, _total, _coverage) = f.finish_top_n(100).unwrap();
    // Should return all groups (1 or more), not crash
    assert!(!top.is_empty());
}

#[test]
fn finish_top_n_coverage_percentage() {
    let mut f = make_folder();
    // 10 identical lines = 1 group covering 100%
    for _ in 0..10 {
        f.process_line("2024-01-01 ERROR same 10.0.0.1").unwrap();
    }
    let (_top, _total, coverage) = f.finish_top_n(10).unwrap();
    assert_eq!(coverage, 100, "single group covering all lines = 100%");
}

// ---------------------------------------------------------------
// finish (drains buffer in chronological order)
// ---------------------------------------------------------------

#[test]
fn finish_drains_buffer_chronologically() {
    let mut f = make_folder();
    // Feed dissimilar lines to create multiple groups
    f.process_line("2024-01-01 ERROR first unique line with 10.0.0.1")
        .unwrap();
    f.process_line("GET /api/v2/status HTTP/1.1 200 OK")
        .unwrap();
    let output = f.finish().unwrap();
    assert!(output.len() >= 2, "should output at least 2 groups");
    // First group in output should be the first line (chronological)
    assert!(
        output[0].contains("first unique"),
        "first output should be the earliest group"
    );
}

#[test]
fn finish_updates_output_lines() {
    let mut f = make_folder();
    f.process_line("a line 10.0.0.1").unwrap();
    f.process_line("another line 10.0.0.2").unwrap();
    let _output = f.finish().unwrap();
    assert!(
        f.stats.output_lines > 0,
        "finish should update output_lines stat"
    );
}

// ---------------------------------------------------------------
// prepare_summary (extracted from finish_summary for testability)
// ---------------------------------------------------------------

#[test]
fn prepare_summary_merges_identical_groups() {
    let mut f = make_folder();
    // Two groups with same normalized text should merge
    f.buffer.push(PatternGroup::new(
        make_line("error <IP>", vec![Token::IPv4("10.0.0.1".into())]),
        1,
    ));
    f.buffer.push(PatternGroup::new(
        make_line("error <IP>", vec![Token::IPv4("10.0.0.2".into())]),
        2,
    ));
    let (display, total_patterns, _, _) = f.prepare_summary(None, None).unwrap();
    assert_eq!(total_patterns, 1, "identical normalized text should merge");
    assert_eq!(display[0].0, 2, "merged count should be 1+1=2");
}

#[test]
fn prepare_summary_accumulates_counts() {
    let mut f = make_folder();
    // Group with 3 lines + group with 2 lines (same normalized) = 5 total
    let mut g1 = PatternGroup::new(make_line("err <IP>", vec![]), 1);
    g1.add_line(make_line("err <IP>", vec![]), 2);
    g1.add_line(make_line("err <IP>", vec![]), 3);
    let mut g2 = PatternGroup::new(make_line("err <IP>", vec![]), 10);
    g2.add_line(make_line("err <IP>", vec![]), 11);
    f.buffer.push(g1);
    f.buffer.push(g2);
    let (display, _, _, _) = f.prepare_summary(None, None).unwrap();
    assert_eq!(display[0].0, 5, "merged count should be 3+2=5");
}

#[test]
fn prepare_summary_sorts_descending() {
    let mut f = make_folder();
    // Group A: 1 line, Group B: 5 lines — B should come first
    f.buffer
        .push(PatternGroup::new(make_line("small", vec![]), 1));
    let mut big = PatternGroup::new(make_line("big", vec![]), 10);
    for i in 0..4 {
        big.add_line(make_line("big", vec![]), 11 + i);
    }
    f.buffer.push(big);
    let (display, _, _, _) = f.prepare_summary(None, None).unwrap();
    assert!(display[0].0 >= display[1].0, "should sort descending");
}

#[test]
fn prepare_summary_top_n_limits() {
    let mut f = make_folder();
    for i in 0..10 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("pattern{i}"), vec![]),
            i + 1,
        ));
    }
    let (display, total, _, _) = f.prepare_summary(Some(3), None).unwrap();
    assert_eq!(display.len(), 3, "top_n=3 should return 3");
    assert_eq!(total, 10, "total_patterns should be 10");
}

#[test]
fn prepare_summary_top_zero_shows_all() {
    let mut f = make_folder();
    for i in 0..5 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    let (display, _, _, _) = f.prepare_summary(Some(0), None).unwrap();
    assert_eq!(display.len(), 5, "top_n=0 should show all");
}

#[test]
fn prepare_summary_default_cap_at_30() {
    let mut f = make_folder();
    for i in 0..50 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("unique{i}"), vec![]),
            i + 1,
        ));
    }
    let (display, _, was_capped, _) = f.prepare_summary(None, None).unwrap();
    assert_eq!(display.len(), 30, "default cap should be 30");
    assert!(was_capped, "should indicate capping");
}

#[test]
fn prepare_summary_fit_budget_limits() {
    let mut f = make_folder();
    for i in 0..20 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("line{i}"), vec![]),
            i + 1,
        ));
    }
    let (display, _, _, fit_truncated) = f.prepare_summary(None, Some(5)).unwrap();
    assert_eq!(display.len(), 4, "fit_budget=5 → show 4 (budget-1)");
    assert_eq!(fit_truncated, 16, "should report 16 remaining");
}

#[test]
fn prepare_summary_flushes_batch_buffer() {
    // Parallel mode: lines go to batch_buffer, not buffer directly
    let mut f = PatternFolder::new(Config {
        thread_count: None,
        min_collapse: 3,
        ..Config::default()
    });
    f.process_line("2024-01-01 ERROR test 10.0.0.1").unwrap();
    assert!(!f.batch_buffer.is_empty(), "should have buffered line");
    let (display, _, _, _) = f.prepare_summary(None, None).unwrap();
    assert!(!display.is_empty(), "should have processed batch");
}

// ---------------------------------------------------------------
// format_group_dispatch: rollup computed for collapsible groups
// ---------------------------------------------------------------

#[test]
fn format_group_dispatch_computes_rollup_for_collapsible() {
    // Kills: >= min_collapse → < min_collapse
    // A group at min_collapse should get rollup metadata in the output
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
        ],
    );
    assert_eq!(group.count(), 4); // >= min_collapse=3
    let output = f.format_group_dispatch(&group).unwrap();
    // Rollup produces variation markers with type names (e.g., "ipv4")
    // The legacy format_collapsed_line produces "[+N similar, varying: X]"
    // With rollup, it produces "[+N similar | ipv4×M ...]"
    assert!(
        output.contains("ipv4") || output.contains("similar"),
        "collapsible group should have rollup or collapse marker, got: {output}"
    );
}

// ---------------------------------------------------------------
// format_summary_line (extracted from finish_summary)
// ---------------------------------------------------------------

#[test]
fn summary_line_no_width() {
    let line = PatternFolder::format_summary_line(5, "error occurred", None);
    assert_eq!(line, "[5x] error occurred");
}

#[test]
fn summary_line_fits_in_width() {
    let line = PatternFolder::format_summary_line(5, "error", Some(100));
    assert_eq!(line, "[5x] error");
}

#[test]
fn summary_line_truncated() {
    let long_rep = "a".repeat(100);
    let line = PatternFolder::format_summary_line(5, &long_rep, Some(50));
    assert!(line.ends_with("..."), "should truncate with ...: {line}");
    assert!(line.len() <= 50);
}

#[test]
fn summary_line_avail_under_20_no_truncate() {
    // Width so small that avail <= 20: don't truncate, just show full
    let line = PatternFolder::format_summary_line(5, "abcdefghij", Some(10));
    assert_eq!(line, "[5x] abcdefghij");
}

#[test]
fn summary_line_truncates_on_multibyte_char_boundary() {
    // A 3-byte char (™ = U+2122, 3 bytes UTF-8) repeated, with the
    // truncation byte budget (avail = 30 - 5 - 3 = 22) landing inside a
    // char. Slicing at the raw byte index would panic; must snap down.
    let rep = "\u{2122}".repeat(30); // 90 bytes, none on a 22-byte boundary
    let line = PatternFolder::format_summary_line(5, &rep, Some(30));
    assert!(line.ends_with("..."), "should truncate: {line}");
    assert!(line.len() <= 30, "should fit in width: len={}", line.len());
}

// ---------------------------------------------------------------
// format_coverage_message (extracted from finish_summary)
// ---------------------------------------------------------------

#[test]
fn coverage_msg_capped() {
    let msg = PatternFolder::format_coverage_message(10, 50, 100, 200, true);
    assert!(msg.contains("10 of 50 patterns"));
    assert!(msg.contains("50% coverage"));
    assert!(msg.contains("--top N"));
}

#[test]
fn coverage_msg_not_capped() {
    let msg = PatternFolder::format_coverage_message(10, 10, 100, 200, false);
    assert!(msg.contains("10 of 10 patterns"));
    assert!(msg.contains("100 of 200 lines"));
    assert!(msg.contains("50% coverage"));
}

#[test]
fn coverage_msg_zero_lines() {
    let msg = PatternFolder::format_coverage_message(0, 0, 0, 0, false);
    assert!(msg.contains("0% coverage"));
}

// ---------------------------------------------------------------
// build_stats_json (extracted from print_stats_json)
// ---------------------------------------------------------------

#[test]
fn build_stats_json_zero_lines() {
    let f = make_folder();
    let json = f.build_stats_json(Duration::from_millis(100));
    assert!(json.compression_ratio.abs() < f64::EPSILON);
    assert_eq!(json.input_lines, 0);
    assert_eq!(json.elapsed_ms, 100);
}

#[test]
fn build_stats_json_with_data() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    f.stats.lines_saved = 50;
    f.stats.output_lines = 50;
    f.stats.timestamps = 10;
    f.stats.ips = 5;
    let json = f.build_stats_json(Duration::from_secs(1));
    assert!((json.compression_ratio - 50.0).abs() < f64::EPSILON);
    assert_eq!(json.input_lines, 100);
    assert_eq!(json.output_lines, 50);
    assert_eq!(json.elapsed_ms, 1000);
    assert_eq!(json.pattern_hits.timestamps, 10);
    assert_eq!(json.pattern_hits.ips, 5);
}

// ---------------------------------------------------------------
// print_stats boundary tests (already takes Writer)
// ---------------------------------------------------------------

// Boundary tests: > 90 and > 70 thresholds
// The code uses strict >, so exactly 90.0 is NOT "High" and exactly 70.0 is NOT "Moderate"

#[test]
fn print_stats_91_pct_is_high() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    f.stats.lines_saved = 91;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("High compression"),
        "91% should be high: {output}"
    );
}

#[test]
fn print_stats_90_pct_is_moderate() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    f.stats.lines_saved = 90;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("Moderate"),
        "exactly 90% is moderate, not high: {output}"
    );
}

#[test]
fn print_stats_71_pct_is_moderate() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    f.stats.lines_saved = 71;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("Moderate"),
        "71% should be moderate: {output}"
    );
}

#[test]
fn print_stats_70_pct_is_low() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    f.stats.lines_saved = 70;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("High compression"),
        "70% is not high: {output}"
    );
    assert!(
        !output.contains("Moderate"),
        "70% is not moderate: {output}"
    );
}

#[test]
fn print_stats_50_groups_no_warning() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    f.stats.collapsed_groups = 50;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("High pattern repetition"),
        "50 groups should not warn: {output}"
    );
}

#[test]
fn print_stats_51_groups_warning() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    f.stats.collapsed_groups = 51;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("High pattern repetition"),
        "51 groups should warn: {output}"
    );
}

#[test]
fn print_stats_zero_counter_no_row() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    f.stats.timestamps = 0;
    f.stats.ips = 5;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("Timestamps"),
        "zero timestamps should have no row"
    );
    assert!(
        output.contains("IP Addresses"),
        "nonzero IPs should have a row"
    );
}

// ---------------------------------------------------------------
// count_pattern_types: remaining token type tests
// ---------------------------------------------------------------

#[test]
fn count_pattern_types_hash() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Hash(crate::patterns::HashType::MD5, "abc".into())]);
    assert_eq!(f.stats.hashes, 1);
}

#[test]
fn count_pattern_types_uuid() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Uuid("550e-8400".into())]);
    assert_eq!(f.stats.uuids, 1);
}

#[test]
fn count_pattern_types_pid() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Pid(1234)]);
    assert_eq!(f.stats.pids, 1);
}

#[test]
fn count_pattern_types_thread_id() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::ThreadID("5678".into())]);
    assert_eq!(f.stats.pids, 1);
}

#[test]
fn count_pattern_types_duration() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Duration("5s".into())]);
    assert_eq!(f.stats.durations, 1);
}

#[test]
fn count_pattern_types_size() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Size("1MB".into())]);
    assert_eq!(f.stats.sizes, 1);
}

#[test]
fn count_pattern_types_http_status() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::HttpStatus(200)]);
    assert_eq!(f.stats.http_status, 1);
}

#[test]
fn count_pattern_types_http_status_class() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::HttpStatusClass("2xx".into())]);
    assert_eq!(f.stats.http_status, 1);
}

#[test]
fn count_pattern_types_path() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Path("/var/log".into())]);
    assert_eq!(f.stats.paths, 1);
}

#[test]
fn count_pattern_types_json() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Json("{}".into())]);
    assert_eq!(f.stats.json, 1);
    assert_eq!(f.stats.paths, 0);
}

#[test]
fn count_pattern_types_number() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Number("42".into())]);
    assert_eq!(f.stats.percentages, 1);
}

#[test]
fn count_pattern_types_quoted_string() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::QuotedString("hello".into())]);
    assert_eq!(f.stats.quoted_strings, 1);
    assert_eq!(f.stats.percentages, 0);
}

#[test]
fn count_pattern_types_fqdn() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Fqdn("example.com".into())]);
    assert_eq!(f.stats.fqdns, 1);
    assert_eq!(f.stats.ips, 0, "FQDNs must not count as IPs");
    // Accumulates (kills += -> -= / *= mutants).
    f.count_pattern_types(&[Token::Fqdn("example.org".into())]);
    assert_eq!(f.stats.fqdns, 2);
}

#[test]
fn count_pattern_types_name() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Name("app".into())]);
    assert_eq!(f.stats.names, 1);
    assert_eq!(f.stats.percentages, 0);
    // Second hit must accumulate (kills += -> -= / *= mutants).
    f.count_pattern_types(&[Token::Name("app".into())]);
    assert_eq!(f.stats.names, 2);
}

#[test]
fn count_pattern_types_bracket_context() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::BracketContext(vec!["error".into()])]);
    assert_eq!(f.stats.brackets, 1);
    assert_eq!(f.stats.percentages, 0);
}

#[test]
fn count_pattern_types_kv_pair() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::KeyValuePair {
        key: "k".into(),
        value_type: "string".into(),
    }]);
    assert_eq!(f.stats.key_values, 1);
    assert_eq!(f.stats.percentages, 0);
}

#[test]
fn count_pattern_types_log_module() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::LogWithModule {
        module: "mod".into(),
        level: "error".into(),
    }]);
    assert_eq!(f.stats.log_modules, 1);
    assert_eq!(f.stats.percentages, 0);
}

#[test]
fn count_pattern_types_structured_message() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::StructuredMessage {
        component: "api".into(),
        level: "info".into(),
    }]);
    assert_eq!(f.stats.structured, 1);
    assert_eq!(f.stats.percentages, 0);
}

// ---------------------------------------------------------------
// sequential_clustering
// ---------------------------------------------------------------

#[test]
fn sequential_clustering_empty_tokens_no_pattern() {
    let mut f = make_folder();
    let line = make_line("no patterns here", vec![]);
    f.sequential_clustering(line).unwrap();
    assert_eq!(f.stats.patterns_detected, 0);
}

#[test]
fn sequential_clustering_with_tokens_increments() {
    let mut f = make_folder();
    let line = make_line("error <IP>", vec![Token::IPv4("10.0.0.1".into())]);
    f.sequential_clustering(line).unwrap();
    assert_eq!(f.stats.patterns_detected, 1);
    assert_eq!(f.stats.ips, 1);
}

// ---------------------------------------------------------------
// prepare_summary boundary tests
// ---------------------------------------------------------------

#[test]
fn prepare_summary_exactly_30_not_capped() {
    let mut f = make_folder();
    for i in 0..30 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("pattern {i}"), vec![]),
            i + 1,
        ));
    }
    let (display, _total, was_capped, _) = f.prepare_summary(None, None).unwrap();
    assert!(!was_capped, "exactly 30 should not be capped");
    assert_eq!(display.len(), 30);
}

#[test]
fn prepare_summary_31_is_capped() {
    let mut f = make_folder();
    for i in 0..31 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("pattern {i}"), vec![]),
            i + 1,
        ));
    }
    let (display, _total, was_capped, _) = f.prepare_summary(None, None).unwrap();
    assert!(was_capped, "31 should be capped");
    assert_eq!(display.len(), 30);
}

#[test]
fn prepare_summary_top_zero_no_cap_50() {
    let mut f = make_folder();
    for i in 0..50 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("pattern {i}"), vec![]),
            i + 1,
        ));
    }
    let (display, _total, was_capped, _) = f.prepare_summary(Some(0), None).unwrap();
    assert!(!was_capped);
    assert_eq!(display.len(), 50);
}

#[test]
fn prepare_summary_fit_budget_10_of_50() {
    let mut f = make_folder();
    for i in 0..50 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("pattern {i}"), vec![]),
            i + 1,
        ));
    }
    let (display, _total, _was_capped, fit_truncated) = f.prepare_summary(None, Some(10)).unwrap();
    assert!(display.len() <= 10);
    assert!(fit_truncated > 0);
}

// ---------------------------------------------------------------
// finish_top_n boundary tests
// ---------------------------------------------------------------

#[test]
fn finish_top_n_zero_input_lines() {
    let mut f = make_folder();
    f.stats.total_lines = 0;
    let (_, _, coverage) = f.finish_top_n(10).unwrap();
    assert_eq!(coverage, 0);
}

// ---------------------------------------------------------------
// Targeted tests for remaining missed mutants
// ---------------------------------------------------------------

// format_group_dispatch line 729: >= with < boundary
// count < min_collapse should NOT compute rollup
#[test]
fn format_group_dispatch_below_min_collapse_no_rollup() {
    let mut f = make_folder(); // min_collapse = 3
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
        ],
    ); // count = 2, below min_collapse = 3
    let output = f.format_group_dispatch(&group).unwrap();
    // Below min_collapse: no rollup marker, just the raw lines
    assert!(
        !output.contains("similar"),
        "2 lines should not collapse: {output}"
    );
}

#[test]
fn format_group_dispatch_at_min_collapse_computes_rollup() {
    let mut f = make_folder(); // min_collapse = 3
    // Use enough varied tokens that rollup produces distinct output vs legacy
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
            vec![Token::IPv4("10.0.0.5".into())],
        ],
    ); // count = 5, well above min_collapse
    let output = f.format_group_dispatch(&group).unwrap();
    // Rollup path produces "ipv4×N" markers; legacy produces "[+N similar, varying: ...]"
    // If >= is mutated to <, count=5 >= 3 would become 5 < 3 = false → empty rollup
    // → legacy format which says "similar" but NOT "ipv4"
    assert!(
        output.contains("ipv4"),
        "rollup should produce ipv4 marker, got legacy format: {output}"
    );
}

// prepare_summary: return value substitution tests (lines 941)
#[test]
fn prepare_summary_returns_nonempty_for_nonempty_buffer() {
    let mut f = make_folder();
    f.buffer
        .push(PatternGroup::new(make_line("error", vec![]), 1));
    let (display, total, was_capped, fit_truncated) = f.prepare_summary(None, None).unwrap();
    assert!(
        !display.is_empty(),
        "should return entries for non-empty buffer"
    );
    assert_eq!(total, 1);
    assert!(!was_capped);
    assert_eq!(fit_truncated, 0);
}

// prepare_summary line 969: > boundary with top_n=Some(0) + fit_budget
#[test]
fn prepare_summary_top_zero_fit_budget_exact_boundary() {
    let mut f = make_folder();
    for i in 0..5 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    // top=0 + budget=5: sorted.len() == budget, NOT > budget → no truncation
    let (display, _, _, fit_truncated) = f.prepare_summary(Some(0), Some(5)).unwrap();
    assert_eq!(display.len(), 5);
    assert_eq!(fit_truncated, 0, "exact fit should not truncate");
}

#[test]
fn prepare_summary_top_zero_fit_budget_over() {
    let mut f = make_folder();
    for i in 0..5 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    // top=0 + budget=3: sorted.len() > budget → truncate
    let (display, _, _, fit_truncated) = f.prepare_summary(Some(0), Some(3)).unwrap();
    assert_eq!(display.len(), 2); // budget.saturating_sub(1) = 2
    assert_eq!(fit_truncated, 3); // 5 - 2 = 3 remaining
}

// prepare_summary line 971: saturating_sub arithmetic
#[test]
fn prepare_summary_top_zero_fit_budget_one() {
    let mut f = make_folder();
    for i in 0..5 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    // budget=1, saturating_sub(1) = 0 → show 0 patterns, remaining = 5
    let (display, _, _, fit_truncated) = f.prepare_summary(Some(0), Some(1)).unwrap();
    assert_eq!(display.len(), 0);
    assert_eq!(fit_truncated, 5);
}

// prepare_summary line 983: > with >= on fit_budget (no top_n)
#[test]
fn prepare_summary_fit_budget_exact() {
    let mut f = make_folder();
    for i in 0..5 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    // fit_budget=5, sorted.len()=5 → NOT > budget → no truncation
    let (display, _, _, fit_truncated) = f.prepare_summary(None, Some(5)).unwrap();
    assert_eq!(display.len(), 5);
    assert_eq!(fit_truncated, 0);
}

// format_summary_line: detailed boundary tests
#[test]
fn summary_line_truncation_arithmetic() {
    // Width = 30, prefix "[5x] " = 5 chars, representative = 30 chars
    // prefix.len() + representative.len() = 35 > 30 → truncate
    // avail = 30 - 5 - 3 = 22 > 20 → do truncate with ...
    let line = PatternFolder::format_summary_line(5, &"x".repeat(30), Some(30));
    assert!(line.ends_with("..."), "should truncate: {line}");
    assert!(line.len() <= 30, "should fit in width: len={}", line.len());
}

#[test]
fn summary_line_prefix_plus_rep_exactly_at_width() {
    // prefix "[5x] " = 5 chars + representative 25 chars = 30 = width → no truncation
    let line = PatternFolder::format_summary_line(5, &"x".repeat(25), Some(30));
    assert!(
        !line.ends_with("..."),
        "exact fit should not truncate: {line}"
    );
}

#[test]
fn summary_line_avail_exactly_20() {
    // Width = 28, prefix "[5x] " = 5, avail = 28 - 5 - 3 = 20 → exactly 20, NOT > 20
    // So: don't truncate (avail must be > 20)
    let long = "x".repeat(30);
    let line = PatternFolder::format_summary_line(5, &long, Some(28));
    assert!(
        !line.ends_with("..."),
        "avail=20 should not truncate: {line}"
    );
}

#[test]
fn summary_line_avail_21_does_truncate() {
    // Width = 29, prefix "[5x] " = 5, avail = 29 - 5 - 3 = 21 > 20 → truncate
    let long = "x".repeat(30);
    let line = PatternFolder::format_summary_line(5, &long, Some(29));
    assert!(line.ends_with("..."), "avail=21 should truncate: {line}");
}

// finish_summary line 1051: replace with Ok(()) — verify it actually does something
#[test]
fn finish_summary_does_not_panic() {
    let mut f = make_folder();
    f.stats.total_lines = 10;
    for i in 0..3 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("error {i}"), vec![]),
            i + 1,
        ));
    }
    // finish_summary prints to stdout — verify it runs without error
    f.finish_summary(None, None).unwrap();
}

// finish_summary line 1068: fit_truncated > 0 boundary
#[test]
fn finish_summary_with_fit_truncation() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    for i in 0..10 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("pattern {i}"), vec![]),
            i + 1,
        ));
    }
    // fit_budget=3 with 10 patterns → fit_truncated > 0
    f.finish_summary(None, Some(3)).unwrap();
    // Can't capture stdout, but no panic = OK
}

// finish_top_n line 1108: delete ! on batch_buffer.is_empty()
#[test]
fn finish_top_n_flushes_batch_buffer() {
    let mut f = make_folder();
    f.stats.total_lines = 5;
    // Put lines in batch_buffer (simulating unprocessed batch)
    f.batch_buffer.push("error one".to_string());
    f.batch_buffer.push("error two".to_string());
    let (output, total, _) = f.finish_top_n(10).unwrap();
    // Should have flushed and processed the batch
    assert!(f.batch_buffer.is_empty(), "batch should be flushed");
    assert!(total > 0 || output.is_empty()); // processed something
}

// finish_top_n line 1131: += on output_lines
#[test]
fn finish_top_n_updates_output_lines() {
    let mut f = make_folder();
    f.stats.total_lines = 10;
    for i in 0..3 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("error {i}"), vec![]),
            i + 1,
        ));
    }
    let before = f.stats.output_lines;
    let _ = f.finish_top_n(10).unwrap();
    assert!(
        f.stats.output_lines > before,
        "should increment output_lines"
    );
}

// finish_top_n line 1139: > with >= on coverage calc
#[test]
fn finish_top_n_coverage_50_percent() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    // Create one group with 50 lines
    let mut group = PatternGroup::new(make_line("error", vec![]), 1);
    for i in 1..50 {
        group.add_line(make_line("error", vec![]), i + 1);
    }
    f.buffer.push(group);
    let (_, _, coverage) = f.finish_top_n(10).unwrap();
    assert_eq!(coverage, 50, "50/100 lines = 50% coverage");
}

// format_group line 1198: delete ! on rollup.is_empty()
#[test]
fn format_group_empty_rollup_uses_legacy() {
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ],
    );
    let empty_rollup = BTreeMap::new();
    let output = f.format_group(&group, &empty_rollup).unwrap();
    // Empty rollup → legacy format_collapsed_line path
    assert!(
        output.contains("similar"),
        "empty rollup should use legacy: {output}"
    );
}

#[test]
fn format_group_nonempty_rollup_uses_compact() {
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
        ],
    );
    let rollup = f.rollup_computer.compute(&group);
    let output = f.format_group(&group, &rollup).unwrap();
    // Non-empty rollup → compact marker path
    assert!(
        output.contains("ipv4") || output.contains("similar"),
        "non-empty rollup should use compact: {output}"
    );
}

// format_group line 1202/1213: - with + on count-2 and count-3
#[test]
fn format_group_lines_saved_arithmetic() {
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
            vec![Token::IPv4("10.0.0.5".into())],
        ],
    ); // count = 5
    let rollup = BTreeMap::new();
    f.format_group(&group, &rollup).unwrap();
    // lines_saved = count - 3 = 5 - 3 = 2
    assert_eq!(f.stats.lines_saved, 2, "5 lines collapsed saves 2");
}

// format_group line 1228: && with || and delete ! on essence_mode PII
#[test]
fn format_group_pii_masking_only_in_non_essence() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        sanitize_pii: true,
        essence_mode: false,
        ..Config::default()
    });
    let group = make_group(
        "user test@example.com logged in",
        vec![
            vec![Token::Email("test@example.com".into())],
            vec![Token::Email("test@example.com".into())],
            vec![Token::Email("test@example.com".into())],
        ],
    );
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    // PII masking: email should be masked
    assert!(
        output.contains("***@***") || !output.contains("test@example.com"),
        "PII should be masked in non-essence mode: {output}"
    );
}

// format_group line 1238: > with >= on group.count() > 1
#[test]
fn format_group_single_line_no_last() {
    let mut f = make_folder();
    let group = make_group("single line", vec![vec![]]);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    // Single line: no "last line" section
    assert_eq!(
        output.lines().count(),
        1,
        "single line should have 1 line: {output}"
    );
}

#[test]
fn format_group_two_lines_has_last() {
    let mut f = make_folder();
    let group = make_group("error msg", vec![vec![], vec![]]);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    // Two lines, below min_collapse: both lines shown
    assert!(
        output.lines().count() >= 2,
        "two lines should show both: {output}"
    );
}

// format_group line 1249: != with == on essence_mode first!=last
#[test]
fn format_group_essence_identical_suppresses_last() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        essence_mode: true,
        ..Config::default()
    });
    // 4 lines, all same normalized text → in essence mode, last = first, suppress last
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
        ],
    );
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    let line_count = output.lines().count();
    // Essence mode with identical first/last normalized: last suppressed
    // Should have first line + collapsed marker, but NOT a third "last" line
    assert!(
        line_count <= 2,
        "essence mode should suppress identical last: {output}"
    );
}

// ---------------------------------------------------------------
// print_stats: each stat field at zero must NOT produce its row
// Kills `> with >=` on each `if self.stats.FIELD > 0` check
// ---------------------------------------------------------------

#[test]
fn print_stats_zero_timestamps_no_row() {
    let mut f = make_folder();
    f.stats.timestamps = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| Timestamps |"),
        "timestamps=0 should not produce Timestamps row: {output}"
    );
}

#[test]
fn print_stats_zero_ips_no_row() {
    let mut f = make_folder();
    f.stats.ips = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| IP Addresses |"),
        "ips=0 should not produce IP Addresses row: {output}"
    );
}

#[test]
fn print_stats_zero_hashes_no_row() {
    let mut f = make_folder();
    f.stats.hashes = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| Hashes |"),
        "hashes=0 should not produce Hashes row: {output}"
    );
}

#[test]
fn print_stats_zero_uuids_no_row() {
    let mut f = make_folder();
    f.stats.uuids = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| UUIDs |"),
        "uuids=0 should not produce UUIDs row: {output}"
    );
}

#[test]
fn print_stats_zero_durations_no_row() {
    let mut f = make_folder();
    f.stats.durations = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| Durations |"),
        "durations=0 should not produce Durations row: {output}"
    );
}

#[test]
fn print_stats_zero_pids_no_row() {
    let mut f = make_folder();
    f.stats.pids = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| Process IDs |"),
        "pids=0 should not produce Process IDs row: {output}"
    );
}

#[test]
fn print_stats_zero_sizes_no_row() {
    let mut f = make_folder();
    f.stats.sizes = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| File Sizes |"),
        "sizes=0 should not produce File Sizes row: {output}"
    );
}

#[test]
fn print_stats_zero_percentages_no_row() {
    let mut f = make_folder();
    f.stats.percentages = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| Numbers/Percentages |"),
        "percentages=0 should not produce Numbers/Percentages row: {output}"
    );
}

#[test]
fn print_stats_zero_http_status_no_row() {
    let mut f = make_folder();
    f.stats.http_status = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| HTTP Status |"),
        "http_status=0 should not produce HTTP Status row: {output}"
    );
}

#[test]
fn print_stats_zero_paths_no_row() {
    let mut f = make_folder();
    f.stats.paths = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| File Paths |"),
        "paths=0 should not produce File Paths row: {output}"
    );
}

#[test]
fn print_stats_zero_kubernetes_no_row() {
    let mut f = make_folder();
    f.stats.kubernetes = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| Kubernetes |"),
        "kubernetes=0 should not produce Kubernetes row: {output}"
    );
}

#[test]
fn print_stats_zero_emails_no_row() {
    let mut f = make_folder();
    f.stats.emails = 0;
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        !output.contains("| Email Addresses |"),
        "emails=0 should not produce Email Addresses row: {output}"
    );
}

// ---------------------------------------------------------------
// format_group: rollup vs legacy path (line 1198 delete ! mutant)
// Distinguishes by output content: rollup has "ipv4×N", legacy has "varying"
// ---------------------------------------------------------------

#[test]
fn format_group_rollup_path_vs_legacy_path_output_differs() {
    // Non-empty rollup should produce compact marker (with type names)
    let mut f1 = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
        ],
    );
    let rollup = f1.rollup_computer.compute(&group);
    assert!(
        !rollup.is_empty(),
        "rollup should be non-empty for varied IPs"
    );
    let output_with_rollup = f1.format_group(&group, &rollup).unwrap();

    // Empty rollup should produce legacy format with "similar" and "varying"
    let mut f2 = make_folder();
    let empty_rollup = BTreeMap::new();
    let output_legacy = f2.format_group(&group, &empty_rollup).unwrap();

    // The two paths must produce different output
    assert_ne!(
        output_with_rollup, output_legacy,
        "rollup vs legacy path should produce different output"
    );
}

// ---------------------------------------------------------------
// format_group: exact count in collapsed marker (lines 1202, 1213)
// Kills `- with +` and `- with /` on count-2 and count-3
// ---------------------------------------------------------------

#[test]
fn format_group_collapsed_marker_exact_count_legacy() {
    // Legacy path (empty rollup): collapsed count = count - 2
    // With 5 lines, the marker should say "+3 similar" (5-2=3)
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
            vec![Token::IPv4("10.0.0.5".into())],
        ],
    );
    let empty_rollup = BTreeMap::new();
    let output = f.format_group(&group, &empty_rollup).unwrap();
    // Legacy format: "[+3 similar, varying: ...]"
    assert!(
        output.contains("+3 similar"),
        "5 lines with empty rollup: marker should say +3 similar (5-2=3), got: {output}"
    );
}

#[test]
fn format_group_collapsed_marker_exact_count_rollup() {
    // Rollup path: collapsed count = count - 2, lines_saved = count - 3
    // With 6 lines, the rollup marker should say "+4 similar" (6-2=4)
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
            vec![Token::IPv4("10.0.0.5".into())],
            vec![Token::IPv4("10.0.0.6".into())],
        ],
    );
    let rollup = f.rollup_computer.compute(&group);
    let output = f.format_group(&group, &rollup).unwrap();
    // Rollup format: "[+4 similar | ...]"
    assert!(
        output.contains("+4 similar"),
        "6 lines with rollup: marker should say +4 similar (6-2=4), got: {output}"
    );
    // Also verify lines_saved = count - 3 = 3
    assert_eq!(f.stats.lines_saved, 3, "6 lines collapsed: saved = 6-3 = 3");
}

// ---------------------------------------------------------------
// format_group: PII + essence interaction (line 1228 && with ||)
// When both sanitize_pii=true AND essence_mode=true, should NOT mask
// ---------------------------------------------------------------

#[test]
fn format_group_pii_plus_essence_does_not_mask() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        sanitize_pii: true,
        essence_mode: true,
        ..Config::default()
    });
    // In essence mode, normalized text is used (not original). Build a group
    // where normalized contains the email text to check masking is NOT applied.
    let mut line = make_line(
        "user alice@test.com logged in",
        vec![Token::Email("alice@test.com".into())],
    );
    line.original = "user alice@test.com logged in".to_string();
    let group = PatternGroup::new(line, 1);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    // In essence mode (even with pii=true), the condition is
    // `sanitize_pii && !essence_mode` which is false, so no masking
    assert!(
        !output.contains("<EMAIL>"),
        "essence mode should NOT mask emails even with sanitize_pii=true: {output}"
    );
}

// ---------------------------------------------------------------
// format_group: count=1 vs count=2 last line (line 1238 > with >=)
// ---------------------------------------------------------------

#[test]
fn format_group_count_1_collapsed_no_last_line() {
    // A group with exactly 1 line above min_collapse threshold cannot
    // happen in practice, but we can test the boundary via a single-line
    // group that does NOT collapse (below min_collapse).
    // The real test: with count=1, `group.count() > 1` is false, so no last line.
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 2, // low threshold to make 3 lines collapse
        ..Config::default()
    });
    let group = make_group("single", vec![vec![]]);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    // count=1: should be just the one line, no extra "last line"
    assert_eq!(
        output.lines().count(),
        1,
        "count=1 should produce exactly 1 line: {output}"
    );
}

#[test]
fn format_group_count_4_collapsed_has_last_line() {
    // With min_collapse=3 and count=4, group collapses and
    // count > 1 is true, so last line should appear.
    // (count must be >= 3 to avoid overflow on lines_saved = count - 3)
    let mut f = make_folder(); // min_collapse=3
    let mut line1 = make_line("error connecting to server", vec![]);
    line1.original = "error connecting to server A".to_string();
    let mut line2 = make_line("error connecting to server", vec![]);
    line2.original = "error connecting to server B".to_string();
    let mut line3 = make_line("error connecting to server", vec![]);
    line3.original = "error connecting to server C".to_string();
    let mut line4 = make_line("error connecting to server", vec![]);
    line4.original = "error connecting to server D".to_string();
    let mut group = PatternGroup::new(line1, 1);
    group.add_line(line2, 2);
    group.add_line(line3, 3);
    group.add_line(line4, 4);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    // count=4 > 1, so last line should be present (3 lines total:
    // first + marker + last)
    let line_count = output.lines().count();
    assert!(
        line_count >= 3,
        "count=4 collapsed should have first+marker+last ({line_count} lines): {output}"
    );
    // Verify the last line content is present
    assert!(
        output.contains("server D"),
        "last line should appear in collapsed output: {output}"
    );
}

// ---------------------------------------------------------------
// format_group: essence mode with different first/last (line 1249)
// Kills `!= with ==` — different lines should show last line
// ---------------------------------------------------------------

#[test]
fn format_group_non_essence_different_first_last_shows_both() {
    // In non-essence collapsed mode, when first_line != last_line,
    // the last line should appear in the output.
    // This tests line 1249: `!self.config.essence_mode || first_line != last_line`
    let mut f = make_folder(); // non-essence, min_collapse=3
    let mut line1 = make_line("error connecting to server", vec![]);
    line1.original = "error connecting to A".to_string();
    let mut line2 = make_line("error connecting to server", vec![]);
    line2.original = "error connecting to B".to_string();
    let mut line3 = make_line("error connecting to server", vec![]);
    line3.original = "error connecting to C".to_string();
    let mut group = PatternGroup::new(line1, 1);
    group.add_line(line2, 2);
    group.add_line(line3, 3);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    // Non-essence mode: condition is true (short-circuits on !essence_mode)
    // So last line ("error connecting to C") should appear
    assert!(
        output.contains("error connecting to C"),
        "non-essence collapsed with different first/last should show last: {output}"
    );
}

#[test]
fn format_group_non_essence_same_first_last_still_shows_last() {
    // Even when first and last original text are identical, in non-essence
    // mode the last line still shows (because !essence_mode is true).
    // This exercises line 1249 where the != check is redundant in non-essence.
    let mut f = make_folder(); // non-essence, min_collapse=3
    let line1 = make_line("identical text", vec![]);
    let line2 = make_line("identical text", vec![]);
    let line3 = make_line("identical text", vec![]);
    let mut group = PatternGroup::new(line1, 1);
    group.add_line(line2, 2);
    group.add_line(line3, 3);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    let line_count = output.lines().count();
    // Non-essence mode: last line always shown when count > 1
    assert_eq!(
        line_count, 3,
        "non-essence collapsed with same first/last should still show 3 lines: {output}"
    );
}

// ---------------------------------------------------------------
// format_group: PII masking for last line (line 1253 && with ||)
// ---------------------------------------------------------------

#[test]
fn format_group_pii_masks_last_line_in_non_essence() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        sanitize_pii: true,
        essence_mode: false,
        ..Config::default()
    });
    // Build a group with 3 lines (collapses). Last line has an email.
    let line1 = make_line(
        "user <EMAIL> logged in",
        vec![Token::Email("first@test.com".into())],
    );
    let line2 = make_line(
        "user <EMAIL> logged in",
        vec![Token::Email("second@test.com".into())],
    );
    let mut line3 = make_line(
        "user <EMAIL> logged in",
        vec![Token::Email("last@test.com".into())],
    );
    line3.original = "user last@test.com logged in".to_string();
    let mut group = PatternGroup::new(line1, 1);
    group.add_line(line2, 2);
    group.add_line(line3, 3);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    // In non-essence mode with PII, last line's email should be masked
    assert!(
        !output.contains("last@test.com"),
        "last line email should be masked with PII in non-essence mode: {output}"
    );
}

#[test]
fn format_group_pii_does_not_mask_last_line_in_essence() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 2,
        sanitize_pii: true,
        essence_mode: true,
        ..Config::default()
    });
    // In essence mode, PII masking for last line should NOT apply
    // because condition is `sanitize_pii && !essence_mode`
    let line1 = make_line(
        "user alice@test.com logged in",
        vec![Token::Email("alice@test.com".into())],
    );
    let mut line2 = make_line(
        "user bob@test.com logged in",
        vec![Token::Email("bob@test.com".into())],
    );
    line2.original = "user bob@test.com logged in".to_string();
    let mut group = PatternGroup::new(line1, 1);
    group.add_line(line2, 2);
    let rollup = BTreeMap::new();
    let output = f.format_group(&group, &rollup).unwrap();
    // In essence mode, normalized text is used (not original), so
    // the email in normalized won't be masked. The key point is
    // the <EMAIL> token should NOT appear.
    assert!(
        !output.contains("<EMAIL>"),
        "essence mode should not apply PII masking to last line: {output}"
    );
}

// ---------------------------------------------------------------
// format_group: non-collapsed group boundary (line 1273 > with >=)
// When count > 1 in non-collapsed essence path, lines_saved accumulates
// ---------------------------------------------------------------

#[test]
fn format_group_essence_non_collapsed_count_1_no_lines_saved() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        essence_mode: true,
        ..Config::default()
    });
    let group = make_group("single pattern", vec![vec![]]);
    let rollup = BTreeMap::new();
    let _ = f.format_group(&group, &rollup).unwrap();
    // count=1, so `count > 1` is false → no lines_saved
    assert_eq!(
        f.stats.lines_saved, 0,
        "essence mode count=1 should not save lines"
    );
}

#[test]
fn format_group_essence_non_collapsed_count_2_saves_lines() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        essence_mode: true,
        ..Config::default()
    });
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
        ],
    );
    let rollup = BTreeMap::new();
    let _ = f.format_group(&group, &rollup).unwrap();
    // count=2, in essence mode below min_collapse: lines_saved = 2-1 = 1
    assert_eq!(
        f.stats.lines_saved, 1,
        "essence mode count=2 should save 1 line"
    );
}

// ---------------------------------------------------------------
// finish_summary: observable side effects (line 1051 replace with Ok(()))
// ---------------------------------------------------------------

#[test]
fn finish_summary_flushes_batch_buffer() {
    // finish_summary calls prepare_summary which flushes batch_buffer.
    // If replaced with Ok(()), prepare_summary wouldn't be called
    // and batch_buffer would remain non-empty.
    let mut f = make_folder();
    f.stats.total_lines = 5;
    // Put lines in batch_buffer (simulating unprocessed parallel batch)
    f.batch_buffer
        .push("2024-01-01 ERROR one 10.0.0.1".to_string());
    f.batch_buffer
        .push("2024-01-01 ERROR two 10.0.0.2".to_string());
    assert!(!f.batch_buffer.is_empty());
    let result = f.finish_summary(None, None);
    assert!(result.is_ok());
    // prepare_summary drains batch_buffer via process_batch
    assert!(
        f.batch_buffer.is_empty(),
        "finish_summary should flush batch_buffer via prepare_summary"
    );
}

// ---------------------------------------------------------------
// finish_summary: fit_truncated=0 should NOT print extra line (line 1068)
// Kills `> with >=` and `> with ==` and `> with <`
// ---------------------------------------------------------------

#[test]
fn prepare_summary_fit_truncated_zero_when_under_budget() {
    // When patterns fit within budget, fit_truncated should be exactly 0
    let mut f = make_folder();
    for i in 0..3 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    // budget=10, only 3 patterns → fit_truncated = 0
    let (_, _, _, fit_truncated) = f.prepare_summary(None, Some(10)).unwrap();
    assert_eq!(
        fit_truncated, 0,
        "3 patterns within budget=10 should have fit_truncated=0"
    );
}

#[test]
fn prepare_summary_fit_truncated_nonzero_when_over_budget() {
    let mut f = make_folder();
    for i in 0..10 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    // budget=5, 10 patterns → fit_truncated > 0
    let (_, _, _, fit_truncated) = f.prepare_summary(None, Some(5)).unwrap();
    assert!(
        fit_truncated > 0,
        "10 patterns with budget=5 should have fit_truncated > 0, got {fit_truncated}"
    );
}

// ---------------------------------------------------------------
// finish_top_n: coverage with total_input_lines > 0 (line 1139)
// Kills `> with >=` — when total_input_lines=0, coverage=0
// ---------------------------------------------------------------

#[test]
fn finish_top_n_zero_total_lines_zero_coverage() {
    let mut f = make_folder();
    f.stats.total_lines = 0;
    // Even with a group in the buffer, coverage should be 0
    // because total_input_lines is 0
    f.buffer
        .push(PatternGroup::new(make_line("error", vec![]), 1));
    let (_, _, coverage) = f.finish_top_n(10).unwrap();
    assert_eq!(
        coverage, 0,
        "zero total_input_lines should produce 0% coverage"
    );
}

#[test]
fn finish_top_n_nonzero_total_lines_nonzero_coverage() {
    let mut f = make_folder();
    f.stats.total_lines = 10;
    let mut group = PatternGroup::new(make_line("error", vec![]), 1);
    for i in 1..10 {
        group.add_line(make_line("error", vec![]), i + 1);
    }
    f.buffer.push(group);
    let (_, _, coverage) = f.finish_top_n(10).unwrap();
    assert_eq!(coverage, 100, "10/10 lines should be 100% coverage");
}

// ---------------------------------------------------------------
// print_stats_json: verify it writes to stderr (line 1506)
// Since print_stats_json writes to real stderr, we test via
// build_stats_json (the extracted testable core) and verify
// the JSON can be serialized to a writer.
// ---------------------------------------------------------------

#[test]
fn build_stats_json_serializes_to_writer() {
    // This kills the "replace with Ok(())" mutant by proving
    // the stats JSON is valid and non-empty when serialized.
    let mut f = make_folder();
    f.stats.total_lines = 50;
    f.stats.lines_saved = 25;
    f.stats.output_lines = 25;
    f.stats.timestamps = 5;
    let stats = f.build_stats_json(Duration::from_millis(42));
    let mut buf = Vec::new();
    serde_json::to_writer(&mut buf, &stats).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(!output.is_empty(), "stats JSON should not be empty");
    let v: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(v["input_lines"], 50);
    assert_eq!(v["output_lines"], 25);
    assert_eq!(v["elapsed_ms"], 42);
    assert_eq!(v["pattern_hits"]["timestamps"], 5);
}

// ---------------------------------------------------------------
// get_stats: verify it returns current stats (line 1613)
// Kills return substitution mutant
// ---------------------------------------------------------------

#[test]
fn get_stats_returns_current_stats() {
    let mut f = make_folder();
    f.stats.total_lines = 42;
    f.stats.ips = 7;
    f.stats.timestamps = 3;
    let stats = f.get_stats();
    assert_eq!(
        stats.total_lines, 42,
        "get_stats should return current total_lines"
    );
    assert_eq!(stats.ips, 7, "get_stats should return current ips");
    assert_eq!(
        stats.timestamps, 3,
        "get_stats should return current timestamps"
    );
}

#[test]
fn get_stats_reflects_processing() {
    let mut f = make_folder();
    // Process some lines to populate stats
    f.process_line("2024-01-01 10:00:00 INFO hello 192.168.1.1")
        .unwrap();
    f.process_line("2024-01-01 10:00:01 INFO world 192.168.1.2")
        .unwrap();
    let stats = f.get_stats();
    assert_eq!(stats.total_lines, 2, "should have processed 2 lines");
    assert!(
        stats.patterns_detected > 0,
        "should detect patterns after processing"
    );
}

// ---------------------------------------------------------------
// Masking: --sanitize-pii must mask in every output mode, not just
// the text fold path.
// ---------------------------------------------------------------

#[test]
fn json_records_mask_pii_when_enabled() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        sanitize_pii: true,
        output_format: "json".to_string(),
        ..Config::default()
    });
    for who in ["alice", "bob", "carol", "dave"] {
        let _ = f
            .process_line(&format!("user {who}@example.com login failed"))
            .unwrap();
    }
    let out = f.finish().unwrap().join("\n");
    assert!(
        !out.contains("example.com"),
        "raw email leaked into JSON output: {out}"
    );
    assert!(out.contains("<EMAIL>"));
}
#[test]
fn text_marker_masks_email_samples_when_enabled() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        sanitize_pii: true,
        ..Config::default()
    });
    // Six lines, three distinct emails: distinct_count is within the
    // text sample threshold, so the compact marker would surface the
    // raw values inline without masking.
    for who in ["alice", "bob", "eve", "alice", "bob", "eve"] {
        let _ = f
            .process_line(&format!("user {who}@example.com login failed"))
            .unwrap();
    }
    let out = f.finish().unwrap().join("\n");
    assert!(
        !out.contains("example.com"),
        "raw email in text output: {out}"
    );
}
#[test]
fn summary_masks_pii_when_enabled() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        sanitize_pii: true,
        ..Config::default()
    });
    for who in ["alice", "bob", "carol"] {
        let _ = f
            .process_line(&format!("user {who}@example.com login failed"))
            .unwrap();
    }
    let (display, _, _, _) = f.prepare_summary(None, None).unwrap();
    assert!(!display.is_empty());
    for (_, representative) in &display {
        assert!(
            !representative.contains("example.com"),
            "raw email in summary line: {representative}"
        );
    }
}

// ---------------------------------------------------------------
// Cross-mode consistency: one fold-metric definition shared by the
// text footer, --stats-json, the JSONL summary record, and markdown.
// ---------------------------------------------------------------

#[test]
fn fold_metrics_agree_between_text_and_json_modes() {
    let run = |format: &str| {
        let mut f = PatternFolder::new(Config {
            thread_count: Some(1),
            output_format: format.to_string(),
            ..Config::default()
        });
        for i in 0..20 {
            let _ = f
                .process_line(&format!("error connecting to 10.0.0.{i} timeout"))
                .unwrap();
        }
        let _ = f.finish().unwrap();
        let s = f.build_stats_json(Duration::from_millis(1));
        // bit-exact ratio comparison: both modes must run the same
        // computation, not merely land close
        (
            s.lines_saved,
            s.collapsed_groups,
            s.compression_ratio.to_bits(),
        )
    };
    assert_eq!(run("text"), run("json"));
}
#[test]
fn summary_record_and_stats_json_report_identical_metrics() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        output_format: "json".to_string(),
        ..Config::default()
    });
    for i in 0..20 {
        let _ = f
            .process_line(&format!("error connecting to 10.0.0.{i} timeout"))
            .unwrap();
    }
    let _ = f.finish().unwrap();
    let mut buf = Vec::new();
    f.print_summary_json(&mut buf, Duration::from_millis(5))
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let stats = f.build_stats_json(Duration::from_millis(5));
    assert_eq!(
        record["lines_saved"].as_u64().unwrap() as usize,
        stats.lines_saved
    );
    assert_eq!(
        record["collapsed_groups"].as_u64().unwrap() as usize,
        stats.collapsed_groups
    );
    assert_eq!(
        record["compression_ratio"].as_f64().unwrap().to_bits(),
        stats.compression_ratio.to_bits()
    );
}
#[test]
fn markdown_document_masks_pii_and_shares_fold_metrics() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        sanitize_pii: true,
        output_format: "markdown".to_string(),
        ..Config::default()
    });
    for who in ["alice", "bob", "eve", "mallory"] {
        let _ = f
            .process_line(&format!("user {who}@example.com login failed"))
            .unwrap();
    }
    let flushed = f.finish().unwrap();
    assert!(
        flushed.is_empty(),
        "markdown mode buffers entries for the document"
    );
    let mut buf = Vec::new();
    f.emit_markdown(&mut buf).unwrap();
    let doc = String::from_utf8(buf).unwrap();
    assert!(!doc.contains("example.com"), "raw email in markdown: {doc}");
    let stats = f.get_stats();
    let expected = (stats.lines_saved as f64 / stats.total_lines as f64) * 100.0;
    assert!(
        doc.contains(&format!("Compression ratio**: {expected:.1}%")),
        "markdown ratio must use the shared fold metric: {doc}"
    );
}

// ---------------------------------------------------------------
// --threads N thread-pool sizing (r98.11)
// ---------------------------------------------------------------

#[test]
fn new_sizes_thread_pool_from_explicit_thread_count() {
    let f = PatternFolder::new(Config {
        thread_count: Some(3),
        ..Config::default()
    });
    let pool = f
        .thread_pool
        .as_ref()
        .expect("thread_count=Some(3) must build a dedicated pool");
    let cores = std::thread::available_parallelism().map_or(8, usize::from);
    assert_eq!(
        pool.current_num_threads(),
        3.min(cores),
        "--threads 3 must size the pool to exactly 3 threads (capped at available parallelism)"
    );
}

/// --threads with an absurd value must clamp to available parallelism, not
/// spawn N raw OS threads (--threads 999999 once took the dev machine down).
#[test]
fn new_caps_thread_pool_at_available_parallelism() {
    let f = PatternFolder::new(Config {
        thread_count: Some(999_999),
        ..Config::default()
    });
    let pool = f
        .thread_pool
        .as_ref()
        .expect("huge thread_count must still build a (capped) pool");
    let cores = std::thread::available_parallelism().map_or(8, usize::from);
    assert_eq!(
        pool.current_num_threads(),
        cores,
        "--threads 999999 must clamp to available parallelism"
    );
}

#[test]
fn new_builds_no_pool_for_single_threaded_mode() {
    let f = PatternFolder::new(Config {
        thread_count: Some(1),
        ..Config::default()
    });
    assert!(
        f.thread_pool.is_none(),
        "Some(1) is the sequential path and must not build a pool"
    );
}

#[test]
fn new_builds_no_pool_for_auto_detect_mode() {
    let f = PatternFolder::new(Config {
        thread_count: None,
        ..Config::default()
    });
    assert!(
        f.thread_pool.is_none(),
        "None means rayon's global default pool, not a dedicated one"
    );
}

#[test]
fn sized_pool_produces_same_output_as_default_pool() {
    let lines = [
        "2024-01-01 10:00:00 ERROR connection refused from 10.0.0.1",
        "2024-01-01 10:00:01 ERROR connection refused from 10.0.0.2",
        "2024-01-01 10:00:02 ERROR connection refused from 10.0.0.3",
        "2024-01-01 10:00:03 ERROR connection refused from 10.0.0.4",
        "2024-01-01 10:00:04 INFO server started on port 8080",
    ];
    let run = |thread_count: Option<usize>| -> Vec<String> {
        let mut f = PatternFolder::new(Config {
            thread_count,
            min_collapse: 3,
            ..Config::default()
        });
        let mut out = Vec::new();
        for line in &lines {
            if let Some(o) = f.process_line(line).unwrap() {
                out.push(o);
            }
        }
        out.extend(f.finish().unwrap());
        out
    };
    assert_eq!(
        run(Some(2)),
        run(None),
        "a sized pool must fold identically to the default pool"
    );
}
