use super::*;
use crate::config::GroupSink;
use crate::patterns::HashType;

fn make_line(normalized: &str, tokens: Vec<Token>) -> LogLine {
    LogLine::new(normalized.to_string(), normalized.to_string(), tokens, 0)
}

fn make_group(normalized: &str, lines: Vec<Vec<Token>>) -> PatternGroup {
    assert!(!lines.is_empty(), "group must have at least one line");
    let mut group = PatternGroup::new(make_line(normalized, lines[0].clone()), 1);
    for (i, tokens) in lines.into_iter().enumerate().skip(1) {
        group.add_line(make_line(normalized, tokens), i + 2);
    }
    group
}

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
fn pii_masking_masks_the_second_occurrence_of_a_repeated_email() {
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

#[test]
fn credentials_password_equals() {
    assert_eq!(
        mask_credentials("login password=hunter2 ok"),
        "login password=<SECRET> ok"
    );
}

#[test]
fn credentials_token_colon_space() {
    assert_eq!(mask_credentials("token: abc123"), "token: <SECRET>");
}

#[test]
fn credentials_mask_keys_that_end_in_a_credential_word() {
    assert_eq!(
        mask_credentials("oauth client_secret=s3cr3t, retrying"),
        "oauth client_secret=<SECRET>, retrying"
    );
}

#[test]
fn credentials_quoted_value_masked_whole() {
    assert_eq!(
        mask_credentials(r#"password = "two words""#),
        "password = <SECRET>"
    );
}

#[test]
fn credential_spans_leave_prose_after_a_credential_word_alone() {
    let line = concat!(
        "failed to fetch token: Post \"https://10.0.0.7:6443/api/v1/",
        "serviceaccounts/blorb/token\": read tcp 10.0.0.7:51706: reset"
    );
    assert!(
        credential_spans(line).is_empty(),
        "the value after token: is too short for a secret and the second key is a URL segment: {:?}",
        credential_spans(line)
            .into_iter()
            .map(|r| &line[r])
            .collect::<Vec<_>>()
    );
}

#[test]
fn credential_spans_still_find_a_real_assignment() {
    let line = "login password=frobnicated ok";
    let spans = credential_spans(line);
    assert_eq!(
        spans.iter().map(|r| &line[r.clone()]).collect::<Vec<_>>(),
        vec!["frobnicated"]
    );
}

#[test]
fn credentials_json_style_key() {
    assert_eq!(
        mask_credentials(r#"{"api_key": "abc123"}"#),
        r#"{"api_key": <SECRET>}"#
    );
}

#[test]
fn credentials_case_insensitive() {
    assert_eq!(mask_credentials("DB_PASSWORD=x1"), "DB_PASSWORD=<SECRET>");
}

#[test]
fn credentials_value_stops_at_query_separator() {
    assert_eq!(
        mask_credentials("GET /cb?access_token=abc123&user=bob"),
        "GET /cb?access_token=<SECRET>&user=bob"
    );
}

#[test]
fn credentials_plain_prose_untouched() {
    let line = "the operation completed successfully";
    assert_eq!(mask_credentials(line), line);
}

#[test]
fn credentials_keyword_without_separator_untouched() {
    let line = "token bucket refilled";
    assert_eq!(mask_credentials(line), line);
}

#[test]
fn credentials_bearer_jwt_masked() {
    assert_eq!(
        mask_credentials("auth Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmN"),
        "auth Bearer <JWT>"
    );
}

#[test]
fn credentials_two_segment_jwt_untouched() {
    let line = "config eyJhbGciOiJIUzI1NiJ9.partial loaded";
    assert_eq!(
        mask_credentials(line),
        line,
        "a real JWT has three segments"
    );
}

#[test]
fn credentials_provider_key_sk() {
    assert_eq!(
        mask_credentials("using sk-abc123def456ghi789 today"),
        "using <KEY> today"
    );
}

#[test]
fn credentials_provider_key_ghp() {
    assert_eq!(
        mask_credentials("push with ghp_AbCd1234EfGh5678"),
        "push with <KEY>"
    );
}

#[test]
fn credentials_provider_key_xoxb() {
    assert_eq!(
        mask_credentials("slack xoxb-1234567890-abcdef"),
        "slack <KEY>"
    );
}

#[test]
fn credentials_short_sk_prefix_untouched() {
    let line = "sk-learn pipeline step";
    assert_eq!(
        mask_credentials(line),
        line,
        "the length floor keeps hyphenated prose like sk-learn"
    );
}

#[test]
fn credentials_assignment_wins_over_jwt() {
    let jwt = concat!(
        "eyJhbGciOiJIUzI1NiJ9",
        ".",
        "eyJzdWIiOiIxIn0",
        ".",
        "sig12345"
    );
    assert_eq!(
        mask_credentials(&format!("token: {jwt}")),
        "token: <SECRET>",
        "the assignment rule runs before the JWT rule and claims the whole value"
    );
}

#[test]
fn pii_masking_applies_credential_rules() {
    let tokens = vec![Token::Email("a@b.com".into())];
    let result = apply_pii_masking("a@b.com password=hunter2", &tokens);
    assert_eq!(result, "<EMAIL> password=<SECRET>");
}

#[test]
fn summary_ranks_every_group_of_a_wide_log() {
    let mut folder = PatternFolder::new(Config {
        thread_count: Some(1),
        summary: true,
        ..Config::default()
    });
    for i in 0..1_100 {
        folder.process_line(&distinct_word(i)).unwrap();
    }
    let SummaryRows {
        display,
        total_patterns,
        ..
    } = folder.prepare_summary(Some(0), None).unwrap();
    assert_eq!(total_patterns, 1_100, "every group must survive to ranking");
    assert_eq!(display.len(), 1_100);
}

#[test]
fn top_n_counts_every_group_of_a_wide_log() {
    let mut folder = PatternFolder::new(Config {
        thread_count: Some(1),
        top_n: Some(5),
        ..Config::default()
    });
    for i in 0..1_100 {
        folder.process_line(&distinct_word(i)).unwrap();
    }
    let TopGroups {
        shown: output,
        total_groups,
        ..
    } = folder.finish_top_n(5, None, false).unwrap();
    assert_eq!(total_groups, 1_100, "denominator must count every group");
    assert_eq!(output.len(), 5);
}

#[test]
fn a_wide_log_conserves_total_count_and_never_duplicates_a_template() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        output_format: OutputFormat::Json,
        min_collapse: 3,
        ..Config::default()
    });
    let mut total_lines = 0usize;
    for round in 0..3 {
        f.process_line("gateway heartbeat ok node=edge-01").unwrap();
        total_lines += 1;
        for i in 0..800 {
            f.process_line(&format!("filler event {}", distinct_word(round * 800 + i)))
                .unwrap();
            total_lines += 1;
        }
    }
    let output = f.finish().unwrap();

    let mut seen_templates = std::collections::HashSet::new();
    let mut counted_total = 0usize;
    for line in &output {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["type"], "group");
        let template = v["normalized"].as_str().unwrap().to_string();
        assert!(
            seen_templates.insert(template.clone()),
            "template appeared in two group records: {template}"
        );
        counted_total += v["count"].as_u64().unwrap() as usize;
    }
    assert_eq!(
        counted_total, total_lines,
        "sum of group counts must equal total input lines"
    );
    let signal_count = output
        .iter()
        .map(|s| serde_json::from_str::<serde_json::Value>(s).unwrap())
        .find(|v| v["normalized"] == "gateway heartbeat ok node=edge-01")
        .map(|v| v["count"].as_u64().unwrap());
    assert_eq!(
        signal_count,
        Some(3),
        "the recurring signal must fold to one record"
    );
}

#[test]
fn a_recurring_line_folds_to_one_record_past_a_thousand_groups() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        explain: true,
        ..Config::default()
    });
    f.process_line("recurringkey").unwrap();
    for i in 0..1_100 {
        f.process_line(&distinct_word(i)).unwrap();
    }
    f.process_line("recurringkey").unwrap();
    let output = f.finish().unwrap();
    let matches = output.iter().filter(|s| s.contains("recurringkey")).count();
    assert_eq!(
        matches, 1,
        "one recurring key must fold to one group record under --explain, got: {output:?}"
    );

    let mut f2 = PatternFolder::new(Config {
        thread_count: Some(1),
        ..Config::default()
    });
    f2.process_line("recurringkey").unwrap();
    for i in 0..1_100 {
        f2.process_line(&distinct_word(i)).unwrap();
    }
    f2.process_line("recurringkey").unwrap();
    let output2 = f2.finish().unwrap();
    let matches2 = output2
        .iter()
        .filter(|s| s.contains("recurringkey"))
        .count();
    assert_eq!(
        matches2, 1,
        "without --explain the recurring key must also fold to one group record, got: {output2:?}"
    );
}

#[test]
fn the_thread_count_does_not_change_the_records_of_a_wide_log() {
    let run = |thread_count| {
        let mut f = PatternFolder::new(Config {
            thread_count,
            output_format: OutputFormat::Json,
            min_collapse: 3,
            ..Config::default()
        });
        for round in 0..3 {
            for _ in 0..400 {
                f.process_line("gateway heartbeat ok node=edge-01").unwrap();
            }
            for i in 0..800 {
                let line = format!("filler event {}", distinct_word(round * 800 + i));
                f.process_line(&line).unwrap();
            }
        }
        f.finish().unwrap()
    };
    let inline = run(Some(1));
    assert!(
        inline.len() > 2_400,
        "2,401 distinct events, more than 1,000 of them live at once"
    );
    assert!(
        inline[0].contains("\"count\":1200"),
        "the repeated group is one record of every member: {}",
        inline[0]
    );
    assert_eq!(
        run(None),
        inline,
        "one thread and the pool fold the same records"
    );
}

fn distinct_word(i: usize) -> String {
    let mut s = String::new();
    let mut x = i;
    for _ in 0..6 {
        s.push(char::from(b'a' + (x % 26) as u8));
        x /= 26;
    }
    s
}

#[test]
fn a_wide_log_preserves_founder_order_and_nontransitive_membership() {
    let a = "worker process alpha started successfully at 10.0.0.1";
    let b = "worker process beta started successfully at 10.0.0.2";
    let c = "worker process beta stopped successfully at 10.0.0.3";
    let run = |explain| {
        let mut folder = PatternFolder::new(Config {
            explain,
            thread_count: Some(1),
            output_format: OutputFormat::Json,
            ..Config::default()
        });
        for _ in 0..3 {
            folder.process_line(a).unwrap();
        }
        for i in 0..1_005 {
            folder
                .process_line(&format!("filler event {}", distinct_word(i)))
                .unwrap();
        }
        for line in [c, c, c, b, b, b] {
            folder.process_line(line).unwrap();
        }
        folder
            .finish()
            .unwrap()
            .iter()
            .map(|s| serde_json::from_str::<serde_json::Value>(s).unwrap())
            .filter(|v| v["normalized"].as_str().unwrap().starts_with("worker"))
            .map(|v| {
                (
                    v["normalized"].clone(),
                    v["count"].clone(),
                    v["variation"].clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let expected = run(true);
    assert_eq!(expected.len(), 2);
    assert_eq!(
        expected[0].1, 6,
        "beta started joins the earlier alpha group across 1,005 other groups"
    );
    assert_eq!(
        expected[1].1, 3,
        "beta started never joins beta stopped, two words from alpha"
    );
    assert_eq!(run(false), expected);
}

#[test]
fn a_capped_varies_set_holds_the_same_values_in_any_order() {
    let values: Vec<String> = (0..40).map(|i| format!("v{i}")).collect();
    let fill = |order: &[usize]| {
        let mut varies = VariesCounts::default();
        for &i in order {
            for _ in 0..=(i % 3) {
                varies.add(&values[i], 1, 8);
            }
        }
        varies
    };
    let forward: Vec<usize> = (0..40).collect();
    let backward: Vec<usize> = (0..40).rev().collect();
    let interleaved: Vec<usize> = (0..40).map(|i| (i * 17) % 40).collect();
    let a = fill(&forward);
    assert!(a.capped);
    assert_eq!(a.counts.len(), 8);
    for order in [&backward, &interleaved] {
        let b = fill(order);
        assert_eq!(b.counts, a.counts);
        assert!(b.capped);
    }
    for (value, &n) in &a.counts {
        let i: usize = value[1..].parse().unwrap();
        assert_eq!(
            n,
            i % 3 + 1,
            "every held value carries its full count: {value}"
        );
    }
    let mut ranked: Vec<&String> = values.iter().collect();
    ranked.sort_by_key(|v| (VariesCounts::rank(v), v.as_str()));
    let mut held: Vec<&String> = a.counts.keys().collect();
    held.sort_by_key(|v| (VariesCounts::rank(v), v.as_str()));
    assert_eq!(held, ranked[..8], "the values held are the lowest-ranked");
}

#[test]
fn pii_masking_empty_email_does_not_loop() {
    let tokens = vec![Token::Email(String::new())];
    let result = apply_pii_masking("no emails here", &tokens);
    assert_eq!(result, "no emails here");
}

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

#[test]
fn seed_for_group_pinned_values() {
    assert_eq!(
        seed_for_group("hello"),
        0xa430_d846_80aa_bd0b,
        "pinned FNV-1a output"
    );
    assert_eq!(
        seed_for_group("world"),
        0x4f59_ff5e_730c_8af3,
        "pinned FNV-1a output"
    );
}

#[test]
fn seed_for_group_empty_string_is_offset_basis() {
    assert_eq!(
        seed_for_group(""),
        0xcbf2_9ce4_8422_2325,
        "no bytes leave the FNV-1a offset basis unchanged"
    );
}

#[test]
fn seed_for_group_different_inputs_different_seeds() {
    let a = seed_for_group("template A: <UUID> failed");
    let b = seed_for_group("template B: <IP> connected");
    assert_ne!(a, b);
}

#[test]
fn hash_token_value_matches_seed_for_same_string() {
    let token = Token::Name("hello".to_string());
    assert_eq!(
        hash_token_value(&token),
        seed_for_group("hello"),
        "both run FNV-1a over the same bytes"
    );
}

#[test]
fn hash_token_value_different_tokens_different_hashes() {
    let a = hash_token_value(&Token::Pid(1234));
    let b = hash_token_value(&Token::Pid(5678));
    assert_ne!(a, b);
}

#[test]
fn streamed_token_hash_equals_hashing_the_value_string_for_every_variant() {
    fn hash_str(s: &str) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0100_0000_01b3;
        let mut h: u64 = FNV_OFFSET;
        for b in s.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }

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
        Token::EmbeddedJson(r#"{"key":"val"}"#.into()),
        Token::Duration("3.5s".into()),
        Token::CpuQuantity("750m".into()),
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
            value_type: crate::patterns::ValueType::Text,
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
        let expected = hash_str(&token_value_string(token));
        assert_eq!(
            hash_token_value(token),
            expected,
            "hash_token_value diverged from value_string hashing for {:?}",
            token_type_name(token)
        );
    }
}

#[test]
fn is_sample_worthy_covers_all_token_variants() {
    let all_tokens: Vec<(Token, bool)> = vec![
        (Token::Uuid("u".into()), true),
        (Token::IPv4("1.2.3.4".into()), true),
        (Token::IPv6("::1".into()), true),
        (Token::Path("/a".into()), true),
        (Token::Email("a@b".into()), true),
        (Token::Hash(HashType::MD5, "abc".into()), true),
        (Token::KubernetesNamespace("ns".into()), true),
        (Token::KubernetesName("web".into()), true),
        (Token::VolumeName("vol".into()), true),
        (Token::PluginType("csi".into()), true),
        (Token::PodName("pod".into()), true),
        (Token::QuotedString("q".into()), true),
        (Token::Name("n".into()), true),
        (Token::HttpStatus(200), true),
        (Token::HttpStatusClass("2xx".into()), true),
        (Token::BracketContext(vec!["err".into()]), true),
        (Token::EmbeddedJson("{}".into()), true),
        (Token::CpuQuantity("750m".into()), true),
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
                value_type: crate::patterns::ValueType::Text,
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

    assert_eq!(
        all_tokens.len(),
        28,
        "Token enum may have new variants — update this test"
    );
}

#[test]
fn token_type_name_covers_all_variants() {
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
        Token::EmbeddedJson("{}".into()),
        Token::Duration("1s".into()),
        Token::CpuQuantity("750m".into()),
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
            value_type: crate::patterns::ValueType::Text,
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
        Token::EmbeddedJson(r#"{"key":"val"}"#.into()),
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
            value_type: crate::patterns::ValueType::Text,
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
            value_type: crate::patterns::ValueType::Text
        }),
        "k=string"
    );
}

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
                Token::Uuid(format!("uuid-{}", i % 3)),
                Token::Timestamp(format!("ts-{i}")),
            ]
        })
        .collect();
    let group = make_group("request <UUID> at <TIMESTAMP>", lines);
    let rollup = rc.compute(&group);

    let uuid_entry = rollup.get("UUID").unwrap();
    assert_eq!(uuid_entry.distinct_count, 3);
    assert_eq!(
        uuid_entry.samples.len(),
        3,
        "3 distinct values fit within ROLLUP_K, so all are shown"
    );
    assert!(!uuid_entry.capped);

    let ts_entry = rollup.get("TIMESTAMP").unwrap();
    assert_eq!(ts_entry.distinct_count, 5);
    assert!(ts_entry.samples.is_empty(), "TIMESTAMP is count-only");
    assert!(!ts_entry.capped);
}

#[test]
fn rollup_exactly_at_cap_is_not_capped() {
    let rc = RollupComputer::with_defaults();
    let lines: Vec<Vec<Token>> = (0..ROLLUP_DISTINCT_CAP)
        .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
        .collect();
    let group = make_group("request <UUID>", lines);
    let rollup = rc.compute(&group);

    let entry = rollup.get("UUID").unwrap();
    assert_eq!(entry.distinct_count, ROLLUP_DISTINCT_CAP);
    assert!(!entry.capped, "exactly at cap should NOT be capped");
}

#[test]
fn rollup_one_over_cap_is_capped() {
    let rc = RollupComputer::with_defaults();
    let lines: Vec<Vec<Token>> = (0..=ROLLUP_DISTINCT_CAP)
        .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
        .collect();
    let group = make_group("request <UUID>", lines);
    let rollup = rc.compute(&group);

    let entry = rollup.get("UUID").unwrap();
    assert_eq!(
        entry.distinct_count, ROLLUP_DISTINCT_CAP,
        "capped at ROLLUP_DISTINCT_CAP"
    );
    assert!(entry.capped, "65th value should trigger capped flag");
}

#[test]
fn rollup_samples_capped_at_k() {
    let rc = RollupComputer::with_defaults();
    let lines: Vec<Vec<Token>> = (0..=ROLLUP_K)
        .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
        .collect();
    let group = make_group("request <UUID>", lines);
    let rollup = rc.compute(&group);

    let entry = rollup.get("UUID").unwrap();
    assert_eq!(entry.distinct_count, ROLLUP_K + 1);
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
    let tokens: Vec<Vec<Token>> = (0..20)
        .map(|i| vec![Token::Uuid(format!("uuid-{i:04}"))])
        .collect();
    let group_a = make_group("template A: <UUID>", tokens.clone());
    let group_b = make_group("template B: <UUID>", tokens);

    let rollup_a = rc.compute(&group_a);
    let rollup_b = rc.compute(&group_b);

    let samples_a = &rollup_a.get("UUID").unwrap().samples;
    let samples_b = &rollup_b.get("UUID").unwrap().samples;

    assert_ne!(
        samples_a, samples_b,
        "different templates seed different draws; 20 choose 7 gives 77,520 possible draws"
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

#[test]
fn marker_empty_rollup() {
    let result = render_compact_marker(42, &BTreeMap::new(), None, None, 3);
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
            counts: None,
            slots: None,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3);
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
            counts: None,
            slots: None,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3);
    assert_eq!(
        result, "[+10 similar | path×5]",
        "5 distinct values exceed the inline threshold of 3: count only, no samples"
    );
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
            counts: None,
            slots: None,
        },
    );
    let result = render_compact_marker(100, &rollup, None, None, 3);
    assert!(
        result.contains("hash×64+"),
        "capped entry needs '+': {result}"
    );
    assert!(
        !result.contains('{'),
        "capped entry should not inline samples: {result}"
    );
}

#[test]
fn marker_time_range_present() {
    let result = render_compact_marker(5, &BTreeMap::new(), Some("10:00:00"), Some("10:05:00"), 3);
    assert_eq!(result, "[+5 similar | 10:00:00 → 10:05:00]");
}

#[test]
fn marker_sample_truncation_at_50_chars() {
    let mut rollup: GroupRollup = BTreeMap::new();
    let long_value = "a".repeat(51);
    let exact_value = "b".repeat(50);
    rollup.insert(
        "PATH",
        VariationEntry {
            distinct_count: 2,
            samples: vec![exact_value.clone(), long_value],
            capped: false,
            counts: None,
            slots: None,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3);
    assert!(
        result.contains(&exact_value),
        "50-char value should not be truncated"
    );
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
            counts: None,
            slots: None,
        },
    );
    rollup.insert(
        "UUID",
        VariationEntry {
            distinct_count: 7,
            samples: vec!["aaa".into(), "bbb".into()],
            capped: false,
            counts: None,
            slots: None,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3);
    assert!(
        result.contains("ipv4×4, uuid×7"),
        "entries are comma-separated, lowercase, in BTreeMap order (IPV4 before UUID): {result}"
    );
}

#[test]
fn marker_count_only_types_filtered_out() {
    let mut rollup: GroupRollup = BTreeMap::new();
    rollup.insert(
        "TIMESTAMP",
        VariationEntry {
            distinct_count: 500,
            samples: vec![],
            capped: false,
            counts: None,
            slots: None,
        },
    );
    rollup.insert(
        "UUID",
        VariationEntry {
            distinct_count: 3,
            samples: vec!["a".into(), "b".into(), "c".into()],
            capped: false,
            counts: None,
            slots: None,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3);
    assert!(
        !result.contains("timestamp"),
        "count-only type with high cardinality should be filtered: {result}"
    );
    assert!(
        result.contains("uuid×3"),
        "sample-worthy type should appear: {result}"
    );
}

#[test]
fn marker_zero_distinct_count_filtered_out() {
    let mut rollup: GroupRollup = BTreeMap::new();
    rollup.insert(
        "UUID",
        VariationEntry {
            distinct_count: 0,
            samples: vec![],
            capped: false,
            counts: None,
            slots: None,
        },
    );
    let result = render_compact_marker(10, &rollup, None, None, 3);
    assert_eq!(
        result, "[+10 similar]",
        "zero-distinct entry must be filtered out"
    );
}

#[test]
fn marker_truncation_exact_length() {
    let mut rollup: GroupRollup = BTreeMap::new();
    let long_value = "x".repeat(100);
    rollup.insert(
        "PATH",
        VariationEntry {
            distinct_count: 1,
            samples: vec![long_value],
            capped: false,
            counts: None,
            slots: None,
        },
    );
    let result = render_compact_marker(5, &rollup, None, None, 3);
    let start = result.find('{').expect("should have inline samples") + 1;
    let end = result.find('}').expect("should have closing brace");
    let rendered_sample = &result[start..end];
    assert_eq!(
        rendered_sample.chars().count(),
        50,
        "49 content chars plus the ellipsis fill the 50-char sample limit: got '{rendered_sample}'"
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

mod rollup_properties {
    use super::*;
    use proptest::collection::vec as pvec;
    use proptest::prelude::*;

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

    fn arb_count_only_token() -> impl Strategy<Value = Token> {
        ("[a-z0-9]{1,20}", 0..4u8).prop_map(|(val, variant)| match variant {
            0 => Token::Timestamp(val),
            1 => Token::Duration(val),
            2 => Token::Number(val),
            _ => Token::Size(val),
        })
    }

    fn arb_token() -> impl Strategy<Value = Token> {
        prop_oneof![arb_sample_worthy_token(), arb_count_only_token(),]
    }

    fn arb_group() -> impl Strategy<Value = PatternGroup> {
        ("[a-z ]{5,30}", pvec(pvec(arb_token(), 0..8), 1..50))
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

fn make_folder() -> PatternFolder {
    PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    })
}

fn rollup_of(lines: &[&str]) -> GroupRollup {
    let mut f = make_folder();
    for l in lines {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1, "these lines must fold into one group");
    f.rollup_computer.compute(&f.buffer[0])
}

#[test]
fn varies_reports_words_no_detector_tokenised() {
    let r = rollup_of(&[
        "2025-09-14 09:09:14,580 - bootstrapping - INFO - Configuring patroni",
        "2025-09-14 09:09:14,609 - bootstrapping - INFO - Configuring crontab",
        "2025-09-14 09:09:14,609 - bootstrapping - INFO - Configuring bootstrap",
    ]);
    let v = &r[VARIES];
    assert_eq!(
        v.distinct_count, 3,
        "untokenised words that differ count like any token type"
    );
    assert_eq!(v.samples, vec!["bootstrap", "crontab", "patroni"]);
    assert!(!v.capped);
}

#[test]
fn the_template_says_varies_where_members_disagree() {
    let mut f = make_folder();
    for l in [
        "2025-06-26T00:45:25+00:00 UXG Max mcad[1886]: ace_reporter.reporter_fail(): Unreachable (http://unifi:8080/inform)",
        "2025-06-26T00:45:26+00:00 UXG Max mcad[1886]: ace_reporter.reporter_fail(): Unreachable (http://unifi:8080/inform)",
        "2025-06-26T00:45:27+00:00 UXG Max mcad[1886]: ace_reporter.reporter_fail(): Timeout (http://unifi:8080/inform)",
        "2025-06-26T00:45:28+00:00 UXG Max mcad[1886]: ace_reporter.reporter_fail(): Unreachable (http://unifi:8080/inform)",
    ] {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1, "the score still folds them");
    assert_eq!(
        f.buffer[0].template(),
        "<TIMESTAMP> UXG Max mcad[<PID>]: ace_reporter.reporter_fail(): <VARIES> (<PATH>)",
        "the shown template must hold for every member, so the word that differs is <VARIES>"
    );
    let r = f.rollup_computer.compute(&f.buffer[0]);
    assert_eq!(r[VARIES].samples, vec!["Unreachable", "Timeout"]);
    assert_eq!(
        r[VARIES].counts,
        Some(vec![3, 1]),
        "each word carries its count, the rare one included"
    );
    assert!(
        r.iter().all(|(k, e)| (*k == VARIES) == e.counts.is_some()),
        "counts are for words only: {r:?}"
    );
}

#[test]
fn varies_samples_are_the_most_frequent_and_the_rarest() {
    let mut lines: Vec<String> = Vec::new();
    for (word, n) in [
        ("alpha", 9),
        ("bravo", 8),
        ("charlie", 7),
        ("delta", 6),
        ("echo", 5),
        ("foxtrot", 4),
        ("golf", 3),
        ("hotel", 2),
        ("india", 1),
    ] {
        for _ in 0..n {
            lines.push(format!(
                "worker finished the nightly batch job with status {word} ok"
            ));
        }
    }
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let r = rollup_of(&refs);
    let v = &r[VARIES];
    assert_eq!(v.distinct_count, 9);
    assert_eq!(
        v.samples,
        vec![
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "india"
        ]
    );
    assert_eq!(
        v.counts,
        Some(vec![9, 8, 7, 6, 5, 4, 1]),
        "ROLLUP_K samples: the six most frequent, then the singleton"
    );
}

#[test]
fn varies_includes_the_representative_value() {
    let r = rollup_of(&[
        "mod_jk child in error state 6",
        "mod_jk child in error state 7",
        "mod_jk child in error state 6",
    ]);
    assert_eq!(
        r[VARIES].samples,
        vec!["6", "7"],
        "the first line's word is part of the variation"
    );
}

#[test]
fn varies_is_absent_when_only_tokens_differ() {
    let r = rollup_of(&["req took 111 ms", "req took 222 ms", "req took 333 ms"]);
    assert!(
        !r.contains_key(VARIES),
        "NUMBER already reports these; VARIES must not repeat them: {r:?}"
    );
    assert!(r.contains_key("NUMBER"));
}

#[test]
fn varies_is_absent_for_identical_lines() {
    let r = rollup_of(&["same words here", "same words here", "same words here"]);
    assert!(!r.contains_key(VARIES), "{r:?}");
}

#[test]
fn an_inserted_word_varies_against_the_members_that_lack_it() {
    let r = rollup_of(&[
        "worker started handling batch alpha beta gamma delta",
        "worker started now handling batch alpha beta gamma delta",
        "worker started handling batch alpha beta gamma delta",
    ]);
    assert_eq!(
        r[VARIES].samples,
        vec![ABSENT, "now"],
        "the inserted word is a slot of its own, absent from the members without it: {r:?}"
    );
    assert_eq!(r[VARIES].counts, Some(vec![2, 1]));
}

#[test]
fn varies_is_capped_like_every_other_type() {
    let lines: Vec<String> = (0..80).map(|i| format!("unit u{i} started")).collect();
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        threshold: 50,
        ..Config::default()
    });
    for l in &refs {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    let r = f.rollup_computer.compute(&f.buffer[0]);
    let v = &r[VARIES];
    assert!(v.capped, "80 distinct words must hit the cap");
    assert_eq!(v.distinct_count, ROLLUP_DISTINCT_CAP);
}

fn explaining_folder() -> PatternFolder {
    PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        explain: true,
        ..Config::default()
    })
}

#[test]
fn explain_records_the_nearest_group_and_the_first_differing_token() {
    let mut f = explaining_folder();
    f.process_line("req took 111 ms").unwrap();
    f.process_line("req took 222 ms").unwrap();
    f.process_line("req took 333 sec").unwrap();
    let founded = f.buffer.last().unwrap();
    let nearest = founded
        .nearest
        .as_ref()
        .expect("a miss records its nearest group");
    assert_eq!(nearest.group_line_no, 1);
    assert!(
        nearest.score > 50.0 && nearest.score < 100.0,
        "score={}",
        nearest.score
    );
    let diff = nearest.first_diff.as_ref().expect("the lines differ");
    assert_eq!(
        diff.ours, "sec",
        "the same shape up to the unit: the lines differ first at the unit"
    );
    assert_eq!(diff.theirs, "ms");
    assert_eq!(&founded.first().normalized[diff.at..diff.at + 3], "sec");
}

#[test]
fn explain_leaves_the_first_group_and_hash_hits_unexplained() {
    let mut f = explaining_folder();
    f.process_line("alpha one").unwrap();
    assert!(
        f.buffer[0].nearest.is_none(),
        "nothing to compare the first line against"
    );
    f.process_line("alpha one").unwrap();
    assert_eq!(f.buffer.len(), 1, "identical line joins by hash");
    assert!(
        f.buffer[0].nearest.is_none(),
        "a group that was joined, not founded, has no nearest"
    );
}

#[test]
fn explain_score_is_the_highest_across_the_whole_buffer() {
    let mut f = explaining_folder();
    f.process_line("zzz zzz zzz zzz").unwrap();
    f.process_line("req took 111 ms").unwrap();
    f.process_line("yyy yyy yyy yyy").unwrap();
    f.process_line("req took 333 sec").unwrap();
    let nearest = f.buffer.last().unwrap().nearest.as_ref().unwrap();
    assert_eq!(
        nearest.group_line_no, 2,
        "the scan goes past the first candidate to the closest group"
    );
}

#[test]
fn explain_first_diff_reports_a_surplus_token_when_one_line_is_a_prefix() {
    let mut f = explaining_folder();
    f.process_line("req took 111 ms").unwrap();
    f.process_line("req took 222 ms retrying").unwrap();
    let diff = f
        .buffer
        .last()
        .unwrap()
        .nearest
        .as_ref()
        .unwrap()
        .first_diff
        .as_ref()
        .unwrap();
    assert_eq!(diff.ours, "retrying");
    assert_eq!(diff.theirs, "");
    let normalized = &f.buffer.last().unwrap().first().normalized;
    assert_eq!(&normalized[diff.at..], "retrying");
}

#[test]
fn explain_off_emits_no_nearest_field() {
    let mut f = make_folder();
    f.process_line("req took 111 ms").unwrap();
    f.process_line("totally unrelated").unwrap();
    assert!(f.buffer[1].nearest.is_none());
    let group = f.buffer.pop().unwrap();
    let json = f
        .format_group_json(&group, f.masked_rollup(BTreeMap::new()))
        .unwrap();
    assert!(!json.contains("nearest"), "{json}");
}

#[test]
fn compact_json_lines_differing_in_one_field_value_fold_into_one_group() {
    let mut f = make_folder();
    for app in [
        "redis-sentinel",
        "redis-sentinel-wiki",
        "redis-sentinel-wiki-prod",
        "redis-sentinel-wiki-prod-eu",
    ] {
        f.process_line(&format!(
            r#"{{"application":"{app}","level":"info","msg":"Update successful"}}"#
        ))
        .unwrap();
    }
    assert_eq!(
        f.buffer.len(),
        1,
        "four records differing only in `application` must fold into one group, \
         whatever the length of the value: {:?}",
        f.buffer
            .iter()
            .map(|g| g.first().normalized.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn quoted_logfmt_lines_differing_in_one_field_value_fold_into_one_group() {
    let mut f = make_folder();
    for app in [
        "redis-sentinel",
        "redis-sentinel-wiki",
        "redis-sentinel-wiki-prod",
        "redis-sentinel-wiki-prod-eu",
    ] {
        f.process_line(&format!(r#"level=info app="{app}" msg="sync""#))
            .unwrap();
    }
    assert_eq!(f.buffer.len(), 1, "same for the quoted logfmt shape");
}

#[test]
fn compact_json_lines_differing_in_one_numeric_field_fold_into_one_group() {
    let mut f = make_folder();
    for ms in ["4", "82", "123", "4567"] {
        f.process_line(&format!(
            r#"{{"msg":"Reconciliation completed","diff_ms":{ms}}}"#
        ))
        .unwrap();
    }
    assert_eq!(
        f.buffer.len(),
        1,
        "a latency crossing 100 ms must not change how the line folds"
    );
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
    f.process_line("hello world").unwrap();
    assert_eq!(f.stats.patterns_detected, 0);
}

#[test]
fn process_line_counts_patterns_for_each_line() {
    let mut f = make_folder();
    f.process_line("request from 10.0.0.1").unwrap();
    f.process_line("request from 10.0.0.2").unwrap();
    assert_eq!(f.stats.total_lines, 2);
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
        thread_count: None,
        min_collapse: 3,
        ..Config::default()
    });
    f.process_line("2024-01-01 INFO hello 10.0.0.1").unwrap();
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
        "5 lines exceed min_collapse 3 and collapse, got: {joined}"
    );
}

#[test]
fn process_line_advances_position_counter() {
    let mut f = make_folder();
    assert_eq!(f.position_counter, 0);
    f.process_line("hello 10.0.0.1").unwrap();
    assert_eq!(f.position_counter, 1);
    f.process_line("world 10.0.0.2").unwrap();
    assert_eq!(f.position_counter, 2);
}

#[test]
fn finish_accumulates_output_lines() {
    let mut f = make_folder();
    f.buffer
        .push(PatternGroup::new(make_line("output line", vec![]), 1));
    assert_eq!(f.stats.output_lines, 0);
    f.finish().unwrap();
    assert!(
        f.stats.output_lines > 0,
        "output_lines should be incremented once the group is emitted, got 0"
    );
}

fn make_folder_json() -> PatternFolder {
    PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        output_format: OutputFormat::Json,
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
    assert_eq!(group.count(), 2);
    let json = f
        .format_group_json(&group, f.masked_rollup(BTreeMap::new()))
        .unwrap();
    assert_eq!(
        f.stats.collapsed_groups, 0,
        "count 2 is below min_collapse 3"
    );
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
    assert_eq!(group.count(), 3);
    let _ = f
        .format_group_json(&group, f.masked_rollup(BTreeMap::new()))
        .unwrap();
    assert_eq!(f.stats.collapsed_groups, 1);
    assert_eq!(
        f.stats.lines_saved, 0,
        "a collapsed group shows 3 lines (first, marker, last), so 3 members save 0"
    );

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
    let _ = f
        .format_group_json(&bigger, f.masked_rollup(BTreeMap::new()))
        .unwrap();
    assert_eq!(f.stats.collapsed_groups, 2);
    assert_eq!(f.stats.lines_saved, 2, "5 - 3, as text mode counts");
}

#[test]
fn format_group_json_essence_mode_saves_like_text_mode() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        output_format: OutputFormat::Json,
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
    let _ = f
        .format_group_json(&group, f.masked_rollup(BTreeMap::new()))
        .unwrap();
    assert_eq!(
        f.stats.collapsed_groups, 0,
        "essence_mode should skip collapsed_groups"
    );
    assert_eq!(
        f.stats.lines_saved, 2,
        "essence shows a group once: 3 members save count - 1, as text mode does"
    );
}

#[test]
fn format_group_json_id_increments() {
    let mut f = make_folder_json();
    let group = make_group("line", vec![vec![]]);
    let json0 = f
        .format_group_json(&group, f.masked_rollup(BTreeMap::new()))
        .unwrap();
    let json1 = f
        .format_group_json(&group, f.masked_rollup(BTreeMap::new()))
        .unwrap();
    let v0: serde_json::Value = serde_json::from_str(&json0).unwrap();
    let v1: serde_json::Value = serde_json::from_str(&json1).unwrap();
    assert_eq!(v0["id"], 0);
    assert_eq!(v1["id"], 1);
}

#[test]
fn format_group_json_token_types_sorted() {
    let mut f = make_folder_json();
    let group = make_group(
        "error <IP> <UUID>",
        vec![vec![
            Token::Uuid("aaa".into()),
            Token::IPv4("10.0.0.1".into()),
        ]],
    );
    let json = f
        .format_group_json(&group, f.masked_rollup(BTreeMap::new()))
        .unwrap();
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
    let json = f
        .format_group_json(&group, f.masked_rollup(BTreeMap::new()))
        .unwrap();
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
    let json = f
        .format_group_json(&group, f.masked_rollup(BTreeMap::new()))
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["type"], "group");
}

#[test]
fn a_group_record_opens_with_the_head_the_report_index_reads() {
    let mut f = make_folder_json();
    let group = make_group("line", vec![vec![], vec![]]);
    f.format_group_json(&group, f.masked_rollup(BTreeMap::new()))
        .unwrap();
    let json = f
        .format_group_json(&group, f.masked_rollup(BTreeMap::new()))
        .unwrap();
    assert_eq!(
        crate::overview::writer_group_head(&json),
        Some((1, 2)),
        "the report index fast path reads id and count from the record's first bytes"
    );
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
fn print_summary_json_ratio_is_saved_over_input_percent() {
    let mut f = make_folder_json();
    f.stats.total_lines = 100;
    f.stats.lines_saved = 80;
    f.stats.output_lines = 20;
    f.stats.collapsed_groups = 5;
    f.stats.patterns_detected = 50;
    f.stats.timestamps = 10;
    f.stats.ips = 5;
    f.stats.template_counts.record("synthetic", 100, None, None);
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
    assert!(
        (v["compression_ratio"].as_f64().unwrap() - 80.0).abs() < 0.01,
        "ratio = 80 saved / 100 input * 100"
    );
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
    f.json_groups_emitted = 2;
    f.json_groups_total = Some(5);
    f.json_omitted_by_fit = 3;
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
fn finish_top_n_derives_json_group_completeness() {
    let mut f = make_folder_json();
    for i in 0..4 {
        for _ in 0..(4 - i) {
            f.process_line(&format!(
                "{} event",
                ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"][i]
            ))
            .unwrap();
        }
    }
    let TopGroups {
        shown,
        total_groups: total,
        fit_truncated,
        ..
    } = f.finish_top_n(3, Some(2), false).unwrap();
    assert_eq!(total, 4);
    assert_eq!(shown.len(), 1, "a fit budget of 2 keeps budget - 1 groups");
    assert_eq!(fit_truncated, 2, "the other 2 of the top 3 are cut by fit");

    let mut buf = Vec::new();
    f.print_summary_json(&mut buf, std::time::Duration::ZERO)
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let groups = &value["completeness"]["groups"];
    assert_eq!(groups["emitted"], 1);
    assert_eq!(groups["total"]["value"], 4);
    assert_eq!(
        groups["omitted_by_top"]["value"], 1,
        "the fourth group is omitted by --top 3"
    );
    assert_eq!(groups["omitted_by_summary_cap"]["value"], 0);
    assert_eq!(groups["omitted_by_fit"]["value"], 2);
    assert!(!groups["complete"].as_bool().unwrap());
}

#[test]
fn summary_keeps_groups_that_share_a_template_but_not_an_anchor() {
    let mut f = make_folder();
    for (anchor, pos) in [(11_u64, 0), (22, 1)] {
        let mut line = make_line("svc <PATH> failed", vec![]);
        line.anchor = anchor;
        f.buffer.push(PatternGroup::new(line, pos));
    }
    let SummaryRows {
        display: shown,
        total_patterns: total,
        ..
    } = f.prepare_summary(None, None).unwrap();
    assert_eq!(
        total, 2,
        "the summary merge keys on template and anchor, as merge_converged does"
    );
    assert_eq!(shown.len(), 2);
}

#[test]
fn finish_top_n_coverage_counts_only_the_groups_shown_after_fit() {
    let mut f = make_folder();
    for i in 0..4 {
        for _ in 0..(4 - i) {
            f.process_line(&format!(
                "{} event",
                ["alpha", "bravo", "charlie", "delta"][i]
            ))
            .unwrap();
        }
    }
    let TopGroups {
        shown,
        coverage_pct: coverage,
        fit_truncated,
        ..
    } = f.finish_top_n(3, Some(2), false).unwrap();
    assert_eq!(shown.len(), 1);
    assert_eq!(fit_truncated, 2);
    assert_eq!(
        coverage, 40,
        "only the 4-line group is shown: 4 of 10 lines, not the 9 the top 3 hold"
    );
}

#[test]
fn finish_top_n_summary_cap_classifies_omissions() {
    let mut f = make_folder_json();
    for i in 0..3 {
        for _ in 0..(3 - i) {
            f.process_line(&format!(
                "{} event",
                ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"][i]
            ))
            .unwrap();
        }
    }
    let TopGroups {
        shown,
        total_groups: total,
        fit_truncated,
        ..
    } = f.finish_top_n(1, None, true).unwrap();
    assert_eq!((shown.len(), total, fit_truncated), (1, 3, 0));

    let mut buf = Vec::new();
    f.print_summary_json(&mut buf, std::time::Duration::ZERO)
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let groups = &value["completeness"]["groups"];
    assert_eq!(
        groups["omitted_by_summary_cap"]["value"], 2,
        "a cap from summary mode's default is not an explicit --top"
    );
    assert_eq!(groups["omitted_by_top"]["value"], 0);
}

#[test]
fn absorb_ingest_report_sets_input_completeness() {
    let mut f = make_folder_json();
    let report = crate::ingest::IngestReport {
        fail_pattern_matched: false,
        overlong_lines_skipped: 2,
        continuation_lines_to_add_back: 0,
        max_lines_reached: true,
        complete_input_hash: None,
    };
    f.absorb_ingest_report(&report, 1);

    let mut buf = Vec::new();
    f.print_summary_json(&mut buf, std::time::Duration::ZERO)
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let input = &value["completeness"]["input"];
    assert!(!input["complete"].as_bool().unwrap());
    assert_eq!(input["skipped_overlong_lines"]["value"], 2);
    assert_eq!(input["unprocessed_after_max_lines"]["kind"], "unknown");
    assert_eq!(input["failed_sources"]["kind"], "exact");
    assert_eq!(input["failed_sources"]["value"], 1);
}

#[test]
fn format_group_dispatch_text_mode_emits_no_json() {
    let mut f = make_folder();
    let group = make_group("hello", vec![vec![]]);
    let output = f.format_group_dispatch(&group).unwrap().expect_shown().text;
    assert!(
        serde_json::from_str::<serde_json::Value>(&output).is_err(),
        "text mode output should not be JSON"
    );
}

#[test]
fn format_group_dispatch_json_mode_emits_valid_json() {
    let mut f = make_folder_json();
    let group = make_group("hello", vec![vec![]]);
    let output = f.format_group_dispatch(&group).unwrap().expect_shown().text;
    let v: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(v["type"], "group");
}

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
    assert_eq!(f.stats.ips, 2, "IPv4 and IPv6 both count as ips");
    assert_eq!(f.stats.ports, 1, "ports have a counter of their own");
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
fn count_pattern_types_gives_every_token_type_its_own_counter() {
    let mut f = make_folder();
    f.count_pattern_types(&[
        Token::Number("42".into()),
        Token::QuotedString("hello".into()),
        Token::Name("foo-bar".into()),
        Token::BracketContext(vec!["ERROR".into()]),
        Token::KeyValuePair {
            key: "k".into(),
            value_type: crate::patterns::ValueType::Text,
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
    assert_eq!(f.stats.numbers, 1, "only Number counts as numbers");
    assert_eq!(f.stats.quoted_strings, 1);
    assert_eq!(f.stats.names, 1);
    assert_eq!(f.stats.brackets, 1);
    assert_eq!(f.stats.key_values, 1);
    assert_eq!(f.stats.log_modules, 1);
    assert_eq!(f.stats.structured, 1);
}

#[test]
fn count_pattern_types_leaves_every_counter_zero_without_tokens() {
    let mut f = make_folder();
    f.count_pattern_types(&[]);
    let s = &f.stats;
    assert_eq!(
        [
            s.timestamps,
            s.ips,
            s.ports,
            s.emails,
            s.kubernetes,
            s.hashes,
            s.fqdns,
            s.numbers,
            s.quoted_strings,
            s.names,
            s.brackets,
            s.key_values,
            s.log_modules,
            s.structured,
            s.uuids,
            s.pids,
            s.durations,
            s.cpu_quantities,
            s.http_status,
            s.sizes,
            s.paths,
            s.json,
            s.macs,
        ],
        [0; 23]
    );
}

#[test]
fn format_group_below_min_collapse_outputs_all_lines() {
    let mut f = make_folder();
    let group = make_group("error connecting", vec![vec![], vec![]]);
    let rollup = BTreeMap::new();
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "2 lines are below min_collapse 3 and print one by one"
    );
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
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
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
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
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
    let group = make_group(
        "normalized <IP>",
        vec![vec![Token::IPv4("10.0.0.1".into())]],
    );
    let rollup = BTreeMap::new();
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert_eq!(output, "normalized <IP>");
}

fn one_ingested_group(config: Config, lines: &[&str]) -> (PatternFolder, PatternGroup) {
    let mut f = PatternFolder::new(config);
    for l in lines {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1, "these lines fold into one group");
    let group = f.buffer.remove(0);
    (f, group)
}

fn sanitized(spec: &str) -> Option<crate::sanitize::Sanitizer> {
    crate::sanitize::Sanitizer::parse(&[spec.to_string()], false)
        .unwrap()
        .map(|z| z.with_test_key(7))
}

#[test]
fn a_credential_is_masked_exactly_once() {
    let raw = "Authorization: Bearer Lq7vRe2pXn";
    for spec in ["credential", "credential:pseudonym"] {
        let (mut f, group) = one_ingested_group(
            Config {
                thread_count: Some(1),
                min_collapse: 3,
                sanitize: sanitized(spec),
                ..Config::default()
            },
            &[raw],
        );
        let output = f
            .format_group(&group, &f.masked_rollup(BTreeMap::new()))
            .unwrap()
            .text;
        if spec == "credential" {
            assert_eq!(output, "Authorization: Bearer <SECRET>", "{spec}");
        } else {
            assert!(
                output.starts_with("Authorization: Bearer <SECRET:") && output.ends_with('>'),
                "{spec}: {output}"
            );
        }
        assert_eq!(output.matches("<SECRET").count(), 1, "{spec}: {output}");
        assert!(
            group.template().matches("<SECRET").count() <= 1
                && !group.template().contains("Lq7vRe2pXn"),
            "{spec}: {}",
            group.template()
        );
    }
}

#[test]
fn a_masked_line_is_normalized_after_masking() {
    let secrets = ["Kestrel42ab", "Plover17cd"];
    let first = format!(r#""[\" token="{}" "#, secrets[0]);
    let second = format!(r#""[\" token="{}" closed"#, secrets[1]);
    for spec in ["credential", "credential:pseudonym"] {
        let mut f = PatternFolder::new(Config {
            thread_count: Some(1),
            sanitize: sanitized(spec),
            ..Config::default()
        });
        f.process_line(&first).unwrap();
        let line = f.ingest(second.clone()).unwrap();
        let nearest = f.nearest_group(&line).expect("a group to compare with");
        assert!(nearest.first_diff.is_some(), "{spec}: {nearest:?}");
        let seen = format!(
            "{} | {} | {} | {nearest:?}",
            f.buffer[0].template(),
            line.normalized,
            line.original
        );
        f.process_line(&second).unwrap();
        let out = f.finish().unwrap().join("\n");
        let briefing: Vec<String> = f
            .build_briefing()
            .templates
            .shown
            .iter()
            .map(|e| e.template.clone())
            .collect();
        assert!(!briefing.is_empty(), "{spec}");
        for secret in secrets {
            assert!(!seen.contains(secret), "{spec}: {secret} in {seen}");
            assert!(!out.contains(secret), "{spec}: {secret} in {out}");
            assert!(
                briefing.iter().all(|t| !t.contains(secret)),
                "{spec}: {secret} in {briefing:?}"
            );
        }
    }
}

#[test]
fn format_group_pii_masking_masks_emails() {
    let (mut f, group) = one_ingested_group(
        Config {
            thread_count: Some(1),
            min_collapse: 3,
            sanitize: Some(crate::sanitize::Sanitizer::pii_alias()),
            ..Config::default()
        },
        &["user alice@test.com logged in"],
    );
    let rollup = BTreeMap::new();
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert!(
        output.contains("<EMAIL>"),
        "PII masking should replace email with <EMAIL>, got: {output}"
    );
    assert!(
        !output.contains("alice@test.com"),
        "email should be masked, got: {output}"
    );
}

#[test]
fn preflight_report_is_the_briefing_schema() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    });
    f.process_line("2024-01-01 10:00:00 error").unwrap();
    f.process_line("2024-01-01 10:00:01 error").unwrap();
    let _ = f.finish().unwrap();

    let mut buf = Vec::new();
    f.print_preflight_json(&mut buf).unwrap();
    let report: serde_json::Value = serde_json::from_str(&String::from_utf8(buf).unwrap()).unwrap();
    assert_eq!(report["lines"], 2);
    assert_eq!(report["source"], serde_json::Value::Null);
    assert!(report["span"].is_object());
    assert!(report["format"].is_object());
    assert!(report["levels"].is_object());
    assert!(report["templates"]["shown"].is_array());
    assert!(report["tokens"].is_array());
}

#[test]
fn build_briefing_source_is_bare_filename() {
    let mut f = make_folder();
    f.register_source("examples/distilled/kubelet.log".to_string());
    let briefing = f.build_briefing();
    assert_eq!(briefing.source.as_deref(), Some("kubelet.log"));
}

#[test]
fn build_briefing_source_none_for_stdin() {
    let f = make_folder();
    let briefing = f.build_briefing();
    assert_eq!(briefing.source, None);
}

#[test]
fn build_briefing_tokens_only_nonzero_classes() {
    let mut f = make_folder();
    f.stats.timestamps = 10;
    f.stats.ips = 5;
    let briefing = f.build_briefing();
    let classes: Vec<&str> = briefing.tokens.iter().map(|t| t.class).collect();
    assert!(classes.contains(&"timestamps"));
    assert!(classes.contains(&"ips"));
    assert!(!classes.contains(&"emails"), "emails is 0, must be absent");
}

#[test]
fn build_briefing_tokens_sorted_by_occurrences_descending() {
    let mut f = make_folder();
    f.stats.ips = 5;
    f.stats.timestamps = 10;
    let briefing = f.build_briefing();
    assert_eq!(briefing.tokens[0].class, "timestamps");
    assert_eq!(briefing.tokens[1].class, "ips");
}

#[test]
fn build_briefing_levels_aggregate_from_process_line() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    });
    f.process_line("E0909 13:07:09.181236 pod_workers.go] err")
        .unwrap();
    f.process_line("W0909 13:07:10.000000 transport.go] warn")
        .unwrap();
    f.process_line("plain line with no level shape").unwrap();
    let _ = f.finish().unwrap();
    let briefing = f.build_briefing();
    assert_eq!(briefing.levels.error, 1);
    assert_eq!(briefing.levels.warn, 1);
    assert_eq!(briefing.levels.lines_with_level, 2);
}

#[test]
fn build_briefing_sniffs_a_top_level_json_record_as_json() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    });
    f.process_line(r#"{"a":1}"#).unwrap();
    f.process_line("plain text line").unwrap();
    f.process_line("more plain text").unwrap();
    let _ = f.finish().unwrap();
    let briefing = f.build_briefing();
    assert_eq!(
        briefing.format.json, 1,
        "a top-level record has no Json token; the matched-delimiter test on the raw line finds it"
    );
    assert_eq!(briefing.format.plain, 2);
    assert_eq!(briefing.format.dominant, "plain");
    assert!(
        briefing.format.mixed,
        "1 of 3 json is not a clean single format"
    );
}

#[test]
fn build_briefing_span_from_timestamp_tokens() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    });
    f.process_line("2024-01-01 10:00:00 first").unwrap();
    f.process_line("no timestamp here").unwrap();
    f.process_line("2024-01-01 10:00:05 last").unwrap();
    let _ = f.finish().unwrap();
    let briefing = f.build_briefing();
    assert!(briefing.span.first.is_some());
    assert!(briefing.span.last.is_some());
    assert_ne!(briefing.span.first, briefing.span.last);
}

#[test]
fn build_briefing_template_counts_complete_after_finish() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    });
    for _ in 0..5 {
        f.process_line("repeated error <VARIES>").unwrap();
    }
    let _ = f.finish().unwrap();
    let briefing = f.build_briefing();
    let total: usize = briefing
        .templates
        .shown
        .iter()
        .map(|e| e.count)
        .collect::<Vec<_>>()
        .iter()
        .sum();
    assert!(total > 0);
    assert_eq!(f.stats.template_counts.total_members(), f.stats.total_lines);
}

#[test]
fn finish_top_n_records_omitted_templates_too() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        top_n: Some(1),
        ..Config::default()
    });
    for i in 0..3 {
        f.process_line(&format!("distinct template number {i}"))
            .unwrap();
    }
    let _ = f.finish_top_n(1, None, false).unwrap();
    assert_eq!(
        f.stats.template_counts.total_members(),
        f.stats.total_lines,
        "groups past --top are recorded too, so the template map stays complete"
    );
}

#[test]
fn print_stats_contains_briefing_header() {
    let f = make_folder();
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("--- lessence briefing:"));
}

#[test]
fn print_stats_stdin_source_in_header() {
    let f = make_folder();
    let mut buf = Vec::new();
    f.print_stats(&mut buf).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("--- lessence briefing: stdin ("));
}

#[test]
fn format_group_collapsed_lines_saved_count() {
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
    let _ = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert_eq!(f.stats.lines_saved, 2, "5 lines collapsed: saved = 5-3 = 2");
}

#[test]
fn format_group_collapsed_at_min_saves_zero() {
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
    let _ = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert_eq!(
        f.stats.lines_saved, 0,
        "3 lines at min_collapse: saved = 3-3 = 0"
    );
}

#[test]
fn format_group_essence_mode_lines_saved() {
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
    let _ = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert_eq!(
        f.stats.lines_saved, 1,
        "essence mode: 2 lines → saved = 2-1 = 1"
    );
}

#[test]
fn format_group_no_collapse_no_lines_saved() {
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
        ],
    );
    let rollup = BTreeMap::new();
    let _ = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert_eq!(f.stats.lines_saved, 0, "below min_collapse: no lines saved");
}

#[test]
fn format_group_collapsed_output_has_three_sections() {
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
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "collapsed output should have 3 lines (first + marker + last)"
    );
}

#[test]
fn finish_top_n_returns_sorted_by_count() {
    let mut f = make_folder();
    for _ in 0..5 {
        f.process_line("2024-01-01 ERROR timeout from 10.0.0.1")
            .unwrap();
    }
    for _ in 0..2 {
        f.process_line("GET /api/health HTTP/1.1 200 OK").unwrap();
    }
    f.process_line("unique log entry with no pattern match")
        .unwrap();

    let TopGroups {
        shown: top,
        total_groups,
        ..
    } = f.finish_top_n(2, None, false).unwrap();
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
    let TopGroups { total_groups, .. } = f.finish_top_n(10, None, false).unwrap();
    assert!(total_groups >= 1, "should have at least 1 group");
}

#[test]
fn finish_top_n_returns_every_group_when_n_exceeds_them() {
    let mut f = make_folder();
    f.process_line("only one line 10.0.0.1").unwrap();
    let TopGroups { shown: top, .. } = f.finish_top_n(100, None, false).unwrap();
    assert_eq!(top.len(), 1, "n = 100 over one group returns that group");
}

#[test]
fn finish_top_n_one_group_of_identical_lines_covers_100_percent() {
    let mut f = make_folder();
    for _ in 0..10 {
        f.process_line("2024-01-01 ERROR same 10.0.0.1").unwrap();
    }
    let TopGroups {
        coverage_pct: coverage,
        ..
    } = f.finish_top_n(10, None, false).unwrap();
    assert_eq!(coverage, 100, "single group covering all lines = 100%");
}

#[test]
fn finish_drains_buffer_chronologically() {
    let mut f = make_folder();
    f.process_line("2024-01-01 ERROR first unique line with 10.0.0.1")
        .unwrap();
    f.process_line("GET /api/v2/status HTTP/1.1 200 OK")
        .unwrap();
    let output = f.finish().unwrap();
    assert!(output.len() >= 2, "should output at least 2 groups");
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

#[test]
fn prepare_summary_merges_identical_groups() {
    let mut f = make_folder();
    f.buffer.push(PatternGroup::new(
        make_line("error <IP>", vec![Token::IPv4("10.0.0.1".into())]),
        1,
    ));
    f.buffer.push(PatternGroup::new(
        make_line("error <IP>", vec![Token::IPv4("10.0.0.2".into())]),
        2,
    ));
    let SummaryRows {
        display,
        total_patterns,
        ..
    } = f.prepare_summary(None, None).unwrap();
    assert_eq!(total_patterns, 1, "identical normalized text should merge");
    assert_eq!(display[0].0, 2, "merged count should be 1+1=2");
}

#[test]
fn prepare_summary_accumulates_counts() {
    let mut f = make_folder();
    let mut g1 = PatternGroup::new(make_line("err <IP>", vec![]), 1);
    g1.add_line(make_line("err <IP>", vec![]), 2);
    g1.add_line(make_line("err <IP>", vec![]), 3);
    let mut g2 = PatternGroup::new(make_line("err <IP>", vec![]), 10);
    g2.add_line(make_line("err <IP>", vec![]), 11);
    f.buffer.push(g1);
    f.buffer.push(g2);
    let SummaryRows { display, .. } = f.prepare_summary(None, None).unwrap();
    assert_eq!(display[0].0, 5, "merged count should be 3+2=5");
}

#[test]
fn account_summary_counts_printed_lines_and_shared_savings() {
    let display: Vec<(usize, String)> = [5, 3, 2, 1]
        .into_iter()
        .map(|c| (c, format!("entry {c}")))
        .collect();
    let mut f = make_folder();
    f.account_summary(&display);
    assert_eq!(f.stats.output_lines, 4, "one printed line per entry");
    assert_eq!(f.stats.collapsed_groups, 2, "5 and 3 reach min_collapse 3");
    assert_eq!(f.stats.lines_saved, 2, "(5-3) + (3-3)");

    let mut essence = PatternFolder::new(Config {
        thread_count: Some(1),
        essence_mode: true,
        ..Config::default()
    });
    essence.account_summary(&display);
    assert_eq!(essence.stats.collapsed_groups, 0);
    assert_eq!(essence.stats.lines_saved, 4 + 2 + 1, "every further member");
}

#[test]
fn prepare_summary_sorts_descending() {
    let mut f = make_folder();
    f.buffer
        .push(PatternGroup::new(make_line("small", vec![]), 1));
    let mut big = PatternGroup::new(make_line("big", vec![]), 10);
    for i in 0..4 {
        big.add_line(make_line("big", vec![]), 11 + i);
    }
    f.buffer.push(big);
    let SummaryRows { display, .. } = f.prepare_summary(None, None).unwrap();
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
    let SummaryRows {
        display,
        total_patterns: total,
        ..
    } = f.prepare_summary(Some(3), None).unwrap();
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
    let SummaryRows { display, .. } = f.prepare_summary(Some(0), None).unwrap();
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
    let SummaryRows {
        display,
        was_capped,
        ..
    } = f.prepare_summary(None, None).unwrap();
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
    let SummaryRows {
        display,
        fit_truncated,
        ..
    } = f.prepare_summary(None, Some(5)).unwrap();
    assert_eq!(display.len(), 4, "fit_budget=5 → show 4 (budget-1)");
    assert_eq!(fit_truncated, 16, "should report 16 remaining");
}

#[test]
fn prepare_summary_flushes_batch_buffer() {
    let mut f = PatternFolder::new(Config {
        thread_count: None,
        min_collapse: 3,
        ..Config::default()
    });
    f.process_line("2024-01-01 ERROR test 10.0.0.1").unwrap();
    assert!(!f.batch_buffer.is_empty(), "should have buffered line");
    let SummaryRows { display, .. } = f.prepare_summary(None, None).unwrap();
    assert!(!display.is_empty(), "should have processed batch");
}

#[test]
fn format_group_dispatch_computes_rollup_for_collapsible() {
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
    assert_eq!(group.count(), 4);
    let output = f.format_group_dispatch(&group).unwrap().expect_shown().text;
    assert!(
        output.contains("ipv4"),
        "a collapsible group gets the rollup marker, which names ipv4; the legacy marker does not, got: {output}"
    );
}

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
    let line = PatternFolder::format_summary_line(5, "abcdefghij", Some(10));
    assert_eq!(
        line, "[5x] abcdefghij",
        "avail of 20 or less keeps the full text"
    );
}

#[test]
fn summary_line_truncates_on_multibyte_char_boundary() {
    let rep = "\u{2122}".repeat(30);
    let line = PatternFolder::format_summary_line(5, &rep, Some(30));
    assert!(
        line.ends_with("..."),
        "avail 30 - 5 - 3 = 22 bytes lands inside a 3-byte char and snaps down: {line}"
    );
    assert!(line.len() <= 30, "should fit in width: len={}", line.len());
}

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

#[test]
fn build_briefing_format_exactly_90_pct_dominant_not_mixed() {
    let mut f = make_folder();
    f.stats.format_plain = 90;
    f.stats.format_json = 10;
    let briefing = f.build_briefing();
    assert!(!briefing.format.mixed, "exactly 90% dominant is not mixed");
}

#[test]
fn build_briefing_format_below_90_pct_dominant_is_mixed() {
    let mut f = make_folder();
    f.stats.format_plain = 89;
    f.stats.format_json = 11;
    let briefing = f.build_briefing();
    assert!(briefing.format.mixed, "89% dominant should be mixed");
}

#[test]
fn build_briefing_format_all_one_class_not_mixed() {
    let mut f = make_folder();
    f.stats.format_plain = 100;
    let briefing = f.build_briefing();
    assert!(!briefing.format.mixed);
    assert_eq!(briefing.format.dominant, "plain");
}

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
    f.count_pattern_types(&[Token::EmbeddedJson("{}".into())]);
    assert_eq!(f.stats.json, 1);
    assert_eq!(f.stats.paths, 0);
}

#[test]
fn count_pattern_types_number() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Number("42".into())]);
    assert_eq!(f.stats.numbers, 1);
}

#[test]
fn count_pattern_types_quoted_string() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::QuotedString("hello".into())]);
    assert_eq!(f.stats.quoted_strings, 1);
    assert_eq!(f.stats.numbers, 0);
}

#[test]
fn count_pattern_types_fqdn() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Fqdn("example.com".into())]);
    assert_eq!(f.stats.fqdns, 1);
    assert_eq!(f.stats.ips, 0, "FQDNs must not count as IPs");
    f.count_pattern_types(&[Token::Fqdn("example.org".into())]);
    assert_eq!(f.stats.fqdns, 2, "a second hit accumulates");
}

#[test]
fn count_pattern_types_name() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::Name("app".into())]);
    assert_eq!(f.stats.names, 1);
    assert_eq!(f.stats.numbers, 0);
    f.count_pattern_types(&[Token::Name("app".into())]);
    assert_eq!(f.stats.names, 2, "a second hit accumulates");
}

#[test]
fn count_pattern_types_bracket_context() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::BracketContext(vec!["error".into()])]);
    assert_eq!(f.stats.brackets, 1);
    assert_eq!(f.stats.numbers, 0);
}

#[test]
fn count_pattern_types_kv_pair() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::KeyValuePair {
        key: "k".into(),
        value_type: crate::patterns::ValueType::Text,
    }]);
    assert_eq!(f.stats.key_values, 1);
    assert_eq!(f.stats.numbers, 0);
}

#[test]
fn count_pattern_types_log_module() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::LogWithModule {
        module: "mod".into(),
        level: "error".into(),
    }]);
    assert_eq!(f.stats.log_modules, 1);
    assert_eq!(f.stats.numbers, 0);
}

#[test]
fn count_pattern_types_structured_message() {
    let mut f = make_folder();
    f.count_pattern_types(&[Token::StructuredMessage {
        component: "api".into(),
        level: "info".into(),
    }]);
    assert_eq!(f.stats.structured, 1);
    assert_eq!(f.stats.numbers, 0);
}

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

#[test]
fn prepare_summary_exactly_30_not_capped() {
    let mut f = make_folder();
    for i in 0..30 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("pattern {i}"), vec![]),
            i + 1,
        ));
    }
    let SummaryRows {
        display,
        was_capped,
        ..
    } = f.prepare_summary(None, None).unwrap();
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
    let SummaryRows {
        display,
        was_capped,
        ..
    } = f.prepare_summary(None, None).unwrap();
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
    let SummaryRows {
        display,
        was_capped,
        ..
    } = f.prepare_summary(Some(0), None).unwrap();
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
    let SummaryRows {
        display,
        fit_truncated,
        ..
    } = f.prepare_summary(None, Some(10)).unwrap();
    assert!(display.len() <= 10);
    assert!(fit_truncated > 0);
}

#[test]
fn finish_top_n_zero_input_lines() {
    let mut f = make_folder();
    f.stats.total_lines = 0;
    let TopGroups {
        coverage_pct: coverage,
        ..
    } = f.finish_top_n(10, None, false).unwrap();
    assert_eq!(coverage, 0);
}

#[test]
fn format_group_dispatch_below_min_collapse_no_rollup() {
    let mut f = make_folder();
    let group = make_group(
        "error <IP>",
        vec![
            vec![Token::IPv4("10.0.0.1".into())],
            vec![Token::IPv4("10.0.0.2".into())],
        ],
    );
    let output = f.format_group_dispatch(&group).unwrap().expect_shown().text;
    assert!(
        !output.contains("similar"),
        "count 2 is below min_collapse 3: the raw lines print: {output}"
    );
}

#[test]
fn format_group_dispatch_at_min_collapse_computes_rollup() {
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
    let output = f.format_group_dispatch(&group).unwrap().expect_shown().text;
    assert!(
        output.contains("ipv4"),
        "count 5 takes the rollup path, whose marker names ipv4; the legacy one does not: {output}"
    );
}

#[test]
fn prepare_summary_returns_nonempty_for_nonempty_buffer() {
    let mut f = make_folder();
    f.buffer
        .push(PatternGroup::new(make_line("error", vec![]), 1));
    let SummaryRows {
        display,
        total_patterns: total,
        was_capped,
        fit_truncated,
    } = f.prepare_summary(None, None).unwrap();
    assert!(
        !display.is_empty(),
        "should return entries for non-empty buffer"
    );
    assert_eq!(total, 1);
    assert!(!was_capped);
    assert_eq!(fit_truncated, 0);
}

#[test]
fn prepare_summary_budget_equal_to_group_count_truncates_nothing() {
    let mut f = make_folder();
    for i in 0..5 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    let SummaryRows {
        display,
        fit_truncated,
        ..
    } = f.prepare_summary(Some(0), Some(5)).unwrap();
    assert_eq!(display.len(), 5);
    assert_eq!(
        fit_truncated, 0,
        "5 groups equal the budget of 5, not more: nothing truncated"
    );
}

#[test]
fn prepare_summary_budget_below_group_count_keeps_budget_minus_one() {
    let mut f = make_folder();
    for i in 0..5 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    let SummaryRows {
        display,
        fit_truncated,
        ..
    } = f.prepare_summary(Some(0), Some(3)).unwrap();
    assert_eq!(display.len(), 2, "budget 3 shows budget - 1 = 2");
    assert_eq!(fit_truncated, 3, "5 - 2 = 3 remaining");
}

#[test]
fn prepare_summary_top_zero_fit_budget_one() {
    let mut f = make_folder();
    for i in 0..5 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    let SummaryRows {
        display,
        fit_truncated,
        ..
    } = f.prepare_summary(Some(0), Some(1)).unwrap();
    assert_eq!(display.len(), 0, "budget 1 shows budget - 1 = 0");
    assert_eq!(fit_truncated, 5, "all 5 remain");
}

#[test]
fn prepare_summary_fit_budget_exact() {
    let mut f = make_folder();
    for i in 0..5 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    let SummaryRows {
        display,
        fit_truncated,
        ..
    } = f.prepare_summary(None, Some(5)).unwrap();
    assert_eq!(display.len(), 5);
    assert_eq!(
        fit_truncated, 0,
        "5 groups equal the budget of 5, not more: nothing truncated"
    );
}

#[test]
fn summary_line_truncates_with_ellipsis_when_avail_exceeds_20() {
    let line = PatternFolder::format_summary_line(5, &"x".repeat(30), Some(30));
    assert!(
        line.ends_with("..."),
        "5 + 30 exceeds width 30 and avail 30 - 5 - 3 = 22 is over 20: {line}"
    );
    assert!(line.len() <= 30, "should fit in width: len={}", line.len());
}

#[test]
fn summary_line_prefix_plus_rep_exactly_at_width() {
    let line = PatternFolder::format_summary_line(5, &"x".repeat(25), Some(30));
    assert!(
        !line.ends_with("..."),
        "prefix 5 + text 25 equals width 30: no truncation: {line}"
    );
}

#[test]
fn summary_line_avail_of_exactly_20_does_not_truncate() {
    let long = "x".repeat(30);
    let line = PatternFolder::format_summary_line(5, &long, Some(28));
    assert!(
        !line.ends_with("..."),
        "avail 28 - 5 - 3 = 20 is not over 20: {line}"
    );
}

#[test]
fn summary_line_avail_21_does_truncate() {
    let long = "x".repeat(30);
    let line = PatternFolder::format_summary_line(5, &long, Some(29));
    assert!(
        line.ends_with("..."),
        "avail 29 - 5 - 3 = 21 is over 20: {line}"
    );
}

#[test]
fn finish_summary_accounts_only_the_rows_a_fit_budget_shows() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    for i in 0..10 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("pattern {i}"), vec![]),
            i + 1,
        ));
    }
    f.finish_summary(
        &SummaryRequest {
            top_n: None,
            fit_budget: Some(3),
            max_width: None,
        },
        &IngestReport::default(),
        0,
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(
        f.stats.output_lines, 2,
        "a fit budget of 3 over 10 patterns prints budget - 1 rows"
    );
}

#[test]
fn finish_top_n_flushes_batch_buffer() {
    let mut f = make_folder();
    f.stats.total_lines = 5;
    f.batch_buffer.push("error one".to_string());
    f.batch_buffer.push("error two".to_string());
    let TopGroups {
        shown: output,
        total_groups: total,
        ..
    } = f.finish_top_n(10, None, false).unwrap();
    assert!(f.batch_buffer.is_empty(), "batch should be flushed");
    assert_eq!(
        (total, output.len()),
        (2, 2),
        "both buffered lines were processed into groups"
    );
}

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
    let _ = f.finish_top_n(10, None, false).unwrap();
    assert!(
        f.stats.output_lines > before,
        "should increment output_lines"
    );
}

#[test]
fn finish_top_n_coverage_50_percent() {
    let mut f = make_folder();
    f.stats.total_lines = 100;
    let mut group = PatternGroup::new(make_line("error", vec![]), 1);
    for i in 1..50 {
        group.add_line(make_line("error", vec![]), i + 1);
    }
    f.buffer.push(group);
    let TopGroups {
        coverage_pct: coverage,
        ..
    } = f.finish_top_n(10, None, false).unwrap();
    assert_eq!(
        coverage, 50,
        "one 50-line group of 100 input lines = 50% coverage"
    );
}

#[test]
fn format_group_with_an_empty_rollup_writes_the_marker_for_a_group_without_rollup_entries() {
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
    let output = f
        .format_group(&group, &f.masked_rollup(empty_rollup.clone()))
        .unwrap()
        .text;
    assert!(
        output.contains("similar"),
        "an empty rollup takes format_marker_for_a_group_without_rollup_entries: {output}"
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
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert!(
        output.contains("ipv4"),
        "a non-empty rollup takes the compact marker path, which names ipv4: {output}"
    );
}

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
    );
    let rollup = BTreeMap::new();
    f.format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap();
    assert_eq!(f.stats.lines_saved, 2, "5 lines collapsed saves 5 - 3 = 2");
}

#[test]
fn format_group_pii_masking_only_in_non_essence() {
    let (mut f, group) = one_ingested_group(
        Config {
            thread_count: Some(1),
            min_collapse: 3,
            sanitize: Some(crate::sanitize::Sanitizer::pii_alias()),
            essence_mode: false,
            ..Config::default()
        },
        &["user test@example.com logged in"; 3],
    );
    let rollup = BTreeMap::new();
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert!(
        output.contains("user <EMAIL> logged in") && !output.contains("test@example.com"),
        "PII should be masked in non-essence mode: {output}"
    );
}

#[test]
fn format_group_single_line_no_last() {
    let mut f = make_folder();
    let group = make_group("single line", vec![vec![]]);
    let rollup = BTreeMap::new();
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
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
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert!(
        output.lines().count() >= 2,
        "two lines should show both: {output}"
    );
}

#[test]
fn format_group_essence_identical_suppresses_last() {
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
            vec![Token::IPv4("10.0.0.3".into())],
            vec![Token::IPv4("10.0.0.4".into())],
        ],
    );
    let rollup = BTreeMap::new();
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    let line_count = output.lines().count();
    assert!(
        line_count <= 2,
        "essence mode with identical first and last template suppresses the last line: {output}"
    );
}

#[test]
fn build_briefing_tokens_count_of_one_is_shown() {
    let mut f = make_folder();
    f.stats.hashes = 1;
    let briefing = f.build_briefing();
    assert!(briefing.tokens.iter().any(|t| t.class == "hashes"));
}

#[test]
fn build_briefing_tokens_count_of_zero_is_absent() {
    let f = make_folder();
    let briefing = f.build_briefing();
    assert!(briefing.tokens.is_empty());
}

#[test]
fn format_group_rollup_path_vs_legacy_path_output_differs() {
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
    let output_with_rollup = f1
        .format_group(&group, &f1.masked_rollup(rollup.clone()))
        .unwrap()
        .text;

    let mut f2 = make_folder();
    let empty_rollup = BTreeMap::new();
    let output_legacy = f2
        .format_group(&group, &f2.masked_rollup(empty_rollup.clone()))
        .unwrap()
        .text;

    assert_ne!(
        output_with_rollup, output_legacy,
        "the rollup marker names types; the legacy one says similar and varying"
    );
}

#[test]
fn format_group_collapsed_marker_exact_count_legacy() {
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
    let output = f
        .format_group(&group, &f.masked_rollup(empty_rollup.clone()))
        .unwrap()
        .text;
    assert!(
        output.contains("+3 similar"),
        "5 lines with empty rollup: marker should say +3 similar (5-2=3), got: {output}"
    );
}

#[test]
fn format_group_collapsed_marker_exact_count_rollup() {
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
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert!(
        output.contains("+4 similar"),
        "6 lines with rollup: marker should say +4 similar (6-2=4), got: {output}"
    );
    assert_eq!(f.stats.lines_saved, 3, "6 lines collapsed: saved = 6-3 = 3");
}

#[test]
fn format_group_pii_plus_essence_masks_the_template() {
    let (mut f, group) = one_ingested_group(
        Config {
            thread_count: Some(1),
            min_collapse: 3,
            sanitize: Some(crate::sanitize::Sanitizer::pii_alias()),
            essence_mode: true,
            ..Config::default()
        },
        &["user alice@test.com logged in"],
    );
    let rollup = BTreeMap::new();
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert_eq!(output, "user <EMAIL> logged in");
}

#[test]
fn format_group_single_line_group_has_no_last_line() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 2,
        ..Config::default()
    });
    let group = make_group("single", vec![vec![]]);
    let rollup = BTreeMap::new();
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert_eq!(
        output.lines().count(),
        1,
        "a one-line group has no last line to show, even at min_collapse 2: {output}"
    );
}

#[test]
fn format_group_count_4_collapsed_has_last_line() {
    let mut f = make_folder();
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
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    let line_count = output.lines().count();
    assert!(
        line_count >= 3,
        "count=4 collapsed should have first+marker+last ({line_count} lines): {output}"
    );
    assert!(
        output.contains("server D"),
        "last line should appear in collapsed output: {output}"
    );
}

#[test]
fn format_group_non_essence_different_first_last_shows_both() {
    let mut f = make_folder();
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
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert!(
        output.contains("error connecting to C"),
        "non-essence collapsed with different first/last should show last: {output}"
    );
}

#[test]
fn format_group_non_essence_same_first_last_still_shows_last() {
    let mut f = make_folder();
    let line1 = make_line("identical text", vec![]);
    let line2 = make_line("identical text", vec![]);
    let line3 = make_line("identical text", vec![]);
    let mut group = PatternGroup::new(line1, 1);
    group.add_line(line2, 2);
    group.add_line(line3, 3);
    let rollup = BTreeMap::new();
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    let line_count = output.lines().count();
    assert_eq!(
        line_count, 3,
        "non-essence collapsed with same first/last should still show 3 lines: {output}"
    );
}

#[test]
fn format_group_pii_masks_last_line_in_non_essence() {
    let (mut f, group) = one_ingested_group(
        Config {
            thread_count: Some(1),
            min_collapse: 3,
            sanitize: Some(crate::sanitize::Sanitizer::pii_alias()),
            essence_mode: false,
            ..Config::default()
        },
        &[
            "user first@test.com logged in",
            "user second@test.com logged in",
            "user last@test.com logged in",
        ],
    );
    let rollup = BTreeMap::new();
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert!(
        !output.contains("test.com") && output.ends_with("user <EMAIL> logged in"),
        "last line email should be masked with PII in non-essence mode: {output}"
    );
}

#[test]
fn format_group_pii_masks_the_essence_line() {
    let (mut f, group) = one_ingested_group(
        Config {
            thread_count: Some(1),
            min_collapse: 2,
            sanitize: Some(crate::sanitize::Sanitizer::pii_alias()),
            essence_mode: true,
            ..Config::default()
        },
        &[
            "user alice@test.com logged in",
            "user bob@test.com logged in",
        ],
    );
    let rollup = BTreeMap::new();
    let output = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert_eq!(
        output, "user <EMAIL> logged in",
        "essence shows the group once, as its shared template, masked"
    );
}

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
    let _ = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
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
    let _ = f
        .format_group(&group, &f.masked_rollup(rollup.clone()))
        .unwrap()
        .text;
    assert_eq!(
        f.stats.lines_saved, 1,
        "essence mode count=2 should save 1 line"
    );
}

#[test]
fn finish_summary_flushes_batch_buffer() {
    let mut f = make_folder();
    f.stats.total_lines = 5;
    f.batch_buffer
        .push("2024-01-01 ERROR one 10.0.0.1".to_string());
    f.batch_buffer
        .push("2024-01-01 ERROR two 10.0.0.2".to_string());
    assert!(!f.batch_buffer.is_empty());
    let result = f.finish_summary(
        &SummaryRequest {
            top_n: None,
            fit_budget: None,
            max_width: None,
        },
        &IngestReport::default(),
        0,
        &mut Vec::new(),
        &mut Vec::new(),
    );
    assert!(result.is_ok());
    assert!(
        f.batch_buffer.is_empty(),
        "finish_summary should flush batch_buffer via prepare_summary"
    );
}

#[test]
fn prepare_summary_fit_truncated_zero_when_under_budget() {
    let mut f = make_folder();
    for i in 0..3 {
        f.buffer.push(PatternGroup::new(
            make_line(&format!("p{i}"), vec![]),
            i + 1,
        ));
    }
    let SummaryRows { fit_truncated, .. } = f.prepare_summary(None, Some(10)).unwrap();
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
    let SummaryRows { fit_truncated, .. } = f.prepare_summary(None, Some(5)).unwrap();
    assert_eq!(
        fit_truncated, 6,
        "budget 5 shows budget - 1 = 4 of 10 patterns"
    );
}

#[test]
fn finish_top_n_zero_total_lines_zero_coverage() {
    let mut f = make_folder();
    f.stats.total_lines = 0;
    f.buffer
        .push(PatternGroup::new(make_line("error", vec![]), 1));
    let TopGroups {
        coverage_pct: coverage,
        ..
    } = f.finish_top_n(10, None, false).unwrap();
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
    let TopGroups {
        coverage_pct: coverage,
        ..
    } = f.finish_top_n(10, None, false).unwrap();
    assert_eq!(coverage, 100, "10/10 lines should be 100% coverage");
}

#[test]
fn build_stats_json_serializes_to_writer() {
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

#[test]
fn json_records_mask_pii_when_enabled() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        sanitize: Some(crate::sanitize::Sanitizer::pii_alias()),
        output_format: OutputFormat::Json,
        ..Config::default()
    });
    for who in ["alice", "bob", "carol", "dave"] {
        f.process_line(&format!("user {who}@example.com login failed"))
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
        sanitize: Some(crate::sanitize::Sanitizer::pii_alias()),
        ..Config::default()
    });
    for who in ["alice", "bob", "eve", "alice", "bob", "eve"] {
        f.process_line(&format!("user {who}@example.com login failed"))
            .unwrap();
    }
    let out = f.finish().unwrap().join("\n");
    assert!(
        !out.contains("example.com"),
        "3 distinct emails are within the inline sample threshold, so the marker shows samples, masked: {out}"
    );
}
#[test]
fn summary_masks_pii_when_enabled() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        sanitize: Some(crate::sanitize::Sanitizer::pii_alias()),
        ..Config::default()
    });
    for who in ["alice", "bob", "carol"] {
        f.process_line(&format!("user {who}@example.com login failed"))
            .unwrap();
    }
    let SummaryRows { display, .. } = f.prepare_summary(None, None).unwrap();
    assert!(!display.is_empty());
    for (_, representative) in &display {
        assert!(
            !representative.contains("example.com"),
            "raw email in summary line: {representative}"
        );
    }
}

#[test]
fn fold_metrics_agree_between_text_and_json_modes() {
    let run = |format: OutputFormat| {
        let mut f = PatternFolder::new(Config {
            thread_count: Some(1),
            output_format: format,
            ..Config::default()
        });
        for i in 0..20 {
            f.process_line(&format!("error connecting to 10.0.0.{i} timeout"))
                .unwrap();
        }
        let _ = f.finish().unwrap();
        let s = f.build_stats_json(Duration::from_millis(1));
        (
            s.lines_saved,
            s.collapsed_groups,
            s.compression_ratio.to_bits(),
        )
    };
    assert_eq!(
        run(OutputFormat::Text),
        run(OutputFormat::Json),
        "bit-exact ratio: both modes run one computation"
    );
}
#[test]
fn summary_record_and_stats_json_report_identical_metrics() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        output_format: OutputFormat::Json,
        ..Config::default()
    });
    for i in 0..20 {
        f.process_line(&format!("error connecting to 10.0.0.{i} timeout"))
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
        sanitize: Some(crate::sanitize::Sanitizer::pii_alias()),
        output_format: OutputFormat::Markdown,
        ..Config::default()
    });
    for who in ["alice", "bob", "eve", "mallory"] {
        f.process_line(&format!("user {who}@example.com login failed"))
            .unwrap();
    }
    let entries = f.finish_markdown().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "markdown mode returns the entries the document is built from"
    );
    let mut buf = Vec::new();
    f.emit_markdown(&entries, &mut buf).unwrap();
    let doc = String::from_utf8(buf).unwrap();
    assert!(!doc.contains("example.com"), "raw email in markdown: {doc}");
    let stats = f.get_stats();
    let expected = (stats.lines_saved as f64 / stats.total_lines as f64) * 100.0;
    assert!(
        doc.contains(&format!("Compression ratio**: {expected:.1}%")),
        "markdown ratio must use the shared fold metric: {doc}"
    );
}

#[test]
fn new_sizes_thread_pool_from_explicit_thread_count() {
    let f = PatternFolder::new(Config {
        thread_count: Some(3),
        ..Config::default()
    });
    let LineDetection::SizedPool(pool) = &f.detection else {
        panic!("thread_count=Some(3) must build a dedicated pool");
    };
    let cores = std::thread::available_parallelism().map_or(8, usize::from);
    assert_eq!(
        pool.current_num_threads(),
        3.min(cores),
        "--threads 3 must size the pool to exactly 3 threads (capped at available parallelism)"
    );
}

#[test]
fn new_caps_thread_pool_at_available_parallelism() {
    let f = PatternFolder::new(Config {
        thread_count: Some(999_999),
        ..Config::default()
    });
    let LineDetection::SizedPool(pool) = &f.detection else {
        panic!("huge thread_count must still build a (capped) pool");
    };
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
        matches!(f.detection, LineDetection::Inline),
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
        matches!(f.detection, LineDetection::GlobalPool),
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
        for line in &lines {
            f.process_line(line).unwrap();
        }
        f.finish().unwrap()
    };
    assert_eq!(
        run(Some(2)),
        run(None),
        "a sized pool must fold identically to the default pool"
    );
}

#[test]
fn variation_types_different_ips() {
    let f = make_folder();
    let first = vec![Token::IPv4("10.0.0.1".to_string())];
    let last = vec![Token::IPv4("10.0.0.2".to_string())];
    assert_eq!(f.summarize_variation_types(&first, &last), vec!["IP"]);
}

#[test]
fn variation_types_same_tokens_no_variation() {
    let f = make_folder();
    let tokens = vec![Token::IPv4("10.0.0.1".to_string())];
    assert!(
        f.summarize_variation_types(&tokens, &tokens).is_empty(),
        "Same tokens should produce no variation"
    );
}

#[test]
fn variation_types_non_essence_includes_timestamps() {
    let f = make_folder();
    let first = vec![Token::Timestamp("2025-01-01T00:00:00Z".to_string())];
    let last = vec![Token::Timestamp("2025-01-02T00:00:00Z".to_string())];
    assert_eq!(
        f.summarize_variation_types(&first, &last),
        vec!["timestamp"]
    );
}

#[test]
fn variation_types_multiple_types_sorted() {
    let f = make_folder();
    let first = vec![
        Token::IPv4("10.0.0.1".to_string()),
        Token::Uuid("aaa".to_string()),
    ];
    let last = vec![
        Token::IPv4("10.0.0.2".to_string()),
        Token::Uuid("bbb".to_string()),
    ];
    assert_eq!(
        f.summarize_variation_types(&first, &last),
        vec!["IP", "UUID"]
    );
}

#[test]
fn variation_types_ignore_payloads_of_presence_only_kinds() {
    let f = make_folder();
    let first = vec![Token::StructuredMessage {
        component: "api".to_string(),
        level: "error".to_string(),
    }];
    let last = vec![Token::StructuredMessage {
        component: "worker".to_string(),
        level: "warn".to_string(),
    }];
    assert!(
        f.summarize_variation_types(&first, &last).is_empty(),
        "presence-only kinds must not vary by payload"
    );
}

#[test]
fn command_options_keep_operations_apart_and_trace_variation_truthful() {
    let mut f = make_folder();
    for worker in ["cedar", "birch", "cedar"] {
        for (operation, option, argument) in [
            ("inspect", "-t", "aabbccddeeff00112233445566778899aabbccdd"),
            (
                "restore",
                "--force",
                "11223344556677889900aabbccddeeff11223344",
            ),
            (
                "compare",
                "--names",
                "aabbccddeeff00112233445566778899aabbccdd..11223344556677889900aabbccddeeff11223344",
            ),
        ] {
            f.process_line(&format!(
                r#"[pod/repo-worker-6789bcdf7-x2z4w/worker] {{"args":"[depot {operation} {option} {argument}]","dir":"/tmp/repo/74ac195d-3097-4be6-b28c-c95067e201ab","level":"info","msg":"Trace","operation_name":"exec depot","time":"2026-09-16T06:01:00Z","time_ms":4.5,"worker":"{worker}"}}"#
            )).unwrap();
        }
    }
    assert_eq!(f.buffer.len(), 3);
    for group in &f.buffer {
        assert_eq!(group.count(), 3);
        let template = group.template();
        assert!(
            template.contains(r#""operation_name":"exec depot""#),
            "{template}"
        );
        assert!(template.contains(r#""worker":<VARIES>"#), "{template}");
        let rollup = f.rollup_computer.compute(group);
        assert_eq!(rollup[VARIES].samples, [r#""cedar""#, r#""birch""#]);
        assert_eq!(rollup[VARIES].counts, Some(vec![2, 1]));
        assert!(
            rollup["PATH"]
                .samples
                .iter()
                .all(|value| !value.starts_with('-'))
        );
    }
}

#[test]
fn quoted_command_arguments_vary_without_erasing_option_names() {
    let mut f = make_folder();
    for option in ["--mode", "--scope"] {
        for value in ["alpha", "beta", "alpha"] {
            f.process_line(&format!(
                r#"{{"args":"[depot {option} {value}]","context":"stable","level":"info","msg":"Trace","operation_name":"exec depot"}}"#
            ))
            .unwrap();
        }
    }
    assert_eq!(f.buffer.len(), 2);
    for (group, option) in f.buffer.iter().zip(["--mode", "--scope"]) {
        assert_eq!(
            group.template(),
            format!(
                r#"{{"args":"[depot {option} <VARIES>]","context":"stable","level":"info","msg":"Trace","operation_name":"exec depot"}}"#
            )
        );
        let rollup = f.rollup_computer.compute(group);
        assert_eq!(rollup[VARIES].samples, ["alpha", "beta"]);
        assert_eq!(rollup[VARIES].counts, Some(vec![2, 1]));
    }
    assert_eq!(unit_spans(r#"controller="crt configmap" done"#).len(), 2);
}

#[test]
fn repeated_option_names_survive_arguments_of_different_lengths() {
    let first = r#"{"msg":"depot --mode alpha extra --mode beta","note":"steady"}"#;
    let mut template = first.to_string();
    for member in [
        r#"{"msg":"depot --mode alpha --mode gamma","note":"steady"}"#,
        r#"{"msg":"depot --mode alpha extra --mode delta","note":"steady"}"#,
    ] {
        let edits = template_edits(&template, member).unwrap();
        apply_edits(&mut template, &edits);
        assert_eq!(template.matches("--mode").count(), 2, "{template}");
        assert!(template.ends_with(r#"","note":"steady"}"#), "{template}");
    }
}

#[test]
fn a_placeholder_against_a_plain_word_varies_too() {
    let mut f = make_folder();
    for l in [
        "[    5.450000] creating proc entry for 10.0.0.1",
        "[    5.450000] creating proc entry for board",
        "[    5.460000] creating proc entry for IsDefault",
    ] {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    assert_eq!(
        f.buffer[0].template(),
        "<TIMESTAMP> creating proc entry for <VARIES>",
        "the founder's placeholder varies against members that hold plain words there"
    );
    let r = f.rollup_computer.compute(&f.buffer[0]);
    assert_eq!(r[VARIES].counts, Some(vec![1, 1, 1]));
    assert!(r[VARIES].samples.contains(&"<IP>".to_string()));
}

#[test]
fn a_shared_field_name_stays_in_front_of_varies() {
    let mut f = make_folder();
    for l in [
        "time=2026-08-26T12:46:24.203681666Z level=info msg=Connecting subsys=hubble-relay address=10.59.151.22:4244 tls=true peer=lupah/ik",
        "time=2026-08-26T12:46:24.203767141Z level=info msg=Connected subsys=hubble-relay address=10.59.151.22:4244 tls=true peer=lupah/ik",
        "time=2026-08-26T12:46:25.203767141Z level=info msg=Connected subsys=hubble-relay address=10.59.151.22:4244 tls=true peer=lupah/ik",
    ] {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    assert!(
        f.buffer[0].template().contains(" msg=<VARIES> subsys="),
        "the shared key msg= stays in front of the slot: {}",
        f.buffer[0].template()
    );
    let r = f.rollup_computer.compute(&f.buffer[0]);
    assert_eq!(r[VARIES].samples, vec!["Connected", "Connecting"]);
    assert_eq!(r[VARIES].counts, Some(vec![2, 1]));

    let mut f = make_folder();
    for host in ["icip", "gifob", "ugiz"] {
        f.process_line(&format!(
            r#"{{"level":"info","ts":1787965945.3273559,"logger":"controllers.ClusterPolicy","msg":"GPU workload configuration","NodeName":"{host}","GpuWorkloadConfig":"container"}}"#
        ))
        .unwrap();
    }
    assert_eq!(
        f.buffer.len(),
        1,
        "one differing field in a spaceless record folds"
    );
    assert!(
        f.buffer[0].template().contains(r#""NodeName":<VARIES>,"#),
        "{}",
        f.buffer[0].template()
    );
}

#[test]
fn a_member_with_fewer_words_marks_the_words_it_lacks() {
    assert_eq!(
        spans_of("alpha beta gamma delta", "alpha gamma delta"),
        vec![(6, 4)],
        "the word the member lacks becomes a slot"
    );
    assert_eq!(
        spans_of("alpha beta gamma", "alpha zeta gamma extra"),
        vec![(6, 4), (16, 0)],
        "a word only the member has opens a slot of its own after the last unit"
    );
    let mut f = make_folder();
    for l in [
        "2026-08-29T01:12:10Z INF | request served 8 |",
        "2026-08-29T01:12:11Z INF | request served |",
        "2026-08-29T01:12:12Z INF | request served |",
    ] {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    assert_eq!(
        f.buffer[0].template(),
        "<TIMESTAMP> INF | request served <VARIES> |"
    );
    let r = f.rollup_computer.compute(&f.buffer[0]);
    assert_eq!(
        r[VARIES].samples,
        vec!["∅", "8"],
        "the members without the word count as absent"
    );
    assert_eq!(r[VARIES].counts, Some(vec![2, 1]));
}

#[test]
fn a_kept_prefix_widens_for_a_member_that_lacks_it() {
    let mut f = make_folder();
    for l in [
        "job 10:30:01 cleaning registries for queue high",
        "job 10:31:02 cleaning registries for queue high",
        "job 11:08:43 cleaning registries for queue high",
    ] {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    assert_eq!(
        f.buffer[0].template(),
        "job <VARIES> cleaning registries for queue high",
        "the kept prefix 10: widens for the member that lacks it"
    );
    let r = f.rollup_computer.compute(&f.buffer[0]);
    assert_eq!(r[VARIES].samples, vec!["10:30:01", "10:31:02", "11:08:43"]);
}

#[test]
fn kept_affixes_keep_only_what_the_member_shares() {
    assert_eq!(kept_affixes("msg=", "", "msg=Connected"), (4, 0));
    assert_eq!(kept_affixes("10:", "", "11:08:43"), (0, 0));
    assert_eq!(
        kept_affixes("k8s:app.kubernetes.io/component=", "", "k8s:app=rook"),
        (4, 0),
        "cut back to the last delimiter the two share"
    );
    assert_eq!(kept_affixes("a=b:", ")", "a=c)"), (2, 1));
    assert_eq!(kept_affixes("slot[", "]", "slot[2]"), (5, 1));
    assert_eq!(kept_affixes("slot[", "]", "slot[2"), (5, 0));
    assert_eq!(
        kept_affixes("key=", "", "key="),
        (0, 0),
        "a member that is the prefix alone leaves no byte for the slot"
    );
}

#[test]
fn a_slot_against_a_member_of_another_length_is_rechecked_in_its_gap() {
    assert_eq!(
        spans_of("a msg=<VARIES> c", "a msg=z c d"),
        vec![(16, 0)],
        "a word past the template's last opens a slot there"
    );
    assert!(spans_of("a msg=<VARIES> c", "a msg=y z c").is_empty());
    assert_eq!(
        spans_of("a msg=<VARIES> c", "a other=y c d"),
        vec![(2, 12), (16, 0)]
    );
    assert_eq!(
        spans_of("a msg=<VARIES> c d", "a c d"),
        vec![(2, 12)],
        "with nothing in the gap the slot keeps nothing"
    );
    assert_eq!(
        spans_of("a k=<VARIES> j=<VARIES> c", "a k=1 c"),
        vec![(13, 10)],
        "a slot whose affix a member unit carries anchors there"
    );
    assert!(
        spans_of("a x <VARIES> k=<VARIES> c", "a x y z k=1 c").is_empty(),
        "the rest of the gap is read on either side of the anchored slot"
    );
    assert_eq!(
        spans_of("a k=<VARIES> j=<VARIES> c", "a x=1 y=2 z=3 c"),
        vec![(2, 10), (13, 10)],
        "with no anchor, which units pair is unknown"
    );
    assert!(
        spans_of("a <VARIES> c", "a b b c").is_empty(),
        "a slot with nothing kept has nothing to recheck"
    );
}

fn marked(template: &str, member: &str) -> String {
    let mut t = template.to_string();
    apply_edits(&mut t, &template_edits(template, member).unwrap());
    t
}

#[test]
fn a_slot_keeps_both_quotes_of_a_pair_or_neither() {
    assert_eq!(
        marked(
            r#"pull image="cache:8.2.1" node=n1"#,
            r#"pull image="cache:8.2.7" node=n1"#
        ),
        r#"pull image="cache:<VARIES>" node=n1"#,
        "the closing quote stays out of the slot, paired with the opening one"
    );
    assert_eq!(
        marked(
            r#"x msg="Failed to sync the pod now" y"#,
            r#"x msg="Passed to sync the pod now" y"#
        ),
        r#"x msg="<VARIES> to sync the pod now" y"#,
        "a quoted sentence's opening quote stays beside the slot"
    );
    assert_eq!(
        marked(
            r#"x msg="sync failed for [alpha]" y"#,
            r#"x msg="sync failed for [beta]" y"#
        ),
        r#"x msg="sync failed for [<VARIES>]" y"#,
        "and its closing quote, with the closers before it"
    );
    assert_eq!(
        marked(
            r#"x err="failed for pod=a1(u)\"" pod="n/p""#,
            r#"x err="failed for pod=b2(u)\"" pod="n/p""#
        ),
        r#"x err="failed for pod=<VARIES>)\"" pod="n/p""#,
        "a backslash travels with the quote it escapes"
    );
    assert_eq!(
        marked(r#"x key="v1" y"#, r#"x key="v2" y"#),
        "x key=<VARIES> y",
        "a whole quoted value is covered whole"
    );
    assert_eq!(
        marked(r#"x image="cache:<VARIES>" y"#, r#"x image="other" y"#),
        r#"x image="<VARIES>" y"#,
        "a slot that widens keeps its quotes paired too"
    );
    assert_eq!(
        balance_quotes("[a]\"", "[b]", 1, 0),
        (1, 0),
        "a unit whose own quote has no partner, against a member without it, is left as it was"
    );
    assert!(!unpaired_quote(r#"a\"b\""#, 0, 6));
    assert!(unpaired_quote(r#"a\"b""#, 0, 5));
}

#[test]
fn a_member_of_another_length_is_counted_by_its_value_not_as_absent() {
    let r = rollup_of(&[
        "sync worker finished copying layer img.v1 into the local cache store ok",
        "sync worker finished copying layer img.v2 into the local cache store ok",
        "sync worker finished copying layer img.v3 img.v4 into the local cache store ok",
    ]);
    assert_eq!(
        r[VARIES].samples,
        vec!["img.v1", "img.v2", "img.v3 img.v4"],
        "the member with two units in the slot is counted by its value, not as absent"
    );
    assert_eq!(r[VARIES].counts, Some(vec![1, 1, 1]));
}

#[test]
fn a_slot_in_a_gap_is_read_the_way_the_join_reads_it() {
    let rc = RollupComputer::with_defaults();
    let counted = |template: &str, lines: &[&str]| {
        let lines: Vec<LogLine> = lines.iter().map(|l| make_line(l, vec![])).collect();
        let mut varies = SlotCounts::new();
        rc.accumulate_varies(&lines, template, &mut varies);
        let out: Vec<Vec<(String, usize)>> = varies
            .into_iter()
            .map(|slot| {
                let mut slot: Vec<(String, usize)> = slot.counts.into_iter().collect();
                slot.sort();
                slot
            })
            .collect();
        out
    };
    let v = |pairs: &[(&str, usize)]| -> Vec<Vec<(String, usize)>> {
        pairs
            .iter()
            .map(|&(s, n)| vec![(s.to_string(), n)])
            .collect()
    };
    assert_eq!(
        counted("a <VARIES> <VARIES> c", &["a x y z c"]),
        v(&[("x", 1), ("y z", 1)]),
        "a run of bare slots reads the member in order, the last taking the rest"
    );
    assert_eq!(
        counted("a <VARIES> <VARIES> c", &["a x c"]),
        v(&[("x", 1), ("∅", 1)])
    );
    assert_eq!(
        counted("a <VARIES> <VARIES> c", &["a c"]),
        v(&[("∅", 1), ("∅", 1)]),
        "only a true absence is counted as absent"
    );
    assert_eq!(
        counted("a k=<VARIES> j=<VARIES> c", &["a k=1 c"]),
        v(&[("1", 1), ("∅", 1)]),
        "a slot whose kept affix a member unit carries is anchored on it"
    );
    assert_eq!(
        counted("a msg=<VARIES> c", &["a msg=y z c"]),
        v(&[("y z", 1)]),
        "the affix is stripped from a value spanning several units"
    );
}

#[test]
fn slot_values_are_read_from_the_masked_line() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        sanitize: crate::sanitize::Sanitizer::parse(&["credential,ip".to_string()], false).unwrap(),
        ..Config::default()
    });
    for l in [
        r#"login user=bob api_key: "Heron5 Stoat8" from 198.51.100.21"#,
        r#"login user=bob api_key: "Heron6 Stoat8" from 198.51.100.22"#,
        r#"login user=bob api_key: "Heron7 Stoat8" from 198.51.100.23"#,
    ] {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1, "these lines must fold into one group");
    let r = f.rollup_computer.compute(&f.buffer[0]);
    let mut samples: Vec<&String> = Vec::new();
    for entry in r.values() {
        samples.extend(&entry.samples);
        for slot in entry.slots.iter().flatten() {
            samples.extend(&slot.samples);
        }
    }
    for s in samples {
        assert!(
            !s.contains("Stoat8") && !s.contains("Heron"),
            "every rollup sample is read from the masked line, got {s:?}"
        );
    }
}

#[test]
fn two_sentence_words_apart_is_another_event() {
    assert_eq!(
        plain_word_diffs(
            "1:S 28 Aug <NUMBER> <TIMESTAMP> * Synchronization with replica <FQDN>:<PORT> succeeded",
            "1:S 28 Aug <NUMBER> <TIMESTAMP> * Connection with replica <FQDN>:<PORT> lost."
        ),
        Some(2),
        "two differing sentence words make another sentence"
    );
    assert_eq!(
        plain_word_diffs("user alice from <IP>", "user bob from <IP>"),
        Some(1),
        "one differing word is a name and folds"
    );
    assert_eq!(
        plain_word_diffs(
            "Fork CoW for RDB: current <SIZE>",
            "Fork CoW for AOF rewrite: current <SIZE>"
        ),
        Some(3)
    );
    assert_eq!(
        plain_word_diffs(
            r#"Failed to watch *v1.Node: nodes is forbidden: cannot list resource "nodes""#,
            r#"Failed to watch *v1.Pod: pods is forbidden: cannot list resource "pods""#
        ),
        Some(1),
        "values are not sentence words: quoted, typed, keyed, numbers and placeholders"
    );
    assert_eq!(
        plain_word_diffs(
            r#"{"controller": "triggerauthentication", "controllerKind": "TriggerAuthentication"}"#,
            r#"{"controller": "scaledjob", "controllerKind": "ScaledJob"}"#
        ),
        Some(0)
    );
    assert_eq!(
        plain_word_diffs("GPS mode 3 -> 2", "GPS mode 2 -> 3"),
        Some(0)
    );
    assert_eq!(
        plain_word_diffs("x k8s:app=virt-handler y", "x k8s:app=traefik y"),
        Some(0)
    );
    assert_eq!(
        plain_word_diffs(
            r#"{"msg":"finished scheduled compaction"}"#,
            r#"{"msg":"storing new hash"}"#
        ),
        Some(3),
        "a JSON sentence's words are sentence words: the key goes, the words stay"
    );

    let mut f = make_folder();
    for l in [
        "1:S 28 Aug 2026 01:22:07.429 * Synchronization with replica redis-node-1.svc.cluster.local:6379 succeeded",
        "1:S 28 Aug 2026 01:24:07.931 * Connection with replica redis-node-1.svc.cluster.local:6379 lost.",
        "1:S 28 Aug 2026 01:26:07.931 * Connection with replica redis-node-0.svc.cluster.local:6379 lost.",
    ] {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 2, "success and loss are two events");
}

#[test]
fn two_small_integers_are_one_shape_and_stay_on_the_line() {
    let mut f = make_folder();
    for l in [
        "Aug 26 09:24:57 gasida chrony-gps-toff[5097]: INFO GPS mode 3 -> 2",
        "Aug 26 09:24:59 gasida chrony-gps-toff[5097]: INFO GPS mode 2 -> 3",
        "Aug 26 11:39:28 gasida chrony-gps-toff[5097]: INFO GPS mode 3 -> 1",
    ] {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    assert_eq!(
        f.buffer[0].template(),
        "<TIMESTAMP> <HOST> chrony-gps-toff[<PID>]: INFO GPS mode <VARIES> -> <VARIES>",
        "small integers stay literal, but no longer keep a short line from folding"
    );
    let r = f.rollup_computer.compute(&f.buffer[0]);
    assert_eq!(r[VARIES].counts, Some(vec![3, 2, 1]));
}

#[test]
fn a_varies_slot_counts_masked_values_under_sanitize_pii() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        sanitize: Some(crate::sanitize::Sanitizer::pii_alias()),
        ..Config::default()
    });
    for l in [
        "auth user a@x.io password=FIXVALUEA1 req 1",
        "auth user a@x.io password=FIXVALUEA2 req 2",
        "auth user a@x.io password=FIXVALUEA3 req 3",
    ] {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    let r = f.rollup_computer.compute(&f.buffer[0]);
    let joined = format!("{:?}", r[VARIES].samples);
    assert!(
        !joined.contains("FIXVALUE"),
        "slot values are read from the masked line: {joined}"
    );
    assert_eq!(
        r[VARIES].samples,
        ["1", "2", "3"],
        "the masked template shows password=<SECRET>, so the request number is its only slot"
    );
}

#[test]
fn request_route_survives_repeated_method_and_version_variation() {
    let mut template = r#"request="GET /health HTTP/1" done"#.to_string();
    for member in [
        r#"request="POST /health HTTP/2" done"#,
        r#"request="PUT /health HTTP/3" done"#,
        r#"request="GET /health HTTP/1" done"#,
    ] {
        let edits = template_edits(&template, member).unwrap();
        apply_edits(&mut template, &edits);
        assert_eq!(template, r#"request="<VARIES> /health HTTP/<VARIES>" done"#);
    }
    assert_eq!(unit_spans(r#"controller="crt configmap" done"#).len(), 2);
    for suffix in ["HTTP/1", "HTTP/", "HTTP/\""] {
        let first = format!("\"GET /health {suffix}");
        let next = format!("\"POST /health {suffix}");
        let mut template = first.clone();
        for (at, len) in spans_of(&first, &next).into_iter().rev() {
            template.replace_range(at..at + len, VARIES_MARK);
        }
        assert_eq!(
            template,
            format!("\"<VARIES> /health {suffix}"),
            "a request cut before its closing quote or version still anchors"
        );
        assert!(unit_spans(&template).iter().all(|&(_, len)| len > 0));
    }
}

#[test]
fn separate_quoted_requests_keep_their_own_targets() {
    let first = r#"request="GET /health HTTP/1" prior="POST /metrics HTTP/1""#;
    let next = r#"request="POST /health HTTP/2" prior="PUT /metrics HTTP/2""#;
    let mut template = first.to_string();
    for (at, len) in spans_of(first, next).into_iter().rev() {
        template.replace_range(at..at + len, VARIES_MARK);
    }
    assert_eq!(
        template,
        r#"request="<VARIES> /health HTTP/<VARIES>" prior="<VARIES> /metrics HTTP/<VARIES>""#
    );
}

#[test]
fn varying_request_methods_keep_routes_out_of_the_varies_rollup() {
    let mut f = make_folder();
    for method in ["GET", "POST", "PUT", "GET"] {
        f.process_line(&format!(
            r#"10.20.30.40 - client [16/Sep/2026:11:20:30 +0000] "{method} /api/items/42 HTTP/1.1" 200 2048 "-" "invented-client/2.0""#
        )).unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    let template = f.buffer[0].template();
    assert!(
        template.contains(r#""<VARIES> /api/items/<N> HTTP/<DECIMAL>""#),
        "{template}"
    );
    let rollup = f.rollup_computer.compute(&f.buffer[0]);
    assert_eq!(rollup[VARIES].samples, ["GET", "POST", "PUT"]);
    assert_eq!(rollup[VARIES].counts, Some(vec![2, 1, 1]));
}

#[test]
fn request_atoms_preserve_nested_pci_addresses_and_status_markers() {
    let first = r#""GET /devices/<N> 0000:2a:00.3 <STATUS_2XX> HTTP/1""#;
    let next = r#""POST /devices/<N> 0000:2a:00.3 <STATUS_2XX> HTTP/2""#;
    let mut template = first.to_string();
    for (at, len) in spans_of(first, next).into_iter().rev() {
        template.replace_range(at..at + len, VARIES_MARK);
    }
    assert_eq!(
        template,
        r#""<VARIES> /devices/<N> 0000:2a:00.3 <STATUS_2XX> HTTP/<VARIES>""#
    );
}

#[test]
fn pci_identity_survives_variation_on_either_side_without_added_spaces() {
    let address = "0000:2a:00.3";
    for (first, next) in [
        ("usb-0000:2a:00.3/input0", "usb-0000:2a:00.3/input1"),
        ("left-0000:2a:00.3/path", "right-0000:2a:00.3/path"),
        ("left-0000:2a:00.3/input0", "right-0000:2a:00.3/input1"),
        (
            r#"path="left-0000:2a:00.3/input0""#,
            r#"path="right-0000:2a:00.3/input1""#,
        ),
        (
            "usb-0000:2a:00.3/input0 ready",
            "ready usb-0000:2a:00.3/input1",
        ),
    ] {
        let mut template = first.to_string();
        for (at, len) in spans_of(first, next).into_iter().rev() {
            template.replace_range(at..at + len, VARIES_MARK);
        }
        assert!(template.contains(address), "{first} vs {next}: {template}");
        assert!(template.contains(VARIES_MARK), "{template}");
        if !first.contains(' ') {
            assert!(!template.contains(' '), "{template}");
        }
    }
}

#[test]
fn pci_template_atoms_do_not_treat_different_address_lists_as_equal() {
    let (first, next) = ("usb-0000:2a:00.3/input0", "usb-0000:2a:00.4/input0");
    let mut template = first.to_string();
    for (at, len) in spans_of(first, next).into_iter().rev() {
        template.replace_range(at..at + len, VARIES_MARK);
    }
    assert_eq!(template.matches("0000:2a:00.3").count(), 0, "{template}");
    let (longer, shorter) = ("left-0000:2a:00.3/right-0000:2a:00.3", "left-0000:2a:00.3");
    assert_eq!(template_edits(longer, shorter), None);
    assert_eq!(template_edits(shorter, longer), None);
}

#[test]
fn hid_suffix_variations_keep_the_pci_address_out_of_the_varies_rollup() {
    let mut f = make_folder();
    for (slot, kind) in [(0, "Keyboard"), (1, "Mouse"), (0, "Keyboard")] {
        f.process_line(&format!(
            "Sep 16 10:20:30 testhost kernel: hid-generic 0003:1001:AA10.0001: input,hidraw{slot}: USB HID v2.10 {kind} [Invented Hardware Remote Input Controller Device] on usb-0000:2a:00.3-4.2/input{slot}"
        )).unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    let template = f.buffer[0].template();
    assert!(template.contains("usb-0000:2a:00.3"), "{template}");
    let rollup = f.rollup_computer.compute(&f.buffer[0]);
    let samples = &rollup[VARIES].samples;
    assert!(samples.iter().any(|s| s.contains("input0")), "{samples:?}");
    assert!(samples.iter().any(|s| s.contains("input1")), "{samples:?}");
    assert!(
        samples.iter().all(|s| !s.contains("0000:2a:00.3")),
        "{samples:?}"
    );
}

#[test]
fn a_quoted_sentence_keeps_its_words_and_a_quoted_name_is_one_slot() {
    assert_eq!(
        unit_spans(r#"a "b c" d"#).len(),
        3,
        "a two-word quoted value is one unit"
    );
    assert_eq!(
        unit_spans(r#"a "b c d e f" g"#).len(),
        7,
        "a five-word quoted string is a sentence"
    );
    let mut f = make_folder();
    for vol in ["xtables-lock", "host-sys", "run-nvidia"] {
        f.process_line(&format!(
            r#"I0914 09:34:56.988344  752362 reconciler_common.go:245] "operationExecutor.VerifyControllerAttachedVolume started for volume \"{vol}\" (UniqueName: \"kubernetes.io/host-path/fe082e26-f4ea-4de8-a42e-4c3b91c60916-{vol}\") pod \"gpu-feature-discovery-mrgp8\" (UID: \"fe082e26-f4ea-4de8-a42e-4c3b91c60916\") " pod="gpu-operator/gpu-feature-discovery-mrgp8""#
        ))
        .unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    let t = f.buffer[0].template();
    assert!(
        t.contains("started for volume <VARIES> (UniqueName:"),
        "a differing quoted value inside the sentence varies on its own: {t}"
    );
    assert!(
        t.contains("VerifyControllerAttachedVolume"),
        "the sentence stays: {t}"
    );
}

#[test]
fn a_token_ending_in_a_small_integer_folds_with_its_siblings() {
    let mut f = make_folder();
    for slot in [1, 2, 1] {
        f.process_line(&format!(
            "Aug 25 02:29:46 USW16PoE user.info : cfgmtd[939]: cfgmtd.cfgmtd_do_write(): Phase2: Verify OK on slot[{slot}]"
        ))
        .unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    assert!(
        f.buffer[0]
            .template()
            .ends_with("Verify OK on slot[<VARIES>]"),
        "{}",
        f.buffer[0].template()
    );
    let r = f.rollup_computer.compute(&f.buffer[0]);
    assert_eq!(
        r[VARIES].samples,
        vec!["1", "2"],
        "slot[1] and slot[2] fold into one group"
    );
    assert_eq!(r[VARIES].counts, Some(vec![2, 1]));
}

#[test]
fn groups_converging_on_one_template_render_once() {
    let mut f = make_folder_json();
    let stem = "svc node ready check pass level info region east";
    for tail in [
        "alpha state one",
        "beta state two",
        "gamma state one",
        "delta state two",
        "alpha state three",
        "beta state four",
    ] {
        f.process_line(&format!("{stem} {tail}")).unwrap();
    }
    assert_eq!(
        f.buffer.len(),
        2,
        "the two founders must not fold on arrival"
    );
    let out = f.finish().unwrap();
    assert_eq!(out.len(), 1, "one claim renders once: {out:?}");
    let record: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
    assert_eq!(record["count"], 6);
    assert_eq!(
        record["normalized"],
        format!("{stem} <VARIES> state <VARIES>")
    );
    let varies = &record["variation"]["VARIES"];
    assert_eq!(varies["distinct_count"], 8, "{varies}");
}

#[test]
fn prose_requests_keep_methods_routes_and_full_url_facts() {
    let mut f = make_folder();
    for host in ["10.4.5.6:8008", "10.4.5.7:8008", "worker.example:8080"] {
        for (method, route) in [
            ("GET", "settings"),
            ("POST", "settings"),
            ("GET", "promote"),
            ("POST", "promote"),
        ] {
            f.process_line(&format!(r#"{{"level":"debug","msg":"making {method} http request: http://{host}/{route}","component":"controller","time":"2026-09-16T06:01:00Z"}}"#)).unwrap();
        }
    }
    assert_eq!(f.buffer.len(), 4);
    for group in &f.buffer {
        assert_eq!(group.count(), 3);
        assert!(
            !group.template().contains("<VARIES>"),
            "{}",
            group.template()
        );
        assert!(group.template().contains("http://<HOST>/"));
        let rollup = f.rollup_computer.compute(group);
        assert_eq!(rollup["PATH"].samples.len(), 3);
    }
}

#[test]
fn short_prose_request_keeps_identity_when_neighboring_fields_vary() {
    let mut f = make_folder();
    for worker in ["cedar", "birch", "cedar"] {
        f.process_line(&format!(r#"{{"request":"GET http://worker.example/items/42","worker":"{worker}","level":"info","message":"request finished"}}"#)).unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    let group = &f.buffer[0];
    assert!(
        group
            .template()
            .contains(r#""request":"GET http://<HOST>/items/<N>""#),
        "{}",
        group.template()
    );
    let rollup = f.rollup_computer.compute(group);
    assert_eq!(rollup[VARIES].samples, [r#""cedar""#, r#""birch""#]);
    assert_eq!(rollup[VARIES].counts, Some(vec![2, 1]));
}

#[test]
fn cpu_quantity_rollup_keeps_values_separate_from_time() {
    let mut f = make_folder();
    for cpu in ["750m", "1250m", "750m"] {
        f.process_line(&format!(
            r#"{{"cpu":"{cpu}","timeout":"20m","message":"resource configuration"}}"#
        ))
        .unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    let group = &f.buffer[0];
    assert!(group.template().contains("<CPU_QUANTITY>"));
    let rollup = f.rollup_computer.compute(group);
    assert_eq!(rollup["CPU_QUANTITY"].samples, ["1250m", "750m"]);
    assert_eq!(rollup["CPU_QUANTITY"].distinct_count, 2);
    assert_eq!(f.stats.cpu_quantities, 3);
    assert_eq!(f.stats.durations, 3);
    f.finish().unwrap();
    let briefing = f.build_briefing();
    assert!(
        briefing
            .tokens
            .iter()
            .any(|t| t.class == "cpu_quantities" && t.occurrences == 3)
    );
}

#[test]
fn a_merged_group_shows_the_later_last_line() {
    let stem = "svc node ready check pass level info region east";
    let last_line_no = |tails: &[&str]| {
        let mut f = make_folder_json();
        for tail in tails {
            f.process_line(&format!("{stem} {tail}")).unwrap();
        }
        let out = f.finish().unwrap();
        assert_eq!(out.len(), 1, "{out:?}");
        let record: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
        record["last"]["line_no"].as_u64().unwrap()
    };
    assert_eq!(
        last_line_no(&[
            "alpha state one",
            "beta state two",
            "delta state two",
            "beta state four",
            "gamma state one",
            "alpha state three",
        ]),
        6,
        "alpha founded first and its last member is the later one"
    );
    assert_eq!(
        last_line_no(&[
            "alpha state one",
            "beta state two",
            "gamma state one",
            "alpha state three",
            "delta state two",
            "beta state four",
        ]),
        6,
        "alpha founded first but beta's last member is the later one"
    );
}

#[test]
fn three_converging_groups_merge_into_one() {
    let mut f = make_folder_json();
    let stem = "svc node ready check pass level info region east";
    for tail in [
        "alpha state one",
        "beta state two",
        "gamma state three",
        "delta state one",
        "alpha state four",
        "epsilon state two",
        "beta state five",
        "zeta state three",
        "gamma state six",
    ] {
        f.process_line(&format!("{stem} {tail}")).unwrap();
    }
    assert_eq!(f.buffer.len(), 3, "three founders two words apart");
    let out = f.finish().unwrap();
    assert_eq!(out.len(), 1, "{out:?}");
    let record: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
    assert_eq!(record["count"], 9);
}

#[test]
fn absorb_uses_position_to_break_equal_source_line_numbers() {
    let make = |text: &str, source: u32, position: usize| {
        PatternGroup::new_at(
            make_line(text, vec![]),
            position,
            LineLocation::new(SourceId(source), 4),
        )
    };
    let mut first = make("svc alpha", 1, 0);
    let second = make("svc beta", 2, 1);
    first.template = "svc <VARIES>".into();
    let mut second = second;
    second.template = first.template.clone();
    first.absorb(second);
    assert_eq!(first.last().normalized, "svc beta");
}

fn summary_json(f: &PatternFolder) -> serde_json::Value {
    let mut buf = Vec::new();
    f.print_summary_json(&mut buf, std::time::Duration::ZERO)
        .unwrap();
    serde_json::from_slice(&buf).unwrap()
}

#[test]
fn a_clean_json_run_reports_complete_everywhere() {
    let mut f = make_folder_json();
    for _ in 0..3 {
        f.process_line("worker heartbeat ok").unwrap();
    }
    f.finish().unwrap();
    let v = summary_json(&f);
    let c = &v["completeness"];
    assert_eq!(c["complete"], true, "{c}");
    assert_eq!(c["input"]["complete"], true, "{c}");
    assert_eq!(c["groups"]["complete"], true, "{c}");
    assert_eq!(c["variation_values"]["complete"], true, "{c}");
    assert_eq!(c["variation_values"]["capped_entries"], 0, "{c}");
    assert_eq!(c["variation_values"]["sampled_entries"], 0, "{c}");
    assert_eq!(c["variation_values"]["uncomputed_groups"], 0, "{c}");
    assert_eq!(
        c["variation_values"]["omitted_values"]["kind"], "exact",
        "{c}"
    );
    assert_eq!(c["variation_values"]["omitted_values"]["value"], 0, "{c}");
}

#[test]
fn uncomputed_variation_groups_make_omitted_values_unknown() {
    let mut f = make_folder_json();
    f.process_line("alpha event").unwrap();
    f.process_line("bravo event").unwrap();
    f.finish().unwrap();
    let v = summary_json(&f);
    let c = &v["completeness"];
    assert_eq!(c["variation_values"]["uncomputed_groups"], 2, "{c}");
    assert_eq!(
        c["variation_values"]["omitted_values"]["kind"], "unknown",
        "{c}"
    );
    assert_eq!(c["variation_values"]["complete"], false, "{c}");
    assert_eq!(c["groups"]["complete"], true, "{c}");
    assert_eq!(c["input"]["complete"], true, "{c}");
    assert_eq!(c["complete"], false, "{c}");
}

#[test]
fn a_sampled_but_uncapped_entry_is_counted_once_with_its_exact_omission() {
    let mut f = make_folder_json();
    let stem = "svc node ready check pass level info region east state";
    for w in ["w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8"] {
        f.process_line(&format!("{stem} {w}")).unwrap();
    }
    let other = "job queue drain step retry limit reached worker slot";
    for w in ["a1", "a2", "a1"] {
        f.process_line(&format!("{other} {w}")).unwrap();
    }
    let out = f.finish().unwrap();
    assert_eq!(out.len(), 2, "{out:?}");
    let v = summary_json(&f);
    let c = &v["completeness"]["variation_values"];
    assert_eq!(c["capped_entries"], 0, "{c}");
    assert_eq!(c["sampled_entries"], 1, "{c}");
    assert_eq!(c["omitted_values"]["kind"], "exact", "{c}");
    assert_eq!(c["omitted_values"]["value"], 1, "{c}");
    assert_eq!(c["complete"], false, "{c}");
    assert_eq!(v["completeness"]["groups"]["complete"], true, "{v}");
    assert_eq!(v["completeness"]["complete"], false, "{v}");
}

#[test]
fn a_capped_entry_makes_omitted_values_a_lower_bound() {
    let mut f = make_folder_json();
    for i in 0..=ROLLUP_DISTINCT_CAP {
        f.process_line(&format!(
            "request 550e8400-e29b-41d4-a716-4466554{i:05} accepted"
        ))
        .unwrap();
    }
    let out = f.finish().unwrap();
    assert_eq!(out.len(), 1, "{out:?}");
    let v = summary_json(&f);
    let c = &v["completeness"]["variation_values"];
    assert_eq!(c["capped_entries"], 1, "{c}");
    assert_eq!(c["sampled_entries"], 1, "{c}");
    assert_eq!(c["omitted_values"]["kind"], "lower_bound", "{c}");
    assert_eq!(c["complete"], false, "{c}");
}

#[test]
fn a_top_omission_alone_makes_groups_and_the_run_incomplete() {
    let mut f = make_folder_json();
    for _ in 0..3 {
        f.process_line("alpha event").unwrap();
    }
    for _ in 0..3 {
        f.process_line("bravo event").unwrap();
    }
    let TopGroups {
        total_groups: total,
        ..
    } = f.finish_top_n(1, None, false).unwrap();
    assert_eq!(total, 2);
    let v = summary_json(&f);
    let c = &v["completeness"];
    assert_eq!(c["groups"]["omitted_by_top"]["value"], 1, "{c}");
    assert_eq!(c["groups"]["complete"], false, "{c}");
    assert_eq!(c["input"]["complete"], true, "{c}");
    assert_eq!(c["variation_values"]["complete"], true, "{c}");
    assert_eq!(c["complete"], false, "{c}");
}

#[test]
fn an_overlong_skip_alone_makes_input_and_the_run_incomplete() {
    let mut f = make_folder_json();
    for _ in 0..3 {
        f.process_line("alpha event").unwrap();
    }
    f.finish().unwrap();
    let report = crate::ingest::IngestReport {
        fail_pattern_matched: false,
        overlong_lines_skipped: 1,
        continuation_lines_to_add_back: 0,
        max_lines_reached: false,
        complete_input_hash: None,
    };
    f.absorb_ingest_report(&report, 0);
    let v = summary_json(&f);
    let c = &v["completeness"];
    assert_eq!(c["input"]["complete"], false, "{c}");
    assert_eq!(c["input"]["skipped_overlong_lines"]["value"], 1, "{c}");
    assert_eq!(
        c["input"]["unprocessed_after_max_lines"]["kind"], "exact",
        "{c}"
    );
    assert_eq!(c["input"]["failed_sources"]["kind"], "exact", "{c}");
    assert_eq!(c["groups"]["complete"], true, "{c}");
    assert_eq!(c["variation_values"]["complete"], true, "{c}");
    assert_eq!(c["complete"], false, "{c}");
}

#[test]
fn the_briefing_rate_is_lines_over_the_span_in_seconds() {
    let mut f = make_folder_json();
    for s in [0, 1, 1, 2, 2, 3, 3, 4, 4, 5] {
        f.process_line(&format!("2025-01-01 10:00:0{s} worker tick"))
            .unwrap();
    }
    f.finish().unwrap();
    let b = f.build_briefing();
    assert_eq!(b.lines, 10);
    assert_eq!(b.span.duration_seconds, Some(5), "{:?}", b.span);
    assert_eq!(b.span.lines_per_second, Some(2.0), "{:?}", b.span);
    assert!(b.histogram.is_some());
}

#[test]
fn a_zero_second_span_has_no_rate() {
    let mut f = make_folder_json();
    f.process_line("2025-01-01 10:00:00 worker tick").unwrap();
    f.process_line("2025-01-01 10:00:00 worker tock").unwrap();
    f.finish().unwrap();
    let b = f.build_briefing();
    assert_eq!(b.span.duration_seconds, Some(0), "{:?}", b.span);
    assert_eq!(b.span.lines_per_second, None, "{:?}", b.span);
}

#[test]
fn a_histogram_needs_a_clock_so_a_log_without_timestamps_has_neither() {
    let mut f = make_folder_json();
    for word in ["alpha", "beta", "gamma", "delta"] {
        f.process_line(&format!("worker {word} finished")).unwrap();
    }
    f.finish().unwrap();
    let b = f.build_briefing();
    assert_eq!(b.span.duration_seconds, None, "{:?}", b.span);
    assert!(
        b.histogram.is_none(),
        "no timestamps means no buckets to place: {:?}",
        b.histogram
    );
}

#[test]
fn a_json_and_a_plain_line_make_the_format_mix_mixed() {
    let mut f = make_folder_json();
    f.process_line(r#"{"level":"info","msg":"started","port":8080}"#)
        .unwrap();
    f.process_line("plain text line without structure").unwrap();
    f.process_line("Alloc=25451 TotalAlloc=99852 Sys=81560")
        .unwrap();
    f.finish().unwrap();
    let b = f.build_briefing();
    assert_eq!(
        (b.format.json, b.format.logfmt, b.format.plain),
        (1, 1, 1),
        "{:?}",
        b.format
    );
    assert!(b.format.mixed, "{:?}", b.format);
}

#[test]
fn an_unfolded_markdown_entry_with_a_plus_is_not_marked_folded() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        output_format: OutputFormat::Markdown,
        ..Config::default()
    });
    f.process_line("sum a+b done").unwrap();
    let entries = f.finish_markdown().unwrap();
    let mut buf = Vec::new();
    f.emit_markdown(&entries, &mut buf).unwrap();
    let doc = String::from_utf8(buf).unwrap();
    assert!(doc.contains("```\nsum a+b done\n```"), "{doc}");
    assert!(!doc.contains("(Folded)"), "{doc}");
}

#[test]
fn an_unsampled_variation_entry_keeps_the_sampled_count_zero() {
    let mut f = make_folder_json();
    for word in ["first", "second", "first"] {
        f.process_line(&format!(
            "job queue drain step retry limit reached worker slot {word}"
        ))
        .unwrap();
    }
    assert_eq!(f.finish().unwrap().len(), 1);
    let summary = summary_json(&f);
    let variation = &summary["completeness"]["variation_values"];
    assert_eq!(variation["sampled_entries"], 0, "{summary}");
    assert_eq!(variation["omitted_values"]["value"], 0, "{summary}");
    assert_eq!(variation["complete"], true, "{summary}");
}

#[test]
fn word_alignment_is_an_lcs_with_its_documented_tie_break() {
    let same = align_words(&["a", "b"], &["a", "b"]);
    assert_eq!(same, vec![Some(0), Some(1)]);
    let skip = align_words(&["a", "b", "c", "d"], &["a", "c", "d"]);
    assert_eq!(skip, vec![Some(0), None, Some(1), Some(2)]);
    let insert = align_words(&["x", "b", "y"], &["b"]);
    assert_eq!(insert, vec![None, Some(0), None]);
    let tie = align_words(&["a", "b"], &["b", "a", "c"]);
    assert_eq!(
        tie,
        vec![None, Some(0)],
        "a tie drops the left word first, the documented choice"
    );
    let rep = align_words(&["k", "v", "k", "w"], &["k", "w"]);
    assert_eq!(
        rep,
        vec![Some(0), None, None, Some(1)],
        "repeated words align in order, never crossing"
    );
    assert!(
        alignable(MAX_ALIGN_WORDS, MAX_ALIGN_WORDS - 1),
        "the cap is inclusive on both sides"
    );
    assert!(alignable(MAX_ALIGN_WORDS, 1));
    assert!(alignable(1, MAX_ALIGN_WORDS));
    assert!(!alignable(MAX_ALIGN_WORDS + 1, 1));
    assert!(!alignable(1, MAX_ALIGN_WORDS + 1));
    let bigger: Vec<&str> = std::iter::repeat_n("w", MAX_ALIGN_WORDS + 1).collect();
    let mut by_position = vec![None; MAX_ALIGN_WORDS + 1];
    by_position[0] = Some(0);
    assert_eq!(
        align_words(&bigger, &["v"]),
        by_position,
        "past the cap and outside the band, units pair by position"
    );
    assert_eq!(align_words(&["v"], &bigger), vec![Some(0)]);
}

#[test]
fn long_lines_align_within_the_band_and_no_further() {
    let over = MAX_ALIGN_WORDS + 1;
    assert!(alignable(over, over));
    assert!(alignable(over + 40, over + 40));
    assert!(alignable(over, over + ALIGN_BAND));
    assert!(alignable(over + ALIGN_BAND, over));
    assert!(!alignable(over, over + ALIGN_BAND + 1));
    assert!(!alignable(over + ALIGN_BAND + 1, over));
    assert!(
        alignable(MAX_ALIGN_WORDS, MAX_ALIGN_WORDS + ALIGN_BAND),
        "one side at the cap, the other past it: the band decides"
    );
    assert!(!alignable(
        MAX_ALIGN_WORDS,
        MAX_ALIGN_WORDS + ALIGN_BAND + 1
    ));
    assert!(
        alignable(MAX_ALIGN_WORDS, MAX_ALIGN_WORDS - ALIGN_BAND - 1),
        "both inside the cap: exact, whatever the difference"
    );
    let words: Vec<String> = (0..MAX_ALIGN_WORDS).map(|i| format!("w{i}")).collect();
    let full: Vec<&str> = words.iter().map(String::as_str).collect();
    let short: Vec<&str> = full[ALIGN_BAND + 1..].to_vec();
    let aligned = align_words(&full, &short);
    assert_eq!(
        aligned[..=ALIGN_BAND],
        vec![None; ALIGN_BAND + 1],
        "inside the cap the exact table runs, not the band"
    );
    for (i, slot) in aligned.iter().enumerate().skip(ALIGN_BAND + 1) {
        assert_eq!(*slot, Some(i - ALIGN_BAND - 1));
    }
}

#[test]
fn a_long_line_with_inserted_units_pairs_every_other_unit() {
    let words: Vec<String> = (0..400).map(|i| format!("u{i}")).collect();
    let line: Vec<&str> = words.iter().map(String::as_str).collect();
    for at in [0, 1, 199, 398, 399] {
        let mut shorter = line.clone();
        shorter.remove(at);
        let expect: Vec<Option<usize>> = (0..400)
            .map(|i| match i.cmp(&at) {
                std::cmp::Ordering::Less => Some(i),
                std::cmp::Ordering::Equal => None,
                std::cmp::Ordering::Greater => Some(i - 1),
            })
            .collect();
        assert_eq!(align_words(&line, &shorter), expect, "dropped at {at}");
        let back: Vec<Option<usize>> = (0..399).map(|i| Some(i + usize::from(i >= at))).collect();
        assert_eq!(align_words(&shorter, &line), back, "inserted at {at}");
    }
    let mut gap = line.clone();
    gap.drain(100..100 + ALIGN_BAND);
    let aligned = align_words(&line, &gap);
    assert_eq!(
        aligned.iter().filter(|a| a.is_none()).count(),
        ALIGN_BAND,
        "the band's whole width gone from one place leaves exactly those units unpaired"
    );
    assert!(aligned[100..100 + ALIGN_BAND].iter().all(Option::is_none));
    assert_eq!(aligned[100 + ALIGN_BAND], Some(100));
}

#[test]
fn long_lines_count_plain_word_diffs_through_the_band() {
    let words: Vec<String> = (0..300).map(|i| format!("w{i}")).collect();
    let line = words.join(" ");
    let with = |extra: &[&str]| {
        let mut w: Vec<&str> = words.iter().map(String::as_str).collect();
        for (n, e) in extra.iter().enumerate() {
            w.insert(150 + n, e);
        }
        w.join(" ")
    };
    assert_eq!(plain_word_diffs(&line, &with(&["zone=k2/west"])), Some(0));
    assert_eq!(plain_word_diffs(&with(&["zone=k2/west"]), &line), Some(0));
    assert_eq!(plain_word_diffs(&line, &with(&["stalled"])), Some(1));
    let values: Vec<String> = (0..=ALIGN_BAND).map(|i| format!("t{i}=v/{i}")).collect();
    let values: Vec<&str> = values.iter().map(String::as_str).collect();
    assert_eq!(
        plain_word_diffs(&line, &with(&values[..ALIGN_BAND])),
        Some(0)
    );
    assert_eq!(plain_word_diffs(&line, &with(&values)), None);
    assert_eq!(plain_word_diffs(&with(&values), &line), None);
}

#[test]
fn a_long_template_marks_the_unit_a_shorter_member_lacks() {
    let words: Vec<String> = (0..300).map(|i| format!("w{i}")).collect();
    let mut founder: Vec<&str> = words.iter().map(String::as_str).collect();
    founder.insert(150, "shard=k7/east");
    let founder = founder.join(" ");
    let member = words.join(" ");
    let edits = spans_of(&founder, &member);
    let at = founder.find("shard=").unwrap();
    assert_eq!(edits, vec![(at, "shard=k7/east".len())]);
    let after = member.find(" w150").unwrap();
    assert_eq!(
        spans_of(&member, &founder),
        vec![(after, 0)],
        "a member unit the template lacks opens a slot there"
    );
}

#[test]
fn shared_affixes_keep_the_field_name_and_the_closing_brackets_only() {
    assert_eq!(shared_affixes("msg=Connecting", "msg=Connected"), (4, 0));
    assert_eq!(shared_affixes("slot[1]", "slot[2]"), (5, 1));
    assert_eq!(shared_affixes("on(1)", "on(22)"), (3, 1));
    assert_eq!(
        shared_affixes(r#""NodeName":"a""#, r#""NodeName":"b""#),
        (11, 0)
    );
    assert_eq!(shared_affixes("alpha", "beta"), (0, 0));
    assert_eq!(
        shared_affixes("k=", "k="),
        (0, 0),
        "the prefix stops one short of the whole word, so a value is never empty"
    );
    assert_eq!(shared_affixes("a=x", "a=x"), (2, 0));
    assert_eq!(
        shared_affixes("]]]", "]]]"),
        (0, 2),
        "the suffix stops one short too, even when every byte is a bracket"
    );
    assert_eq!(shared_affixes("x]]", "y]]"), (0, 2));
}

#[test]
fn a_field_value_follows_a_plain_key_and_nothing_else() {
    assert_eq!(field_value("k=v"), Some("v"));
    assert_eq!(field_value("k:v"), Some("v"));
    assert_eq!(field_value("_k=v"), Some("v"));
    assert_eq!(field_value("a-b=v"), Some("v"));
    assert_eq!(field_value("a_b=v"), Some("v"));
    assert_eq!(field_value(r#""k":v"#), Some("v"));
    assert_eq!(field_value("bare"), Some("bare"));
    assert_eq!(field_value("9k=v"), None);
    assert_eq!(field_value("1:S"), None);
    assert_eq!(field_value("a.b=v"), None);
    assert_eq!(field_value(r#""9k":v"#), None);
}

#[test]
fn a_bracketed_value_needs_both_brackets_to_be_data() {
    assert!(data_shaped("v=[x]"));
    assert!(data_shaped("v=(x)"));
    assert!(!data_shaped("v=[x"));
    assert!(!data_shaped("v=x]"));
    assert!(!data_shaped("v=(x"));
    assert!(!data_shaped("v=x)"));
    assert!(!data_shaped("plain"));
}

#[test]
fn units_cut_requests_options_and_pci_addresses_out_whole() {
    let texts = |s: &str| -> Vec<String> {
        unit_spans(s)
            .into_iter()
            .map(|(at, len)| s[at..at + len].to_string())
            .collect()
    };
    let covers = |s: &str| {
        let spans = unit_spans(s);
        for w in spans.windows(2) {
            assert!(w[0].0 + w[0].1 <= w[1].0, "overlap in {s:?}: {spans:?}");
        }
        let total: usize = spans.iter().map(|(_, l)| l).sum();
        assert!(total <= s.len(), "{s:?}: {spans:?}");
    };
    for s in [
        r#"req "GET /api/v1/items HTTP/1.1" 200"#,
        r#"a "GET /x HTTP/1.1" b "POST /y HTTP/2" c"#,
        "dev 0000:21:00.0 up",
        "path /sys/0000:21:00.0/0000:21:00.1/x",
        r#"msg="  --bpf-lb-mode=snat" subsys=daemon"#,
        r#"a="--x=1 --y=2" b"#,
        r#"a="q \" --z=3" b"#,
    ] {
        covers(s);
    }
    assert!(texts("dev 0000:21:00.0 up").contains(&"0000:21:00.0".to_string()));
    let two = texts("path /sys/0000:21:00.0/0000:21:00.1/x");
    assert!(
        two.contains(&"0000:21:00.0".to_string()) && two.contains(&"0000:21:00.1".to_string()),
        "{two:?}"
    );
    let req = texts(r#"req "GET /api/v1/items HTTP/1.1" 200"#);
    assert!(req.iter().any(|u| u == "/api/v1/items"), "{req:?}");
    let opt = texts(r#"msg="  --bpf-lb-mode=snat" subsys=daemon"#);
    assert!(opt.iter().any(|u| u == "--bpf-lb-mode"), "{opt:?}");
    let opts = texts(r#"a="--x=1 --y=2" b"#);
    assert!(
        opts.iter().any(|u| u == "--x") && opts.iter().any(|u| u == "--y"),
        "{opts:?}"
    );
    let esc = texts(r#"a="q \" --z=3" b"#);
    assert!(esc.iter().any(|u| u == "--z"), "{esc:?}");
}

#[test]
fn plain_word_diffs_count_sentence_words_not_values() {
    assert_eq!(plain_word_diffs("user alice", "user bob"), Some(1));
    assert_eq!(plain_word_diffs("user alice", "user 10.0.0.1"), Some(1));
    assert_eq!(plain_word_diffs("peer 10.0.0.1", "peer 10.0.0.2"), Some(0));
    assert_eq!(plain_word_diffs("p q", "p q x.y"), Some(0));
    assert_eq!(plain_word_diffs("p q", "p q q"), Some(0));
    assert_eq!(plain_word_diffs("p q", "p q r"), Some(1));
    assert_eq!(plain_word_diffs(r#"m="a b""#, r#"m="a b c""#), Some(1));
    assert_eq!(plain_word_diffs(r#"m="a b""#, r#"m="a c""#), Some(1));
    assert_eq!(
        plain_word_diffs("Fork CoW for RDB", "Fork CoW for AOF rewrite"),
        Some(3)
    );
}

#[test]
fn the_compact_marker_ellipsis_means_more_values_than_shown() {
    let entry = |distinct: usize, samples: &[&str]| VariationEntry {
        distinct_count: distinct,
        samples: samples.iter().map(ToString::to_string).collect(),
        capped: false,
        counts: Some(vec![1; samples.len()]),
        slots: None,
    };
    let mut more = BTreeMap::new();
    more.insert(VARIES, entry(3, &["a", "b"]));
    assert!(render_compact_marker(10, &more, None, None, 3).contains('…'));
    let mut all = BTreeMap::new();
    all.insert(VARIES, entry(2, &["a", "b"]));
    assert!(!render_compact_marker(10, &all, None, None, 3).contains('…'));
}

#[test]
fn a_registered_source_has_its_name_and_stdin_has_none() {
    let mut f = make_folder();
    let id = f.register_source("app.log".to_string());
    assert_eq!(f.source_name(id), Some("app.log".to_string()));
    assert_eq!(f.source_name(SourceId::STDIN), None);
}

#[test]
fn anchor_mismatch_is_set_only_when_the_anchors_differ() {
    let mut f = explaining_folder();
    f.process_line(r#"[2026-08-16 14:08:34 +0200] ::ffff - "GET /login/ HTTP/1.1" 200 17450.949"#)
        .unwrap();
    f.process_line(r#"[2026-08-16 14:08:31 +0200] ::ffff - "GET /admin/ HTTP/1.1" 200 14502.251"#)
        .unwrap();
    assert_eq!(
        f.buffer.len(),
        2,
        "different endpoints found separate groups"
    );
    assert!(f.buffer[1].nearest.as_ref().unwrap().anchor_mismatch);

    let mut f = explaining_folder();
    f.process_line("req took 111 ms").unwrap();
    f.process_line("req took 333 sec").unwrap();
    assert_eq!(f.buffer.len(), 2);
    assert!(!f.buffer[1].nearest.as_ref().unwrap().anchor_mismatch);
}

#[test]
fn shared_affix_bounds_bind_on_the_shorter_side() {
    assert!(alignable(MAX_ALIGN_WORDS - 1, MAX_ALIGN_WORDS));
    assert_eq!(
        shared_affixes("k=", "k=x"),
        (0, 0),
        "the whole shorter word is never a prefix"
    );
    assert_eq!(shared_affixes("k=x", "k="), (0, 0));
    assert_eq!(
        shared_affixes("]]", "]]]"),
        (0, 1),
        "brackets stop one short of the shorter word"
    );
    assert_eq!(shared_affixes("]]]", "]]"), (0, 1));
    assert_eq!(
        shared_affixes("f(())", "f((x))"),
        (3, 1),
        "prefix and suffix are kept together"
    );
    assert_eq!(shared_affixes("f((x))", "f(())"), (3, 1));
}

#[test]
fn word_alignment_drops_a_left_word_to_reach_a_later_match() {
    assert_eq!(
        align_words(&["a", "a"], &["b", "a", "a"]),
        vec![Some(1), Some(2)]
    );
    assert_eq!(
        align_words(&["a", "a"], &["b", "a", "b"]),
        vec![None, Some(1)]
    );
    assert_eq!(align_words(&["a"], &["b", "b", "a"]), vec![Some(2)]);
    assert_eq!(
        align_words(&["a", "z", "b"], &["b", "a"]),
        vec![None, None, Some(0)]
    );
    assert_eq!(
        align_words(&["a", "b"], &["x", "a", "b", "a", "b"]),
        vec![Some(1), Some(2)]
    );
}

#[test]
fn a_repeated_left_unit_is_not_a_plain_word_diff() {
    assert_eq!(plain_word_diffs("p q q", "p q"), Some(0));
    assert_eq!(plain_word_diffs("p q x.y", "p q"), Some(0));
}

#[test]
fn unit_spans_are_non_empty_ordered_and_reach_every_request_and_option() {
    let pinned = [
        (
            r#"a "GET /x HTTP/1.1" b "POST /y HTTP/2" c"#,
            vec![
                (0, 1),
                (2, 1),
                (3, 3),
                (7, 2),
                (10, 5),
                (15, 3),
                (18, 1),
                (20, 1),
                (22, 1),
                (23, 4),
                (28, 2),
                (31, 5),
                (36, 1),
                (37, 1),
                (39, 1),
            ],
        ),
        (
            r#"a="--x=1 --y=2" b"#,
            vec![
                (0, 2),
                (2, 1),
                (3, 3),
                (6, 2),
                (9, 3),
                (12, 2),
                (14, 1),
                (16, 1),
            ],
        ),
        (
            r#"a="q \" --z=3" b"#,
            vec![
                (0, 2),
                (2, 1),
                (3, 1),
                (5, 2),
                (8, 3),
                (11, 2),
                (13, 1),
                (15, 1),
            ],
        ),
        ("dev 0000:21:00.0 up", vec![(0, 3), (4, 12), (17, 2)]),
        ("0000:21:00.0", vec![(0, 12)]),
        (
            "path /sys/0000:21:00.0/0000:21:00.1/x",
            vec![(0, 4), (5, 5), (10, 12), (22, 1), (23, 12), (35, 2)],
        ),
        (
            r#"req "GET /api/v1/items HTTP/1.1" 200"#,
            vec![
                (0, 3),
                (4, 1),
                (5, 3),
                (9, 13),
                (23, 5),
                (28, 3),
                (31, 1),
                (33, 3),
            ],
        ),
        (
            r#"msg="  --bpf-lb-mode=snat" subsys=daemon"#,
            vec![(0, 4), (4, 1), (7, 13), (20, 5), (25, 1), (27, 13)],
        ),
    ];
    for (s, expected) in pinned {
        let spans = unit_spans(s);
        let mut last_end = 0;
        for &(at, len) in &spans {
            assert!(len > 0, "empty span at {at} in {s:?}: {spans:?}");
            assert!(at >= last_end, "out of order in {s:?}: {spans:?}");
            last_end = at + len;
        }
        assert_eq!(spans, expected, "{s:?}");
    }
    fn texts(s: &str) -> Vec<&str> {
        unit_spans(s)
            .into_iter()
            .map(|(at, len)| &s[at..at + len])
            .collect()
    }
    assert!(texts(r#"a "GET /x HTTP/1.1" b "POST /y HTTP/2" c"#).contains(&"/y"));
    assert!(texts(r#"a="q \" --z=3" b"#).contains(&"--z"));
    let last_word = texts(r#"a="--x b c y""#);
    assert!(
        last_word.contains(&"y") && last_word.contains(&"\""),
        "a long quoted value's final word stays apart from the closing quote: {last_word:?}"
    );
    assert!(!last_word.contains(&"y\""));
    let after_quote = texts(r#"a="--x b c d "tail"#);
    assert!(after_quote.contains(&"\"") && after_quote.contains(&"tail"));
    assert!(!after_quote.contains(&"\"tail"));
}

#[test]
fn unit_boundaries_hold_for_glued_stale_and_doubled_quotes() {
    fn texts(s: &str) -> Vec<&str> {
        let spans = unit_spans(s);
        let mut last_end = 0;
        for &(at, len) in &spans {
            assert!(len > 0, "empty span at {at} in {s:?}: {spans:?}");
            assert!(at >= last_end, "out of order in {s:?}: {spans:?}");
            last_end = at + len;
        }
        spans
            .into_iter()
            .map(|(at, len)| &s[at..at + len])
            .collect()
    }
    let glued = texts(r#"a="--x"tail"#);
    assert!(
        glued.contains(&"tail") && !glued.contains(&"\"tail"),
        "the closing quote is cut from the word glued behind it: {glued:?}"
    );
    let after_option = texts(r#"a="--x" m="p q""#);
    assert!(
        after_option.contains(&"m=\"p q\""),
        "the range cursor moves past the option string: {after_option:?}"
    );
    let after_request = texts(r#""GET /x HTTP/1.1" m="p q""#);
    assert!(
        after_request.contains(&"m=\"p q\""),
        "the request cursor moves past the request: {after_request:?}"
    );
    let stale = texts(r#"x "GET /a HTTP/1.1 "POST /b HTTP/1.1" y"#);
    assert!(
        stale.contains(&"/a") && stale.contains(&"/b"),
        "an unterminated request's stale boundary is cleared before the next request: {stale:?}"
    );
    let doubled = texts(r#"""GET /x HTTP/1.1" z""#);
    assert!(
        doubled.contains(&"/x"),
        "a doubled opening quote leaves every boundary consumed: {doubled:?}"
    );
}

#[test]
fn an_earlier_founder_keeps_its_later_last_member() {
    let mut f = make_folder_json();
    let stem = "svc node ready check pass level info region east";
    for tail in [
        "alpha state one",
        "beta state two",
        "delta state two",
        "beta state four",
        "gamma state one",
        "alpha state three",
    ] {
        f.process_line(&format!("{stem} {tail}")).unwrap();
    }
    assert_eq!(f.buffer.len(), 2, "two founders two words apart");
    let out = f.finish().unwrap();
    assert_eq!(out.len(), 1, "{out:?}");
    let record: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
    assert_eq!(record["count"], 6);
    assert_eq!(record["first"]["line_no"], 1);
    assert_eq!(record["last"]["line_no"], 6);
    assert_eq!(record["last"]["line"], format!("{stem} alpha state three"));
}

#[test]
fn briefing_counts_each_severity_and_logfmt_line() {
    let mut stats = FoldingStats::default();
    for level in ["fatal", "info", "debug", "trace"] {
        let tokens = vec![
            Token::LogWithModule {
                level: level.into(),
                module: "worker".into(),
            },
            Token::KeyValuePair {
                key: "job".into(),
                value_type: crate::patterns::ValueType::Number,
            },
            Token::KeyValuePair {
                key: "attempt".into(),
                value_type: crate::patterns::ValueType::Number,
            },
        ];
        stats.record_briefing_line(&tokens, "job=12 attempt=3");
        stats.record_briefing_line(&tokens, "job=13 attempt=4");
    }
    assert_eq!(stats.format_logfmt, 8);
    assert_eq!(stats.level_lines_with_level, 8);
    assert_eq!(stats.level_fatal, 2);
    assert_eq!(stats.level_info, 2);
    assert_eq!(stats.level_debug, 2);
    assert_eq!(stats.level_trace, 2);
}

#[test]
fn mac_occurrences_and_distinct_values_are_separate_counts() {
    let mut f = make_folder();
    for value in [
        "aa:bb:cc:dd:ee:01",
        "aa:bb:cc:dd:ee:02",
        "aa:bb:cc:dd:ee:01",
    ] {
        f.count_pattern_types(&[Token::Mac(value.into())]);
    }
    assert_eq!(f.stats.macs, 3);
    assert_eq!(
        f.stats.cardinality_for(StatsBucket::Macs),
        crate::briefing::Distinct::Exact(2)
    );
    assert_eq!(
        f.stats.cardinality_for(StatsBucket::Emails),
        crate::briefing::Distinct::Exact(0)
    );
}

#[test]
fn group_epoch_range_uses_both_member_timestamps() {
    let group = make_group(
        "event <TIMESTAMP>",
        vec![
            vec![Token::Timestamp("2024-01-01T00:00:00Z".into())],
            vec![Token::Timestamp("2024-01-01T00:00:07Z".into())],
        ],
    );
    assert_eq!(
        group_epoch_range(&group),
        (Some(1_704_067_200), Some(1_704_067_207))
    );
}
#[test]
fn json_variation_samples_are_complete_only_when_exact_and_all_present() {
    for (distinct_count, capped, complete) in
        [(1, false, true), (2, false, false), (1, true, false)]
    {
        let json = JsonVariationEntry::from(VariationEntry {
            distinct_count,
            samples: vec!["alpha".into()],
            capped,
            counts: None,
            slots: None,
        });
        assert_eq!(json.samples_complete, complete);
    }
}

#[test]
fn zero_numeric_tokens_hash_their_canonical_zero_digit() {
    let mut decimal = FNV_OFFSET;
    fnv1a_fold_decimal(&mut decimal, 0);
    let mut text = FNV_OFFSET;
    fnv1a_fold(&mut text, b"0");
    assert_eq!(decimal, text);
    assert_ne!(decimal, FNV_OFFSET);
}

#[test]
fn framed_continuations_add_to_input_and_saved_line_totals() {
    let mut f = make_folder_json();
    f.stats.total_lines = 7;
    f.stats.lines_saved = 2;
    let report = crate::ingest::IngestReport {
        fail_pattern_matched: false,
        overlong_lines_skipped: 0,
        continuation_lines_to_add_back: 3,
        max_lines_reached: false,
        complete_input_hash: None,
    };
    f.absorb_ingest_report(&report, 0);
    assert_eq!(f.stats.total_lines, 10);
    assert_eq!(f.stats.lines_saved, 5);
    f.absorb_ingest_report(&report, 0);
    assert_eq!(f.stats.total_lines, 13);
    assert_eq!(f.stats.lines_saved, 8);
}

#[test]
fn absorbed_continuation_lines_accumulate_apart_from_the_total() {
    let mut f = make_folder_json();
    let report = |n: usize| crate::ingest::IngestReport {
        fail_pattern_matched: false,
        overlong_lines_skipped: 0,
        continuation_lines_to_add_back: n,
        max_lines_reached: false,
        complete_input_hash: None,
    };
    assert_eq!(f.stats.continuation_lines_absorbed, 0);
    f.absorb_ingest_report(&report(3), 0);
    assert_eq!(f.stats.continuation_lines_absorbed, 3);
    f.absorb_ingest_report(&report(2), 0);
    assert_eq!(f.stats.continuation_lines_absorbed, 5);
    f.absorb_ingest_report(&report(0), 0);
    assert_eq!(f.stats.continuation_lines_absorbed, 5);
}

#[test]
fn input_degraded_codes_name_exactly_what_the_ingest_proved() {
    let mut f = make_folder_json();
    assert!(f.input_degraded_codes().is_empty());
    f.absorb_ingest_report(
        &crate::ingest::IngestReport {
            fail_pattern_matched: false,
            overlong_lines_skipped: 2,
            continuation_lines_to_add_back: 0,
            max_lines_reached: true,
            complete_input_hash: None,
        },
        1,
    );
    assert_eq!(
        f.input_degraded_codes(),
        vec![
            "input.overlong_lines_skipped",
            "input.max_lines_reached",
            "input.failed_sources"
        ]
    );
}

#[test]
fn fit_budget_equal_to_group_count_keeps_every_entry() {
    let mut f = make_folder_json();
    f.process_line("alpha").unwrap();
    f.process_line("bravo charlie delta").unwrap();
    let TopGroups {
        shown: out,
        total_groups: total,
        fit_truncated: truncated,
        ..
    } = f.finish_top_n(2, Some(2), false).unwrap();
    assert_eq!(total, 2);
    assert_eq!(out.len(), 2);
    assert_eq!(truncated, 0);
}
#[test]
fn converging_groups_from_one_batch_end_on_the_true_last_member() {
    let mut f = PatternFolder::new(Config {
        thread_count: None,
        output_format: OutputFormat::Json,
        ..Config::default()
    });
    let stem = "svc node ready check pass level info region east";
    for tail in [
        "alpha state one",
        "gamma state one",
        "alpha state three",
        "beta state two",
        "delta state two",
        "beta state four",
    ] {
        f.process_line(&format!("{stem} {tail}")).unwrap();
    }
    f.process_batch().unwrap();
    assert_eq!(f.buffer.len(), 2);
    assert!(
        f.buffer[0].position < f.buffer[1].position,
        "every batch line takes its own position, as it would one at a time"
    );
    assert_ne!(
        f.buffer[0].last_line_no, f.buffer[1].last_line_no,
        "every batch line carries its own line number"
    );
    let out = f.finish().unwrap();
    assert_eq!(out.len(), 1);
    let record: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
    assert_eq!(record["count"], 6);
    assert_eq!(record["last"]["line"], format!("{stem} beta state four"));
    assert_eq!(record["last"]["line_no"], 6);
}

#[test]
fn a_literal_marker_singleton_is_not_duplicated_when_another_source_converges() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 5,
        ..Config::default()
    });
    let stem = "svc node ready check pass level info region east";
    let literal = format!("{stem} <VARIES> state <VARIES>");
    f.process_line_at(&literal, Some(SourceId(1)), 5).unwrap();
    f.process_line_at(&format!("{stem} alpha state one"), Some(SourceId(2)), 1)
        .unwrap();
    f.process_line_at(&format!("{stem} gamma state one"), Some(SourceId(2)), 2)
        .unwrap();
    f.process_line_at(&format!("{stem} alpha state three"), Some(SourceId(2)), 3)
        .unwrap();
    let out = f.finish().unwrap();
    assert_eq!(
        out.iter()
            .flat_map(|s| s.lines())
            .filter(|line| *line == literal)
            .count(),
        1
    );
}

#[test]
fn an_option_identity_survives_a_positional_alignment_shift() {
    let edits = spans_of("a --x v", "--x v a");
    assert!(!edits.is_empty());
    assert!(
        edits.iter().all(|&(at, len)| at + len <= 2 || at >= 5),
        "{edits:?}"
    );
}

#[test]
fn an_option_shaped_suffix_after_pci_still_marks_its_changed_value() {
    let template = "dev 0000:21:00.0--x=1 up";
    let mut rendered = template.to_string();
    let edits = spans_of(template, "dev 0000:21:00.0--x=2 up");
    assert!(!edits.is_empty());
    for (at, len) in edits.into_iter().rev() {
        rendered.replace_range(at..at + len, VARIES_MARK);
    }
    assert_eq!(rendered, "dev 0000:21:00.0--x=<VARIES> up");
}

#[test]
fn finishing_json_groups_counts_every_emitted_record() {
    let mut f = make_folder_json();
    f.process_line("alpha").unwrap();
    f.process_line("bravo charlie delta").unwrap();
    let out = f.finish().unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(f.json_groups_emitted, out.len());
}

#[test]
fn distillation_keeps_converging_groups_separate_until_selection() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        group_sink: GroupSink::RecordDistillMembers {
            members_per_group: 1,
        },
        ..Config::default()
    });
    let stem = "svc node ready check pass level info region east";
    for tail in [
        "alpha state one",
        "gamma state one",
        "alpha state three",
        "beta state two",
        "delta state two",
        "beta state four",
    ] {
        f.process_line(&format!("{stem} {tail}")).unwrap();
    }
    assert_eq!(f.buffer.len(), 2);
    assert_eq!(f.buffer[0].template(), f.buffer[1].template());
    f.finish().unwrap();
    assert_eq!(f.distill_groups.len(), 2);
}

mod alignment_properties {
    use super::*;
    use proptest::collection::vec as pvec;
    use proptest::prelude::*;

    fn exact_with_path(left: &[&str], right: &[&str]) -> (Vec<Option<usize>>, Vec<isize>) {
        let (rows, cols) = (left.len(), right.len());
        let mut lcs = vec![vec![0usize; cols + 1]; rows + 1];
        for i in (0..rows).rev() {
            for j in (0..cols).rev() {
                lcs[i][j] = if left[i] == right[j] {
                    lcs[i + 1][j + 1] + 1
                } else {
                    lcs[i + 1][j].max(lcs[i][j + 1])
                };
            }
        }
        let mut out = vec![None; rows];
        let mut path = vec![0isize];
        let (mut i, mut j) = (0, 0);
        while i < rows && j < cols {
            if left[i] == right[j] {
                out[i] = Some(j);
                i += 1;
                j += 1;
            } else if lcs[i + 1][j] >= lcs[i][j + 1] {
                i += 1;
            } else {
                j += 1;
            }
            path.push(j as isize - i as isize);
        }
        (out, path)
    }

    fn arb_pair() -> impl Strategy<Value = (Vec<&'static str>, Vec<&'static str>)> {
        const WORDS: [&str; 3] = ["a", "b", "c"];
        (
            pvec(0..3usize, 0..24),
            pvec((0..3u8, any::<prop::sample::Index>(), 0..3usize), 0..5),
        )
            .prop_map(|(base, edits)| {
                let left: Vec<&str> = base.iter().map(|&w| WORDS[w]).collect();
                let mut right = left.clone();
                for (op, at, w) in edits {
                    let n = right.len();
                    match op {
                        0 => right.insert(at.index(n + 1), WORDS[w]),
                        1 if n > 0 => {
                            right.remove(at.index(n));
                        }
                        _ if n > 0 => right[at.index(n)] = WORDS[w],
                        _ => {}
                    }
                }
                (left, right)
            })
    }

    proptest! {
        #[test]
        fn banded_alignment_is_the_exact_one_whenever_its_path_fits(
            (left, right) in arb_pair(),
            band in 1..4usize,
        ) {
            prop_assume!(left.len().abs_diff(right.len()) <= band);
            let (exact, path) = exact_with_path(&left, &right);
            prop_assert_eq!(&align_exact(&left, &right), &exact);
            let d = right.len() as isize - left.len() as isize;
            let (lo, hi) = (d.min(0) - band as isize, d.max(0) + band as isize);
            let banded = align_banded(&left, &right, band);
            if path.iter().all(|k| (lo..=hi).contains(k)) {
                prop_assert_eq!(&banded, &exact);
            }
            let mut last = None;
            for (i, slot) in banded.iter().enumerate() {
                if let Some(j) = *slot {
                    prop_assert_eq!(left[i], right[j], "any band pairs only equal words");
                    prop_assert!(last.is_none_or(|l| j > l), "any band pairs words in order");
                    last = Some(j);
                }
            }
        }

        #[test]
        fn a_band_as_wide_as_the_table_is_the_exact_alignment((left, right) in arb_pair()) {
            let band = left.len().max(right.len()).max(1);
            prop_assert_eq!(align_banded(&left, &right, band), align_exact(&left, &right));
        }
    }
}

#[test]
fn a_line_joins_through_slots_only_in_quoted_values() {
    let joins = |template: &str, line: &str, threshold: u8| {
        joins_through_slots(
            template,
            &unit_spans(template),
            line,
            &unit_spans(line),
            threshold,
        )
    };
    let template =
        r#"attach volume <VARIES> src <VARIES> pod \"relay-<SUFFIX>\" uid (\"0f3c\") node n1"#;
    assert!(
        joins(
            template,
            r#"attach volume \"a\" src \"b\" pod \"relay-<SUFFIX>\" uid (\"0f3c\") node n1"#,
            83
        ),
        "the line differs from the template only under slots"
    );
    assert!(
        joins(
            template,
            r#"attach volume \"a\" src \"b\" pod \"cilium-<SUFFIX>\" uid (\"0f3c\") node n1"#,
            83
        ),
        "one quoted value more: 10 of 11 units agree"
    );
    assert!(
        joins(
            template,
            r#"attach volume \"a\" src \"b\" pod \"relay-<SUFFIX>\" uid (\"7a21\") node n1"#,
            83
        ),
        "a quoted value inside the same brackets still counts as a value"
    );
    let two = r#"attach volume \"a\" src \"b\" pod \"cilium-<SUFFIX>\" uid (\"7a21\") node n1"#;
    assert!(
        !joins(template, two, 84),
        "two quoted values more: 9 of 11 is under 84%"
    );
    assert!(
        joins(template, two, 80),
        "two quoted values more: 9 of 11 is over 80%"
    );
    assert!(
        !joins(
            template,
            r#"attach volume \"a\" src \"b\" pod \"relay-<SUFFIX>\" uid (\"0f3c\") node n2"#,
            50
        ),
        "a bare word is the sentence, never a value"
    );
    assert!(
        !joins(
            template,
            r#"attach volume \"a\" src \"b\" pod \"relay-<SUFFIX>\" uid \"0f3c\" node n1"#,
            50
        ),
        "the brackets around a quoted value are part of the shape"
    );
    assert!(
        joins("uid <VARIES>) ok", r#"uid \"x\") ok"#, 83),
        "under a slot a quoted value agrees, with what the slot keeps around it"
    );
    assert!(
        !joins("uid <VARIES>) ok", r#"uid \"x\" ok"#, 10),
        "the slot's kept ) is missing"
    );
    assert!(
        !joins("uid <VARIES> ok", "uid late ok", 10),
        "under a slot only a quoted value agrees"
    );
    assert!(
        !joins("msg=<VARIES> ok", "msg=late ok", 10),
        "under a slot only a quoted value agrees"
    );
    assert!(
        !joins(
            r#"{"file":<VARIES>,"reason":"bad_ext"} x y z"#,
            r#"{"file":"a.jpg","reason":"bad_body"} x y z"#,
            10
        ),
        "a JSON field is not a quoted value: its key is the sentence"
    );
    assert!(
        !joins(template, r#"attach volume \"a\" pod"#, 10),
        "a different unit count is never joined this way"
    );
}

#[test]
fn quoted_value_sets_aside_brackets_and_separators() {
    assert_eq!(quoted_value(r#""web-0""#), Some(("", "")));
    assert_eq!(quoted_value(r#"\"0f3c\")"#), Some(("", ")")));
    assert_eq!(quoted_value(r#"("web-0"),"#), Some(("(", "),")));
    assert_eq!(quoted_value(r#""""#), Some(("", "")));
    assert_eq!(quoted_value("\""), None);
    assert_eq!(quoted_value(r#"\""#), None);
    assert_eq!(quoted_value("web-0"), None);
    assert_eq!(quoted_value(r#""open"#), None);
    assert_eq!(quoted_value(r#""reason":"denied","#), None);
    assert_eq!(quoted_value(r#"\"a\"b\""#), None);
}

#[test]
fn first_difference_may_vary_reads_the_first_differing_word() {
    assert!(first_difference_may_vary(
        r#"T    P attach <VARIES> pod \"a\" ok"#,
        r#"T P attach \"x\" pod \"b\" ok"#
    ));
    assert!(first_difference_may_vary(
        r#"T attach "a b" ok"#,
        r#"T attach "a c" ok"#
    ));
    assert!(first_difference_may_vary(
        r#"msg "x y z" ok"#,
        r#"msg "x q z" ok"#
    ));
    assert!(!first_difference_may_vary(
        "T attach <VARIES> ok",
        "T detach <VARIES> ok"
    ));
    assert!(!first_difference_may_vary(r#"a "b" c"#, r#"a "b" d"#));
    assert!(first_difference_may_vary("a b", "a b c"));
}

#[test]
fn a_kept_prefix_the_member_carries_whole_stays_whole_without_a_delimiter() {
    assert_eq!(
        kept_affixes("ab", "", "abc"),
        (2, 0),
        "the member has the whole prefix and a byte more, so the prefix stays whole with no delimiter to cut back to"
    );
}

#[test]
fn a_kept_suffix_leaves_the_slot_at_least_one_byte_of_the_member() {
    assert_eq!(
        kept_affixes("a=", "bc", "a=bc"),
        (2, 1),
        "a= and bc would cover all of a=bc: the suffix gives back b"
    );
    assert_eq!(kept_affixes("a=", "x", "a=x"), (2, 0));
    assert_eq!(
        kept_affixes("f(", "x)", "f(ax)"),
        (2, 2),
        "with room to spare the whole suffix is compared from its end"
    );
}

#[test]
fn an_escaped_quote_after_an_opening_quote_leaves_that_quote_unpaired() {
    assert!(
        unpaired_quote(r#""a\""#, 0, 4),
        "the quote at 0 is unescaped and the one at 3 is escaped: an odd unescaped count"
    );
}

#[test]
fn a_slot_starting_at_an_escaped_quote_does_not_take_the_backslash_before_it() {
    assert_eq!(
        balance_quotes(r#"a\"b"#, r#"a\"xx\"b"#, 2, 0),
        (3, 0),
        "the backslash belongs to the kept prefix, and the quote joins it"
    );
}

#[test]
fn a_slot_whose_only_quote_opens_it_keeps_that_quote_in_the_prefix() {
    assert_eq!(
        balance_quotes(r#"x"ab"#, r#"x"zz"ab"#, 1, 0),
        (2, 0),
        "the quote opens the slot, so it is read from the opening side, not taken as a closer"
    );
}

#[test]
fn closers_after_a_closing_quote_stop_one_byte_short_of_the_template() {
    assert_eq!(
        balance_quotes(r#"k="))""#, r#"k="a)))""#, 3, 0),
        (3, 2),
        "the quote and one ) join the suffix; the other ) stays, as the slot may not be empty"
    );
}

#[test]
fn closers_after_a_closing_quote_stop_one_byte_short_of_the_member() {
    assert_eq!(balance_quotes(r#"k="a)))""#, r#"k="))""#, 3, 0), (3, 2));
}

#[test]
fn an_opening_quote_at_the_slot_end_is_not_kept_beside_it() {
    assert_eq!(
        balance_quotes(r#"k=v"]"#, r#"k=v"zz]"#, 2, 1),
        (2, 1),
        "keeping the quote would empty the slot, so the slot stays as it was"
    );
}

#[test]
fn an_opening_quote_is_kept_only_where_the_member_has_a_byte_after_it() {
    assert_eq!(
        balance_quotes(r#"k="ab]"#, r#"k="]"#, 2, 1),
        (2, 1),
        "k=\" kept with ] would leave the four-byte member nothing for the slot"
    );
    assert_eq!(
        balance_quotes(r#"k="ab]"#, r#"j="xyz]"#, 2, 1),
        (2, 1),
        "a member that does not open the same way keeps nothing more either"
    );
}

#[test]
fn a_whole_quoted_value_is_cut_after_its_field_delimiter() {
    assert_eq!(
        balance_quotes(r#"k="v1")"#, "k=v2)", 4, 1),
        (2, 1),
        "neither quote can stay beside the slot: it covers the whole quoted value and the suffix keeps )"
    );
}

#[test]
fn a_suffix_holding_the_partner_quote_is_given_up_to_the_slot() {
    assert_eq!(
        balance_quotes(r#"a"b""#, "x", 0, 1),
        (0, 0),
        "the quotes pair only once the slot takes the suffix"
    );
}

#[test]
fn units_in_a_gap_pair_in_order_when_both_sides_have_as_many() {
    let tmpl = ["a", "x", "y", "c"];
    let mem = ["a", "p", "q", "c"];
    let aligned = [Some(0), None, None, Some(3)];
    assert_eq!(
        unit_ranges(&tmpl, &mem, &aligned),
        UnitRanges {
            stands_for: vec![Some((0, 1)), Some((1, 2)), Some((2, 3)), Some((3, 4))],
            unshown: vec![]
        }
    );
}

#[test]
fn a_gap_at_the_end_of_the_template_reads_the_rest_of_the_member() {
    let tmpl = ["a", "x"];
    let mem = ["a", "p", "q"];
    assert_eq!(
        unit_ranges(&tmpl, &mem, &[Some(0), None]),
        UnitRanges {
            stands_for: vec![Some((0, 1)), Some((1, 3))],
            unshown: vec![]
        }
    );
}

#[test]
fn a_slot_that_loses_only_its_suffix_still_widens() {
    assert_eq!(
        marked("a slot[<VARIES>] c", "a slot[2 c"),
        "a slot[<VARIES> c"
    );
}

fn shifted_lines(left_len: usize, right_len: usize, shift: isize) -> (Vec<String>, Vec<String>) {
    let lead = |n: usize| (0..n).map(|i| format!("new{i}"));
    let word = |i: usize| format!("w{i}");
    let k = shift.unsigned_abs();
    if shift >= 0 {
        let left = (0..left_len).map(word).collect();
        let right = lead(k).chain((0..right_len - k).map(word)).collect();
        (left, right)
    } else {
        let left = lead(k).chain((0..left_len - k).map(word)).collect();
        let right = (0..right_len).map(word).collect();
        (left, right)
    }
}

#[test]
fn either_side_past_the_cap_makes_the_band_decide() {
    for (left_len, right_len, shift) in [
        (MAX_ALIGN_WORDS, MAX_ALIGN_WORDS + 4, 20),
        (MAX_ALIGN_WORDS + 4, MAX_ALIGN_WORDS, -20),
    ] {
        let (left, right) = shifted_lines(left_len, right_len, shift);
        let left: Vec<&str> = left.iter().map(String::as_str).collect();
        let right: Vec<&str> = right.iter().map(String::as_str).collect();
        let banded = align_banded(&left, &right, ALIGN_BAND);
        assert_ne!(
            banded,
            align_exact(&left, &right),
            "the exact path lies outside the band, so the two disagree"
        );
        assert_eq!(align_words(&left, &right), banded, "{left_len} {right_len}");
    }
}

#[test]
fn a_side_exactly_at_the_cap_is_still_aligned_exactly() {
    let (left, right) = shifted_lines(MAX_ALIGN_WORDS - 6, MAX_ALIGN_WORDS, 20);
    let left: Vec<&str> = left.iter().map(String::as_str).collect();
    let right: Vec<&str> = right.iter().map(String::as_str).collect();
    let exact = align_exact(&left, &right);
    assert_eq!(exact[0], Some(20));
    assert_ne!(exact, align_banded(&left, &right, ALIGN_BAND));
    assert_eq!(align_words(&left, &right), exact);
}

#[test]
fn a_path_on_the_edge_of_the_band_is_inside_it() {
    let (left, right) = shifted_lines(30, 30, ALIGN_BAND as isize);
    let left: Vec<&str> = left.iter().map(String::as_str).collect();
    let right: Vec<&str> = right.iter().map(String::as_str).collect();
    let exact = align_exact(&left, &right);
    assert_eq!(exact[0], Some(ALIGN_BAND));
    assert_eq!(align_banded(&left, &right, ALIGN_BAND), exact);
}

#[test]
fn each_slot_of_a_multi_slot_marker_is_listed_once_and_comma_separated() {
    let entry = |s: &str| VariationEntry {
        distinct_count: 1,
        samples: vec![s.to_string()],
        capped: false,
        counts: Some(vec![2]),
        slots: None,
    };
    let mut rollup = BTreeMap::new();
    rollup.insert(
        VARIES,
        VariationEntry {
            distinct_count: 2,
            samples: vec!["a".into(), "b".into()],
            capped: false,
            counts: Some(vec![2, 2]),
            slots: Some(vec![entry("a"), entry("b")]),
        },
    );
    assert_eq!(
        render_compact_marker(10, &rollup, None, None, 3),
        "[+10 similar | varies×1 {a×2}, varies×1 {b×2}]"
    );
}

#[test]
fn a_count_only_type_at_its_cap_is_capped_only_by_a_new_value() {
    let rc = RollupComputer::with_defaults();
    let stamps = |n: usize| -> Vec<Vec<Token>> {
        (0..n)
            .map(|i| vec![Token::Timestamp(format!("ts-{i:04}"))])
            .collect()
    };
    let mut lines = stamps(ROLLUP_DISTINCT_CAP);
    lines.push(vec![Token::Timestamp("ts-0000".into())]);
    let entry = rc.compute(&make_group("<TIMESTAMP> beat", lines))["TIMESTAMP"].clone();
    assert_eq!(entry.distinct_count, ROLLUP_DISTINCT_CAP);
    assert!(!entry.capped, "a repeat at the cap needs no room");
    let entry = rc.compute(&make_group(
        "<TIMESTAMP> beat",
        stamps(ROLLUP_DISTINCT_CAP + 1),
    ))["TIMESTAMP"]
        .clone();
    assert_eq!(entry.distinct_count, ROLLUP_DISTINCT_CAP);
    assert!(entry.capped, "a new value past the cap does");
}

fn plain_line(s: &str) -> LogLine {
    LogLine::new(s.into(), s.into(), Vec::new(), seed_for_group(s))
}

#[test]
fn a_group_holds_every_member_below_and_past_min_collapse() {
    let text = "cache warm pass done";
    let mut group = PatternGroup::new(plain_line(text), 0);
    for line_no in 1..6 {
        group.add_line(plain_line(text), line_no);
        assert_eq!(group.lines.len(), group.count);
    }
    assert_eq!(group.count, 6);
}

#[test]
fn absorbing_two_full_groups_past_min_collapse_keeps_every_member() {
    let text = "cache warm pass done";
    let mut group = PatternGroup::new(plain_line(text), 0);
    group.add_line(plain_line(text), 1);
    let mut other =
        PatternGroup::new_at(plain_line(text), 1, LineLocation::new(SourceId::STDIN, 5));
    other.add_line(plain_line(text), 6);
    group.absorb(other);
    assert_eq!(group.count, 4);
    assert_eq!(group.lines.len(), 4);
}

#[test]
fn a_line_joins_a_group_through_its_slots_only_under_the_same_anchor() {
    let mut group = PatternGroup::new(make_line("mount <VARIES> done", vec![]), 0);
    group.slot_units = Some(unit_spans(&group.template));
    let line = make_line(r#"mount "vol-a" done"#, vec![]);
    assert!(group.joins_through_slots(&line, &mut None, 83));
    let mut elsewhere = line.clone();
    elsewhere.anchor = 7;
    assert!(!group.joins_through_slots(&elsewhere, &mut None, 83));
}

#[test]
fn a_line_with_more_units_than_the_template_never_joins_through_slots() {
    assert!(!joins_through_slots(
        "a b",
        &unit_spans("a b"),
        "a b c",
        &unit_spans("a b c"),
        0
    ));
}

#[test]
fn a_json_group_carries_its_timeline_on_the_log_wide_grid() {
    let mut f = make_folder_json();
    for minute in 0..40 {
        f.process_line(&format!(
            "2026-03-04T10:{minute:02}:00Z INFO poller heartbeat ok from node-3"
        ))
        .unwrap();
    }
    let out = f.finish().unwrap();
    let record: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
    let range = &record["time_range"];
    assert!(
        range["bucket_seconds"].as_i64().is_some_and(|s| s > 0),
        "{range}"
    );
    let buckets = range["buckets"].as_array().expect("buckets");
    assert_eq!(
        buckets.iter().map(|b| b.as_u64().unwrap()).sum::<u64>(),
        40,
        "{range}"
    );
}

#[test]
fn a_template_without_a_slot_holds_only_for_its_own_words() {
    assert!(template_holds("worker ready now", "worker ready now"));
    assert!(!template_holds("worker ready now", "worker ready later"));
    assert!(!template_holds("worker ready now", "worker ready"));
}

#[test]
fn a_bare_slot_stands_for_any_word_or_none() {
    assert!(template_holds("worker <VARIES> ready", "worker c3 ready"));
    assert!(template_holds("worker <VARIES> ready", "worker ready"));
    assert!(!template_holds("worker <VARIES> ready", "worker c3 done"));
}

#[test]
fn a_member_word_the_template_does_not_show_breaks_the_claim() {
    assert!(
        !template_holds("worker <VARIES> ready", "worker c3 ready now"),
        "a template that hides a member word is as false as one that names a word the member lacks"
    );
    assert!(!template_holds("worker ready", "worker is ready"));
    assert!(!template_holds("[ -f <PATH> ]", "[ ! -f <PATH> ]"));
}

#[test]
fn a_bare_slot_shows_a_run_of_words_or_none() {
    assert!(template_holds(
        "worker <VARIES> ready",
        "worker is now ready"
    ));
    assert!(template_holds("worker ready <VARIES>", "worker ready"));
    assert!(template_holds(
        "worker ready <VARIES>",
        "worker ready at 10:00"
    ));
    assert!(template_holds("<VARIES> worker ready", "now worker ready"));
}

#[test]
fn a_slot_with_kept_text_shows_no_word_outside_its_run() {
    assert!(!template_holds("x q=[<VARIES>] done", "x q=[a b] c done"));
    assert!(!template_holds("x q=[<VARIES>] done", "x w q=[a b] done"));
    assert!(
        template_holds("x q=[<VARIES>] done", "x q=[a] done"),
        "a run that starts and ends in one word"
    );
}

#[test]
fn the_templates_words_are_on_the_member_in_the_templates_order() {
    assert!(!template_holds("alpha beta", "beta alpha"));
    assert!(!template_holds("alpha <VARIES> beta", "beta c3 alpha"));
}

#[test]
fn text_kept_beside_a_slot_is_part_of_the_claim() {
    assert!(template_holds("x msg=<VARIES> y", "x msg=hello y"));
    assert!(template_holds("x msg=<VARIES> y", "x msg= y"));
    assert!(!template_holds("x msg=<VARIES> y", "x text=hello y"));
    assert!(template_holds("x [<VARIES>] y", "x [a1] y"));
    assert!(!template_holds("x [<VARIES>] y", "x [a1 y"));
    assert!(
        !template_holds("x ab<VARIES>bc y", "x abc y"),
        "the member is shorter than the kept text on both sides together"
    );
}

#[test]
fn a_slot_with_kept_text_may_stand_for_several_words() {
    assert!(template_holds("x q=[<VARIES>] done", "x q=[a b c] done"));
    assert!(!template_holds("x q=[<VARIES>] done", "x q=[a b c done"));
    assert!(
        !template_holds("x q=[<VARIES>] done", "x done q=[a b c]"),
        "the words after the slot's last one are still checked, in order"
    );
}

#[test]
fn a_template_holds_when_it_reads_true_character_by_character() {
    let template = r#"{"req":"put >> <VARIES>,"size":"22"}"#;
    let member = r#"{"req":"put >> range > >>","size":"22"}"#;
    assert!(
        template_holds(template, member),
        "the slot swallowed a quote, so the units differ, but read as text the template is true"
    );
    assert!(!template_holds(
        template,
        r#"{"req":"put >> range > >>","size":"23"}"#
    ));
    assert!(reads_as("a <VARIES> c <VARIES> e", "a b c d e"));
    assert!(!reads_as("a <VARIES> c <VARIES> e", "a b d c"));
    assert!(!reads_as("a <VARIES> c", "b a c"));
    assert!(reads_as("abc", "abc"));
    assert!(!reads_as("abc", "abcd"));
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "the template does not hold for the line that joined")]
fn a_line_its_groups_template_is_false_of_stops_a_test_build() {
    let mut group = PatternGroup::new(make_line("user alice@test.com logged in", vec![]), 1);
    group.add_line(make_line("user bob@test.com logged in", vec![]), 2);
}

fn spans_of(template: &str, member: &str) -> Vec<(usize, usize)> {
    template_edits(template, member)
        .expect("the member can be shown")
        .into_iter()
        .map(|edit| match edit {
            Edit::Vary { at, len } => (at, len),
            Edit::Open { at, .. } => (at, 0),
            Edit::Respace { at, len, .. } => (at, len),
        })
        .collect()
}

#[test]
fn a_word_only_a_later_member_has_opens_a_slot_where_it_sits() {
    let mut f = make_folder();
    for l in [
        "+ [ -f /etc/a.conf ]",
        "+ [ -f /etc/b.conf ]",
        "+ [ ! -f /etc/c.conf ]",
    ] {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 1);
    assert_eq!(f.buffer[0].template(), "+ [ <VARIES> -f <PATH> ]");
    let r = f.rollup_computer.compute(&f.buffer[0]);
    assert_eq!(r[VARIES].samples, vec![ABSENT, "!"]);
    assert_eq!(r[VARIES].counts, Some(vec![2, 1]));
}

#[test]
fn a_run_of_extra_words_is_one_slot() {
    assert_eq!(marked("a b c", "a x y b c"), "a <VARIES> b c");
    assert_eq!(spans_of("a b c", "a x y b c"), vec![(1, 0)]);
}

#[test]
fn extra_words_before_the_first_unit_open_a_slot_in_front() {
    assert_eq!(marked("a b", "x a b"), "<VARIES> a b");
    assert_eq!(
        marked("a b", "x,a b"),
        "<VARIES> a b",
        "written with a space: the members without the words have no comma there"
    );
}

#[test]
fn extra_words_past_the_last_unit_open_a_slot_at_the_end() {
    assert_eq!(marked("a b", "a b c d"), "a b <VARIES>");
}

#[test]
fn an_opened_slot_leaves_the_template_one_separator_where_its_members_have_one() {
    assert_eq!(
        marked(r#"{"a":1,"c":3}"#, r#"{"a":1,"b":2,"c":3}"#),
        r#"{"a":1 <VARIES> "c":3}"#,
        "neither gap beside the slot keeps a comma, whichever member came first"
    );
}

#[test]
fn a_slot_anchored_in_a_gap_leaves_the_words_after_it_to_a_slot_of_their_own() {
    assert_eq!(
        marked("a <VARIES> k=<VARIES> c", "a y k=1 z c"),
        "a <VARIES> k=<VARIES> <VARIES> c",
        "k= anchors on k=1, and nothing else shows the z after it"
    );
}

#[test]
fn a_lone_unit_in_a_gap_keeps_the_affixes_it_shares_with_its_counterpart() {
    assert_eq!(
        marked("a [x:error] b c", "a [y:error] b c d"),
        "a [<VARIES>] b c <VARIES>",
        "the unit counts differ, but one unit on each side of the gap pairs as an aligned pair would"
    );
}

#[test]
fn two_long_lines_too_unlike_to_align_call_for_no_edit() {
    let words: Vec<String> = (0..300).map(|i| format!("w{i}")).collect();
    let template = words.join(" ");
    let longer = format!("{template} {}", words[..=ALIGN_BAND].join(" "));
    assert_eq!(template_edits(&template, &longer), None);
}

#[test]
fn a_slot_opens_only_where_the_run_is_set_apart_on_both_lines() {
    let open = |at: usize, text: &str| {
        Some(Edit::Open {
            at,
            unit_with_separator: text.to_string(),
        })
    };
    let member = ("a b c", [(0, 1), (2, 1), (4, 1)]);
    assert_eq!(
        slot_opening("abcdefg", &[(0, 3), (3, 4)], member.0, &member.1, 1, (1, 2)),
        None,
        "template units 0 and 1 touch: nowhere to put a unit between them"
    );
    assert_eq!(
        slot_opening(
            "abc defg",
            &[(0, 3), (4, 4)],
            member.0,
            &member.1,
            1,
            (1, 2)
        ),
        open(3, " <VARIES>")
    );
    let template = ("a c", [(0, 1), (2, 1)]);
    assert_eq!(
        slot_opening(
            template.0,
            &template.1,
            "ab c",
            &[(0, 1), (1, 1), (3, 1)],
            1,
            (1, 2)
        ),
        None,
        "the run touches the member unit before it"
    );
    assert_eq!(
        slot_opening(
            template.0,
            &template.1,
            "a bc",
            &[(0, 1), (2, 1), (3, 1)],
            1,
            (1, 2)
        ),
        None,
        "the run touches the member unit after it"
    );
    assert_eq!(
        slot_opening("a", &[(0, 1)], "x;a", &[(0, 1), (2, 1)], 0, (0, 1)),
        open(0, "<VARIES>;"),
        "in front of the first unit nothing needs a gap"
    );
    assert_eq!(
        slot_opening("a", &[(0, 1)], "a;x", &[(0, 1), (2, 1)], 1, (1, 2)),
        open(1, ";<VARIES>"),
        "past the last unit nothing needs a gap"
    );
    assert_eq!(
        slot_opening("a", &[(0, 1)], "x", &[(0, 1)], 0, (0, 1)),
        open(0, "<VARIES> "),
        "a run that is the whole member has no separator of its own to use"
    );
    assert_eq!(
        slot_opening("a", &[(0, 1)], "x", &[(0, 1)], 1, (0, 1)),
        open(1, " <VARIES>")
    );
    assert_eq!(
        slot_opening("", &[], "x", &[(0, 1)], 0, (0, 1)),
        None,
        "an empty template has no unit to open a slot beside"
    );
}

#[test]
fn an_opened_slot_takes_the_separators_of_its_gap_with_it() {
    assert_eq!(
        slot_opening("a {}", &[(0, 1)], "a {x}", &[(0, 1), (3, 1)], 1, (1, 2)),
        Some(Edit::Respace {
            at: 1,
            len: 3,
            with: format!(" {VARIES_MARK}")
        }),
        "past the last unit the gap's braces go, as they would from the member that has x"
    );
    assert_eq!(
        marked("GRPC response: {}", r#"GRPC response: {"size":7}"#),
        "GRPC response: <VARIES>"
    );
    assert_eq!(
        marked(r#"GRPC response: {"size":7}"#, "GRPC response: {}"),
        "GRPC response: <VARIES>",
        "the same template in the other order"
    );
    assert_eq!(
        marked("{a}", "{x,a}"),
        "<VARIES> a}",
        "in front of the first unit the leading brace goes too"
    );
    assert_eq!(marked("{x,a}", "{a}"), "<VARIES> a}");
    assert_eq!(marked("{a}", "x{a}"), "<VARIES> a}");
}

#[test]
fn a_full_scan_counts_an_opened_slot_as_absent_for_the_members_without_it() {
    for texts in [
        [
            "worker alpha ready on n1",
            "worker alpha ready on n2",
            "worker alpha ready now on n1",
            "worker alpha ready on n1",
        ],
        [
            "worker alpha ready on n1",
            "worker alpha ready on n1",
            "worker alpha ready on n2",
            "worker alpha ready now on n1",
        ],
    ] {
        let computer = RollupComputer::with_defaults();
        let mut full = PatternGroup::new(plain_line(texts[0]), 0);
        for (i, text) in texts.iter().enumerate().skip(1) {
            full.add_line(plain_line(text), i);
        }
        assert_eq!(full.template, "worker alpha ready <VARIES> on <VARIES>");
        let rollup = computer.compute(&full);
        assert_eq!(
            rollup[VARIES].slots.as_ref().unwrap()[0].samples,
            vec![ABSENT, "now"],
            "{texts:?}"
        );
    }
}

const GLUED: [&str; 3] = [
    "pci slot 0000:21:00.0 link is up and ready for traffic now",
    "pci slot 0000:21:00.0 link is up and ready for traffic now",
    "pci slot x-0000:21:00.0 link is up and ready for traffic now",
];

#[test]
fn a_line_whose_extra_word_cannot_open_a_slot_founds_its_own_group() {
    let mut f = make_folder();
    for l in GLUED {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 2);
    assert_eq!(f.buffer[0].count(), 2);
    assert_eq!(f.buffer[0].template(), f.buffer[0].first().normalized);
}

#[test]
fn a_line_equal_to_the_founder_calls_for_no_edit() {
    let mut group = PatternGroup::new(plain_line("a <VARIES> c"), 0);
    group.template = "a <VARIES>".into();
    assert_eq!(
        group.edits_for(&plain_line("a <VARIES> c")),
        Some(Vec::new())
    );
}

#[test]
fn every_member_unit_is_shown_read_unit_by_unit() {
    assert!(
        shows_every_unit("x msg=<VARIES> y", "x msg=hello y"),
        "the unit reading alone, without the character reading beside it"
    );
    assert!(!shows_every_unit("x msg=<VARIES> y", "x text=hello y"));
    assert!(
        !shows_every_unit("x ab<VARIES>b y", "x ab y"),
        "the kept text on both sides needs room in one word, overlapping none"
    );
    assert!(
        shows_every_unit("x q=[<VARIES>] done", "x q=[a] done"),
        "a run of one unit"
    );
    assert!(
        shows_every_unit("x q=[<VARIES>] done", "x q=[a b c] done"),
        "a run of several units"
    );
    assert!(shows_every_unit("q=[<VARIES>] done", "q=[a b] done"));
    assert!(!shows_every_unit("x q=[<VARIES>] done", "x q=[a b] c done"));
    assert!(!shows_every_unit("x q=[<VARIES>]", "x q=[a b] c"));
    assert!(
        shows_every_unit("a <VARIES> b", "a b"),
        "a bare slot shows any run or none"
    );
    assert!(shows_every_unit("a <VARIES> b", "a x y b"));
    assert!(shows_every_unit("a <VARIES>", "a x y"));
    assert!(
        !shows_every_unit("a b", "a b c"),
        "nothing past the template's end is shown"
    );
    assert!(!shows_every_unit("a b", "a"));
}

#[test]
fn a_collapsed_group_of_tokenless_lines_writes_the_bare_similar_marker() {
    let mut f = make_folder();
    for _ in 0..3 {
        f.process_line("hello world").unwrap();
    }
    assert_eq!(
        f.finish().unwrap(),
        vec!["hello world\n[+1 similar]\nhello world".to_string()],
        "a group whose rollup is empty has no tokens to name, so its marker is bare"
    );
}

#[test]
fn a_summary_run_saves_what_top_n_and_the_default_run_save() {
    let lines: Vec<String> = (0..20)
        .map(|i| format!("error connecting to 10.0.0.{i} timeout"))
        .chain(["a line of its own".to_string()])
        .collect();
    let fed = || {
        let mut f = make_folder();
        for line in &lines {
            f.process_line(line).unwrap();
        }
        f
    };
    let saved = |f: &PatternFolder| {
        let s = f.build_stats_json(Duration::ZERO);
        (s.lines_saved, s.collapsed_groups)
    };
    let mut default_run = fed();
    default_run.finish().unwrap();
    let mut top = fed();
    top.finish_top_n(TOP_SHOWS_EVERY_GROUP, None, false)
        .unwrap();
    let mut summary = fed();
    summary
        .finish_summary(
            &SummaryRequest {
                top_n: None,
                fit_budget: None,
                max_width: None,
            },
            &IngestReport::default(),
            0,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();
    assert_eq!(
        saved(&summary),
        saved(&default_run),
        "--summary --stats-json must agree with the default run"
    );
    assert_eq!(
        saved(&summary),
        saved(&top),
        "--summary --stats-json must agree with --top N"
    );
}

#[test]
fn the_summary_coverage_counts_records_read_before_the_ingest_report_adds_continuations() {
    let mut f = make_folder();
    for word in ["alpha", "beta", "gamma", "delta"] {
        f.process_line(&format!("{word} finished")).unwrap();
    }
    let report = IngestReport {
        continuation_lines_to_add_back: 6,
        ..IngestReport::default()
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    f.finish_summary(
        &SummaryRequest {
            top_n: Some(TOP_SHOWS_EVERY_GROUP),
            fit_budget: None,
            max_width: None,
        },
        &report,
        0,
        &mut out,
        &mut err,
    )
    .unwrap();
    let err = String::from_utf8(err).unwrap();
    assert!(
        err.contains("4 of 4 lines"),
        "the coverage line counts the 4 records read, not the 10 input lines: {err}"
    );
    assert_eq!(
        f.stats.total_lines, 10,
        "the statistics count the continuation lines, absorbed after the summary"
    );
    assert_eq!(String::from_utf8(out).unwrap().lines().count(), 4);
}

#[test]
fn stats_json_is_one_line_holding_the_built_stats() {
    let f = make_folder();
    let mut buf = Vec::new();
    f.print_stats_json(Duration::from_millis(7), &mut buf)
        .unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(text.ends_with('\n'), "one JSON line: {text}");
    assert_eq!(text.lines().count(), 1, "one JSON line: {text}");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["elapsed_ms"], 7, "{v}");
}

#[test]
fn a_markdown_entry_is_marked_folded_exactly_when_its_group_collapsed() {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        output_format: OutputFormat::Markdown,
        ..Config::default()
    });
    for _ in 0..3 {
        f.process_line("hello world").unwrap();
    }
    f.process_line("a+b is similar to c").unwrap();
    let entries = f.finish_markdown().unwrap();
    let mut buf = Vec::new();
    f.emit_markdown(&entries, &mut buf).unwrap();
    let doc = String::from_utf8(buf).unwrap();
    assert!(doc.contains("### Entry 1 (Folded)"), "{doc}");
    assert!(
        !doc.contains("### Entry 2 (Folded)"),
        "a line that only says + and similar did not collapse: {doc}"
    );
}

#[test]
fn explain_annotates_records_and_changes_no_group() {
    let lines = [
        "worker 1 started job alpha",
        "worker 2 started job beta",
        "worker 3 started job gamma",
        "cache miss for key users",
        "cache miss for key orders",
        "disk full on volume data",
    ];
    let run = |explain: bool| {
        let mut f = PatternFolder::new(Config {
            thread_count: Some(1),
            output_format: OutputFormat::Json,
            explain,
            ..Config::default()
        });
        for line in lines {
            f.process_line(line).unwrap();
        }
        f.finish()
            .unwrap()
            .iter()
            .map(|record| {
                let mut v: serde_json::Value = serde_json::from_str(record).unwrap();
                v.as_object_mut().unwrap().remove("nearest");
                v
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        run(true),
        run(false),
        "--explain is read-only diagnostics: folding is unchanged"
    );
}

fn folder_fed_three_groups() -> PatternFolder {
    let mut f = PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    });
    let groups = [
        ("disk full on volume data", 6),
        ("connection reset by remote peer", 5),
        ("scheduler queue drained completely", 4),
    ];
    for (line, times) in groups {
        for _ in 0..times {
            f.process_line(line).unwrap();
        }
    }
    f
}

#[test]
fn a_top_limit_does_not_change_lines_saved_or_compression_ratio() {
    let mut every_group = folder_fed_three_groups();
    let _ = every_group.finish().unwrap();
    let mut top_one = folder_fed_three_groups();
    let TopGroups { shown, .. } = top_one.finish_top_n(1, None, false).unwrap();
    assert_eq!(shown.len(), 1, "the limit leaves groups unshown");

    let full = every_group.build_stats_json(Duration::ZERO);
    let limited = top_one.build_stats_json(Duration::ZERO);
    assert_eq!(full.lines_saved, (6 - 3) + (5 - 3) + (4 - 3));
    assert_eq!(
        limited.lines_saved, full.lines_saved,
        "every group of the fold counts toward lines_saved, shown or not"
    );
    assert!(
        (limited.compression_ratio - full.compression_ratio).abs() < f64::EPSILON,
        "compression_ratio is the same with and without --top"
    );
}

#[test]
fn a_summary_top_limit_does_not_change_lines_saved() {
    let mut every_row = folder_fed_three_groups();
    let SummaryRows { display, .. } = every_row.prepare_summary(Some(0), None).unwrap();
    every_row.account_summary(&display);
    let mut top_one = folder_fed_three_groups();
    let SummaryRows { display, .. } = top_one.prepare_summary(Some(1), None).unwrap();
    assert_eq!(display.len(), 1, "the limit leaves rows unshown");
    top_one.account_summary(&display);

    assert_eq!(every_row.stats.lines_saved, (6 - 3) + (5 - 3) + (4 - 3));
    assert_eq!(
        top_one.stats.lines_saved, every_row.stats.lines_saved,
        "every summary row counts toward lines_saved, shown or not"
    );
}

const START_ON_NODE: [&str; 4] = [
    r#"failed to start "db" on node "n1""#,
    r#"failed to start "cache" on node "n2""#,
    r#"failed to start "db" on node "n2""#,
    r#"failed to start "cache" on node "n1""#,
];

fn every_order(lines: &[&'static str]) -> Vec<Vec<&'static str>> {
    if lines.len() <= 1 {
        return vec![lines.to_vec()];
    }
    let mut orders = Vec::new();
    for (i, &head) in lines.iter().enumerate() {
        let mut rest = lines.to_vec();
        rest.remove(i);
        for mut tail in every_order(&rest) {
            tail.insert(0, head);
            orders.push(tail);
        }
    }
    orders
}

fn assert_one_group_in_every_order(lines: &[&'static str], orders_expected: usize) {
    let orders = every_order(lines);
    assert_eq!(orders.len(), orders_expected);
    for order in orders {
        let mut f = make_folder();
        for line in &order {
            f.process_line(line).unwrap();
        }
        assert_eq!(
            f.buffer.len(),
            1,
            "a line both slots cover joins whatever the order: {order:?}"
        );
        assert_eq!(
            f.buffer[0].count(),
            lines.len(),
            "the one group holds every line: {order:?}"
        );
        assert_eq!(f.buffer[0].lines.len(), lines.len());
    }
}

#[test]
fn three_lines_two_quoted_slots_fold_to_one_group_in_every_order() {
    assert_one_group_in_every_order(&START_ON_NODE[..3], 6);
}

#[test]
fn four_lines_two_quoted_slots_fold_to_one_group_in_every_order() {
    assert_one_group_in_every_order(&START_ON_NODE, 24);
}

#[test]
fn a_slot_inside_a_quoted_value_keeps_the_words_every_member_shares() {
    assert_eq!(
        marked(
            r#"reply response="count:0 ok" key=alpha"#,
            r#"reply response="count:12 ok" key=alpha"#
        ),
        r#"reply response="count:<VARIES> ok" key=alpha"#
    );
    assert_eq!(
        marked(
            r#"reply response="0 ok" key=alpha"#,
            r#"reply response="12 ok" key=alpha"#
        ),
        r#"reply response="<VARIES> ok" key=alpha"#,
        "both quotes and the shared word stay on the line"
    );
    assert_eq!(
        marked(
            r#"reply response="count:<VARIES> ok" key=alpha"#,
            r#"reply response="count:7 bad" key=alpha"#
        ),
        r#"reply response="count:<VARIES>" key=alpha"#,
        "a member that ends the value in another word keeps only the closing quote"
    );
    assert_eq!(shared_affixes(r#"r="0 ok""#, r#"r="12 ok""#), (2, 4));
    assert_eq!(
        kept_affixes("r=\"", " ok\"", "r=\"5 ok\""),
        (3, 4),
        "a member that shares the whole kept tail keeps it"
    );
    assert_eq!(
        kept_affixes("r=\"", " a ok\"", "r=\"5 b ok\""),
        (2, 4),
        "a partly shared tail keeps the words the member shares"
    );
    assert_eq!(
        kept_affixes("r=\"", " ok\"", "r=\"5 xok\""),
        (2, 0),
        "a tail shared only part-way into a word is cut back to the start of a word"
    );
    assert_eq!(
        kept_affixes("slot[", "\"]", "slot[2]"),
        (5, 1),
        "a tail with no word in it still keeps its closing brackets"
    );
}

#[test]
fn single_word_units_and_unquoted_words_fold_as_before() {
    assert_eq!(
        marked("reply count:0 key=alpha", "reply count:12 key=alpha"),
        "reply count:<VARIES> key=alpha"
    );
    assert_eq!(
        marked(
            "reply (count:0 size:5 ok) key=alpha",
            "reply (count:12 size:5 ok) key=alpha"
        ),
        "reply (count:<VARIES> size:5 ok) key=alpha",
        "unquoted words are units of their own"
    );
}

#[test]
fn a_unit_a_member_lacks_takes_the_separator_the_member_lacks_with_it() {
    assert_eq!(
        marked("sync done x a=1, b=2 took 5", "sync done x a=1 took 5"),
        "sync done x a=1 <VARIES> took 5"
    );
    assert_eq!(
        marked(
            "got peers=node-1,node-2,node-3 ok",
            "got peers=node-1,node-2 ok"
        ),
        "got peers=node-1,node-2 <VARIES> ok"
    );
    assert_eq!(
        marked("set a=1, b=2, c=3 done", "set a=1, c=3 done"),
        "set a=1 <VARIES> c=3 done",
        "neither gap beside the slot keeps its comma"
    );
    assert_eq!(
        marked(r#"{"a":1,"b":2,"c":3}"#, r#"{"a":1,"c":3}"#),
        r#"{"a":1 <VARIES> "c":3}"#
    );
    assert_eq!(
        marked("set a=1, b=2, c=3, d=4 done", "set a=1 d=4 done"),
        "set a=1 <VARIES> <VARIES> d=4 done",
        "no comma is left beside the slots of a run of lacking units"
    );
    assert_eq!(
        marked("set a=1, <VARIES> took 5", "set a=1 took 5"),
        "set a=1 <VARIES> took 5",
        "a slot a member lacks loses the comma the member lacks"
    );
}

#[test]
fn an_opened_slot_has_no_separator_the_members_without_it_lack() {
    assert_eq!(
        marked("set a=1, c=3 done", "set a=1, b=2, c=3 done"),
        "set a=1 <VARIES> c=3 done"
    );
    assert_eq!(
        marked(
            "got peers=node-1,node-2 ok",
            "got peers=node-1,node-2,node-3 ok"
        ),
        "got peers=node-1,node-2 <VARIES> ok"
    );
    assert_eq!(marked("a,b", "a,b,c"), "a,b <VARIES>");
}

#[test]
fn a_separator_beside_a_slot_a_member_lacks_is_a_false_claim() {
    assert!(!template_holds(
        "sync done x a=1, <VARIES> took 5",
        "sync done x a=1 took 5"
    ));
    assert!(template_holds(
        "sync done x a=1, <VARIES> took 5",
        "sync done x a=1, b=2 took 5"
    ));
    assert!(template_holds(
        "sync done x a=1 <VARIES> took 5",
        "sync done x a=1 took 5"
    ));
    assert!(!template_holds(
        "set a=1, <VARIES>, c=3 done",
        "set a=1, c=3 done"
    ));
    assert!(template_holds(
        "set a=1 <VARIES>, c=3 done",
        "set a=1, c=3 done"
    ));
    assert!(template_holds(
        "set a=1 <VARIES>, c=3 done",
        "set a=1, b=2, c=3 done"
    ));
    assert!(!template_holds(
        "got peers=node-1,node-2,<VARIES> ok",
        "got peers=node-1,node-2 ok"
    ));
    assert!(!template_holds("<VARIES>,a b", "a b"));
}

#[test]
fn a_word_glued_to_a_unit_is_refused_whichever_line_founded_the_group() {
    let plain = "pci slot 0000:41:00.0 link up";
    let glued_before = "pci slot x-0000:41:00.0 link up";
    let glued_after = "pci slot 0000:41:00.0-x link up";
    assert_eq!(template_edits(plain, glued_before), None);
    assert_eq!(template_edits(glued_before, plain), None);
    assert_eq!(template_edits(plain, glued_after), None);
    assert_eq!(template_edits(glued_after, plain), None);
}

#[test]
fn a_glued_word_absent_with_the_unit_it_is_glued_to_still_varies() {
    assert!(template_edits("a x-0000:41:00.0 b", "a b").is_some());
    assert!(template_edits("a 0000:41:00.0-x b", "a b").is_some());
}

#[test]
fn a_bare_slot_glued_to_a_unit_may_stand_for_nothing() {
    assert_eq!(
        template_edits("a <VARIES>0000:41:00.0 b", "a 0000:41:00.0 b"),
        Some(Vec::new())
    );
}

#[test]
fn a_glued_founder_keeps_the_plain_lines_apart_in_reversed_order() {
    let mut f = make_folder();
    for l in [
        "pci slot x-0000:41:00.0 link is up and ready for traffic now",
        "pci slot 0000:41:00.0 link is up and ready for traffic now",
        "pci slot 0000:41:00.0 link is up and ready for traffic now",
    ] {
        f.process_line(l).unwrap();
    }
    assert_eq!(f.buffer.len(), 2);
    assert_eq!(f.buffer[0].count(), 1);
    assert_eq!(f.buffer[1].count(), 2);
}
