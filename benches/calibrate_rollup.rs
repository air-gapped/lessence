//! Phase 5 calibration harness (NOT a criterion bench).
//!
//! A one-shot binary that runs lessence across the Tier 1 + Tier 2 +
//! Tier 3 corpus with `distinct_cap = usize::MAX` and records the
//! distribution of per-group distinct_count values per token type. The
//! output is a report used to retire three `PLACEHOLDER_*` constants:
//!
//! - `PLACEHOLDER_DISTINCT_CAP`: set to the smallest power-of-two ≥
//!   P99 of observed distinct_count on sample-worthy token types.
//! - `PLACEHOLDER_K`: set to the smallest K where P95 of distinct_count
//!   on sample-worthy types is captured. Capped at 8 (terminal width).
//! - `PLACEHOLDER_TEXT_SAMPLE_THRESHOLD`: set to the largest T where
//!   P99 of rendered text-marker length stays under 120 chars.
//!
//! Run with:
//!   cargo bench --bench calibrate_rollup
//!
//! Output is written to stdout as a Markdown report (committed as
//! `docs/rollup-calibration.md` after review).
//!
//! This bench is registered with `harness = false` so criterion is not
//! involved — we're collecting statistics, not timing code.

use lessence::normalize::Normalizer;
use lessence::patterns::{LogLine, Token};
use lessence::{Config, PatternFolder};
use std::collections::BTreeMap;

/// Full corpus across all three tiers. Missing files are skipped
/// gracefully so the harness works on a partial checkout.
const CORPUS: &[&str] = &[
    // Tier 1
    "examples/kubelet.log",
    "examples/argocd_controller_production.log",
    "examples/harbor_postgres_primary.log",
    "examples/openssh_brute_force.log",
    "examples/apache_error_production.log",
    "examples/nginx_sample.log",
    // Tier 2
    "examples/epyc_7days_journalctl.log",
    // Tier 3 — manual sweep corpus
    "examples/cilium_full.log",
    "examples/argocd_server_production.log",
    "examples/apiserver_production.log",
    "examples/harbor_postgres_replica.log",
    "examples/linux_auditd.log",
    "examples/linux_auth_secure.log",
    "examples/vllm_embedding_production.log",
    "examples/rancher_production.log",
    "examples/security_attacks.log",
    "examples/kubectl_events.log",
    "examples/hdfs_sample.log",
];

/// Token-type classification — must stay in sync with `is_sample_worthy`
/// in `src/folder.rs`. The calibration distinguishes these because
/// we only care about sample-worthy types when picking K and the cap.
#[allow(dead_code)] // Reference copy of the production classifier; kept in sync.
fn is_sample_worthy(token: &Token) -> bool {
    matches!(
        token,
        Token::Uuid(_)
            | Token::IPv4(_)
            | Token::IPv6(_)
            | Token::Path(_)
            | Token::Email(_)
            | Token::Hash(_, _)
            | Token::KubernetesNamespace(_)
            | Token::VolumeName(_)
            | Token::PluginType(_)
            | Token::PodName(_)
            | Token::QuotedString(_)
            | Token::Name(_)
            | Token::HttpStatus(_)
            | Token::HttpStatusClass(_)
            | Token::BracketContext(_)
            | Token::Json(_)
    )
}

fn token_type_name(token: &Token) -> &'static str {
    match token {
        Token::Timestamp(_) => "TIMESTAMP",
        Token::IPv4(_) => "IPV4",
        Token::IPv6(_) => "IPV6",
        Token::Port(_) => "PORT",
        Token::Hash(_, _) => "HASH",
        Token::Uuid(_) => "UUID",
        Token::Pid(_) => "PID",
        Token::ThreadID(_) => "THREAD_ID",
        Token::Path(_) => "PATH",
        Token::Json(_) => "JSON",
        Token::Duration(_) => "DURATION",
        Token::Size(_) => "SIZE",
        Token::Number(_) => "NUMBER",
        Token::HttpStatus(_) => "HTTP_STATUS",
        Token::QuotedString(_) => "QUOTED_STRING",
        Token::Name(_) => "NAME",
        Token::KubernetesNamespace(_) => "K8S_NAMESPACE",
        Token::VolumeName(_) => "K8S_VOLUME",
        Token::PluginType(_) => "K8S_PLUGIN",
        Token::PodName(_) => "K8S_POD",
        Token::HttpStatusClass(_) => "HTTP_STATUS_CLASS",
        Token::BracketContext(_) => "BRACKET_CONTEXT",
        Token::KeyValuePair { .. } => "KEY_VALUE",
        Token::LogWithModule { .. } => "LOG_WITH_MODULE",
        Token::StructuredMessage { .. } => "STRUCTURED_MESSAGE",
        Token::Email(_) => "EMAIL",
    }
}

fn token_value_string(token: &Token) -> String {
    match token {
        Token::Timestamp(s)
        | Token::IPv4(s)
        | Token::IPv6(s)
        | Token::Uuid(s)
        | Token::Path(s)
        | Token::Json(s)
        | Token::Duration(s)
        | Token::Size(s)
        | Token::Number(s)
        | Token::QuotedString(s)
        | Token::Name(s)
        | Token::KubernetesNamespace(s)
        | Token::VolumeName(s)
        | Token::PluginType(s)
        | Token::PodName(s)
        | Token::ThreadID(s)
        | Token::HttpStatusClass(s)
        | Token::Email(s) => s.clone(),
        Token::Hash(_, s) => s.clone(),
        Token::BracketContext(parts) => parts.join(","),
        Token::Port(p) => p.to_string(),
        Token::HttpStatus(s) => s.to_string(),
        Token::Pid(p) => p.to_string(),
        Token::KeyValuePair { key, value_type } => format!("{key}={value_type}"),
        Token::LogWithModule { level, module } => format!("{level}:{module}"),
        Token::StructuredMessage { component, level } => format!("{component}:{level}"),
    }
}

/// Process a file through lessence with single-threaded config and
/// collect the per-group, per-token-type distinct-value lists.
/// Groups are identified by normalized template.
fn collect_distinct_per_group(
    path: &str,
) -> Option<Vec<BTreeMap<&'static str, Vec<String>>>> {
    let content = std::fs::read_to_string(path).ok()?;

    // First pass: build groups via PatternFolder (so grouping matches
    // production behaviour). But we can't introspect PatternGroup from
    // the outside since it's private. Instead, re-normalize lines and
    // group them by exact normalized text — an approximation that's
    // close to lessence's similarity clustering in practice for typical
    // logs (most groups are built from identical-normalized lines).
    let config = Config {
        thread_count: Some(1),
        ..Default::default()
    };
    let normalizer = Normalizer::new(config.clone());

    // Group index -> per-type distinct value list
    let mut groups: BTreeMap<String, BTreeMap<&'static str, Vec<String>>> =
        BTreeMap::new();

    for line in content.lines() {
        let log_line: LogLine = match normalizer.normalize_line(line.to_string()) {
            Ok(l) => l,
            Err(_) => continue,
        };
        let key = log_line.normalized.clone();
        let entry = groups.entry(key).or_default();
        for token in &log_line.tokens {
            let name = token_type_name(token);
            let value = token_value_string(token);
            entry.entry(name).or_default().push(value);
        }
    }

    // Convert to Vec and deduplicate values per entry.
    // We keep only unique values here (distinct count). For
    // performance we deduplicate via sort+dedup rather than HashSet
    // since the eval corpus is bounded.
    let mut out: Vec<BTreeMap<&'static str, Vec<String>>> = Vec::new();
    for (_key, mut per_type) in groups {
        for values in per_type.values_mut() {
            values.sort();
            values.dedup();
        }
        out.push(per_type);
    }
    // Prevent dead_code warnings on fields only used through iteration.
    let _ = PatternFolder::new(config);
    Some(out)
}

fn percentile(sorted: &[usize], p: f64) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len() as f64;
    let index = ((n - 1.0) * p).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let mut p = 1usize;
    while p < n {
        p <<= 1;
    }
    p
}

fn main() {
    println!("# Rollup Calibration Report");
    println!();
    println!("Generated by `cargo bench --bench calibrate_rollup`.");
    println!();
    println!("This report measures the distribution of per-group");
    println!("`distinct_count` values across the full Tier 1 + Tier 2 +");
    println!("Tier 3 corpus. The three `PLACEHOLDER_*` constants in");
    println!("`src/folder.rs` are retired with values derived from these");
    println!("distributions.");
    println!();

    // Per-token-type distributions across all groups in all files.
    let mut per_type_counts: BTreeMap<&'static str, Vec<usize>> = BTreeMap::new();
    let mut files_processed = 0usize;
    let mut files_skipped = 0usize;
    let mut total_groups = 0usize;

    for path in CORPUS {
        match collect_distinct_per_group(path) {
            Some(groups) => {
                files_processed += 1;
                total_groups += groups.len();
                for per_type in groups {
                    for (name, values) in per_type {
                        let distinct = values.len();
                        per_type_counts.entry(name).or_default().push(distinct);
                    }
                }
            }
            None => {
                files_skipped += 1;
                eprintln!("(skipped: {path} not available)");
            }
        }
    }

    println!("## Corpus coverage");
    println!();
    println!("- Files processed: {files_processed}");
    println!("- Files skipped (gitignored/missing): {files_skipped}");
    println!("- Total unique groups observed: {total_groups}");
    println!();

    // Per-type percentiles table
    println!("## Per-token-type distinct_count distribution");
    println!();
    println!("Percentiles are computed over ALL observed (group, token_type) pairs");
    println!("across the corpus. Higher cardinality types (UUID, HASH, IPV4 on");
    println!("request-heavy logs) dominate the tail.");
    println!();
    println!("| Token type | Count | P50 | P90 | P95 | P99 | Max |");
    println!("|---|---|---|---|---|---|---|");

    let mut all_sample_worthy_distinct: Vec<usize> = Vec::new();

    for (name, counts) in &mut per_type_counts {
        counts.sort_unstable();
        let n = counts.len();
        let p50 = percentile(counts, 0.50);
        let p90 = percentile(counts, 0.90);
        let p95 = percentile(counts, 0.95);
        let p99 = percentile(counts, 0.99);
        let max = counts.last().copied().unwrap_or(0);
        println!("| {name} | {n} | {p50} | {p90} | {p95} | {p99} | {max} |");

        // Accumulate sample-worthy types for the global cap pick.
        // We check by name here to avoid holding real tokens.
        const SAMPLE_WORTHY_NAMES: &[&str] = &[
            "UUID",
            "IPV4",
            "IPV6",
            "PATH",
            "EMAIL",
            "HASH",
            "K8S_NAMESPACE",
            "K8S_VOLUME",
            "K8S_PLUGIN",
            "K8S_POD",
            "QUOTED_STRING",
            "NAME",
            "HTTP_STATUS",
            "HTTP_STATUS_CLASS",
            "BRACKET_CONTEXT",
            "JSON",
        ];
        if SAMPLE_WORTHY_NAMES.contains(name) {
            all_sample_worthy_distinct.extend(counts.iter());
        }
    }

    println!();
    println!("## DISTINCT_CAP calibration");
    println!();
    all_sample_worthy_distinct.sort_unstable();
    let global_p95 = percentile(&all_sample_worthy_distinct, 0.95);
    let global_p99 = percentile(&all_sample_worthy_distinct, 0.99);
    let global_max = all_sample_worthy_distinct.last().copied().unwrap_or(0);
    let cap_recommendation = next_power_of_two(global_p99);
    println!("Across **sample-worthy** token types on the full corpus:");
    println!();
    println!("- P95: {global_p95}");
    println!("- P99: {global_p99}");
    println!("- Max observed: {global_max}");
    println!();
    println!("**Recommended `DISTINCT_CAP = {cap_recommendation}`** (smallest power-of-two ≥ P99).");
    println!();

    println!("## K (samples per token type) calibration");
    println!();
    let k_candidate = global_p95.min(8); // Cap at 8 for terminal width
    println!("K is the max number of sample values surfaced per token type in");
    println!("JSON mode. Setting K to the P95 of distinct_count on sample-worthy");
    println!("types ensures most groups get their COMPLETE distinct set shown");
    println!("(nothing hidden), while the terminal-width ceiling of 8 bounds the");
    println!("text marker when it falls through to inline samples.");
    println!();
    println!("**Recommended `K = {k_candidate}`** (min of P95={global_p95} and terminal cap=8).");
    println!();

    // TEXT_SAMPLE_THRESHOLD: for each candidate T in {2,3,4,5,6,8}, count
    // groups where the inline-sample render would exceed 120 chars. Pick
    // the largest T where P99 of rendered length ≤ 120.
    println!("## TEXT_SAMPLE_THRESHOLD calibration");
    println!();
    println!("The text-mode compact marker inlines the full distinct set when");
    println!("`distinct_count <= T`. For each candidate T we measure what");
    println!("fraction of marker lines would exceed a 120-char terminal width.");
    println!();
    println!("| T | Groups where marker ≤ 120 | Groups where marker > 120 | Pass rate |");
    println!("|---|---|---|---|");
    // We can't easily simulate the full marker render here without
    // recreating PatternFolder. Approximate: estimate marker length as
    // 50 + sum(len(name)+3 + sum(sample_lens + 2 for samples ≤ T)).
    // The 50 accounts for fixed overhead ([+N similar | ts→ts |]).
    // This is a rough estimate; Phase 5 could refine via direct
    // instrumentation if the approximation is too loose.
    // For Phase 5 we report a conservative ceiling.
    let mut recommended_threshold: usize = 3;
    for t in [2usize, 3, 4, 5, 6, 8] {
        let mut pass = 0usize;
        let mut fail = 0usize;
        for per_type in per_type_counts.values() {
            // Per token type, estimate contribution to the marker line.
            // Short-circuit on type count only; avoid sample-value
            // length which we don't have here.
            let estimated_marker_len = 50
                + per_type.iter().filter(|&&c| c <= t).count() * 20
                + per_type.iter().filter(|&&c| c > t).count() * 12;
            if estimated_marker_len <= 120 {
                pass += 1;
            } else {
                fail += 1;
            }
        }
        let total = pass + fail;
        let rate = if total > 0 {
            pass as f64 / total as f64 * 100.0
        } else {
            0.0
        };
        println!("| {t} | {pass} | {fail} | {rate:.1}% |");
        if rate >= 99.0 {
            recommended_threshold = t;
        }
    }
    println!();
    println!("**Recommended `TEXT_SAMPLE_THRESHOLD = {recommended_threshold}`**");
    println!(
        "  (largest T with ≥99% of markers fitting in 120 chars; estimate from type-count heuristic)."
    );
    println!();

    println!("## Final calibrated values");
    println!();
    println!("```rust");
    println!("const PLACEHOLDER_K: usize = {k_candidate};");
    println!("const PLACEHOLDER_DISTINCT_CAP: usize = {cap_recommendation};");
    println!("const PLACEHOLDER_TEXT_SAMPLE_THRESHOLD: usize = {recommended_threshold};");
    println!("```");
    println!();
    println!("Applied in `src/folder.rs` in the same commit that retires the");
    println!("`PLACEHOLDER_*` naming prefix.");
}
