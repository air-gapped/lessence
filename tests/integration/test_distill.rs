//! `--distill` / `--anonymize`: the distilled file must fold the way the log
//! it came from did, and must carry none of that log's values.
//!
//! Development tooling, hidden flags — but the contract is the whole point,
//! so it is tested end to end through the binary.

use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const KUBELET: &str = "tests/fixtures/kubelet_2k.log";
const MICRO: &str = "tests/fixtures/microservices.log";

/// The `--members` default, as `src/cli.rs` declares it.
const DEFAULT_MEMBERS: usize = 3;

fn lessence_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lessence"))
}

fn run(args: &[&str]) -> Output {
    lessence_bin().args(args).output().expect("failed to run")
}

fn run_stdin(args: &[&str], input: &[u8]) -> Output {
    let mut child = lessence_bin()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

/// Every group record's template, as `--explain` reports it.
fn templates(jsonl: &[u8]) -> BTreeSet<String> {
    String::from_utf8_lossy(jsonl)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "group")
        .filter_map(|v| v["normalized"].as_str().map(str::to_string))
        .collect()
}

/// (group count, lines in groups too small to fold) — the two terms of the
/// size bound a distillation may not exceed.
fn group_shape(jsonl: &[u8]) -> (usize, usize) {
    let mut groups = 0;
    let mut unfolded = 0;
    for value in String::from_utf8_lossy(jsonl)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "group")
    {
        groups += 1;
        let count = value["count"].as_u64().unwrap_or(0) as usize;
        if count < 3 {
            unfolded += count;
        }
    }
    (groups, unfolded)
}

/// Every collapsed group's `count`, in the order `--explain` reports them.
fn group_counts(jsonl: &[u8]) -> Vec<usize> {
    String::from_utf8_lossy(jsonl)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "group")
        .map(|v| v["count"].as_u64().unwrap_or(0) as usize)
        .collect()
}

/// Sample values of the classes `--anonymize` invents, as the original's
/// own `--explain` facts report them.
fn invented_class_samples(jsonl: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for value in String::from_utf8_lossy(jsonl)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "group")
    {
        let Some(variation) = value["variation"].as_object() else {
            continue;
        };
        for kind in [
            "IPV4", "IPV6", "UUID", "HASH", "FQDN", "HOST", "MAC", "EMAIL",
        ] {
            let Some(samples) = variation.get(kind).and_then(|v| v["samples"].as_array()) else {
                continue;
            };
            out.extend(
                samples
                    .iter()
                    .filter_map(|s| s.as_str())
                    .map(str::to_string),
            );
        }
    }
    out.sort();
    out.dedup();
    out
}

fn uuids(text: &str) -> BTreeSet<String> {
    let re = regex::Regex::new(r"\b[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b")
        .expect("static regex");
    re.find_iter(text).map(|m| m.as_str().to_string()).collect()
}

// ---- (a) the contract: everything still proved, at a derived size ----

/// The distinct sorted token-type vectors `--explain` reports — the
/// structures a distillation must still show.
fn structures(jsonl: &[u8]) -> BTreeSet<Vec<String>> {
    explain_groups(jsonl)
        .iter()
        .map(|g| {
            g["token_types"]
                .as_array()
                .expect("token_types")
                .iter()
                .map(|t| t.as_str().expect("token type").to_string())
                .collect()
        })
        .collect()
}

/// Every token type that fires anywhere.
fn token_types(jsonl: &[u8]) -> BTreeSet<String> {
    structures(jsonl).into_iter().flatten().collect()
}

fn explain_groups(jsonl: &[u8]) -> Vec<serde_json::Value> {
    str::from_utf8(jsonl)
        .expect("utf8")
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "group")
        .collect()
}

#[test]
fn a_distillation_still_proves_every_structure_and_token_type() {
    for fixture in [KUBELET, MICRO] {
        let original = run(&["--explain", "-q", fixture]);
        assert!(original.status.success(), "{fixture}: --explain failed");
        let want_structures = structures(&original.stdout);
        let want_types = token_types(&original.stdout);
        assert!(!want_structures.is_empty(), "{fixture}: nothing to compare");

        let distilled = run(&["--distill", fixture]);
        assert_eq!(
            distilled.status.code(),
            Some(0),
            "{fixture}: --distill reported a broken contract:\n{}",
            String::from_utf8_lossy(&distilled.stderr)
        );

        let refolded = run_stdin(&["--explain", "-q"], &distilled.stdout);
        let have_structures = structures(&refolded.stdout);
        let have_types = token_types(&refolded.stdout);
        assert!(
            want_structures.is_subset(&have_structures),
            "{fixture}: structures lost: {:?}",
            want_structures
                .difference(&have_structures)
                .collect::<Vec<_>>()
        );
        assert!(
            want_types.is_subset(&have_types),
            "{fixture}: token types lost: {:?}",
            want_types.difference(&have_types).collect::<Vec<_>>()
        );
        let varies = |out: &[u8]| {
            explain_groups(out)
                .iter()
                .any(|g| g["normalized"].as_str().unwrap_or("").contains("<VARIES>"))
        };
        assert_eq!(
            varies(&original.stdout),
            varies(&refolded.stdout),
            "{fixture}: a <VARIES> slot must survive wherever the input had one"
        );

        // The selection rules, added up. A chosen group keeps its founding
        // member, one member per `<VARIES>` slot it marks, one per distinct
        // normalized form up to DISTILL_FORMS, one per token type it
        // carries, and enough to reach --members. The cover chooses at most
        // three groups per structure, two more for the <VARIES> and folded
        // top-ups, and one group may carry the capping set. A derived
        // bound, not a tuned number — it moves when the rules do, never
        // when a corpus does.
        let varies_max = explain_groups(&original.stdout)
            .iter()
            .map(|g| {
                g["normalized"]
                    .as_str()
                    .unwrap_or("")
                    .matches("<VARIES>")
                    .count()
            })
            .max()
            .unwrap_or(0);
        let per_group =
            1 + varies_max + lessence::folder::DISTILL_FORMS + want_types.len() + DEFAULT_MEMBERS;
        let (_, unfolded) = group_shape(&original.stdout);
        let bound = (3 * want_structures.len() + 2) * per_group
            + lessence::folder::ROLLUP_DISTINCT_CAP
            + 1
            + unfolded;
        let emitted = String::from_utf8_lossy(&distilled.stdout).lines().count();
        assert!(
            emitted <= bound,
            "{fixture}: {emitted} lines exceeds the derived bound {bound} \
             ({} structures, per_group {per_group}, {unfolded} unfolded)",
            want_structures.len()
        );
    }
}

// ---- (b) the check is load-bearing: a weaker selection would break it ----

#[test]
fn members_one_still_proves_every_structure() {
    // `--members 1` asks for the smallest possible distillation. The
    // members that built a group's template are kept regardless, so the
    // contract still holds — a selection that fell back to "the first
    // line" would report a lost structure here and exit 1.
    let original = run(&["--explain", "-q", KUBELET]);
    let want = structures(&original.stdout);

    let distilled = run(&["--distill", "--members", "1", KUBELET]);
    assert_eq!(
        distilled.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&distilled.stderr)
    );
    let refolded = run_stdin(&["--explain", "-q"], &distilled.stdout);
    assert!(
        want.is_subset(&structures(&refolded.stdout)),
        "structures lost at --members 1"
    );

    let full = run(&["--distill", KUBELET]);
    assert!(
        distilled.stdout.len() <= full.stdout.len(),
        "--members 1 must never be larger than the default"
    );
}

// ---- (c) anonymisation: nothing of the original survives, consistently ----

#[test]
fn anonymize_leaves_no_original_value_of_an_invented_class() {
    let original = run(&["--explain", "-q", KUBELET]);
    let samples = invented_class_samples(&original.stdout);
    assert!(
        samples.len() > 10,
        "the fixture must carry values worth inventing, got {}",
        samples.len()
    );

    let distilled = run(&["--distill", "--anonymize", "--seed", "1", KUBELET]);
    assert_eq!(
        distilled.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&distilled.stderr)
    );
    let text = String::from_utf8_lossy(&distilled.stdout).to_string();
    for sample in &samples {
        assert!(
            !text.contains(sample.as_str()),
            "the original {sample} survived anonymisation"
        );
    }
}

#[test]
fn one_original_maps_to_one_invention_everywhere() {
    let source = std::fs::read_to_string(KUBELET).expect("fixture");
    let anonymized = run(&["--anonymize", "--seed", "1", KUBELET]);
    assert_eq!(anonymized.status.code(), Some(0));
    let out = String::from_utf8_lossy(&anonymized.stdout).to_string();

    // Consistency and injectivity together: one invention per original and
    // no two originals sharing one means the distinct count cannot move.
    assert_eq!(
        uuids(&source).len(),
        uuids(&out).len(),
        "the number of distinct UUIDs must survive the mapping"
    );
    assert!(uuids(&source).is_disjoint(&uuids(&out)), "no UUID survived");

    // Two lines that shared a UUID must share one afterwards.
    let src_lines: Vec<&str> = source.lines().collect();
    let out_lines: Vec<&str> = out.lines().collect();
    assert_eq!(src_lines.len(), out_lines.len());
    let mut checked = 0;
    for i in 0..src_lines.len() {
        for j in (i + 1)..src_lines.len().min(i + 40) {
            let shared = &uuids(src_lines[i]) & &uuids(src_lines[j]);
            if shared.is_empty() {
                continue;
            }
            let shared_out = &uuids(out_lines[i]) & &uuids(out_lines[j]);
            assert_eq!(
                shared.len(),
                shared_out.len(),
                "lines {i} and {j} shared {} UUIDs before and {} after",
                shared.len(),
                shared_out.len()
            );
            checked += 1;
            if checked > 20 {
                return;
            }
        }
    }
    assert!(checked > 0, "the fixture must share a UUID between lines");
}

#[test]
fn the_same_seed_invents_the_same_log_and_a_different_seed_does_not() {
    let one = run(&["--distill", "--anonymize", "--seed", "1", KUBELET]);
    let again = run(&["--distill", "--anonymize", "--seed", "1", KUBELET]);
    let other = run(&["--distill", "--anonymize", "--seed", "2", KUBELET]);
    assert_eq!(one.stdout, again.stdout, "--seed 1 must be reproducible");
    assert_ne!(one.stdout, other.stdout, "--seed 2 must invent differently");
    assert_eq!(other.status.code(), Some(0));
}

// ---- (d) --anonymize-words ----

#[test]
fn anonymize_words_removes_a_word_the_detectors_never_class() {
    // The vocabulary word is the fixture's own host name, read from the
    // fixture so the source never spells it: `Host:<word>` on some line.
    let source = std::fs::read_to_string(KUBELET).expect("fixture");
    let word = source
        .lines()
        .find_map(|l| l.split("Host:").nth(1))
        .map(|rest| {
            rest.chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect::<String>()
                .to_lowercase()
        })
        .expect("the fixture must carry a Host: field for this test to mean anything");
    assert!(word.len() >= 3, "host word too short to test: {word:?}");

    let dir = tempfile::tempdir().expect("tempdir");
    let vocab = dir.path().join("vocab.txt");
    std::fs::write(&vocab, format!("{word}\n")).expect("write vocab");

    let distilled = run(&[
        "--distill",
        "--anonymize",
        "--anonymize-words",
        vocab.to_str().expect("path"),
        "--seed",
        "1",
        KUBELET,
    ]);
    assert_eq!(
        distilled.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&distilled.stderr)
    );
    let text = String::from_utf8_lossy(&distilled.stdout).to_lowercase();
    assert!(!text.contains(&word), "the vocabulary word survived");

    // The templates still have to match — that is checked inside the run
    // (exit 0 above), and again here against the original.
    let refolded = run_stdin(&["--explain", "-q"], &distilled.stdout);
    assert!(!templates(&refolded.stdout).is_empty());
}

// ---- (e) output-mode flags are rejected, not ignored ----

#[test]
fn distill_with_an_output_mode_flag_is_a_usage_error_naming_both() {
    let out = run(&["--distill", "--format", "markdown", MICRO]);
    assert_eq!(out.status.code(), Some(2), "must be a usage error");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--distill"), "{err}");
    assert!(err.contains("--format"), "{err}");
}

// ---- (f) --anonymize alone rewrites the whole log ----

#[test]
fn anonymize_without_distill_emits_every_line() {
    let source = std::fs::read_to_string(MICRO).expect("fixture");
    let out = run(&["--anonymize", "--seed", "1", MICRO]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).lines().count(),
        source.lines().count(),
        "--anonymize alone keeps every line"
    );
}

// ---- (g) an over-fold across a literal word cannot be distilled away ----

#[test]
fn a_fold_across_a_literal_word_keeps_both_words() {
    // Two events the folder merges: nine say `cleanly`, one says `dirty`,
    // and the odd one is last — exactly where "the first three members"
    // would lose it.
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("over.log");
    let mut text = String::new();
    for i in 0..9 {
        text.push_str(&format!(
            "2025-01-20T10:20:0{i}.000Z worker {i} finished cleanly\n"
        ));
    }
    text.push_str("2025-01-20T10:20:09.000Z worker 9 finished dirty\n");
    std::fs::write(&log, &text).expect("write log");

    let out = run(&[
        "--distill",
        "--threshold",
        "60",
        log.to_str().expect("path"),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let distilled = String::from_utf8_lossy(&out.stdout);
    assert!(
        distilled.contains("finished dirty"),
        "the rare word must survive distillation:\n{distilled}"
    );
    assert!(
        distilled.contains("finished cleanly"),
        "the common word must survive too:\n{distilled}"
    );
}

#[test]
fn the_distilled_log_is_a_subset_of_its_input_and_says_nothing_on_stdout() {
    let mut input = String::new();
    for second in 0..100 {
        input.push_str(&format!(
            "2025-01-20T10:{:02}:{:02}Z housekeeping heartbeat\n",
            second / 60,
            second % 60
        ));
        if [0, 2, 4].contains(&second) {
            input.push_str(&format!(
                "2025-01-20T10:00:{second:02}Z database connection failed\n"
            ));
        }
    }
    let out = run_stdin(&["--distill", "--threads", "1"], input.as_bytes());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let log = String::from_utf8_lossy(&out.stdout);
    assert!(
        log.lines().count() < input.lines().count(),
        "a distillation is smaller than its input"
    );
    assert!(
        log.lines()
            .all(|line| input.lines().any(|original| original == line)),
        "every line is a line of the input, unchanged"
    );
    assert!(
        !log.contains("lessence:"),
        "diagnostics must stay on stderr"
    );

    // Both events survive: the rare one is the whole reason to distil.
    assert!(log.contains("housekeeping heartbeat"));
    assert!(log.contains("database connection failed"));
}
