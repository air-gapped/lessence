use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const KUBELET: &str = "tests/fixtures/kubelet_2k.log";
const MICRO: &str = "tests/fixtures/microservices.log";

const DEFAULT_MEMBERS_AS_SRC_CLI_DECLARES: usize = 3;
const MIN_FOLDED_GROUP_COUNT: usize = 3;
const ANONYMIZE_INVENTED_CLASSES: [&str; 8] = [
    "IPV4", "IPV6", "UUID", "HASH", "FQDN", "HOST", "MAC", "EMAIL",
];

fn lessence_bin() -> Command {
    crate::common::lessence()
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

fn templates(jsonl: &[u8]) -> BTreeSet<String> {
    String::from_utf8_lossy(jsonl)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "group")
        .filter_map(|v| v["normalized"].as_str().map(str::to_string))
        .collect()
}

fn group_count_and_unfolded_lines(jsonl: &[u8]) -> (usize, usize) {
    let mut groups = 0;
    let mut unfolded = 0;
    for value in String::from_utf8_lossy(jsonl)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "group")
    {
        groups += 1;
        let count = value["count"].as_u64().unwrap_or(0) as usize;
        if count < MIN_FOLDED_GROUP_COUNT {
            unfolded += count;
        }
    }
    (groups, unfolded)
}

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
        for kind in ANONYMIZE_INVENTED_CLASSES {
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
        let founding_member = 1;
        let one_per_varies_slot = varies_max;
        let one_per_distinct_form = lessence::folder::DISTILL_FORMS;
        let one_per_token_type = want_types.len();
        let per_group = founding_member
            + one_per_varies_slot
            + one_per_distinct_form
            + one_per_token_type
            + DEFAULT_MEMBERS_AS_SRC_CLI_DECLARES;
        let cover_groups_per_structure = 3;
        let varies_and_folded_top_up_groups = 2;
        let capping_set = lessence::folder::ROLLUP_DISTINCT_CAP + 1;
        let (_, unfolded) = group_count_and_unfolded_lines(&original.stdout);
        let derived_bound = (cover_groups_per_structure * want_structures.len()
            + varies_and_folded_top_up_groups)
            * per_group
            + capping_set
            + unfolded;
        let emitted = String::from_utf8_lossy(&distilled.stdout).lines().count();
        assert!(
            emitted <= derived_bound,
            "{fixture}: {emitted} lines exceeds the derived bound {derived_bound} \
             ({} structures, per_group {per_group}, {unfolded} unfolded)",
            want_structures.len()
        );
    }
}

#[test]
fn members_one_still_proves_every_structure() {
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
        "structures lost at --members 1: the members that built a group's template are kept regardless"
    );

    let full = run(&["--distill", KUBELET]);
    assert!(
        distilled.stdout.len() <= full.stdout.len(),
        "--members 1 must never be larger than the default"
    );
}

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

    assert_eq!(
        uuids(&source).len(),
        uuids(&out).len(),
        "the number of distinct UUIDs must survive the mapping: one invention per original, \
         no two originals sharing one"
    );
    assert!(uuids(&source).is_disjoint(&uuids(&out)), "no UUID survived");

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

#[test]
fn anonymize_words_removes_a_word_the_detectors_never_class() {
    let source = std::fs::read_to_string(KUBELET).expect("fixture");
    let host_word_read_from_fixture = source
        .lines()
        .find_map(|l| l.split("Host:").nth(1))
        .map(|rest| {
            rest.chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect::<String>()
                .to_lowercase()
        })
        .expect("the fixture must carry a Host: field for this test to mean anything");
    let word = host_word_read_from_fixture;
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

    let refolded = run_stdin(&["--explain", "-q"], &distilled.stdout);
    assert!(
        !templates(&refolded.stdout).is_empty(),
        "the distilled log must still fold into templates"
    );
}

#[test]
fn distill_with_an_output_mode_flag_is_a_usage_error_naming_both() {
    let out = run(&["--distill", "--format", "markdown", MICRO]);
    assert_eq!(out.status.code(), Some(2), "must be a usage error");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--distill"), "{err}");
    assert!(err.contains("--format"), "{err}");
}

#[test]
fn distill_with_stats_json_is_a_usage_error_naming_both() {
    for mode in ["--distill", "--anonymize"] {
        let out = run(&[mode, "--stats-json", MICRO]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{mode} writes no statistics, so --stats-json must be refused, not ignored: {err}"
        );
        assert!(out.stdout.is_empty(), "{mode}: no log is written");
        assert!(
            err.contains(mode) && err.contains("--stats-json"),
            "{mode}: {err}"
        );
    }
}

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

#[test]
fn a_fold_across_a_literal_word_keeps_both_words() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("over.log");
    let mut text = String::new();
    for i in 0..9 {
        text.push_str(&format!(
            "2025-01-20T10:20:0{i}.000Z worker {i} finished cleanly\n"
        ));
    }
    let rare_word_last_where_first_members_would_lose_it =
        "2025-01-20T10:20:09.000Z worker 9 finished dirty\n";
    text.push_str(rare_word_last_where_first_members_would_lose_it);
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

    assert!(
        log.contains("housekeeping heartbeat"),
        "the common event survives"
    );
    assert!(
        log.contains("database connection failed"),
        "the rare event survives: it is the reason to distil"
    );
}
