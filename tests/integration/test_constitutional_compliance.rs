use std::io::Write;
use std::process::Stdio;
use std::str;
use std::sync::LazyLock;

#[path = "../fixtures/log_generator.rs"]
mod log_generator;

#[test]
fn generated_kubelet_style_log_folds_to_between_5_and_30_lines() {
    const GENERATED_LINES_OVER_FIVE_PATTERNS: usize = 1000;
    const MOST_FOLDED_LINES: usize = 30;
    const FEWEST_FOLDED_LINES_BEFORE_PATTERNS_MERGE: usize = 5;
    let input = log_generator::generate_log(GENERATED_LINES_OVER_FIVE_PATTERNS);
    let input_lines = input.lines().count();

    let mut child = crate::common::lessence()
        .args(["--no-stats", "--threads", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn lessence");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child
        .wait_with_output()
        .expect("Failed to wait for lessence");
    assert!(output.status.success(), "lessence execution failed");

    let compressed = str::from_utf8(&output.stdout).expect("Invalid UTF-8");
    let output_lines = compressed.lines().count();
    let ratio = ((input_lines - output_lines) as f64 / input_lines as f64) * 100.0;

    println!("Constitutional compliance (generated 1000 lines):");
    println!("  Input: {input_lines}, Output: {output_lines}, Ratio: {ratio:.1}%");

    assert!(
        output_lines <= MOST_FOLDED_LINES,
        "Compression regression: {output_lines} > 30 lines from {input_lines} input"
    );
    assert!(
        ratio >= 95.0,
        "Compression ratio {ratio:.1}% < 95.0% on generated kubelet-style logs"
    );

    assert!(
        output_lines >= FEWEST_FOLDED_LINES_BEFORE_PATTERNS_MERGE,
        "Over-compression: {output_lines} < 5 lines — patterns are being merged incorrectly"
    );
}

#[test]
fn kubelet_fold_matches_golden_and_every_near_miss_shape_names_its_bead() {
    const NEAR_MISS_SCORE_FLOOR_WITH_HEADROOM_BELOW_THRESHOLD_83: f64 = 75.0;
    let Some(file) = crate::common::require_example("examples/distilled/kubelet.log") else {
        return;
    };

    let output = crate::common::lessence()
        .args(["--explain", "--threads", "1"])
        .stdin(file)
        .output()
        .expect("Failed to execute lessence");
    assert!(output.status.success(), "lessence execution failed");
    let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let mut groups = 0usize;
    let mut inventory: Vec<String> = Vec::new();
    let mut near_misses: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::default();
    for record in stdout.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(record) else {
            continue;
        };
        if v["type"] != "group" {
            continue;
        }
        groups += 1;
        let count = v["count"].as_u64().unwrap_or(0) as usize;
        inventory.push(format!(
            "{count}\t{}",
            v["normalized"].as_str().unwrap_or("")
        ));
        let nearest = &v["nearest"];
        if count != 1 || nearest.is_null() {
            continue;
        }
        let anchor_split_is_on_purpose = nearest["anchor_mismatch"] == true;
        let slot_split_is_on_purpose = nearest["slot_refused"] == true;
        if anchor_split_is_on_purpose || slot_split_is_on_purpose {
            continue;
        }
        let score = nearest["score"].as_f64().unwrap_or(0.0);
        if score < NEAR_MISS_SCORE_FLOOR_WITH_HEADROOM_BELOW_THRESHOLD_83 {
            continue;
        }
        let ours = nearest["first_diff"]["ours"].as_str().unwrap_or("");
        *near_misses
            .entry(one_cause_shape_of_differing_token(ours))
            .or_default() += 1;
    }
    let golden_text = std::fs::read_to_string("examples/distilled/kubelet.golden")
        .expect("Failed to read examples/distilled/kubelet.golden");
    let mut golden: Vec<String> = golden_text.lines().map(str::to_string).collect();
    inventory.sort();
    golden.sort();
    if inventory != golden {
        let inv_set: std::collections::BTreeSet<&String> = inventory.iter().collect();
        let gold_set: std::collections::BTreeSet<&String> = golden.iter().collect();
        let extra: Vec<_> = inv_set.difference(&gold_set).take(20).collect();
        let missing: Vec<_> = gold_set.difference(&inv_set).take(20).collect();
        panic!(
            "kubelet.log fold does not match examples/distilled/kubelet.golden\n\
             + in fold, not in golden\n{}\n\
             - in golden, not in fold\n{}\n\
             run: make distill   (BLESS=1 make distill to re-bless after an intended change)",
            extra
                .iter()
                .map(|s| format!("  {s}"))
                .collect::<Vec<_>>()
                .join("\n"),
            missing
                .iter()
                .map(|s| format!("  {s}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    println!(
        "Constitutional compliance (kubelet.log): {groups} groups, {} near-miss shapes",
        near_misses.len()
    );
    for (shape, n) in &near_misses {
        println!("  {n:>4}  {shape}");
    }

    let known: &[(&str, &str)] = &[
        (
            "<W>=\"<W>",
            "distinct error cause, by design: first word of a quoted error sentence",
        ),
        ("<W>", "distinct error cause, by design: two error tails"),
        (
            "\\\"<W>\\\"",
            "distinct container named in a quoted error sentence, by design (lessence-t8q)",
        ),
        (
            "\\\"<NAME>\\\"",
            "distinct action named in an escaped error payload, by design (lessence-8bfp)",
        ),
        (
            "\"<W>",
            "another sentence opens, verb and cause differ, by design (lessence-a8t)",
        ),
        (
            "<W>\"",
            "another sentence closes, verb and cause differ, by design (lessence-a8t)",
        ),
        (
            "<W>=[<NAME>],",
            "struct field naming another volume, by design (lessence-a8t)",
        ),
        (
            "<W>],",
            "a bracketed error list with one more item, by design (lessence-35si)",
        ),
        (
            "<W>=\"<NAME>,<W>:<W>{<W>:<W>,<W>:<NAME>,<W>:<NAME>,<W>:<NAME>,<W>:<W>,<W>:<NAME>,<W>:<W>{<NAME>},},<W>:<W>,<W>:<W>",
            "Go struct dump naming a distinct container and image, by design (lessence-t8q)",
        ),
    ];
    let unexplained: Vec<_> = near_misses
        .keys()
        .filter(|shape| !known.iter().any(|(k, _)| *k == shape.as_str()))
        .collect();
    assert!(
        unexplained.is_empty(),
        "CONSTITUTIONAL VIOLATION: near-miss singleton shapes with no owning bead: {unexplained:#?}\n\
         Each is a line lessence reports it should have folded (nearest.score >= 75, no anchor).\n\
         Fix the shape, or add it to `known` with the bead that tracks it."
    );
}

fn one_cause_shape_of_differing_token(token: &str) -> String {
    let mut out = String::new();
    let mut name = String::new();
    let flush = |name: &mut String, out: &mut String| {
        if name.is_empty() {
            return;
        }
        let hyphenated_or_placeholder_name = name.contains('-') || name.contains('<');
        if hyphenated_or_placeholder_name {
            out.push_str("<NAME>");
        } else {
            out.push_str("<W>");
        }
        name.clear();
    };
    let mut depth = 0u8;
    for c in token.chars() {
        let in_name =
            c.is_alphanumeric() || matches!(c, '_' | '.' | '-' | '/' | '<' | '>') || depth > 0;
        if in_name {
            if c == '<' {
                depth += 1;
            } else if c == '>' {
                depth = depth.saturating_sub(1);
            }
            name.push(c);
        } else {
            flush(&mut name, &mut out);
            out.push(c);
        }
    }
    flush(&mut name, &mut out);
    out
}

#[test]
fn test_processing_speed_requirement() {
    if cfg!(debug_assertions) {
        eprintln!("Skipping speed test: debug build (use --release)");
        return;
    }

    use std::time::Instant;

    let Some(file) = crate::common::require_example("examples/distilled/kubelet.log") else {
        return;
    };

    let start = Instant::now();
    let output = crate::common::lessence()
        .args(["--no-stats"])
        .stdin(file)
        .output()
        .expect("Failed to execute lessence");
    let duration = start.elapsed();

    assert!(output.status.success(), "lessence execution failed");

    println!("Speed: {:.2}s (limit: ≤30s)", duration.as_secs_f64());
    assert!(
        duration.as_secs() <= 30,
        "SPEED VIOLATION: {:.2}s > 30s",
        duration.as_secs_f64()
    );
}

fn templates_printed_by_several_anchor_split_groups_worst_first(
    corpus: &std::path::Path,
) -> Vec<(String, usize)> {
    anchor_split_groups_sharing_a_template(corpus)
        .into_iter()
        .map(|(template, lines)| (template, lines.len()))
        .collect()
}

fn anchor_split_groups_sharing_a_template(corpus: &std::path::Path) -> Vec<(String, Vec<String>)> {
    let output = crate::common::lessence()
        .args(["--explain", "--threads", "1"])
        .stdin(std::fs::File::open(corpus).expect("corpus just listed by caller"))
        .output()
        .expect("Failed to execute lessence");
    assert!(
        output.status.success(),
        "lessence execution failed on {}",
        corpus.display()
    );
    let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let mut sample_lines_and_any_anchor_mismatch_by_template: std::collections::HashMap<
        String,
        (Vec<String>, bool),
    > = std::collections::HashMap::new();
    for record in stdout.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(record) else {
            continue;
        };
        if v["type"] != "group" {
            continue;
        }
        let normalized = v["normalized"].as_str().unwrap_or("").to_string();
        let anchor_mismatch = v["nearest"]["anchor_mismatch"] == true;
        let sample = v["first"]["line"].as_str().unwrap_or("").to_string();
        let entry = sample_lines_and_any_anchor_mismatch_by_template
            .entry(normalized)
            .or_insert((Vec::new(), false));
        entry.0.push(sample);
        entry.1 |= anchor_mismatch;
    }

    let mut offenders: Vec<(String, Vec<String>)> =
        sample_lines_and_any_anchor_mismatch_by_template
            .into_iter()
            .filter(|(_, (lines, saw_mismatch))| lines.len() > 1 && *saw_mismatch)
            .map(|(template, (lines, _))| (template, lines))
            .collect();
    offenders.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    offenders
}

#[test]
#[ignore = "documents open invisible-anchor splits; each class becomes a ##CASE as it is fixed"]
fn invisible_anchor_splits() {
    let Some(distilled_dir_exists) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(distilled_dir_exists);

    let mut corpora: Vec<std::path::PathBuf> = std::fs::read_dir("examples/distilled")
        .expect("examples/distilled must be readable once require_example confirmed it exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "log"))
        .collect();
    corpora.sort();
    assert!(
        !corpora.is_empty(),
        "examples/distilled/*.log must be non-empty — a gate fails loudly on an absent corpus, never passes by omission"
    );

    let mut total = 0usize;
    for corpus in &corpora {
        let offenders = templates_printed_by_several_anchor_split_groups_worst_first(corpus);
        if offenders.is_empty() {
            continue;
        }
        total += offenders.len();
        let (example, count) = &offenders[0];
        let cut: String = example.chars().take(160).collect();
        eprintln!(
            "{}: {} template(s) printed by >1 anchor-mismatched group; worst shared by {count}: {cut}",
            corpus.display(),
            offenders.len(),
        );
    }
    eprintln!(
        "\n{total} invisible anchor split(s) total across {} corpora\n",
        corpora.len()
    );
}

fn http_status_classes_in_anchor_order(line: &str) -> Vec<char> {
    static STATUS_CLASS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?i)"?[a-z_.]*status(?:_?code)?"?\s*[:=]\s*"?([1-5])\d\d\b"#)
            .expect("status-class regex must compile")
    });
    static REQUEST_CLASS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#" HTTP/[0-9.]+" ([1-5])\d\d\b"#)
            .expect("request status-class regex must compile")
    });
    let mut classes = Vec::new();
    for pattern in [
        line.contains("HTTP/").then_some(&*REQUEST_CLASS),
        (line.contains("tatus") || line.contains("TATUS")).then_some(&*STATUS_CLASS),
    ]
    .into_iter()
    .flatten()
    {
        classes.extend(
            pattern
                .captures_iter(line)
                .filter_map(|c| c.get(1))
                .map(|m| m.as_str().chars().next().expect("regex captured one digit")),
        );
    }
    classes
}

#[test]
fn an_http_status_class_split_is_visible() {
    let Some(distilled_dir_exists) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(distilled_dir_exists);
    let mut corpora: Vec<_> = std::fs::read_dir("examples/distilled")
        .expect("distilled corpora must be readable")
        .map(|entry| entry.expect("read corpus entry").path())
        .filter(|path| path.extension().is_some_and(|e| e == "log"))
        .collect();
    corpora.sort();
    assert!(!corpora.is_empty(), "missing distilled corpora");
    let checked = std::sync::atomic::AtomicU64::new(0);
    crate::common::sweep_corpora(&corpora, |corpus| {
        let text = std::fs::read_to_string(corpus).expect("read distilled corpus");
        if !text
            .lines()
            .any(|line| !http_status_classes_in_anchor_order(line).is_empty())
        {
            return;
        }
        checked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let offenders: Vec<_> = anchor_split_groups_sharing_a_template(corpus)
            .into_iter()
            .filter(|(_, lines)| {
                lines
                    .iter()
                    .map(|line| http_status_classes_in_anchor_order(line))
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    > 1
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "{} hides HTTP status identities: {offenders:?}",
            corpus.display()
        );
    });
    assert!(
        checked.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "missing HTTP status corpora"
    );
}

#[test]
fn audit_syscall_outcomes_stay_visible_and_separate() {
    use std::collections::BTreeMap;
    use std::io::Read;

    let Some(mut file) = crate::common::require_example("examples/distilled/linux_auditd.log")
    else {
        return;
    };
    let mut text = String::new();
    file.read_to_string(&mut text).expect("read audit corpus");
    let outcome = |line: &str| {
        line.split_ascii_whitespace()
            .find(|field| field.starts_with("success="))
            .expect("syscall must carry an outcome")
            .to_string()
    };
    let mut expected = BTreeMap::<String, u64>::new();
    for line in text
        .lines()
        .filter(|line| line.starts_with("type=SYSCALL "))
    {
        *expected.entry(outcome(line)).or_default() += 1;
    }
    assert!(expected.get("success=yes").is_some_and(|n| *n > 0));
    assert!(expected.get("success=no").is_some_and(|n| *n > 0));

    let output = crate::common::lessence()
        .args([
            "--explain",
            "--threads",
            "1",
            "examples/distilled/linux_auditd.log",
        ])
        .output()
        .expect("run audit corpus");
    assert!(output.status.success());
    let mut actual = BTreeMap::<String, u64>::new();
    for record in str::from_utf8(&output.stdout).unwrap().lines() {
        let group: serde_json::Value = serde_json::from_str(record).expect("valid explain record");
        if group["type"] != "group" {
            continue;
        }
        let first = group["first"]["line"].as_str().unwrap();
        if !first.starts_with("type=SYSCALL ") {
            continue;
        }
        let shown = outcome(group["normalized"].as_str().unwrap());
        assert!(
            matches!(shown.as_str(), "success=yes" | "success=no"),
            "{group}"
        );
        assert_eq!(shown, outcome(first), "{group}");
        assert_eq!(
            shown,
            outcome(group["last"]["line"].as_str().unwrap()),
            "{group}"
        );
        *actual.entry(shown).or_default() += group["count"].as_u64().unwrap();
    }
    assert_eq!(actual, expected, "each outcome retains every input line");
}

#[test]
fn execution_commands_preserve_options_operations_and_counts() {
    use std::collections::BTreeMap;
    use std::io::Read;

    let Some(mut file) = crate::common::require_example("examples/distilled/k8s_argocd_aux.log")
    else {
        return;
    };
    let command = regex::Regex::new(r#""(args|msg)":"(\[?git [^"]*)""#).unwrap();
    let revision = regex::Regex::new(r"\b[0-9a-f]{32,40}\b").unwrap();
    let signature = |line: &str| {
        command.captures(line).map(|caps| {
            (
                caps[1].to_string(),
                revision.replace_all(&caps[2], "<HASH>").into_owned(),
            )
        })
    };
    let mut text = String::new();
    file.read_to_string(&mut text)
        .expect("read execution corpus");
    let mut expected = BTreeMap::new();
    for line in text.lines() {
        if let Some(key) = signature(line) {
            *expected.entry(key).or_insert(0u64) += 1;
        }
    }
    assert!(expected.keys().any(|(field, _)| field == "args"));
    assert!(expected.keys().any(|(field, _)| field == "msg"));

    let output = crate::common::lessence()
        .args([
            "--explain",
            "--threads",
            "1",
            "examples/distilled/k8s_argocd_aux.log",
        ])
        .output()
        .expect("run execution corpus");
    assert!(output.status.success());
    let mut actual = BTreeMap::new();
    for record in str::from_utf8(&output.stdout).unwrap().lines() {
        let group: serde_json::Value = serde_json::from_str(record).expect("valid explain record");
        if group["type"] != "group" {
            continue;
        }
        let Some(first) = signature(group["first"]["line"].as_str().unwrap()) else {
            continue;
        };
        let shown = group["normalized"].as_str().unwrap();
        assert_eq!(signature(shown), Some(first.clone()), "{group}");
        assert_eq!(
            signature(group["last"]["line"].as_str().unwrap()),
            Some(first.clone()),
            "{group}"
        );
        if first.0 == "args" {
            assert!(shown.contains(r#""operation_name":"exec git""#), "{group}");
        }
        for sample in group["variation"]["VARIES"]["samples"]
            .as_array()
            .into_iter()
            .flatten()
        {
            assert_ne!(sample, "∅", "execution fields are present: {group}");
        }
        for sample in group["variation"]["PATH"]["samples"]
            .as_array()
            .into_iter()
            .flatten()
        {
            assert!(
                !sample.as_str().unwrap().starts_with('-'),
                "an option is not a path: {group}"
            );
        }
        *actual.entry(first).or_insert(0u64) += group["count"].as_u64().unwrap();
    }
    assert_eq!(actual, expected, "each command retains every input line");
}

fn cli_option_signature(line: &str) -> Vec<&str> {
    static OPTION: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?:^|[\s"'])(--[A-Za-z][A-Za-z0-9_-]*|-[A-Za-z]\b)"#).unwrap()
    });
    OPTION
        .captures_iter(line)
        .map(|caps| caps.get(1).unwrap().as_str())
        .collect()
}

#[test]
fn cli_option_identities_stay_visible_in_every_corpus() {
    use std::collections::BTreeMap;

    let Some(distilled_dir_exists) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(distilled_dir_exists);
    let checked = std::sync::atomic::AtomicU64::new(0);
    let mut corpora: Vec<std::path::PathBuf> = std::fs::read_dir("examples/distilled")
        .expect("read corpora")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "log"))
        .collect();
    corpora.sort();
    assert!(!corpora.is_empty(), "examples/distilled holds no corpora");
    crate::common::sweep_corpora(&corpora, |path| {
        let input = std::fs::read_to_string(path).expect("read corpus");
        if !input
            .lines()
            .any(|line| !cli_option_signature(line).is_empty())
        {
            return;
        }
        let mut expected_counts = BTreeMap::<Vec<String>, u64>::new();
        for line in input.lines() {
            let names = cli_option_signature(line);
            if !names.is_empty() {
                *expected_counts
                    .entry(names.into_iter().map(str::to_string).collect())
                    .or_default() += 1;
            }
        }
        let mut actual_counts = BTreeMap::<Vec<String>, u64>::new();
        let output = crate::common::lessence()
            .args(["--explain", "--threads", "1"])
            .arg(path)
            .output()
            .expect("run option corpus");
        assert!(
            output.status.success(),
            "{}: --explain exited {:?}: {}",
            path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        for record in str::from_utf8(&output.stdout).unwrap().lines() {
            let group: serde_json::Value =
                serde_json::from_str(record).expect("valid explain record");
            if group["type"] != "group" {
                continue;
            }
            let expected = cli_option_signature(group["first"]["line"].as_str().unwrap());
            if expected.is_empty() {
                continue;
            }
            checked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                cli_option_signature(group["normalized"].as_str().unwrap()),
                expected,
                "{}: {group}",
                path.display()
            );
            assert_eq!(
                cli_option_signature(group["last"]["line"].as_str().unwrap()),
                expected,
                "{}: {group}",
                path.display()
            );
            *actual_counts
                .entry(expected.into_iter().map(str::to_string).collect())
                .or_default() += group["count"].as_u64().unwrap();
        }
        assert_eq!(
            actual_counts,
            expected_counts,
            "{}: option line totals",
            path.display()
        );
    });
    assert!(
        checked.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "missing CLI option corpus groups"
    );
}

#[test]
fn call_site_traceback_and_program_splits_are_visible() {
    let Some(distilled_dir_exists) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(distilled_dir_exists);
    for name in [
        "apiserver_production.log",
        "k8s_grafana.log",
        "k8s_json_sample.log",
        "k8s_tetragon.log",
    ] {
        let path = std::path::Path::new("examples/distilled").join(name);
        assert!(path.exists(), "missing corpus {}", path.display());
        let offenders = anchor_split_groups_sharing_a_template(&path);
        assert!(
            offenders.is_empty(),
            "{} hides event identities: {offenders:?}",
            path.display()
        );
    }
}

#[test]
fn systemd_unit_splits_are_visible() {
    let Some(distilled_dir_exists) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(distilled_dir_exists);
    for name in [
        "epyc_7days_journalctl.log",
        "host_fedora_journal.log",
        "host_fedora_user_journal.log",
        "host_pi_dmesg.log",
    ] {
        let path = std::path::Path::new("examples/distilled").join(name);
        assert!(path.exists(), "missing corpus {}", path.display());
        let offenders: Vec<_> = anchor_split_groups_sharing_a_template(&path)
            .into_iter()
            .filter(|(_, lines)| lines.iter().any(|line| line.contains("systemd[")))
            .collect();
        assert!(
            offenders.is_empty(),
            "{} hides systemd units: {offenders:?}",
            path.display()
        );
    }
}

#[test]
fn pci_address_splits_are_visible() {
    static PCI: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"\b[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\b")
            .expect("PCI address regex must compile")
    });
    let Some(distilled_dir_exists) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(distilled_dir_exists);
    for name in ["epyc_7days_journalctl.log", "nas_dmesg.log"] {
        let path = std::path::Path::new("examples/distilled").join(name);
        assert!(path.exists(), "missing corpus {}", path.display());
        let groups_disagreeing_on_ordered_pci_identities: Vec<_> =
            anchor_split_groups_sharing_a_template(&path)
                .into_iter()
                .filter(|(_, lines)| {
                    lines
                        .iter()
                        .map(|line| PCI.find_iter(line).map(|m| m.as_str()).collect::<Vec<_>>())
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        > 1
                })
                .collect();
        assert!(
            groups_disagreeing_on_ordered_pci_identities.is_empty(),
            "{} hides PCI identities: {groups_disagreeing_on_ordered_pci_identities:?}",
            path.display()
        );
    }
}

#[test]
fn a_route_split_is_visible() {
    for name in ["k8s_traefik.log", "nginx_sample.log", "k8s_rook_ceph.log"] {
        let path = std::path::Path::new("examples/distilled").join(name);
        let Some(distilled_dir_exists) = crate::common::require_example("examples/distilled")
        else {
            return;
        };
        drop(distilled_dir_exists);
        assert!(path.exists(), "missing corpus {}", path.display());
        let offenders = anchor_split_groups_sharing_a_template(&path);
        assert!(
            offenders.is_empty(),
            "{}: {} route-anchor split(s) invisible on the shown line: {:?}",
            path.display(),
            offenders.len(),
            offenders
                .iter()
                .take(5)
                .map(|(t, lines)| format!(
                    "{}x {}",
                    lines.len(),
                    t.chars().take(160).collect::<String>()
                ))
                .collect::<Vec<_>>()
        );
    }
}

fn pod_and_container_as_pod_skeleton_strips_them(line: &str) -> Option<(String, String)> {
    static PREFIX: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^\[pod/([^/\]]+)/([^\]]+)\]").expect("prefix regex"));
    const KUBERNETES_GENERATED_SUFFIX_ALPHABET: &[u8] = b"bcdfghjklmnpqrstvwxz2456789";
    let caps = PREFIX.captures(line)?;
    let pod = caps.get(1)?.as_str();
    let container = caps.get(2)?.as_str();
    let kubernetes_generated_segment = |seg: &str| {
        let b = seg.as_bytes();
        (!b.is_empty() && b.iter().all(u8::is_ascii_digit))
            || (b.len() <= 2 && b.iter().all(u8::is_ascii_lowercase))
            || (b.len() == 5
                && b.iter()
                    .all(|c| KUBERNETES_GENERATED_SUFFIX_ALPHABET.contains(c)))
            || ((8..=10).contains(&b.len())
                && b.iter().all(|c| {
                    KUBERNETES_GENERATED_SUFFIX_ALPHABET.contains(c) || c.is_ascii_digit()
                }))
    };
    let mut keep = pod;
    for _ in 0..3 {
        match keep.rsplit_once('-') {
            Some((head, tail)) if kubernetes_generated_segment(tail) => keep = head,
            _ => break,
        }
    }
    Some((keep.to_string(), container.to_string()))
}

#[test]
fn a_pod_prefix_split_is_visible() {
    let Some(distilled_dir_exists) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(distilled_dir_exists);

    let mut corpora: Vec<std::path::PathBuf> = std::fs::read_dir("examples/distilled")
        .expect("examples/distilled must be readable once require_example confirmed it exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|f| f.starts_with("k8s_") && f.ends_with(".log"))
        })
        .collect();
    corpora.sort();
    assert!(
        !corpora.is_empty(),
        "examples/distilled/k8s_*.log must be non-empty — a gate fails loudly on an absent corpus, never passes by omission"
    );

    crate::common::sweep_corpora(&corpora, |path| {
        let offenders: Vec<(String, Vec<String>)> = anchor_split_groups_sharing_a_template(path)
            .into_iter()
            .filter(|(_, lines)| {
                let pod_identities_of_sampled_lines: std::collections::BTreeSet<(String, String)> =
                    lines
                        .iter()
                        .filter_map(|l| pod_and_container_as_pod_skeleton_strips_them(l))
                        .collect();
                pod_identities_of_sampled_lines.len() > 1
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "{}: {} pod-prefix-anchor split(s) invisible on the shown line: {:?}",
            path.display(),
            offenders.len(),
            offenders
                .iter()
                .take(5)
                .map(|(t, lines)| format!(
                    "{}x {}",
                    lines.len(),
                    t.chars().take(160).collect::<String>()
                ))
                .collect::<Vec<_>>()
        );
    });
}

#[test]
fn prose_http_requests_preserve_methods_routes_and_counts() {
    use std::collections::BTreeMap;
    let path = "examples/distilled/k8s_postgres_operator.log";
    let Some(file) = crate::common::require_example(path) else {
        return;
    };
    drop(file);
    fn identity(line: &str) -> Option<(String, String)> {
        let (_, record) = line.split_once("] ")?;
        let value: serde_json::Value = serde_json::from_str(record).ok()?;
        let message = value["msg"].as_str()?.strip_prefix("making ")?;
        let (method, target) = message.split_once(" http request: ")?;
        let (_, rest) = target.split_once("://")?;
        let (_, route) = rest.split_once('/')?;
        Some((method.to_string(), format!("/{route}")))
    }
    let input = std::fs::read_to_string(path).expect("read operator corpus");
    let mut expected = BTreeMap::<(String, String), u64>::new();
    for key in input.lines().filter_map(identity) {
        *expected.entry(key).or_default() += 1;
    }
    assert!(expected.keys().any(|(method, _)| method == "POST"));
    assert!(expected.keys().any(|(method, _)| method == "GET"));
    assert!(expected.len() >= 4, "request route coverage disappeared");
    let output = crate::common::lessence()
        .args(["--explain", "--threads", "1", path])
        .output()
        .expect("run corpus");
    assert!(output.status.success());
    let mut actual = BTreeMap::<(String, String), u64>::new();
    for line in str::from_utf8(&output.stdout).unwrap().lines() {
        let group: serde_json::Value = serde_json::from_str(line).unwrap();
        if group["type"] != "group" {
            continue;
        }
        let Some(key) = identity(group["first"]["line"].as_str().unwrap()) else {
            continue;
        };
        assert_eq!(
            identity(group["last"]["line"].as_str().unwrap()),
            Some(key.clone())
        );
        let shown = group["normalized"].as_str().unwrap();
        assert!(
            shown.contains(&format!(
                "making {} http request: http://<HOST>{}\"",
                key.0, key.1
            )),
            "{group}"
        );
        for sample in group["variation"]["PATH"]["samples"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let url = sample.as_str().unwrap();
            let (_, rest) = url.split_once("://").expect("full request URL in facts");
            let (_, route) = rest.split_once('/').unwrap();
            assert_eq!(format!("/{route}"), key.1);
        }
        *actual.entry(key).or_default() += group["count"].as_u64().unwrap();
    }
    assert_eq!(actual, expected, "per-method and route line counts");
}

#[test]
fn command_timings_remain_decimal_measurements() {
    let path = "examples/distilled/k8s_argocd_aux.log";
    let Some(file) = crate::common::require_example(path) else {
        return;
    };
    drop(file);
    let timing = regex::Regex::new(r#""time_ms":([0-9]+\.[0-9]+)"#).unwrap();
    let input = std::fs::read_to_string(path).expect("read execution corpus");
    let expected = input.lines().filter(|line| timing.is_match(line)).count() as u64;
    assert!(expected > 0, "missing command timing records");
    assert!(
        timing
            .captures_iter(&input)
            .any(|c| c[1].split_once('.').unwrap().1.len() == 16),
        "missing long decimal regression shape"
    );
    let output = crate::common::lessence()
        .args(["--explain", "--threads", "1", path])
        .output()
        .expect("run execution corpus");
    assert!(output.status.success());
    let mut actual = 0;
    for line in str::from_utf8(&output.stdout).unwrap().lines() {
        let group: serde_json::Value = serde_json::from_str(line).unwrap();
        if group["type"] != "group" || !timing.is_match(group["first"]["line"].as_str().unwrap()) {
            continue;
        }
        assert!(timing.is_match(group["last"]["line"].as_str().unwrap()));
        assert!(
            group["normalized"]
                .as_str()
                .unwrap()
                .contains(r#""time_ms":<DECIMAL>}"#),
            "{group}"
        );
        actual += group["count"].as_u64().unwrap();
    }
    assert_eq!(actual, expected, "all command timing lines accounted for");
}

#[test]
fn cpu_resources_keep_quantity_values_in_configuration_diffs() {
    let path = "examples/distilled/k8s_postgres_operator.log";
    let Some(file) = crate::common::require_example(path) else {
        return;
    };
    drop(file);
    let input = std::fs::read_to_string(path).expect("read operator corpus");
    let cpu = regex::Regex::new(r"\bcpu:([0-9]+m)").unwrap();
    let clean = |s: &str| s.replace(['\\', '"'], "");
    let expected_values: std::collections::BTreeSet<String> = cpu
        .captures_iter(&clean(&input))
        .map(|c| c[1].to_string())
        .collect();
    let input_lines = input
        .lines()
        .filter(|line| cpu.is_match(&clean(line)))
        .count() as u64;
    let input_quantities = cpu.captures_iter(&clean(&input)).count() as u64;
    let normalizer_before_clustering =
        lessence::normalize::Normalizer::new(lessence::Config::default());
    for (index, raw) in input.lines().enumerate() {
        let expected = cpu.captures_iter(&clean(raw)).count();
        if expected == 0 {
            continue;
        }
        let line = normalizer_before_clustering
            .normalize_line(raw.to_string())
            .unwrap();
        let normalized = clean(&line.normalized());
        assert_eq!(
            normalized.matches("cpu:<CPU_QUANTITY>").count(),
            expected,
            "CPU fields on source line {}",
            index + 1
        );
        assert!(!normalized.contains("cpu:<DURATION>"));
    }
    assert!(
        input_lines > 0 && expected_values.len() >= 2,
        "missing CPU resource shapes"
    );
    let output = crate::common::lessence()
        .args(["--explain", "--threads", "1", path])
        .output()
        .expect("run operator corpus");
    assert!(output.status.success());
    let mut counted = 0;
    let mut quantities = 0;
    let mut values = std::collections::BTreeSet::new();
    for line in str::from_utf8(&output.stdout).unwrap().lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        if row["type"] == "summary" {
            quantities = row["pattern_hits"]["cpu_quantities"].as_u64().unwrap();
            continue;
        }
        if row["type"] != "group" || !cpu.is_match(&clean(row["first"]["line"].as_str().unwrap())) {
            continue;
        }
        assert!(cpu.is_match(&clean(row["last"]["line"].as_str().unwrap())));
        let normalized = clean(row["normalized"].as_str().unwrap());
        assert!(!normalized.contains("cpu:<DURATION>"));
        let count = row["count"].as_u64().unwrap();
        if count > 1 {
            let facts = &row["variation"]["CPU_QUANTITY"];
            assert_eq!(facts["samples_complete"], true, "{row}");
            for value in facts["samples"].as_array().unwrap() {
                values.insert(value.as_str().unwrap().to_string());
            }
        }
        counted += count;
    }
    assert_eq!(counted, input_lines);
    assert_eq!(quantities, input_quantities);
    assert_eq!(values, expected_values);
}
