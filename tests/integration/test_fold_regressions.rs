use std::io::Write;
use std::process::Stdio;
use std::sync::LazyLock;

const DEFAULT_CORPUS: &str = include_str!("../fixtures/fold_regressions.log");

const NEW_BLOCKS_FIXTURE_ENV_SET_BY_GATE: &str = "LESSENCE_FIXTURE";
const BASELINE_BIN_ENV_SET_BY_GATE: &str = "LESSENCE_BIN";
const HOLDS_ON_BASE_MARKER_READ_BY_GATE: &str = " holds-on-base";

static CORPUS: LazyLock<String> =
    LazyLock::new(|| match std::env::var(NEW_BLOCKS_FIXTURE_ENV_SET_BY_GATE) {
        Ok(path) => std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{NEW_BLOCKS_FIXTURE_ENV_SET_BY_GATE}={path}: {e}")),
        Err(_) => DEFAULT_CORPUS.to_string(),
    });

static BIN: LazyLock<String> = LazyLock::new(|| {
    std::env::var(BASELINE_BIN_ENV_SET_BY_GATE)
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_lessence").to_string())
});

#[derive(Debug, PartialEq)]
enum Expect {
    ExactGroupCount(usize),
    FirstTemplateAbsent(String),
    FirstTemplatePresent(String),
    StdoutAbsent(String),
    StdoutPresent(String),
    StderrPresent(String),
    ExitStatus(i32),
}

impl Expect {
    fn reads_the_fold_so_harness_adds_json(&self) -> bool {
        matches!(
            self,
            Expect::ExactGroupCount(_)
                | Expect::FirstTemplateAbsent(_)
                | Expect::FirstTemplatePresent(_)
        )
    }
}

struct Case {
    bead: String,
    why: String,
    from: String,
    flags: Vec<String>,
    expect: Expect,
    lines: Vec<String>,
    todo_known_open_defect: bool,
}

fn parse(corpus: &str) -> Vec<Case> {
    let mut out: Vec<Case> = Vec::new();

    for (n, raw) in corpus.lines().enumerate() {
        let lineno = n + 1;
        let bad = |msg: &str| -> ! { panic!("fold_regressions.log line {lineno}: {msg}") };

        let (rest, todo_known_open_defect) =
            match (raw.strip_prefix("##CASE "), raw.strip_prefix("##TODO ")) {
                (Some(r), _) => (Some(r), false),
                (None, Some(r)) => (Some(r), true),
                _ => (None, false),
            };
        if let Some(rest) = rest {
            let (bead, spec) = rest
                .split_once(' ')
                .unwrap_or_else(|| bad("##CASE needs a bead and an expectation"));
            let spec = spec
                .strip_suffix(HOLDS_ON_BASE_MARKER_READ_BY_GATE)
                .unwrap_or(spec);
            let (kind, value) = spec
                .split_once('=')
                .unwrap_or_else(|| bad("expectation must be key=value"));
            let value = value.to_string();
            let expect = match kind {
                "groups" => Expect::ExactGroupCount(
                    value
                        .parse()
                        .unwrap_or_else(|_| bad("groups= wants a number")),
                ),
                "template_absent" => Expect::FirstTemplateAbsent(value),
                "template_present" => Expect::FirstTemplatePresent(value),
                "out_absent" => Expect::StdoutAbsent(value),
                "out_present" => Expect::StdoutPresent(value),
                "err_present" => Expect::StderrPresent(value),
                "exit" => Expect::ExitStatus(
                    value
                        .parse()
                        .unwrap_or_else(|_| bad("exit= wants a number")),
                ),
                other => bad(&format!("unknown expectation `{other}`")),
            };
            out.push(Case {
                bead: bead.trim().to_string(),
                why: String::new(),
                from: String::new(),
                flags: Vec::new(),
                expect,
                lines: Vec::new(),
                todo_known_open_defect,
            });
            continue;
        }

        let file_header_or_block_closing_blank = raw.starts_with("##") || raw.trim().is_empty();
        if raw.starts_with("##WHY ") || raw.starts_with("##FROM ") || raw.starts_with("##FLAGS ") {
            let case = out
                .last_mut()
                .unwrap_or_else(|| panic!("line {lineno}: directive outside a case"));
            if let Some(why) = raw.strip_prefix("##WHY ") {
                if !case.why.is_empty() {
                    case.why.push(' ');
                }
                case.why.push_str(why.trim());
            } else if let Some(from) = raw.strip_prefix("##FROM ") {
                case.from.push_str(from.trim());
            } else if let Some(flags) = raw.strip_prefix("##FLAGS ") {
                case.flags
                    .extend(flags.split_whitespace().map(str::to_string));
            }
        } else if !file_header_or_block_closing_blank {
            out.last_mut()
                .unwrap_or_else(|| panic!("line {lineno}: input line outside a case"))
                .lines
                .push(raw.to_string());
        }
    }

    assert!(!out.is_empty(), "the regression corpus parsed to nothing");
    for case in &out {
        assert!(!case.lines.is_empty(), "{}: no input lines", case.bead);
        assert!(!case.why.is_empty(), "{}: no ##WHY", case.bead);
        assert!(!case.from.is_empty(), "{}: no ##FROM", case.bead);
    }
    out
}

struct Run {
    stdout: String,
    stderr: String,
    status: i32,
}

const SAME_PSEUDONYM_KEY_FOR_EVERY_THREAD_COUNT: &str = "fixture";

fn run(case: &Case, threads: &str) -> Run {
    let mut args: Vec<String> = vec!["--threads".into(), threads.into(), "-q".into()];
    args.extend(case.flags.iter().cloned());
    if case.expect.reads_the_fold_so_harness_adds_json()
        && !case.flags.iter().any(|f| f == "--format")
    {
        args.push("--format".into());
        args.push("json".into());
    }
    let text_mode_asserts_folded_text_not_report_overview = !args.iter().any(|f| {
        matches!(
            f.as_str(),
            "--format" | "--json" | "--summary" | "--top" | "--fit" | "--preflight" | "--explain"
        )
    }) || args.iter().any(|f| f == "text");
    if text_mode_asserts_folded_text_not_report_overview {
        args.push("--no-report".into());
    }
    feed(&args, case.lines.iter())
}

fn feed<'a>(args: &[String], lines: impl Iterator<Item = &'a String>) -> Run {
    let mut child = crate::common::command(&*BIN)
        .args(args)
        .env(
            "LESSENCE_SANITIZE_KEY",
            SAME_PSEUDONYM_KEY_FOR_EVERY_THREAD_COUNT,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn lessence");
    let mut stdin = child.stdin.take().expect("stdin");
    for line in lines {
        let refused_flags_exited_before_reading_all_input = writeln!(stdin, "{line}").is_err();
        if refused_flags_exited_before_reading_all_input {
            break;
        }
    }
    drop(stdin);
    let done = child.wait_with_output().expect("wait");
    Run {
        stdout: String::from_utf8_lossy(&done.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&done.stderr).into_owned(),
        status: done.status.code().unwrap_or(-1),
    }
}

const MARKDOWN_HEADER_STAMPED_TO_THE_SECOND: &str = "*Generated by lessence";

fn without_wall_clock(stdout: &str) -> String {
    let mut out = String::with_capacity(stdout.len());
    let mut rest = stdout;
    while let Some(at) = rest.find("\"elapsed_ms\":") {
        out.push_str(&rest[..at]);
        out.push_str("\"elapsed_ms\":<N>");
        let after = &rest[at + r#""elapsed_ms":"#.len()..];
        let skip = after
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after.len());
        rest = &after[skip..];
    }
    out.push_str(rest);
    out.lines()
        .map(|l| {
            if l.starts_with(MARKDOWN_HEADER_STAMPED_TO_THE_SECOND) {
                "*Generated by lessence <VERSION> on <TIME>*"
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn first_template(stdout: &str) -> String {
    for line in stdout.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
            && v.get("type").and_then(|t| t.as_str()) == Some("group")
        {
            return v
                .get("normalized")
                .and_then(|n| n.as_str())
                .unwrap_or_default()
                .to_string();
        }
    }
    String::new()
}

fn count_groups(stdout: &str) -> usize {
    stdout
        .lines()
        .filter(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(|t| t == "group"))
                .unwrap_or(false)
        })
        .count()
}

fn par_map_in_case_order<C: Sync, T: Send>(
    cases: &[C],
    f: impl Fn(&C) -> Option<T> + Sync,
) -> Vec<T> {
    let workers = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    let chunk = cases.len().div_ceil(workers).max(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = cases
            .chunks(chunk)
            .map(|c| s.spawn(|| c.iter().filter_map(&f).collect::<Vec<T>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("case thread panicked"))
            .collect()
    })
}

fn check(cases: &[Case]) -> Vec<String> {
    par_map_in_case_order(cases, |case| {
        let got = run(case, "1");
        let stdout = got.stdout.as_str();
        let complaint = match &case.expect {
            Expect::ExactGroupCount(want) => {
                let n = count_groups(stdout);
                (n != *want).then(|| format!("want {want} group(s), got {n}\n     {stdout}"))
            }
            Expect::FirstTemplateAbsent(text) => {
                let t = first_template(stdout);
                t.contains(text.as_str())
                    .then(|| format!("`{text}` must not appear\n     template: {t}"))
            }
            Expect::FirstTemplatePresent(text) => {
                let t = first_template(stdout);
                (!t.contains(text.as_str()))
                    .then(|| format!("`{text}` is missing\n     template: {t}"))
            }
            Expect::StdoutAbsent(text) => {
                let needle = unescape_ansi_escape_and_tab(text);
                stdout
                    .contains(&needle)
                    .then(|| format!("`{text}` must not appear in output\n     {stdout}"))
            }
            Expect::StdoutPresent(text) => {
                let needle = unescape_ansi_escape_and_tab(text);
                (!stdout.contains(&needle))
                    .then(|| format!("`{text}` is missing from output\n     {stdout}"))
            }
            Expect::StderrPresent(text) => {
                let needle = unescape_ansi_escape_and_tab(text);
                (!got.stderr.contains(&needle))
                    .then(|| format!("`{text}` is missing from stderr\n     {}", got.stderr))
            }
            Expect::ExitStatus(want) => (got.status != *want)
                .then(|| format!("want exit {want}, got {}\n     {}", got.status, got.stderr)),
        };
        let binary_panicked_in_a_built_in_check = got.stderr.contains("panicked at");
        let crash = if binary_panicked_in_a_built_in_check {
            format!(
                "\n     the binary panicked:\n     {}",
                got.stderr.trim_end()
            )
        } else {
            String::new()
        };
        complaint.map(|detail| {
            format!(
                "{}\n     {}\n     from: {}\n     flags: {:?}\n     {detail}{crash}",
                case.bead, case.why, case.from, case.flags
            )
        })
    })
}

#[test]
fn known_fold_regressions() {
    let cases: Vec<Case> = parse(&CORPUS)
        .into_iter()
        .filter(|c| !c.todo_known_open_defect)
        .collect();
    let failures = check(&cases);
    assert!(
        failures.is_empty(),
        "{} of {} fold regressions came back:\n\n{}\n",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

#[test]
#[ignore = "documents open defects; promote each ##TODO to ##CASE as it is fixed"]
fn known_open_defects() {
    let cases: Vec<Case> = parse(&CORPUS)
        .into_iter()
        .filter(|c| c.todo_known_open_defect)
        .collect();
    let failures = check(&cases);
    let fixed = cases.len() - failures.len();
    eprintln!(
        "\n{} open defects documented, {} of them now pass and should be promoted to ##CASE\n",
        cases.len(),
        fixed
    );
    if fixed > 0 {
        let passing: Vec<_> = cases
            .iter()
            .filter(|c| !failures.iter().any(|f| f.starts_with(&c.bead)))
            .map(|c| c.bead.as_str())
            .collect();
        eprintln!("promote: {passing:?}\n");
    }
}

fn unescape_ansi_escape_and_tab(text: &str) -> String {
    text.replace("\\e", "\u{1b}").replace("\\t", "\t")
}

#[test]
fn every_case_is_identical_at_any_thread_count() {
    let cases = parse(&CORPUS);
    let diffs = par_map_in_case_order(&cases, |case| {
        let a = without_wall_clock(&run(case, "1").stdout);
        let b = without_wall_clock(&run(case, "8").stdout);
        (a != b).then(|| format!("{} — {} differs at 8 threads", case.bead, case.why))
    });
    assert!(
        diffs.is_empty(),
        "{} case(s) differ at 8 threads (the parallel path batches and re-clusters):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

/// Cases whose line order is part of their meaning, so the reversed input is a different log: `(case id, reason)`.
const ORDER_IS_THE_INPUT: &[(&str, &str)] = &[(
    "092dda7#2",
    "--frame-continuations joins an indented line to the record above it, so reversed lines are a different log",
)];

/// Cases that fold into different groups when reversed, a defect not yet fixed: `(case id, bead id)`; this table only shrinks.
const KNOWN_ORDER_DEPENDENT: &[(&str, &str)] = &[
    ("lessence-682#1", "lessence-v5kr"),
    ("lessence-bek#1", "lessence-v5kr"),
    ("lessence-1tee#5", "lessence-v5kr"),
];

const FEWEST_CASES_THE_REVERSED_ORDER_TEST_MUST_COMPARE: usize = 200;

fn case_ids(cases: &[Case]) -> Vec<String> {
    let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    cases
        .iter()
        .map(|c| {
            let n = seen.entry(c.bead.as_str()).or_default();
            *n += 1;
            format!("{}#{n}", c.bead)
        })
        .collect()
}

fn picks_an_output_without_group_records(flags: &[String]) -> bool {
    flags
        .windows(2)
        .any(|w| w[0] == "--format" && !w[1].eq_ignore_ascii_case("json"))
        || flags
            .iter()
            .any(|f| matches!(f.as_str(), "--summary" | "--preflight"))
}

fn sorted_group_counts(stdout: &str) -> Vec<u64> {
    let mut counts: Vec<u64> = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|v| v.get("type").and_then(|t| t.as_str()) == Some("group"))
        .map(|v| {
            v.get("count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_else(|| panic!("group record without a count: {v}"))
        })
        .collect();
    counts.sort_unstable();
    counts
}

enum Reversal {
    Skipped,
    Same(String),
    Differs(String, String),
}

#[test]
fn every_case_folds_into_the_same_groups_in_reverse_order() {
    let parsed = parse(&CORPUS);
    let ids = case_ids(&parsed);
    for (id, _) in ORDER_IS_THE_INPUT.iter().chain(KNOWN_ORDER_DEPENDENT) {
        assert!(
            ids.iter().any(|i| i == id),
            "{id} is listed in a reversed-order table but names no case; delete the entry"
        );
    }
    let cases: Vec<(String, &Case)> = ids
        .into_iter()
        .zip(&parsed)
        .filter(|(id, c)| {
            !c.todo_known_open_defect && !ORDER_IS_THE_INPUT.iter().any(|(o, _)| o == id)
        })
        .collect();

    let outcomes = par_map_in_case_order(&cases, |(id, case)| {
        if picks_an_output_without_group_records(&case.flags) {
            return Some(Reversal::Skipped);
        }
        let mut args: Vec<String> = vec!["--threads".into(), "1".into()];
        if !case.flags.iter().any(|f| f == "--explain") {
            args.push("--explain".into());
        }
        args.extend(case.flags.iter().cloned());
        let forward = feed(&args, case.lines.iter());
        let forward_counts = sorted_group_counts(&forward.stdout);
        if forward.status != 0 || forward_counts.is_empty() {
            return Some(Reversal::Skipped);
        }
        let reversed_counts = sorted_group_counts(&feed(&args, case.lines.iter().rev()).stdout);
        Some(if forward_counts == reversed_counts {
            Reversal::Same(id.clone())
        } else {
            Reversal::Differs(
                id.clone(),
                format!("{id}  forward={forward_counts:?}  reversed={reversed_counts:?}"),
            )
        })
    });

    let known = |id: &str| KNOWN_ORDER_DEPENDENT.iter().any(|(k, _)| *k == id);
    let mut compared = 0;
    let mut skipped = 0;
    let mut differing: Vec<String> = Vec::new();
    let mut fixed_but_still_listed: Vec<String> = Vec::new();
    for outcome in outcomes {
        match outcome {
            Reversal::Skipped => skipped += 1,
            Reversal::Same(id) if known(&id) => fixed_but_still_listed.push(format!(
                "{id} now folds the same in reverse order; delete its KNOWN_ORDER_DEPENDENT entry"
            )),
            Reversal::Differs(id, _) if known(&id) => {}
            Reversal::Same(_) => compared += 1,
            Reversal::Differs(_, line) => {
                compared += 1;
                differing.push(line);
            }
        }
    }

    assert!(
        compared >= FEWEST_CASES_THE_REVERSED_ORDER_TEST_MUST_COMPARE,
        "only {compared} case(s) compared ({skipped} skipped); the reversed-order test must compare at least {FEWEST_CASES_THE_REVERSED_ORDER_TEST_MUST_COMPARE}"
    );
    assert!(
        differing.is_empty() && fixed_but_still_listed.is_empty(),
        "{} of {compared} case(s) fold into different groups in reverse order ({skipped} skipped):\n{}\n{}",
        differing.len(),
        differing.join("\n"),
        fixed_but_still_listed.join("\n")
    );
}
