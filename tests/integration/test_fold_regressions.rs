//! Drives `tests/fixtures/fold_regressions.log` through the real binary.
//!
//! The corpus is the data; this file is only the harness. See the header of
//! that file for the block format and for why it exists.
//!
//! Running the binary rather than the library is deliberate: half the defects
//! in the corpus are only reachable through a flag — `--sanitize-pii`,
//! `--disable-patterns`, `--summary`, `--preflight`, `--format markdown` — and
//! an in-crate harness cannot see those surfaces at all.

use std::io::Write;
use std::process::{Command, Stdio};

const CORPUS: &str = include_str!("../fixtures/fold_regressions.log");
const BIN: &str = env!("CARGO_BIN_EXE_lessence");

#[derive(Debug, PartialEq)]
enum Expect {
    /// Exactly this many groups come out.
    Groups(usize),
    /// The first group's normalized template must not contain this.
    TemplateAbsent(String),
    /// The first group's normalized template must contain this.
    TemplatePresent(String),
    /// Raw stdout must not contain this.
    OutAbsent(String),
    /// Raw stdout must contain this.
    OutPresent(String),
    /// Raw stderr must contain this.
    ErrPresent(String),
    /// The process must exit with this status.
    Exit(i32),
}

impl Expect {
    /// Expectations about the fold itself need the machine format; the harness
    /// supplies it so a case does not have to remember.
    fn needs_json(&self) -> bool {
        matches!(
            self,
            Expect::Groups(_) | Expect::TemplateAbsent(_) | Expect::TemplatePresent(_)
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
    /// `##TODO`: a known defect with no fix yet. Documents the expected
    /// behaviour; checked only by the ignored `known_open_defects` test.
    todo: bool,
}

fn parse(corpus: &str) -> Vec<Case> {
    let mut out: Vec<Case> = Vec::new();

    for (n, raw) in corpus.lines().enumerate() {
        let lineno = n + 1;
        let bad = |msg: &str| -> ! { panic!("fold_regressions.log line {lineno}: {msg}") };

        let (rest, todo) = match (raw.strip_prefix("##CASE "), raw.strip_prefix("##TODO ")) {
            (Some(r), _) => (Some(r), false),
            (None, Some(r)) => (Some(r), true),
            _ => (None, false),
        };
        if let Some(rest) = rest {
            let (bead, spec) = rest
                .split_once(' ')
                .unwrap_or_else(|| bad("##CASE needs a bead and an expectation"));
            let (kind, value) = spec
                .split_once('=')
                .unwrap_or_else(|| bad("expectation must be key=value"));
            let value = value.to_string();
            let expect = match kind {
                "groups" => Expect::Groups(
                    value
                        .parse()
                        .unwrap_or_else(|_| bad("groups= wants a number")),
                ),
                "template_absent" => Expect::TemplateAbsent(value),
                "template_present" => Expect::TemplatePresent(value),
                "out_absent" => Expect::OutAbsent(value),
                "out_present" => Expect::OutPresent(value),
                "err_present" => Expect::ErrPresent(value),
                "exit" => Expect::Exit(
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
                todo,
            });
            continue;
        }

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
        } else if raw.starts_with("##") || raw.trim().is_empty() {
            // File header, or the blank line that closes a block.
        } else {
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

/// What one run of the binary produced.
struct Run {
    stdout: String,
    stderr: String,
    status: i32,
}

/// Run the binary over a case's lines.
fn run(case: &Case, threads: &str) -> Run {
    let mut args: Vec<String> = vec!["--threads".into(), threads.into(), "-q".into()];
    args.extend(case.flags.iter().cloned());
    if case.expect.needs_json() && !case.flags.iter().any(|f| f == "--format") {
        args.push("--format".into());
        args.push("json".into());
    }

    let mut child = Command::new(BIN)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn lessence");
    // A case may exercise a flag combination the binary refuses, in which case
    // it exits before reading all of stdin. The broken pipe is the behaviour
    // under test, not a harness failure — the expectation checks the exit code.
    let mut stdin = child.stdin.take().expect("stdin");
    for line in &case.lines {
        if writeln!(stdin, "{line}").is_err() {
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

/// `elapsed_ms` is wall-clock and differs run to run; it is not part of the
/// fold. Everything else in the output is.
fn without_timing(stdout: &str) -> String {
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
    out
}

/// The `normalized` field of the first group record.
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

/// Run every case in `cases`, returning one complaint per failure.
fn check(cases: &[Case]) -> Vec<String> {
    let mut failures = Vec::new();
    for case in cases {
        let got = run(case, "1");
        let stdout = got.stdout.as_str();
        let complaint = match &case.expect {
            Expect::Groups(want) => {
                let n = count_groups(stdout);
                (n != *want).then(|| format!("want {want} group(s), got {n}\n     {stdout}"))
            }
            Expect::TemplateAbsent(text) => {
                let t = first_template(stdout);
                t.contains(text.as_str())
                    .then(|| format!("`{text}` must not appear\n     template: {t}"))
            }
            Expect::TemplatePresent(text) => {
                let t = first_template(stdout);
                (!t.contains(text.as_str()))
                    .then(|| format!("`{text}` is missing\n     template: {t}"))
            }
            Expect::OutAbsent(text) => {
                let needle = unescape(text);
                stdout
                    .contains(&needle)
                    .then(|| format!("`{text}` must not appear in output\n     {stdout}"))
            }
            Expect::OutPresent(text) => {
                let needle = unescape(text);
                (!stdout.contains(&needle))
                    .then(|| format!("`{text}` is missing from output\n     {stdout}"))
            }
            Expect::ErrPresent(text) => {
                let needle = unescape(text);
                (!got.stderr.contains(&needle))
                    .then(|| format!("`{text}` is missing from stderr\n     {}", got.stderr))
            }
            Expect::Exit(want) => (got.status != *want)
                .then(|| format!("want exit {want}, got {}\n     {}", got.status, got.stderr)),
        };
        if let Some(detail) = complaint {
            failures.push(format!(
                "{}\n     {}\n     from: {}\n     flags: {:?}\n     {detail}",
                case.bead, case.why, case.from, case.flags
            ));
        }
    }
    failures
}

#[test]
fn known_fold_regressions() {
    let cases: Vec<Case> = parse(CORPUS).into_iter().filter(|c| !c.todo).collect();
    let failures = check(&cases);
    assert!(
        failures.is_empty(),
        "{} of {} fold regressions came back:\n\n{}\n",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

/// The `##TODO` blocks: defects the 25-corpus study found that have no fix
/// yet. Ignored so the suite stays green; run it to see what is still open,
/// and promote a block to `##CASE` when its fix lands:
///
///     cargo test --test integration known_open_defects -- --ignored --nocapture
#[test]
#[ignore = "documents open defects; promote each ##TODO to ##CASE as it is fixed"]
fn known_open_defects() {
    let cases: Vec<Case> = parse(CORPUS).into_iter().filter(|c| c.todo).collect();
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
    // Deliberately no assert: this test reports, it does not gate.
}

/// `\e` for the escape byte, so an ANSI case stays readable in the corpus.
fn unescape(text: &str) -> String {
    text.replace("\\e", "\u{1b}").replace("\\t", "\t")
}

/// Every case must produce identical output however many threads run it. The
/// parallel path batches and re-clusters, which is a separate way to get the
/// same fold wrong.
#[test]
fn every_case_is_identical_at_any_thread_count() {
    for case in parse(CORPUS) {
        assert_eq!(
            without_timing(&run(&case, "1").stdout),
            without_timing(&run(&case, "8").stdout),
            "{} — {} differs at 8 threads",
            case.bead,
            case.why
        );
    }
}
