//! Fold-behaviour regressions, driven by `tests/fixtures/fold_regressions.log`.
//!
//! The corpus is the data; this file is only the harness. See the header of
//! that file for the block format and for why it exists.

use super::*;

const CORPUS: &str = include_str!("../../tests/fixtures/fold_regressions.log");

enum Expect {
    /// The lines must end up in exactly this many groups.
    Groups(usize),
    /// The first line's normalized form must not contain this placeholder.
    Absent(&'static str),
    /// The first line's normalized form must contain this text.
    Present(&'static str),
}

struct Case {
    bead: &'static str,
    why: String,
    from: &'static str,
    expect: Expect,
    lines: Vec<&'static str>,
}

/// Parse the corpus into cases. Panics loudly on a malformed block — a case
/// that silently fails to parse is a case that silently stops protecting.
fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    let mut current: Option<Case> = None;

    for (n, raw) in CORPUS.lines().enumerate() {
        let lineno = n + 1;
        if let Some(rest) = raw.strip_prefix("##CASE ") {
            if let Some(case) = current.take() {
                out.push(case);
            }
            let (bead, expect) = rest
                .split_once(' ')
                .unwrap_or_else(|| panic!("line {lineno}: ##CASE needs a bead and an expectation"));
            let expect = if let Some(n) = expect.strip_prefix("groups=") {
                Expect::Groups(
                    n.parse()
                        .unwrap_or_else(|_| panic!("line {lineno}: groups= wants a number")),
                )
            } else if let Some(tok) = expect.strip_prefix("absent=") {
                Expect::Absent(tok)
            } else if let Some(text) = expect.strip_prefix("present=") {
                Expect::Present(text)
            } else {
                panic!("line {lineno}: unknown expectation `{expect}`");
            };
            current = Some(Case {
                bead: bead.trim(),
                why: String::new(),
                from: "",
                expect,
                lines: Vec::new(),
            });
        } else if let Some(why) = raw.strip_prefix("##WHY ") {
            let case = current
                .as_mut()
                .unwrap_or_else(|| panic!("line {lineno}: ##WHY outside a case"));
            if !case.why.is_empty() {
                case.why.push(' ');
            }
            case.why.push_str(why.trim());
        } else if let Some(from) = raw.strip_prefix("##FROM ") {
            current
                .as_mut()
                .unwrap_or_else(|| panic!("line {lineno}: ##FROM outside a case"))
                .from = from.trim();
        } else if raw.starts_with("##") || raw.trim().is_empty() {
            // File header, or the blank line that ends a block.
        } else {
            current
                .as_mut()
                .unwrap_or_else(|| panic!("line {lineno}: input line outside a case"))
                .lines
                .push(raw);
        }
    }
    if let Some(case) = current.take() {
        out.push(case);
    }

    assert!(!out.is_empty(), "the regression corpus parsed to nothing");
    for case in &out {
        assert!(
            !case.lines.is_empty(),
            "{}: case has no input lines",
            case.bead
        );
        assert!(!case.why.is_empty(), "{}: case has no ##WHY", case.bead);
        assert!(!case.from.is_empty(), "{}: case has no ##FROM", case.bead);
    }
    out
}

fn folder() -> PatternFolder {
    PatternFolder::new(Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    })
}

#[test]
fn known_fold_regressions() {
    let cases = cases();
    let mut failures = Vec::new();

    for case in &cases {
        let mut f = folder();
        for line in &case.lines {
            f.process_line(line).unwrap();
        }
        let complaint = match case.expect {
            Expect::Groups(want) => {
                let got = f.buffer.len();
                (got != want).then(|| {
                    let templates: Vec<_> = f
                        .buffer
                        .iter()
                        .map(|g| g.first().normalized.clone())
                        .collect();
                    format!("want {want} group(s), got {got}\n     templates: {templates:#?}")
                })
            }
            Expect::Absent(placeholder) | Expect::Present(placeholder) => {
                let normalized = f
                    .normalizer
                    .normalize_line(case.lines[0].to_string())
                    .unwrap()
                    .normalized;
                let contains = normalized.contains(placeholder);
                let bad = match case.expect {
                    Expect::Absent(_) => contains,
                    _ => !contains,
                };
                bad.then(|| {
                    let verb = if contains {
                        "must not appear"
                    } else {
                        "is missing"
                    };
                    format!("`{placeholder}` {verb}\n     normalized: {normalized}")
                })
            }
        };
        if let Some(detail) = complaint {
            failures.push(format!(
                "{}\n     {}\n     from: {}\n     {detail}",
                case.bead, case.why, case.from
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} fold regressions came back:\n\n{}\n",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

/// Every case must fold identically however many threads run it. The parallel
/// path batches and re-clusters, so it is a separate way to get this wrong.
#[test]
fn every_case_folds_identically_at_any_thread_count() {
    for case in cases() {
        let mut single = folder();
        let mut multi = PatternFolder::new(Config {
            thread_count: Some(8),
            min_collapse: 3,
            ..Config::default()
        });
        for line in &case.lines {
            single.process_line(line).unwrap();
            multi.process_line(line).unwrap();
        }
        assert_eq!(
            single.finish().unwrap(),
            multi.finish().unwrap(),
            "{} — {} folds differently at 8 threads",
            case.bead,
            case.why
        );
    }
}
