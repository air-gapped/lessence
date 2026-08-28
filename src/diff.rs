//! `--diff <other-lessence>`: which lines fold differently between two builds?
//!
//! Every fold change this project has shipped was measured the same way: run
//! two binaries, diff two outputs, then stare at hundreds of changed lines to
//! work out which *input lines* actually moved and whether that was right.
//! This is that loop as one command. It reads two `--format json` streams and
//! joins them on `first.line_no`, so it exercises no folding code of its own
//! and cannot change what either binary does.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// One folded group as the JSON stream reports it — only what the join needs.
#[derive(Debug, serde::Deserialize)]
struct Group {
    count: usize,
    first: Line,
    last: Line,
}

#[derive(Debug, serde::Deserialize)]
struct Line {
    line_no: usize,
    #[serde(default)]
    source: Option<String>,
}

/// `(source, line_no)` of a group's first line: the one key that identifies
/// a group across builds, since ids are assigned in flush order.
type Key = (Option<String>, usize);

/// A run's groups keyed by their founding line, plus each line's own group.
struct Fold {
    groups: BTreeMap<Key, Group>,
}

impl Fold {
    /// Run `bin` over `files` and parse the group records it emits.
    fn run(bin: &Path, files: &[PathBuf], threads: &str) -> Result<Self> {
        let out = Command::new(bin)
            .args(["--format", "json", "--threads", threads, "-q"])
            .args(files)
            .output()
            .with_context(|| format!("could not run {}", bin.display()))?;
        if !out.status.success() {
            bail!(
                "{} exited with {}: {}",
                bin.display(),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let mut groups = BTreeMap::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            // The summary record has no `first`; anything else that fails to
            // parse is a real problem with the other binary's output.
            if line.contains(r#""type":"summary""#) {
                continue;
            }
            let g: Group = serde_json::from_str(line)
                .with_context(|| format!("{}: unparseable group record", bin.display()))?;
            groups.insert((g.first.source.clone(), g.first.line_no), g);
        }
        Ok(Self { groups })
    }
}

/// Compare `old` against `new` over the same input and print every group that
/// moved. Returns the number of differences, so the caller can set the exit
/// status like `diff(1)` does.
pub fn run(old: &Path, new: &Path, files: &[PathBuf], threads: &str) -> Result<usize> {
    let before = Fold::run(old, files, threads)?;
    let after = Fold::run(new, files, threads)?;

    // Build the report first, write it second: keeps the borrow of stdout
    // out of the comparison, and lets one place handle a closed pipe.
    let mut lines: Vec<String> = Vec::new();
    let mut report = |kind: &str, key: &Key, detail: String| {
        let src = key.0.as_deref().unwrap_or("-");
        lines.push(format!("{kind:<6} {src}:{:<7} {detail}", key.1));
    };

    for (key, g) in &before.groups {
        match after.groups.get(key) {
            None => report(
                "joined",
                key,
                format!("was its own group of {}; now folds into another", g.count),
            ),
            Some(n) if n.count != g.count => report(
                "resized",
                key,
                format!(
                    "{} -> {} lines (last line {} -> {})",
                    g.count, n.count, g.last.line_no, n.last.line_no
                ),
            ),
            Some(_) => {}
        }
    }
    for (key, n) in &after.groups {
        if !before.groups.contains_key(key) {
            report(
                "split",
                key,
                format!(
                    "founded a new group of {}; used to fold into another",
                    n.count
                ),
            );
        }
    }
    let diffs = lines.len();
    lines.push(format!(
        "groups: {} -> {}   moved: {diffs}",
        before.groups.len(),
        after.groups.len()
    ));

    // A reader that stops early (`| head`) closes the pipe; that is the
    // reader's decision, not an error worth a panic.
    let mut out = io::stdout().lock();
    for line in &lines {
        match writeln!(out, "{line}") {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(diffs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Fold {
        let mut groups = BTreeMap::new();
        for line in json.lines() {
            if line.contains(r#""type":"summary""#) {
                continue;
            }
            let g: Group = serde_json::from_str(line).unwrap();
            groups.insert((g.first.source.clone(), g.first.line_no), g);
        }
        Fold { groups }
    }

    #[test]
    fn a_group_record_parses_down_to_the_join_key() {
        let f = parse(
            r#"{"type":"group","id":0,"count":3,"normalized":"x","first":{"source":"a.log","line":"x","line_no":4},"last":{"source":"a.log","line":"x","line_no":9},"time_range":{}}
{"type":"summary","input_lines":3}"#,
        );
        let g = &f.groups[&(Some("a.log".into()), 4)];
        assert_eq!(g.count, 3);
        assert_eq!(g.last.line_no, 9);
    }

    #[test]
    fn stdin_source_is_null_and_still_keys() {
        let f = parse(
            r#"{"type":"group","count":1,"first":{"source":null,"line":"x","line_no":1},"last":{"source":null,"line":"x","line_no":1}}"#,
        );
        assert!(f.groups.contains_key(&(None, 1)));
    }
}
