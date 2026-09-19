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

    #[cfg(unix)]
    mod process {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{Mutex, MutexGuard};

        // These tests write a script and then execute it. A sibling test thread that forks a
        // child in between hands that child the still-open write descriptor until its exec,
        // and the script then fails with "text file busy". One at a time removes the race.
        static SERIAL: Mutex<()> = Mutex::new(());

        fn serial() -> MutexGuard<'static, ()> {
            SERIAL
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        /// The fork-to-exec window of any child spawned by another test thread can leave the
        /// script's write descriptor open; exec then fails with "text file busy". Retry it.
        fn retrying<T>(mut f: impl FnMut() -> Result<T>) -> Result<T> {
            let mut last = f();
            for _ in 0..20 {
                match &last {
                    Err(e) if format!("{e:#}").contains("Text file busy") => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        last = f();
                    }
                    _ => break,
                }
            }
            last
        }

        fn fold(bin: &Path, files: &[PathBuf], threads: &str) -> Result<Fold> {
            retrying(|| Fold::run(bin, files, threads))
        }

        fn cmp(old: &Path, new: &Path, files: &[PathBuf], threads: &str) -> Result<usize> {
            retrying(|| run(old, new, files, threads))
        }

        fn binary(dir: &Path, body: &str) -> PathBuf {
            let path = dir.join("other-lessence");
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            path
        }

        #[test]
        fn fold_runs_with_explicit_arguments_and_keeps_source_identity() {
            let _serial = serial();
            let dir = tempfile::tempdir().unwrap();
            let bin = binary(
                dir.path(),
                r#"[ "$#" = 7 ] && [ "$1" = --format ] && [ "$2" = json ] &&
[ "$3" = --threads ] && [ "$4" = 3 ] && [ "$5" = -q ] &&
[ "$6" = first.log ] && [ "$7" = 'second log' ] || exit 9
cat <<'JSON'
{"count":3,"first":{"source":"first.log","line_no":1},"last":{"line_no":7}}
{"count":2,"first":{"source":"second log","line_no":1},"last":{"line_no":5}}
{"count":1,"first":{"line_no":1},"last":{"line_no":1}}
{"type":"summary","input_lines":6}
JSON"#,
            );
            let fold = fold(&bin, &["first.log".into(), "second log".into()], "3")
                .expect("the child receives separate filename arguments");
            assert_eq!(fold.groups.len(), 3);
            let first = &fold.groups[&(Some("first.log".into()), 1)];
            assert_eq!((first.count, first.last.line_no), (3, 7));
            assert_eq!(fold.groups[&(Some("second log".into()), 1)].count, 2);
            assert_eq!(fold.groups[&(None, 1)].count, 1);
        }

        #[test]
        fn fold_reports_launch_exit_and_record_errors() {
            let _serial = serial();
            let dir = tempfile::tempdir().unwrap();
            let missing = fold(&dir.path().join("missing"), &[], "1")
                .err()
                .expect("missing binary must fail");
            assert!(missing.to_string().contains("could not run"));

            for (body, expected) in [
                ("echo 'fixture failure' >&2; exit 7", "fixture failure"),
                ("echo not-json", "unparseable group record"),
            ] {
                let bin = binary(dir.path(), body);
                let error = fold(&bin, &[], "1").err().expect("must fail");
                assert!(error.to_string().contains(expected), "{error:#}");
                assert!(error.to_string().contains("other-lessence"), "{error:#}");
            }
        }

        #[test]
        fn comparison_counts_joins_splits_and_resizes_but_not_unchanged_groups() {
            let _serial = serial();
            let old_dir = tempfile::tempdir().unwrap();
            let new_dir = tempfile::tempdir().unwrap();
            let old = binary(
                old_dir.path(),
                r#"cat <<'JSON'
{"count":2,"first":{"line_no":1},"last":{"line_no":2}}
{"count":7,"first":{"line_no":3},"last":{"line_no":9}}
{"count":1,"first":{"line_no":4},"last":{"line_no":4}}
JSON"#,
            );
            let new = binary(
                new_dir.path(),
                r#"cat <<'JSON'
{"count":2,"first":{"line_no":1},"last":{"line_no":2}}
{"count":3,"first":{"line_no":3},"last":{"line_no":5}}
{"count":1,"first":{"line_no":6},"last":{"line_no":6}}
JSON"#,
            );
            assert_eq!(cmp(&old, &new, &[], "1").unwrap(), 3);
            assert_eq!(cmp(&new, &new, &[], "1").unwrap(), 0);
        }

        #[test]
        fn comparison_distinguishes_sources_and_propagates_child_failure() {
            let _serial = serial();
            let old_dir = tempfile::tempdir().unwrap();
            let new_dir = tempfile::tempdir().unwrap();
            let old = binary(
                old_dir.path(),
                r#"echo '{"count":1,"first":{"source":"old.log","line_no":1},"last":{"line_no":1}}'"#,
            );
            let new = binary(
                new_dir.path(),
                r#"echo '{"count":1,"first":{"source":"new.log","line_no":1},"last":{"line_no":1}}'"#,
            );
            assert_eq!(cmp(&old, &new, &[], "1").unwrap(), 2);
            let bad = binary(new_dir.path(), "echo 'cannot fold' >&2; exit 7");
            for (before, after) in [(&old, &bad), (&bad, &old)] {
                let error = cmp(before, after, &[], "1").unwrap_err();
                assert!(error.to_string().contains("cannot fold"), "{error:#}");
            }
        }
    }
}
