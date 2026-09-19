//! `--skill` ships the agent skill from the binary (lessence-xo4).

use std::process::{Command, Stdio};

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run lessence");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn skill_prints_the_frontmatter_first_and_the_provenance_after_it() {
    let (code, out, err) = run(&["--skill"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("---\nname: lessence\n"), "{}", &out[..60]);
    let after = out.find("\n---\n").expect("frontmatter end") + 5;
    let note = &out[after..];
    assert!(
        note.starts_with("<!-- Printed by `lessence --skill` from lessence "),
        "{}",
        &note[..80]
    );
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        note.contains(&format!("from lessence {version} (")),
        "{}",
        &note[..120]
    );
    assert!(out.contains("## Core Commands"));
    assert!(
        out.contains("lessence --skill"),
        "the skill tells the agent how to reinstall itself"
    );
}

#[test]
fn skill_flags_prints_the_flag_reference() {
    let (code, out, _) = run(&["--skill", "flags"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("<!-- Printed by"));
    assert!(out.contains("# lessence — Complete Flag Reference"));
    assert!(out.contains("--skill"));
}

#[test]
fn skill_exits_before_reading_input_and_ignores_files() {
    // stdin is null and the file does not exist: --skill must not open either
    let (code, out, err) = run(&["--skill", "/nonexistent/never.log"]);
    assert_eq!(code, 2, "a file name is not a topic: {out}");
    assert!(err.contains("unknown --skill topic"), "{err}");
    let (code, out, _) = run(&["--skill", "skill", "/nonexistent/never.log"]);
    assert_eq!(code, 0, "with an explicit topic the file is never opened");
    assert!(out.starts_with("---\n"));
}

#[test]
fn skill_unknown_topic_exits_2_and_names_the_topics() {
    let (code, out, err) = run(&["--skill", "recipes"]);
    assert_eq!(code, 2);
    assert!(out.is_empty());
    assert!(err.contains("skill, flags"), "{err}");
}

#[test]
fn json_is_the_same_as_format_json() {
    let input = "alpha one\nalpha two\nalpha three\nalpha four\n";
    let with_flag = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--json", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.take().unwrap().write_all(input.as_bytes())?;
            c.wait_with_output()
        })
        .unwrap();
    let with_format = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--format", "json", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.take().unwrap().write_all(input.as_bytes())?;
            c.wait_with_output()
        })
        .unwrap();
    let a = String::from_utf8_lossy(&with_flag.stdout);
    let b = String::from_utf8_lossy(&with_format.stdout);
    assert!(a.trim_end().ends_with('}'), "{a}");
    // identical modulo elapsed_ms
    let strip = |s: &str| s.replace(|c: char| c.is_ascii_digit(), "");
    assert_eq!(strip(&a), strip(&b));
}

#[test]
fn json_conflicts_with_an_explicit_format_and_with_distill() {
    for args in [
        &["--json", "--format", "text"][..],
        &["--json", "--format", "markdown"][..],
        &["--json", "--format", "json"][..],
    ] {
        let (code, _, err) = run(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(
            err.contains("--json") && err.contains("--format"),
            "{args:?}: {err}"
        );
    }
    let (code, _, err) = run(&["--json", "--distill"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--json"), "{err}");
}

#[test]
fn json_works_with_summary_top_and_explain() {
    for args in [
        &["--json", "--summary", "-q"][..],
        &["--json", "--top", "2", "-q"][..],
        &["--json", "--explain", "-q"][..],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_lessence"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin
                    .take()
                    .unwrap()
                    .write_all(b"alpha one\nalpha two\nalpha three\nbeta\n")?;
                c.wait_with_output()
            })
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        let last = text.lines().last().unwrap_or("");
        assert!(
            last.starts_with('{') && last.ends_with('}'),
            "{args:?}: {last}"
        );
    }
}
