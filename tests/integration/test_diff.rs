use std::os::unix::fs::PermissionsExt;

#[test]
fn diff_reports_changes_and_uses_diff_exit_status() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("input.log");
    std::fs::write(&log, "alpha\nalpha\nbeta\nbeta\nbeta\ngamma\n").unwrap();
    let old_records = dir.path().join("old.jsonl");
    let records: Vec<String> = [(2, 1, 2), (7, 3, 9), (1, 4, 4)]
        .into_iter()
        .map(|(count, first, last)| {
            serde_json::json!({
                "count": count,
                "first": {"source": log, "line_no": first},
                "last": {"source": log, "line_no": last},
            })
            .to_string()
        })
        .collect();
    std::fs::write(&old_records, records.join("\n") + "\n").unwrap();
    let old = dir.path().join("old-lessence");
    std::fs::write(
        &old,
        format!("#!/bin/sh\ncat '{}'\n", old_records.display()),
    )
    .unwrap();
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o700)).unwrap();

    let bin = env!("CARGO_BIN_EXE_lessence");
    let output = crate::common::command(bin)
        .arg("--diff")
        .arg(&old)
        .arg(&log)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    let source = log.display();
    assert_eq!(
        text,
        format!(
            "resized {source}:3       7 -> 3 lines (last line 9 -> 5)\n\
             joined {source}:4       was its own group of 1; now folds into another\n\
             split  {source}:6       founded a new group of 1; used to fold into another\n\
             groups: 3 -> 3   moved: 3\n"
        )
    );

    let identical = crate::common::command(bin)
        .args(["--diff", bin])
        .arg(&log)
        .output()
        .unwrap();
    assert!(identical.status.success());
    assert_eq!(
        String::from_utf8(identical.stdout).unwrap(),
        "groups: 3 -> 3   moved: 0\n"
    );
}

#[test]
fn diff_passes_a_dash_named_file_as_a_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("-q"), "alpha\nbeta\n").unwrap();
    let bin = env!("CARGO_BIN_EXE_lessence");
    let output = crate::common::command(bin)
        .current_dir(dir.path())
        .args(["--diff", bin, "--", "-q"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("groups: 0 -> 0"), "{text}");
}

#[test]
fn diff_refuses_flags_its_folds_would_ignore_even_at_default_values() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("in.log");
    std::fs::write(&log, "alpha\n").unwrap();
    let bin = env!("CARGO_BIN_EXE_lessence");
    for flag in [
        ["--threshold", "83"],
        ["--min-collapse", "3"],
        ["--max-lines", "10"],
        ["--max-line-length", "100"],
        ["--fail-on-pattern", "x"],
    ] {
        let output = crate::common::command(bin)
            .args(["--diff", bin])
            .args(flag)
            .arg(&log)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{flag:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(flag[0]),
            "{flag:?}"
        );
    }
}

#[test]
fn an_empty_name_in_disable_patterns_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("in.log");
    std::fs::write(&log, "alpha\n").unwrap();
    let output = crate::common::command(env!("CARGO_BIN_EXE_lessence"))
        .args(["--disable-patterns", "json,"])
        .arg(&log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
