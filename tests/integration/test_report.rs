use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn bin() -> Command {
    crate::common::lessence()
}

// /tmp is a tmpfs on most Linux distributions.
fn disk_backed_tmpdir() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-reports");
    std::fs::create_dir_all(&base).expect("scratch dir");
    tempfile::TempDir::new_in(&base).expect("scratch dir")
}

fn distilled_corpora() -> Vec<PathBuf> {
    let dir = Path::new("examples/distilled");
    let Ok(entries) = std::fs::read_dir(dir) else {
        assert!(
            std::env::var_os("CI").is_some(),
            "examples/distilled is required for this test and could not be read; a gate never passes by absence (only CI, which carries no corpora, skips)"
        );
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "log"))
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty() || std::env::var_os("CI").is_some(),
        "examples/distilled holds no corpora"
    );
    paths
}

fn run_default(dir: &Path, args: &[&str]) -> Output {
    bin()
        .args(["--report-dir", dir.to_str().unwrap()])
        .args(args)
        .output()
        .expect("failed to run lessence")
}

fn report_file(dir: &Path) -> PathBuf {
    let runs: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("report dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    assert_eq!(runs.len(), 1, "exactly one run directory: {runs:?}");
    let name = runs[0].file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.starts_with("run-") && name.len() == "run-20260919-161814-f1362b46".len(),
        "run directory is run-<UTC yyyymmdd-hhmmss>-<8 hex>: {name}"
    );
    runs[0].join("report.jsonl")
}

fn records(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad record {l:.120}: {e}")))
        .collect()
}

fn groups(records: &[Value]) -> Vec<&Value> {
    records.iter().filter(|r| r["type"] == "group").collect()
}

#[test]
fn the_report_is_the_same_inventory_format_json_produces_on_every_corpus() {
    crate::common::sweep_corpora(&distilled_corpora(), |corpus| {
        let tmp = disk_backed_tmpdir();
        let run = run_default(tmp.path(), &["-q", corpus.to_str().unwrap()]);
        assert!(
            run.status.success(),
            "{}: {}",
            corpus.display(),
            String::from_utf8_lossy(&run.stderr)
        );
        let report = std::fs::read_to_string(report_file(tmp.path())).unwrap();

        let json = bin()
            .args(["--format", "json", "-q"])
            .arg(corpus)
            .output()
            .expect("failed to run lessence --format json");
        assert!(
            json.status.success(),
            "{}: --format json exited {:?}: {}",
            corpus.display(),
            json.status.code(),
            String::from_utf8_lossy(&json.stderr)
        );
        let json = String::from_utf8(json.stdout).unwrap();

        let (a, b) = (records(&report), records(&json));
        let (ga, gb) = (groups(&a), groups(&b));
        assert_eq!(
            ga.len(),
            gb.len(),
            "{}: group count differs",
            corpus.display()
        );
        assert!(!ga.is_empty(), "{}: no groups at all", corpus.display());
        for (x, y) in ga.iter().zip(&gb) {
            assert_eq!(
                x,
                y,
                "{}: the report must be the same inventory --format json produces; a group record differs",
                corpus.display()
            );
        }

        let mut sa = a.last().unwrap().clone();
        let mut sb = b.last().unwrap().clone();
        assert_eq!(sa["type"], "summary", "{}", corpus.display());
        assert_eq!(sb["type"], "summary", "{}", corpus.display());
        for s in [&mut sa, &mut sb] {
            s.as_object_mut().unwrap().remove("elapsed_ms");
        }
        assert_eq!(
            sa,
            sb,
            "{}: the summary must match --format json except elapsed_ms",
            corpus.display()
        );

        let text = std::fs::read_to_string(corpus).unwrap();
        let raw: Vec<&str> = text.lines().collect();
        for g in &ga {
            let line_no = g["first"]["line_no"].as_u64().unwrap() as usize;
            assert_eq!(
                g["first"]["line"].as_str().unwrap(),
                raw[line_no - 1],
                "{}: with no transforming options, group {} first.line is not the raw line at {line_no}",
                corpus.display(),
                g["id"]
            );
        }
    });
}

#[test]
fn default_stdout_stays_inside_sixteen_kib_on_every_corpus() {
    crate::common::sweep_corpora(&distilled_corpora(), |corpus| {
        let tmp = disk_backed_tmpdir();
        let run = run_default(tmp.path(), &[corpus.to_str().unwrap()]);
        assert!(run.status.success(), "{}", corpus.display());
        assert!(
            run.stdout.len() <= 16384,
            "{}: {} bytes of stdout at default flags",
            corpus.display(),
            run.stdout.len()
        );
        let stdout = String::from_utf8(run.stdout).unwrap();
        assert!(
            stdout.contains(" total, ") && stdout.contains(" omitted"),
            "{}: the locator must count what it omitted",
            corpus.display()
        );
    });
}

fn fixture() -> &'static str {
    "tests/fixtures/nginx_sample.log"
}

#[test]
fn the_locator_is_the_first_and_the_last_line_and_names_the_report() {
    let tmp = disk_backed_tmpdir();
    let run = run_default(tmp.path(), &["-q", fixture()]);
    assert!(run.status.success());
    let stdout = String::from_utf8(run.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    let path = report_file(tmp.path());

    let head = lines[0];
    assert!(head.starts_with("report: "), "{head}");
    assert!(head.contains(path.to_str().unwrap()), "{head}");
    assert!(head.contains("file: complete"), "{head}");
    assert!(head.contains("input: complete"), "{head}");
    assert!(head.contains("run: run-"), "{head}");
    assert!(head.contains(" size: "), "{head}");

    let tail_locator = lines
        .iter()
        .rposition(|l| l.starts_with("report: "))
        .expect("a tail locator");
    assert_eq!(lines[tail_locator], head, "the tail repeats the locator");
    let tail = lines[tail_locator..].join("\n");
    assert_eq!(tail.matches("jq ").count(), 4, "four recipes: {tail}");
    assert!(
        tail.contains("potentially large: a full record can be arbitrarily long"),
        "the full-record recipe labels its own cost: {tail}"
    );
    assert!(!tail.contains("cat "), "no recipe cats the report: {tail}");
}

#[test]
fn quiet_drops_the_briefing_block_and_keeps_the_locators() {
    let tmp = disk_backed_tmpdir();
    let loud = run_default(tmp.path(), &[fixture()]);
    let quiet_dir = disk_backed_tmpdir();
    let quiet = run_default(quiet_dir.path(), &["-q", fixture()]);

    let loud = String::from_utf8(loud.stdout).unwrap();
    let quiet = String::from_utf8(quiet.stdout).unwrap();
    assert!(loud.contains("lessence briefing"), "{loud}");
    assert!(!quiet.contains("lessence briefing"), "{quiet}");
    assert!(quiet.starts_with("report: "), "{quiet}");
    assert!(
        quiet.contains('[') && quiet.contains("x] id="),
        "entries stay"
    );
}

#[test]
fn overview_zero_prints_no_entries_and_overview_n_prints_n() {
    let tmp = disk_backed_tmpdir();
    let none = run_default(tmp.path(), &["-q", "--overview", "0", fixture()]);
    let none = String::from_utf8(none.stdout).unwrap();
    assert!(none.contains("0 selected, 0 printed"), "{none}");
    assert!(!none.contains("x] id="), "no entries: {none}");

    let some = disk_backed_tmpdir();
    let out = run_default(some.path(), &["-q", "--overview", "3", fixture()]);
    let out = String::from_utf8(out.stdout).unwrap();
    assert_eq!(out.matches("x] id=").count(), 3, "exactly 3 entries: {out}");
    assert!(out.contains("3 selected, 3 printed"), "{out}");
}

#[test]
fn overview_all_prints_every_group_the_report_holds() {
    let tmp = disk_backed_tmpdir();
    let run = run_default(tmp.path(), &["-q", "--overview", "all", fixture()]);
    assert!(run.status.success());
    let stdout = String::from_utf8(run.stdout).unwrap();
    let report = std::fs::read_to_string(report_file(tmp.path())).unwrap();
    let total = groups(&records(&report)).len();
    assert!(total > 3, "the fixture must have several groups");
    assert!(
        stdout.contains(&format!(
            "{total} total, {total} selected, {total} printed, 0 omitted"
        )),
        "{stdout}"
    );
    for id in 0..total {
        assert!(stdout.contains(&format!("id={id} ")), "group {id} missing");
    }
}

#[test]
fn no_report_writes_nothing_and_streams_the_folded_text() {
    let tmp = disk_backed_tmpdir();
    let run = bin()
        .env("LESSENCE_REPORT_DIR", tmp.path())
        .args(["--no-report", "-q", fixture()])
        .output()
        .unwrap();
    assert!(run.status.success());
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert!(
        !stdout.starts_with("report: "),
        "no overview: {stdout:.200}"
    );
    assert!(!stdout.contains("\"type\":\"group\""), "text, not JSON");
    assert_eq!(
        std::fs::read_dir(tmp.path()).unwrap().count(),
        0,
        "--no-report must not create anything"
    );
}

#[test]
fn a_non_empty_xdg_state_home_carries_the_default_report_directory() {
    let tmp = disk_backed_tmpdir();
    let run = bin()
        .env_remove("LESSENCE_REPORT_DIR")
        .env("XDG_STATE_HOME", tmp.path())
        .args(["-q", fixture()])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let reports = tmp.path().join("lessence/reports");
    assert!(
        report_file(&reports).is_file(),
        "the default lands under $XDG_STATE_HOME/lessence/reports"
    );
}

#[test]
fn the_environment_directory_is_used_when_no_flag_gives_one() {
    let tmp = disk_backed_tmpdir();
    let nested = tmp.path().join("a/b");
    let run = bin()
        .env("LESSENCE_REPORT_DIR", &nested)
        .args(["-q", fixture()])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        report_file(&nested).is_file(),
        "missing parents are created"
    );
}

fn usage_error(args: &[&str]) -> String {
    let out = bin().args(args).stdin(Stdio::null()).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected a usage error from {args:?}, got {:?}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stderr).unwrap()
}

const NO_REPORT_MODES: [&str; 8] = [
    "--format=json",
    "--json",
    "--format=markdown",
    "--summary",
    "--top=5",
    "--fit",
    "--preflight",
    "--explain",
];

#[test]
fn every_report_flag_is_a_usage_error_outside_the_default_text_run() {
    for mode in NO_REPORT_MODES {
        for flag in [
            "--report-dir=/tmp/x",
            "--report-max-bytes=4096",
            "--overview=5",
            "--overview-bytes=999",
        ] {
            let err = usage_error(&[mode, flag, fixture()]);
            assert!(
                err.contains(flag.split('=').next().unwrap()),
                "the error must name {flag}: {err}"
            );
        }
    }
}

fn stdout_without_run_dependent_values(out: &Output) -> String {
    let text = String::from_utf8_lossy(&out.stdout);
    let text = regex::Regex::new(r#""elapsed_ms": ?\d+"#)
        .unwrap()
        .replace_all(&text, r#""elapsed_ms":0"#);
    regex::Regex::new(r"(?m)^\*Generated by .*$")
        .unwrap()
        .replace_all(&text, "*Generated by*")
        .into_owned()
}

#[test]
fn no_report_is_accepted_and_changes_nothing_in_a_mode_that_writes_no_report() {
    let modes = NO_REPORT_MODES
        .iter()
        .map(|mode| vec![*mode, fixture()])
        .chain([vec!["--skill"]]);
    for args in modes {
        let mode = args[0];
        let with = bin()
            .args(&args)
            .arg("--no-report")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let without = bin().args(&args).stdin(Stdio::null()).output().unwrap();
        let stderr = String::from_utf8_lossy(&with.stderr);
        assert_eq!(with.status.code(), Some(0), "{mode} --no-report: {stderr}");
        assert!(!stderr.contains("--no-report"), "{mode}: {stderr}");
        assert_eq!(
            stdout_without_run_dependent_values(&with),
            stdout_without_run_dependent_values(&without),
            "{mode}: --no-report must change nothing"
        );
    }
}

#[test]
fn no_report_cannot_be_combined_with_a_report_flag() {
    for flag in [
        "--report-dir=/tmp/x",
        "--report-max-bytes=4096",
        "--overview=5",
        "--overview-bytes=999",
    ] {
        let err = usage_error(&["--no-report", flag, fixture()]);
        assert!(err.contains("--no-report"), "{err}");
        assert!(err.contains(flag.split('=').next().unwrap()), "{err}");
    }
}

#[test]
fn overview_above_the_maximum_and_all_with_a_byte_budget_are_usage_errors() {
    let err = usage_error(&["--overview=10001", fixture()]);
    assert!(err.contains("10000"), "{err}");
    let tmp = disk_backed_tmpdir();
    assert!(
        run_default(tmp.path(), &["-q", "--overview", "10000", fixture()])
            .status
            .success(),
        "--overview 10000 itself is accepted: the check is a bound, not a ban"
    );

    let err = usage_error(&["--overview=all", "--overview-bytes=1", fixture()]);
    assert!(err.contains("--overview-bytes"), "{err}");

    let err = usage_error(&["--overview=lots", fixture()]);
    assert!(err.contains("'lots'"), "{err}");
}

fn assert_no_partial(dir: &Path) {
    let leftovers: Vec<PathBuf> = walk(dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "partial"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "a .partial was left behind: {leftovers:?}"
    );
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn a_quota_too_small_for_the_report_writes_no_report_and_exits_one() {
    let tmp = disk_backed_tmpdir();
    let run = run_default(tmp.path(), &["--report-max-bytes", "4096", "-q", fixture()]);
    assert_eq!(run.status.code(), Some(1));
    let err = String::from_utf8(run.stderr).unwrap();
    assert!(err.contains("report: not written"), "{err}");
    assert!(err.contains("--report-max-bytes 4096"), "{err}");
    assert_no_partial(tmp.path());
    assert!(walk(tmp.path()).is_empty(), "nothing is left on disk");
}

#[cfg(unix)] // a directory is made unwritable with Unix mode bits
#[test]
fn an_unwritable_directory_fails_before_any_input_is_read() {
    let tmp = disk_backed_tmpdir();
    let locked = tmp.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    let run = bin()
        .args(["--report-dir", locked.to_str().unwrap(), "-q", fixture()])
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(1));
    let err = String::from_utf8(run.stderr).unwrap();
    assert!(err.contains("report: not written"), "{err}");
    assert!(
        err.contains("--no-report"),
        "the error names the way out: {err}"
    );
    assert!(err.contains("--report-dir"), "{err}");
    assert!(
        !err.contains("lessence briefing"),
        "nothing was folded, so there is no briefing: {err}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn tmpfs_is_rejected_for_automatic_placement_and_accepted_by_the_explicit_pair() {
    let shm = Path::new("/dev/shm");
    if !shm.is_dir() {
        eprintln!("Skipping: no /dev/shm on this machine");
        return;
    }
    let dir = shm.join(format!("lessence-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let run = bin()
        .env("LESSENCE_REPORT_DIR", &dir)
        .args(["-q", fixture()])
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(1));
    let err = String::from_utf8(run.stderr).unwrap();
    assert!(
        err.contains("tmpfs"),
        "automatic placement through the environment is rejected by name: {err}"
    );
    assert!(walk(&dir).is_empty(), "nothing is written to a rejected fs");

    let run = bin()
        .args(["--report-dir", dir.to_str().unwrap(), "-q", fixture()])
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(1),
        "an explicit dir alone is refused"
    );

    let run = bin()
        .args([
            "--report-dir",
            dir.to_str().unwrap(),
            "--report-max-bytes",
            "10M",
            "-q",
            fixture(),
        ])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "the explicit pair accepts any filesystem: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(report_file(&dir).is_file());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_failure_writing_the_first_record_removes_the_partial_and_says_the_input_is_complete() {
    let tmp = disk_backed_tmpdir();
    let run = bin()
        .env("LESSENCE_TEST_FAIL_WRITE", "1")
        .args([
            "--threads",
            "1",
            "--report-dir",
            tmp.path().to_str().unwrap(),
            "-q",
            fixture(),
        ])
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(1));
    let err = String::from_utf8(run.stderr).unwrap();
    assert!(err.contains("report: not written"), "{err}");
    assert!(
        err.contains("record 1"),
        "the failure names the first write: {err}"
    );
    assert!(
        err.contains("briefing: input complete"),
        "every record is written after EOF, so the input is complete: {err}"
    );
    assert_no_partial(tmp.path());
    assert!(walk(tmp.path()).is_empty());
}

#[test]
fn a_failure_writing_the_summary_record_never_claims_a_complete_report() {
    let tmp = disk_backed_tmpdir();
    let clean = disk_backed_tmpdir();
    run_default(clean.path(), &["-q", fixture()]);
    let summary_record_number = std::fs::read_to_string(report_file(clean.path()))
        .unwrap()
        .lines()
        .count();

    let run = bin()
        .env(
            "LESSENCE_TEST_FAIL_WRITE",
            summary_record_number.to_string(),
        )
        .args([
            "--report-dir",
            tmp.path().to_str().unwrap(),
            "-q",
            fixture(),
        ])
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(1));
    let err = String::from_utf8(run.stderr).unwrap();
    assert!(err.contains("report: not written"), "{err}");
    assert!(
        err.contains(&format!("record {summary_record_number}")),
        "the failure names the summary write: {err}"
    );
    assert!(
        !err.contains("input incomplete"),
        "EOF was reached, so the input is not incomplete: {err}"
    );
    assert_no_partial(tmp.path());
    assert!(walk(tmp.path()).is_empty());
}

#[test]
fn a_directory_fsync_failure_after_the_rename_keeps_the_complete_report() {
    let tmp = disk_backed_tmpdir();
    let run = bin()
        .env("LESSENCE_TEST_FAIL_DIR_FSYNC", "1")
        .args([
            "--report-dir",
            tmp.path().to_str().unwrap(),
            "-q",
            fixture(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(1),
        "a failed fsync is still a failure"
    );
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert!(
        stdout.contains("file: complete, durability unconfirmed ("),
        "{stdout}"
    );
    assert!(stdout.contains("x] id="), "the overview still prints");
    let report = report_file(tmp.path());
    assert!(report.is_file(), "the renamed report is retained");
    let text = std::fs::read_to_string(&report).unwrap();
    assert_eq!(
        records(&text).last().unwrap()["type"],
        "summary",
        "and its content is complete"
    );
    assert_no_partial(tmp.path());
}

#[test]
fn a_fatal_utf8_error_removes_the_report_and_says_the_input_was_incomplete() {
    let tmp = disk_backed_tmpdir();
    let bad = tmp.path().join("bad.log");
    std::fs::write(&bad, b"fine line one\nfine line two\n\xff\xfe not utf8\n").unwrap();
    let run = bin()
        .args([
            "--report-dir",
            tmp.path().to_str().unwrap(),
            bad.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_ne!(
        run.status.code(),
        Some(0),
        "a fatal read error is not success"
    );
    let err = String::from_utf8_lossy(&run.stderr).into_owned();
    assert!(err.contains("report: not written"), "{err}");
    assert!(err.contains("input incomplete (aborted at line "), "{err}");
    assert_no_partial(tmp.path());
    assert!(
        walk(tmp.path()) == vec![bad],
        "only the input file is left: {:?}",
        walk(tmp.path())
    );
}

#[test]
fn a_damaged_report_leaves_the_file_in_place_and_says_the_overview_is_unavailable() {
    let tmp = disk_backed_tmpdir();
    let run = bin()
        .env("LESSENCE_TEST_TRUNCATE_REPORT", "200")
        .args([
            "--report-dir",
            tmp.path().to_str().unwrap(),
            "-q",
            fixture(),
        ])
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(1));
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert!(stdout.starts_with("report: "), "the locator is still first");
    assert!(
        stdout.contains("overview: unavailable (report is damaged: 200 bytes on disk, "),
        "no group is silently omitted: {stdout}"
    );
    assert!(stdout.contains("jq "), "the recipes still print");
    let report = report_file(tmp.path());
    assert!(report.is_file(), "the report stays where it is");
    assert_eq!(
        std::fs::metadata(&report).unwrap().len(),
        200,
        "the fixture truncated it, nothing else touched it"
    );
}

#[test]
fn a_degraded_input_still_completes_the_report_and_the_locator_names_the_code() {
    let tmp = disk_backed_tmpdir();
    let run = run_default(tmp.path(), &["--max-lines", "20", "-q", fixture()]);
    assert!(
        run.status.success(),
        "--max-lines is a degradation, not a failure"
    );
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert!(stdout.contains("file: complete"), "{stdout}");
    assert!(
        stdout.contains("input: degraded(input.max_lines_reached)"),
        "{stdout}"
    );
    let report = std::fs::read_to_string(report_file(tmp.path())).unwrap();
    let summary = records(&report).last().unwrap().clone();
    assert_eq!(
        summary["degraded"][0]["code"], "input.max_lines_reached",
        "stdout and the file agree on what the input was"
    );
}

#[test]
fn stats_json_goes_to_stderr_alongside_the_overview() {
    let tmp = disk_backed_tmpdir();
    let run = run_default(tmp.path(), &["--stats-json", fixture()]);
    assert!(run.status.success());
    let stdout = String::from_utf8(run.stdout).unwrap();
    let stderr = String::from_utf8(run.stderr).unwrap();
    assert!(stdout.starts_with("report: "), "{stdout:.200}");
    assert!(
        !stdout.contains("lessence briefing"),
        "--stats-json replaces the briefing block: {stdout:.200}"
    );
    let json: Value = serde_json::from_str(stderr.trim()).expect(&stderr);
    assert!(json["input_lines"].is_number(), "{stderr}");
}

#[cfg(unix)]
#[test]
fn the_run_directory_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = disk_backed_tmpdir();
    assert!(run_default(tmp.path(), &["-q", fixture()]).status.success());
    let report = report_file(tmp.path());
    assert_eq!(
        std::fs::metadata(report.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&report).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn fail_on_pattern_still_exits_one_with_a_complete_report() {
    let tmp = disk_backed_tmpdir();
    let run = run_default(tmp.path(), &["--fail-on-pattern", ".", "-q", fixture()]);
    assert_eq!(run.status.code(), Some(1));
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert!(stdout.contains("file: complete"), "{stdout}");
    assert!(report_file(tmp.path()).is_file());
}

#[test]
fn the_report_matches_format_json_under_the_transforming_options_too() {
    for options in [
        vec!["--sanitize-pii"],
        vec!["--sanitize", "email"],
        vec!["--frame-continuations"],
        vec!["--preserve-color"],
    ] {
        let tmp = disk_backed_tmpdir();
        let mut args = options.clone();
        args.extend(["-q", fixture()]);
        let run = run_default(tmp.path(), &args);
        assert!(
            run.status.success(),
            "{options:?}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        let report = std::fs::read_to_string(report_file(tmp.path())).unwrap();

        let mut json_args = vec!["--format", "json", "-q"];
        json_args.extend(options.iter().copied());
        json_args.push(fixture());
        let json = bin().args(&json_args).output().unwrap();
        let json = String::from_utf8(json.stdout).unwrap();

        let (a, b) = (records(&report), records(&json));
        let (ga, gb) = (groups(&a), groups(&b));
        assert_eq!(ga.len(), gb.len(), "{options:?}: group count differs");
        assert!(!ga.is_empty(), "{options:?}: no groups at all");
        for (x, y) in ga.iter().zip(&gb) {
            assert_eq!(
                x, y,
                "{options:?}: an option that transforms records must land in the report as in --format json; a group record differs"
            );
        }
        let mut sa = a.last().unwrap().clone();
        let mut sb = b.last().unwrap().clone();
        for s in [&mut sa, &mut sb] {
            s.as_object_mut().unwrap().remove("elapsed_ms");
        }
        assert_eq!(sa, sb, "{options:?}: summary differs");
    }
}

// Rust ignores SIGPIPE, so a closed reader surfaces as EPIPE on write.
fn with_closed_reader(dir: &Path, env: &[(&str, &str)], args: &[&str]) -> Option<i32> {
    let mut cmd = bin();
    cmd.args(["--report-dir", dir.to_str().unwrap()]).args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    drop(child.stdout.take());
    child.wait().expect("wait").code()
}

#[test]
fn a_closed_reader_keeps_a_successful_run_successful_and_keeps_the_report() {
    let tmp = disk_backed_tmpdir();
    assert_eq!(with_closed_reader(tmp.path(), &[], &[fixture()]), Some(0));
    assert!(report_file(tmp.path()).is_file(), "the artifact survives");
}

#[test]
fn a_closed_reader_never_turns_a_determined_failure_into_a_success() {
    let cases: Vec<(&str, Vec<(&str, &str)>, Vec<&str>)> = vec![
        ("failed source", vec![], vec![fixture(), "no/such/file.log"]),
        (
            "--fail-on-pattern",
            vec![],
            vec!["--fail-on-pattern", ".", fixture()],
        ),
        (
            "directory fsync failure",
            vec![("LESSENCE_TEST_FAIL_DIR_FSYNC", "1")],
            vec![fixture()],
        ),
        (
            "overview failure",
            vec![("LESSENCE_TEST_TRUNCATE_REPORT", "200")],
            vec![fixture()],
        ),
    ];
    for (name, env, args) in cases {
        let tmp = disk_backed_tmpdir();
        assert_eq!(
            with_closed_reader(tmp.path(), &env, &args),
            Some(1),
            "{name}: a broken stdout pipe must not become exit 0"
        );
        assert!(
            report_file(tmp.path()).is_file(),
            "{name}: the complete report is retained"
        );
        assert_no_partial(tmp.path());
    }
}

#[test]
fn diff_and_the_other_early_modes_reject_a_report_flag_instead_of_ignoring_it() {
    for args in [
        vec!["--diff", "/bin/true", "--report-dir", "/tmp/x", fixture()],
        vec!["--diff", "/bin/true", "--overview", "5", fixture()],
        vec!["--skill", "--report-dir", "/tmp/x"],
        vec!["--help-human", "--overview-bytes", "100"],
        vec!["--completions", "bash", "--report-max-bytes", "1M"],
    ] {
        let err = usage_error(&args);
        assert!(
            err.contains("default text run"),
            "{args:?} must be a usage error naming the default text run: {err}"
        );
    }
}

#[test]
fn a_rejected_combination_names_the_command_that_does_work() {
    let err = usage_error(&["--format=json", "--overview", "all", fixture()]);
    assert!(err.contains("--format json"), "{err}");
    let err = usage_error(&["--no-report", "--overview", "5", fixture()]);
    assert!(err.contains("drop --no-report"), "{err}");
}

// The memory bound needs a cgroup cap:
// systemd-run --user --scope -p MemoryMax=1G \
//   cargo nextest run --release --profile slow -E 'test(overview_all_streams)'
#[test]
fn overview_all_streams_two_hundred_thousand_groups_without_collecting_them() {
    use std::io::Write;

    const GROUPS: usize = 200_000;
    let tmp = disk_backed_tmpdir();
    let path = tmp.path().join("report.jsonl");
    {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        for id in 0..GROUPS {
            writeln!(
                f,
                r#"{{"type":"group","id":{id},"count":{},"normalized":"group {id} <NUMBER> <PATH>","time_range":{{"first_seen":null,"last_seen":null}},"variation":{{}}}}"#,
                id % 97 + 1
            )
            .unwrap();
        }
        writeln!(f, r#"{{"type":"summary","complete":true}}"#).unwrap();
    }

    struct ByteCounterKeepingTheHead {
        bytes: usize,
        head: Vec<u8>,
    }
    impl Write for ByteCounterKeepingTheHead {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes += buf.len();
            if self.head.len() < 4096 {
                self.head.extend_from_slice(buf);
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let locator = lessence::overview::Locator {
        path: &path,
        file: lessence::report::Finished::Durable,
        input: lessence::overview::InputState::Complete,
        run_id: "run-test",
        size_bytes: std::fs::metadata(&path).unwrap().len(),
    };
    let mut out = ByteCounterKeepingTheHead {
        bytes: 0,
        head: Vec::new(),
    };
    lessence::overview::render(
        &mut out,
        &path,
        &locator,
        lessence::overview::Entries::All,
        lessence::overview::DEFAULT_BYTES,
        None,
        None,
    )
    .expect("--overview all streams one record at a time and must complete on a 200k-group report");
    assert!(
        out.bytes > GROUPS * 20,
        "every group must have been written: {} bytes",
        out.bytes
    );
    let head = String::from_utf8_lossy(&out.head);
    assert!(
        head.contains(&format!("{GROUPS} total, {GROUPS} selected")),
        "{head}"
    );
}
