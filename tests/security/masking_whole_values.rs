//! Masked values leave no byte behind, in any output stream or saved file,
//! whichever spelling of `--sanitize` asks for them. Every value here is
//! invented, from the documentation ranges.

use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

fn bin() -> Command {
    crate::common::lessence()
}

/// A disk-backed scratch directory: the report's filesystem policy refuses
/// the tmpfs `/tmp` usually is.
fn scratch() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-reports");
    std::fs::create_dir_all(&base).expect("scratch dir");
    tempfile::TempDir::new_in(&base).expect("scratch dir")
}

/// Every output mode; the ones that are a default text run also save a
/// report, which is read back with the streams.
const MODES: &[&[&str]] = &[
    &["--overview", "all"],
    &["--no-report"],
    &["--essence"],
    &["--format", "json"],
    &["--format", "markdown"],
    &["--top", "1"],
    &["--summary"],
    &["--preflight"],
];

fn saves_report(mode: &[&str]) -> bool {
    !mode.iter().any(|a| {
        matches!(
            *a,
            "--no-report" | "--format" | "--top" | "--summary" | "--preflight"
        )
    })
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// A tag followed directly by an alphanumeric.
static GLUED_TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<(?:IP|HOST|EMAIL|SECRET|JWT|KEY)(?::[0-9a-f]{16})?>[0-9A-Za-z]").unwrap()
});

fn write_input(dir: &Path, lines: &[String]) -> PathBuf {
    let path = dir.join("input.log");
    std::fs::write(&path, lines.join("\n") + "\n").expect("write input");
    path
}

/// stdout, stderr and every saved file of one run, concatenated.
fn run(input: &Path, args: &[&str], mode: &[&str]) -> String {
    let dir = scratch();
    let mut cmd = bin();
    cmd.args(args).args(mode);
    if saves_report(mode) {
        cmd.args(["--report-dir", dir.path().to_str().unwrap()]);
    }
    let out = cmd.arg(input).output().expect("run lessence");
    assert!(
        out.status.success(),
        "{args:?} {mode:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut all = String::from_utf8_lossy(&out.stdout).into_owned();
    all.push_str(&String::from_utf8_lossy(&out.stderr));
    if saves_report(mode) {
        let files = files_under(dir.path());
        assert!(!files.is_empty(), "{args:?} {mode:?}: no report saved");
        for file in files {
            all.push_str(&std::fs::read_to_string(file).expect("read report"));
        }
    }
    all
}

/// Run `input` through every mode under each argument set and assert no
/// listed value is in anything the run wrote.
fn assert_absent_everywhere(input: &Path, variants: &[(&[&str], &[&str])]) {
    for (args, values) in variants {
        for mode in MODES {
            let out = run(input, args, mode);
            for value in *values {
                assert!(
                    !out.contains(value),
                    "{args:?} {mode:?}: {value:?} is in the output:\n{out}"
                );
            }
            assert!(
                !GLUED_TAG.is_match(&out),
                "{args:?} {mode:?}: a tag is followed by an alphanumeric:\n{out}"
            );
        }
    }
}

#[test]
fn masking_replaces_whole_addresses() {
    let dir = scratch();
    let lines: Vec<String> = (1..=4)
        .map(|i| {
            format!(
                "route {i} from 192.0.2.1 to 192.0.2.15 via gw.example.com and gw.example.com.au \
                 notify ann@example.com and joann@example.com"
            )
        })
        .collect();
    let input = write_input(dir.path(), &lines);
    let ips: &[&str] = &["192.0.2.1"];
    let hosts: &[&str] = &["gw.example.com"];
    let emails: &[&str] = &["ann@example.com"];
    assert_absent_everywhere(
        &input,
        &[
            (&["--sanitize", "ip"], ips),
            (&["--sanitize", "ip:pseudonym"], ips),
            (&["--sanitize", "host"], hosts),
            (&["--sanitize", "host:pseudonym"], hosts),
            (&["--sanitize", "email"], emails),
            (&["--sanitize", "email:pseudonym"], emails),
            (&["--sanitize-pii"], emails),
        ],
    );

    // Two addresses are two pseudonyms, not one.
    let out = run(&input, &["--sanitize", "ip:pseudonym"], &["--no-report"]);
    let line = out
        .lines()
        .find(|l| l.starts_with("route 1 "))
        .expect("{out}");
    let tags: std::collections::HashSet<&str> = Regex::new(r"<IP:[0-9a-f]{16}>")
        .unwrap()
        .find_iter(line)
        .map(|m| m.as_str())
        .collect();
    assert_eq!(tags.len(), 2, "{line}");
}

#[test]
fn masking_is_independent_of_disabled_detectors() {
    let dir = scratch();
    let mut lines = Vec::new();
    for i in 1..=4 {
        lines.push(format!(
            "Nov 10 10:00:0{i} gwlab sshd[12{i}]: session for alice@example.com from 2001:db8::7 id{i}"
        ));
        lines.push(format!(
            "\"GET /reset?user=bob@example.com HTTP/1.1\" 200 {i}"
        ));
        lines.push(format!("fetch http://[2001:db8::9]:8080/health try {i}"));
    }
    let input = write_input(dir.path(), &lines);
    let emails: &[&str] = &["alice@example.com", "bob@example.com"];
    let ips: &[&str] = &["2001:db8::7", "2001:db8::9"];
    let hosts: &[&str] = &["gwlab"];
    assert_absent_everywhere(
        &input,
        &[
            (&["--sanitize-pii"], emails),
            (&["--sanitize-pii", "--disable-patterns", "email"], emails),
            (
                &["--sanitize", "email", "--disable-patterns", "email"],
                emails,
            ),
            (
                &[
                    "--sanitize",
                    "email:pseudonym",
                    "--disable-patterns",
                    "email",
                ],
                emails,
            ),
            (&["--sanitize", "ip"], ips),
            (&["--sanitize", "ip", "--disable-patterns", "network"], ips),
            (
                &[
                    "--sanitize",
                    "ip:pseudonym",
                    "--disable-patterns",
                    "network",
                ],
                ips,
            ),
            (
                &["--sanitize", "host", "--disable-patterns", "network"],
                hosts,
            ),
            (
                &[
                    "--sanitize",
                    "host:pseudonym",
                    "--disable-patterns",
                    "network",
                ],
                hosts,
            ),
        ],
    );
}

#[test]
fn credential_forms_mask_the_secret_part() {
    let dir = scratch();
    let mut lines = Vec::new();
    lines.push("dial postgres://app:Hunter2Secret@db.example.com:5432/x".to_string());
    lines.push("cache redis://:Hunter2Secret@cache.example.net:6379 connected".to_string());
    lines.push("broker for queue amqp://svc:Hunter2Secret@mq.example.org/vhost is up".to_string());
    for i in 1..=4 {
        lines.push(format!(
            "GET /api {i} Authorization: Bearer Zm9vYmFyYmF6cXV4MTIz"
        ));
        lines.push(format!(
            "check {i} Proxy-Authorization: Basic YWxpY2U6czNjcjN0UGFzcw=="
        ));
    }
    let input = write_input(dir.path(), &lines);
    let secrets: &[&str] = &[
        "Zm9vYmFyYmF6cXV4MTIz",
        "Hunter2Secret",
        "YWxpY2U6czNjcjN0UGFzcw",
    ];
    assert_absent_everywhere(
        &input,
        &[
            (&["--sanitize", "credential"], secrets),
            (&["--sanitize", "credential:pseudonym"], secrets),
            (&["--sanitize-pii"], secrets),
        ],
    );

    // The rest of each line stays.
    let out = run(&input, &["--sanitize", "credential"], &["--no-report"]);
    for kept in [
        "Authorization: Bearer <SECRET>",
        "postgres://app:<SECRET>@db.example.com:5432/x",
        "Proxy-Authorization: Basic <SECRET>",
    ] {
        assert!(out.contains(kept), "{kept:?} missing:\n{out}");
    }
}

#[test]
fn ranked_output_masks_every_template() {
    let dir = scratch();
    let mut lines: Vec<String> = (1..=6)
        .map(|i| format!("job {i} finished cleanly in worker pool"))
        .collect();
    lines.extend((1..=3).map(|i| format!("login user=bob password=Wren{i}Fable9")));
    let input = write_input(dir.path(), &lines);
    let secrets: &[&str] = &["Fable9"];
    assert_absent_everywhere(
        &input,
        &[
            (&["--sanitize", "credential"], secrets),
            (&["--sanitize", "credential:pseudonym"], secrets),
            (&["--sanitize-pii"], secrets),
        ],
    );
    for top in ["0", "1", "2"] {
        for format in ["text", "json"] {
            let out = run(
                &input,
                &["--sanitize-pii", "--format", format],
                &["--top", top],
            );
            assert!(!out.contains("Fable9"), "--top {top} {format}:\n{out}");
        }
    }
}

/// `--explain` names the first word two lines differ in. That word is
/// shown as the masked line shows it, and its offset points into the
/// masked `normalized` text.
#[test]
fn explain_shows_the_first_difference_masked() {
    let dir = scratch();
    let mut lines: Vec<String> = (1..=3)
        .map(|i| format!("login user=bob password=Wren{i}Fable9 ok"))
        .collect();
    lines.push("login user=bob token=Quill7Marsh ok then stop".to_string());
    lines.push("login user=bob api_key: \"Heron5 Stoat8\" from 198.51.100.21".to_string());
    lines.push("login user=bob api_key: \"Heron6 Stoat8\" from 198.51.100.22".to_string());
    let input = write_input(dir.path(), &lines);
    let secrets: &[&str] = &["Fable9", "Quill7Marsh", "Stoat8", "Heron", "198.51.100"];
    for args in [
        &["--sanitize", "credential,ip"][..],
        &["--sanitize", "credential:pseudonym,ip:pseudonym"],
        &["--sanitize-pii", "--sanitize", "ip"],
        &[
            "--sanitize",
            "credential,ip",
            "--disable-patterns",
            "quoted-string",
        ],
    ] {
        let run = bin()
            .args(args)
            .arg("--explain")
            .arg(&input)
            .output()
            .expect("run lessence");
        assert!(run.status.success(), "{args:?}");
        let out = String::from_utf8_lossy(&run.stdout);
        let err = String::from_utf8_lossy(&run.stderr);
        for value in secrets {
            assert!(
                !out.contains(value) && !err.contains(value),
                "{args:?}: {value:?} is in:\n{out}{err}"
            );
        }
        let mut diffs = 0;
        for record in out.lines() {
            let record: serde_json::Value = serde_json::from_str(record).expect("JSONL");
            let Some(diff) = record["nearest"]["first_diff"].as_object() else {
                continue;
            };
            diffs += 1;
            if record["count"] != 1 {
                continue;
            }
            let normalized = record["normalized"].as_str().expect("normalized");
            let at = diff["at"].as_u64().expect("at") as usize;
            let ours = diff["ours"].as_str().expect("ours");
            assert!(
                normalized
                    .get(at..)
                    .is_some_and(|rest| rest.starts_with(ours)),
                "{args:?}: {ours:?} is not at {at} of {normalized:?}"
            );
        }
        assert!(diffs >= 3, "{args:?}: no first_diff records:\n{out}");
    }
}

/// A rollup sample that holds a longer value beside a shorter one of the
/// same group (a path through `192.0.2.123` in a group that also names
/// `192.0.2.1`) has the longer value replaced whole.
#[test]
fn a_rollup_sample_masks_each_value_whole() {
    let dir = scratch();
    let lines: Vec<String> = (1..=4)
        .map(|i| format!("copy {i} from 192.0.2.1 to /data/192.0.2.123/out"))
        .collect();
    let input = write_input(dir.path(), &lines);
    let values: &[&str] = &["192.0.2.1", "23/out"];
    assert_absent_everywhere(
        &input,
        &[
            (&["--sanitize", "ip"], values),
            (&["--sanitize", "ip:pseudonym"], values),
        ],
    );
    let out = run(&input, &["--sanitize", "ip"], &["--no-report"]);
    assert!(out.contains("{/data/<IP>/out}"), "{out}");
}

#[test]
fn an_address_with_any_port_is_replaced() {
    let dir = scratch();
    let mut lines = Vec::new();
    for i in 1..=4 {
        lines.push(format!("peer 198.51.100.3:99999 dropped {i}"));
        lines.push(format!("peer [2001:db8::5]:70000 dropped {i}"));
    }
    let input = write_input(dir.path(), &lines);
    let ips: &[&str] = &["198.51.100.3", "2001:db8::5"];
    assert_absent_everywhere(
        &input,
        &[
            (&["--sanitize", "ip"], ips),
            (&["--sanitize", "ip:pseudonym"], ips),
        ],
    );

    let out = bin()
        .args(["--anonymize", "--seed", "1"])
        .arg(&input)
        .output()
        .expect("run lessence");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut all = String::from_utf8_lossy(&out.stdout).into_owned();
    all.push_str(&String::from_utf8_lossy(&out.stderr));
    for ip in ips {
        assert!(!all.contains(ip), "{ip:?} survived --anonymize:\n{all}");
    }
    assert_eq!(all.matches(":99999 dropped").count(), 4, "{all}");
}
