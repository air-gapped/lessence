//! Whole-output masking regression (lessence-iyw).
//!
//! With --sanitize-pii enabled, no fixture secret may appear anywhere in
//! the process output — stdout or stderr, any field, any mode. Every
//! value below is a synthetic fixture. One test per output mode so a
//! regression names the mode that leaked.

use std::io::Write;
use std::process::{Command, Stdio};

const FIXTURE: &[u8] = b"auth user alice@example.com password=FIXVALUEA1 req 1\n\
auth user alice@example.com password=FIXVALUEA2 req 2\n\
auth user alice@example.com password=FIXVALUEA3 req 3\n\
auth user alice@example.com password=FIXVALUEA4 req 4\n\
session Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmN start\n\
push key ghp_FixtureAbCd1234EfGh done\n";

/// Substrings that must not survive in any output. FIXVALUEA covers all
/// four per-line values; the JWT is matched by its header segment.
const SECRETS: &[&str] = &[
    "alice@example.com",
    "FIXVALUEA",
    "eyJhbGciOiJIUzI1NiJ9",
    "ghp_FixtureAbCd1234EfGh",
];

/// Run the binary with --sanitize-pii plus `args`, feed the fixture on
/// stdin, and return stdout and stderr concatenated.
fn run_masked(args: &[&str]) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--sanitize-pii")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn lessence");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(FIXTURE)
        .unwrap();
    let output = child.wait_with_output().expect("Failed to read output");
    assert!(
        output.status.success(),
        "lessence {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut all = String::from_utf8(output.stdout).expect("Invalid UTF-8 stdout");
    all.push_str(&String::from_utf8_lossy(&output.stderr));
    all
}

fn assert_no_secret(mode: &str, output: &str) {
    for secret in SECRETS {
        assert!(
            !output.contains(secret),
            "{mode}: fixture secret {secret:?} survived in output:\n{output}"
        );
    }
    assert!(!output.is_empty(), "{mode}: produced no output at all");
}

#[test]
fn masking_regression_text() {
    let out = run_masked(&[]);
    assert_no_secret("text", &out);
    assert!(out.contains("<SECRET>"), "text: mask token missing:\n{out}");
    assert!(out.contains("<EMAIL>"), "text: email mask missing:\n{out}");
}

#[test]
fn masking_regression_markdown() {
    let out = run_masked(&["--format", "markdown"]);
    assert_no_secret("markdown", &out);
    assert!(out.contains("<SECRET>"), "markdown: mask missing:\n{out}");
}

#[test]
fn masking_regression_json() {
    let out = run_masked(&["--format", "json"]);
    assert_no_secret("json", &out);
    assert!(out.contains("<SECRET>"), "json: mask missing:\n{out}");
}

#[test]
fn masking_regression_summary() {
    let out = run_masked(&["--summary"]);
    assert_no_secret("summary", &out);
}

#[test]
fn masking_regression_top() {
    let out = run_masked(&["--top", "5"]);
    assert_no_secret("top", &out);
}

#[test]
fn masking_regression_preflight() {
    let out = run_masked(&["--preflight"]);
    assert_no_secret("preflight", &out);
}

#[test]
fn masking_regression_essence() {
    // Essence mode tokenises emails during normalization; credential
    // values are not tokens and must be masked by the credential rules.
    let out = run_masked(&["--essence"]);
    assert_no_secret("essence", &out);
    assert!(out.contains("<SECRET>"), "essence: mask missing:\n{out}");
}
