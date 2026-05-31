use std::process::Command;
use std::str;

#[test]
fn test_markdown_output_format() {
    // Test that --format markdown produces valid markdown
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--format", "markdown", "--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let markdown_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");

    // Validate markdown structure
    assert!(
        markdown_output.contains("# Log Analysis"),
        "Should contain main header"
    );
    assert!(
        markdown_output.contains("## Summary"),
        "Should contain summary section"
    );
    assert!(
        markdown_output.contains("## Compressed Logs"),
        "Should contain compressed logs section"
    );

    // Should contain markdown formatting
    assert!(
        markdown_output.contains("**"),
        "Should contain bold formatting"
    );
    assert!(
        markdown_output.contains("- "),
        "Should contain list formatting"
    );

    // Should be readable and well-structured
    let lines: Vec<&str> = markdown_output.lines().collect();
    assert!(lines.len() > 5, "Should have substantial content");

    println!("✅ Markdown output format validation passed");
}

#[test]
fn test_markdown_readability_features() {
    // Test readability features specific to markdown
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--format", "markdown", "--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let markdown_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");

    // Check for folded pattern indicators
    assert!(
        markdown_output.contains("similar") || markdown_output.contains("collapsed"),
        "Should indicate folded/similar lines"
    );

    // Check for code blocks for log content
    assert!(
        markdown_output.contains("```"),
        "Should use code blocks for log content"
    );

    // Should have clear section separation
    let header_count = markdown_output.matches("##").count();
    assert!(
        header_count >= 2,
        "Should have multiple sections with headers"
    );

    println!("✅ Markdown readability features validation passed");
}

#[test]
fn test_markdown_escapes_untrusted_fence_breakout() {
    // A crafted log line that tries to close the code fence and inject
    // markdown/HTML structure must be neutralized: the content is wrapped in a
    // backtick run longer than any run it contains, so the injected `# PWNED`
    // heading, link, and <img> never reach the top level of the rendered doc.
    let malicious = "log start ``` # PWNED [click](http://evil) <img src=x onerror=alert(1)>";

    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--format", "markdown", "--no-stats"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn lessence");
    child
        .stdin
        .take()
        .expect("no stdin")
        .write_all(malicious.as_bytes())
        .expect("failed to write stdin");
    let output = child.wait_with_output().expect("failed to wait");
    assert!(output.status.success(), "lessence execution failed");

    let md = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");

    // The 3-backtick run in the content must NOT appear as a fence delimiter on
    // its own line — the emitter must escalate to a 4-backtick fence around it.
    assert!(
        md.lines().any(|l| l.trim_end() == "````"),
        "content with embedded ``` must be wrapped in an escalated 4-backtick fence:\n{md}"
    );
    assert!(
        !md.lines().any(|l| l.trim_end() == "```"),
        "a bare ``` fence is breakable by the embedded backtick run:\n{md}"
    );

    // The injected heading must never appear at the start of a line (which is
    // how markdown renders an ATX heading) outside of the fenced block — the
    // whole untrusted line is emitted verbatim inside the fence.
    assert!(
        !md.lines().any(|l| l.starts_with("# PWNED")),
        "injected heading escaped the fence and became a real heading:\n{md}"
    );

    println!("✅ Markdown fence-breakout escaping validation passed");
}
