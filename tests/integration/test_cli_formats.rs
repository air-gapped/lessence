use std::process::Command;
use std::str;

#[test]
fn test_text_format_default() {
    // Test that text format is the default and produces expected output

    // Test with default format (no --format flag)
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(
        output.status.success(),
        "lessence execution failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");

    // Text format should produce plain log lines
    let lines = text_output.lines().collect::<Vec<_>>();
    assert!(!lines.is_empty(), "Text output should not be empty");

    // Should not be JSON (no braces) or Markdown (no # headers)
    assert!(
        !text_output.starts_with('{'),
        "Default output should not be JSON"
    );
    assert!(
        !text_output.contains("# Log Analysis"),
        "Default output should not be Markdown"
    );

    // Should contain compressed log patterns with folding indicators
    let has_folded_content = lines
        .iter()
        .any(|line| line.contains('+') && line.contains("similar"));

    // Test explicit --format text flag produces same result
    let explicit_output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--format", "text", "--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(
        explicit_output.status.success(),
        "lessence execution failed"
    );

    let explicit_text_output =
        str::from_utf8(&explicit_output.stdout).expect("Invalid UTF-8 output");
    assert_eq!(
        text_output, explicit_text_output,
        "Default and explicit text format should be identical"
    );

    println!("✅ Text format (default) validation passed");
    println!("  Output lines: {}", lines.len());
    if has_folded_content {
        println!("  Contains folded patterns: Yes");
    }
}

#[test]
fn test_markdown_format_flag() {
    // Test --format markdown produces valid markdown structure

    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--format", "markdown", "--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(
        output.status.success(),
        "lessence execution failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let markdown_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let lines = markdown_output.lines().collect::<Vec<_>>();

    // Validate markdown structure
    assert!(
        lines.iter().any(|line| line.starts_with("# Log Analysis")),
        "Should contain main header '# Log Analysis'"
    );

    assert!(
        lines.iter().any(|line| line.starts_with("## Summary")),
        "Should contain summary section '## Summary'"
    );

    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("## Compressed Logs")),
        "Should contain compressed logs section '## Compressed Logs'"
    );

    // Validate summary content
    let has_original_lines = lines.iter().any(|line| line.contains("**Original lines**"));
    let has_compressed_lines = lines
        .iter()
        .any(|line| line.contains("**Compressed lines**"));
    let has_compression_ratio = lines
        .iter()
        .any(|line| line.contains("**Compression ratio**"));

    assert!(has_original_lines, "Should contain original lines count");
    assert!(
        has_compressed_lines,
        "Should contain compressed lines count"
    );
    assert!(has_compression_ratio, "Should contain compression ratio");

    // Validate folded entries are properly formatted
    let has_folded_entries = lines
        .iter()
        .any(|line| line.starts_with("### Entry") && line.contains("(Folded)"));
    let has_code_blocks = lines.iter().any(|line| line.trim() == "```");

    if has_folded_entries {
        assert!(has_code_blocks, "Folded entries should be in code blocks");
    }

    // Should not be JSON
    assert!(
        !markdown_output.starts_with('{'),
        "Markdown output should not be JSON"
    );

    println!("✅ Markdown format validation passed");
    println!("  Total lines: {}", lines.len());
    println!("  Has folded entries: {has_folded_entries}");
}

#[test]
fn test_format_selection_errors() {
    // Test that invalid format values produce appropriate errors

    let invalid_formats = vec!["xml", "csv", "yaml", "invalid"];

    for invalid_format in invalid_formats {
        let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
            .args(["--format", invalid_format, "--no-stats"])
            .stdin(
                std::fs::File::open("tests/fixtures/nginx_sample.log")
                    .expect("nginx_sample.log not found"),
            )
            .output()
            .expect("Failed to execute lessence");

        // Should either fail or fall back to text format
        if !output.status.success() {
            // Expected behavior: command fails with error
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("Expected error for format '{invalid_format}': {stderr}");
        } else {
            // Alternative behavior: falls back to text format
            let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
            assert!(
                !stdout.starts_with('{'),
                "Invalid format '{invalid_format}' should not produce JSON"
            );
            assert!(
                !stdout.contains("# Log Analysis"),
                "Invalid format '{invalid_format}' should not produce Markdown"
            );
            println!("Format '{invalid_format}' fell back to text format");
        }
    }

    println!("✅ Format selection error handling validated");
}

// ---- Alias and case canonicalization (lessence-fiz) ----
//
// Every accepted spelling of --format must reach the dispatch code in its
// canonical form. Before the fix, validation lowercased but dispatch
// compared the raw string, so `--format md` and any uppercase spelling
// silently emitted text.

fn run_with_format(format: &str) -> String {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--format", format, "--no-stats"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn lessence");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"alpha event one\nbeta event two\n")
        .unwrap();
    let output = child.wait_with_output().expect("Failed to read output");
    assert!(
        output.status.success(),
        "--format {format} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("Invalid UTF-8 output")
}

fn assert_markdown(format: &str) {
    let stdout = run_with_format(format);
    assert!(
        stdout.contains("# Log Analysis"),
        "--format {format} must emit the markdown document, got: {stdout}"
    );
}

fn assert_json(format: &str) {
    let stdout = run_with_format(format);
    assert!(
        stdout.lines().all(|l| l.starts_with('{')),
        "--format {format} must emit JSONL records, got: {stdout}"
    );
}

fn assert_text(format: &str) {
    let stdout = run_with_format(format);
    assert!(
        !stdout.starts_with('{') && !stdout.contains("# Log Analysis"),
        "--format {format} must emit plain text, got: {stdout}"
    );
}

#[test]
fn format_spelling_text() {
    assert_text("text");
}

#[test]
fn format_spelling_plain_alias() {
    assert_text("plain");
}

#[test]
fn format_spelling_markdown() {
    assert_markdown("markdown");
}

#[test]
fn format_spelling_md_alias() {
    assert_markdown("md");
}

#[test]
fn format_spelling_markdown_uppercase() {
    assert_markdown("MARKDOWN");
}

#[test]
fn format_spelling_json() {
    assert_json("json");
}

#[test]
fn format_spelling_json_uppercase() {
    assert_json("JSON");
}

#[test]
fn format_spelling_jsonl() {
    assert_json("jsonl");
}
