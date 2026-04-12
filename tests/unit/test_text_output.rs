use std::process::Command;
use std::str;

#[test]
fn test_plain_text_output_format() {
    // Test that --format text produces plain text (current default behavior)
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--format", "text", "--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let text_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");

    // Should be plain text — not markdown or JSON. The old checks used
    // a blanket `!contains('<')`, `!contains('#')`, and `!contains('{')`,
    // which are too strict: log data legitimately contains `<` (e.g.
    // syslog brackets, normalized token placeholders like `<PATH>` in
    // compact-marker samples), `#` (e.g. many log formats include `#`),
    // and `{` (the compact marker's inline-sample set syntax is
    // `TYPE×N {s1, s2}`). Narrow checks to actual JSON / HTML output.
    assert!(
        !text_output.contains("<html") && !text_output.contains("</"),
        "Should not contain HTML tags"
    );
    assert!(
        !text_output.contains("## "),
        "Should not contain markdown headers"
    );
    assert!(
        !text_output.trim_start().starts_with("{\""),
        "Should not start with JSON output"
    );

    // Should contain folded line indicators
    assert!(
        text_output.contains("similar") || text_output.contains('+'),
        "Should indicate folded lines"
    );

    // Should be minimal overhead - just the compressed content
    let lines: Vec<&str> = text_output.lines().collect();
    assert!(!lines.is_empty(), "Should have content");

    println!("✅ Plain text output format validation passed");
}

#[test]
fn test_text_minimal_overhead() {
    // Test that text format has minimal overhead
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--format", "text", "--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let text_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");

    // Text output should be the most compact
    let line_count = text_output.lines().count();

    // Compare with default output (should be same or very similar)
    let default_output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    let default_text = str::from_utf8(&default_output.stdout).expect("Invalid UTF-8 output");
    let default_line_count = default_text.lines().count();

    // Text format should be similar to default (minimal overhead)
    let line_diff = (line_count as i32 - default_line_count as i32).abs();
    assert!(
        line_diff <= 2,
        "Text format should have minimal overhead vs default"
    );

    println!("✅ Text minimal overhead validation passed");
}
