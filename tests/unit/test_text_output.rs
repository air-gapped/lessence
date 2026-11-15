use std::str;

#[test]
fn test_plain_text_output_format() {
    let output = crate::common::lessence()
        .args(["--format", "text", "--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let text_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");

    assert!(
        !text_output.contains("<html") && !text_output.contains("</"),
        "Should not contain HTML tags (a bare '<' is legal: syslog brackets, <PATH>-style \
         placeholders in compact-marker samples)"
    );
    assert!(
        !text_output.contains("## "),
        "Should not contain markdown headers (a bare '#' is legal in many log formats)"
    );
    assert!(
        !text_output.trim_start().starts_with("{\""),
        "Should not start with JSON output (a bare '{{' is legal: the compact marker's \
         TYPE×N {{s1, s2}} sample set)"
    );

    assert!(
        text_output.contains("similar") || text_output.contains('+'),
        "Should indicate folded lines"
    );

    let lines: Vec<&str> = text_output.lines().collect();
    assert!(!lines.is_empty(), "Should have content");

    println!("✅ Plain text output format validation passed");
}

#[test]
fn test_text_minimal_overhead() {
    let output = crate::common::lessence()
        .args(["--format", "text", "--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let text_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");

    let line_count = text_output.lines().count();

    let default_output = crate::common::lessence()
        .args(["--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    let default_text = str::from_utf8(&default_output.stdout).expect("Invalid UTF-8 output");
    let default_line_count = default_text.lines().count();

    let line_diff = (line_count as i32 - default_line_count as i32).abs();
    assert!(
        line_diff <= 2,
        "Text format should have minimal overhead vs default"
    );

    println!("✅ Text minimal overhead validation passed");
}
