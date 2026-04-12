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
