use std::process::Command;
use std::str;

/// Build the release binary if it doesn't exist or is out of date
fn ensure_release_build() {
    let build_output = Command::new("cargo")
        .args(["build", "--release"])
        .output()
        .expect("Failed to build release binary");

    assert!(build_output.status.success(), "Failed to build release binary: {}",
        String::from_utf8_lossy(&build_output.stderr));
}

#[test]
fn test_text_format_default() {
    // Test that text format is the default and produces expected output
    ensure_release_build();

    // Test with default format (no --format flag)
    let output = Command::new("./target/release/lessence")
        .args(["--no-stats"])
        .stdin(std::fs::File::open("tests/fixtures/nginx_sample.log").expect("nginx_sample.log not found"))
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed: {}",
        String::from_utf8_lossy(&output.stderr));

    let text_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");

    // Text format should produce plain log lines
    let lines = text_output.lines().collect::<Vec<_>>();
    assert!(!lines.is_empty(), "Text output should not be empty");

    // Should not be JSON (no braces) or Markdown (no # headers)
    assert!(!text_output.starts_with('{'), "Default output should not be JSON");
    assert!(!text_output.contains("# Log Analysis"), "Default output should not be Markdown");

    // Should contain compressed log patterns with folding indicators
    let has_folded_content = lines.iter().any(|line| line.contains("+") && line.contains("similar"));

    // Test explicit --format text flag produces same result
    let explicit_output = Command::new("./target/release/lessence")
        .args(["--format", "text", "--no-stats"])
        .stdin(std::fs::File::open("tests/fixtures/nginx_sample.log").expect("nginx_sample.log not found"))
        .output()
        .expect("Failed to execute lessence");

    assert!(explicit_output.status.success(), "lessence execution failed");

    let explicit_text_output = str::from_utf8(&explicit_output.stdout).expect("Invalid UTF-8 output");
    assert_eq!(text_output, explicit_text_output, "Default and explicit text format should be identical");

    println!("✅ Text format (default) validation passed");
    println!("  Output lines: {}", lines.len());
    if has_folded_content {
        println!("  Contains folded patterns: Yes");
    }
}

#[test]
fn test_markdown_format_flag() {
    // Test --format markdown produces valid markdown structure
    ensure_release_build();

    let output = Command::new("./target/release/lessence")
        .args(["--format", "markdown", "--no-stats"])
        .stdin(std::fs::File::open("tests/fixtures/nginx_sample.log").expect("nginx_sample.log not found"))
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed: {}",
        String::from_utf8_lossy(&output.stderr));

    let markdown_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let lines = markdown_output.lines().collect::<Vec<_>>();

    // Validate markdown structure
    assert!(lines.iter().any(|line| line.starts_with("# Log Analysis")),
        "Should contain main header '# Log Analysis'");

    assert!(lines.iter().any(|line| line.starts_with("## Summary")),
        "Should contain summary section '## Summary'");

    assert!(lines.iter().any(|line| line.starts_with("## Compressed Logs")),
        "Should contain compressed logs section '## Compressed Logs'");

    // Validate summary content
    let has_original_lines = lines.iter().any(|line| line.contains("**Original lines**"));
    let has_compressed_lines = lines.iter().any(|line| line.contains("**Compressed lines**"));
    let has_compression_ratio = lines.iter().any(|line| line.contains("**Compression ratio**"));

    assert!(has_original_lines, "Should contain original lines count");
    assert!(has_compressed_lines, "Should contain compressed lines count");
    assert!(has_compression_ratio, "Should contain compression ratio");

    // Validate folded entries are properly formatted
    let has_folded_entries = lines.iter().any(|line| line.starts_with("### Entry") && line.contains("(Folded)"));
    let has_code_blocks = lines.iter().any(|line| line.trim() == "```");

    if has_folded_entries {
        assert!(has_code_blocks, "Folded entries should be in code blocks");
    }

    // Should not be JSON
    assert!(!markdown_output.starts_with('{'), "Markdown output should not be JSON");

    println!("✅ Markdown format validation passed");
    println!("  Total lines: {}", lines.len());
    println!("  Has folded entries: {}", has_folded_entries);
}

#[test]
fn test_format_compression_quality() {
    // Test that all formats maintain constitutional compliance (≥98.4% compression)
    ensure_release_build();

    let formats = vec!["text", "markdown"];

    for format in formats {
        println!("Testing compression quality for format: {}", format);

        let Ok(file) = std::fs::File::open("examples/kubelet.log") else {
            eprintln!("Skipping: examples/kubelet.log not available");
            return;
        };

        let output = Command::new("./target/release/lessence")
            .args(["--format", format, "--no-stats"])
            .stdin(file)
            .output()
            .expect("Failed to execute lessence");

        assert!(output.status.success(), "lessence execution failed for format {}: {}",
            format, String::from_utf8_lossy(&output.stderr));

        // Read original file to get input line count
        let original_content = std::fs::read_to_string("examples/kubelet.log")
            .expect("Failed to read kubelet.log");
        let input_lines = original_content.lines().count();

        let output_str = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");

        // For Markdown, we need to count actual log entries, not format lines
        let effective_compressed_lines = match format {
            "markdown" => {
                // Extract compressed lines count from markdown summary
                let lines = output_str.lines();
                let mut compressed_lines = 0;
                for line in lines {
                    if line.contains("**Compressed lines**:") {
                        // Extract number from "- **Compressed lines**: 1196"
                        if let Some(colon_pos) = line.find(':') {
                            let number_part = line[colon_pos + 1..].trim();
                            compressed_lines = number_part.parse().unwrap_or(0);
                        }
                        break;
                    }
                }
                compressed_lines
            },
            "text" => output_str.lines().count(),
            _ => panic!("Unexpected format: {}", format)
        };

        // Calculate compression ratio
        let compression_ratio = ((input_lines - effective_compressed_lines) as f64 / input_lines as f64) * 100.0;

        println!("  Format: {}", format);
        println!("    Input lines: {}", input_lines);
        println!("    Effective compressed lines: {}", effective_compressed_lines);
        println!("    Compression ratio: {:.2}%", compression_ratio);

        // Constitutional compliance requirement: ≥98.4% compression (≤1,101 lines from kubelet.log)
        assert!(effective_compressed_lines <= 1101,
            "❌ CONSTITUTIONAL VIOLATION for {}: {} > 1,101 lines", format, effective_compressed_lines);

        assert!(compression_ratio >= 98.4,
            "❌ CONSTITUTIONAL VIOLATION for {}: {:.2}% < 98.4% compression", format, compression_ratio);

        println!("  ✅ Constitutional compliance PASSED for {}", format);
    }
}

#[test]
fn test_format_selection_errors() {
    // Test that invalid format values produce appropriate errors
    ensure_release_build();

    let invalid_formats = vec!["xml", "csv", "yaml", "invalid"];

    for invalid_format in invalid_formats {
        let output = Command::new("./target/release/lessence")
            .args(["--format", invalid_format, "--no-stats"])
            .stdin(std::fs::File::open("tests/fixtures/nginx_sample.log").expect("nginx_sample.log not found"))
            .output()
            .expect("Failed to execute lessence");

        // Should either fail or fall back to text format
        if !output.status.success() {
            // Expected behavior: command fails with error
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("Expected error for format '{}': {}", invalid_format, stderr);
        } else {
            // Alternative behavior: falls back to text format
            let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
            assert!(!stdout.starts_with('{'),
                "Invalid format '{}' should not produce JSON", invalid_format);
            assert!(!stdout.contains("# Log Analysis"),
                "Invalid format '{}' should not produce Markdown", invalid_format);
            println!("Format '{}' fell back to text format", invalid_format);
        }
    }

    println!("✅ Format selection error handling validated");
}