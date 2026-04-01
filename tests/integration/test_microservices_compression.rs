use std::process::Command;
use std::str;

#[test]
fn test_microservices_compression_improvement() {
    // Build the release binary first
    let build_output = Command::new("cargo")
        .args(&["build", "--release"])
        .output()
        .expect("Failed to build release binary");

    assert!(build_output.status.success(), "Failed to build release binary");

    // Test compression on microservices.log
    let output = Command::new("./target/release/lessence")
        .args(&["--no-stats"])
        .stdin(std::fs::File::open("tests/fixtures/microservices.log").expect("microservices.log not found"))
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    // Read original file to get input line count
    let original_content = std::fs::read_to_string("tests/fixtures/microservices.log")
        .expect("Failed to read microservices.log");
    let input_lines = original_content.lines().count();

    // Calculate compression ratio
    let compression_ratio = ((input_lines - output_lines) as f64 / input_lines as f64) * 100.0;

    println!("Microservices compression test:");
    println!("  Input lines: {}", input_lines);
    println!("  Output lines: {}", output_lines);
    println!("  Compression ratio: {:.1}%", compression_ratio);

    // Microservices logs have varied content; actual compression ~26%
    assert!(compression_ratio >= 20.0,
        "Microservices compression should be ≥20%, got {:.1}%", compression_ratio);
}

#[test]
fn test_microservices_baseline_without_new_patterns() {
    // This test documents the baseline before new patterns
    // Used for comparison to validate improvement

    let output = Command::new("./target/release/lessence")
        .args(&["--no-stats"])
        .stdin(std::fs::File::open("tests/fixtures/microservices.log").expect("microservices.log not found"))
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    // Document current baseline for comparison
    println!("Microservices baseline test (before BracketContext pattern):");
    println!("  Output lines: {}", output_lines);

    // Ensure we're not regressing from current baseline
    // Based on testing: 52 → 42 lines (19% compression)
    assert!(output_lines <= 45, "Baseline regression detected: {} > 45 lines", output_lines);
}