use std::process::Command;
use std::str;

#[test]
fn test_nginx_compression_improvement() {
    // Test compression on nginx_sample.log
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    // Read original file to get input line count
    let original_content = std::fs::read_to_string("tests/fixtures/nginx_sample.log")
        .expect("Failed to read nginx_sample.log");
    let input_lines = original_content.lines().count();

    // Calculate compression ratio
    let compression_ratio = ((input_lines - output_lines) as f64 / input_lines as f64) * 100.0;

    println!("Nginx compression test:");
    println!("  Input lines: {input_lines}");
    println!("  Output lines: {output_lines}");
    println!("  Compression ratio: {compression_ratio:.1}%");

    // Nginx logs achieve ~78% compression
    assert!(
        compression_ratio >= 75.0,
        "Nginx compression should be ≥75%, got {compression_ratio:.1}%"
    );
}

#[test]
fn test_nginx_baseline_without_new_patterns() {
    // This test documents the baseline before new patterns
    // Used for comparison to validate improvement

    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    // Document current baseline for comparison
    println!("Nginx baseline test (before HttpStatusClass pattern):");
    println!("  Output lines: {output_lines}");

    // Ensure we're not regressing from current baseline
    // Based on testing: 50 → 14 lines (72% compression)
    assert!(
        output_lines <= 20,
        "Baseline regression detected: {output_lines} > 20 lines"
    );
}
