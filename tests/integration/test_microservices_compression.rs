use std::str;

#[test]
fn test_microservices_compression_improvement() {
    let output = crate::common::lessence()
        .args(["--no-stats", "--no-report"])
        .stdin(
            std::fs::File::open("tests/fixtures/microservices.log")
                .expect("microservices.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    let original_content = std::fs::read_to_string("tests/fixtures/microservices.log")
        .expect("Failed to read microservices.log");
    let input_lines = original_content.lines().count();

    let compression_ratio = ((input_lines - output_lines) as f64 / input_lines as f64) * 100.0;

    println!("Microservices compression test:");
    println!("  Input lines: {input_lines}");
    println!("  Output lines: {output_lines}");
    println!("  Compression ratio: {compression_ratio:.1}%");

    assert!(
        compression_ratio >= 20.0,
        "Microservices compression should be ≥20%, got {compression_ratio:.1}%"
    );
}

#[test]
fn test_microservices_baseline_without_new_patterns() {
    let output = crate::common::lessence()
        .args(["--no-stats", "--no-report"])
        .stdin(
            std::fs::File::open("tests/fixtures/microservices.log")
                .expect("microservices.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    println!("Microservices baseline test (before BracketContext pattern):");
    println!("  Output lines: {output_lines}");

    assert!(
        output_lines <= 45,
        "Baseline regression detected: {output_lines} > 45 lines"
    );
}
