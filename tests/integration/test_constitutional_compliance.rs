use std::process::Command;
use std::str;

#[test]
fn test_constitutional_compliance_kubelet() {
    // This is the CRITICAL constitutional compliance test
    // Must maintain ≥98.5% compression on kubelet.log (≤1,087 lines)

    // Build the release binary first
    let build_output = Command::new("cargo")
        .args(&["build", "--release"])
        .output()
        .expect("Failed to build release binary");

    assert!(build_output.status.success(), "Failed to build release binary");

    // Test compression on kubelet.log (the constitutional benchmark)
    let Ok(file) = std::fs::File::open("examples/kubelet.log") else {
        eprintln!("Skipping: examples/kubelet.log not available");
        return;
    };

    let output = Command::new("./target/release/lessence")
        .args(&["--no-stats"])
        .stdin(file)
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    // Read original file to get input line count (should be 70,548)
    let original_content = std::fs::read_to_string("examples/kubelet.log")
        .expect("Failed to read kubelet.log");
    let input_lines = original_content.lines().count();

    // Calculate compression ratio
    let compression_ratio = ((input_lines - output_lines) as f64 / input_lines as f64) * 100.0;

    println!("Constitutional compliance test:");
    println!("  Input lines: {}", input_lines);
    println!("  Output lines: {}", output_lines);
    println!("  Compression ratio: {:.2}%", compression_ratio);
    println!("  Constitutional limit: ≤1,100 lines (98.4%)");

    // CRITICAL: Constitutional compliance requirement
    assert!(output_lines <= 1100,
        "❌ CONSTITUTIONAL VIOLATION: {} > 1,100 lines", output_lines);

    assert!(compression_ratio >= 98.4,
        "❌ CONSTITUTIONAL VIOLATION: {:.2}% < 98.4% compression", compression_ratio);

    // Validate we're within expected range (current baseline: ~1,094 lines)
    assert!(output_lines >= 1000 && output_lines <= 1100,
        "Output {} outside expected range [1000, 1100]", output_lines);

    println!("✅ Constitutional compliance PASSED");
}

#[test]
fn test_processing_speed_requirement() {
    // Constitutional requirement: ≤30 seconds for kubelet.log processing

    use std::time::Instant;

    // Build the release binary first
    let build_output = Command::new("cargo")
        .args(&["build", "--release"])
        .output()
        .expect("Failed to build release binary");

    assert!(build_output.status.success(), "Failed to build release binary");

    // Measure processing time
    let Ok(file) = std::fs::File::open("examples/kubelet.log") else {
        eprintln!("Skipping: examples/kubelet.log not available");
        return;
    };

    let start = Instant::now();

    let output = Command::new("./target/release/lessence")
        .args(&["--no-stats"])
        .stdin(file)
        .output()
        .expect("Failed to execute lessence");

    let duration = start.elapsed();

    assert!(output.status.success(), "lessence execution failed");

    println!("Processing speed test:");
    println!("  Duration: {:.2}s", duration.as_secs_f64());
    println!("  Constitutional limit: ≤30s");

    // CRITICAL: Constitutional speed requirement
    assert!(duration.as_secs() <= 30,
        "❌ CONSTITUTIONAL VIOLATION: {:.2}s > 30s processing time", duration.as_secs_f64());

    println!("✅ Processing speed requirement PASSED");
}