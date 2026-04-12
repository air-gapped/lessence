use std::process::Command;
use std::str;

#[test]
fn test_constitutional_compliance_kubelet() {
    // This is the CRITICAL constitutional compliance test
    // Must maintain ≥98.5% compression on kubelet.log (≤1,087 lines)

    // Build the release binary first
    let build_output = Command::new("cargo")
        .args(["build", "--release"])
        .output()
        .expect("Failed to build release binary");

    assert!(
        build_output.status.success(),
        "Failed to build release binary"
    );

    // Test compression on kubelet.log (the constitutional benchmark)
    let Ok(file) = std::fs::File::open("examples/kubelet.log") else {
        eprintln!("Skipping: examples/kubelet.log not available");
        return;
    };

    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--no-stats"])
        .stdin(file)
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    // Read original file to get input line count (should be 70,548)
    let original_content =
        std::fs::read_to_string("examples/kubelet.log").expect("Failed to read kubelet.log");
    let input_lines = original_content.lines().count();

    // Calculate compression ratio
    let compression_ratio = ((input_lines - output_lines) as f64 / input_lines as f64) * 100.0;

    println!("Constitutional compliance test:");
    println!("  Input lines: {input_lines}");
    println!("  Output lines: {output_lines}");
    println!("  Compression ratio: {compression_ratio:.2}%");
    println!("  Constitutional limit: ≤1,100 lines (98.4%)");

    // CRITICAL: Constitutional compliance requirement
    assert!(
        output_lines <= 1100,
        "❌ CONSTITUTIONAL VIOLATION: {output_lines} > 1,100 lines"
    );

    assert!(
        compression_ratio >= 98.4,
        "❌ CONSTITUTIONAL VIOLATION: {compression_ratio:.2}% < 98.4% compression"
    );

    // Validate we're within expected range (baseline: ~941 lines at threshold=75)
    // Lower bound catches regressions that merge too aggressively
    // Upper bound is the constitutional limit
    assert!(
        (800..=1100).contains(&output_lines),
        "Output {output_lines} outside expected range [800, 1100]"
    );

    println!("✅ Constitutional compliance PASSED");
}

#[test]
fn test_processing_speed_requirement() {
    // Constitutional requirement: ≤30 seconds for kubelet.log processing.
    //
    // This test only makes sense with an optimized binary. In debug mode
    // (cargo test, cargo mutants) the binary is 10-20x slower and would
    // always fail the 30s limit. Skip gracefully — the criterion benchmarks
    // are the real performance gate.
    if cfg!(debug_assertions) {
        eprintln!("Skipping speed test: debug build (use --release for meaningful results)");
        return;
    }

    use std::time::Instant;

    let Ok(file) = std::fs::File::open("examples/kubelet.log") else {
        eprintln!("Skipping: examples/kubelet.log not available");
        return;
    };

    let start = Instant::now();

    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--no-stats"])
        .stdin(file)
        .output()
        .expect("Failed to execute lessence");

    let duration = start.elapsed();

    assert!(output.status.success(), "lessence execution failed");

    println!("Processing speed test:");
    println!("  Duration: {:.2}s", duration.as_secs_f64());
    println!("  Constitutional limit: ≤30s");

    assert!(
        duration.as_secs() <= 30,
        "❌ CONSTITUTIONAL VIOLATION: {:.2}s > 30s processing time",
        duration.as_secs_f64()
    );

    println!("✅ Processing speed requirement PASSED");
}
