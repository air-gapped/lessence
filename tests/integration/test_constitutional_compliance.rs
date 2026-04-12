use std::io::Write;
use std::process::{Command, Stdio};
use std::str;

#[path = "../fixtures/log_generator.rs"]
mod log_generator;

#[test]
fn test_constitutional_compliance_generated() {
    // Constitutional compliance test using generated synthetic logs.
    // Verifies that lessence maintains high compression on repetitive
    // kubelet-style patterns. This runs on all builds (debug + release)
    // and doesn't depend on gitignored corpus files.
    //
    // The generator produces 1000 lines across 5 patterns exercising
    // all major token types (UUID, IP, Hash, Path, PodName, Namespace,
    // PID, Timestamp, Duration, QuotedString).
    let input = log_generator::generate_log(1000);
    let input_lines = input.lines().count();

    let mut child = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--no-stats", "--threads", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn lessence");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child
        .wait_with_output()
        .expect("Failed to wait for lessence");
    assert!(output.status.success(), "lessence execution failed");

    let compressed = str::from_utf8(&output.stdout).expect("Invalid UTF-8");
    let output_lines = compressed.lines().count();
    let ratio = ((input_lines - output_lines) as f64 / input_lines as f64) * 100.0;

    println!("Constitutional compliance (generated 1000 lines):");
    println!("  Input: {input_lines}, Output: {output_lines}, Ratio: {ratio:.1}%");

    // 1000 lines with 5 repeating patterns should compress to ≤30 lines.
    // The generator is deterministic so this is a stable assertion.
    assert!(
        output_lines <= 30,
        "Compression regression: {output_lines} > 30 lines from {input_lines} input"
    );
    assert!(
        ratio >= 95.0,
        "Compression ratio {ratio:.1}% < 95.0% on generated kubelet-style logs"
    );

    // Lower bound: too few output lines means over-aggressive folding
    // (merging patterns that shouldn't be merged)
    assert!(
        output_lines >= 5,
        "Over-compression: {output_lines} < 5 lines — patterns are being merged incorrectly"
    );
}

#[test]
fn test_constitutional_compliance_kubelet() {
    // Bonus test against real kubelet.log when available (gitignored).
    // Skipped in debug builds and when the file is missing.
    if cfg!(debug_assertions) {
        eprintln!("Skipping kubelet.log test: debug build (use --release)");
        return;
    }

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

    let compressed = str::from_utf8(&output.stdout).expect("Invalid UTF-8");
    let output_lines = compressed.lines().count();
    let original = std::fs::read_to_string("examples/kubelet.log").unwrap();
    let input_lines = original.lines().count();
    let ratio = ((input_lines - output_lines) as f64 / input_lines as f64) * 100.0;

    println!("Constitutional compliance (kubelet.log):");
    println!("  Input: {input_lines}, Output: {output_lines}, Ratio: {ratio:.1}%");

    assert!(
        output_lines <= 1100,
        "CONSTITUTIONAL VIOLATION: {output_lines} > 1100 lines"
    );
    assert!(
        ratio >= 98.4,
        "CONSTITUTIONAL VIOLATION: {ratio:.1}% < 98.4%"
    );
    assert!(
        (800..=1100).contains(&output_lines),
        "Output {output_lines} outside expected range [800, 1100]"
    );
}

#[test]
fn test_processing_speed_requirement() {
    // Speed test only makes sense with release binary + real corpus.
    if cfg!(debug_assertions) {
        eprintln!("Skipping speed test: debug build (use --release)");
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

    println!("Speed: {:.2}s (limit: ≤30s)", duration.as_secs_f64());
    assert!(
        duration.as_secs() <= 30,
        "SPEED VIOLATION: {:.2}s > 30s",
        duration.as_secs_f64()
    );
}
